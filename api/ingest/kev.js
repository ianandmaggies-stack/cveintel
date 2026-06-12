/**
 * KEV Ingest Job
 * Downloads CISA Known Exploited Vulnerabilities catalogue
 * and upserts into cve_kev table.
 *
 * Source: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
 * Cadence: Daily
 */

import https from 'https';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import dotenv from 'dotenv';
import pool from '../db/index.js';

dotenv.config();

const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const RAW_PATH = process.env.RAW_FILES_PATH || './ingest/raw';
const JOB_NAME = 'kev';

// ============================================
// Logging helpers
// ============================================

async function logStart() {
  const result = await pool.query(
    `INSERT INTO ingest_log (job_name, started_at, status)
     VALUES ($1, NOW(), 'running')
     RETURNING log_id`,
    [JOB_NAME]
  );
  return result.rows[0].log_id;
}

async function logComplete(logId, counts) {
  await pool.query(
    `UPDATE ingest_log SET
       completed_at     = NOW(),
       status           = $1,
       records_fetched  = $2,
       records_inserted = $3,
       records_updated  = $4,
       records_failed   = $5,
       error_message    = $6,
       checksum         = $7
     WHERE log_id = $8`,
    [
      counts.status,
      counts.fetched,
      counts.inserted,
      counts.updated,
      counts.failed,
      counts.error || null,
      counts.checksum || null,
      logId
    ]
  );
}

async function setLock(isRunning) {
  await pool.query(
    `UPDATE ingest_status SET is_running = $1, started_at = $2
     WHERE job_name = $3`,
    [isRunning, isRunning ? new Date() : null, JOB_NAME]
  );
}

// ============================================
// Fetch stage
// ============================================

function downloadFile(url) {
  return new Promise((resolve, reject) => {
    let data = '';
    https.get(url, (res) => {
      if (res.statusCode !== 200) {
        reject(new Error(`HTTP ${res.statusCode}`));
        return;
      }
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve(data));
    }).on('error', reject);
  });
}

function computeChecksum(data) {
  return crypto.createHash('md5').update(data).digest('hex');
}

async function getLastChecksum() {
  const result = await pool.query(
    `SELECT checksum FROM ingest_log
     WHERE job_name = $1 AND status = 'success'
     ORDER BY completed_at DESC LIMIT 1`,
    [JOB_NAME]
  );
  return result.rows[0]?.checksum || null;
}

// ============================================
// Transform stage
// ============================================

function parseKevData(raw) {
  const json = JSON.parse(raw);
  if (!json.vulnerabilities || !Array.isArray(json.vulnerabilities)) {
    throw new Error('Unexpected KEV JSON structure');
  }
  return json.vulnerabilities.map(v => ({
    cve_id:             v.cveID,
    date_added:         v.dateAdded || null,
    vulnerability_name: v.vulnerabilityName || null,
    vendor_project:     v.vendorProject || null,
    product:            v.product || null,
    required_action:    v.requiredAction || null,
    due_date:           v.dueDate || null,
  }));
}

// ============================================
// Load stage
// ============================================

async function upsertKevEntries(entries) {
  let inserted = 0;
  let updated = 0;
  let failed = 0;

  // Find entries not in our table yet — these are new
  const existing = await pool.query(
    `SELECT cve_id FROM cve_kev`
  );
  const existingIds = new Set(existing.rows.map(r => r.cve_id));

  for (const entry of entries) {
    try {
      const result = await pool.query(
        `INSERT INTO cve_kev (
           cve_id, date_added, vulnerability_name,
           vendor_project, product, required_action, due_date
         ) VALUES ($1,$2,$3,$4,$5,$6,$7)
         ON CONFLICT (cve_id) DO UPDATE SET
           vulnerability_name = EXCLUDED.vulnerability_name,
           vendor_project     = EXCLUDED.vendor_project,
           product            = EXCLUDED.product,
           required_action    = EXCLUDED.required_action,
           due_date           = EXCLUDED.due_date
         RETURNING cve_id`,
        [
          entry.cve_id,
          entry.date_added,
          entry.vulnerability_name,
          entry.vendor_project,
          entry.product,
          entry.required_action,
          entry.due_date,
        ]
      );

      if (existingIds.has(entry.cve_id)) {
        updated++;
      } else {
        inserted++;
      }
    } catch (err) {
      console.error(`Failed to upsert ${entry.cve_id}:`, err.message);
      failed++;
    }
  }

  return { inserted, updated, failed };
}

async function updateKevScoreFlags(newCveIds) {
  if (newCveIds.length === 0) return;

  // Flag new KEV members in cve_score if record exists
  await pool.query(
    `UPDATE cve_score SET kev_member = TRUE
     WHERE cve_id = ANY($1)`,
    [newCveIds]
  );

  console.log(`  Flagged ${newCveIds.length} CVEs as KEV members in cve_score`);
}

// ============================================
// Main
// ============================================

async function runKevIngest() {
  console.log(`\n[KEV] Starting ingest — ${new Date().toISOString()}`);

  const logId = await logStart();
  await setLock(true);

  const counts = {
    status:   'failed',
    fetched:  0,
    inserted: 0,
    updated:  0,
    failed:   0,
    checksum: null,
    error:    null,
  };

  try {
    // --- FETCH ---
    console.log('  Downloading KEV data...');
    const raw = await downloadFile(KEV_URL);
    const checksum = computeChecksum(raw);
    counts.checksum = checksum;

    // Check for duplicate run
    const lastChecksum = await getLastChecksum();
    if (lastChecksum === checksum) {
      console.log('  Checksum matches last run — no changes. Skipping.');
      counts.status = 'skipped';
      counts.error = 'Duplicate checksum';
      await logComplete(logId, counts);
      await setLock(false);
      return;
    }

    // Save raw file as .tmp then rename on success
    const tmpPath = path.join(RAW_PATH, 'kev_latest.json.tmp');
    const finalPath = path.join(RAW_PATH, 'kev_latest.json');
    fs.writeFileSync(tmpPath, raw);

    // --- TRANSFORM ---
    console.log('  Parsing KEV data...');
    const entries = parseKevData(raw);
    counts.fetched = entries.length;
    console.log(`  Found ${entries.length} KEV entries`);

    // Sanity check
    if (entries.length < 100) {
      throw new Error(`Suspiciously low KEV count: ${entries.length}`);
    }

    // Get current KEV IDs before upsert to find new ones
    const beforeResult = await pool.query(`SELECT cve_id FROM cve_kev`);
    const beforeIds = new Set(beforeResult.rows.map(r => r.cve_id));

    // --- LOAD ---
    console.log('  Upserting KEV entries...');
    const result = await upsertKevEntries(entries);
    counts.inserted = result.inserted;
    counts.updated  = result.updated;
    counts.failed   = result.failed;

    // Find genuinely new KEV entries
    const afterResult = await pool.query(`SELECT cve_id FROM cve_kev`);
    const newIds = afterResult.rows
      .map(r => r.cve_id)
      .filter(id => !beforeIds.has(id));

    console.log(`  New KEV entries: ${newIds.length}`);

    // Update score flags for new KEV members
    await updateKevScoreFlags(newIds);

    // Rename tmp file to final
    fs.renameSync(tmpPath, finalPath);

    counts.status = 'success';
    console.log(`\n[KEV] Complete — ${counts.inserted} inserted, ${counts.updated} updated, ${counts.failed} failed`);

  } catch (err) {
    counts.error = err.message;
    console.error(`\n[KEV] Failed:`, err.message);
  } finally {
    await logComplete(logId, counts);
    await setLock(false);
    pool.end();
  }
}

runKevIngest();

