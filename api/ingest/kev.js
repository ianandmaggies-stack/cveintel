/**
 * KEV Ingest Job
 * Downloads CISA Known Exploited Vulnerabilities catalogue
 * Source: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
 * Cadence: Daily
 */

import https from 'https';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import dotenv from 'dotenv';
import pool from '../db/index.js';
import { acquireLock, releaseLock, logStart, logComplete } from './ingestLock.js';

dotenv.config();

const KEV_URL  = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const RAW_PATH = process.env.RAW_FILES_PATH || './ingest/raw';
const JOB_NAME = 'kev';

function downloadFile(url) {
  return new Promise((resolve, reject) => {
    let data = '';
    https.get(url, (res) => {
      if (res.statusCode !== 200) { reject(new Error(`HTTP ${res.statusCode}`)); return; }
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve(data));
    }).on('error', reject);
  });
}

function computeChecksum(data) {
  return crypto.createHash('md5').update(data).digest('hex');
}

async function getLastChecksum() {
  const r = await pool.query(
    `SELECT checksum FROM ingest_log WHERE job_name=$1 AND status='success' ORDER BY completed_at DESC LIMIT 1`,
    [JOB_NAME]
  );
  return r.rows[0]?.checksum || null;
}

function parseKevData(raw) {
  const json = JSON.parse(raw);
  if (!json.vulnerabilities || !Array.isArray(json.vulnerabilities))
    throw new Error('Unexpected KEV JSON structure');
  return json.vulnerabilities.map(v => ({
    cve_id:             v.cveID,
    date_added:         v.dateAdded         || null,
    vulnerability_name: v.vulnerabilityName || null,
    vendor_project:     v.vendorProject     || null,
    product:            v.product           || null,
    required_action:    v.requiredAction    || null,
    due_date:           v.dueDate           || null,
  }));
}

async function upsertKevEntries(entries) {
  const existing = await pool.query(`SELECT cve_id FROM cve_kev`);
  const existingIds = new Set(existing.rows.map(r => r.cve_id));
  let inserted = 0, updated = 0, failed = 0;

  for (const entry of entries) {
    try {
      await pool.query(
        `INSERT INTO cve_kev (cve_id,date_added,vulnerability_name,vendor_project,product,required_action,due_date)
         VALUES ($1,$2,$3,$4,$5,$6,$7)
         ON CONFLICT (cve_id) DO UPDATE SET
           vulnerability_name=EXCLUDED.vulnerability_name, vendor_project=EXCLUDED.vendor_project,
           product=EXCLUDED.product, required_action=EXCLUDED.required_action, due_date=EXCLUDED.due_date`,
        [entry.cve_id, entry.date_added, entry.vulnerability_name, entry.vendor_project, entry.product, entry.required_action, entry.due_date]
      );
      existingIds.has(entry.cve_id) ? updated++ : inserted++;
    } catch (err) { console.error(`Failed ${entry.cve_id}:`, err.message); failed++; }
  }
  return { inserted, updated, failed };
}

async function updateKevScoreFlags(newCveIds) {
  if (newCveIds.length === 0) return;
  await pool.query(`UPDATE cve_score SET kev_member=TRUE WHERE cve_id=ANY($1)`, [newCveIds]);
  console.log(`  Flagged ${newCveIds.length} CVEs as KEV members in cve_score`);
}

async function runKevIngest() {
  console.log(`\n[KEV] Starting ingest — ${new Date().toISOString()}`);

  const locked = await acquireLock(pool, JOB_NAME);
  if (!locked) { await pool.end(); return; }

  const logId  = await logStart(pool, JOB_NAME);
  const counts = { status: 'failed', fetched: 0, inserted: 0, updated: 0, failed: 0, checksum: null, error: null };

  try {
    console.log('  Downloading KEV data...');
    const raw      = await downloadFile(KEV_URL);
    const checksum = computeChecksum(raw);
    counts.checksum = checksum;

    const lastChecksum = await getLastChecksum();
    if (lastChecksum === checksum) {
      console.log('  Checksum matches — no changes. Skipping.');
      counts.status = 'skipped';
      counts.error  = 'Duplicate checksum';
    } else {
      const tmpPath   = path.join(RAW_PATH, 'kev_latest.json.tmp');
      const finalPath = path.join(RAW_PATH, 'kev_latest.json');
      fs.writeFileSync(tmpPath, raw);

      const entries = parseKevData(raw);
      counts.fetched = entries.length;
      console.log(`  Found ${entries.length} KEV entries`);

      if (entries.length < 100) throw new Error(`Suspiciously low KEV count: ${entries.length}`);

      const beforeResult = await pool.query(`SELECT cve_id FROM cve_kev`);
      const beforeIds    = new Set(beforeResult.rows.map(r => r.cve_id));

      const result = await upsertKevEntries(entries);
      counts.inserted = result.inserted;
      counts.updated  = result.updated;
      counts.failed   = result.failed;

      const afterResult = await pool.query(`SELECT cve_id FROM cve_kev`);
      const newIds = afterResult.rows.map(r => r.cve_id).filter(id => !beforeIds.has(id));
      await updateKevScoreFlags(newIds);

      fs.renameSync(tmpPath, finalPath);
      counts.status = 'success';
      console.log(`\n[KEV] Complete — ${counts.inserted} inserted, ${counts.updated} updated`);
    }
  } catch (err) {
    counts.error = err.message;
    console.error(`\n[KEV] Failed:`, err.message);
  } finally {
    try { await logComplete(pool, logId, counts); } catch (e) { console.error('logComplete failed:', e.message); }
    try { await releaseLock(pool, JOB_NAME);      } catch (e) { console.error('releaseLock failed:', e.message); }
    await pool.end();
  }
}

runKevIngest();
