/**
 * EPSS Ingest Job
 * Downloads daily EPSS scores from FIRST.org
 * Calculates 1d and 7d deltas against previous snapshots
 *
 * Source: https://epss.cyentia.com/epss_scores-YYYY-MM-DD.csv
 * Cadence: Daily
 * Size: ~250k rows
 */

import https from 'https';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import dotenv from 'dotenv';
import pool from '../db/index.js';

dotenv.config();

const RAW_PATH = process.env.RAW_FILES_PATH || './ingest/raw';
const JOB_NAME = 'epss';
const MIN_RECORD_THRESHOLD = 1000;

// ============================================
// Helpers — date
// ============================================

function todayString() {
  return new Date().toISOString().split('T')[0];
}

function daysAgoString(days) {
  const d = new Date();
  d.setDate(d.getDate() - days);
  return d.toISOString().split('T')[0];
}

function buildEpssUrl(dateStr) {
  return `https://epss.cyentia.com/epss_scores-${dateStr}.csv.gz`;
}

// ============================================
// Logging helpers (same pattern as KEV)
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

async function getLastChecksum() {
  const result = await pool.query(
    `SELECT checksum FROM ingest_log
     WHERE job_name = $1 AND status = 'success'
     ORDER BY completed_at DESC LIMIT 1`,
    [JOB_NAME]
  );
  return result.rows[0]?.checksum || null;
}

function computeChecksum(data) {
  return crypto.createHash('md5').update(data).digest('hex');
}

// ============================================
// Fetch stage
// ============================================

function downloadFile(url) {
  return new Promise((resolve, reject) => {
    https.get(url, (res) => {
      if (res.statusCode === 301 || res.statusCode === 302) {
        // Follow redirect
        downloadFile(res.headers.location).then(resolve).catch(reject);
        return;
      }
      if (res.statusCode !== 200) {
        reject(new Error(`HTTP ${res.statusCode} for ${url}`));
        return;
      }
      const chunks = [];
      res.on('data', chunk => chunks.push(chunk));
      res.on('end', () => resolve(Buffer.concat(chunks)));
      res.on('error', reject);
    }).on('error', reject);
  });
}

// ============================================
// Transform stage
// ============================================

function parseCsv(text) {
  const lines = text.split('\n');
  const entries = [];

  for (const line of lines) {
    // Skip comments and header
    if (line.startsWith('#') || line.startsWith('cve') || line.trim() === '') {
      continue;
    }
    const parts = line.split(',');
    if (parts.length < 3) continue;

    const cve_id     = parts[0].trim();
    const epss_score = parseFloat(parts[1]);
    const percentile = parseFloat(parts[2]);

    if (!cve_id.startsWith('CVE-')) continue;
    if (isNaN(epss_score) || isNaN(percentile)) continue;

    entries.push({ cve_id, epss_score, percentile });
  }

  return entries;
}

// ============================================
// Delta calculation
// ============================================

async function getPreviousScore(cveId, daysAgo) {
  const dateStr = daysAgoString(daysAgo);
  const result = await pool.query(
    `SELECT epss_score FROM cve_epss
     WHERE cve_id = $1
     AND snapshot_date <= $2
     ORDER BY snapshot_date DESC
     LIMIT 1`,
    [cveId, dateStr]
  );
  return result.rows[0]?.epss_score || null;
}

async function getPreviousScoresBulk(daysAgo) {
  const dateStr = daysAgoString(daysAgo);
  const result = await pool.query(
    `SELECT DISTINCT ON (cve_id) cve_id, epss_score
     FROM cve_epss
     WHERE snapshot_date <= $1
     ORDER BY cve_id, snapshot_date DESC`,
    [dateStr]
  );
  const map = new Map();
  for (const row of result.rows) {
    map.set(row.cve_id, parseFloat(row.epss_score));
  }
  return map;
}

// ============================================
// Load stage
// ============================================

async function insertEpssEntries(entries, today, prev1d, prev7d) {
  let inserted = 0;
  let failed = 0;

  // Batch insert in chunks of 1000 for performance
  const chunkSize = 1000;

  for (let i = 0; i < entries.length; i += chunkSize) {
    const chunk = entries.slice(i, i + chunkSize);

    // Build bulk insert
    const values = [];
    const params = [];
    let paramIndex = 1;

    for (const entry of chunk) {
      values.push(
        `($${paramIndex++}, $${paramIndex++}, $${paramIndex++}, $${paramIndex++})`
      );
      params.push(
        entry.cve_id,
        today,
        entry.epss_score,
        entry.percentile
      );
    }

    try {
      await pool.query(
        `INSERT INTO cve_epss (cve_id, snapshot_date, epss_score, percentile)
         VALUES ${values.join(', ')}
         ON CONFLICT (cve_id, snapshot_date) DO UPDATE SET
           epss_score = EXCLUDED.epss_score,
           percentile = EXCLUDED.percentile`,
        params
      );
      inserted += chunk.length;
    } catch (err) {
      console.error(`Chunk ${i}-${i + chunkSize} failed:`, err.message);
      failed += chunk.length;
    }

    // Progress indicator every 50k rows
    if (i % 50000 === 0 && i > 0) {
      console.log(`  Processed ${i} / ${entries.length} rows...`);
    }
  }

  return { inserted, failed };
}

async function updateCveScoresBulk(entries, prev1d, prev7d) {
  console.log('  Bulk updating cve_score with EPSS deltas...');

  const cveIds   = [];
  const deltas1d = [];
  const deltas7d = [];

  for (const entry of entries) {
    const score1d = prev1d.get(entry.cve_id) ?? null;
    const score7d = prev7d.get(entry.cve_id) ?? null;
    cveIds.push(entry.cve_id);
    deltas1d.push(score1d !== null ? parseFloat((entry.epss_score - score1d).toFixed(5)) : null);
    deltas7d.push(score7d !== null ? parseFloat((entry.epss_score - score7d).toFixed(5)) : null);
  }

  await pool.query(`
    CREATE TEMP TABLE tmp_epss_scores (
      cve_id   TEXT,
      delta_1d NUMERIC(6,5),
      delta_7d NUMERIC(6,5)
    ) 
  `);

  const chunkSize = 5000;
  for (let i = 0; i < cveIds.length; i += chunkSize) {
    const chunk_ids = cveIds.slice(i, i + chunkSize);
    const chunk_1d  = deltas1d.slice(i, i + chunkSize);
    const chunk_7d  = deltas7d.slice(i, i + chunkSize);
    const values    = chunk_ids.map((_, j) => `($${j*3+1}, $${j*3+2}, $${j*3+3})`).join(', ');
    const params    = [];
    for (let j = 0; j < chunk_ids.length; j++) {
      params.push(chunk_ids[j], chunk_1d[j], chunk_7d[j]);
    }
    await pool.query(
      `INSERT INTO tmp_epss_scores (cve_id, delta_1d, delta_7d) VALUES ${values}`,
      params
    );
    if (i % 50000 === 0 && i > 0) {
      console.log(`  Staged ${i} / ${cveIds.length} rows...`);
    }
  }

  const result = await pool.query(`
    INSERT INTO cve_score (cve_id, epss_delta_1d, epss_delta_7d, epss_pending, score_updated)
    SELECT cve_id, delta_1d, delta_7d, FALSE, NOW()
    FROM tmp_epss_scores
    ON CONFLICT (cve_id) DO UPDATE SET
      epss_delta_1d = EXCLUDED.epss_delta_1d,
      epss_delta_7d = EXCLUDED.epss_delta_7d,
      epss_pending  = FALSE,
      score_updated = NOW()
  `);

  console.log(`  cve_score updated — ${result.rowCount} rows affected`);
  return result.rowCount;
}

// ============================================
// Main
// ============================================

async function runEpssIngest() {
  console.log(`\n[EPSS] Starting ingest — ${new Date().toISOString()}`);

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
    const today = todayString();
    const url = buildEpssUrl(today);

    // --- FETCH ---
    console.log(`  Downloading EPSS data for ${today}...`);
    console.log(`  URL: ${url}`);

    let rawBuffer;
    try {
      rawBuffer = await downloadFile(url);
    } catch (err) {
      // Try yesterday if today's file not yet published
      console.log(`  Today's file not available, trying yesterday...`);
      const yesterday = daysAgoString(1);
      rawBuffer = await downloadFile(buildEpssUrl(yesterday));
      console.log(`  Using ${yesterday} snapshot`);
    }

    const checksum = computeChecksum(rawBuffer);
    counts.checksum = checksum;

    // Check for duplicate
    const lastChecksum = await getLastChecksum();
    if (lastChecksum === checksum) {
      console.log('  Checksum matches last run — skipping.');
      counts.status = 'skipped';
      counts.error = 'Duplicate checksum';
      await logComplete(logId, counts);
      await setLock(false);
      return;
    }

    // Decompress — EPSS files are gzipped
    const { gunzipSync } = await import('zlib');
    const rawText = gunzipSync(rawBuffer).toString('utf8');

    // Save raw file
    const tmpPath = path.join(RAW_PATH, 'epss_latest.csv.tmp');
    const finalPath = path.join(RAW_PATH, 'epss_latest.csv');
    fs.writeFileSync(tmpPath, rawText);

    // --- TRANSFORM ---
    console.log('  Parsing CSV...');
    const entries = parseCsv(rawText);
    counts.fetched = entries.length;
    console.log(`  Parsed ${entries.length} EPSS entries`);

    // Sanity check
    if (entries.length < MIN_RECORD_THRESHOLD) {
      throw new Error(`Suspiciously low EPSS count: ${entries.length}`);
    }

    // Load previous scores for delta calculation
    console.log('  Loading previous scores for delta calculation...');
    const prev1d = await getPreviousScoresBulk(1);
    const prev7d = await getPreviousScoresBulk(7);
    console.log(`  Previous 1d scores: ${prev1d.size} CVEs`);
    console.log(`  Previous 7d scores: ${prev7d.size} CVEs`);

    // --- LOAD ---
    console.log('  Inserting EPSS snapshot...');
    const insertResult = await insertEpssEntries(entries, today, prev1d, prev7d);
    counts.inserted = insertResult.inserted;
    counts.failed   = insertResult.failed;

    // Update cve_score with deltas
    const updatedScores = await updateCveScoresBulk(entries, prev1d, prev7d);
    counts.updated = updatedScores;

    // Rename tmp to final
    fs.renameSync(tmpPath, finalPath);

    counts.status = 'success';
    console.log(`\n[EPSS] Complete — ${counts.inserted} inserted, ${counts.updated} scores updated, ${counts.failed} failed`);

  } catch (err) {
    counts.error = err.message;
    console.error(`\n[EPSS] Failed:`, err.message);
  } finally {
    await logComplete(logId, counts);
    await setLock(false);
    pool.end();
  }
}

runEpssIngest();
