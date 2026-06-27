/**
 * EPSS Ingest Job
 * Downloads daily EPSS scores from FIRST.org
 * Source: https://epss.cyentia.com/epss_scores-YYYY-MM-DD.csv
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

const RAW_PATH = process.env.RAW_FILES_PATH || './ingest/raw';
const JOB_NAME = 'epss';
const MIN_RECORD_THRESHOLD = 1000;

function todayString()      { return new Date().toISOString().split('T')[0]; }
function daysAgoString(n)   { const d = new Date(); d.setDate(d.getDate() - n); return d.toISOString().split('T')[0]; }
function buildEpssUrl(date) { return `https://epss.cyentia.com/epss_scores-${date}.csv.gz`; }
function computeChecksum(d) { return crypto.createHash('md5').update(d).digest('hex'); }

async function getLastChecksum() {
  const r = await pool.query(
    `SELECT checksum FROM ingest_log WHERE job_name=$1 AND status='success' ORDER BY completed_at DESC LIMIT 1`,
    [JOB_NAME]
  );
  return r.rows[0]?.checksum || null;
}

function downloadFile(url) {
  return new Promise((resolve, reject) => {
    https.get(url, (res) => {
      if (res.statusCode === 301 || res.statusCode === 302) {
        downloadFile(res.headers.location).then(resolve).catch(reject); return;
      }
      if (res.statusCode !== 200) { reject(new Error(`HTTP ${res.statusCode} for ${url}`)); return; }
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => resolve(Buffer.concat(chunks)));
      res.on('error', reject);
    }).on('error', reject);
  });
}

function parseCsv(text) {
  const entries = [];
  for (const line of text.split('\n')) {
    if (line.startsWith('#') || line.startsWith('cve') || !line.trim()) continue;
    const [cve_id, epss_str, pct_str] = line.split(',');
    if (!cve_id?.startsWith('CVE-')) continue;
    const epss_score = parseFloat(epss_str);
    const percentile = parseFloat(pct_str);
    if (!isNaN(epss_score) && !isNaN(percentile)) entries.push({ cve_id: cve_id.trim(), epss_score, percentile });
  }
  return entries;
}

async function getPreviousScoresBulk(daysAgo) {
  const r = await pool.query(
    `SELECT DISTINCT ON (cve_id) cve_id, epss_score FROM cve_epss
     WHERE snapshot_date <= $1 ORDER BY cve_id, snapshot_date DESC`,
    [daysAgoString(daysAgo)]
  );
  const map = new Map();
  for (const row of r.rows) map.set(row.cve_id, parseFloat(row.epss_score));
  return map;
}

async function insertEpssEntries(entries, today) {
  let inserted = 0, failed = 0;
  const chunkSize = 1000;
  for (let i = 0; i < entries.length; i += chunkSize) {
    const chunk  = entries.slice(i, i + chunkSize);
    const values = [], params = [];
    let p = 1;
    for (const e of chunk) {
      values.push(`($${p++},$${p++},$${p++},$${p++})`);
      params.push(e.cve_id, today, e.epss_score, e.percentile);
    }
    try {
      await pool.query(
        `INSERT INTO cve_epss (cve_id,snapshot_date,epss_score,percentile) VALUES ${values.join(',')}
         ON CONFLICT (cve_id,snapshot_date) DO UPDATE SET epss_score=EXCLUDED.epss_score, percentile=EXCLUDED.percentile`,
        params
      );
      inserted += chunk.length;
    } catch (err) { console.error(`Chunk ${i} failed:`, err.message); failed += chunk.length; }
    if (i % 50000 === 0 && i > 0) console.log(`  Inserted ${i}/${entries.length}...`);
  }
  return { inserted, failed };
}

async function updateCveScoresBulk(entries, prev1d, prev7d) {
  console.log('  Bulk updating cve_score with EPSS deltas...');
  const cveIds = [], d1 = [], d7 = [];
  for (const e of entries) {
    const s1 = prev1d.get(e.cve_id) ?? null;
    const s7 = prev7d.get(e.cve_id) ?? null;
    cveIds.push(e.cve_id);
    d1.push(s1 !== null ? parseFloat((e.epss_score - s1).toFixed(5)) : null);
    d7.push(s7 !== null ? parseFloat((e.epss_score - s7).toFixed(5)) : null);
  }
  await pool.query(`CREATE TEMP TABLE tmp_epss_scores (cve_id TEXT, delta_1d NUMERIC(6,5), delta_7d NUMERIC(6,5))`);
  const chunkSize = 5000;
  for (let i = 0; i < cveIds.length; i += chunkSize) {
    const ids = cveIds.slice(i, i + chunkSize);
    const values = ids.map((_, j) => `($${j*3+1},$${j*3+2},$${j*3+3})`).join(',');
    const params = [];
    for (let j = 0; j < ids.length; j++) params.push(ids[j], d1[i+j], d7[i+j]);
    await pool.query(`INSERT INTO tmp_epss_scores VALUES ${values}`, params);
  }
  const r = await pool.query(
    `INSERT INTO cve_score (cve_id,epss_delta_1d,epss_delta_7d,epss_pending,score_updated)
     SELECT cve_id,delta_1d,delta_7d,FALSE,NOW() FROM tmp_epss_scores
     ON CONFLICT (cve_id) DO UPDATE SET
       epss_delta_1d=EXCLUDED.epss_delta_1d, epss_delta_7d=EXCLUDED.epss_delta_7d,
       epss_pending=FALSE, score_updated=NOW()`
  );
  console.log(`  cve_score updated — ${r.rowCount} rows`);
  return r.rowCount;
}

async function runEpssIngest() {
  console.log(`\n[EPSS] Starting ingest — ${new Date().toISOString()}`);

  const locked = await acquireLock(pool, JOB_NAME);
  if (!locked) { await pool.end(); return; }

  const logId  = await logStart(pool, JOB_NAME);
  const counts = { status: 'failed', fetched: 0, inserted: 0, updated: 0, failed: 0, checksum: null, error: null };

  try {
    const today = todayString();
    let rawBuffer;
    try {
      rawBuffer = await downloadFile(buildEpssUrl(today));
    } catch {
      console.log('  Today not available, trying yesterday...');
      rawBuffer = await downloadFile(buildEpssUrl(daysAgoString(1)));
    }

    const checksum = computeChecksum(rawBuffer);
    counts.checksum = checksum;
    if (await getLastChecksum() === checksum) {
      console.log('  Checksum matches — skipping.');
      counts.status = 'skipped'; counts.error = 'Duplicate checksum';
    } else {
      const { gunzipSync } = await import('zlib');
      const rawText = gunzipSync(rawBuffer).toString('utf8');
      const tmpPath = path.join(RAW_PATH, 'epss_latest.csv.tmp');
      fs.writeFileSync(tmpPath, rawText);

      const entries = parseCsv(rawText);
      counts.fetched = entries.length;
      console.log(`  Parsed ${entries.length} EPSS entries`);
      if (entries.length < MIN_RECORD_THRESHOLD) throw new Error(`Low EPSS count: ${entries.length}`);

      const [prev1d, prev7d] = await Promise.all([getPreviousScoresBulk(1), getPreviousScoresBulk(7)]);
      const ins = await insertEpssEntries(entries, today);
      counts.inserted = ins.inserted; counts.failed = ins.failed;
      counts.updated  = await updateCveScoresBulk(entries, prev1d, prev7d);

      fs.renameSync(tmpPath, path.join(RAW_PATH, 'epss_latest.csv'));
      counts.status = 'success';
      console.log(`\n[EPSS] Complete — ${counts.inserted} inserted, ${counts.updated} scores updated`);
    }
  } catch (err) {
    counts.error = err.message;
    console.error(`\n[EPSS] Failed:`, err.message);
  } finally {
    try { await logComplete(pool, logId, counts); } catch (e) { console.error('logComplete failed:', e.message); }
    try { await releaseLock(pool, JOB_NAME);      } catch (e) { console.error('releaseLock failed:', e.message); }
    await pool.end();
  }
}

runEpssIngest();
