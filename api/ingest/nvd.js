/**
 * NVD Ingest Job
 * Downloads CVE data from the National Vulnerability Database API
 * Populates cve_core and cve_cpe tables
 *
 * Usage:
 *   node ingest/nvd.js          -- delta mode (last 8 days)
 *   node ingest/nvd.js --full   -- full ingest (all CVEs)
 */

import https from 'https';
import fs from 'fs';
import path from 'path';
import dotenv from 'dotenv';
import pool from '../db/index.js';
import { stripHtml } from '../utils/sanitise.js';
import { acquireLock, releaseLock, logStart, logComplete } from './ingestLock.js';

dotenv.config();

const JOB_NAME          = 'nvd';
const RAW_PATH          = process.env.RAW_FILES_PATH || './ingest/raw';
const NVD_API_KEY       = process.env.NVD_API_KEY   || null;
const RESULTS_PER_PAGE  = 2000;
const RATE_LIMIT_DELAY  = NVD_API_KEY ? 700 : 6500;
const BATCH_SIZE        = 100;   // records per multi-row upsert
const CPE_BATCH_SIZE    = 500;   // CPE rows per insert

// ============================================
// Fetch
// ============================================

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

function fetchPage(url) {
  return new Promise((resolve, reject) => {
    const headers = { 'Accept': 'application/json' };
    if (NVD_API_KEY) headers['apiKey'] = NVD_API_KEY;
    const u = new URL(url);
    https.get({ hostname: u.hostname, path: u.pathname + u.search, headers, method: 'GET' }, (res) => {
      if (res.statusCode === 403) return reject(new Error('NVD API key invalid or rate limited'));
      if (res.statusCode !== 200) return reject(new Error(`HTTP ${res.statusCode}`));
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => { try { resolve(JSON.parse(data)); } catch { reject(new Error('Parse failed')); } });
    }).on('error', reject);
  });
}

async function fetchAllPages(baseUrl) {
  const all = [];
  let startIndex = 0, total = null, pageNum = 0;
  do {
    const url = `${baseUrl}&resultsPerPage=${RESULTS_PER_PAGE}&startIndex=${startIndex}`;
    pageNum++;
    let retries = 3, result = null;
    while (retries > 0) {
      try { result = await fetchPage(url); break; }
      catch (err) {
        retries--;
        if (retries === 0) throw err;
        console.log(`  Retry ${3 - retries}/3: ${err.message}`);
        await sleep(RATE_LIMIT_DELAY * 2);
      }
    }
    if (total === null) { total = result.totalResults; console.log(`  Total CVEs: ${total}`); }
    const vulns = result.vulnerabilities || [];
    all.push(...vulns);
    startIndex += vulns.length;
    console.log(`  Page ${pageNum}: ${vulns.length} fetched (${all.length}/${total})`);
    if (startIndex < total) await sleep(RATE_LIMIT_DELAY);
  } while (startIndex < total);
  return all;
}

// ============================================
// Transform
// ============================================

function parseCvssVector(vector) {
  if (!vector) return {};
  const p = {};
  for (const seg of vector.split('/')) { const [k, v] = seg.split(':'); p[k] = v; }
  return {
    attack_vector:       ({ N: 'network', A: 'adjacent', L: 'local', P: 'physical' })[p['AV']] || null,
    privileges_required: ({ N: 'none',    L: 'low',      H: 'high'  })[p['PR']]    || null,
    user_interaction:    ({ N: 'none',    R: 'required'              })[p['UI']]    || null,
    scope:               ({ U: 'unchanged', C: 'changed'             })[p['S']]     || null,
  };
}

function extractCvss(cve) {
  const m    = cve.metrics || {};
  const data = m.cvssMetricV31?.[0]?.cvssData || m.cvssMetricV30?.[0]?.cvssData || m.cvssMetricV2?.[0]?.cvssData || null;
  if (!data) return { cvss_base: null, cvss_vector: null, cvss_version: null, ...parseCvssVector(null) };
  return { cvss_base: data.baseScore, cvss_vector: data.vectorString, cvss_version: data.version, ...parseCvssVector(data.vectorString) };
}

function extractCwe(cve) {
  for (const w of (cve.weaknesses  || []))
    for (const d of (w.description || []))
      if (d.value?.startsWith('CWE-')) return d.value;
  return null;
}

function extractDescription(cve) {
  const en = (cve.descriptions || []).find(d => d.lang === 'en');
  return stripHtml(en?.value || null);
}

function extractCpes(cveId, configurations) {
  const cpes = [];
  for (const config of (configurations || []))
    for (const node of (config.nodes || []))
      for (const match of (node.cpeMatch || []))
        if (match.vulnerable && match.criteria) {
          const p = match.criteria.split(':');
          cpes.push({ cve_id: cveId, cpe_string: match.criteria, vendor: p[3] || null, product: p[4] || null, version: p[5] || null });
        }
  return cpes;
}

function hasPatch(cve) {
  const tags = ['Patch', 'Vendor Advisory', 'Mitigation'];
  return (cve.references || []).some(r => (r.tags || []).some(t => tags.includes(t)));
}

function transformCve(item) {
  const cve  = item.cve;
  const cvss = extractCvss(cve);
  return {
    core: {
      cve_id:              cve.id,
      published_date:      cve.published?.split('T')[0]    || null,
      modified_date:       cve.lastModified?.split('T')[0] || null,
      description:         extractDescription(cve),
      cvss_base:           cvss.cvss_base,
      cvss_vector:         cvss.cvss_vector,
      cvss_version:        cvss.cvss_version,
      cwe_id:              extractCwe(cve),
      patch_available:     hasPatch(cve),
      attack_vector:       cvss.attack_vector,
      privileges_required: cvss.privileges_required,
      user_interaction:    cvss.user_interaction,
      scope:               cvss.scope,
      source_updated:      new Date(),
    },
    cpes: extractCpes(cve.id, cve.configurations)
  };
}

// ============================================
// Platform tagging
// ============================================

async function loadVendorMap() {
  const r   = await pool.query('SELECT vendor_pattern, platform_tag FROM platform_vendor_map');
  const map = new Map();
  for (const row of r.rows) map.set(row.vendor_pattern.toLowerCase(), row.platform_tag);
  return map;
}

function getPlatformTag(vendor, vendorMap) {
  if (!vendor) return 'other';
  const v = vendor.toLowerCase();
  if (vendorMap.has(v)) return vendorMap.get(v);
  for (const [p, tag] of vendorMap) if (v.includes(p) || p.includes(v)) return tag;
  return 'other';
}

// ============================================
// Batch upsert — multi-row for speed
// ============================================

async function upsertCoreBatch(cores) {
  if (cores.length === 0) return { inserted: 0, updated: 0 };

  // Build multi-row VALUES clause
  const cols = 14;
  const values = [];
  const params = [];
  cores.forEach((c, i) => {
    const base = i * cols;
    values.push(`($${base+1},$${base+2},$${base+3},$${base+4},$${base+5},$${base+6},$${base+7},$${base+8},$${base+9},$${base+10},$${base+11},$${base+12},$${base+13},$${base+14})`);
    params.push(
      c.cve_id, c.published_date, c.modified_date, c.description,
      c.cvss_base, c.cvss_vector, c.cvss_version, c.cwe_id,
      c.patch_available, c.attack_vector, c.privileges_required,
      c.user_interaction, c.scope, c.source_updated
    );
  });

  const sql = `
    INSERT INTO cve_core (
      cve_id, published_date, modified_date, description,
      cvss_base, cvss_vector, cvss_version, cwe_id,
      patch_available, attack_vector, privileges_required,
      user_interaction, scope, source_updated
    ) VALUES ${values.join(',')}
    ON CONFLICT (cve_id) DO UPDATE SET
      modified_date        = EXCLUDED.modified_date,
      description          = EXCLUDED.description,
      cvss_base            = EXCLUDED.cvss_base,
      cvss_vector          = EXCLUDED.cvss_vector,
      cvss_version         = EXCLUDED.cvss_version,
      cwe_id               = EXCLUDED.cwe_id,
      patch_available      = EXCLUDED.patch_available,
      attack_vector        = EXCLUDED.attack_vector,
      privileges_required  = EXCLUDED.privileges_required,
      user_interaction     = EXCLUDED.user_interaction,
      scope                = EXCLUDED.scope,
      source_updated       = EXCLUDED.source_updated
    WHERE cve_core.modified_date IS DISTINCT FROM EXCLUDED.modified_date
    RETURNING cve_id, (xmax = 0) AS is_insert
  `;

  const r = await pool.query(sql, params);
  const inserted = r.rows.filter(row => row.is_insert).length;
  const updated  = r.rows.filter(row => !row.is_insert).length;
  return { inserted, updated, touched: r.rows.map(row => row.cve_id) };
}

async function deleteStaleCpes(cveIds) {
  if (cveIds.length === 0) return;
  const params = cveIds.map((_, i) => `$${i + 1}`).join(',');
  await pool.query(`DELETE FROM cve_cpe WHERE cve_id IN (${params})`, cveIds);
}

async function insertCpeBatch(cpes, vendorMap) {
  if (cpes.length === 0) return;
  const cols   = 6;
  const values = [];
  const params = [];
  cpes.forEach((c, i) => {
    const base = i * cols;
    values.push(`($${base+1},$${base+2},$${base+3},$${base+4},$${base+5},$${base+6})`);
    params.push(c.cve_id, c.cpe_string, c.vendor, c.product, c.version, getPlatformTag(c.vendor, vendorMap));
  });
  await pool.query(
    `INSERT INTO cve_cpe (cve_id, cpe_string, vendor, product, version, platform_tag)
     VALUES ${values.join(',')}
     ON CONFLICT DO NOTHING`,
    params
  );
}

async function processBatch(records, vendorMap) {
  const cores = records.map(r => r.core);

  // 1. Upsert all core records in one query
  const { inserted, updated, touched } = await upsertCoreBatch(cores);

  // 2. Delete stale CPEs only for updated records (not new inserts)
  const updatedIds = records
    .filter(r => touched.includes(r.core.cve_id))
    .filter((_, i) => !records[i]?.isNew) // heuristic: touched but not inserted = updated
    .map(r => r.core.cve_id);

  // Simpler: delete CPEs for all touched records, re-insert fresh
  if (touched.length > 0) await deleteStaleCpes(touched);

  // 3. Collect all CPEs and batch insert
  const allCpes = records
    .filter(r => touched.includes(r.core.cve_id))
    .flatMap(r => r.cpes);

  for (let i = 0; i < allCpes.length; i += CPE_BATCH_SIZE) {
    await insertCpeBatch(allCpes.slice(i, i + CPE_BATCH_SIZE), vendorMap);
  }

  return { inserted, updated, failed: 0 };
}

// ============================================
// Main
// ============================================

async function runNvdIngest() {
  const fullMode = process.argv.includes('--full');
  console.log(`\n[NVD] Starting ${fullMode ? 'FULL' : 'DELTA'} ingest — ${new Date().toISOString()}`);
  if (!NVD_API_KEY) console.warn('  WARNING: No NVD_API_KEY set. Rate limited to 5 req/30s — fetch will be slow.');

  const locked = await acquireLock(pool, JOB_NAME);
  if (!locked) { await pool.end(); return; }

  const logId  = await logStart(pool, JOB_NAME);
  const counts = { status: 'failed', fetched: 0, inserted: 0, updated: 0, failed: 0, error: null };

  try {
    const vendorMap = await loadVendorMap();
    console.log(`  Loaded ${vendorMap.size} vendor patterns`);

    let baseUrl = 'https://services.nvd.nist.gov/rest/json/cves/2.0?';
    if (!fullMode) {
      const end = new Date(), start = new Date();
      start.setDate(start.getDate() - 8);
      const fmt = d => d.toISOString().replace('Z', '000');
      baseUrl += `lastModStartDate=${fmt(start)}&lastModEndDate=${fmt(end)}`;
    } else {
      baseUrl += 'noRejected';
    }

    const vulnerabilities = await fetchAllPages(baseUrl);
    counts.fetched = vulnerabilities.length;
    console.log(`  Fetched ${counts.fetched} CVEs. Transforming...`);

    if (counts.fetched === 0) {
      console.log('  No CVEs in window — nothing to do.');
      counts.status = 'success';
    } else {
      const records = vulnerabilities.map(transformCve);

      console.log(`  Upserting in batches of ${BATCH_SIZE}...`);
      const start = Date.now();

      for (let i = 0; i < records.length; i += BATCH_SIZE) {
        const batch  = records.slice(i, i + BATCH_SIZE);
        const result = await processBatch(batch, vendorMap);
        counts.inserted += result.inserted;
        counts.updated  += result.updated;
        counts.failed   += result.failed;

        if ((i + BATCH_SIZE) % 1000 === 0 || i + BATCH_SIZE >= records.length) {
          const pct  = Math.min(100, Math.round(((i + BATCH_SIZE) / records.length) * 100));
          const secs = ((Date.now() - start) / 1000).toFixed(0);
          console.log(`  Progress: ${Math.min(i + BATCH_SIZE, records.length)}/${records.length} (${pct}%) — ${secs}s elapsed`);
        }
      }

      const elapsed = ((Date.now() - start) / 1000).toFixed(1);
      console.log(`\n[NVD] DB write complete in ${elapsed}s — ${counts.inserted} inserted, ${counts.updated} updated, ${counts.failed} failed`);

      const rawPath = path.join(RAW_PATH, `nvd_${fullMode ? 'full' : 'delta'}_latest.json`);
      fs.writeFileSync(rawPath, JSON.stringify({ count: vulnerabilities.length, timestamp: new Date() }));
      counts.status = 'success';
    }

  } catch (err) {
    counts.error = err.message;
    console.error(`\n[NVD] Failed:`, err.message);
  } finally {
    // IMPORTANT: logComplete and releaseLock MUST complete before pool.end()
    // pool.end() closes all connections immediately — always call it last
    try { await logComplete(pool, logId, counts); } catch (e) { console.error('logComplete failed:', e.message); }
    try { await releaseLock(pool, JOB_NAME);      } catch (e) { console.error('releaseLock failed:', e.message); }
    await pool.end();
  }
}

runNvdIngest();
