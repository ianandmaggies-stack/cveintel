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

const JOB_NAME = 'nvd';
const RAW_PATH = process.env.RAW_FILES_PATH || './ingest/raw';
const NVD_API_KEY = process.env.NVD_API_KEY || null;
const RESULTS_PER_PAGE = 2000;
const RATE_LIMIT_DELAY = NVD_API_KEY ? 700 : 6500;

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
  let startIndex = 0, total = null, page = 0;
  do {
    const url = `${baseUrl}&resultsPerPage=${RESULTS_PER_PAGE}&startIndex=${startIndex}`;
    page++;
    let retries = 3, result = null;
    while (retries > 0) {
      try { result = await fetchPage(url); break; }
      catch (err) {
        retries--;
        if (retries === 0) throw err;
        console.log(`  Retry ${3-retries}/3: ${err.message}`);
        await sleep(RATE_LIMIT_DELAY * 2);
      }
    }
    if (total === null) { total = result.totalResults; console.log(`  Total CVEs: ${total}`); }
    const vulns = result.vulnerabilities || [];
    all.push(...vulns);
    startIndex += vulns.length;
    console.log(`  Page ${page}: ${vulns.length} fetched (${all.length}/${total})`);
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
  for (const seg of vector.split('/')) { const [k,v] = seg.split(':'); p[k] = v; }
  return {
    attack_vector:       ({ N:'network', A:'adjacent', L:'local', P:'physical' })[p['AV']] || null,
    privileges_required: ({ N:'none', L:'low', H:'high' })[p['PR']] || null,
    user_interaction:    ({ N:'none', R:'required' })[p['UI']] || null,
    scope:               ({ U:'unchanged', C:'changed' })[p['S']] || null,
  };
}

function extractCvss(cve) {
  const m = cve.metrics || {};
  const data = m.cvssMetricV31?.[0]?.cvssData || m.cvssMetricV30?.[0]?.cvssData || m.cvssMetricV2?.[0]?.cvssData || null;
  if (!data) return { cvss_base: null, cvss_vector: null, cvss_version: null, ...parseCvssVector(null) };
  return { cvss_base: data.baseScore, cvss_vector: data.vectorString, cvss_version: data.version, ...parseCvssVector(data.vectorString) };
}

function extractCwe(cve) {
  for (const w of (cve.weaknesses || []))
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
          cpes.push({ cve_id: cveId, cpe_string: match.criteria, vendor: p[3]||null, product: p[4]||null, version: p[5]||null });
        }
  return cpes;
}

function hasPatch(cve) {
  const tags = ['Patch','Vendor Advisory','Mitigation'];
  return (cve.references||[]).some(r => (r.tags||[]).some(t => tags.includes(t)));
}

function transformCve(item) {
  const cve = item.cve;
  const cvss = extractCvss(cve);
  return {
    core: {
      cve_id: cve.id,
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
      source_updated:      new Date()
    },
    cpes: extractCpes(cve.id, cve.configurations)
  };
}

// ============================================
// Platform tagging
// ============================================

async function loadVendorMap() {
  const r = await pool.query('SELECT vendor_pattern, platform_tag FROM platform_vendor_map');
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
// Upsert
// ============================================

async function upsertCveBatch(records, vendorMap) {
  let inserted = 0, updated = 0, failed = 0;
  for (const { core, cpes } of records) {
    try {
      const r = await pool.query(
        `INSERT INTO cve_core (
           cve_id, published_date, modified_date, description,
           cvss_base, cvss_vector, cvss_version, cwe_id,
           patch_available, attack_vector, privileges_required,
           user_interaction, scope, source_updated
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
         ON CONFLICT (cve_id) DO UPDATE SET
           modified_date = EXCLUDED.modified_date, description = EXCLUDED.description,
           cvss_base = EXCLUDED.cvss_base, cvss_vector = EXCLUDED.cvss_vector,
           cvss_version = EXCLUDED.cvss_version, cwe_id = EXCLUDED.cwe_id,
           patch_available = EXCLUDED.patch_available, attack_vector = EXCLUDED.attack_vector,
           privileges_required = EXCLUDED.privileges_required,
           user_interaction = EXCLUDED.user_interaction, scope = EXCLUDED.scope,
           source_updated = EXCLUDED.source_updated
         WHERE cve_core.modified_date IS DISTINCT FROM EXCLUDED.modified_date
         RETURNING (xmax = 0) AS is_insert`,
        [core.cve_id, core.published_date, core.modified_date, core.description,
         core.cvss_base, core.cvss_vector, core.cvss_version, core.cwe_id,
         core.patch_available, core.attack_vector, core.privileges_required,
         core.user_interaction, core.scope, core.source_updated]
      );
      if (r.rows.length > 0) {
        if (r.rows[0].is_insert) { inserted++; }
        else { updated++; await pool.query('DELETE FROM cve_cpe WHERE cve_id = $1', [core.cve_id]); }
        for (const cpe of cpes) {
          await pool.query(
            `INSERT INTO cve_cpe (cve_id, cpe_string, vendor, product, version, platform_tag)
             VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`,
            [cpe.cve_id, cpe.cpe_string, cpe.vendor, cpe.product, cpe.version, getPlatformTag(cpe.vendor, vendorMap)]
          );
        }
      }
    } catch (err) { console.error(`Failed ${core.cve_id}:`, err.message); failed++; }
  }
  return { inserted, updated, failed };
}

// ============================================
// Main
// ============================================

async function runNvdIngest() {
  const fullMode = process.argv.includes('--full');
  console.log(`\n[NVD] Starting ${fullMode ? 'FULL' : 'DELTA'} ingest — ${new Date().toISOString()}`);
  if (!NVD_API_KEY) console.warn('  WARNING: No NVD_API_KEY. Rate limited to 5 req/30s.');

  // Acquire lock — auto-clears stale locks older than 6h
  const locked = await acquireLock(pool, JOB_NAME);
  if (!locked) { await pool.end(); return; }

  const logId = await logStart(pool, JOB_NAME);
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

    if (vulnerabilities.length === 0) {
      console.log('  No CVEs in window — nothing to do');
      counts.status = 'success';
    } else {
      const records = vulnerabilities.map(transformCve);
      const batchSize = 500;
      for (let i = 0; i < records.length; i += batchSize) {
        const r = await upsertCveBatch(records.slice(i, i + batchSize), vendorMap);
        counts.inserted += r.inserted;
        counts.updated  += r.updated;
        counts.failed   += r.failed;
        if (i % 5000 === 0 && i > 0) console.log(`  Progress: ${i}/${records.length}`);
      }
      const rawPath = path.join(RAW_PATH, `nvd_${fullMode ? 'full' : 'delta'}_latest.json`);
      fs.writeFileSync(rawPath, JSON.stringify({ count: vulnerabilities.length, timestamp: new Date() }));
      counts.status = 'success';
      console.log(`\n[NVD] Complete — ${counts.inserted} inserted, ${counts.updated} updated, ${counts.failed} failed`);
    }

  } catch (err) {
    counts.error = err.message;
    console.error(`\n[NVD] Failed:`, err.message);
  } finally {
    await logComplete(pool, logId, counts);
    await releaseLock(pool, JOB_NAME);
    pool.end();
  }
}

runNvdIngest();
