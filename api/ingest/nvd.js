/**
 * NVD Ingest Job
 * Downloads CVE data from the National Vulnerability Database API
 * Populates cve_core and cve_cpe tables
 * Parses CVSS vectors into individual fields
 * Tags CPEs with platform via platform_vendor_map
 *
 * Source: https://services.nvd.nist.gov/rest/json/cves/2.0
 * Cadence: Daily delta, weekly full
 * Size: ~250k CVEs, 2M+ CPE entries
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

dotenv.config();

const JOB_NAME = 'nvd';
const RAW_PATH = process.env.RAW_FILES_PATH || './ingest/raw';
const NVD_API_KEY = process.env.NVD_API_KEY || null;
const RESULTS_PER_PAGE = 2000;

// Rate limits: 5 req/30s without key, 50 req/30s with key
const RATE_LIMIT_DELAY = NVD_API_KEY ? 700 : 6500;

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
       error_message    = $6
     WHERE log_id = $7`,
    [
      counts.status,
      counts.fetched,
      counts.inserted,
      counts.updated,
      counts.failed,
      counts.error || null,
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

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function fetchPage(url) {
  return new Promise((resolve, reject) => {
    const headers = { 'Accept': 'application/json' };
    if (NVD_API_KEY) headers['apiKey'] = NVD_API_KEY;

    const options = new URL(url);
    const reqOptions = {
      hostname: options.hostname,
      path: options.pathname + options.search,
      headers,
      method: 'GET'
    };

    https.get(reqOptions, (res) => {
      if (res.statusCode === 403) {
        reject(new Error('NVD API key invalid or rate limited'));
        return;
      }
      if (res.statusCode !== 200) {
        reject(new Error(`HTTP ${res.statusCode}`));
        return;
      }
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch (e) {
          reject(new Error('Failed to parse NVD response'));
        }
      });
    }).on('error', reject);
  });
}

async function fetchAllPages(baseUrl) {
  const allVulnerabilities = [];
  let startIndex = 0;
  let totalResults = null;
  let pageNum = 0;

  do {
    const url = `${baseUrl}&resultsPerPage=${RESULTS_PER_PAGE}&startIndex=${startIndex}`;
    pageNum++;

    let retries = 3;
    let page = null;

    while (retries > 0) {
      try {
        page = await fetchPage(url);
        break;
      } catch (err) {
        retries--;
        if (retries === 0) throw err;
        console.log(`  Retry ${3 - retries}/3 after error: ${err.message}`);
        await sleep(RATE_LIMIT_DELAY * 2);
      }
    }

    if (totalResults === null) {
      totalResults = page.totalResults;
      console.log(`  Total CVEs to fetch: ${totalResults}`);
    }

    const vulns = page.vulnerabilities || [];
    allVulnerabilities.push(...vulns);
    startIndex += vulns.length;

    console.log(`  Page ${pageNum}: fetched ${vulns.length} CVEs (${allVulnerabilities.length}/${totalResults})`);

    if (startIndex < totalResults) {
      await sleep(RATE_LIMIT_DELAY);
    }

  } while (startIndex < totalResults);

  return allVulnerabilities;
}

// ============================================
// Transform stage
// ============================================

function parseCvssVector(vector) {
  if (!vector) return {};

  const parts = {};
  const segments = vector.split('/');
  for (const seg of segments) {
    const [key, val] = seg.split(':');
    parts[key] = val;
  }

  const avMap = { N: 'network', A: 'adjacent', L: 'local', P: 'physical' };
  const prMap = { N: 'none', L: 'low', H: 'high' };
  const uiMap = { N: 'none', R: 'required' };
  const scMap = { U: 'unchanged', C: 'changed' };

  return {
    attack_vector:        avMap[parts['AV']] || null,
    privileges_required:  prMap[parts['PR']] || null,
    user_interaction:     uiMap[parts['UI']] || null,
    scope:                scMap[parts['S']]  || null,
  };
}

function extractCvss(cve) {
  const metrics = cve.metrics || {};
  const v31 = metrics.cvssMetricV31?.[0]?.cvssData;
  const v30 = metrics.cvssMetricV30?.[0]?.cvssData;
  const v2  = metrics.cvssMetricV2?.[0]?.cvssData;
  const data = v31 || v30 || v2 || null;
  if (!data) return { cvss_base: null, cvss_vector: null, cvss_version: null, ...parseCvssVector(null) };
  return {
    cvss_base:    data.baseScore   || null,
    cvss_vector:  data.vectorString || null,
    cvss_version: data.version     || null,
    ...parseCvssVector(data.vectorString)
  };
}

function extractCwe(cve) {
  const weaknesses = cve.weaknesses || [];
  for (const w of weaknesses) {
    for (const d of (w.description || [])) {
      if (d.value && d.value.startsWith('CWE-')) return d.value;
    }
  }
  return null;
}

function extractDescription(cve) {
  const descs = cve.descriptions || [];
  const en = descs.find(d => d.lang === 'en');
  return en?.value || null;
}

function extractCpes(cveId, configurations) {
  const cpes = [];
  if (!configurations) return cpes;
  for (const config of configurations) {
    for (const node of (config.nodes || [])) {
      for (const match of (node.cpeMatch || [])) {
        if (!match.vulnerable || !match.criteria) continue;
        const parts   = match.criteria.split(':');
        const vendor  = parts[3] || null;
        const product = parts[4] || null;
        const version = parts[5] || null;
        cpes.push({ cve_id: cveId, cpe_string: match.criteria, vendor, product, version });
      }
    }
  }
  return cpes;
}

function hasPatchReference(cve) {
  const patchTags = ['Patch', 'Vendor Advisory', 'Mitigation'];
  return (cve.references || []).some(r => (r.tags || []).some(t => patchTags.includes(t)));
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
      patch_available:     hasPatchReference(cve),
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
  const result = await pool.query('SELECT vendor_pattern, platform_tag FROM platform_vendor_map');
  const map = new Map();
  for (const row of result.rows) {
    map.set(row.vendor_pattern.toLowerCase(), row.platform_tag);
  }
  return map;
}

function getPlatformTag(vendor, vendorMap) {
  if (!vendor) return 'other';
  const v = vendor.toLowerCase();
  if (vendorMap.has(v)) return vendorMap.get(v);
  for (const [pattern, tag] of vendorMap) {
    if (v.includes(pattern) || pattern.includes(v)) return tag;
  }
  return 'other';
}

// ============================================
// Load stage — ON CONFLICT upsert
// ============================================

async function upsertCveBatch(records, vendorMap) {
  let inserted = 0;
  let updated  = 0;
  let failed   = 0;

  for (const { core, cpes } of records) {
    try {
      // Single upsert — xmax = 0 means inserted, > 0 means updated
      const result = await pool.query(
        `INSERT INTO cve_core (
           cve_id, published_date, modified_date, description,
           cvss_base, cvss_vector, cvss_version, cwe_id,
           patch_available, attack_vector, privileges_required,
           user_interaction, scope, source_updated
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
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
         RETURNING (xmax = 0) AS is_insert`,
        [
          core.cve_id, core.published_date, core.modified_date,
          core.description, core.cvss_base, core.cvss_vector,
          core.cvss_version, core.cwe_id, core.patch_available,
          core.attack_vector, core.privileges_required,
          core.user_interaction, core.scope, core.source_updated
        ]
      );

      if (result.rows.length > 0) {
        if (result.rows[0].is_insert) {
          inserted++;
        } else {
          updated++;
          // Refresh CPEs for updated CVEs
          await pool.query('DELETE FROM cve_cpe WHERE cve_id = $1', [core.cve_id]);
        }
      }
      // If no rows returned, record was unchanged — skip CPE insert

      // Insert CPEs for new or updated records only
      if (result.rows.length > 0 && cpes.length > 0) {
        for (const cpe of cpes) {
          const platformTag = getPlatformTag(cpe.vendor, vendorMap);
          await pool.query(
            `INSERT INTO cve_cpe (cve_id, cpe_string, vendor, product, version, platform_tag)
             VALUES ($1,$2,$3,$4,$5,$6)
             ON CONFLICT DO NOTHING`,
            [cpe.cve_id, cpe.cpe_string, cpe.vendor, cpe.product, cpe.version, platformTag]
          );
        }
      }

    } catch (err) {
      console.error(`Failed to upsert ${core.cve_id}:`, err.message);
      failed++;
    }
  }

  return { inserted, updated, failed };
}

// ============================================
// Main
// ============================================

async function runNvdIngest() {
  const args     = process.argv.slice(2);
  const fullMode = args.includes('--full');

  console.log(`\n[NVD] Starting ${fullMode ? 'FULL' : 'DELTA'} ingest — ${new Date().toISOString()}`);
  if (!NVD_API_KEY) {
    console.warn('  WARNING: No NVD_API_KEY set. Rate limited to 5 req/30s. This will be slow.');
  }

  const logId = await logStart();
  await setLock(true);

  const counts = { status: 'failed', fetched: 0, inserted: 0, updated: 0, failed: 0, error: null };

  try {
    console.log('  Loading vendor map...');
    const vendorMap = await loadVendorMap();
    console.log(`  Loaded ${vendorMap.size} vendor patterns`);

    // Build API URL
    let baseUrl = 'https://services.nvd.nist.gov/rest/json/cves/2.0?';
    if (!fullMode) {
      const endDate   = new Date();
      const startDate = new Date();
      startDate.setDate(startDate.getDate() - 8);
      const fmt = d => d.toISOString().replace('Z', '000');
      baseUrl += `lastModStartDate=${fmt(startDate)}&lastModEndDate=${fmt(endDate)}`;
    } else {
      baseUrl += 'noRejected';
    }

    console.log('  Fetching from NVD API...');
    const vulnerabilities = await fetchAllPages(baseUrl);
    counts.fetched = vulnerabilities.length;
    console.log(`  Fetched ${vulnerabilities.length} CVEs total`);

    if (vulnerabilities.length === 0) {
      console.log('  No CVEs in window — nothing to do');
      counts.status = 'success';
      await logComplete(logId, counts);
      await setLock(false);
      return;
    }

    console.log('  Transforming CVE records...');
    const records = vulnerabilities.map(transformCve);

    console.log('  Upserting CVE records...');
    const batchSize = 500;
    for (let i = 0; i < records.length; i += batchSize) {
      const batch  = records.slice(i, i + batchSize);
      const result = await upsertCveBatch(batch, vendorMap);
      counts.inserted += result.inserted;
      counts.updated  += result.updated;
      counts.failed   += result.failed;
      if (i % 5000 === 0 && i > 0) {
        console.log(`  Progress: ${i}/${records.length} CVEs processed...`);
      }
    }

    const rawPath = path.join(RAW_PATH, `nvd_${fullMode ? 'full' : 'delta'}_latest.json`);
    fs.writeFileSync(rawPath, JSON.stringify({ count: vulnerabilities.length, timestamp: new Date() }));

    counts.status = 'success';
    console.log(`\n[NVD] Complete — ${counts.inserted} inserted, ${counts.updated} updated, ${counts.failed} failed`);

  } catch (err) {
    counts.error = err.message;
    console.error(`\n[NVD] Failed:`, err.message);
  } finally {
    await logComplete(logId, counts);
    await setLock(false);
    pool.end();
  }
}

runNvdIngest();
