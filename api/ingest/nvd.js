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

  // Prefer CVSS v3.1, fall back to v3.0, then v2
  const v31 = metrics.cvssMetricV31?.[0]?.cvssData;
  const v30 = metrics.cvssMetricV30?.[0]?.cvssData;
  const v2  = metrics.cvssMetricV2?.[0]?.cvssData;

  const data = v31 || v30 || v2 || null;
  if (!data) return { cvss_base: null, cvss_vector: null, cvss_version: null, ...parseCvssVector(null) };

  return {
    cvss_base:    data.baseScore || null,
    cvss_vector:  data.vectorString || null,
    cvss_version: data.version || null,
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
    const nodes = config.nodes || [];
    for (const node of nodes) {
      const matches = node.cpeMatch || [];
      for (const match of matches) {
        if (!match.vulnerable) continue;
        const cpe = match.criteria;
        if (!cpe) continue;

        // Parse CPE string: cpe:2.3:type:vendor:product:version:...
        const parts = cpe.split(':');
        const vendor  = parts[3] || null;
        const product = parts[4] || null;
        const version = parts[5] || null;

        cpes.push({ cve_id: cveId, cpe_string: cpe, vendor, product, version });
      }
    }
  }
  return cpes;
}

function hasPatchReference(cve) {
  const refs = cve.references || [];
  const patchTags = ['Patch', 'Vendor Advisory', 'Mitigation'];
  return refs.some(r => (r.tags || []).some(t => patchTags.includes(t)));
}

function transformCve(item) {
  const cve = item.cve;
  const cveId = cve.id;
  const cvss = extractCvss(cve);

  return {
    core: {
      cve_id:              cveId,
      published_date:      cve.published?.split('T')[0] || null,
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
    cpes: extractCpes(cveId, cve.configurations)
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
  // Exact match first
  if (vendorMap.has(v)) return vendorMap.get(v);
  // Partial match
  for (const [pattern, tag] of vendorMap) {
    if (v.includes(pattern) || pattern.includes(v)) return tag;
  }
  return 'other';
}

// ============================================
// Load stage
// ============================================

async function upsertCveBatch(records, vendorMap) {
  let inserted = 0;
  let updated = 0;
  let failed = 0;

  for (const record of records) {
    const { core, cpes } = record;

    try {
      // Check if exists
      const existing = await pool.query(
        'SELECT cve_id, modified_date FROM cve_core WHERE cve_id = $1',
        [core.cve_id]
      );

      if (existing.rows.length === 0) {
        // Insert new
        await pool.query(
          `INSERT INTO cve_core (
             cve_id, published_date, modified_date, description,
             cvss_base, cvss_vector, cvss_version, cwe_id,
             patch_available, attack_vector, privileges_required,
             user_interaction, scope, source_updated
           ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
          [
            core.cve_id, core.published_date, core.modified_date,
            core.description, core.cvss_base, core.cvss_vector,
            core.cvss_version, core.cwe_id, core.patch_available,
            core.attack_vector, core.privileges_required,
            core.user_interaction, core.scope, core.source_updated
          ]
        );
        inserted++;
      } else {
        // Only update if modified date is newer
        const existingDate = existing.rows[0].modified_date;
        if (!existingDate || core.modified_date > existingDate.toISOString().split('T')[0]) {
          await pool.query(
            `UPDATE cve_core SET
               modified_date = $2, description = $3,
               cvss_base = $4, cvss_vector = $5, cvss_version = $6,
               cwe_id = $7, patch_available = $8, attack_vector = $9,
               privileges_required = $10, user_interaction = $11,
               scope = $12, source_updated = $13
             WHERE cve_id = $1`,
            [
              core.cve_id, core.modified_date, core.description,
              core.cvss_base, core.cvss_vector, core.cvss_version,
              core.cwe_id, core.patch_available, core.attack_vector,
              core.privileges_required, core.user_interaction,
              core.scope, core.source_updated
            ]
          );
          updated++;

          // Refresh CPEs for updated CVEs
          await pool.query('DELETE FROM cve_cpe WHERE cve_id = $1', [core.cve_id]);
        } else {
          continue; // No change needed
        }
      }

      // Insert CPEs
      for (const cpe of cpes) {
        const platformTag = getPlatformTag(cpe.vendor, vendorMap);
        await pool.query(
          `INSERT INTO cve_cpe (cve_id, cpe_string, vendor, product, version, platform_tag)
           VALUES ($1, $2, $3, $4, $5, $6)`,
          [cpe.cve_id, cpe.cpe_string, cpe.vendor, cpe.product, cpe.version, platformTag]
        );
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
  // Check for delta vs full mode
  // Delta: last 8 days of changes (daily run)
  // Full: no date filter (weekly run or first run)
  const args = process.argv.slice(2);
  const fullMode = args.includes('--full');

  console.log(`\n[NVD] Starting ${fullMode ? 'FULL' : 'DELTA'} ingest — ${new Date().toISOString()}`);
  if (!NVD_API_KEY) {
    console.warn('  WARNING: No NVD_API_KEY set. Rate limited to 5 req/30s. This will be slow.');
  }

  const logId = await logStart();
  await setLock(true);

  const counts = {
    status:   'failed',
    fetched:  0,
    inserted: 0,
    updated:  0,
    failed:   0,
    error:    null,
  };

  try {
    // Load vendor map for platform tagging
    console.log('  Loading vendor map...');
    const vendorMap = await loadVendorMap();
    console.log(`  Loaded ${vendorMap.size} vendor patterns`);

    // Build URL
    let baseUrl = 'https://services.nvd.nist.gov/rest/json/cves/2.0?';
    if (!fullMode) {
      // Delta: changes in last 8 days
      const endDate   = new Date();
      const startDate = new Date();
      startDate.setDate(startDate.getDate() - 8);
      const fmt = d => d.toISOString().replace('Z', '000');
      baseUrl += `lastModStartDate=${fmt(startDate)}&lastModEndDate=${fmt(endDate)}`;
    } else {
      baseUrl += 'noRejected';
    }

    // Fetch all pages
    console.log(`  Fetching from NVD API...`);
    const vulnerabilities = await fetchAllPages(baseUrl);
    counts.fetched = vulnerabilities.length;
    console.log(`  Fetched ${vulnerabilities.length} CVEs total`);

    if (vulnerabilities.length === 0 && !fullMode) {
      console.log('  No changes in delta window — nothing to do');
      counts.status = 'success';
      await logComplete(logId, counts);
      await setLock(false);
      return;
    }

    // Transform
    console.log('  Transforming CVE records...');
    const records = vulnerabilities.map(transformCve);

    // Load in batches of 500
    console.log('  Upserting CVE records...');
    const batchSize = 500;
    for (let i = 0; i < records.length; i += batchSize) {
      const batch = records.slice(i, i + batchSize);
      const result = await upsertCveBatch(batch, vendorMap);
      counts.inserted += result.inserted;
      counts.updated  += result.updated;
      counts.failed   += result.failed;

      if (i % 5000 === 0 && i > 0) {
        console.log(`  Progress: ${i}/${records.length} CVEs processed...`);
      }
    }

    // Save a record of what we fetched
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
