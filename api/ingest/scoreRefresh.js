/**
 * Score Refresh Job
 * Calculates combined risk scores for all CVEs
 * Also writes global_risk_snapshot for trend tracking
 */

import dotenv from 'dotenv';
import pool from '../db/index.js';
import { acquireLock, releaseLock, logStart, logComplete } from './ingestLock.js';

dotenv.config();

const JOB_NAME = 'score_refresh';

function calcVelocityPoints(delta7d) {
  if (!delta7d || delta7d <= 0) return 0;
  if (delta7d < 0.1) return 3;
  if (delta7d < 0.3) return 6;
  return 10;
}

function calcAttackVectorModifier(v) {
  return ({ network: 1.00, adjacent: 0.85, local: 0.75, physical: 0.60 })[v] || 1.00;
}

function calcPreKevScore(epss, delta7d, exploit, cvss, av, days, noPatch) {
  let s = 0;
  if (epss > 0.4)        s += 2;
  if (delta7d > 0.2)     s += 2;
  if (exploit)           s += 2;
  if (cvss > 7.0)        s += 1;
  if (av === 'network')  s += 1;
  if (days > 14)         s += 1;
  if (!noPatch)          s += 1;
  return s;
}

function calculateScore(cve) {
  const cvssPoints     = cve.cvss_base ? (parseFloat(cve.cvss_base) / 10) * 20 : 0;
  const epssScore      = parseFloat(cve.epss_score || 0);
  const epssPoints     = epssScore * 25;
  const delta7d        = parseFloat(cve.epss_delta_7d || 0);
  const velocityPoints = calcVelocityPoints(delta7d);
  const kevPoints      = cve.kev_member ? 25 : 0;
  const exploitPoints  = (!cve.kev_member && cve.exploit_available) ? 10 : 0;
  const patchPoints    = !cve.patch_available ? 10 : 0;
  const combined       = Math.min(100, cvssPoints + epssPoints + velocityPoints + kevPoints + exploitPoints + patchPoints);
  const avMod          = calcAttackVectorModifier(cve.attack_vector);
  const adjusted       = Math.min(100, combined * avMod);
  const days           = cve.published_date ? Math.floor((Date.now() - new Date(cve.published_date)) / 86400000) : 0;
  const preKevScore    = cve.kev_member ? 0 : calcPreKevScore(epssScore, delta7d, cve.exploit_available, parseFloat(cve.cvss_base || 0), cve.attack_vector, days, cve.patch_available);
  return {
    combined_score:         parseFloat(combined.toFixed(2)),
    adjusted_score:         parseFloat(adjusted.toFixed(2)),
    kev_member:             cve.kev_member || false,
    exploit_available:      cve.exploit_available || false,
    epss_pending:           !cve.epss_score,
    attack_vector_modifier: parseFloat(avMod.toFixed(2)),
    cross_platform_modifier: 1.00,
    pre_kev_score:          preKevScore,
    pre_kev_flag:           preKevScore >= 5,
  };
}

async function refreshScores() {
  console.log('  Loading CVE dataset...');
  const r = await pool.query(`
    SELECT c.cve_id, c.cvss_base, c.attack_vector, c.patch_available, c.published_date,
           e.epss_score, s.epss_delta_1d, s.epss_delta_7d,
           CASE WHEN k.cve_id  IS NOT NULL THEN TRUE ELSE FALSE END AS kev_member,
           CASE WHEN ex.cve_id IS NOT NULL THEN TRUE ELSE FALSE END AS exploit_available
    FROM cve_core c
    LEFT JOIN (SELECT DISTINCT ON (cve_id) cve_id, epss_score FROM cve_epss ORDER BY cve_id, snapshot_date DESC) e ON e.cve_id = c.cve_id
    LEFT JOIN cve_score s  ON s.cve_id  = c.cve_id
    LEFT JOIN cve_kev k    ON k.cve_id  = c.cve_id
    LEFT JOIN (SELECT DISTINCT cve_id FROM cve_exploits) ex ON ex.cve_id = c.cve_id
  `);
  console.log(`  Loaded ${r.rows.length} CVEs`);
  return r.rows;
}

async function writeScoresBulk(rows) {
  console.log('  Writing scores...');
  const chunkSize = 5000;
  let updated = 0, failed = 0;
  for (let i = 0; i < rows.length; i += chunkSize) {
    const chunk = rows.slice(i, i + chunkSize);
    const values = [], params = [];
    let p = 1;
    for (const row of chunk) {
      const s = calculateScore(row);
      if (values.length === 0) {
        values.push(`($${p++}::text,$${p++}::numeric,$${p++}::numeric,$${p++}::numeric,$${p++}::numeric,$${p++}::boolean,$${p++}::boolean,$${p++}::boolean,$${p++}::numeric,$${p++}::numeric,$${p++}::integer,$${p++}::boolean)`);
      } else {
        values.push(`($${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++})`);
      }
      params.push(row.cve_id, s.combined_score, s.adjusted_score, row.epss_delta_1d||null, row.epss_delta_7d||null,
        s.kev_member, s.exploit_available, s.epss_pending, s.attack_vector_modifier, s.cross_platform_modifier, s.pre_kev_score, s.pre_kev_flag);
    }
    try {
      await pool.query(`
        INSERT INTO cve_score (cve_id,combined_score,adjusted_score,epss_delta_1d,epss_delta_7d,kev_member,exploit_available,epss_pending,attack_vector_modifier,cross_platform_modifier,pre_kev_score,pre_kev_flag,score_updated)
        SELECT cve_id,combined_score::numeric,adjusted_score::numeric,epss_delta_1d::numeric,epss_delta_7d::numeric,kev_member::boolean,exploit_available::boolean,epss_pending::boolean,attack_vector_modifier::numeric,cross_platform_modifier::numeric,pre_kev_score::integer,pre_kev_flag::boolean,NOW()
        FROM (VALUES ${values.join(',')}) AS v(cve_id,combined_score,adjusted_score,epss_delta_1d,epss_delta_7d,kev_member,exploit_available,epss_pending,attack_vector_modifier,cross_platform_modifier,pre_kev_score,pre_kev_flag)
        ON CONFLICT (cve_id) DO UPDATE SET
          combined_score=EXCLUDED.combined_score, adjusted_score=EXCLUDED.adjusted_score,
          epss_delta_1d=EXCLUDED.epss_delta_1d,   epss_delta_7d=EXCLUDED.epss_delta_7d,
          kev_member=EXCLUDED.kev_member,           exploit_available=EXCLUDED.exploit_available,
          epss_pending=EXCLUDED.epss_pending,       attack_vector_modifier=EXCLUDED.attack_vector_modifier,
          cross_platform_modifier=EXCLUDED.cross_platform_modifier,
          pre_kev_score=EXCLUDED.pre_kev_score,     pre_kev_flag=EXCLUDED.pre_kev_flag,
          score_updated=NOW()
      `, params);
      updated += chunk.length;
    } catch (err) { console.error(`Chunk ${i} failed:`, err.message); failed += chunk.length; }
    if (i % 50000 === 0 && i > 0) console.log(`  Scored ${i}/${rows.length}...`);
  }
  return { updated, failed };
}

async function writeGlobalSnapshot() {
  console.log('  Writing global risk snapshot...');
  const today = new Date().toISOString().split('T')[0];
  const [prevKevRow, prevCvesRow, stats] = await Promise.all([
    pool.query(`SELECT kev_total   FROM global_risk_snapshot WHERE snapshot_date = CURRENT_DATE - 1`),
    pool.query(`SELECT total_cves  FROM global_risk_snapshot WHERE snapshot_date = CURRENT_DATE - 1`),
    pool.query(`
      SELECT COUNT(*) AS total_cves,
        COUNT(*) FILTER (WHERE adjusted_score >= 75)                       AS critical_count,
        COUNT(*) FILTER (WHERE adjusted_score >= 50 AND adjusted_score < 75) AS high_count,
        COUNT(*) FILTER (WHERE adjusted_score >= 25 AND adjusted_score < 50) AS medium_count,
        COUNT(*) FILTER (WHERE adjusted_score < 25)                        AS low_count,
        COUNT(*) FILTER (WHERE kev_member = TRUE)                          AS kev_total,
        COUNT(*) FILTER (WHERE pre_kev_flag = TRUE)                        AS pre_kev_count,
        COUNT(*) FILTER (WHERE exploit_available = TRUE)                   AS exploit_count
      FROM cve_score
    `),
  ]);
  const s       = stats.rows[0];
  const prevKev = parseInt(prevKevRow.rows[0]?.kev_total  || 0);
  const prevTot = parseInt(prevCvesRow.rows[0]?.total_cves || 0);
  await pool.query(`
    INSERT INTO global_risk_snapshot
      (snapshot_date,total_cves,critical_count,high_count,medium_count,low_count,
       kev_total,kev_added_today,pre_kev_count,exploit_count,new_cves_today)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
    ON CONFLICT (snapshot_date) DO UPDATE SET
      total_cves=EXCLUDED.total_cves, critical_count=EXCLUDED.critical_count,
      high_count=EXCLUDED.high_count,  medium_count=EXCLUDED.medium_count,
      low_count=EXCLUDED.low_count,    kev_total=EXCLUDED.kev_total,
      kev_added_today=EXCLUDED.kev_added_today, pre_kev_count=EXCLUDED.pre_kev_count,
      exploit_count=EXCLUDED.exploit_count,     new_cves_today=EXCLUDED.new_cves_today
  `, [
    today,
    parseInt(s.total_cves), parseInt(s.critical_count), parseInt(s.high_count),
    parseInt(s.medium_count), parseInt(s.low_count), parseInt(s.kev_total),
    Math.max(0, parseInt(s.kev_total) - prevKev),
    parseInt(s.pre_kev_count), parseInt(s.exploit_count),
    Math.max(0, parseInt(s.total_cves) - prevTot),
  ]);
  console.log(`  Snapshot written for ${today}`);
}

async function runScoreRefresh() {
  console.log(`\n[SCORE] Starting refresh — ${new Date().toISOString()}`);

  const locked = await acquireLock(pool, JOB_NAME);
  if (!locked) { await pool.end(); return; }

  const logId  = await logStart(pool, JOB_NAME);
  const counts = { status: 'failed', updated: 0, failed: 0, error: null };

  try {
    const rows   = await refreshScores();
    const result = await writeScoresBulk(rows);
    counts.updated = result.updated;
    counts.failed  = result.failed;
    counts.status  = result.failed === 0 ? 'success' : 'partial';
    await writeGlobalSnapshot();

    const stats = await pool.query(`
      SELECT
        COUNT(*) FILTER (WHERE adjusted_score >= 75)                         AS critical,
        COUNT(*) FILTER (WHERE adjusted_score >= 50 AND adjusted_score < 75) AS high,
        COUNT(*) FILTER (WHERE kev_member = TRUE)                            AS kev_count,
        COUNT(*) FILTER (WHERE pre_kev_flag = TRUE)                          AS pre_kev_count,
        COUNT(*) FILTER (WHERE exploit_available = TRUE)                     AS exploit_count
      FROM cve_score
    `);
    const s = stats.rows[0];
    console.log(`\n[SCORE] Complete — ${counts.updated} scored`);
    console.log(`  CRITICAL: ${s.critical}  HIGH: ${s.high}  KEV: ${s.kev_count}  PRE-KEV: ${s.pre_kev_count}  EXPLOIT: ${s.exploit_count}`);

  } catch (err) {
    counts.error = err.message;
    console.error(`\n[SCORE] Failed:`, err.message);
  } finally {
    try { await logComplete(pool, logId, counts); } catch (e) { console.error('logComplete failed:', e.message); }
    try { await releaseLock(pool, JOB_NAME);      } catch (e) { console.error('releaseLock failed:', e.message); }
    await pool.end();
  }
}

runScoreRefresh();
