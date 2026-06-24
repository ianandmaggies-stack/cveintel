/**
 * Score Refresh Job
 * Calculates combined risk scores for all CVEs
 * Also populates global_risk_snapshot for trend tracking
 */

import dotenv from 'dotenv';
import pool from '../db/index.js';

dotenv.config();

const JOB_NAME = 'score_refresh';

async function logStart() {
  const result = await pool.query(
    `INSERT INTO ingest_log (job_name, started_at, status) VALUES ($1, NOW(), 'running') RETURNING log_id`,
    [JOB_NAME]
  );
  return result.rows[0].log_id;
}

async function logComplete(logId, counts) {
  await pool.query(
    `UPDATE ingest_log SET completed_at=NOW(), status=$1, records_updated=$2, records_failed=$3, error_message=$4 WHERE log_id=$5`,
    [counts.status, counts.updated, counts.failed, counts.error || null, logId]
  );
}

async function setLock(isRunning) {
  await pool.query(
    `UPDATE ingest_status SET is_running=$1, started_at=$2 WHERE job_name=$3`,
    [isRunning, isRunning ? new Date() : null, JOB_NAME]
  );
}

function calcVelocityPoints(delta7d) {
  if (!delta7d || delta7d <= 0) return 0;
  if (delta7d < 0.1) return 3;
  if (delta7d < 0.3) return 6;
  return 10;
}

function calcAttackVectorModifier(attackVector) {
  return { network: 1.00, adjacent: 0.85, local: 0.75, physical: 0.60 }[attackVector] || 1.00;
}

function calcPreKevScore(epssScore, delta7d, exploitAvailable, cvssBase, attackVector, daysSincePublished, patchAvailable) {
  let score = 0;
  if (epssScore > 0.4)            score += 2;
  if (delta7d > 0.2)              score += 2;
  if (exploitAvailable)           score += 2;
  if (cvssBase > 7.0)             score += 1;
  if (attackVector === 'network') score += 1;
  if (daysSincePublished > 14)    score += 1;
  if (!patchAvailable)            score += 1;
  return score;
}

function calculateScore(cve) {
  const cvssPoints     = cve.cvss_base ? (parseFloat(cve.cvss_base) / 10) * 20 : 0;
  const epssScore      = parseFloat(cve.epss_score || 0);
  const epssPoints     = epssScore * 25;
  const delta7d        = parseFloat(cve.epss_delta_7d || 0);
  const velocityPoints = calcVelocityPoints(delta7d);
  const kevPoints      = cve.kev_member ? 25 : 0;
  const exploitPoints  = (!cve.kev_member && cve.exploit_available) ? 10 : 0;
  const patchPoints    = (!cve.patch_available) ? 10 : 0;
  const combinedScore  = Math.min(100, cvssPoints + epssPoints + velocityPoints + kevPoints + exploitPoints + patchPoints);
  const avModifier     = calcAttackVectorModifier(cve.attack_vector);
  const adjustedScore  = Math.min(100, combinedScore * avModifier);
  const daysSince      = cve.published_date ? Math.floor((Date.now() - new Date(cve.published_date)) / 86400000) : 0;
  const preKevScore    = cve.kev_member ? 0 : calcPreKevScore(epssScore, delta7d, cve.exploit_available, parseFloat(cve.cvss_base || 0), cve.attack_vector, daysSince, cve.patch_available);

  return {
    combined_score:          parseFloat(combinedScore.toFixed(2)),
    adjusted_score:          parseFloat(adjustedScore.toFixed(2)),
    kev_member:              cve.kev_member || false,
    exploit_available:       cve.exploit_available || false,
    epss_pending:            !cve.epss_score,
    attack_vector_modifier:  parseFloat(avModifier.toFixed(2)),
    cross_platform_modifier: 1.00,
    pre_kev_score:           preKevScore,
    pre_kev_flag:            preKevScore >= 5,
  };
}

async function refreshScores() {
  console.log('  Building combined CVE dataset...');
  const result = await pool.query(`
    SELECT c.cve_id, c.cvss_base, c.attack_vector, c.patch_available, c.published_date,
           e.epss_score, s.epss_delta_1d, s.epss_delta_7d,
           CASE WHEN k.cve_id IS NOT NULL THEN TRUE ELSE FALSE END AS kev_member,
           CASE WHEN ex.cve_id IS NOT NULL THEN TRUE ELSE FALSE END AS exploit_available
    FROM cve_core c
    LEFT JOIN (SELECT DISTINCT ON (cve_id) cve_id, epss_score FROM cve_epss ORDER BY cve_id, snapshot_date DESC) e ON e.cve_id = c.cve_id
    LEFT JOIN cve_score s ON s.cve_id = c.cve_id
    LEFT JOIN cve_kev k ON k.cve_id = c.cve_id
    LEFT JOIN (SELECT DISTINCT cve_id FROM cve_exploits) ex ON ex.cve_id = c.cve_id
  `);
  console.log(`  Loaded ${result.rows.length} CVEs for scoring`);
  return result.rows;
}

async function writeScoresBulk(rows) {
  console.log('  Writing scores via bulk upsert...');
  const chunkSize = 5000;
  let updated = 0, failed = 0;

  for (let i = 0; i < rows.length; i += chunkSize) {
    const chunk  = rows.slice(i, i + chunkSize);
    const values = [];
    const params = [];
    let p = 1;

    for (const row of chunk) {
      const score = calculateScore(row);
      if (values.length === 0) {
        values.push(`($${p++}::text,$${p++}::numeric,$${p++}::numeric,$${p++}::numeric,$${p++}::numeric,$${p++}::boolean,$${p++}::boolean,$${p++}::boolean,$${p++}::numeric,$${p++}::numeric,$${p++}::integer,$${p++}::boolean)`);
      } else {
        values.push(`($${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++})`);
      }
      params.push(row.cve_id, score.combined_score, score.adjusted_score, row.epss_delta_1d||null, row.epss_delta_7d||null, score.kev_member, score.exploit_available, score.epss_pending, score.attack_vector_modifier, score.cross_platform_modifier, score.pre_kev_score, score.pre_kev_flag);
    }

    try {
      await pool.query(`
        INSERT INTO cve_score (cve_id,combined_score,adjusted_score,epss_delta_1d,epss_delta_7d,kev_member,exploit_available,epss_pending,attack_vector_modifier,cross_platform_modifier,pre_kev_score,pre_kev_flag,score_updated)
        SELECT cve_id,combined_score::numeric,adjusted_score::numeric,epss_delta_1d::numeric,epss_delta_7d::numeric,kev_member::boolean,exploit_available::boolean,epss_pending::boolean,attack_vector_modifier::numeric,cross_platform_modifier::numeric,pre_kev_score::integer,pre_kev_flag::boolean,NOW()
        FROM (VALUES ${values.join(',')}) AS v(cve_id,combined_score,adjusted_score,epss_delta_1d,epss_delta_7d,kev_member,exploit_available,epss_pending,attack_vector_modifier,cross_platform_modifier,pre_kev_score,pre_kev_flag)
        ON CONFLICT (cve_id) DO UPDATE SET
          combined_score=EXCLUDED.combined_score, adjusted_score=EXCLUDED.adjusted_score,
          epss_delta_1d=EXCLUDED.epss_delta_1d, epss_delta_7d=EXCLUDED.epss_delta_7d,
          kev_member=EXCLUDED.kev_member, exploit_available=EXCLUDED.exploit_available,
          epss_pending=EXCLUDED.epss_pending, attack_vector_modifier=EXCLUDED.attack_vector_modifier,
          cross_platform_modifier=EXCLUDED.cross_platform_modifier,
          pre_kev_score=EXCLUDED.pre_kev_score, pre_kev_flag=EXCLUDED.pre_kev_flag,
          score_updated=NOW()
      `, params);
      updated += chunk.length;
    } catch (err) {
      console.error(`Chunk ${i} failed:`, err.message);
      failed += chunk.length;
    }

    if (i % 50000 === 0 && i > 0) console.log(`  Scored ${i} / ${rows.length} CVEs...`);
  }

  return { updated, failed };
}

// ============================================
// Global risk snapshot — daily trend data
// ============================================

async function writeGlobalSnapshot() {
  console.log('  Writing global risk snapshot...');

  const today = new Date().toISOString().split('T')[0];

  // Get yesterday's KEV count to calculate new additions today
  const yesterday = await pool.query(
    `SELECT kev_total FROM global_risk_snapshot
     WHERE snapshot_date = CURRENT_DATE - 1`
  );
  const prevKev = parseInt(yesterday.rows[0]?.kev_total || 0);

  // Get yesterday's CVE count for new_cves_today
  const prevCves = await pool.query(
    `SELECT total_cves FROM global_risk_snapshot
     WHERE snapshot_date = CURRENT_DATE - 1`
  );
  const prevTotal = parseInt(prevCves.rows[0]?.total_cves || 0);

  const stats = await pool.query(`
    SELECT
      COUNT(*) AS total_cves,
      COUNT(*) FILTER (WHERE adjusted_score >= 75) AS critical_count,
      COUNT(*) FILTER (WHERE adjusted_score >= 50 AND adjusted_score < 75) AS high_count,
      COUNT(*) FILTER (WHERE adjusted_score >= 25 AND adjusted_score < 50) AS medium_count,
      COUNT(*) FILTER (WHERE adjusted_score < 25) AS low_count,
      COUNT(*) FILTER (WHERE kev_member = TRUE) AS kev_total,
      COUNT(*) FILTER (WHERE pre_kev_flag = TRUE) AS pre_kev_count,
      COUNT(*) FILTER (WHERE exploit_available = TRUE) AS exploit_count
    FROM cve_score
  `);

  const s = stats.rows[0];

  await pool.query(`
    INSERT INTO global_risk_snapshot (
      snapshot_date, total_cves, critical_count, high_count, medium_count, low_count,
      kev_total, kev_added_today, pre_kev_count, exploit_count, new_cves_today
    ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
    ON CONFLICT (snapshot_date) DO UPDATE SET
      total_cves     = EXCLUDED.total_cves,
      critical_count = EXCLUDED.critical_count,
      high_count     = EXCLUDED.high_count,
      medium_count   = EXCLUDED.medium_count,
      low_count      = EXCLUDED.low_count,
      kev_total      = EXCLUDED.kev_total,
      kev_added_today = EXCLUDED.kev_added_today,
      pre_kev_count  = EXCLUDED.pre_kev_count,
      exploit_count  = EXCLUDED.exploit_count,
      new_cves_today = EXCLUDED.new_cves_today
  `, [
    today,
    parseInt(s.total_cves),
    parseInt(s.critical_count),
    parseInt(s.high_count),
    parseInt(s.medium_count),
    parseInt(s.low_count),
    parseInt(s.kev_total),
    Math.max(0, parseInt(s.kev_total) - prevKev),
    parseInt(s.pre_kev_count),
    parseInt(s.exploit_count),
    Math.max(0, parseInt(s.total_cves) - prevTotal)
  ]);

  console.log(`  Global snapshot written for ${today}`);
}

// ============================================
// Main
// ============================================

async function runScoreRefresh() {
  console.log(`\n[SCORE] Starting refresh — ${new Date().toISOString()}`);
  const logId = await logStart();
  await setLock(true);
  const counts = { status: 'failed', updated: 0, failed: 0, error: null };

  try {
    const rows   = await refreshScores();
    const result = await writeScoresBulk(rows);
    counts.updated = result.updated;
    counts.failed  = result.failed;
    counts.status  = result.failed === 0 ? 'success' : 'partial';

    // Write daily snapshot for trend tracking
    await writeGlobalSnapshot();

    const stats = await pool.query(`
      SELECT
        COUNT(*) FILTER (WHERE adjusted_score >= 75) AS critical,
        COUNT(*) FILTER (WHERE adjusted_score >= 50 AND adjusted_score < 75) AS high,
        COUNT(*) FILTER (WHERE adjusted_score >= 25 AND adjusted_score < 50) AS medium,
        COUNT(*) FILTER (WHERE adjusted_score < 25) AS low,
        COUNT(*) FILTER (WHERE kev_member = TRUE) AS kev_count,
        COUNT(*) FILTER (WHERE pre_kev_flag = TRUE) AS pre_kev_count,
        COUNT(*) FILTER (WHERE exploit_available = TRUE) AS exploit_count
      FROM cve_score
    `);

    const s = stats.rows[0];
    console.log(`\n[SCORE] Complete — ${counts.updated} scores calculated, ${counts.failed} failed`);
    console.log(`  CRITICAL: ${s.critical}`);
    console.log(`  HIGH:     ${s.high}`);
    console.log(`  MEDIUM:   ${s.medium}`);
    console.log(`  LOW:      ${s.low}`);
    console.log(`  KEV:      ${s.kev_count}`);
    console.log(`  PRE-KEV:  ${s.pre_kev_count}`);
    console.log(`  EXPLOIT:  ${s.exploit_count}`);

  } catch (err) {
    counts.error = err.message;
    console.error(`\n[SCORE] Failed:`, err.message);
  } finally {
    await logComplete(logId, counts);
    await setLock(false);
    pool.end();
  }
}

runScoreRefresh();
