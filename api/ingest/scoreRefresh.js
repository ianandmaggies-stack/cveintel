/**
 * Score Refresh Job
 * Calculates combined risk scores for all CVEs
 * Reads from cve_core, cve_epss, cve_kev, cve_exploits
 * Writes to cve_score
 *
 * Scoring algorithm:
 *   cvss_points      = (cvss_base / 10) * 20        max 20
 *   epss_points      = epss_score * 25               max 25
 *   velocity_points  = stepped(epss_delta_7d)        max 10
 *   kev_points       = kev_member ? 25 : 0           max 25
 *   exploit_points   = exploit_available ? 10 : 0    max 10
 *   patch_points     = !patch_available ? 10 : 0     max 10
 *
 *   combined_score   = MIN(100, sum of above)
 *   adjusted_score   = combined_score * attack_vector_modifier * cross_platform_modifier
 *
 * Cadence: After each ingest job completes
 */

import dotenv from 'dotenv';
import pool from '../db/index.js';

dotenv.config();

const JOB_NAME = 'score_refresh';

// ============================================
// Logging
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
       records_updated  = $2,
       records_failed   = $3,
       error_message    = $4
     WHERE log_id = $5`,
    [counts.status, counts.updated, counts.failed, counts.error || null, logId]
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
// Scoring helpers
// ============================================

function calcVelocityPoints(delta7d) {
  if (!delta7d || delta7d <= 0) return 0;
  if (delta7d < 0.1) return 3;
  if (delta7d < 0.3) return 6;
  return 10;
}

function calcAttackVectorModifier(attackVector) {
  const map = {
    network:  1.00,
    adjacent: 0.85,
    local:    0.75,
    physical: 0.60,
  };
  return map[attackVector] || 1.00;
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

  const combinedScore = Math.min(100,
    cvssPoints + epssPoints + velocityPoints + kevPoints + exploitPoints + patchPoints
  );

  const avModifier    = calcAttackVectorModifier(cve.attack_vector);
  const adjustedScore = Math.min(100, combinedScore * avModifier);

  const daysSincePublished = cve.published_date
    ? Math.floor((Date.now() - new Date(cve.published_date)) / 86400000)
    : 0;

  const preKevScore = cve.kev_member ? 0 : calcPreKevScore(
    epssScore, delta7d, cve.exploit_available,
    parseFloat(cve.cvss_base || 0), cve.attack_vector,
    daysSincePublished, cve.patch_available
  );

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

// ============================================
// Main refresh logic
// ============================================

async function refreshScores() {
  console.log('  Building combined CVE dataset...');

  const result = await pool.query(`
    SELECT
      c.cve_id,
      c.cvss_base,
      c.attack_vector,
      c.patch_available,
      c.published_date,
      e.epss_score,
      s.epss_delta_1d,
      s.epss_delta_7d,
      CASE WHEN k.cve_id IS NOT NULL THEN TRUE ELSE FALSE END AS kev_member,
      CASE WHEN ex.cve_id IS NOT NULL THEN TRUE ELSE FALSE END AS exploit_available
    FROM cve_core c
    LEFT JOIN (
      SELECT DISTINCT ON (cve_id) cve_id, epss_score
      FROM cve_epss
      ORDER BY cve_id, snapshot_date DESC
    ) e ON e.cve_id = c.cve_id
    LEFT JOIN cve_score s ON s.cve_id = c.cve_id
    LEFT JOIN cve_kev k ON k.cve_id = c.cve_id
    LEFT JOIN (
      SELECT DISTINCT cve_id FROM cve_exploits
    ) ex ON ex.cve_id = c.cve_id
  `);

  console.log(`  Loaded ${result.rows.length} CVEs for scoring`);
  return result.rows;
}

async function writeScoresBulk(rows) {
  console.log('  Writing scores via bulk upsert...');

  const chunkSize = 5000;
  let updated = 0;
  let failed  = 0;

  for (let i = 0; i < rows.length; i += chunkSize) {
    const chunk = rows.slice(i, i + chunkSize);

    const values = [];
    const params = [];
    let p = 1;

    for (const row of chunk) {
      const score = calculateScore(row);
      // Explicit casts on first row so PostgreSQL knows the types
      // for subsequent rows in the same VALUES clause
      if (values.length === 0) {
        values.push(
          `($${p++}::text, $${p++}::numeric, $${p++}::numeric,` +
          ` $${p++}::numeric, $${p++}::numeric,` +
          ` $${p++}::boolean, $${p++}::boolean, $${p++}::boolean,` +
          ` $${p++}::numeric, $${p++}::numeric,` +
          ` $${p++}::integer, $${p++}::boolean)`
        );
      } else {
        values.push(`($${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++})`);
      }
      params.push(
        row.cve_id,
        score.combined_score,
        score.adjusted_score,
        row.epss_delta_1d  || null,
        row.epss_delta_7d  || null,
        score.kev_member,
        score.exploit_available,
        score.epss_pending,
        score.attack_vector_modifier,
        score.cross_platform_modifier,
        score.pre_kev_score,
        score.pre_kev_flag
      );
    }

    try {
      await pool.query(`
        INSERT INTO cve_score (
          cve_id, combined_score, adjusted_score,
          epss_delta_1d, epss_delta_7d,
          kev_member, exploit_available, epss_pending,
          attack_vector_modifier, cross_platform_modifier,
          pre_kev_score, pre_kev_flag,
          score_updated
        )
        SELECT
          cve_id,
          combined_score::numeric,
          adjusted_score::numeric,
          epss_delta_1d::numeric,
          epss_delta_7d::numeric,
          kev_member::boolean,
          exploit_available::boolean,
          epss_pending::boolean,
          attack_vector_modifier::numeric,
          cross_platform_modifier::numeric,
          pre_kev_score::integer,
          pre_kev_flag::boolean,
          NOW()
        FROM (
          VALUES ${values.join(',')}
        ) AS v(
          cve_id, combined_score, adjusted_score,
          epss_delta_1d, epss_delta_7d,
          kev_member, exploit_available, epss_pending,
          attack_vector_modifier, cross_platform_modifier,
          pre_kev_score, pre_kev_flag
        )
        ON CONFLICT (cve_id) DO UPDATE SET
          combined_score          = EXCLUDED.combined_score,
          adjusted_score          = EXCLUDED.adjusted_score,
          epss_delta_1d           = EXCLUDED.epss_delta_1d,
          epss_delta_7d           = EXCLUDED.epss_delta_7d,
          kev_member              = EXCLUDED.kev_member,
          exploit_available       = EXCLUDED.exploit_available,
          epss_pending            = EXCLUDED.epss_pending,
          attack_vector_modifier  = EXCLUDED.attack_vector_modifier,
          cross_platform_modifier = EXCLUDED.cross_platform_modifier,
          pre_kev_score           = EXCLUDED.pre_kev_score,
          pre_kev_flag            = EXCLUDED.pre_kev_flag,
          score_updated           = NOW()
      `, params);

      updated += chunk.length;
    } catch (err) {
      console.error(`Chunk ${i} failed:`, err.message);
      failed += chunk.length;
    }

    if (i % 50000 === 0 && i > 0) {
      console.log(`  Scored ${i} / ${rows.length} CVEs...`);
    }
  }

  return { updated, failed };
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

    const stats = await pool.query(`
      SELECT
        COUNT(*) FILTER (WHERE adjusted_score >= 75) AS critical,
        COUNT(*) FILTER (WHERE adjusted_score >= 50 AND adjusted_score < 75) AS high,
        COUNT(*) FILTER (WHERE adjusted_score >= 25 AND adjusted_score < 50) AS medium,
        COUNT(*) FILTER (WHERE adjusted_score < 25) AS low,
        COUNT(*) FILTER (WHERE kev_member = TRUE) AS kev_count,
        COUNT(*) FILTER (WHERE pre_kev_flag = TRUE) AS pre_kev_count
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
