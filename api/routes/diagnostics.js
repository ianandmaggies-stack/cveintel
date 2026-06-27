import express from 'express';
import pool from '../db/index.js';
import { requireAuth } from '../middleware/auth.js';

const router = express.Router();

const STUCK_THRESHOLD_HOURS = 4;

router.get('/diagnostics', requireAuth, async (req, res) => {
  try {
    const safe = async (label, fn) => {
      try { return await fn(); }
      catch (e) { console.error(`Diagnostics [${label}]:`, e.message); return null; }
    };

    const [tableCountsRes, ingestStatusRes, recentLogsRes, lastSuccessRes, lastSkippedRes, snapshotCountRes, dbSizeRes, tableSizesRes, connectRes] = await Promise.all([

      safe('table_counts', () => pool.query(`
        SELECT relname AS table_name, n_live_tup AS row_count
        FROM pg_stat_user_tables
        WHERE relname IN (
          'cve_core','cve_epss','cve_kev','cve_score','cve_exploits',
          'cve_cpe','threat_actors','geopolitical_events','global_risk_snapshot','ingest_log'
        ) ORDER BY relname
      `)),

      safe('ingest_status', () => pool.query(`
        SELECT job_name, is_running, started_at,
          EXTRACT(EPOCH FROM (NOW() - started_at)) / 3600 AS running_hours
        FROM ingest_status ORDER BY job_name
      `)),

      safe('recent_logs', () => pool.query(`
        SELECT job_name, started_at, completed_at, status,
               records_fetched, records_inserted, records_updated, records_failed, error_message,
               EXTRACT(EPOCH FROM (completed_at - started_at))::INT AS duration_seconds
        FROM ingest_log ORDER BY started_at DESC LIMIT 50
      `)),

      // Last successful run per job
      safe('last_success', () => pool.query(`
        SELECT DISTINCT ON (job_name)
               job_name, started_at AS last_success_at, completed_at,
               records_fetched, records_inserted, records_updated,
               EXTRACT(EPOCH FROM (NOW() - completed_at)) / 3600 AS hours_ago
        FROM ingest_log
        WHERE status = 'success'
        ORDER BY job_name, started_at DESC
      `)),

      // Last skipped run per job (skipped = healthy, data unchanged)
      safe('last_skipped', () => pool.query(`
        SELECT DISTINCT ON (job_name)
               job_name, started_at AS last_skipped_at, completed_at,
               EXTRACT(EPOCH FROM (NOW() - completed_at)) / 3600 AS hours_ago
        FROM ingest_log
        WHERE status = 'skipped'
        ORDER BY job_name, started_at DESC
      `)),

      safe('snapshot_count', () => pool.query(`SELECT COUNT(*) FROM global_risk_snapshot`)),

      safe('db_size', () => pool.query(`
        SELECT pg_size_pretty(pg_database_size(current_database())) AS total_size,
               pg_database_size(current_database()) AS total_bytes
      `)),

      safe('table_sizes', () => pool.query(`
        SELECT t.tbl,
               CASE WHEN to_regclass(t.tbl) IS NOT NULL
                    THEN pg_size_pretty(pg_total_relation_size(to_regclass(t.tbl)))
                    ELSE 'n/a' END AS size
        FROM (VALUES ('cve_core'),('cve_cpe'),('cve_epss'),('cve_score'),('cve_exploits')) AS t(tbl)
      `)),

      safe('connect', () => pool.query(`SELECT NOW() AS db_time`)),
    ]);

    const logsByJob = {};
    for (const row of (recentLogsRes?.rows || [])) {
      if (!logsByJob[row.job_name]) logsByJob[row.job_name] = [];
      if (logsByJob[row.job_name].length < 10) logsByJob[row.job_name].push(row);
    }

    const lastSuccessMap = {};
    for (const row of (lastSuccessRes?.rows  || [])) lastSuccessMap[row.job_name]  = row;

    const lastSkippedMap = {};
    for (const row of (lastSkippedRes?.rows  || [])) lastSkippedMap[row.job_name]  = row;

    // Build job health — skipped counts as healthy (data unchanged is fine)
    const jobHealth = {};
    for (const s of (ingestStatusRes?.rows || [])) {
      const lastSuccess = lastSuccessMap[s.job_name] || null;
      const lastSkipped = lastSkippedMap[s.job_name] || null;
      const lastRun     = logsByJob[s.job_name]?.[0]  || null;
      const runningHours = parseFloat(s.running_hours || 0);
      const isStuck      = s.is_running && runningHours > STUCK_THRESHOLD_HOURS;

      // Most recent positive outcome — either a success or a skip (no change = healthy)
      const lastPositive = (() => {
        if (!lastSuccess && !lastSkipped) return null;
        if (!lastSuccess) return { ...lastSkipped, via: 'skipped' };
        if (!lastSkipped) return { ...lastSuccess, via: 'success' };
        return new Date(lastSuccess.last_success_at) > new Date(lastSkipped.last_skipped_at)
          ? { ...lastSuccess, via: 'success' }
          : { ...lastSkipped, via: 'skipped' };
      })();

      let healthStatus;
      if (isStuck)                              healthStatus = 'stuck';
      else if (s.is_running)                    healthStatus = 'running';
      else if (!lastRun)                        healthStatus = 'never_run';
      else if (lastRun.status === 'success')    healthStatus = 'ok';
      else if (lastRun.status === 'skipped')    healthStatus = 'ok';      // skipped = data unchanged = healthy
      else if (lastRun.status === 'failed')     healthStatus = 'failed';
      else                                      healthStatus = 'unknown';

      jobHealth[s.job_name] = {
        job_name:            s.job_name,
        is_running:          s.is_running,
        running_hours:       runningHours,
        is_stuck:            isStuck,
        health_status:       healthStatus,
        last_run:            lastRun,
        last_success:        lastSuccess,
        last_positive:       lastPositive,
        hours_since_positive: lastPositive ? parseFloat(lastPositive.hours_ago) : null,
      };
    }

    const tableSizeMap = {};
    for (const row of (tableSizesRes?.rows || [])) tableSizeMap[row.tbl] = row.size;

    const dbSize   = dbSizeRes?.rows[0] || { total_size: 'unknown' };
    const dbOnline = !!connectRes?.rows[0]?.db_time;

    res.json({
      data: {
        generated_at:  new Date().toISOString(),
        db_online:     dbOnline,
        table_counts:  tableCountsRes?.rows  || [],
        ingest_status: ingestStatusRes?.rows || [],
        job_health:    jobHealth,
        logs_by_job:   logsByJob,
        snapshot_days: parseInt(snapshotCountRes?.rows[0]?.count || 0),
        db_size: {
          total_size:        dbSize.total_size,
          cve_core_size:     tableSizeMap['cve_core']     || 'n/a',
          cve_cpe_size:      tableSizeMap['cve_cpe']      || 'n/a',
          cve_epss_size:     tableSizeMap['cve_epss']     || 'n/a',
          cve_score_size:    tableSizeMap['cve_score']    || 'n/a',
          cve_exploits_size: tableSizeMap['cve_exploits'] || 'n/a',
        },
      }
    });

  } catch (err) {
    console.error('Diagnostics fatal:', err);
    res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: err.message, status: 500 } });
  }
});

export default router;
