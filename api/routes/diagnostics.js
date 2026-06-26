import express from 'express';
import pool from '../db/index.js';
import { requireAuth } from '../middleware/auth.js';

const router = express.Router();

// GET /api/v1/diagnostics
router.get('/diagnostics', requireAuth, async (req, res) => {
  try {
    const [tableCounts, ingestStatus, recentLogs, snapshotCount, dbSize, indexHealth] = await Promise.all([

      // Row counts for all major tables
      pool.query(`
        SELECT table_name, n_live_tup AS row_count
        FROM pg_stat_user_tables
        WHERE table_name IN (
          'cve_core','cve_epss','cve_kev','cve_score',
          'cve_exploits','cve_cpe','threat_actors',
          'geopolitical_events','global_risk_snapshot','ingest_log'
        )
        ORDER BY table_name
      `),

      // Current lock status of each ingest job
      pool.query(`
        SELECT job_name, is_running, started_at
        FROM ingest_status
        ORDER BY job_name
      `),

      // Last 10 runs per job
      pool.query(`
        SELECT job_name, started_at, completed_at, status,
               records_fetched, records_inserted, records_updated,
               records_failed, error_message,
               EXTRACT(EPOCH FROM (completed_at - started_at))::INT AS duration_seconds
        FROM ingest_log
        ORDER BY started_at DESC
        LIMIT 40
      `),

      // Snapshot history count
      pool.query(`SELECT COUNT(*) FROM global_risk_snapshot`),

      // Database size
      pool.query(`
        SELECT
          pg_size_pretty(pg_database_size(current_database())) AS total_size,
          pg_database_size(current_database()) AS total_bytes,
          pg_size_pretty(pg_total_relation_size('cve_core'))    AS cve_core_size,
          pg_size_pretty(pg_total_relation_size('cve_cpe'))     AS cve_cpe_size,
          pg_size_pretty(pg_total_relation_size('cve_epss'))    AS cve_epss_size,
          pg_size_pretty(pg_total_relation_size('cve_score'))   AS cve_score_size,
          pg_size_pretty(pg_total_relation_size('cve_exploits')) AS cve_exploits_size
      `),

      // Index usage — catch any unused indexes
      pool.query(`
        SELECT indexrelname AS index_name,
               relname AS table_name,
               idx_scan AS scans,
               idx_tup_read AS tuples_read
        FROM pg_stat_user_indexes
        ORDER BY idx_scan DESC
        LIMIT 20
      `),
    ]);

    // Pivot logs per job for last-10-per-job view
    const logsByJob = {};
    for (const row of recentLogs.rows) {
      if (!logsByJob[row.job_name]) logsByJob[row.job_name] = [];
      if (logsByJob[row.job_name].length < 10) logsByJob[row.job_name].push(row);
    }

    res.json({
      data: {
        generated_at:    new Date().toISOString(),
        table_counts:    tableCounts.rows,
        ingest_status:   ingestStatus.rows,
        logs_by_job:     logsByJob,
        snapshot_days:   parseInt(snapshotCount.rows[0].count),
        db_size:         dbSize.rows[0],
        index_health:    indexHealth.rows,
      }
    });
  } catch (err) {
    console.error('Diagnostics error:', err);
    res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: err.message, status: 500 } });
  }
});

export default router;
