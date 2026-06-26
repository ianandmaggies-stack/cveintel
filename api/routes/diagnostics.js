import express from 'express';
import pool from '../db/index.js';
import { requireAuth } from '../middleware/auth.js';

const router = express.Router();

// GET /api/v1/diagnostics
router.get('/diagnostics', requireAuth, async (req, res) => {
  try {

    // Run each query independently so one failure doesn't kill the whole page
    const safe = async (label, fn) => {
      try { return await fn(); }
      catch (e) { console.error(`Diagnostics [${label}]:`, e.message); return null; }
    };

    const [
      tableCountsRes,
      ingestStatusRes,
      recentLogsRes,
      snapshotCountRes,
      dbSizeRes,
      tableSizesRes,
    ] = await Promise.all([

      safe('table_counts', () => pool.query(`
        SELECT relname AS table_name,
               n_live_tup AS row_count
        FROM pg_stat_user_tables
        WHERE relname IN (
          'cve_core','cve_epss','cve_kev','cve_score',
          'cve_exploits','cve_cpe','threat_actors',
          'geopolitical_events','global_risk_snapshot','ingest_log'
        )
        ORDER BY relname
      `)),

      safe('ingest_status', () => pool.query(`
        SELECT job_name, is_running, started_at
        FROM ingest_status
        ORDER BY job_name
      `)),

      safe('recent_logs', () => pool.query(`
        SELECT job_name, started_at, completed_at, status,
               records_fetched, records_inserted, records_updated,
               records_failed, error_message,
               EXTRACT(EPOCH FROM (completed_at - started_at))::INT AS duration_seconds
        FROM ingest_log
        ORDER BY started_at DESC
        LIMIT 50
      `)),

      safe('snapshot_count', () => pool.query(`
        SELECT COUNT(*) FROM global_risk_snapshot
      `)),

      safe('db_size', () => pool.query(`
        SELECT pg_size_pretty(pg_database_size(current_database())) AS total_size,
               pg_database_size(current_database()) AS total_bytes
      `)),

      // Table sizes — use to_regclass to avoid errors on missing tables
      safe('table_sizes', () => pool.query(`
        SELECT t.tbl,
               CASE WHEN to_regclass(t.tbl) IS NOT NULL
                    THEN pg_size_pretty(pg_total_relation_size(to_regclass(t.tbl)))
                    ELSE 'n/a'
               END AS size
        FROM (VALUES
          ('cve_core'),('cve_cpe'),('cve_epss'),
          ('cve_score'),('cve_exploits')
        ) AS t(tbl)
      `)),

    ]);

    // Pivot logs per job
    const logsByJob = {};
    for (const row of (recentLogsRes?.rows || [])) {
      if (!logsByJob[row.job_name]) logsByJob[row.job_name] = [];
      if (logsByJob[row.job_name].length < 10) logsByJob[row.job_name].push(row);
    }

    // Table size map
    const tableSizeMap = {};
    for (const row of (tableSizesRes?.rows || [])) {
      tableSizeMap[row.tbl] = row.size;
    }

    const dbSize = dbSizeRes?.rows[0] || { total_size: 'unknown', total_bytes: 0 };

    res.json({
      data: {
        generated_at:  new Date().toISOString(),
        table_counts:  tableCountsRes?.rows  || [],
        ingest_status: ingestStatusRes?.rows || [],
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
    console.error('Diagnostics fatal error:', err);
    res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: err.message, status: 500 } });
  }
});

export default router;
