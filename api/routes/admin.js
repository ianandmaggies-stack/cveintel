import express from 'express';
import pool from '../db/index.js';
import { requireAuth, requireAdmin } from '../middleware/auth.js';

const router = express.Router();

router.use(requireAuth, requireAdmin);

router.get('/ingest/status', async (req, res) => {
  try {
    const [status, recentLogs] = await Promise.all([
      pool.query('SELECT * FROM ingest_status ORDER BY job_name'),
      pool.query(`SELECT log_id, job_name, status, records_fetched, records_inserted, records_updated, records_failed, started_at, completed_at, error_message FROM ingest_log ORDER BY log_id DESC LIMIT 20`)
    ]);
    res.json({ data: { jobs: status.rows, recent_logs: recentLogs.rows } });
  } catch (err) {
    res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'Status query failed', status: 500 } });
  }
});

router.get('/system/health', async (req, res) => {
  try {
    const [cveCount, epssCount, kevCount, scoreCount] = await Promise.all([
      pool.query('SELECT COUNT(*) as count FROM cve_core'),
      pool.query('SELECT COUNT(*) as count FROM cve_epss'),
      pool.query('SELECT COUNT(*) as count FROM cve_kev'),
      pool.query('SELECT COUNT(*) as count FROM cve_score')
    ]);
    res.json({
      data: {
        database: 'healthy',
        counts: {
          cve_core:  parseInt(cveCount.rows[0].count),
          cve_epss:  parseInt(epssCount.rows[0].count),
          cve_kev:   parseInt(kevCount.rows[0].count),
          cve_score: parseInt(scoreCount.rows[0].count)
        },
        timestamp: new Date().toISOString()
      }
    });
  } catch (err) {
    res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'Health check failed', status: 500 } });
  }
});

export default router;
