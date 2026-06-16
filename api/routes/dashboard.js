import express from 'express';
import pool from '../db/index.js';
import { requireAuth } from '../middleware/auth.js';

const router = express.Router();

// GET /api/v1/clients/:clientId/dashboard
router.get('/clients/:clientId/dashboard', requireAuth, async (req, res) => {
  try {
    const [bands, topCritical, trending, platforms] = await Promise.all([

      pool.query(`
        SELECT
          COUNT(*) FILTER (WHERE adjusted_score >= 75) AS critical,
          COUNT(*) FILTER (WHERE adjusted_score >= 50 AND adjusted_score < 75) AS high,
          COUNT(*) FILTER (WHERE adjusted_score >= 25 AND adjusted_score < 50) AS medium,
          COUNT(*) FILTER (WHERE adjusted_score < 25) AS low,
          COUNT(*) FILTER (WHERE kev_member = TRUE) AS kev_total,
          COUNT(*) FILTER (WHERE pre_kev_flag = TRUE) AS pre_kev_total
        FROM cve_score
      `),

      pool.query(`
        SELECT
          s.cve_id, s.adjusted_score, s.kev_member,
          s.exploit_available, s.pre_kev_flag,
          c.description, c.attack_vector, c.patch_available,
          c.user_interaction, c.scope
        FROM cve_score s
        JOIN cve_core c ON c.cve_id = s.cve_id
        WHERE s.adjusted_score >= 75
        ORDER BY s.adjusted_score DESC
        LIMIT 10
      `),

      pool.query(`
        SELECT
          s.cve_id, s.adjusted_score, s.epss_delta_7d,
          c.description, c.attack_vector
        FROM cve_score s
        JOIN cve_core c ON c.cve_id = s.cve_id
        WHERE s.epss_delta_7d > 0
        ORDER BY s.epss_delta_7d DESC
        LIMIT 5
      `),

      pool.query(`
        SELECT
          cp.platform_tag,
          COUNT(DISTINCT s.cve_id) FILTER (WHERE s.adjusted_score >= 75) AS critical,
          COUNT(DISTINCT s.cve_id) FILTER (WHERE s.kev_member = TRUE) AS kev
        FROM cve_score s
        JOIN cve_cpe cp ON cp.cve_id = s.cve_id
        GROUP BY cp.platform_tag
        ORDER BY critical DESC
      `)
    ]);

    const stats = bands.rows[0];
    res.json({
      data: {
        summary: {
          critical:      parseInt(stats.critical),
          high:          parseInt(stats.high),
          medium:        parseInt(stats.medium),
          low:           parseInt(stats.low),
          kev_total:     parseInt(stats.kev_total),
          pre_kev_total: parseInt(stats.pre_kev_total)
        },
        top_critical: topCritical.rows,
        trending:     trending.rows,
        platforms:    platforms.rows
      }
    });
  } catch (err) {
    console.error('Dashboard error:', err);
    res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'Dashboard query failed', status: 500 } });
  }
});

export default router;
