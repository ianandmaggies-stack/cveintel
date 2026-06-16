import express from 'express';
import pool from '../db/index.js';
import { requireAuth } from '../middleware/auth.js';

const router = express.Router();

router.get('/clients/:clientId/posture', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        COUNT(*) FILTER (WHERE adjusted_score >= 75) AS critical,
        COUNT(*) FILTER (WHERE adjusted_score >= 50 AND adjusted_score < 75) AS high,
        COUNT(*) FILTER (WHERE adjusted_score >= 25 AND adjusted_score < 50) AS medium,
        COUNT(*) FILTER (WHERE adjusted_score < 25) AS low,
        COUNT(*) FILTER (WHERE kev_member = TRUE) AS kev_total,
        COUNT(*) FILTER (WHERE pre_kev_flag = TRUE) AS pre_kev_total,
        ROUND(AVG(adjusted_score)::numeric, 2) AS avg_score
      FROM cve_score
    `);
    res.json({ data: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'Posture query failed', status: 500 } });
  }
});

export default router;
