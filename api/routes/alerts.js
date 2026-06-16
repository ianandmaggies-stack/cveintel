import express from 'express';
import pool from '../db/index.js';
import { requireAuth } from '../middleware/auth.js';

const router = express.Router();

router.get('/clients/:clientId/alerts', requireAuth, async (req, res) => {
  const { page = 1, limit = 25, type } = req.query;
  const offset = (parseInt(page) - 1) * parseInt(limit);
  try {
    const conditions = ['client_id = $1'];
    const params     = [req.params.clientId];
    let   p          = 2;
    if (type) { conditions.push(`alert_type = $${p++}`); params.push(type); }
    const where = `WHERE ${conditions.join(' AND ')}`;
    const [countResult, dataResult] = await Promise.all([
      pool.query(`SELECT COUNT(*) as total FROM client_alerts ${where}`, params),
      pool.query(`SELECT * FROM client_alerts ${where} ORDER BY triggered_at DESC LIMIT $${p} OFFSET $${p+1}`, [...params, parseInt(limit), offset])
    ]);
    const total = parseInt(countResult.rows[0].total);
    res.json({ data: dataResult.rows, meta: { total, page: parseInt(page), limit: parseInt(limit), pages: Math.ceil(total / parseInt(limit)) } });
  } catch (err) {
    console.error('Alerts error:', err);
    res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'Alerts query failed', status: 500 } });
  }
});

export default router;
