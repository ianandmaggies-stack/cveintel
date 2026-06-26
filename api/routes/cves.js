import express from 'express';
import pool from '../db/index.js';
import { requireAuth } from '../middleware/auth.js';
import { stripHtml } from '../utils/sanitise.js';

const router = express.Router();

// Safety net: sanitise any description coming out of the DB
function sanitiseCve(row) {
  if (!row) return row;
  if (row.description)        row.description        = stripHtml(row.description);
  if (row.vulnerability_name) row.vulnerability_name = stripHtml(row.vulnerability_name);
  return row;
}

// GET /api/v1/cves
router.get('/cves', requireAuth, async (req, res) => {
  try {
    const page     = Math.max(1, parseInt(req.query.page)  || 1);
    const limit    = Math.min(100, parseInt(req.query.limit) || 25);
    const offset   = (page - 1) * limit;
    const band     = req.query.band     || null;
    const platform = req.query.platform || null;
    const search   = req.query.search   || null;
    const kev      = req.query.kev      === 'true';
    const exploit  = req.query.exploit  === 'true';
    const preKev   = req.query.pre_kev  === 'true';
    const sortBy   = ['adjusted_score','epss_delta_7d','published_date'].includes(req.query.sort)
      ? req.query.sort : 'adjusted_score';

    const conditions = [];
    const params     = [];

    if (band === 'critical') { conditions.push(`s.adjusted_score >= 75`); }
    else if (band === 'high')   { conditions.push(`s.adjusted_score >= 50 AND s.adjusted_score < 75`); }
    else if (band === 'medium') { conditions.push(`s.adjusted_score >= 25 AND s.adjusted_score < 50`); }
    else if (band === 'low')    { conditions.push(`s.adjusted_score < 25`); }

    if (kev)     conditions.push(`s.kev_member = TRUE`);
    if (exploit)  conditions.push(`s.exploit_available = TRUE`);
    if (preKev)   conditions.push(`s.pre_kev_flag = TRUE`);

    if (platform) {
      params.push(platform);
      conditions.push(`EXISTS (SELECT 1 FROM cve_cpe cp WHERE cp.cve_id = s.cve_id AND cp.platform_tag = $${params.length})`);
    }

    if (search) {
      params.push(`%${search}%`);
      conditions.push(`(s.cve_id ILIKE $${params.length} OR c.description ILIKE $${params.length})`);
    }

    const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

    params.push(limit, offset);
    const dataQ = `
      SELECT
        s.cve_id, s.adjusted_score, s.kev_member,
        s.exploit_available, s.pre_kev_flag, s.epss_delta_7d,
        c.description, c.attack_vector, c.patch_available,
        c.published_date, c.cvss_base
      FROM cve_score s
      JOIN cve_core c ON c.cve_id = s.cve_id
      ${where}
      ORDER BY s.${sortBy} DESC NULLS LAST
      LIMIT $${params.length - 1} OFFSET $${params.length}
    `;

    const countParams = params.slice(0, -2);
    const countQ = `
      SELECT COUNT(*) FROM cve_score s
      JOIN cve_core c ON c.cve_id = s.cve_id
      ${where}
    `;

    const [data, count] = await Promise.all([
      pool.query(dataQ,  params),
      pool.query(countQ, countParams)
    ]);

    res.json({
      data: {
        cves:  data.rows.map(sanitiseCve),
        total: parseInt(count.rows[0].count),
        page,
        limit
      }
    });
  } catch (err) {
    console.error('CVE list error:', err);
    res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'CVE query failed', status: 500 } });
  }
});

// GET /api/v1/cves/:cveId
router.get('/cves/:cveId', requireAuth, async (req, res) => {
  try {
    const { cveId } = req.params;
    const [core, score, kev, epssHistory, exploits, cpes] = await Promise.all([
      pool.query(`SELECT * FROM cve_core  WHERE cve_id = $1`, [cveId]),
      pool.query(`SELECT * FROM cve_score WHERE cve_id = $1`, [cveId]),
      pool.query(`SELECT * FROM cve_kev   WHERE cve_id = $1`, [cveId]),
      pool.query(
        `SELECT snapshot_date, epss_score, percentile FROM cve_epss
         WHERE cve_id = $1 ORDER BY snapshot_date DESC LIMIT 30`,
        [cveId]
      ),
      pool.query(
        `SELECT source, exploit_type, verified, published_date
         FROM cve_exploits WHERE cve_id = $1 ORDER BY published_date DESC`,
        [cveId]
      ),
      pool.query(
        `SELECT DISTINCT vendor, product, version, platform_tag
         FROM cve_cpe WHERE cve_id = $1 LIMIT 20`,
        [cveId]
      )
    ]);

    if (!core.rows[0]) {
      return res.status(404).json({ error: { code: 'NOT_FOUND', message: 'CVE not found', status: 404 } });
    }

    const coreRow = sanitiseCve({ ...core.rows[0] });

    res.json({
      data: {
        core:         coreRow,
        score:        score.rows[0]    || null,
        kev:          kev.rows[0]      || null,
        epss_history: epssHistory.rows,
        exploits:     exploits.rows,
        cpes:         cpes.rows
      }
    });
  } catch (err) {
    console.error('CVE detail error:', err);
    res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'CVE detail query failed', status: 500 } });
  }
});

export default router;
