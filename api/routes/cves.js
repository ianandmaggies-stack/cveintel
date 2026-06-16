import express from 'express';
import pool from '../db/index.js';
import { requireAuth } from '../middleware/auth.js';

const router = express.Router();

const VALID_BANDS     = ['critical', 'high', 'medium', 'low'];
const VALID_PLATFORMS = ['microsoft', 'linux', 'network', 'other'];
const VALID_SORT      = ['score', 'date', 'velocity'];

// GET /api/v1/clients/:clientId/cves
router.get('/clients/:clientId/cves', requireAuth, async (req, res) => {
  const { band, platform, exposure, kev, exploit, user_interaction, scope, sort = 'score', page = 1, limit = 25 } = req.query;

  if (band && !VALID_BANDS.includes(band)) {
    return res.status(400).json({ error: { code: 'INVALID_FILTER', message: 'Invalid band value', valid_values: VALID_BANDS, status: 400 } });
  }
  if (platform && !VALID_PLATFORMS.includes(platform)) {
    return res.status(400).json({ error: { code: 'INVALID_FILTER', message: 'Invalid platform value', valid_values: VALID_PLATFORMS, status: 400 } });
  }
  if (sort && !VALID_SORT.includes(sort)) {
    return res.status(400).json({ error: { code: 'INVALID_FILTER', message: 'Invalid sort value', valid_values: VALID_SORT, status: 400 } });
  }

  const offset     = (parseInt(page) - 1) * parseInt(limit);
  const conditions = [];
  const params     = [];
  let   p          = 1;

  if (band) {
    const ranges = { critical: [75,100], high: [50,74.99], medium: [25,49.99], low: [0,24.99] };
    const [min, max] = ranges[band];
    conditions.push(`s.adjusted_score >= $${p++} AND s.adjusted_score <= $${p++}`);
    params.push(min, max);
  }
  if (kev === 'true')     conditions.push('s.kev_member = TRUE');
  if (exploit === 'true') conditions.push('s.exploit_available = TRUE');
  if (user_interaction)  { conditions.push(`c.user_interaction = $${p++}`); params.push(user_interaction); }
  if (scope)             { conditions.push(`c.scope = $${p++}`);            params.push(scope); }
  if (exposure === 'external') conditions.push("c.attack_vector = 'network'");
  if (exposure === 'internal') conditions.push("c.attack_vector IN ('local','adjacent')");

  const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
  const joinClause  = platform ? `JOIN cve_cpe cp ON cp.cve_id = s.cve_id AND cp.platform_tag = $${p++}` : '';
  if (platform) params.push(platform);

  const sortMap = { score: 's.adjusted_score DESC', date: 'c.published_date DESC', velocity: 's.epss_delta_7d DESC NULLS LAST' };
  const orderBy = sortMap[sort];

  try {
    const [countResult, dataResult] = await Promise.all([
      pool.query(`SELECT COUNT(DISTINCT s.cve_id) as total FROM cve_score s JOIN cve_core c ON c.cve_id = s.cve_id ${joinClause} ${whereClause}`, params),
      pool.query(
        `SELECT s.cve_id, s.adjusted_score, s.kev_member, s.exploit_available, s.pre_kev_flag,
                s.epss_delta_7d, c.description, c.cvss_base, c.attack_vector,
                c.user_interaction, c.scope, c.patch_available, c.published_date
         FROM cve_score s
         JOIN cve_core c ON c.cve_id = s.cve_id
         ${joinClause}
         ${whereClause}
         ORDER BY ${orderBy}
         LIMIT $${p} OFFSET $${p+1}`,
        [...params, parseInt(limit), offset]
      )
    ]);

    const total = parseInt(countResult.rows[0].total);
    res.json({
      data: dataResult.rows,
      meta: { total, page: parseInt(page), limit: parseInt(limit), pages: Math.ceil(total / parseInt(limit)), applied_filters: { band, platform, exposure, kev, sort } }
    });
  } catch (err) {
    console.error('CVE list error:', err);
    res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'CVE query failed', status: 500 } });
  }
});

// GET /api/v1/clients/:clientId/cves/:cveId
router.get('/clients/:clientId/cves/:cveId', requireAuth, async (req, res) => {
  const { cveId } = req.params;
  try {
    const [cveResult, epssHistory, cpeResult] = await Promise.all([
      pool.query(
        `SELECT c.*, s.combined_score, s.adjusted_score, s.kev_member, s.exploit_available,
                s.pre_kev_flag, s.pre_kev_score, s.epss_delta_1d, s.epss_delta_7d,
                s.attack_vector_modifier, s.epss_pending, s.score_updated,
                k.date_added AS kev_date_added, k.required_action AS kev_required_action
         FROM cve_core c
         LEFT JOIN cve_score s ON s.cve_id = c.cve_id
         LEFT JOIN cve_kev k ON k.cve_id = c.cve_id
         WHERE c.cve_id = $1`, [cveId]
      ),
      pool.query(`SELECT snapshot_date, epss_score, percentile FROM cve_epss WHERE cve_id = $1 ORDER BY snapshot_date DESC LIMIT 30`, [cveId]),
      pool.query(`SELECT cpe_string, vendor, product, version, platform_tag FROM cve_cpe WHERE cve_id = $1 LIMIT 20`, [cveId])
    ]);

    if (cveResult.rows.length === 0) {
      return res.status(404).json({ error: { code: 'CVE_NOT_FOUND', message: `${cveId} not found`, status: 404 } });
    }

    const cve       = cveResult.rows[0];
    const cvssBase  = parseFloat(cve.cvss_base || 0);
    const epssScore = parseFloat(epssHistory.rows[0]?.epss_score || 0);
    const delta7d   = parseFloat(cve.epss_delta_7d || 0);

    const scoreBreakdown = {
      components: {
        cvss:     { points: parseFloat(((cvssBase / 10) * 20).toFixed(2)), max: 20, value: cvssBase },
        epss:     { points: parseFloat((epssScore * 25).toFixed(2)), max: 25, value: epssScore },
        velocity: { points: delta7d >= 0.3 ? 10 : delta7d >= 0.1 ? 6 : delta7d > 0 ? 3 : 0, max: 10, delta_7d: delta7d },
        kev:      { points: cve.kev_member ? 25 : 0, max: 25, member: cve.kev_member },
        exploit:  { points: (!cve.kev_member && cve.exploit_available) ? 10 : 0, max: 10, available: cve.exploit_available, suppressed_by: cve.kev_member ? 'kev' : null },
        no_patch: { points: !cve.patch_available ? 10 : 0, max: 10, patch_available: cve.patch_available }
      },
      modifiers: { attack_vector: { value: cve.attack_vector, modifier: cve.attack_vector_modifier } },
      combined_score: cve.combined_score,
      adjusted_score: cve.adjusted_score
    };

    res.json({ data: { ...cve, epss_history: epssHistory.rows, cpes: cpeResult.rows, score_breakdown: scoreBreakdown } });
  } catch (err) {
    console.error('CVE detail error:', err);
    res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'CVE detail query failed', status: 500 } });
  }
});

export default router;
