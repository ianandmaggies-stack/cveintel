import express from 'express';
import pool from '../db/index.js';
import { requireAuth } from '../middleware/auth.js';

const router = express.Router();

// GET /api/v1/brief
// Morning Brief — delta intelligence, top movers, new KEV, pre-KEV signals
router.get('/brief', requireAuth, async (req, res) => {
  try {
    const [snapshots, newKev, epssMovers, preKev, risingExploits, activeActors] = await Promise.all([

      // Last 2 snapshots for delta calculation
      pool.query(`
        SELECT snapshot_date, critical_count, high_count, kev_total,
               kev_added_today, pre_kev_count, exploit_count, new_cves_today
        FROM global_risk_snapshot
        ORDER BY snapshot_date DESC
        LIMIT 2
      `),

      // CVEs added to KEV in last 7 days
      pool.query(`
        SELECT k.cve_id, k.vulnerability_name, k.vendor_project, k.product, k.date_added,
               c.description, c.attack_vector,
               s.adjusted_score
        FROM cve_kev k
        JOIN cve_core c ON c.cve_id = k.cve_id
        JOIN cve_score s ON s.cve_id = k.cve_id
        WHERE k.date_added >= NOW() - INTERVAL '7 days'
        ORDER BY k.date_added DESC, s.adjusted_score DESC
        LIMIT 5
      `),

      // Top EPSS movers — biggest 7d jump
      pool.query(`
        SELECT s.cve_id, s.epss_delta_7d, s.adjusted_score,
               s.kev_member, s.exploit_available, s.pre_kev_flag,
               c.description, c.attack_vector, c.patch_available
        FROM cve_score s
        JOIN cve_core c ON c.cve_id = s.cve_id
        WHERE s.epss_delta_7d > 0.01
        ORDER BY s.epss_delta_7d DESC
        LIMIT 5
      `),

      // Freshest pre-KEV flags — highest pre_kev_score
      pool.query(`
        SELECT s.cve_id, s.pre_kev_score, s.adjusted_score,
               s.exploit_available, s.epss_delta_7d,
               c.description, c.attack_vector, c.patch_available,
               c.published_date
        FROM cve_score s
        JOIN cve_core c ON c.cve_id = s.cve_id
        WHERE s.pre_kev_flag = TRUE
        ORDER BY s.pre_kev_score DESC, s.adjusted_score DESC
        LIMIT 5
      `),

      // CVEs with exploits published in last 30 days and no patch
      pool.query(`
        SELECT s.cve_id, s.adjusted_score, s.kev_member,
               c.description, c.attack_vector, c.patch_available,
               MIN(e.published_date) AS earliest_exploit
        FROM cve_score s
        JOIN cve_core c ON c.cve_id = s.cve_id
        JOIN cve_exploits e ON e.cve_id = s.cve_id
        WHERE e.published_date >= NOW() - INTERVAL '30 days'
          AND c.patch_available = FALSE
          AND s.adjusted_score >= 50
        GROUP BY s.cve_id, s.adjusted_score, s.kev_member,
                 c.description, c.attack_vector, c.patch_available
        ORDER BY s.adjusted_score DESC
        LIMIT 5
      `),

      // Most recently active threat actors with CVE mappings
      pool.query(`
        SELECT ta.actor_id, ta.display_name, ta.actor_type, ta.country,
               ta.target_sectors, COUNT(cta.cve_id) as cve_count
        FROM threat_actors ta
        JOIN cve_threat_actor cta ON cta.actor_id = ta.actor_id
        GROUP BY ta.actor_id, ta.display_name, ta.actor_type,
                 ta.country, ta.target_sectors
        ORDER BY cve_count DESC
        LIMIT 3
      `)
    ]);

    // Build delta — compare today vs yesterday snapshot
    const today     = snapshots.rows[0] || null;
    const yesterday = snapshots.rows[1] || null;

    const delta = today ? {
      critical:    yesterday ? parseInt(today.critical_count)  - parseInt(yesterday.critical_count)  : null,
      high:        yesterday ? parseInt(today.high_count)      - parseInt(yesterday.high_count)      : null,
      kev:         yesterday ? parseInt(today.kev_total)       - parseInt(yesterday.kev_total)       : null,
      pre_kev:     yesterday ? parseInt(today.pre_kev_count)   - parseInt(yesterday.pre_kev_count)   : null,
      new_cves:    today.new_cves_today    ? parseInt(today.new_cves_today)    : 0,
      kev_added:   today.kev_added_today   ? parseInt(today.kev_added_today)   : 0,
      exploit_count: today.exploit_count   ? parseInt(today.exploit_count)     : 0,
    } : null;

    const current = today ? {
      critical:      parseInt(today.critical_count),
      high:          parseInt(today.high_count),
      kev_total:     parseInt(today.kev_total),
      pre_kev_count: parseInt(today.pre_kev_count),
      exploit_count: parseInt(today.exploit_count),
      new_cves_today: parseInt(today.new_cves_today),
      snapshot_date:  today.snapshot_date,
    } : null;

    res.json({
      data: {
        current,
        delta,
        has_history:     !!yesterday,
        new_kev:         newKev.rows,
        epss_movers:     epssMovers.rows,
        pre_kev:         preKev.rows,
        rising_exploits: risingExploits.rows,
        active_actors:   activeActors.rows,
      }
    });

  } catch (err) {
    console.error('Brief error:', err);
    res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'Brief query failed', status: 500 } });
  }
});

export default router;
