import express from 'express';
import pool from '../db/index.js';
import { requireAuth } from '../middleware/auth.js';

const router = express.Router();

// GET /api/v1/landscape
// Global threat landscape data - trend, actors, events
router.get('/landscape', requireAuth, async (req, res) => {
  try {
    const [snapshots, actors, events, actorCveCounts] = await Promise.all([

      // Last 90 days of global snapshots
      pool.query(`
        SELECT snapshot_date, total_cves, critical_count, high_count,
               kev_total, kev_added_today, pre_kev_count, exploit_count, new_cves_today
        FROM global_risk_snapshot
        ORDER BY snapshot_date ASC
        LIMIT 90
      `),

      // All threat actors
      pool.query(`
        SELECT actor_id, display_name, actor_type, country,
               country_relationship, also_known_as, target_sectors,
               description, mitre_id
        FROM threat_actors
        ORDER BY actor_type, country NULLS LAST, display_name
      `),

      // Geopolitical events
      pool.query(`
        SELECT event_id, event_date, event_name, region, impact_level, notes
        FROM geopolitical_events
        ORDER BY event_date DESC
      `),

      // CVE count per actor
      pool.query(`
        SELECT actor_id, COUNT(*) as cve_count
        FROM cve_threat_actor
        GROUP BY actor_id
      `)
    ]);

    // Merge CVE counts into actors
    const cveCountMap = new Map(actorCveCounts.rows.map(r => [r.actor_id, parseInt(r.cve_count)]));
    const actorsWithCounts = actors.rows.map(a => ({
      ...a,
      cve_count: cveCountMap.get(a.actor_id) || 0
    }));

    res.json({
      data: {
        snapshots:  snapshots.rows,
        actors:     actorsWithCounts,
        events:     events.rows
      }
    });

  } catch (err) {
    console.error('Landscape error:', err);
    res.status(500).json({
      error: { code: 'INTERNAL_ERROR', message: 'Landscape query failed', status: 500 }
    });
  }
});

export default router;
