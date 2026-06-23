-- ============================================
-- CVE INTEL — Migration 001
-- Threat intelligence and trend tables
-- Run: psql -U cveintel_user -d cveintel -h localhost -f api/db/migrations/001_threat_intelligence.sql
-- ============================================

-- Threat actor profiles
CREATE TABLE IF NOT EXISTS threat_actors (
    actor_id              TEXT PRIMARY KEY,
    display_name          TEXT NOT NULL,
    actor_type            TEXT NOT NULL,  -- state_sanctioned|state_affiliated|criminal|hacktivist|opportunistic
    country               TEXT,           -- ISO 2-letter code or NULL
    country_relationship  TEXT,           -- sanctioned|affiliated|none|NULL
    also_known_as         JSONB,          -- array of alias strings
    target_sectors        JSONB,          -- array of sector strings
    description           TEXT,
    mitre_id              TEXT,           -- e.g. G0096
    source                TEXT
);

-- CVE to threat actor mappings
CREATE TABLE IF NOT EXISTS cve_threat_actor (
    cve_id        TEXT,
    actor_id      TEXT REFERENCES threat_actors(actor_id),
    source        TEXT,
    flagged_date  DATE,
    PRIMARY KEY (cve_id, actor_id)
);

-- Geopolitical events timeline
CREATE TABLE IF NOT EXISTS geopolitical_events (
    event_id      SERIAL PRIMARY KEY,
    event_date    DATE NOT NULL,
    event_name    TEXT NOT NULL,
    region        TEXT,
    impact_level  TEXT,  -- high|medium|low
    notes         TEXT
);

-- Global daily risk snapshot (not per-client)
CREATE TABLE IF NOT EXISTS global_risk_snapshot (
    snapshot_date     DATE PRIMARY KEY,
    total_cves        INT DEFAULT 0,
    critical_count    INT DEFAULT 0,
    high_count        INT DEFAULT 0,
    medium_count      INT DEFAULT 0,
    low_count         INT DEFAULT 0,
    kev_total         INT DEFAULT 0,
    kev_added_today   INT DEFAULT 0,
    pre_kev_count     INT DEFAULT 0,
    exploit_count     INT DEFAULT 0,
    new_cves_today    INT DEFAULT 0
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_cve_threat_actor_actor
    ON cve_threat_actor (actor_id);
CREATE INDEX IF NOT EXISTS idx_cve_threat_actor_cve
    ON cve_threat_actor (cve_id);
CREATE INDEX IF NOT EXISTS idx_geo_events_date
    ON geopolitical_events (event_date);
CREATE INDEX IF NOT EXISTS idx_global_snapshot_date
    ON global_risk_snapshot (snapshot_date);
