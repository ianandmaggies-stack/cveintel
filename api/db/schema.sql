-- ============================================
-- CVE INTEL — DATABASE SCHEMA v1.0
-- ============================================

-- ============================================
-- BLOCK 1: Hot Tier (shared CVE data)
-- ============================================

CREATE TABLE cve_core (
    cve_id                  TEXT PRIMARY KEY,
    published_date          DATE,
    modified_date           DATE,
    description             TEXT,
    cvss_base               NUMERIC(4,2),
    cvss_vector             TEXT,
    cvss_version            TEXT,
    cwe_id                  TEXT,
    patch_available         BOOLEAN,
    attack_vector           TEXT,
    privileges_required     TEXT,
    user_interaction        TEXT,
    scope                   TEXT,
    source_updated          TIMESTAMP
);

CREATE TABLE cve_epss (
    cve_id                  TEXT,
    snapshot_date           DATE,
    epss_score              NUMERIC(6,5),
    percentile              NUMERIC(6,5),
    PRIMARY KEY (cve_id, snapshot_date)
);

CREATE TABLE cve_kev (
    cve_id                  TEXT PRIMARY KEY,
    date_added              DATE,
    vulnerability_name      TEXT,
    vendor_project          TEXT,
    product                 TEXT,
    required_action         TEXT,
    due_date                DATE
);

CREATE TABLE cve_exploits (
    exploit_id              SERIAL PRIMARY KEY,
    cve_id                  TEXT,
    source                  TEXT,
    exploit_type            TEXT,
    verified                BOOLEAN,
    published_date          DATE
);

CREATE TABLE cve_cpe (
    cpe_id                  SERIAL PRIMARY KEY,
    cve_id                  TEXT,
    cpe_string              TEXT,
    vendor                  TEXT,
    product                 TEXT,
    version                 TEXT,
    platform_tag            TEXT
);

CREATE TABLE cve_score (
    cve_id                  TEXT PRIMARY KEY,
    combined_score          NUMERIC(5,2),
    adjusted_score          NUMERIC(5,2),
    epss_delta_1d           NUMERIC(6,5),
    epss_delta_7d           NUMERIC(6,5),
    kev_member              BOOLEAN DEFAULT FALSE,
    exploit_available       BOOLEAN DEFAULT FALSE,
    temporal_cvss           NUMERIC(4,2),
    epss_pending            BOOLEAN DEFAULT TRUE,
    attack_vector_modifier  NUMERIC(4,2),
    cross_platform_modifier NUMERIC(4,2),
    pre_kev_score           INT DEFAULT 0,
    pre_kev_flag            BOOLEAN DEFAULT FALSE,
    score_updated           TIMESTAMP
);

CREATE TABLE cve_ransomware (
    cve_id                  TEXT PRIMARY KEY,
    group_name              TEXT,
    first_observed          DATE,
    source                  TEXT
);

CREATE TABLE cve_fix_confidence (
    cve_id                  TEXT PRIMARY KEY,
    fix_confidence          INT,
    fix_type                TEXT,
    patch_age_days          INT,
    confidence_updated      TIMESTAMP
);

CREATE TABLE cve_sector_flags (
    cve_id                  TEXT,
    sector                  TEXT,
    source_advisory         TEXT,
    flagged_date            DATE,
    PRIMARY KEY (cve_id, sector)
);

CREATE TABLE sector_threat_timeline (
    cve_id                  TEXT,
    sector                  TEXT,
    warned_date             DATE,
    source                  TEXT,
    region                  TEXT,
    PRIMARY KEY (cve_id, sector, region)
);

CREATE TABLE threat_propagation_pattern (
    cve_id                  TEXT PRIMARY KEY,
    days_publish_to_exploit INT,
    days_exploit_to_kev     INT,
    days_kev_to_smb         INT,
    first_sector_hit        TEXT,
    propagation_confidence  INT
);

-- ============================================
-- BLOCK 2: Reference Tier (semi-static)
-- ============================================

CREATE TABLE client_profiles (
    profile_id              TEXT PRIMARY KEY,
    label                   TEXT,
    description             TEXT,
    cpe_bundle              JSONB,
    default_platform_tags   JSONB
);

CREATE TABLE platform_vendor_map (
    vendor_pattern          TEXT PRIMARY KEY,
    platform_tag            TEXT
);

CREATE TABLE product_lifecycle (
    product_id              TEXT PRIMARY KEY,
    display_name            TEXT,
    vendor                  TEXT,
    eol_date                DATE,
    extended_support_end    DATE,
    platform_tag            TEXT
);

-- ============================================
-- BLOCK 3: Client Tier
-- ============================================

CREATE TABLE clients (
    client_id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                    TEXT,
    tier                    TEXT,
    industry_vertical       TEXT,
    stack_match_status      TEXT DEFAULT 'pending',
    stack_match_updated     TIMESTAMP,
    created_at              TIMESTAMP DEFAULT NOW()
);

CREATE TABLE client_stack (
    stack_id                SERIAL PRIMARY KEY,
    client_id               UUID REFERENCES clients(client_id) ON DELETE CASCADE,
    cpe_string              TEXT,
    platform_tag            TEXT,
    version_declaration     TEXT,
    version_string          TEXT,
    is_eol                  BOOLEAN DEFAULT FALSE,
    eol_date                DATE,
    source                  TEXT,
    added_at                TIMESTAMP DEFAULT NOW()
);

-- ============================================
-- BLOCK 4: Cold Tier (per client, materialised)
-- ============================================

CREATE TABLE client_cve_relevance (
    client_id               UUID REFERENCES clients(client_id) ON DELETE CASCADE,
    cve_id                  TEXT,
    initial_load            BOOLEAN DEFAULT TRUE,
    status                  TEXT DEFAULT 'active',
    eol_affected            BOOLEAN DEFAULT FALSE,
    first_seen              TIMESTAMP DEFAULT NOW(),
    status_updated          TIMESTAMP,
    PRIMARY KEY (client_id, cve_id)
);

CREATE TABLE client_cve_cpe_matches (
    client_id               UUID REFERENCES clients(client_id) ON DELETE CASCADE,
    cve_id                  TEXT,
    matched_cpe             TEXT,
    platform_tag            TEXT,
    PRIMARY KEY (client_id, cve_id, matched_cpe)
);

CREATE TABLE client_alerts (
    alert_id                SERIAL PRIMARY KEY,
    client_id               UUID REFERENCES clients(client_id) ON DELETE CASCADE,
    cve_id                  TEXT,
    alert_type              TEXT,
    kev_override            BOOLEAN DEFAULT FALSE,
    triggered_at            TIMESTAMP DEFAULT NOW(),
    delivered               BOOLEAN DEFAULT FALSE,
    last_alerted_at         TIMESTAMP
);

CREATE TABLE client_risk_snapshot (
    snapshot_id             SERIAL PRIMARY KEY,
    client_id               UUID REFERENCES clients(client_id) ON DELETE CASCADE,
    snapshot_date           DATE,
    critical_count          INT DEFAULT 0,
    high_count              INT DEFAULT 0,
    medium_count            INT DEFAULT 0,
    low_count               INT DEFAULT 0,
    overall_risk_score      NUMERIC(5,2),
    critical_microsoft      INT DEFAULT 0,
    critical_linux          INT DEFAULT 0,
    critical_network        INT DEFAULT 0,
    critical_other          INT DEFAULT 0,
    kev_exposure_microsoft  INT DEFAULT 0,
    kev_exposure_linux      INT DEFAULT 0,
    kev_exposure_network    INT DEFAULT 0,
    kev_exposure_other      INT DEFAULT 0,
    critical_external       INT DEFAULT 0,
    critical_internal       INT DEFAULT 0,
    kev_exposure_external   INT DEFAULT 0,
    kev_exposure_internal   INT DEFAULT 0,
    human_vector_count      INT DEFAULT 0,
    lateral_movement_count  INT DEFAULT 0,
    kev_exposure_total      INT DEFAULT 0,
    eol_exposure_count      INT DEFAULT 0,
    pre_kev_count           INT DEFAULT 0,
    ransomware_exposure     INT DEFAULT 0,
    stack_exposure_pct      NUMERIC(5,2),
    mean_time_to_patch      NUMERIC(8,2),
    coverage_gap_count      INT DEFAULT 0
);

CREATE TABLE client_remediation_queue (
    client_id               UUID REFERENCES clients(client_id) ON DELETE CASCADE,
    cve_id                  TEXT,
    queue_position          INT,
    priority_label          TEXT,
    reasoning               JSONB,
    queue_updated           TIMESTAMP DEFAULT NOW(),
    PRIMARY KEY (client_id, cve_id)
);

-- ============================================
-- BLOCK 5: Operational Tables
-- ============================================

CREATE TABLE ingest_log (
    log_id                  SERIAL PRIMARY KEY,
    job_name                TEXT,
    started_at              TIMESTAMP,
    completed_at            TIMESTAMP,
    status                  TEXT,
    records_fetched         INT DEFAULT 0,
    records_inserted        INT DEFAULT 0,
    records_updated         INT DEFAULT 0,
    records_failed          INT DEFAULT 0,
    error_message           TEXT,
    source_url              TEXT,
    checksum                TEXT
);

CREATE TABLE ingest_status (
    job_name                TEXT PRIMARY KEY,
    is_running              BOOLEAN DEFAULT FALSE,
    started_at              TIMESTAMP
);

CREATE TABLE export_jobs (
    job_id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id               UUID REFERENCES clients(client_id) ON DELETE CASCADE,
    export_type             TEXT,
    status                  TEXT DEFAULT 'pending',
    requested_at            TIMESTAMP DEFAULT NOW(),
    completed_at            TIMESTAMP,
    download_url            TEXT,
    expires_at              TIMESTAMP
);

CREATE TABLE cve_compound_risk (
    cve_id_a                TEXT,
    cve_id_b                TEXT,
    compound_type           TEXT,
    risk_multiplier         NUMERIC(4,2),
    PRIMARY KEY (cve_id_a, cve_id_b)
);

-- ============================================
-- INDEXES — Cold and operational tiers
-- ============================================

CREATE INDEX idx_client_cve_relevance_status
    ON client_cve_relevance (client_id, status);
CREATE INDEX idx_client_cve_relevance_active
    ON client_cve_relevance (client_id)
    WHERE status = 'active';
CREATE INDEX idx_client_cpe_matches_platform
    ON client_cve_cpe_matches (client_id, platform_tag);
CREATE INDEX idx_client_alerts_cooldown
    ON client_alerts (client_id, cve_id, alert_type, last_alerted_at);
CREATE INDEX idx_client_risk_snapshot_date
    ON client_risk_snapshot (client_id, snapshot_date);
CREATE INDEX idx_ingest_log_job
    ON ingest_log (job_name, started_at);

-- ============================================
-- Seed ingest_status with job names
-- ============================================

INSERT INTO ingest_status (job_name, is_running) VALUES
    ('nvd',           FALSE),
    ('epss',          FALSE),
    ('kev',           FALSE),
    ('exploits',      FALSE),
    ('score_refresh', FALSE);
