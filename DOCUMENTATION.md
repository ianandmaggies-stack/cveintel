# CVE Intel — Complete Project Documentation

> A CVE intelligence platform for IT security professionals, small teams, independent contractors and MSSPs.
> No agents. No enterprise contract. No noise.

---

## Table of Contents

1. [Product Vision](#product-vision)
2. [Architecture Overview](#architecture-overview)
3. [Data Sources](#data-sources)
4. [Scoring Algorithm](#scoring-algorithm)
5. [Database Schema](#database-schema)
6. [Ingest Pipeline](#ingest-pipeline)
7. [API Layer](#api-layer)
8. [Frontend](#frontend)
9. [Threat Intelligence](#threat-intelligence)
10. [Operations](#operations)
11. [Competitive Position](#competitive-position)
12. [Roadmap](#roadmap)

---

## Product Vision

CVE Intel gives small security teams the signal they actually need — not a list of everything, but the things that matter to their environment right now.

### Target Market
- Independent security contractors
- SMB IT teams with a security responsibility
- MSSPs managing multiple SMB clients

### Pricing Tiers
| Tier | Who | Differentiators |
|---|---|---|
| Solo | Independent contractor | Full intelligence, single account |
| Team | SMB security team | Multi-user, peer benchmarking |
| MSSP | Managed service providers | Multi-client, white-label, infographic export |

### Core Differentiators
- **No deployment required** — web app only, zero friction
- **Combined risk score** — CVSS + EPSS + KEV + exploit + velocity in one number
- **Pre-KEV flagging** — early warning before CISA confirms exploitation
- **EPSS velocity tracking** — 7-day delta, nobody else surfaces this at this price
- **Ransomware correlation** — CVEs linked to active campaigns
- **EOL product detection** — permanently unresolvable CVEs flagged
- **Threat actor profiles** — 21 tracked actors with geopolitical context
- **Trend landscape** — rising/falling threat environment over time

---

## Architecture Overview

```
Data Sources
    │
    ▼
Ingest Pipeline (Node.js jobs)
    │
    ▼
PostgreSQL 16 (26+ tables)
    │
    ▼
Express API (REST, /api/v1/)
    │
    ▼
React Frontend (Vite, port 5174)
```

### Tech Stack
```
OS:           Ubuntu 24.04
Runtime:      Node.js 20
Database:     PostgreSQL 16
Web server:   Nginx (reverse proxy, future)
API:          Express 4
Frontend:     React 18 + Vite
Styling:      Tailwind CSS 3 + shadcn/ui
Charts:       Recharts
State:        TanStack Query + localStorage
HTTP:         Axios
Auth:         JWT (jsonwebtoken)
```

### Server Details (Development)
```
IP:           192.168.0.86
OS:           Ubuntu 24.04
User:         cve
Project root: /home/cve/cveintel
GitHub:       https://github.com/ianandmaggies-stack/cveintel
```

### Ports
```
4000  — CVE Intel API
5174  — CVE Intel React dev
80    — Nginx (shared, Blackwood Keep)
3001  — CI6 (do not touch)
3002  — Blackwood Keep Node (do not touch)
3389  — RDP (do not touch)
5432  — PostgreSQL
```

---

## Data Sources

| Source | What | URL | Cadence |
|---|---|---|---|
| NVD | Core CVE data, CVSS, CPE | https://services.nvd.nist.gov/rest/json/cves/2.0 | Daily delta, weekly full |
| EPSS | Exploitation probability | https://epss.cyentia.com/epss_scores-YYYY-MM-DD.csv.gz | Daily |
| CISA KEV | Known exploited vulnerabilities | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | Daily (2x) |
| ExploitDB | Known exploits | https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv | Weekly |
| Metasploit | Weaponised modules | https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json | Weekly |
| MITRE ATT&CK | Threat actor profiles | Manual seed, update periodically | Manual |
| CISA Advisories | Geopolitical events | Manual seed | Manual |

### Data Volumes (as of June 2026)
```
cve_core:     340,243 CVEs (1988-2026)
cve_cpe:      2,522,315 CPE entries
cve_epss:     341,583+ rows (grows daily)
cve_kev:      1,623 entries
cve_score:    342,671 scored records
cve_exploits: 28,022 exploit mappings
threat_actors: 21 profiles
geopolitical_events: 15 events
```

---

## Scoring Algorithm

All CVEs receive a combined 0-100 risk score.

### Component Scores

| Signal | Max Points | Calculation |
|---|---|---|
| CVSS base | 20 | `(cvss_base / 10) * 20` |
| EPSS score | 25 | `epss_score * 25` |
| EPSS velocity (7d) | 10 | Stepped: >0=3, ≥0.1=6, ≥0.3=10 |
| KEV membership | 25 | Binary: on KEV = 25 |
| Exploit available | 10 | Non-KEV + exploit = 10 |
| No patch | 10 | Binary: no patch = 10 |

### Modifiers
```
Attack vector modifier:
  network   → ×1.00
  adjacent  → ×0.85
  local     → ×0.75
  physical  → ×0.60

Cross-platform modifier:
  matches >1 platform → ×1.10
```

### Score Bands
| Band | Range | Alert Behaviour |
|---|---|---|
| CRITICAL | 75-100 | Always alert |
| HIGH | 50-74 | Alert if stack match |
| MEDIUM | 25-49 | Digest only |
| LOW | 0-24 | No alert |

### Pre-KEV Algorithm
Predicts CVEs likely to appear on CISA KEV before confirmation:
```
+2  EPSS > 0.4
+2  EPSS 7d delta > 0.2
+2  Exploit available
+1  CVSS base > 7.0
+1  Attack vector = network
+1  Published > 14 days ago
+1  No patch available

pre_kev_flag = score >= 5
```

### Score Colours
```
CRITICAL  #E24B4A
HIGH      #BA7517
MEDIUM    #888780
LOW       #1D9E75
```

---

## Database Schema

### Table Inventory (26+ tables)

#### Hot Tier (shared CVE data)
| Table | Description |
|---|---|
| `cve_core` | Master CVE records from NVD |
| `cve_epss` | Daily EPSS scores per CVE |
| `cve_kev` | CISA KEV entries |
| `cve_exploits` | ExploitDB + Metasploit mappings |
| `cve_cpe` | CPE affected product entries |
| `cve_score` | Calculated combined risk scores |
| `cve_ransomware` | CVEs linked to ransomware campaigns |
| `cve_fix_confidence` | Patch confidence scoring |
| `cve_sector_flags` | Sector-specific CVE flags |
| `sector_threat_timeline` | When sectors were warned |
| `threat_propagation_pattern` | CVE exploitation patterns |

#### Reference Tier (semi-static)
| Table | Description |
|---|---|
| `client_profiles` | Predefined stack bundles (6 profiles) |
| `platform_vendor_map` | Vendor → platform tag mapping (59 rows) |
| `product_lifecycle` | EOL dates for common products (34 rows) |
| `threat_actors` | Threat actor profiles (21 actors) |
| `geopolitical_events` | Key events timeline (15 events) |
| `global_risk_snapshot` | Daily global metric snapshots |

#### Client Tier
| Table | Description |
|---|---|
| `clients` | Client accounts |
| `client_stack` | Declared software stack per client |

#### Cold Tier (per-client)
| Table | Description |
|---|---|
| `client_cve_relevance` | CVEs matched to client stack |
| `client_cve_cpe_matches` | Which CPEs triggered matches |
| `client_alerts` | Alert history |
| `client_risk_snapshot` | Historical risk posture per client |
| `client_remediation_queue` | Prioritised fix list |

#### Operational
| Table | Description |
|---|---|
| `ingest_log` | Full history of all ingest runs |
| `ingest_status` | Current lock state per job |
| `export_jobs` | Async export job tracking |
| `cve_threat_actor` | CVE to threat actor mappings |
| `cve_compound_risk` | Dangerous CVE pairs (V2) |

### Key Design Decisions
- CVE ID is the universal join key across all tables
- Hot tier is shared across all clients — one copy, many queries
- Cold tier is per-client, materialised at ingest time
- Score refresh is event-driven, not per-request
- All ingest jobs use mutex locking via `ingest_status`
- Raw files written as `.tmp`, renamed on success

---

## Ingest Pipeline

### Five Jobs

| Job | File | Source | Cadence |
|---|---|---|---|
| KEV | `ingest/kev.js` | CISA JSON | Daily (2×) |
| EPSS | `ingest/epss.js` | FIRST.org CSV.gz | Daily |
| NVD | `ingest/nvd.js` | NVD REST API | Daily delta / weekly full |
| Exploits | `ingest/exploits.js` | ExploitDB + Metasploit | Weekly |
| Score refresh | `ingest/scoreRefresh.js` | Internal | After each ingest |

### Cron Schedule
```
0  3  * * *   /home/cve/cveintel/cron.sh daily   # KEV+EPSS+NVD+scores
0  15 * * *   /home/cve/cveintel/cron.sh kev     # KEV check (updates anytime)
0  2  * * 0   /home/cve/cveintel/cron.sh weekly  # adds exploits
```

### Three-Stage Pattern
Every job follows: **Fetch → Transform → Load**
- Fetch downloads to `.tmp` file, renames on success
- Transform validates and normalises
- Load upserts to PostgreSQL in bulk chunks

### Key Rules
- Checksum comparison prevents duplicate processing
- Ingest mutex prevents concurrent job conflicts
- Locks older than 2 hours auto-cleared by cron wrapper
- Score change threshold: only alert if delta > 2.0 points
- NVD full ingest requires: `node --max-old-space-size=4096`
- EPSS bulk update uses temp table (not row-by-row)

### Score Refresh Also Writes
- `global_risk_snapshot` — daily trend data point
- `cve_score.exploit_available` — updated from exploit ingest
- `cve_score.kev_member` — updated from KEV ingest
- `cve_score.pre_kev_flag` — recalculated from all signals

---

## API Layer

### Base URL
```
http://192.168.0.86:4000/api/v1/
```

### Authentication
- JWT tokens, 8h expiry
- Refresh tokens, 7d expiry
- Dev credentials: `admin@cveintel.dev` / `dev-password`

### Middleware Stack (in order)
```
1. Rate limiter (300 req/15min)
2. Auth validator (JWT)
3. Client scope check
4. Input validator
5. Route handler
6. Response formatter
7. Request logger (redacts passwords, tokens)
```

### Endpoints

```
POST   /auth/login
POST   /auth/refresh
POST   /auth/logout

GET    /clients/:id/dashboard
GET    /clients/:id/cves
GET    /clients/:id/cves/:cveId
GET    /clients/:id/alerts
GET    /clients/:id/posture

GET    /landscape

GET    /admin/ingest/status
GET    /admin/system/health

GET    /health
```

### CVE List Filter Params
```
?band=critical|high|medium|low
?platform=microsoft|linux|network|other
?exposure=external|internal
?kev=true
?exploit=true
?user_interaction=required
?scope=changed
?sort=score|date|velocity
?page=1&limit=25
```

### Standard Response Shape
```json
{
  "data": { ... },
  "meta": { "total": 0, "page": 1, "limit": 25, "pages": 0 }
}
```

### Error Shape
```json
{
  "error": { "code": "CVE_NOT_FOUND", "message": "...", "status": 404 }
}
```

---

## Frontend

### Pages

| Page | Route | Description |
|---|---|---|
| Login | `/login` | JWT auth |
| Dashboard | `/dashboard` | KPIs, critical CVEs, trending, platform split |
| CVE List | `/cves` | 340k CVEs, filters, pagination |
| CVE Detail | `/cves/:id` | Score breakdown, EPSS chart, timeline |
| Threat Landscape | `/landscape` | Trend charts, actor profiles, geo events |
| Executive Report | `/report` | Board-ready report, technical + executive modes |

### Component Architecture
```
Pages (fetch data via TanStack Query)
  └── Components (receive props, render only)
        └── UI primitives (shadcn)

AuthStore (localStorage) — JWT, client_id, role
FilterStore (session) — active filters, pagination
TanStack Query cache — all server data
```

### Design System
```
Font:       JetBrains Mono (data), Inter (prose)
Background: #0a0a0a
Border:     #1a1a1a / #2a2a2a
Text:       #e5e5e5 / #888 / #555
Accent:     #E24B4A (red)
Info:       #5b9bd5 (blue links)
```

---

## Threat Intelligence

### Threat Actor Classification

| Type | Description | Example |
|---|---|---|
| `state_sanctioned` | Directly government operated | APT41, Sandworm |
| `state_affiliated` | Government tolerates/protects | Charming Kitten, KillNet |
| `criminal` | Financially motivated | LockBit, BlackCat, Cl0p |
| `hacktivist` | Ideologically motivated | Anonymous, IT Army Ukraine |
| `opportunistic` | Low sophistication, no agenda | — |

### Country Relationship
```
sanctioned   — government directs the group
affiliated   — government protects/tolerates
none         — no government relationship
null         — unknown
```

### Current Actor Coverage (21 actors)
- **China (4):** APT1, APT10, APT41, Volt Typhoon
- **Russia (3):** APT28, APT29, Sandworm
- **North Korea (2):** APT38, Lazarus Group
- **Iran (3):** APT33, APT34, Charming Kitten
- **Criminal (6):** LockBit, BlackCat, Cl0p, REvil, Scattered Spider, LAPSUS$
- **Hacktivist (3):** Anonymous, KillNet, IT Army of Ukraine

### Geopolitical Events (15 seeded)
Key events 2022-2025 including Ukraine invasion, MOVEit exploitation,
Change Healthcare attack, CrowdStrike outage, and more.

---

## Operations

### Management Script
```bash
./cveintel.sh start            # Start API + UI
./cveintel.sh stop             # Stop both
./cveintel.sh restart          # Restart both
./cveintel.sh status           # Health check
./cveintel.sh logs             # Recent logs
./cveintel.sh update           # Git pull + restart
./cveintel.sh ingest           # Daily ingest now
./cveintel.sh ingest:weekly    # Weekly ingest (+ exploits)
./cveintel.sh ingest:kev       # KEV only
./cveintel.sh ingest:epss      # EPSS only
./cveintel.sh ingest:nvd       # NVD delta only
./cveintel.sh ingest:exploits  # Exploits only
./cveintel.sh ingest:scores    # Recalculate scores
./cveintel.sh reset-locks      # Clear stuck locks
```

### If Server Was Off During Scheduled Ingest
```bash
./cveintel.sh ingest           # catches up daily jobs
./cveintel.sh ingest:weekly    # if Sunday was missed
```

### Useful Database Queries
```sql
-- Data counts
SELECT 'cve_core' as t, COUNT(*) FROM cve_core
UNION ALL SELECT 'cve_score', COUNT(*) FROM cve_score
UNION ALL SELECT 'cve_exploits', COUNT(*) FROM cve_exploits
UNION ALL SELECT 'cve_kev', COUNT(*) FROM cve_kev;

-- Score distribution
SELECT
  COUNT(*) FILTER (WHERE adjusted_score >= 75) AS critical,
  COUNT(*) FILTER (WHERE adjusted_score >= 50 AND adjusted_score < 75) AS high,
  COUNT(*) FILTER (WHERE kev_member = TRUE) AS kev,
  COUNT(*) FILTER (WHERE exploit_available = TRUE) AS exploit,
  COUNT(*) FILTER (WHERE pre_kev_flag = TRUE) AS pre_kev
FROM cve_score;

-- Recent ingest history
SELECT job_name, status, records_fetched, records_inserted, completed_at
FROM ingest_log ORDER BY log_id DESC LIMIT 10;

-- Reset stuck locks
UPDATE ingest_log SET status='failed', completed_at=NOW()
WHERE status='running';
UPDATE ingest_status SET is_running=FALSE, started_at=NULL;
```

### Known Gotchas
- NVD full ingest needs `node --max-old-space-size=4096`
- Vite needs `--host` flag to be network accessible
- API must listen on `0.0.0.0` not `127.0.0.1`
- Tailwind pinned to v3 — v4 breaks shadcn
- GitHubWrite MCP token expires September 12 2026
- Seed data must be truncated before re-running
- `ON COMMIT DROP` temp tables drop before next query — remove it
- PostgreSQL VALUES clause needs explicit type casts

---

## Competitive Position

### Signal Comparison
| Signal | CVE Intel | Tenable | Qualys | Free tools |
|---|---|---|---|---|
| CVSS | ✅ | ✅ | ✅ | ✅ |
| KEV | ✅ | ✅ | ✅ | Partial |
| EPSS | ✅ | ✅ | Partial | Rarely |
| EPSS velocity | ✅ | ❌ | ❌ | ❌ |
| Pre-KEV flag | ✅ | ❌ | ❌ | ❌ |
| Exploit signal | ✅ | ✅ | ✅ | Rarely |
| Threat actors | ✅ | Paid | Paid | ❌ |
| Geo events | ✅ | ❌ | ❌ | ❌ |
| No agent | ✅ | ❌ | ❌ | ✅ |
| SMB price | ✅ | ❌ | ❌ | Free |

### Honest Gap
No verified asset discovery — relies on self-declaration.
Tenable/Qualys scan the network; we don't.
This is also our advantage — zero friction onboarding.

---

## Roadmap

### Phase 2 — Real Product (next)
- [ ] User management — real accounts, registration, password reset
- [ ] Client stack declaration — onboarding flow
- [ ] Email alert delivery (SMTP/Sendgrid)
- [ ] Settings page
- [ ] Remediation queue view
- [ ] Alert centre view

### Phase 3 — More Intelligence
- [ ] Ransomware CVE ingest (CISA StopRansomware)
- [ ] EPSS historical backfill (6 months)
- [ ] CVE-to-threat-actor mapping (CISA advisory parser)
- [ ] Sector threat feed automation
- [ ] Compounding vulnerability detection

### Phase 4 — Production
- [ ] Nginx config + domain
- [ ] Production server migration
- [ ] Billing integration
- [ ] MSSP multi-client view
- [ ] Peer benchmarking (anonymous, opt-in)

### V2 Features (explicitly deferred)
- ATT&CK technique mapping
- HIBP credential exposure
- Industry vertical compliance (HIPAA/PCI-DSS)
- Cursor-based pagination
- Time-to-exploit benchmarking
- Threat actor targeting per client
- Geographic propagation mapping

---

## Session History

This product was designed and built across multiple sessions
with Claude (Anthropic) acting as architect, engineer, and
product advisor. The complete design rationale is captured
in session handoff documents stored alongside this codebase.

Key decisions made:
- PostgreSQL over SQLite — multi-tenant product requirement
- No AI backend — algorithmic scoring, auditable and predictable
- Snapshot-first — one dataset shared across all clients
- Pre-KEV as primary differentiator — novel at any price point
- SMB/contractor focus — underserved, no agent friction
- Dark terminal aesthetic — credible to security professionals
- GitHubWrite MCP for code delivery — Claude pushes directly

---

*CVE///INTEL — Built with Claude, Anthropic*
