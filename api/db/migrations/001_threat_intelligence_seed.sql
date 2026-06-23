-- ============================================
-- CVE INTEL — Threat Actor Seed Data
-- Source: MITRE ATT&CK, CISA advisories
-- Run after 001_threat_intelligence.sql
-- ============================================

INSERT INTO threat_actors
  (actor_id, display_name, actor_type, country, country_relationship,
   also_known_as, target_sectors, description, mitre_id, source)
VALUES

-- ============================================
-- CHINA — State sanctioned
-- ============================================
(
  'apt41',
  'APT41',
  'state_sanctioned',
  'CN',
  'sanctioned',
  '["Winnti", "Barium", "Double Dragon", "Wicked Panda"]',
  '["healthcare", "finance", "defence", "technology", "telecommunications"]',
  'Chinese state-sponsored group conducting espionage and financially motivated attacks. Unique in conducting both nation-state espionage and cybercrime operations.',
  'G0096',
  'MITRE ATT&CK'
),
(
  'apt1',
  'APT1',
  'state_sanctioned',
  'CN',
  'sanctioned',
  '["Comment Crew", "Comment Panda", "Byzantine Candor"]',
  '["defence", "aerospace", "government", "energy"]',
  'Chinese PLA Unit 61398. Prolific espionage group targeting US defence and aerospace sectors.',
  'G0006',
  'MITRE ATT&CK'
),
(
  'apt10',
  'APT10',
  'state_sanctioned',
  'CN',
  'sanctioned',
  '["Stone Panda", "MenuPass", "Red Apollo", "CVNX"]',
  '["managed_service_providers", "healthcare", "government", "finance"]',
  'Chinese group known for targeting managed service providers to gain access to their clients. Cloud Hopper campaign attributed to this group.',
  'G0045',
  'MITRE ATT&CK'
),
(
  'volt_typhoon',
  'Volt Typhoon',
  'state_sanctioned',
  'CN',
  'sanctioned',
  '["Bronze Silhouette", "Vanguard Panda"]',
  '["critical_infrastructure", "energy", "water", "communications", "transport"]',
  'Chinese state actor pre-positioning in US critical infrastructure. CISA issued multiple advisories 2023-2024. Focus on living-off-the-land techniques.',
  'G1017',
  'CISA Advisory'
),

-- ============================================
-- RUSSIA — State sanctioned
-- ============================================
(
  'sandworm',
  'Sandworm',
  'state_sanctioned',
  'RU',
  'sanctioned',
  '["Voodoo Bear", "BlackEnergy", "Telebots", "Iron Viking"]',
  '["energy", "government", "critical_infrastructure", "media"]',
  'Russian GRU Unit 74455. Responsible for NotPetya, Ukraine power grid attacks, and Olympic Destroyer. Most destructive cyberattacks on record.',
  'G0034',
  'MITRE ATT&CK'
),
(
  'apt28',
  'APT28',
  'state_sanctioned',
  'RU',
  'sanctioned',
  '["Fancy Bear", "Sofacy", "Pawn Storm", "Sednit", "STRONTIUM"]',
  '["government", "defence", "media", "political"]',
  'Russian GRU Unit 26165. Known for DNC hack, election interference, and targeting NATO countries. Focuses on espionage and influence operations.',
  'G0007',
  'MITRE ATT&CK'
),
(
  'apt29',
  'APT29',
  'state_sanctioned',
  'RU',
  'sanctioned',
  '["Cozy Bear", "The Dukes", "NOBELIUM", "Midnight Blizzard"]',
  '["government", "think_tanks", "healthcare", "technology", "finance"]',
  'Russian SVR foreign intelligence. Responsible for SolarWinds supply chain attack. Highly sophisticated, patient, stealthy operations.',
  'G0016',
  'MITRE ATT&CK'
),

-- ============================================
-- NORTH KOREA — State sanctioned
-- ============================================
(
  'lazarus',
  'Lazarus Group',
  'state_sanctioned',
  'KP',
  'sanctioned',
  '["Hidden Cobra", "Zinc", "Guardians of Peace"]',
  '["finance", "cryptocurrency", "defence", "media"]',
  'North Korean state group responsible for Sony Pictures hack, WannaCry, and billions stolen from cryptocurrency exchanges. Funds regime through cybercrime.',
  'G0032',
  'MITRE ATT&CK'
),
(
  'apt38',
  'APT38',
  'state_sanctioned',
  'KP',
  'sanctioned',
  '["Nickel Gladstone", "BeagleBoyz"]',
  '["finance", "banking", "cryptocurrency"]',
  'North Korean group focused exclusively on financial theft from banks and financial institutions. SWIFT banking system attacks attributed to this group.',
  'G0082',
  'MITRE ATT&CK'
),

-- ============================================
-- IRAN — State sanctioned
-- ============================================
(
  'apt33',
  'APT33',
  'state_sanctioned',
  'IR',
  'sanctioned',
  '["Elfin", "Refined Kitten", "Magnallium"]',
  '["energy", "aerospace", "petrochemical"]',
  'Iranian group targeting aviation and energy sectors, particularly in Saudi Arabia and South Korea. Known for destructive Shamoon malware.',
  'G0064',
  'MITRE ATT&CK'
),
(
  'apt34',
  'APT34',
  'state_sanctioned',
  'IR',
  'sanctioned',
  '["OilRig", "Helix Kitten", "Crambus"]',
  '["finance", "government", "energy", "telecommunications"]',
  'Iranian group targeting Middle East financial and government sectors. Linked to Iranian Ministry of Intelligence.',
  'G0049',
  'MITRE ATT&CK'
),
(
  'charming_kitten',
  'Charming Kitten',
  'state_affiliated',
  'IR',
  'affiliated',
  '["APT35", "Phosphorus", "Mint Sandstorm", "TA453"]',
  '["government", "academia", "human_rights", "media", "healthcare"]',
  'Iranian group with state affiliation. Known for spear-phishing campaigns targeting academics, journalists, and human rights activists.',
  'G0059',
  'MITRE ATT&CK'
),

-- ============================================
-- CRIMINAL — Ransomware groups
-- ============================================
(
  'lockbit',
  'LockBit',
  'criminal',
  NULL,
  'none',
  '["LockBit 2.0", "LockBit 3.0", "LockBit Black"]',
  '["healthcare", "finance", "manufacturing", "education", "government"]',
  'Most prolific ransomware group by victim count. Ransomware-as-a-service model. Operators believed to be based in Russia but no state direction. Disrupted by law enforcement in 2024 but resumed operations.',
  NULL,
  'CISA Advisory'
),
(
  'blackcat',
  'BlackCat / ALPHV',
  'criminal',
  NULL,
  'none',
  '["ALPHV", "Noberus"]',
  '["healthcare", "finance", "critical_infrastructure"]',
  'Sophisticated ransomware group using Rust-based malware. Known for triple extortion and attacking healthcare. FBI disrupted in 2023; group attempted comeback before apparent shutdown.',
  NULL,
  'CISA Advisory'
),
(
  'clop',
  'Cl0p',
  'criminal',
  'UA',
  'none',
  '["TA505", "Clop"]',
  '["finance", "retail", "manufacturing", "education"]',
  'Criminal ransomware group known for mass exploitation of zero-days in file transfer software (MOVEit, GoAnywhere). Believed to operate from Ukraine/Russia.',
  NULL,
  'CISA Advisory'
),
(
  'revil',
  'REvil',
  'criminal',
  'RU',
  'affiliated',
  '["Sodinokibi", "Gold Southfield"]',
  '["retail", "manufacturing", "finance", "legal"]',
  'Russian ransomware group behind Kaseya and JBS attacks. Arrested by Russian FSB in 2022 but members likely still active under other names.',
  NULL,
  'CISA Advisory'
),
(
  'scattered_spider',
  'Scattered Spider',
  'criminal',
  NULL,
  'none',
  '["UNC3944", "Muddled Libra", "Octo Tempest"]',
  '["finance", "telecommunications", "hospitality", "retail"]',
  'English-speaking criminal group known for social engineering and SIM swapping. Mostly young western members. MGM and Caesars attacks in 2023.',
  NULL,
  'CISA Advisory'
),

-- ============================================
-- HACKTIVIST — No nation allegiance
-- ============================================
(
  'anonymous',
  'Anonymous',
  'hacktivist',
  NULL,
  'none',
  '["Anon", "AnonOps"]',
  '["government", "law_enforcement", "corporations"]',
  'Decentralised international hacktivist collective. No leadership, no membership. Anyone can act under the Anonymous banner. Known for DDoS attacks and data leaks against governments and corporations they oppose.',
  NULL,
  'Public record'
),
(
  'killnet',
  'KillNet',
  'hacktivist',
  'RU',
  'affiliated',
  '["Legion"]',
  '["government", "healthcare", "critical_infrastructure"]',
  'Pro-Russia hacktivist group conducting DDoS attacks against NATO countries since Ukraine invasion. Claims independence but widely considered to have tacit Russian government support.',
  NULL,
  'CISA Advisory'
),
(
  'it_army_ukraine',
  'IT Army of Ukraine',
  'hacktivist',
  'UA',
  'affiliated',
  '[]',
  '["russian_government", "russian_infrastructure", "russian_finance"]',
  'Ukrainian government-coordinated volunteer hacking collective formed after Russia invasion in 2022. Targets Russian infrastructure, government, and financial systems.',
  NULL,
  'Public record'
),
(
  'lapsus',
  'LAPSUS$',
  'criminal',
  NULL,
  'none',
  '["DEV-0537"]',
  '["technology", "telecommunications", "media"]',
  'Extortion group known for targeting major tech companies including Microsoft, Nvidia, Samsung, and Rockstar Games. Members identified as teenagers in UK and Brazil.',
  NULL,
  'Public record'
);

-- ============================================
-- Geopolitical events seed data
-- ============================================

INSERT INTO geopolitical_events
  (event_date, event_name, region, impact_level, notes)
VALUES
  ('2022-02-24', 'Russia invades Ukraine', 'Europe', 'high',
   'Immediate surge in destructive cyberattacks against Ukraine. Sandworm wiper malware deployed. NATO countries saw increased scanning and phishing.'),
  ('2022-03-01', 'KillNet formed and begins NATO DDoS campaign', 'Europe', 'medium',
   'Pro-Russia hacktivist group begins coordinated DDoS against NATO government websites.'),
  ('2023-01-19', 'Royal Mail ransomware attack (LockBit)', 'UK', 'medium',
   'LockBit ransomware disrupts UK Royal Mail international shipping for weeks.'),
  ('2023-03-15', 'GoAnywhere zero-day mass exploitation (Cl0p)', 'Global', 'high',
   'Cl0p exploits CVE-2023-0669 in Fortra GoAnywhere. 130+ organisations compromised.'),
  ('2023-05-31', 'MOVEit zero-day mass exploitation (Cl0p)', 'Global', 'high',
   'Cl0p exploits CVE-2023-34362 in Progress MOVEit. 2000+ organisations affected including US government agencies.'),
  ('2023-07-26', 'Niger coup — West Africa instability', 'Africa', 'low',
   'Political instability in West Africa. Minor increase in regional cyber activity.'),
  ('2023-09-08', 'MGM Resorts attack (Scattered Spider)', 'USA', 'medium',
   'Social engineering attack causes 10 days of outage at MGM. Estimated $100M+ impact.'),
  ('2023-10-07', 'Hamas attacks Israel — Middle East conflict begins', 'Middle East', 'high',
   'Immediate surge in hacktivist activity on both sides. Iranian-linked groups increase targeting of Israeli infrastructure.'),
  ('2023-12-18', 'ALPHV/BlackCat FBI disruption', 'Global', 'medium',
   'FBI seizes BlackCat infrastructure. Group attempted comeback before apparent shutdown in 2024.'),
  ('2024-02-19', 'LockBit law enforcement disruption (Operation Cronos)', 'Global', 'high',
   'International law enforcement disrupts LockBit. 34 servers seized, 2 arrested. Group resumed operations within days.'),
  ('2024-02-21', 'Change Healthcare ransomware attack (BlackCat)', 'USA', 'high',
   'Largest healthcare data breach in US history. 100M+ patient records. $22M ransom paid.'),
  ('2024-04-01', 'XZ Utils supply chain backdoor discovered (CVE-2024-3094)', 'Global', 'high',
   'Nation-state actor (likely Russia) nearly succeeds in backdooring Linux SSH via XZ Utils. Discovered by accident.'),
  ('2024-07-19', 'CrowdStrike global IT outage', 'Global', 'high',
   'Faulty update causes 8.5M Windows machines to blue screen. Not a cyberattack but largest IT outage in history. Demonstrated fragility of critical dependencies.'),
  ('2024-11-05', 'US Presidential Election', 'USA', 'medium',
   'Increased nation-state influence operations and scanning activity around election period.'),
  ('2025-01-01', 'Increased Volt Typhoon activity in US critical infrastructure', 'USA', 'high',
   'CISA issues multiple advisories on Chinese pre-positioning in US water, energy, and communications infrastructure.');
