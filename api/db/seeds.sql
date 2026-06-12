-- ============================================
-- CVE INTEL — SEED DATA
-- ============================================

-- ============================================
-- platform_vendor_map
-- Maps vendor name patterns to platform tags
-- ============================================

INSERT INTO platform_vendor_map (vendor_pattern, platform_tag) VALUES
    ('microsoft',           'microsoft'),
    ('windows',             'microsoft'),
    ('office',              'microsoft'),
    ('exchange',            'microsoft'),
    ('iis',                 'microsoft'),
    ('sql_server',          'microsoft'),
    ('azure',               'microsoft'),
    ('sharepoint',          'microsoft'),
    ('skype',               'microsoft'),
    ('teams',               'microsoft'),
    ('red_hat',             'linux'),
    ('redhat',              'linux'),
    ('canonical',           'linux'),
    ('ubuntu',              'linux'),
    ('debian',              'linux'),
    ('centos',              'linux'),
    ('fedora',              'linux'),
    ('suse',                'linux'),
    ('opensuse',            'linux'),
    ('apache',              'linux'),
    ('nginx',               'linux'),
    ('openssl',             'linux'),
    ('openssh',             'linux'),
    ('linux',               'linux'),
    ('docker',              'linux'),
    ('kubernetes',          'linux'),
    ('containerd',          'linux'),
    ('mysql',               'linux'),
    ('mariadb',             'linux'),
    ('postgresql',          'linux'),
    ('php',                 'linux'),
    ('python',              'linux'),
    ('perl',                'linux'),
    ('ruby',                'linux'),
    ('cisco',               'network'),
    ('fortinet',            'network'),
    ('palo_alto',           'network'),
    ('f5',                  'network'),
    ('juniper',             'network'),
    ('checkpoint',          'network'),
    ('sonicwall',           'network'),
    ('netgear',             'network'),
    ('ubiquiti',            'network'),
    ('watchguard',          'network'),
    ('citrix',              'network'),
    ('pulse_secure',        'network'),
    ('ivanti',              'network'),
    ('vmware',              'other'),
    ('oracle',              'other'),
    ('sap',                 'other'),
    ('ibm',                 'other'),
    ('adobe',               'other'),
    ('google',              'other'),
    ('mozilla',             'other'),
    ('apple',               'other'),
    ('zoom',                'other'),
    ('atlassian',           'other'),
    ('confluence',          'other'),
    ('jira',                'other');

-- ============================================
-- product_lifecycle
-- EOL dates for common products
-- ============================================

INSERT INTO product_lifecycle
    (product_id, display_name, vendor, eol_date, extended_support_end, platform_tag)
VALUES
    -- Microsoft Windows Server
    ('ms_ws_2008',    'Windows Server 2008',       'microsoft', '2020-01-14', NULL,         'microsoft'),
    ('ms_ws_2008r2',  'Windows Server 2008 R2',    'microsoft', '2020-01-14', NULL,         'microsoft'),
    ('ms_ws_2012',    'Windows Server 2012',       'microsoft', '2023-10-10', NULL,         'microsoft'),
    ('ms_ws_2012r2',  'Windows Server 2012 R2',    'microsoft', '2023-10-10', NULL,         'microsoft'),
    ('ms_ws_2016',    'Windows Server 2016',       'microsoft', '2027-01-12', NULL,         'microsoft'),
    ('ms_ws_2019',    'Windows Server 2019',       'microsoft', '2029-01-09', NULL,         'microsoft'),
    ('ms_ws_2022',    'Windows Server 2022',       'microsoft', '2031-10-14', NULL,         'microsoft'),
    -- Microsoft Windows Desktop
    ('ms_w7',         'Windows 7',                 'microsoft', '2020-01-14', NULL,         'microsoft'),
    ('ms_w8',         'Windows 8',                 'microsoft', '2016-01-12', NULL,         'microsoft'),
    ('ms_w81',        'Windows 8.1',               'microsoft', '2023-01-10', NULL,         'microsoft'),
    ('ms_w10',        'Windows 10',                'microsoft', '2025-10-14', NULL,         'microsoft'),
    ('ms_w11',        'Windows 11',                'microsoft', '2031-10-14', NULL,         'microsoft'),
    -- Microsoft Exchange
    ('ms_ex_2010',    'Exchange Server 2010',      'microsoft', '2020-10-13', NULL,         'microsoft'),
    ('ms_ex_2013',    'Exchange Server 2013',      'microsoft', '2023-04-11', NULL,         'microsoft'),
    ('ms_ex_2016',    'Exchange Server 2016',      'microsoft', '2025-10-14', NULL,         'microsoft'),
    ('ms_ex_2019',    'Exchange Server 2019',      'microsoft', '2025-10-14', NULL,         'microsoft'),
    -- Microsoft SQL Server
    ('ms_sql_2012',   'SQL Server 2012',           'microsoft', '2022-07-12', NULL,         'microsoft'),
    ('ms_sql_2014',   'SQL Server 2014',           'microsoft', '2024-07-09', NULL,         'microsoft'),
    ('ms_sql_2016',   'SQL Server 2016',           'microsoft', '2026-07-14', NULL,         'microsoft'),
    ('ms_sql_2017',   'SQL Server 2017',           'microsoft', '2027-10-12', NULL,         'microsoft'),
    ('ms_sql_2019',   'SQL Server 2019',           'microsoft', '2030-01-08', NULL,         'microsoft'),
    -- Red Hat
    ('rh_el6',        'Red Hat Enterprise Linux 6','red_hat',   '2024-06-30', NULL,         'linux'),
    ('rh_el7',        'Red Hat Enterprise Linux 7','red_hat',   '2024-06-30', '2026-06-30', 'linux'),
    ('rh_el8',        'Red Hat Enterprise Linux 8','red_hat',   '2029-05-31', NULL,         'linux'),
    ('rh_el9',        'Red Hat Enterprise Linux 9','red_hat',   '2032-05-31', NULL,         'linux'),
    -- Ubuntu
    ('ub_1804',       'Ubuntu 18.04 LTS',          'canonical', '2023-04-30', '2028-04-30', 'linux'),
    ('ub_2004',       'Ubuntu 20.04 LTS',          'canonical', '2025-04-30', '2030-04-30', 'linux'),
    ('ub_2204',       'Ubuntu 22.04 LTS',          'canonical', '2027-04-30', '2032-04-30', 'linux'),
    ('ub_2404',       'Ubuntu 24.04 LTS',          'canonical', '2029-04-30', '2034-04-30', 'linux'),
    -- OpenSSL
    ('ossl_10',       'OpenSSL 1.0.x',             'openssl',   '2019-12-31', NULL,         'linux'),
    ('ossl_11',       'OpenSSL 1.1.x',             'openssl',   '2023-09-11', NULL,         'linux'),
    ('ossl_30',       'OpenSSL 3.0.x',             'openssl',   '2026-09-07', NULL,         'linux'),
    ('ossl_31',       'OpenSSL 3.1.x',             'openssl',   '2025-03-14', NULL,         'linux'),
    ('ossl_32',       'OpenSSL 3.2.x',             'openssl',   '2026-11-23', NULL,         'linux');

-- ============================================
-- client_profiles
-- Predefined stack bundles
-- ============================================

INSERT INTO client_profiles (profile_id, label, description, cpe_bundle, default_platform_tags)
VALUES
(
    'enterprise_windows',
    'Large org, mostly Microsoft',
    'Windows Server, Exchange, IIS, SQL Server, M365 — typical large enterprise stack',
    '[
        {"cpe": "cpe:2.3:o:microsoft:windows_server_2022:*", "display_name": "Windows Server 2022", "platform_tag": "microsoft", "known_versions": ["2022", "2019", "2016", "2012 R2"]},
        {"cpe": "cpe:2.3:a:microsoft:exchange_server:*", "display_name": "Microsoft Exchange Server", "platform_tag": "microsoft", "known_versions": ["2019", "2016", "2013"]},
        {"cpe": "cpe:2.3:a:microsoft:internet_information_services:*", "display_name": "IIS", "platform_tag": "microsoft", "known_versions": ["10.x", "8.5"]},
        {"cpe": "cpe:2.3:a:microsoft:sql_server:*", "display_name": "SQL Server", "platform_tag": "microsoft", "known_versions": ["2022", "2019", "2017", "2016"]},
        {"cpe": "cpe:2.3:a:microsoft:365:*", "display_name": "Microsoft 365", "platform_tag": "microsoft", "known_versions": ["current"]}
    ]'::jsonb,
    '["microsoft"]'::jsonb
),
(
    'linux_web_stack',
    'Web-facing Linux stack',
    'Apache or Nginx, OpenSSL, Linux distros, Docker — web-facing and cloud',
    '[
        {"cpe": "cpe:2.3:a:apache:http_server:*", "display_name": "Apache HTTP Server", "platform_tag": "linux", "known_versions": ["2.4.x", "2.4.58", "2.4.51"]},
        {"cpe": "cpe:2.3:a:nginx:nginx:*", "display_name": "Nginx", "platform_tag": "linux", "known_versions": ["1.24.x", "1.25.x"]},
        {"cpe": "cpe:2.3:a:openssl:openssl:*", "display_name": "OpenSSL", "platform_tag": "linux", "known_versions": ["3.x", "1.1.1"]},
        {"cpe": "cpe:2.3:o:canonical:ubuntu_linux:*", "display_name": "Ubuntu Linux", "platform_tag": "linux", "known_versions": ["24.04", "22.04", "20.04"]},
        {"cpe": "cpe:2.3:a:docker:docker:*", "display_name": "Docker Engine", "platform_tag": "linux", "known_versions": ["current", "24.x"]}
    ]'::jsonb,
    '["linux"]'::jsonb
),
(
    'mixed_smb',
    'Small / medium business',
    'Windows desktops and servers mixed with common Linux services',
    '[
        {"cpe": "cpe:2.3:o:microsoft:windows_server_2019:*", "display_name": "Windows Server 2019", "platform_tag": "microsoft", "known_versions": ["2019", "2016"]},
        {"cpe": "cpe:2.3:o:microsoft:windows_10:*", "display_name": "Windows 10", "platform_tag": "microsoft", "known_versions": ["22H2", "21H2"]},
        {"cpe": "cpe:2.3:a:microsoft:office:*", "display_name": "Microsoft Office", "platform_tag": "microsoft", "known_versions": ["2021", "2019", "365"]},
        {"cpe": "cpe:2.3:a:apache:http_server:*", "display_name": "Apache HTTP Server", "platform_tag": "linux", "known_versions": ["2.4.x"]},
        {"cpe": "cpe:2.3:a:openssl:openssl:*", "display_name": "OpenSSL", "platform_tag": "linux", "known_versions": ["3.x", "1.1.1"]}
    ]'::jsonb,
    '["microsoft", "linux"]'::jsonb
),
(
    'network_heavy',
    'Network and infrastructure',
    'Cisco, Fortinet, Palo Alto, F5 — edge-heavy network infrastructure',
    '[
        {"cpe": "cpe:2.3:o:cisco:ios:*", "display_name": "Cisco IOS", "platform_tag": "network", "known_versions": ["15.x", "16.x", "17.x"]},
        {"cpe": "cpe:2.3:o:cisco:ios_xe:*", "display_name": "Cisco IOS XE", "platform_tag": "network", "known_versions": ["17.x", "16.x"]},
        {"cpe": "cpe:2.3:o:fortinet:fortios:*", "display_name": "Fortinet FortiOS", "platform_tag": "network", "known_versions": ["7.x", "6.4.x"]},
        {"cpe": "cpe:2.3:o:paloaltonetworks:pan-os:*", "display_name": "Palo Alto PAN-OS", "platform_tag": "network", "known_versions": ["11.x", "10.x"]},
        {"cpe": "cpe:2.3:a:f5:big-ip:*", "display_name": "F5 BIG-IP", "platform_tag": "network", "known_versions": ["17.x", "16.x"]}
    ]'::jsonb,
    '["network"]'::jsonb
),
(
    'devops_cloud',
    'Cloud-native / DevOps',
    'Kubernetes, Docker, AWS and Azure components, Linux — cloud-native stack',
    '[
        {"cpe": "cpe:2.3:a:kubernetes:kubernetes:*", "display_name": "Kubernetes", "platform_tag": "linux", "known_versions": ["1.29.x", "1.28.x"]},
        {"cpe": "cpe:2.3:a:docker:docker:*", "display_name": "Docker Engine", "platform_tag": "linux", "known_versions": ["current", "24.x"]},
        {"cpe": "cpe:2.3:a:containerd:containerd:*", "display_name": "containerd", "platform_tag": "linux", "known_versions": ["1.7.x"]},
        {"cpe": "cpe:2.3:o:canonical:ubuntu_linux:*", "display_name": "Ubuntu Linux", "platform_tag": "linux", "known_versions": ["24.04", "22.04"]},
        {"cpe": "cpe:2.3:a:openssl:openssl:*", "display_name": "OpenSSL", "platform_tag": "linux", "known_versions": ["3.x"]}
    ]'::jsonb,
    '["linux"]'::jsonb
),
(
    'custom',
    'I will define my own stack',
    'Manually declare your full stack — complete CPE control',
    '[]'::jsonb,
    '[]'::jsonb
);
