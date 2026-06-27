/**
 * stackConfig.js
 * Single source of truth for tech stack categories, subcategories,
 * vendor mappings, and product mappings.
 *
 * Structure:
 *   category       — top-level grouping (e.g. Microsoft)
 *   subs           — named subcategories with explicit vendor/product filters
 *   vendorMatch    — CPE vendor strings that belong to this category
 *   platformMatch  — platform_tag values that belong to this category
 *
 * "Other [category]" is computed automatically:
 *   - For vendor-based categories: vendor IN vendorMatch AND product NOT IN any named sub products
 *   - For platform-based categories: platform_tag IN platformMatch AND vendor NOT IN any named sub vendors
 *
 * DEFAULT_STACK — applied to new users before they configure their profile.
 * Only Microsoft and Linux subcategory IDs are enabled by default.
 */

export const STACK_CONFIG = [
  {
    id:           'microsoft',
    label:        'Microsoft',
    icon:         '🪟',
    vendorMatch:  ['microsoft'],
    subs: [
      { id: 'ms_winserver',  label: 'Windows Server',   products: ['windows_server'] },
      { id: 'ms_windesk',    label: 'Windows Desktop',  products: ['windows_10', 'windows_11', 'windows_8', 'windows_7'] },
      { id: 'ms_exchange',   label: 'Exchange',         products: ['exchange_server', 'exchange'] },
      { id: 'ms_office',     label: 'Office / M365',    products: ['office', '365', 'microsoft_365', 'word', 'excel', 'powerpoint', 'outlook'] },
      { id: 'ms_iis',        label: 'IIS',              products: ['iis', 'internet_information_server'] },
      { id: 'ms_sql',        label: 'SQL Server',       products: ['sql_server'] },
      { id: 'ms_azure',      label: 'Azure',            products: ['azure'] },
      { id: 'ms_sharepoint', label: 'SharePoint',       products: ['sharepoint'] },
      { id: 'ms_edge',       label: 'Edge / IE',        products: ['edge', 'internet_explorer'] },
      { id: 'ms_defender',   label: 'Defender / Security', products: ['defender', 'security_essentials'] },
      { id: 'ms_other',      label: 'Other Microsoft',  other: true },
    ],
  },
  {
    id:           'linux',
    label:        'Linux & Open Source',
    icon:         '🐧',
    vendorMatch:  ['linux', 'canonical', 'debian', 'redhat', 'fedoraproject', 'opensuse', 'suse', 'gnu'],
    subs: [
      { id: 'lx_kernel',   label: 'Linux Kernel',      vendors: ['linux'] },
      { id: 'lx_ubuntu',   label: 'Ubuntu / Canonical', vendors: ['canonical'] },
      { id: 'lx_debian',   label: 'Debian',            vendors: ['debian'] },
      { id: 'lx_rhel',     label: 'RHEL / RedHat',     vendors: ['redhat'] },
      { id: 'lx_fedora',   label: 'Fedora',            vendors: ['fedoraproject'] },
      { id: 'lx_suse',     label: 'SUSE / openSUSE',   vendors: ['suse', 'opensuse'] },
      { id: 'lx_apache',   label: 'Apache',            vendors: ['apache'] },
      { id: 'lx_nginx',    label: 'nginx',             vendors: ['nginx', 'f5'] },
      { id: 'lx_openssl',  label: 'OpenSSL',           vendors: ['openssl'] },
      { id: 'lx_gnu',      label: 'GNU / glibc',       vendors: ['gnu'] },
      { id: 'lx_other',    label: 'Other Linux / OSS', other: true },
    ],
  },
  {
    id:           'apple',
    label:        'Apple',
    icon:         '🍎',
    vendorMatch:  ['apple'],
    subs: [
      { id: 'ap_macos',   label: 'macOS',        products: ['macos', 'mac_os_x', 'mac_os'] },
      { id: 'ap_ios',     label: 'iOS / iPadOS', products: ['iphone_os', 'ipados', 'ios'] },
      { id: 'ap_safari',  label: 'Safari',       products: ['safari'] },
      { id: 'ap_xcode',   label: 'Xcode',        products: ['xcode'] },
      { id: 'ap_icloud',  label: 'iCloud',       products: ['icloud'] },
      { id: 'ap_other',   label: 'Other Apple',  other: true },
    ],
  },
  {
    id:           'google',
    label:        'Google',
    icon:         '🔍',
    vendorMatch:  ['google'],
    subs: [
      { id: 'go_chrome',    label: 'Chrome / Chromium', products: ['chrome', 'chromium'] },
      { id: 'go_android',   label: 'Android',           products: ['android'] },
      { id: 'go_gcp',       label: 'Google Cloud',      products: ['cloud'] },
      { id: 'go_workspace', label: 'Workspace',         products: ['workspace', 'gmail', 'drive'] },
      { id: 'go_other',     label: 'Other Google',      other: true },
    ],
  },
  {
    id:           'oracle',
    label:        'Oracle',
    icon:         '🗄️',
    vendorMatch:  ['oracle', 'sun'],
    subs: [
      { id: 'or_db',       label: 'Oracle Database', products: ['database', 'db'] },
      { id: 'or_java',     label: 'Java / JDK',      products: ['jdk', 'jre', 'java'] },
      { id: 'or_weblogic', label: 'WebLogic',        products: ['weblogic'] },
      { id: 'or_mysql',    label: 'MySQL',           products: ['mysql'] },
      { id: 'or_vbox',     label: 'VirtualBox',      products: ['virtualbox'] },
      { id: 'or_other',    label: 'Other Oracle',    other: true },
    ],
  },
  {
    id:           'cisco',
    label:        'Cisco',
    icon:         '🌐',
    vendorMatch:  ['cisco'],
    subs: [
      { id: 'ci_ios',      label: 'IOS / IOS-XE',  products: ['ios', 'ios_xe', 'ios_xr'] },
      { id: 'ci_asa',      label: 'ASA / Firewall', products: ['adaptive_security_appliance', 'asa', 'firepower'] },
      { id: 'ci_webex',    label: 'Webex',          products: ['webex'] },
      { id: 'ci_nxos',     label: 'NX-OS',          products: ['nx-os', 'nxos'] },
      { id: 'ci_other',    label: 'Other Cisco',    other: true },
    ],
  },
  {
    id:           'ibm',
    label:        'IBM',
    icon:         '🏢',
    vendorMatch:  ['ibm'],
    subs: [
      { id: 'ib_aix',       label: 'AIX',           products: ['aix'] },
      { id: 'ib_websphere', label: 'WebSphere',      products: ['websphere'] },
      { id: 'ib_db2',       label: 'Db2',           products: ['db2'] },
      { id: 'ib_zos',       label: 'z/OS',          products: ['z/os', 'zos'] },
      { id: 'ib_other',     label: 'Other IBM',     other: true },
    ],
  },
  {
    id:           'adobe',
    label:        'Adobe',
    icon:         '🎨',
    vendorMatch:  ['adobe'],
    subs: [
      { id: 'ad_acrobat',   label: 'Acrobat / Reader',   products: ['acrobat', 'reader'] },
      { id: 'ad_cf',        label: 'ColdFusion',         products: ['coldfusion'] },
      { id: 'ad_commerce',  label: 'Commerce / Magento', products: ['commerce', 'magento'] },
      { id: 'ad_creative',  label: 'Creative Cloud',     products: ['photoshop', 'illustrator', 'premiere', 'after_effects', 'creative_cloud'] },
      { id: 'ad_other',     label: 'Other Adobe',        other: true },
    ],
  },
  {
    id:           'network',
    label:        'Network & Perimeter',
    icon:         '🔒',
    platformMatch: ['network'],
    vendorMatch:  ['fortinet', 'palo_alto_networks', 'juniper', 'f5', 'citrix', 'ivanti', 'pulsesecure', 'sonicwall', 'barracuda', 'checkpoint'],
    subs: [
      { id: 'nw_fortinet',  label: 'Fortinet',        vendors: ['fortinet'] },
      { id: 'nw_paloalto',  label: 'Palo Alto',       vendors: ['palo_alto_networks'] },
      { id: 'nw_juniper',   label: 'Juniper',         vendors: ['juniper'] },
      { id: 'nw_f5',        label: 'F5 BIG-IP',       vendors: ['f5'] },
      { id: 'nw_citrix',    label: 'Citrix',          vendors: ['citrix'] },
      { id: 'nw_ivanti',    label: 'Ivanti / Pulse',  vendors: ['ivanti', 'pulsesecure'] },
      { id: 'nw_sonicwall', label: 'SonicWall',       vendors: ['sonicwall'] },
      { id: 'nw_other',     label: 'Other Network',   other: true },
    ],
  },
  {
    id:           'soho',
    label:        'SOHO / Consumer Network',
    icon:         '📡',
    vendorMatch:  ['dlink', 'netgear', 'tenda', 'totolink', 'tp-link', 'asus', 'zyxel', 'huawei'],
    subs: [
      { id: 'sh_dlink',    label: 'D-Link',    vendors: ['dlink'] },
      { id: 'sh_netgear',  label: 'Netgear',   vendors: ['netgear'] },
      { id: 'sh_tenda',    label: 'Tenda',     vendors: ['tenda'] },
      { id: 'sh_tplink',   label: 'TP-Link',   vendors: ['tp-link'] },
      { id: 'sh_asus',     label: 'ASUS',      vendors: ['asus'] },
      { id: 'sh_zyxel',    label: 'Zyxel',     vendors: ['zyxel'] },
      { id: 'sh_huawei',   label: 'Huawei',    vendors: ['huawei'] },
      { id: 'sh_other',    label: 'Other SOHO', other: true },
    ],
  },
  {
    id:           'cloud',
    label:        'Cloud & Virtualisation',
    icon:         '☁️',
    vendorMatch:  ['vmware', 'docker', 'kubernetes', 'amazon', 'hashicorp'],
    subs: [
      { id: 'cl_vmware',  label: 'VMware',      vendors: ['vmware'] },
      { id: 'cl_docker',  label: 'Docker',      vendors: ['docker'] },
      { id: 'cl_k8s',     label: 'Kubernetes',  vendors: ['kubernetes'] },
      { id: 'cl_aws',     label: 'AWS',         vendors: ['amazon'] },
      { id: 'cl_other',   label: 'Other Cloud', other: true },
    ],
  },
  {
    id:           'hardware',
    label:        'Hardware & Firmware',
    icon:         '💾',
    vendorMatch:  ['intel', 'qualcomm', 'nvidia', 'samsung', 'hp', 'dell', 'lenovo', 'amd'],
    subs: [
      { id: 'hw_intel',    label: 'Intel',    vendors: ['intel'] },
      { id: 'hw_qualcomm', label: 'Qualcomm', vendors: ['qualcomm'] },
      { id: 'hw_nvidia',   label: 'NVIDIA',   vendors: ['nvidia'] },
      { id: 'hw_amd',      label: 'AMD',      vendors: ['amd'] },
      { id: 'hw_hp',       label: 'HP / HPE', vendors: ['hp', 'hpe', 'hewlett-packard'] },
      { id: 'hw_dell',     label: 'Dell',     vendors: ['dell'] },
      { id: 'hw_lenovo',   label: 'Lenovo',   vendors: ['lenovo'] },
      { id: 'hw_samsung',  label: 'Samsung',  vendors: ['samsung'] },
      { id: 'hw_other',    label: 'Other Hardware', other: true },
    ],
  },
  {
    id:           'enterprise',
    label:        'Enterprise Software',
    icon:         '🏗️',
    vendorMatch:  ['sap', 'gitlab', 'jenkins', 'atlassian', 'foxitsoftware', 'mozilla', 'elastic', 'splunk'],
    subs: [
      { id: 'en_sap',       label: 'SAP',              vendors: ['sap'] },
      { id: 'en_gitlab',    label: 'GitLab',           vendors: ['gitlab'] },
      { id: 'en_jenkins',   label: 'Jenkins',          vendors: ['jenkins'] },
      { id: 'en_atlassian', label: 'Atlassian',        vendors: ['atlassian'] },
      { id: 'en_mozilla',   label: 'Firefox / Mozilla', vendors: ['mozilla'] },
      { id: 'en_elastic',   label: 'Elastic / Kibana', vendors: ['elastic'] },
      { id: 'en_splunk',    label: 'Splunk',           vendors: ['splunk'] },
      { id: 'en_other',     label: 'Other Enterprise', other: true },
    ],
  },
  {
    id:           'ot',
    label:        'Industrial & OT',
    icon:         '🏭',
    vendorMatch:  ['siemens', 'schneider-electric', 'rockwell', 'honeywell', 'ge', 'abb'],
    subs: [
      { id: 'ot_siemens',    label: 'Siemens',           vendors: ['siemens'] },
      { id: 'ot_schneider',  label: 'Schneider Electric', vendors: ['schneider-electric'] },
      { id: 'ot_rockwell',   label: 'Rockwell',          vendors: ['rockwell', 'allen-bradley'] },
      { id: 'ot_honeywell',  label: 'Honeywell',         vendors: ['honeywell'] },
      { id: 'ot_other',      label: 'Other OT / ICS',    other: true },
    ],
  },
];

// All sub IDs enabled by default (Microsoft + Linux only)
export const DEFAULT_STACK = {
  stack_configured: false,
  enabled: [
    // Microsoft
    'ms_winserver', 'ms_windesk', 'ms_exchange', 'ms_office',
    'ms_iis', 'ms_sql', 'ms_azure', 'ms_sharepoint',
    'ms_edge', 'ms_defender', 'ms_other',
    // Linux & Open Source
    'lx_kernel', 'lx_ubuntu', 'lx_debian', 'lx_rhel',
    'lx_fedora', 'lx_suse', 'lx_apache', 'lx_nginx',
    'lx_openssl', 'lx_gnu', 'lx_other',
  ],
};

// Helper: get all sub IDs for a category
export function getCategorySubIds(category) {
  return category.subs.map(s => s.id);
}

// Helper: check if all subs in a category are enabled
export function isCategoryFullyEnabled(category, enabled) {
  return getCategorySubIds(category).every(id => enabled.includes(id));
}

// Helper: check if any subs in a category are enabled
export function isCategoryPartiallyEnabled(category, enabled) {
  const ids = getCategorySubIds(category);
  const enabledCount = ids.filter(id => enabled.includes(id)).length;
  return enabledCount > 0 && enabledCount < ids.length;
}

// Build vendor/platform filter params for API queries from enabled sub IDs
export function buildFilterParams(enabled) {
  if (!enabled || enabled.length === 0) return {};

  const vendorIncludes   = new Set();
  const vendorExcludes   = new Map(); // category vendorMatch -> excluded named vendors
  const platformIncludes = new Set();
  const productExcludes  = new Map(); // vendor -> excluded named products

  for (const category of STACK_CONFIG) {
    const catSubIds   = getCategorySubIds(category);
    const enabledSubs = category.subs.filter(s => enabled.includes(s.id));
    if (enabledSubs.length === 0) continue;

    // Which named subs are enabled vs not
    const namedSubs      = category.subs.filter(s => !s.other);
    const otherSub       = category.subs.find(s => s.other);
    const enabledNamed   = namedSubs.filter(s => enabled.includes(s.id));
    const otherEnabled   = otherSub && enabled.includes(otherSub.id);

    if (category.vendorMatch) {
      // Vendor-based category
      const allEnabled = enabledSubs.length === catSubIds.length;

      if (allEnabled) {
        // Everything in this category — just match all vendors
        category.vendorMatch.forEach(v => vendorIncludes.add(v));
      } else {
        // Partial selection
        // Add vendors from named enabled subs
        for (const sub of enabledNamed) {
          if (sub.vendors) sub.vendors.forEach(v => vendorIncludes.add(v));
          else category.vendorMatch.forEach(v => vendorIncludes.add(v)); // product-filtered
        }
        // Add "other" = vendor in category but NOT in named sub vendors
        if (otherEnabled) {
          category.vendorMatch.forEach(v => vendorIncludes.add(v));
        }
      }
    }

    if (category.platformMatch) {
      category.platformMatch.forEach(p => platformIncludes.add(p));
    }
  }

  return {
    vendors:   Array.from(vendorIncludes),
    platforms: Array.from(platformIncludes),
  };
}
