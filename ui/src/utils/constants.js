export const ALERT_TYPES = [
  'new_match', 'kev_added', 'score_spike',
  'score_drop', 'exploit_added', 'pre_kev_flag',
  'ransomware_added', 'eol_detected'
];

export const PLATFORMS = ['microsoft', 'linux', 'network', 'other'];

export const EXPOSURE  = ['external', 'internal'];

export const STATUS_OPTIONS = [
  { value: 'active',        label: 'Active' },
  { value: 'patched',       label: 'Patched' },
  { value: 'accepted_risk', label: 'Accept risk' },
  { value: 'not_applicable', label: 'Not applicable' },
];
