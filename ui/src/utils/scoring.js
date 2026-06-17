export const BANDS = {
  critical: { label: 'Critical', min: 75, color: '#E24B4A', bg: '#FCEBEB', text: '#A32D2D' },
  high:     { label: 'High',     min: 50, color: '#BA7517', bg: '#FAEEDA', text: '#854F0B' },
  medium:   { label: 'Medium',   min: 25, color: '#888780', bg: '#F5F5F4', text: '#57534E' },
  low:      { label: 'Low',      min: 0,  color: '#1D9E75', bg: '#E1F5EE', text: '#085041' },
};

export function getBand(score) {
  const s = parseFloat(score);
  if (s >= 75) return BANDS.critical;
  if (s >= 50) return BANDS.high;
  if (s >= 25) return BANDS.medium;
  return BANDS.low;
}

export function getBandName(score) {
  const s = parseFloat(score);
  if (s >= 75) return 'critical';
  if (s >= 50) return 'high';
  if (s >= 25) return 'medium';
  return 'low';
}
