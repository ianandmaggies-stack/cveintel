export function formatScore(score) {
  return parseFloat(score).toFixed(1);
}

export function formatDate(dateStr) {
  if (!dateStr) return '—';
  return new Date(dateStr).toISOString().split('T')[0];
}

export function formatEpss(score) {
  if (!score) return '—';
  return `${(parseFloat(score) * 100).toFixed(1)}%`;
}

export function truncate(str, n = 80) {
  if (!str) return '—';
  return str.length > n ? str.slice(0, n) + '...' : str;
}
