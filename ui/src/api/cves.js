import client from './client.js';

export const getCves = (clientId, params) =>
  client.get(`/clients/${clientId}/cves`, { params }).then(r => r.data);

export const getCve = (clientId, cveId) =>
  client.get(`/clients/${clientId}/cves/${cveId}`).then(r => r.data.data);
