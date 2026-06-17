import client from './client.js';

export const getDashboard = (clientId) =>
  client.get(`/clients/${clientId}/dashboard`).then(r => r.data.data);
