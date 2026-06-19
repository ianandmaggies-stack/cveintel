import client from './client.js';

export const getPosture = (clientId) =>
  client.get(`/clients/${clientId}/posture`).then(r => r.data.data);

export const getDashboard = (clientId) =>
  client.get(`/clients/${clientId}/dashboard`).then(r => r.data.data);
