import client from './client.js';

export const getLandscape = () =>
  client.get('/landscape').then(r => r.data.data);
