import client from './client.js';

export async function getBrief() {
  const res = await client.get('/brief');
  return res.data.data;
}
