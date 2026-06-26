import client from './client.js';

export async function getDiagnostics() {
  const res = await client.get('/diagnostics');
  return res.data.data;
}
