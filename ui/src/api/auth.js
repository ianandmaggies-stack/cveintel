import axios from 'axios';

export const login = (email, password) =>
  axios.post('/api/v1/auth/login', { email, password }).then(r => r.data.data);

export const logout = () =>
  axios.post('/api/v1/auth/logout').then(r => r.data);
