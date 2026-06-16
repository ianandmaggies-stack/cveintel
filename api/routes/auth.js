import express from 'express';
import { signToken, signRefreshToken, requireAuth } from '../middleware/auth.js';

const router = express.Router();

// POST /api/v1/auth/login
// Dev mode: hardcoded admin credentials
// TODO: replace with real user table lookup
router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({
      error: { code: 'INVALID_INPUT', message: 'Email and password required', status: 400 }
    });
  }
  try {
    if (email === 'admin@cveintel.dev' && password === 'dev-password') {
      const token        = signToken({ client_id: 'dev-client-id', email, role: 'admin' });
      const refreshToken = signRefreshToken({ email, role: 'admin' });
      return res.json({ data: { token, refresh_token: refreshToken, role: 'admin' } });
    }
    return res.status(401).json({
      error: { code: 'AUTH_REQUIRED', message: 'Invalid credentials', status: 401 }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'Login failed', status: 500 } });
  }
});

// POST /api/v1/auth/refresh
router.post('/refresh', requireAuth, async (req, res) => {
  try {
    const token = signToken({ client_id: req.user.client_id, email: req.user.email, role: req.user.role });
    res.json({ data: { token } });
  } catch (err) {
    res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'Token refresh failed', status: 500 } });
  }
});

// POST /api/v1/auth/logout
router.post('/logout', requireAuth, (req, res) => {
  res.json({ data: { message: 'Logged out successfully' } });
});

export default router;
