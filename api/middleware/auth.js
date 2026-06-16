import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-in-production';

export async function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      error: { code: 'AUTH_REQUIRED', message: 'Authentication required', status: 401 }
    });
  }
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({
        error: { code: 'AUTH_EXPIRED', message: 'Token expired', status: 401 }
      });
    }
    return res.status(401).json({
      error: { code: 'AUTH_REQUIRED', message: 'Invalid token', status: 401 }
    });
  }
}

export function requireClientScope(req, res, next) {
  const urlClientId   = req.params.clientId;
  const tokenClientId = req.user?.client_id;
  const isAdmin       = req.user?.role === 'admin';
  if (isAdmin) return next();
  if (!urlClientId || urlClientId !== tokenClientId) {
    return res.status(403).json({
      error: { code: 'FORBIDDEN', message: 'Access denied', status: 403 }
    });
  }
  next();
}

export function requireAdmin(req, res, next) {
  if (req.user?.role !== 'admin') {
    return res.status(403).json({
      error: { code: 'FORBIDDEN', message: 'Admin access required', status: 403 }
    });
  }
  next();
}

export function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '8h' });
}

export function signRefreshToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
}
