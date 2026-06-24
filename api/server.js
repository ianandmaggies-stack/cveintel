import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import dotenv from 'dotenv';
import { rateLimit } from 'express-rate-limit';

import authRoutes from './routes/auth.js';
import dashboardRoutes from './routes/dashboard.js';
import cveRoutes from './routes/cves.js';
import alertRoutes from './routes/alerts.js';
import postureRoutes from './routes/posture.js';
import adminRoutes from './routes/admin.js';
import landscapeRoutes from './routes/landscape.js';

import { requestLogger } from './middleware/logger.js';
import { errorHandler } from './middleware/errorHandler.js';

dotenv.config();

const app  = express();
const PORT = process.env.API_PORT || 4000;
const HOST = '0.0.0.0';

app.use(helmet());
app.use(cors({
  origin: [
    'http://localhost:5174',
    'http://192.168.0.86:5174',
    process.env.CORS_ORIGIN
  ].filter(Boolean)
}));
app.use(express.json());
app.use(requestLogger);

const standardLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: { code: 'RATE_LIMITED', message: 'Too many requests', status: 429 } }
});

app.use('/api/', standardLimiter);

app.use('/api/v1/auth',      authRoutes);
app.use('/api/v1',           dashboardRoutes);
app.use('/api/v1',           cveRoutes);
app.use('/api/v1',           alertRoutes);
app.use('/api/v1',           postureRoutes);
app.use('/api/v1',           landscapeRoutes);
app.use('/api/v1/admin',     adminRoutes);

app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.use((req, res) => {
  res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Endpoint not found', status: 404 } });
});

app.use(errorHandler);

app.listen(PORT, HOST, () => {
  console.log(`CVE Intel API running on ${HOST}:${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});

export default app;
