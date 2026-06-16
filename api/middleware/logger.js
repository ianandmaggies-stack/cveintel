const REDACTED = '[REDACTED]';
const SENSITIVE_BODY_FIELDS = ['password', 'token', 'api_key', 'secret'];
const SENSITIVE_HEADERS     = ['authorization', 'cookie'];

function redactBody(body) {
  if (!body || typeof body !== 'object') return body;
  const clean = { ...body };
  for (const field of SENSITIVE_BODY_FIELDS) {
    if (clean[field]) clean[field] = REDACTED;
  }
  return clean;
}

export function requestLogger(req, res, next) {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    console.log(JSON.stringify({
      method:   req.method,
      path:     req.path,
      status:   res.statusCode,
      duration: `${duration}ms`,
      ip:       req.ip,
    }));
  });
  next();
}
