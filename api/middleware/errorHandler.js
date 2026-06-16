export function errorHandler(err, req, res, next) {
  console.error('Unhandled error:', err.message);
  res.status(500).json({
    error: {
      code:    'INTERNAL_ERROR',
      message: 'An unexpected error occurred',
      status:  500
    }
  });
}
