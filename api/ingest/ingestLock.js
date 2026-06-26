/**
 * ingestLock.js
 * Shared lock management for all ingest jobs.
 *
 * Handles:
 * - Stale lock detection and auto-clear (job marked running but process is dead)
 * - Phantom log entry cleanup (running entries with no completion)
 * - Lock acquisition with age check
 */

const STALE_LOCK_HOURS = 6;

export async function acquireLock(pool, jobName) {
  // Check for existing lock
  const status = await pool.query(
    `SELECT is_running, started_at,
       EXTRACT(EPOCH FROM (NOW() - started_at)) / 3600 AS running_hours
     FROM ingest_status WHERE job_name = $1`,
    [jobName]
  );

  const row = status.rows[0];

  if (row?.is_running) {
    const hours = parseFloat(row.running_hours || 0);
    if (hours < STALE_LOCK_HOURS) {
      console.log(`[${jobName}] Already running (${hours.toFixed(1)}h). Skipping.`);
      return false;
    }
    // Lock is stale — auto clear it and mark phantom log entry as failed
    console.warn(`[${jobName}] Stale lock detected (${hours.toFixed(1)}h) — clearing automatically.`);
    await pool.query(
      `UPDATE ingest_log
       SET status = 'failed', completed_at = NOW(),
           error_message = 'Process killed — lock cleared automatically after ${STALE_LOCK_HOURS}h'
       WHERE job_name = $1 AND status = 'running'`,
      [jobName]
    );
    await pool.query(
      `UPDATE ingest_status SET is_running = FALSE, started_at = NULL WHERE job_name = $1`,
      [jobName]
    );
  }

  // Acquire lock
  await pool.query(
    `UPDATE ingest_status SET is_running = TRUE, started_at = NOW() WHERE job_name = $1`,
    [jobName]
  );
  return true;
}

export async function releaseLock(pool, jobName) {
  await pool.query(
    `UPDATE ingest_status SET is_running = FALSE, started_at = NULL WHERE job_name = $1`,
    [jobName]
  );
}

export async function logStart(pool, jobName) {
  const result = await pool.query(
    `INSERT INTO ingest_log (job_name, started_at, status)
     VALUES ($1, NOW(), 'running') RETURNING log_id`,
    [jobName]
  );
  return result.rows[0].log_id;
}

export async function logComplete(pool, logId, counts) {
  await pool.query(
    `UPDATE ingest_log SET
       completed_at     = NOW(),
       status           = $1,
       records_fetched  = $2,
       records_inserted = $3,
       records_updated  = $4,
       records_failed   = $5,
       error_message    = $6
     WHERE log_id = $7`,
    [
      counts.status,
      counts.fetched  || 0,
      counts.inserted || 0,
      counts.updated  || 0,
      counts.failed   || 0,
      counts.error    || null,
      logId
    ]
  );
}
