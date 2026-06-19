#!/bin/bash
# CVE Intel — Cron wrapper
# Called by cron, handles logging and lock checking
# Usage: /home/cve/cveintel/cron.sh {kev|epss|nvd|scores|daily}

ROOT="/home/cve/cveintel"
API="$ROOT/api"
LOG_DIR="$ROOT/logs"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
DATE=$(date '+%Y%m%d_%H%M%S')

mkdir -p $LOG_DIR

# Ensure PostgreSQL is running before any ingest
if ! systemctl is-active --quiet postgresql@16-main; then
  echo "[$TIMESTAMP] PostgreSQL not running, starting..." >> $LOG_DIR/cron.log
  sudo systemctl start postgresql@16-main
  sleep 5
fi

# Check for stuck locks older than 2 hours and clear them
psql -U cveintel_user -d cveintel -h localhost -c \
  "UPDATE ingest_log
   SET status='failed', error_message='Cleared by cron - exceeded 2 hour timeout', completed_at=NOW()
   WHERE status='running'
   AND started_at < NOW() - INTERVAL '2 hours';
   UPDATE ingest_status SET is_running=FALSE, started_at=NULL
   WHERE is_running=TRUE AND started_at < NOW() - INTERVAL '2 hours';" \
  >> $LOG_DIR/cron.log 2>&1

function run_job() {
  JOB=$1
  SCRIPT=$2
  FLAGS=$3
  LOG_FILE="$LOG_DIR/${JOB}_${DATE}.log"

  echo "[$TIMESTAMP] Starting $JOB ingest" >> $LOG_DIR/cron.log
  cd $API && node $FLAGS $SCRIPT >> $LOG_FILE 2>&1

  if [ $? -eq 0 ]; then
    echo "[$TIMESTAMP] $JOB completed successfully" >> $LOG_DIR/cron.log
  else
    echo "[$TIMESTAMP] $JOB FAILED - see $LOG_FILE" >> $LOG_DIR/cron.log
  fi

  # Keep only last 14 days of logs
  find $LOG_DIR -name "*.log" -mtime +14 -delete 2>/dev/null
}

case "$1" in
  kev)
    run_job "kev" "ingest/kev.js" ""
    ;;
  epss)
    run_job "epss" "ingest/epss.js" ""
    ;;
  nvd)
    run_job "nvd" "ingest/nvd.js" ""
    ;;
  scores)
    run_job "score_refresh" "ingest/scoreRefresh.js" ""
    ;;
  daily)
    # Full daily sequence
    echo "[$TIMESTAMP] Starting daily ingest sequence" >> $LOG_DIR/cron.log
    run_job "kev"           "ingest/kev.js"           ""
    run_job "epss"          "ingest/epss.js"          ""
    run_job "nvd"           "ingest/nvd.js"           ""
    run_job "score_refresh" "ingest/scoreRefresh.js"  ""
    echo "[$TIMESTAMP] Daily ingest sequence complete" >> $LOG_DIR/cron.log
    ;;
  *)
    echo "Usage: $0 {kev|epss|nvd|scores|daily}"
    exit 1
    ;;
esac
