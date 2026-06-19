#!/bin/bash
# CVE Intel — Management Script
# Usage:
#   ./cveintel.sh start    — start both servers
#   ./cveintel.sh stop     — stop both servers
#   ./cveintel.sh restart  — restart both servers
#   ./cveintel.sh status   — check what's running
#   ./cveintel.sh logs     — show recent logs
#   ./cveintel.sh update   — git pull + restart

ROOT="/home/cve/cveintel"
API="$ROOT/api"
UI="$ROOT/ui"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No colour

function print_header() {
  echo -e "\n${BLUE}CVE///INTEL Management${NC}"
  echo -e "${BLUE}───────────────────────${NC}"
}

function check_screen() {
  screen -ls | grep -q "$1"
}

function start_api() {
  if check_screen "cveintel-api"; then
    echo -e "${YELLOW}API already running${NC}"
  else
    screen -dmS cveintel-api bash -c "cd $API && npm run dev 2>&1 | tee /tmp/cveintel-api.log"
    sleep 2
    if check_screen "cveintel-api"; then
      echo -e "${GREEN}✓ API started on port 4000${NC}"
    else
      echo -e "${RED}✗ API failed to start — check /tmp/cveintel-api.log${NC}"
    fi
  fi
}

function start_ui() {
  if check_screen "cveintel-ui"; then
    echo -e "${YELLOW}UI already running${NC}"
  else
    screen -dmS cveintel-ui bash -c "cd $UI && npm run dev -- --host 2>&1 | tee /tmp/cveintel-ui.log"
    sleep 3
    if check_screen "cveintel-ui"; then
      echo -e "${GREEN}✓ UI started on port 5174${NC}"
    else
      echo -e "${RED}✗ UI failed to start — check /tmp/cveintel-ui.log${NC}"
    fi
  fi
}

function stop_api() {
  if check_screen "cveintel-api"; then
    screen -S cveintel-api -X quit
    echo -e "${GREEN}✓ API stopped${NC}"
  else
    echo -e "${YELLOW}API not running${NC}"
  fi
}

function stop_ui() {
  if check_screen "cveintel-ui"; then
    screen -S cveintel-ui -X quit
    echo -e "${GREEN}✓ UI stopped${NC}"
  else
    echo -e "${YELLOW}UI not running${NC}"
  fi
}

function show_status() {
  echo -e "\n${BLUE}Server status:${NC}"

  if check_screen "cveintel-api"; then
    echo -e "  API     ${GREEN}● running${NC}   port 4000"
  else
    echo -e "  API     ${RED}○ stopped${NC}"
  fi

  if check_screen "cveintel-ui"; then
    echo -e "  UI      ${GREEN}● running${NC}   port 5174"
  else
    echo -e "  UI      ${RED}○ stopped${NC}"
  fi

  echo -e "\n${BLUE}Database status:${NC}"
  if systemctl is-active --quiet postgresql@16-main; then
    echo -e "  Postgres ${GREEN}● running${NC}"
    COUNT=$(psql -U cveintel_user -d cveintel -h localhost -tAc "SELECT COUNT(*) FROM cve_core;" 2>/dev/null)
    if [ -n "$COUNT" ]; then
      echo -e "  CVE records: ${GREEN}$COUNT${NC}"
    fi
  else
    echo -e "  Postgres ${RED}○ stopped${NC}"
  fi

  echo -e "\n${BLUE}Quick test:${NC}"
  HEALTH=$(curl -s http://127.0.0.1:4000/health 2>/dev/null)
  if echo "$HEALTH" | grep -q 'ok'; then
    echo -e "  API health  ${GREEN}✓ ok${NC}"
  else
    echo -e "  API health  ${RED}✗ not responding${NC}"
  fi

  echo -e "\n${BLUE}Access:${NC}"
  echo -e "  http://192.168.0.86:5174"
  echo -e "  Login: admin@cveintel.dev / dev-password\n"
}

function show_logs() {
  echo -e "\n${BLUE}API logs (last 30 lines):${NC}"
  tail -30 /tmp/cveintel-api.log 2>/dev/null || echo "No API log found"
  echo -e "\n${BLUE}UI logs (last 10 lines):${NC}"
  tail -10 /tmp/cveintel-ui.log 2>/dev/null || echo "No UI log found"
}

function reset_ingest_locks() {
  echo -e "\n${BLUE}Resetting stuck ingest locks...${NC}"
  psql -U cveintel_user -d cveintel -h localhost -c \
    "UPDATE ingest_log SET status='failed', error_message='Reset by management script', completed_at=NOW() WHERE status='running';
     UPDATE ingest_status SET is_running=FALSE, started_at=NULL;" 2>/dev/null
  echo -e "${GREEN}✓ Locks cleared${NC}"
}

# Main
print_header

case "$1" in
  start)
    echo -e "Starting CVE Intel..."
    start_api
    start_ui
    sleep 1
    show_status
    ;;
  stop)
    echo -e "Stopping CVE Intel..."
    stop_api
    stop_ui
    ;;
  restart)
    echo -e "Restarting CVE Intel..."
    stop_api
    stop_ui
    sleep 1
    start_api
    start_ui
    sleep 1
    show_status
    ;;
  status)
    show_status
    ;;
  logs)
    show_logs
    ;;
  update)
    echo -e "Pulling latest code..."
    cd $ROOT && git pull
    echo -e "Restarting servers..."
    stop_api
    stop_ui
    sleep 1
    start_api
    start_ui
    sleep 1
    show_status
    ;;
  reset-locks)
    reset_ingest_locks
    ;;
  *)
    echo -e "Usage: ./cveintel.sh {start|stop|restart|status|logs|update|reset-locks}"
    echo -e ""
    echo -e "  start        Start API and UI servers"
    echo -e "  stop         Stop both servers"
    echo -e "  restart      Restart both servers"
    echo -e "  status       Show server and database status"
    echo -e "  logs         Show recent server logs"
    echo -e "  update       Git pull and restart"
    echo -e "  reset-locks  Clear stuck ingest locks"
    echo ""
    ;;
esac
