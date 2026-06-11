#!/usr/bin/env bash
# Start the demo issuer (:8001) and relying party (:8002).
set -euo pipefail
cd "$(dirname "$0")/.."

if [ ! -f demo-state/public/log.jsonl ]; then
  echo "==> initializing federation state"
  uv run python scripts/init_federation.py --state demo-state
fi

echo "==> starting issuer on :8001 and RP on :8002 (Ctrl-C stops both)"
uv run uvicorn zkage_issuer.app:create_demo_app --factory --port 8001 &
ISSUER_PID=$!
uv run uvicorn zkage_rp.app:create_demo_app --factory --port 8002 &
RP_PID=$!
trap 'kill "$ISSUER_PID" "$RP_PID" 2>/dev/null || true' EXIT INT TERM

sleep 1
cat <<'EOF'

Demo walkthrough (in another terminal):

  uv run zkage-ua enroll --issuer http://127.0.0.1:8001 --claim-age 21 --state ./ua-state.json
  uv run zkage-ua verify --rp http://127.0.0.1:8002 --scope 18 --state ./ua-state.json
  uv run zkage-ua log-status --state ./ua-state.json

Demo RP page: http://127.0.0.1:8002

EOF
wait
