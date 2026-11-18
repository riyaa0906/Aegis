#!/usr/bin/env bash
# Runs the full Aegis security evaluation and writes evaluations/results/.
# Brings up the stack, measures baseline vs protected, then tears the stack down.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
PY="uv run --directory apps/agent python"
EVAL="$ROOT/evaluations/run_eval.py"

DB=postgres://aegis:aegis@127.0.0.1:5433/aegis
COMMON_ENV=(
  AEGIS_POLICY_FILE=policies/development.yaml
  AEGIS_MCP_URL=http://127.0.0.1:3301/mcp
  AEGIS_HTTP_PORT=3300
  AEGIS_DATABASE_URL="$DB"
  AEGIS_REDIS_URL=redis://127.0.0.1:6380
  AEGIS_CLASSIFIER_URL=http://127.0.0.1:3100/classify
)

pids=()
cleanup() { kill "${pids[@]}" 2>/dev/null || true; }
trap cleanup EXIT

start_gateway() { env "${COMMON_ENV[@]}" "$@" node apps/gateway/dist/index.js --http 2>/dev/null & GW=$!; pids+=("$GW"); }
stop_gateway() { kill "$GW" 2>/dev/null || true; wait "$GW" 2>/dev/null || true; }
wait_gateway() { curl -s --retry-connrefused --retry 30 --retry-delay 1 -o /dev/null "http://127.0.0.1:3300/approvals"; }

echo "== bringing up infrastructure =="
docker compose up -d postgres redis >/dev/null
docker exec aegis-postgres-1 psql -U aegis -c "truncate table approvals" >/dev/null 2>&1 || true

uv run --directory apps/classifier uvicorn aegis_classifier.service:app --port 3100 >/tmp/aegis-eval-classifier.log 2>&1 & pids+=($!)
MCP_HTTP_PORT=3301 node apps/mcp-server/dist/index.js --http 2>/dev/null & pids+=($!)
echo "== waiting for the classifier model to load =="
curl -s --retry-connrefused --retry 90 --retry-delay 2 --max-time 300 http://127.0.0.1:3100/health >/dev/null
curl -s --max-time 900 -X POST http://127.0.0.1:3100/classify -H 'content-type: application/json' -d '{"text":"warmup"}' >/dev/null

echo "== phase 1: attack success rate, screening, approvals (normal gateway) =="
start_gateway; wait_gateway
$PY "$EVAL" asr
$PY "$EVAL" screening
$PY "$EVAL" approval
REQ=$($PY "$EVAL" durability-before)
echo "   created+approved $REQ; restarting gateway to prove durable recovery"
stop_gateway

start_gateway; wait_gateway
$PY "$EVAL" durability-after
stop_gateway

echo "== phase 2: approval timeout (gateway with a 1s timeout) =="
start_gateway AEGIS_APPROVAL_TIMEOUT_MS=1000 AEGIS_APPROVAL_SWEEP_MS=500; wait_gateway
$PY "$EVAL" timeout
stop_gateway

echo "== summary =="
$PY "$ROOT/evaluations/summarize.py"
