#!/usr/bin/env bash
# Sinatra verifier integration test.
#
# Boots examples/verifier_sinatra.rb on a random port, hits every
# endpoint with curl, asserts the response shape, and tears down the
# server. Uses the system Ruby + gem-installed Sinatra, not bundler,
# so it doesn't pollute the gemspec dev-deps.
#
# Run with:
#   bash scripts/sinatra_integration_test.sh
#
# Exits 0 on success, non-zero on any check failure.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
PORT="${CONFIUM_TEST_PORT:-9294}"
BASE="http://127.0.0.1:${PORT}"

cd "$ROOT"

if ! bundle exec ruby -e 'require "sinatra/base"; require "json"; require "net/http"' 2>/dev/null; then
  echo "FAIL: sinatra not installed in the bundler environment" >&2
  echo "  fix: bundle install" >&2
  exit 1
fi

# Boot the Sinatra app in the background via bundler so the confium
# gem is on the load path. We pass the port via env so the app picks
# it up (Sinatra respects PORT, but we set --port too).
PORT="$PORT" bundle exec ruby "$HERE/../examples/verifier_sinatra.rb" -p "$PORT" -s puma >/tmp/sinatra_test.log 2>&1 &
APP_PID=$!

cleanup() {
  if kill -0 "$APP_PID" 2>/dev/null; then
    kill -TERM "$APP_PID" 2>/dev/null || true
    wait "$APP_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

# Wait up to 5s for the server to come up.
for _ in $(seq 1 50); do
  if curl -sf "$BASE/health" >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done

if ! curl -sf "$BASE/health" >/dev/null 2>&1; then
  echo "FAIL: server did not come up at $BASE" >&2
  cat /tmp/sinatra_test.log >&2 || true
  exit 1
fi

PASS=0
FAIL=0

check() {
  local label="$1"
  local actual="$2"
  local expected="$3"
  if [[ "$actual" == "$expected" ]]; then
    PASS=$((PASS + 1))
    echo "  OK   $label"
  else
    FAIL=$((FAIL + 1))
    echo "  FAIL $label (expected=$expected actual=$actual)"
  fi
}

echo "== GET /health"
BODY=$(curl -sf "$BASE/health")
check "health ok=true" "$(echo "$BODY" | ruby -rjson -e 'puts JSON.parse(STDIN.read)["ok"]')" "true"
check "health version non-empty" "$(echo "$BODY" | ruby -rjson -e 'puts JSON.parse(STDIN.read)["version"].to_s.length > 0')" "true"

echo "== POST /verify/composite with missing fields"
RES=$(curl -s -w $'\n%{http_code}\n' \
  -H "Content-Type: application/json" \
  -X POST -d '{}' \
  "$BASE/verify/composite")
CODE=$(echo "$RES" | tail -1)
check "missing-field status 400" "$CODE" "400"

echo "== GET /unknown route"
RES=$(curl -s -w $'\n%{http_code}\n' "$BASE/nonexistent")
CODE=$(echo "$RES" | tail -1)
check "unknown-route status 404" "$CODE" "404"

echo "== Summary"
echo "  pass=$PASS fail=$FAIL"
[[ "$FAIL" -eq 0 ]] || exit 1
echo "OK: Sinatra verifier integration test passed"
