#!/usr/bin/env bash
# perf_smoke_api.sh — lightweight API latency smoke test
# Usage: ./scripts/perf_smoke_api.sh [BASE_URL] [API_KEY]
#
# Requires: curl
# Pass/Fail threshold: p95 < 200ms
#
set -euo pipefail

BASE_URL="${1:-http://127.0.0.1:8000}"
API_KEY="${2:-${TECHNIEUM_API_KEY:-}}"

N=20
THRESHOLD=200

pass=0
fail=0

measure_p95() {
    local url="$1" label="$2" key="${3:-}"
    local -a times
    local auth_header=""
    [ -n "$key" ] && auth_header="-H X-API-Key: $key"
    for i in $(seq 1 "$N"); do
        ms=$(curl -s -o /dev/null -w "%{time_total}" ${key:+-H "X-API-Key: $key"} "$url" \
            | awk '{printf "%d", $1*1000}')
        times+=("$ms")
    done
    IFS=$'\n' local -a sorted
    sorted=($(printf '%s\n' "${times[@]}" | sort -n))
    unset IFS
    local idx=$(( (N * 95 / 100) - 1 ))
    [ "$idx" -lt 0 ] && idx=0
    local p95="${sorted[$idx]}"
    printf "  %-30s  p95=%dms\n" "$label" "$p95"
    if [ "$p95" -le "$THRESHOLD" ]; then pass=$((pass+1)); else fail=$((fail+1)); fi
}

echo "=== Technieum API latency smoke test ==="
echo "  base=$BASE_URL  n=$N  threshold=${THRESHOLD}ms"
echo ""

measure_p95 "$BASE_URL/health"              "/health            (no auth)"
if [ -n "$API_KEY" ]; then
    measure_p95 "$BASE_URL/api/v1/scans/"   "/api/v1/scans      " "$API_KEY"
    measure_p95 "$BASE_URL/api/v1/assets/"  "/api/v1/assets     " "$API_KEY"
    measure_p95 "$BASE_URL/api/v1/findings/" "/api/v1/findings  " "$API_KEY"
    measure_p95 "$BASE_URL/api/v1/metrics/" "/api/v1/metrics    " "$API_KEY"
else
    echo "  (authenticated endpoints skipped — set TECHNIEUM_API_KEY to include)"
fi

echo ""
echo "Results: $pass passed, $fail failed (threshold=${THRESHOLD}ms)"
if [ "$fail" -gt 0 ]; then
    echo "FAIL" >&2; exit 1
fi
echo "PASS"
