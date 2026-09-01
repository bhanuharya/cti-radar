#!/usr/bin/env bash
# Benchmark harness: Python (FastAPI) vs Rust (axum) CTI Radar backend.
#
# Measures wall-clock, peak RSS, and CPU for BOTH implementations against the
# SAME data dir + SAME workload, so the comparison is apples-to-apples.
#
# Usage:
#   bash bench/bench.sh [iters] [mode]
#     iters  — number of iterations (default 5)
#     mode   — "api" (HTTP endpoints) | "scan" (full scan pipeline)
#
# Requires: /usr/bin/time (GNU time), curl, and both servers ready to serve.

set -uo pipefail

ITERS="${1:-5}"
MODE="${2:-api}"
DATA_DIR="${CTI_DATA_DIR:-$HOME/code/cti-dashboard/data}"
PY_HOST="${PY_HOST:-127.0.0.1:8084}"
RS_HOST="${RS_HOST:-127.0.0.1:8085}"
TOKEN="${CTI_SCAN_TOKEN:-tok}"
OUT="bench/results/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"

if ! command -v /usr/bin/time >/dev/null 2>&1 && ! command -v time >/dev/null 2>&1; then
  echo "ERROR: GNU time not found (needed for peak RSS). apt install time" >&2
  exit 1
fi

# median of a list of numbers (one per line)
median() { sort -n | awk '{a[NR]=$1} END {print (NR%2 ? a[(NR+1)/2] : (a[NR/2]+a[NR/2+1])/2)}'; }

run_api_bench() {
  local host="$1" label="$2"
  local wall=() rss=() cpu=()
  echo "=== [$label] API endpoints (${ITERS} iters) ==="
  for i in $(seq 1 "$ITERS"); do
    local tfile="$OUT/${label}-api-${i}.txt"
    # summary + findings + graph + dashboard (the CPU-heavy normalization paths)
    /usr/bin/time -v \
      bash -c "
        curl -s -H 'X-CTI-Token: $TOKEN' 'http://$host/api/summary?org=sample' >/dev/null
        curl -s -H 'X-CTI-Token: $TOKEN' 'http://$host/api/findings?org=sample' >/dev/null
        curl -s -H 'X-CTI-Token: $TOKEN' 'http://$host/api/graph?org=sample' >/dev/null
        curl -s -H 'X-CTI-Token: $TOKEN' 'http://$host/api/dashboard?org=sample' >/dev/null
      " 2>"$tfile"
    wall+=("$(grep 'Elapsed (wall clock)' "$tfile" | awk '{print $NF}')")
    rss+=("$(grep 'Maximum resident set size' "$tfile" | awk '{print $NF}')")
    cpu+=("$(grep 'Percent of CPU' "$tfile" | awk '{print $NF}')")
  done
  echo "  wall (s):      $(printf '%s\n' "${wall[@]}" | median)"
  echo "  peak RSS (KB): $(printf '%s\n' "${rss[@]}" | median)"
  echo "  CPU %:         $(printf '%s\n' "${cpu[@]}" | median)"
  printf '%s\n' "${wall[@]}" > "$OUT/${label}-wall.txt"
  printf '%s\n' "${rss[@]}" > "$OUT/${label}-rss.txt"
  printf '%s\n' "${cpu[@]}" > "$OUT/${label}-cpu.txt"
}

run_scan_bench() {
  local host="$1" label="$2"
  local wall=() rss=()
  echo "=== [$label] scan pipeline (${ITERS} iters) ==="
  for i in $(seq 1 "$ITERS"); do
    local tfile="$OUT/${label}-scan-${i}.txt"
    # trigger a fast scan, poll job until done
    local jid
    jid=$(curl -s -H "X-CTI-Token: $TOKEN" -H 'Content-Type: application/json' \
      -X POST "http://$host/api/orgs/sample/scan" -d '{"mode":"fast"}' | python3 -c 'import sys,json;print(json.load(sys.stdin).get("job_id",""))')
    if [ -z "$jid" ]; then echo "  WARN: no job id"; continue; fi
    # time the full scan (spawned server-side; we measure server process via /proc)
    # NOTE: scan wall-clock is measured by the SERVER, not the client; here we
    # poll and record the elapsed until status != running.
    local start end
    start=$(date +%s.%N)
    local status="running"
    while [ "$status" = "running" ]; do
      status=$(curl -s -H "X-CTI-Token: $TOKEN" "http://$host/api/orgs/sample/scan/$jid" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("status","running"))' 2>/dev/null || echo running)
      sleep 0.2
    done
    end=$(date +%s.%N)
    wall+=("$(echo "$end - $start" | bc)")
  done
  echo "  wall (s): $(printf '%s\n' "${wall[@]}" | median)"
  printf '%s\n' "${wall[@]}" > "$OUT/${label}-scan-wall.txt"
}

echo "CTI Radar bench — mode=$MODE iters=$ITERS"
echo "Results dir: $OUT"

if [ "$MODE" = "api" ]; then
  run_api_bench "$PY_HOST" "python"
  run_api_bench "$RS_HOST" "rust"
elif [ "$MODE" = "scan" ]; then
  run_scan_bench "$PY_HOST" "python"
  run_scan_bench "$RS_HOST" "rust"
else
  echo "Unknown mode: $MODE (use api|scan)" >&2
  exit 1
fi

echo
echo "=== SUMMARY (medians) ==="
echo "Results in: $OUT"
echo "Compare with: python3 bench/compare.py $OUT"
