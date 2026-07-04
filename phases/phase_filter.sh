#!/bin/bash
# =============================================================
#  phases/phase_filter.sh — Pre-Filter & Live Filter
#  Runs context_manager.py cleanup + httpx live check
#  Usage: bash phases/phase_filter.sh --output-dir <out> [options]
# =============================================================
set -euo pipefail

# ── Args ──────────────────────────────────────────────────────
OUTPUT_DIR=""
THREADS=10
PROXY=""
STEALTH=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
    --threads)    THREADS="$2";    shift 2 ;;
    --proxy)      PROXY="$2";      shift 2 ;;
    --stealth)    STEALTH=1; shift ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

if [[ -z "$OUTPUT_DIR" ]]; then
  echo "Usage: $0 --output-dir <dir> [--threads N] [--proxy URL] [--stealth]"
  exit 1
fi

# ── Initialize ────────────────────────────────────────────────
OUT="$OUTPUT_DIR"
mkdir -p "$OUT/logs" "$OUT/poc" "$OUT/tmp"
STATE="$OUT/.state"
mkdir -p "$STATE"
LOG="$OUT/logs/reflexionx.log"
ACTIVITY_FILE="$STATE/last_activity"
PHASE_LOG="$STATE/phase_log"
export OUT STATE LOG ACTIVITY_FILE PHASE_LOG DOMAIN THREADS PROXY STEALTH COOKIE

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

source "$SCRIPT_DIR/phases/common.sh"
_common_init_state

# ── Restore DOMAIN ────────────────────────────────────────────
if [[ -f "$STATE/domain" ]]; then
  DOMAIN=$(cat "$STATE/domain" 2>/dev/null || echo "")
fi
if [[ -z "${DOMAIN:-}" ]] && [[ -f "$OUT/all_urls.txt" ]]; then
  DOMAIN=$(head -n 1 "$OUT/all_urls.txt" 2>/dev/null | awk -F/ '{print $3}' || echo "")
fi
export DOMAIN

if [[ -f "$STATE/scope_domains" ]]; then
  mapfile -t SCOPE_DOMAINS < "$STATE/scope_domains" 2>/dev/null || true
fi

check_deps

main() {
# ── Resume check ──────────────────────────────────────────────
if checkpoint_check live_filter; then
  log "[RESUME] Skipping Live Filter (already complete)"
  echo "Phase filter skipped (already complete)"
  return 0
fi

# ── 2a · Smart URL Pre-filtering (context_manager.py) ────────
TOTAL_URLS=$(count_lines "$OUT/all_urls.txt")
HTTPX_INPUT="$OUT/all_urls.txt"

if command -v python3 &>/dev/null && [[ -f "$SCRIPT_DIR/context_manager.py" ]]; then
  set_phase "Pre-filtering URLs" "$TOTAL_URLS"
  log "Pre-filtering URLs (removing static files, deduplicating endpoints)..."

  local _ctx_cmd="python3 $SCRIPT_DIR/context_manager.py --mode filter_urls --input $OUT/all_urls.txt --output $OUT/filtered_urls.txt"
  debug_tool_start "python3/context_manager" "$_ctx_cmd"
  local _ctx_start; _ctx_start=$(date +%s)

  local filter_result
  filter_result=$(python3 "$SCRIPT_DIR/context_manager.py" \
    --mode filter_urls \
    --input "$OUT/all_urls.txt" \
    --output "$OUT/filtered_urls.txt" \
    2>>"$OUT/logs/errors.log")
  local _ctx_exit=$?

  local _ctx_dur=$(( $(date +%s) - _ctx_start ))
  debug_tool_end "python3/context_manager" "$_ctx_exit" "$OUT/filtered_urls.txt" "$_ctx_dur"

  if [[ -f "$OUT/filtered_urls.txt" ]] && [[ -s "$OUT/filtered_urls.txt" ]]; then
    HTTPX_INPUT="$OUT/filtered_urls.txt"
    local filtered_count; filtered_count=$(count_lines "$OUT/filtered_urls.txt")
    log "Pre-filtered: $TOTAL_URLS -> $filtered_count unique endpoints ($filter_result)"
  else
    log "Pre-filter produced no output, using all URLs"
  fi
else
  log "context_manager.py not available, using all URLs for httpx"
fi

HTTPX_COUNT=$(count_lines "$HTTPX_INPUT")

# ── 2b · httpx live probing ───────────────────────────────────
set_phase "Live Filtering (httpx)" "$HTTPX_COUNT"
log "Filtering live URLs (httpx) — $HTTPX_COUNT URLs..."

local httpx_concurrency=25
local httpx_rate_limit=100
local httpx_timeout=10
local httpx_max_time=900

if [[ $STEALTH -eq 1 ]]; then
  httpx_concurrency=3
  httpx_rate_limit=10
  httpx_timeout=15
  httpx_max_time=1200
fi

touch "$OUT/live.txt"
local _hx_cmd="httpx -silent -mc 200,201,204,301,302,307,308,401,403 -l $HTTPX_INPUT -o $OUT/live.txt"
debug_tool_start "httpx" "$_hx_cmd"
local _hx_start; _hx_start=$(date +%s)

local httpx_arr=(
  httpx -silent
  -mc 200,201,204,301,302,307,308,401,403
  -l "$HTTPX_INPUT"
  -o "$OUT/live.txt"
  -c "$httpx_concurrency"
  -rl "$httpx_rate_limit"
  -timeout "$httpx_timeout"
  -retries 2
  -random-agent
  -follow-redirect
  -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
  -H "Accept-Language: en-US,en;q=0.9"
  -H "Accept-Encoding: gzip, deflate, br"
  -H "Connection: keep-alive"
  -H "Cache-Control: max-age=0"
)
[[ -n "${COOKIE:-}" ]] && httpx_arr+=(-H "Cookie: $COOKIE")

local _httpx_max_time=${httpx_max_time:-600}
("${httpx_arr[@]}" > /dev/null 2>>"$OUT/logs/errors.log") &
HTTPX_PID=$!
( sleep "$_httpx_max_time" && kill -TERM "$HTTPX_PID" 2>/dev/null ) &
HTTPX_WATCHDOG_PID=$!
while kill -0 $HTTPX_PID 2>/dev/null; do
  c=$(count_lines "$OUT/live.txt")
  state_set "phase_done" "$c"
  state_set "phase" "Live Filter (httpx): ${c} alive / ${HTTPX_COUNT} checked"
  sleep 2
done
kill "$HTTPX_WATCHDOG_PID" 2>/dev/null || true
wait $HTTPX_PID 2>/dev/null; local _hx_exit=$?

local _hx_dur=$(( $(date +%s) - _hx_start ))
debug_tool_end "httpx" "$_hx_exit" "$OUT/live.txt" "$_hx_dur"

LIVE=$(count_lines "$OUT/live.txt")
log "Live URLs from httpx: $LIVE"

# ── 2c · Fallback: bypass httpx if WAF blocked everything ────
if [[ $LIVE -eq 0 && $HTTPX_COUNT -gt 0 ]]; then
  log "WARN: httpx returned 0 live URLs — WAF likely blocking probes"
  log "Fallback: extracting parameterized URLs directly from collected data"
  state_set "phase" "Fallback: extracting parameterized URLs..."
  grep '[?]' "$HTTPX_INPUT" | grep '=' | sort -u > "$OUT/live.txt" 2>/dev/null || true
  LIVE=$(count_lines "$OUT/live.txt")
  if [[ $LIVE -eq 0 ]]; then
    cp "$HTTPX_INPUT" "$OUT/live.txt"
    LIVE=$(count_lines "$OUT/live.txt")
    log "Broad fallback: using all $LIVE filtered URLs"
  else
    log "Fallback: extracted $LIVE parameterized URLs (skipping liveness check)"
  fi
  enforce_scope "$OUT/live.txt" "Fallback live URLs"
  LIVE=$(count_lines "$OUT/live.txt")
fi

checkpoint_done live_filter

echo "Phase filter complete: $LIVE live URLs in $OUT/live.txt"
}

main "$@"
