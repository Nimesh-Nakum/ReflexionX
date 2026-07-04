#!/bin/bash
# =============================================================
#  phases/phase_browser.sh — Browser Validation + Blind XSS + PoC Triage
#  Runs xss_browser.py, oob_handler.py, poc_triage.py
#  Usage: bash phases/phase_browser.sh --output-dir <out> [options]
# =============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# ── Args ──────────────────────────────────────────────────────
OUTPUT_DIR=""
THREADS=10
PROXY=""
STEALTH=0
POST_DATA=""
BLIND_URL=""
COOKIE=""
VALIDATE=0
FRAGMENT_SCAN=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir)   OUTPUT_DIR="$2";   shift 2 ;;
    --threads)      THREADS="$2";      shift 2 ;;
    --proxy)        PROXY="$2";        shift 2 ;;
    --stealth)      STEALTH=1;      shift ;;
    --post-data)    POST_DATA="$2";    shift 2 ;;
    --blind-url)    BLIND_URL="$2";    shift 2 ;;
    --cookie)       COOKIE="$2";       shift 2 ;;
    --validate)     VALIDATE=1;      shift ;;
    --fragment-scan) FRAGMENT_SCAN=1; shift ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

if [[ -z "$OUTPUT_DIR" ]]; then
  echo "Usage: $0 --output-dir <dir> [--threads N] [--proxy URL] [--stealth] [--post-data FILE] [--blind-url URL] [--cookie VAL] [--validate] [--fragment-scan]"
  exit 1
fi

# ── Initialize ────────────────────────────────────────────────
OUT="$OUTPUT_DIR"
mkdir -p "$OUT/logs" "$OUT/poc" "$OUT/tmp"
export OUT LOG THREADS PROXY STEALTH COOKIE POST_DATA BLIND_URL VALIDATE FRAGMENT_SCAN

STATE="$OUT/.state"
mkdir -p "$STATE"
export STATE

LOG="$OUT/logs/reflexionx.log"
export LOG
ACTIVITY_FILE="$STATE/last_activity"
export ACTIVITY_FILE
PHASE_LOG="$STATE/phase_log"
export PHASE_LOG

source "$SCRIPT_DIR/phases/common.sh"
_common_init_state

if [[ -f "$STATE/domain" ]]; then
  DOMAIN=$(cat "$STATE/domain" 2>/dev/null || echo "")
fi
export DOMAIN

if [[ -f "$STATE/scope_domains" ]]; then
  mapfile -t SCOPE_DOMAINS < "$STATE/scope_domains" 2>/dev/null || true
fi
export SCOPE_DOMAINS

check_deps

# ══ Browser Validation (Playwright) ═════════════════════════
if checkpoint_check browser_validation; then
  log "[RESUME] Skipping Browser Validation (already complete)"
elif [[ $VALIDATE -eq 1 ]]; then
  browser_input="$OUT/high_priority_targets.txt"
  [[ ! -f "$browser_input" || ! -s "$browser_input" ]] && \
    browser_input="$OUT/final_targets.txt"
  combined_browser_input="$OUT/tmp/browser_targets_combined.txt"
  {
    [[ -f "$browser_input" ]] && cat "$browser_input"
    [[ -f "$OUT/poc/poc.txt" ]] && cat "$OUT/poc/poc.txt"
    find "$OUT/poc" -maxdepth 1 -name '*.txt' -exec grep -hEo 'https?://[^ ]+' {} + 2>/dev/null
  } | sort -u > "$combined_browser_input" 2>/dev/null || true
  [[ -s "$combined_browser_input" ]] && browser_input="$combined_browser_input"
  BROWSER_COUNT; BROWSER_COUNT=$(count_lines "$browser_input")
  if [[ $BROWSER_COUNT -gt 0 ]]; then
    set_phase "Browser Validation (Playwright)" "$BROWSER_COUNT"
    log "Validating top targets with headless browser..."
    browser_args=("$SCRIPT_DIR/xss_browser.py"
      --input "$browser_input"
      --output-dir "$OUT"
      --timeout 5000
      --max-concurrent 3
      --max-urls 200
      --retry)
    [[ -n "$PROXY" ]] && browser_args+=(--proxy "$PROXY")
    [[ $STEALTH -eq 1 ]] && browser_args+=(--stealth)
    [[ -n "$POST_DATA" ]] && browser_args+=(--post-data "$POST_DATA")
    [[ -n "$POST_DATA" && -f "$POST_DATA" ]] && browser_args+=(--verify-stored "$POST_DATA")
    [[ -n "${COOKIE:-}" ]] && browser_args+=(--cookie "$COOKIE")
    [[ $FRAGMENT_SCAN -eq 1 && -f "$OUT/fragment_urls.txt" ]] && \
      browser_args+=(--fragment-urls "$OUT/fragment_urls.txt")
    debug_tool_start "python3/xss_browser" "python3 ${browser_args[*]}"
    _bw_start; _bw_start=$(date +%s)

    python3 "${browser_args[@]}" \
      2>>"$OUT/logs/errors.log"
    _bw_exit=$?

    _bw_dur=$(( $(date +%s) - _bw_start ))
    debug_tool_end "python3/xss_browser" "$_bw_exit" "$OUT/confirmed_execution.txt" "$_bw_dur"

    if [[ $_bw_exit -ne 0 ]]; then
      log "WARN: Browser validation failed"
    fi
    if [[ -f "$OUT/confirmed_execution.txt" ]]; then
      CONFIRMED=$(count_lines "$OUT/confirmed_execution.txt")
      log "Browser-confirmed XSS: $CONFIRMED"
    fi
    checkpoint_done browser_validation
  fi
fi

# ══ POC Triage ══════════════════════════════════════════════
if checkpoint_check poc_triage; then
  log "[RESUME] Skipping POC Triage (already complete)"
elif command -v python3 &>/dev/null && [[ -f "$SCRIPT_DIR/poc_triage.py" ]]; then
  POC_COUNT; POC_COUNT=$(find "$OUT/poc" -maxdepth 1 -name '*.txt' ! -name 'poc.txt' 2>/dev/null | wc -l)
  if [[ $POC_COUNT -gt 0 ]]; then
    set_phase "POC Triage" "$POC_COUNT"
    log "Triaging $POC_COUNT POC files..."
    _poc_cmd="python3 $SCRIPT_DIR/poc_triage.py --output-dir $OUT --poc-dir $OUT/poc"
    debug_tool_start "python3/poc_triage" "$_poc_cmd"
    _poc_start; _poc_start=$(date +%s)

    python3 "$SCRIPT_DIR/poc_triage.py" \
      --output-dir "$OUT" \
      --poc-dir "$OUT/poc" \
      2>>"$OUT/logs/errors.log"
    _poc_exit=$?

    _poc_dur=$(( $(date +%s) - _poc_start ))
    debug_tool_end "python3/poc_triage" "$_poc_exit" "$OUT/triage_report.txt" "$_poc_dur"

    if [[ $_poc_exit -ne 0 ]]; then
      log "WARN: POC triage failed"
    fi
    checkpoint_done poc_triage
  fi
fi

# ══ Blind XSS Injection ════════════════════════════════════
if checkpoint_check blind_xss_injection; then
  log "[RESUME] Skipping Blind XSS Injection (already complete)"
elif [[ -n "$BLIND_URL" ]] && command -v python3 &>/dev/null && \
     [[ -f "$SCRIPT_DIR/oob_handler.py" ]]; then
  oob_input="$OUT/high_priority_targets.txt"
  [[ ! -f "$oob_input" || ! -s "$oob_input" ]] && oob_input="$OUT/final_targets.txt"
  OOB_COUNT; OOB_COUNT=$(count_lines "$oob_input")
  if [[ $OOB_COUNT -gt 0 ]]; then
    set_phase "Blind XSS Injection" "$OOB_COUNT"
    log "Injecting OOB callback payloads -> $BLIND_URL"
    _oob_cmd="python3 $SCRIPT_DIR/oob_handler.py --input $oob_input --output-dir $OUT --oob-url $BLIND_URL"
    debug_tool_start "python3/oob_handler" "$_oob_cmd"
    _oob_start; _oob_start=$(date +%s)

    python3 "$SCRIPT_DIR/oob_handler.py" \
      --input "$oob_input" \
      --output-dir "$OUT" \
      --oob-url "$BLIND_URL" \
      --threads "$THREADS" \
      ${PROXY:+--proxy "$PROXY"} \
      2>>"$OUT/logs/errors.log"
    _oob_exit=$?

    _oob_dur=$(( $(date +%s) - _oob_start ))
    debug_tool_end "python3/oob_handler" "$_oob_exit" "$OUT/blind_xss.txt" "$_oob_dur"

    if [[ $_oob_exit -ne 0 ]]; then
      log "WARN: OOB injection failed"
    fi
    checkpoint_done blind_xss_injection
  fi
fi

echo "Phase browser complete"
