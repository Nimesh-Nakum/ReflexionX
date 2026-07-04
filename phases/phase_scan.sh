#!/bin/bash
# =============================================================
#  phases/phase_scan.sh — XSS Scan (dalfox) + Retry + XSStrike +
#  Nuclei + Param Mining
#  Usage: bash phases/phase_scan.sh --output-dir <out> [options]
# =============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# ── Args ──────────────────────────────────────────────────────
OUTPUT_DIR=""
THREADS=10
PROXY=""
NUCLEI=0
PARAM_MINE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir)  OUTPUT_DIR="$2";  shift 2 ;;
    --threads)     THREADS="$2";     shift 2 ;;
    --proxy)       PROXY="$2";       shift 2 ;;
    --nuclei)      NUCLEI=1;      shift ;;
    --param-mine)  PARAM_MINE=1;  shift ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

if [[ -z "$OUTPUT_DIR" ]]; then
  echo "Usage: $0 --output-dir <dir> [--threads N] [--proxy URL] [--nuclei] [--param-mine]"
  exit 1
fi

# ── Initialize ────────────────────────────────────────────────
OUT="$OUTPUT_DIR"
mkdir -p "$OUT/logs" "$OUT/poc" "$OUT/tmp"
export OUT LOG THREADS PROXY STEALTH COOKIE NUCLEI_SCAN PARAM_MINE

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

NUCLEI_SCAN=$NUCLEI
export NUCLEI_SCAN

check_deps

FINAL; FINAL=$(count_lines "$OUT/final_targets.txt")
log "Final targets: $FINAL"

if [[ $FINAL -eq 0 ]]; then
  log "No targets to scan."
  echo "Phase scan complete: 0 targets scanned"
  exit 0
fi

# ══ XSS Scan (dalfox) ══════════════════════════════════════
if checkpoint_check xss_scan_dalfox; then
  log "[RESUME] Skipping XSS Scan (already complete)"
else
  set_phase "XSS Scanning (dalfox)" "$FINAL"
  state_set "done" 0
  log "Parallel dalfox scan — $THREADS threads..."

  dalfox_input="$OUT/final_targets.txt"
  [[ -f "$OUT/ai_priority_targets.txt" ]] && dalfox_input="$OUT/ai_priority_targets.txt"

  rm -f "$STATE/skip_headless"
  if [[ $FINAL -gt 10 ]]; then
    touch "$STATE/skip_headless"
    log "Target count > 10, skipping dalfox headless DOM mining for stability"
  else
    log "Small target set ($FINAL), enabling dalfox headless DOM mining"
  fi

  dispatch_scan "$dalfox_input"
  checkpoint_done xss_scan_dalfox
fi

# ══ Retry Failed URLs ══════════════════════════════════════
if [[ -f "$STATE/failed_scans.txt" && -s "$STATE/failed_scans.txt" ]]; then
  mapfile -t RETRY_URLS < <(sort -u "$STATE/failed_scans.txt")
  if [[ ${#RETRY_URLS[@]} -gt 0 ]]; then
    set_phase "Retrying Failed URLs" "${#RETRY_URLS[@]}"
    log "Retrying ${#RETRY_URLS[@]} failed URLs..."
    retry_file="$OUT/tmp/retry_targets.txt"
    printf '%s\n' "${RETRY_URLS[@]}" > "$retry_file"
    rm -f "$STATE/failed_scans.txt"
    dispatch_scan "$retry_file"
  fi
else
  log "No failed scans to retry."
fi

# ══ AI Agentic Loop ════════════════════════════════════════
if checkpoint_check ai_agentic_loop; then
  log "[RESUME] Skipping AI Agentic Loop (already complete)"
else
  ai_analyze "deep_exploit"
  checkpoint_done ai_agentic_loop
fi

# ══ XSStrike Validation ════════════════════════════════════
if command -v xsstrike &>/dev/null; then
  log "Preparing XSStrike fallback targets..."
  if [[ -s "$OUT/poc/poc.txt" ]]; then
    grep -vFf "$OUT/poc/poc.txt" "$OUT/final_targets.txt" | grep "[?]" | head -n 30 > "$OUT/xsstrike_targets.txt" 2>/dev/null || true
  else
    grep "[?]" "$OUT/final_targets.txt" | head -n 30 > "$OUT/xsstrike_targets.txt" 2>/dev/null || true
  fi
  XSS_COUNT=$(count_lines "$OUT/xsstrike_targets.txt")
  if [[ $XSS_COUNT -gt 0 ]]; then
    set_phase "XSStrike Validation" "$XSS_COUNT"
    state_set "done" 0
    log "Running XSStrike on top $XSS_COUNT unresolved targets..."
    dispatch_xsstrike "$OUT/xsstrike_targets.txt"
  else
    log "No suitable targets for XSStrike fallback."
  fi
else
  log "XSStrike not found in PATH. Skipping secondary validation."
fi

# ══ Nuclei XSS Template Scanning ══════════════════════════
if [[ $NUCLEI_SCAN -eq 1 ]] && command -v python3 &>/dev/null && \
   [[ -f "$SCRIPT_DIR/nuclei_scanner.py" ]]; then
  nuclei_input="$OUT/live.txt"
  NUCLEI_COUNT; NUCLEI_COUNT=$(count_lines "$nuclei_input")
  if [[ $NUCLEI_COUNT -gt 0 ]]; then
    set_phase "Nuclei XSS Scanning" "$NUCLEI_COUNT"
    log "Running nuclei XSS templates on $NUCLEI_COUNT live URLs..."
    nuclei_args=("$SCRIPT_DIR/nuclei_scanner.py"
      --urls "$nuclei_input"
      --output-dir "$OUT"
      --threads "$THREADS")
    [[ -n "$PROXY" ]] && nuclei_args+=(--proxy "$PROXY")
    [[ -n "${COOKIE:-}" ]] && nuclei_args+=(--cookie "$COOKIE")
    python3 "${nuclei_args[@]}" 2>>"$OUT/logs/errors.log" || \
      log "WARN: Nuclei scanning failed (optional)"
  fi
fi

# ══ Hidden Parameter Mining ════════════════════════════════
if [[ $PARAM_MINE -eq 1 ]] && command -v python3 &>/dev/null && \
   [[ -f "$SCRIPT_DIR/param_miner.py" ]]; then
  mine_input="$OUT/live.txt"
  MINE_COUNT; MINE_COUNT=$(count_lines "$mine_input")
  if [[ $MINE_COUNT -gt 0 ]]; then
    head -n 100 "$mine_input" > "$OUT/tmp/param_mine_targets.txt"
    mine_actual; mine_actual=$(count_lines "$OUT/tmp/param_mine_targets.txt")
    set_phase "Parameter Mining" "$mine_actual"
    log "Mining $mine_actual URLs for hidden parameters..."
    python3 "$SCRIPT_DIR/param_miner.py" \
      --urls "$OUT/tmp/param_mine_targets.txt" \
      --output-dir "$OUT" \
      --threads "$THREADS" \
      ${PROXY:+--proxy "$PROXY"} \
      ${COOKIE:+--cookie "$COOKIE"} \
      2>>"$OUT/logs/errors.log" || \
      log "WARN: Parameter mining failed (optional)"
    if [[ -f "$OUT/mined_params.txt" && -s "$OUT/mined_params.txt" ]]; then
      mined_count; mined_count=$(count_lines "$OUT/mined_params.txt")
      log "Mined $mined_count new reflected parameters — rescanning with dalfox"
      if [[ $mined_count -gt 0 ]]; then
        set_phase "Scanning Mined Params (dalfox)" "$mined_count"
        dispatch_scan "$OUT/mined_params.txt"
      fi
    fi
  fi
fi

echo "Phase scan complete"
