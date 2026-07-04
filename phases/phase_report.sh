#!/bin/bash
# =============================================================
#  phases/phase_report.sh — Report Generation
#  Runs report.py + ai_report_generator.py, generates dashboard
#  Usage: bash phases/phase_report.sh --output-dir <out>
# =============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# ── Args ──────────────────────────────────────────────────────
OUTPUT_DIR=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

if [[ -z "$OUTPUT_DIR" ]]; then
  echo "Usage: $0 --output-dir <dir>"
  exit 1
fi

# ── Initialize ────────────────────────────────────────────────
OUT="$OUTPUT_DIR"
mkdir -p "$OUT/logs" "$OUT/poc" "$OUT/tmp"
export OUT LOG

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

# ── Report generation ────────────────────────────────────────
if command -v python3 &>/dev/null && [[ -f "$SCRIPT_DIR/report.py" ]]; then
  set_phase "Generating Report" 0
  log "Generating HTML report..."
  debug_tool_start "python3/report" "python3 $SCRIPT_DIR/report.py --output-dir $OUT"
  _rep_start; _rep_start=$(date +%s)

  python3 "$SCRIPT_DIR/report.py" --output-dir "$OUT" \
    2>>"$OUT/logs/errors.log"
  _rep_exit=$?

  _rep_dur=$(( $(date +%s) - _rep_start ))
  debug_tool_end "python3/report" "$_rep_exit" "$OUT/report.html" "$_rep_dur"

  if [[ $_rep_exit -ne 0 ]]; then
    log "WARN: Report generation failed"
  fi
  if [[ -f "$OUT/report.html" ]]; then
    log "Report: $OUT/report.html"
  fi
  checkpoint_done report_generation
else
  log "report.py not found or python3 not available — skipping report"
fi

# ── AI Report Generator ───────────────────────────────────────
if [[ -f "$OUT/logs/ai_debug.log" ]] || [[ -f "$OUT/scan_log.jsonl" ]]; then
  if command -v python3 &>/dev/null && [[ -f "$SCRIPT_DIR/ai_report_generator.py" ]]; then
    log "Running AI report generator..."
    python3 "$SCRIPT_DIR/ai_report_generator.py" --output-dir "$OUT" \
      2>>"$OUT/logs/errors.log" || \
      log "WARN: AI report generation failed (optional)"
  fi
fi

# ── Summary ───────────────────────────────────────────────────
set_phase "Complete" 0
cleanup_logs_dir

FOUND; FOUND=$(state_get "found")
DONE_N; DONE_N=$(state_get "done")
ERRORS_N; ERRORS_N=$(state_get "errors")
TOTAL_URLS; TOTAL_URLS=$(count_lines "$OUT/all_urls.txt")
LIVE; LIVE=$(count_lines "$OUT/live.txt")
PARAMS; PARAMS=$(count_lines "$OUT/params.txt")
REFLECTED; REFLECTED=$(count_lines "$OUT/reflected_urls.txt")
FINAL; FINAL=$(count_lines "$OUT/final_targets.txt")

echo ""
echo "  ========================================"
echo "  Scan Summary — $DOMAIN"
echo "  ========================================"
echo ""
echo "  URLs Collected  : $TOTAL_URLS"
echo "  Live (httpx)    : $LIVE"
echo "  With Parameters : $PARAMS"
echo "  Reflected       : $REFLECTED"
echo "  Final Targets   : $FINAL"
echo "  Scanned         : $DONE_N"
echo "  XSS Found       : $FOUND"
echo "  Errors          : $ERRORS_N"
echo ""
[[ -f "$OUT/report.html" ]] && echo "  Report          : $OUT/report.html"
echo ""

echo "Phase report complete"
