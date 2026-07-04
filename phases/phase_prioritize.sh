#!/bin/bash
# =============================================================
#  phases/phase_prioritize.sh — Prioritise
#  Scores and sorts targets from reflection_contexts.json
#  Outputs final_targets.txt
#  Usage: bash phases/phase_prioritize.sh --output-dir <out>
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

# ── Determine scoring input ───────────────────────────────────
scoring_input="$OUT/reflected_urls.txt"
[[ -f "$OUT/reflected_validated.txt" && -s "$OUT/reflected_validated.txt" ]] && \
  scoring_input="$OUT/reflected_validated.txt"

if [[ ! -s "$scoring_input" ]]; then
  if [[ -f "$OUT/params.txt" && -s "$OUT/params.txt" ]]; then
    scoring_input="$OUT/params.txt"
    log "No reflected URLs — falling back to parameterized URLs"
  elif [[ -f "$OUT/live.txt" && -s "$OUT/live.txt" ]]; then
    scoring_input="$OUT/live.txt"
    log "No parameterized URLs — falling back to all live URLs"
  fi
fi

if [[ -f "$OUT/live.txt" ]] && [[ $(count_lines "$OUT/live.txt") -lt 50 ]] && [[ $(count_lines "$OUT/live.txt") -gt 0 ]]; then
  scoring_input="$OUT/live.txt"
  log "Small target surface (< 50 live URLs), scanning all live URLs"
fi

SCORING_COUNT=$(count_lines "$scoring_input")
set_phase "Scoring Targets" "$SCORING_COUNT"
log "Scoring by parameter sensitivity + context... (source: $(basename "$scoring_input"))"

export _OUTDIR="$OUT"
while IFS= read -r url; do
  score_url "$url"
  state_inc "phase_done"
done < "$scoring_input" \
  | sort -rn \
  | cut -d' ' -f2- \
  > "$OUT/final_targets.txt"

enforce_scope "$OUT/final_targets.txt" "Final scan targets"
FINAL=$(count_lines "$OUT/final_targets.txt")
log "Final targets after scoring: $FINAL"

if [[ $FINAL -eq 0 ]]; then
  log "No targets or DOM XSS risks to scan. Done."
  echo "Phase prioritize complete: 0 targets"
  exit 0
fi

echo "Phase prioritize complete: $FINAL targets in $OUT/final_targets.txt"
