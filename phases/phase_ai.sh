#!/bin/bash
# =============================================================
#  phases/phase_ai.sh — AI Agentic Loop
#  Calls reflexion_agent.py at four checkpoints
#  Usage: bash phases/phase_ai.sh --output-dir <out> [options]
# =============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# ── Args ──────────────────────────────────────────────────────
OUTPUT_DIR=""
DOMAIN=""
AI_MODEL="nvidia/nemotron-3-super-120b-a12b:free"
MAX_ITERATIONS=25
AI_DEPTH="conservative"
AI_AGENT=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir)      OUTPUT_DIR="$2";      shift 2 ;;
    --domain)          DOMAIN="$2";          shift 2 ;;
    --model)           AI_MODEL="$2";        shift 2 ;;
    --max-iterations)  MAX_ITERATIONS="$2";  shift 2 ;;
    --ai-depth)        AI_DEPTH="$2";       shift 2 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

if [[ -z "$OUTPUT_DIR" ]]; then
  echo "Usage: $0 --output-dir <dir> [--domain <d>] [--model <m>] [--max-iterations N] [--ai-depth conservative|aggressive]"
  exit 1
fi

# ── Initialize ────────────────────────────────────────────────
OUT="$OUTPUT_DIR"
mkdir -p "$OUT/logs" "$OUT/poc" "$OUT/tmp"
export OUT LOG AI_AGENT AI_MODEL AI_DEPTH MAX_ITERATIONS

STATE="$OUT/.state"
mkdir -p "$STATE"
export STATE

LOG="$OUT/logs/reflexionx.log"
export LOG
ACTIVITY_FILE="$STATE/last_activity"
export ACTIVITY_FILE
PHASE_LOG="$STATE/phase_log"
export PHASE_LOG

if [[ -f "$STATE/domain" ]]; then
  DOMAIN=$(cat "$STATE/domain" 2>/dev/null || echo "")
fi
export DOMAIN

source "$SCRIPT_DIR/phases/common.sh"
_common_init_state

# ── ai_analyze uses AI_AGENT which we set to 1 ───────────────
# Re-export so common.sh's ai_analyze picks it up
AI_AGENT=1
export AI_AGENT

echo "Running AI agentic loop (depth=$AI_DEPTH, model=$AI_MODEL)..."

# ── Post-collection analysis ──────────────────────────────────
if checkpoint_check post_collection; then
  log "[RESUME] Skipping AI post_collection checkpoint"
else
  ai_analyze "post_collection"
  checkpoint_done post_collection
fi

# ── Pre-scan analysis ─────────────────────────────────────────
if checkpoint_check pre_scan; then
  log "[RESUME] Skipping AI pre_scan checkpoint"
else
  ai_analyze "pre_scan"
  checkpoint_done pre_scan
fi

# ── Deep exploit analysis ─────────────────────────────────────
if checkpoint_check ai_agentic_loop; then
  log "[RESUME] Skipping AI deep_exploit checkpoint"
else
  ai_analyze "deep_exploit"
  checkpoint_done ai_agentic_loop
fi

# ── Post-browser analysis ─────────────────────────────────────
if checkpoint_check post_browser; then
  log "[RESUME] Skipping AI post_browser checkpoint"
else
  ai_analyze "post_browser"
  checkpoint_done post_browser
fi

echo "Phase AI complete"
