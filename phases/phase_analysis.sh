#!/bin/bash
# =============================================================
#  phases/phase_analysis.sh — DOM XSS + Fragment Injection +
#  Cross-Page Tracking + Stored XSS Chain
#  Usage: bash phases/phase_analysis.sh --output-dir <out> [options]
# =============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# ── Args ──────────────────────────────────────────────────────
OUTPUT_DIR=""
THREADS=10
PROXY=""
POST_DATA=""
COOKIE=""
FRAGMENT_SCAN=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir)   OUTPUT_DIR="$2";  shift 2 ;;
    --threads)      THREADS="$2";     shift 2 ;;
    --proxy)        PROXY="$2";       shift 2 ;;
    --post-data)    POST_DATA="$2";   shift 2 ;;
    --cookie)       COOKIE="$2";      shift 2 ;;
    --fragment-scan) FRAGMENT_SCAN=1; shift ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

if [[ -z "$OUTPUT_DIR" ]]; then
  echo "Usage: $0 --output-dir <dir> [--threads N] [--proxy URL] [--post-data FILE] [--cookie VAL] [--fragment-scan]"
  exit 1
fi

# ── Initialize ────────────────────────────────────────────────
OUT="$OUTPUT_DIR"
mkdir -p "$OUT/logs" "$OUT/poc" "$OUT/tmp"
export OUT LOG THREADS PROXY STEALTH COOKIE POST_DATA FRAGMENT_SCAN

STATE="$OUT/.state"
mkdir -p "$STATE"
export STATE

LOG="$OUT/logs/reflexionx.log"
export LOG
ACTIVITY_FILE="$STATE/last_activity"
export ACTIVITY_FILE
PHASE_LOG="$STATE/phase_log"
export PHASE_LOG
DOM_SCAN=1
export DOM_SCAN

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

# ══ 4.6 · DOM XSS Analysis ════════════════════════════════
if [[ -f "$OUT/tmp/katana.txt" ]]; then
  grep -iE '\.js(\?|$)' "$OUT/tmp/katana.txt" > "$OUT/tmp/katana_js.txt" 2>/dev/null || true
else
  > "$OUT/tmp/katana_js.txt"
fi
JS_COUNT=$(count_lines "$OUT/tmp/katana_js.txt")
if [[ $JS_COUNT -gt 0 ]]; then
  set_phase "DOM XSS Analysis" "$JS_COUNT"
  log "Analyzing $JS_COUNT JavaScript files for DOM XSS..."
  _dom_cmd="python3 $SCRIPT_DIR/dom_analyzer.py --js-urls $OUT/tmp/katana_js.txt --output-dir $OUT"
  debug_tool_start "python3/dom_analyzer" "$_dom_cmd"
  _dom_start; _dom_start=$(date +%s)

  python3 "$SCRIPT_DIR/dom_analyzer.py" \
    --js-urls "$OUT/tmp/katana_js.txt" \
    --output-dir "$OUT" \
    --threads 5 \
    2>>"$OUT/logs/errors.log"
  _dom_exit=$?

  _dom_dur=$(( $(date +%s) - _dom_start ))
  debug_tool_end "python3/dom_analyzer" "$_dom_exit" "$OUT/dom_risks.txt" "$_dom_dur"

  if [[ $_dom_exit -ne 0 ]]; then
    log "WARN: DOM analysis failed"
  fi
  if [[ -f "$OUT/dom_risks.txt" ]]; then
    DOM_RISKS=$(grep -c '^URL:' "$OUT/dom_risks.txt" 2>/dev/null || echo 0)
    log "DOM XSS risks identified: $DOM_RISKS"
  fi
else
  log "No JS files found for DOM analysis"
fi

# ══ Fragment URL Generation for Fragment/DOM XSS ═════════════
if [[ $FRAGMENT_SCAN -eq 1 ]] && command -v python3 &>/dev/null; then
  frag_base_input=""
  if [[ -f "$OUT/all_urls.txt" && -s "$OUT/all_urls.txt" ]]; then
    frag_base_input="$OUT/all_urls.txt"
  elif [[ -f "$OUT/live.txt" && -s "$OUT/live.txt" ]]; then
    frag_base_input="$OUT/live.txt"
  fi
  if [[ -n "$frag_base_input" ]]; then
    frag_count; frag_count=$(count_lines "$frag_base_input")
    if [[ $frag_count -gt 0 ]]; then
      set_phase "Fragment URL Generation" "$frag_count"
      log "Generating fragment URLs for DOM XSS testing..."
      python3 "$SCRIPT_DIR/fragment_injector.py" \
        --base-urls "$frag_base_input" \
        --encode-fn unescape \
        --output-dir "$OUT" \
        --canary "HF5XSSCONFIRMED" \
        2>>"$OUT/logs/errors.log"
      if [[ -f "$OUT/fragment_urls.txt" ]]; then
        FRAG_COUNT=$(count_lines "$OUT/fragment_urls.txt")
        log "Fragment URLs generated: $FRAG_COUNT"
      fi
    fi
  fi
fi

# ══ Cross-Page Parameter Flow Tracking ═════════════════════
if [[ -f "$OUT/reflection_contexts.json" ]] && command -v python3 &>/dev/null; then
  set_phase "Cross-Page Flow Tracking" "reflection_contexts.json"
  log "Analyzing cross-page parameter flow..."
  python3 "$SCRIPT_DIR/cross_page_tracker.py" \
    --contexts "$OUT/reflection_contexts.json" \
    --output-dir "$OUT" \
    2>>"$OUT/logs/errors.log"
  if [[ -f "$OUT/cross_page_flows.json" ]]; then
    FLOW_COUNT=$(python3 -c "import json; d=json.load(open('$OUT/cross_page_flows.json')); print(len(d))" 2>/dev/null || echo 0)
    log "Cross-page flow issues found: $FLOW_COUNT"
  fi
fi

# ══ Auto Form Extraction (-A) ══════════════════════════════
local form_input="$OUT/live.txt"
[[ ! -s "$form_input" ]] && form_input="$OUT/filtered_urls.txt"
[[ ! -s "$form_input" ]] && form_input="$OUT/all_urls.txt"
[[ ! -s "$form_input" ]] && form_input="$OUT/tmp/katana.txt"
if [[ "${AUTO_FORMS:-0}" == "1" ]] && [[ -f "$form_input" && -s "$form_input" ]] && command -v python3 &>/dev/null && [[ -f "$SCRIPT_DIR/form_extractor.py" ]]; then
  set_phase "Auto Form Extraction" "$form_input"
  log "Running automated form extraction on endpoints ($form_input)..."
  python3 "$SCRIPT_DIR/form_extractor.py" \
    --urls "$form_input" \
    --output "$OUT/post_targets.txt" \
    ${COOKIE:+--cookie "$COOKIE"} \
    2>>"$OUT/logs/errors.log" || true
  if [[ -s "$OUT/post_targets.txt" ]]; then
    POST_DATA="$OUT/post_targets.txt"
    log "Extracted POST form targets to $POST_DATA"
  fi
fi

# ══ Stored XSS Chain Verification ══════════════════════════
if [[ -n "$POST_DATA" ]] && [[ -f "$POST_DATA" ]] && command -v python3 &>/dev/null; then
  set_phase "Stored XSS Chain Verification" "$POST_DATA"
  log "Running stored XSS chain verification (POST -> GET -> check)..."
  local verify_input="$OUT/reflected_urls.txt"
  [[ ! -s "$verify_input" ]] && verify_input="$OUT/live.txt"
  [[ ! -s "$verify_input" ]] && verify_input="$OUT/filtered_urls.txt"
  [[ ! -s "$verify_input" ]] && verify_input="$OUT/all_urls.txt"
  if [[ -f "$verify_input" && -s "$verify_input" ]]; then
    python3 "$SCRIPT_DIR/stored_xss_chain.py" \
      --post-data "$POST_DATA" \
      --verify-urls "$verify_input" \
      --verify-same-page \
      --output-dir "$OUT" \
      ${COOKIE:+--cookie "$COOKIE"} \
      2>>"$OUT/logs/errors.log"
    if [[ -f "$OUT/stored_xss_findings.json" ]]; then
      STORED_COUNT=$(python3 -c "import json; d=json.load(open('$OUT/stored_xss_findings.json')); print(len(d))" 2>/dev/null || echo 0)
      log "Stored XSS confirmations: $STORED_COUNT"
    fi
  fi
fi

echo "Phase analysis complete"
