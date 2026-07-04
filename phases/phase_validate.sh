#!/bin/bash
# =============================================================
#  phases/phase_validate.sh — Reflection Check + Reflection Validation
#  curl-based reflection check (kxss replacement) + xss_validator.py
#  Usage: bash phases/phase_validate.sh --output-dir <out> [options]
# =============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# ── Args ──────────────────────────────────────────────────────
OUTPUT_DIR=""
THREADS=10
PROXY=""
STEALTH=0
POST_DATA=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
    --threads)    THREADS="$2";    shift 2 ;;
    --proxy)      PROXY="$2";      shift 2 ;;
    --stealth)    STEALTH=1; shift ;;
    --post-data)  POST_DATA="$2";  shift 2 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

if [[ -z "$OUTPUT_DIR" ]]; then
  echo "Usage: $0 --output-dir <dir> [--threads N] [--proxy URL] [--stealth] [--post-data FILE]"
  exit 1
fi

# ── Initialize ────────────────────────────────────────────────
OUT="$OUTPUT_DIR"
mkdir -p "$OUT/logs" "$OUT/poc" "$OUT/tmp"
export OUT LOG THREADS PROXY STEALTH COOKIE POST_DATA

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
elif [[ -f "$OUT/params.txt" ]]; then
  DOMAIN=$(head -n 1 "$OUT/params.txt" 2>/dev/null | awk -F/ '{print $3}' || echo "")
fi
export DOMAIN

if [[ -f "$STATE/scope_domains" ]]; then
  mapfile -t SCOPE_DOMAINS < "$STATE/scope_domains" 2>/dev/null || true
fi

# ── Resume check ──────────────────────────────────────────────
if checkpoint_check param_extraction; then
  log "[RESUME] Skipping Reflection Check (already complete)"
  echo "Phase validate skipped (param_extraction already complete)"
  exit 0
fi

check_deps

PARAMS=$(count_lines "$OUT/params.txt")
if [[ $PARAMS -eq 0 ]]; then
  log "No parameterised URLs found. Skipping reflection check."
  touch "$OUT/reflected_urls.txt"
  touch "$OUT/reflected_validated.txt"
  touch "$OUT/high_priority_targets.txt"
  checkpoint_done param_extraction
  echo "Phase validate complete: 0 params, 0 reflected"
  exit 0
fi

# ══ Reflection Check (curl-based, PARALLEL) ═════════════════
set_phase "Reflection Check" "$PARAMS"
log "Running reflection check on $PARAMS parameterized URLs (${THREADS} threads)..."

_rc_cmd="curl-based reflection checker on $OUT/params.txt"
debug_tool_start "reflection_check" "$_rc_cmd"
_rc_start; _rc_start=$(date +%s)

> "$OUT/kxss_raw.txt"
> "$OUT/reflected_urls.txt"

check_reflection() {
  url_file="$1"
  _S="$2" _O="$3"

  url
  url=$(cat "$url_file" 2>/dev/null) || return 1

  _UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
  state_inc "phase_done"

  canary="rxss${RANDOM}$(date +%s)"
  test_url=""
  if [[ "$url" == *"?"* ]]; then
    _base="${url%%\?*}"
    _query="${url#*\?}"
    _newq
    _newq=$(printf '%s' "$_query" | awk -v canary="$canary" -F'&' '{
      for(i=1;i<=NF;i++){
        split($i,a,"=")
        if(length(a)>=2) $i=a[1]"="canary
      }
      OFS="&"
      print
    }')
    test_url="${_base}?${_newq}"
  else
    test_url="$url"
  fi

  curl_args=( -sS --max-time 10
    -H "User-Agent: $_UA"
    -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    -H "Accept-Language: en-US,en;q=0.9"
    --compressed )
  [[ -n "${COOKIE:-}" ]] && curl_args+=(-H "Cookie: $COOKIE")
  curl_args+=(-- "$test_url")

  _curl_rc=0
  body=""
  body=$(curl "${curl_args[@]}" 2>/dev/null)
  _curl_rc=$?

  if [[ $_curl_rc -ne 0 ]]; then
    { flock 9; printf '%s\n' "CURL_ERR:$_curl_rc: $url" >> "$_O/tmp/curl_errors.log"; } 9>"$_S/error_w.lock" 2>/dev/null
    return 0
  fi

  if echo "$body" | grep -qF "$canary"; then
    { flock 9; printf '%s\n' "$url" >> "$_O/reflected_urls.txt"; } 9>"$_S/reflect_w.lock"

    chars_reflected=""
    for char in '"' "'" '<' '>'; do
      char_canary="rxpfx${char}rxsfx"
      char_url="$url"
      if [[ "$url" == *"?"* ]]; then
        _cbase="${url%%\?*}"
        _cquery="${url#*\?}"
        _newcq
        _newcq=$(printf '%s' "$_cquery" | sed "s|=[^&]*|=${char_canary}|g")
        char_url="${_cbase}?${_newcq}"
      fi
      char_curl_args=( -sS --max-time 10
        -H "User-Agent: $_UA"
        --compressed )
      [[ -n "${COOKIE:-}" ]] && char_curl_args+=(-H "Cookie: $COOKIE")
      char_curl_args+=(-- "$char_url")

      char_body=""
      char_body=$(curl "${char_curl_args[@]}" 2>/dev/null) || continue
      if echo "$char_body" | grep -qF "$char_canary"; then
        chars_reflected="${chars_reflected}${char}"
      fi
    done

    if [[ -n "$chars_reflected" ]]; then
      { flock 9; echo "Reflected chars [$chars_reflected] on $url" >> "$_O/kxss_raw.txt"; } 9>"$_S/kxss_w.lock"
    fi
  fi
}
export -f check_reflection state_inc

# ── Dispatch URLs to temp files for parallel processing ──────
_rc_tmp="$OUT/tmp/urls_reflect"
mkdir -p "$_rc_tmp"
_rc_i=0
while IFS= read -r url; do
  tf="$_rc_tmp/url_${_rc_i}.txt"
  printf '%s' "$url" > "$tf"
  printf '%s\0' "$tf"
  (( _rc_i++ ))
done < "$OUT/params.txt" | \
  xargs -0 -P "${THREADS:-10}" -I{} \
    /bin/bash -c 'check_reflection '\$@'' _ \
      "{}" "$STATE" "$OUT"

# Wait for workers to finish writing
_before=0 _after=0 _stable=0
for _i in $(seq 1 5); do
  _before=$(count_lines "$OUT/reflected_urls.txt")
  sleep 1
  _after=$(count_lines "$OUT/reflected_urls.txt")
  [[ "$_before" == "$_after" ]] && { _stable=1; break; }
done
[[ $_stable -eq 0 ]] && sleep 2

_rc_reflected; _rc_reflected=$(count_lines "$OUT/reflected_urls.txt")
_rc_specials; _rc_specials=$(wc -l < "$OUT/kxss_raw.txt" 2>/dev/null || echo 0)
_rc_dur=$(( $(date +%s) - _rc_start ))
debug_tool_end "reflection_check" "0" "$OUT/reflected_urls.txt" "$_rc_dur"

log "Reflection check complete: $PARAMS checked, $_rc_reflected reflected, $_rc_specials with special chars (${_rc_dur}s)"

checkpoint_done param_extraction

# ══ Reflection Validation (Python) ══════════════════════════
REFLECTED=$(count_lines "$OUT/reflected_urls.txt")
REFLECTED=${REFLECTED:-0}
log "Reflected URLs for scanning: $REFLECTED"

if checkpoint_check reflection_validation; then
  log "[RESUME] Skipping Reflection Validation (already complete)"
elif [[ $REFLECTED -gt 0 ]] && command -v python3 &>/dev/null && \
     python3 -c 'import requests' 2>/dev/null; then
  set_phase "Reflection Validation (Python)" "$REFLECTED"
  log "Running deep reflection validation..."
  validator_args=("$SCRIPT_DIR/xss_validator.py"
    --input "$OUT/reflected_urls.txt"
    --output-dir "$OUT"
    --threads "$THREADS")
  [[ -n "$PROXY" ]] && validator_args+=(--proxy "$PROXY")
  [[ $STEALTH -eq 1 ]] && validator_args+=(--stealth)
  [[ -n "$POST_DATA" ]] && validator_args+=(--post-data "$POST_DATA")
  [[ -n "${COOKIE:-}" ]] && validator_args+=(--cookie "$COOKIE")

  debug_tool_start "python3/xss_validator" "python3 ${validator_args[*]}"
  _val_start; _val_start=$(date +%s)

  python3 "${validator_args[@]}" \
    2>>"$OUT/logs/errors.log"
  _val_exit=$?

  _val_dur=$(( $(date +%s) - _val_start ))
  debug_tool_end "python3/xss_validator" "$_val_exit" "$OUT/reflected_validated.txt" "$_val_dur"

  if [[ $_val_exit -ne 0 ]]; then
    log "WARN: Python validator failed, falling back to kxss results"
    cp "$OUT/reflected_urls.txt" "$OUT/reflected_validated.txt" 2>/dev/null || true
    cp "$OUT/reflected_urls.txt" "$OUT/high_priority_targets.txt" 2>/dev/null || true
  fi
  if [[ -f "$OUT/reflected_validated.txt" && -s "$OUT/reflected_validated.txt" ]]; then
    VALIDATED=$(count_lines "$OUT/reflected_validated.txt")
    log "Python-validated reflections: $VALIDATED"
  else
    VALIDATED=0
  fi
  checkpoint_done reflection_validation
else
  log "Skipping Python validation (not available or no reflected URLs)"
  if [[ -f "$OUT/reflected_urls.txt" && -s "$OUT/reflected_urls.txt" ]]; then
    cp "$OUT/reflected_urls.txt" "$OUT/high_priority_targets.txt"
    cp "$OUT/reflected_urls.txt" "$OUT/reflected_validated.txt"
  else
    log "no reflected URLs to propagate — skipping empty file copy"
  fi
fi

echo "Phase validate complete: reflected=$REFLECTED"
