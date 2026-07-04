#!/bin/bash
# =============================================================
#  common.sh — Shared functions and variables for ReflexionX
#  Source this file from any phase script.
# =============================================================

# Guard against double-sourcing
if [[ -n "${_REFLEXIONX_COMMON_LOADED:-}" ]]; then
  return 0 2>/dev/null || true
fi
_REFLEXIONX_COMMON_LOADED=1

# ── Defaults for variables set by reflexionx.sh main args ─────
# Phase scripts must export/override these before calling functions.
OUT="${OUT:-}"
LOG="${LOG:-}"
DOMAIN="${DOMAIN:-}"
STATE="${STATE:-}"
THREADS="${THREADS:-10}"
PROXY="${PROXY:-}"
STEALTH="${STEALTH:-0}"
COOKIE="${COOKIE:-}"
BOT_TOKEN="${BOT_TOKEN:-}"
CHAT_ID="${CHAT_ID:-}"
BLIND_URL="${BLIND_URL:-}"
POST_DATA="${POST_DATA:-}"
VALIDATE="${VALIDATE:-0}"
DOM_SCAN="${DOM_SCAN:-0}"
FRAGMENT_SCAN="${FRAGMENT_SCAN:-0}"
RESUME_DIR="${RESUME_DIR:-}"
SCOPE_FILE="${SCOPE_FILE:-}"
NUCLEI_SCAN="${NUCLEI_SCAN:-0}"
PARAM_MINE="${PARAM_MINE:-0}"
START_TIME="${START_TIME:-0}"

# Script directory (reflexionx.sh root)
_script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export SCRIPT_DIR="${SCRIPT_DIR:-$_script_dir}"

# ── Colors ────────────────────────────────────────────────────
RED=$(tput setaf 1 2>/dev/null || printf '')
GREEN=$(tput setaf 2 2>/dev/null || printf '')
YELLOW=$(tput setaf 3 2>/dev/null || printf '')
CYAN=$(tput setaf 6 2>/dev/null || printf '')
MAGENTA=$(tput setaf 5 2>/dev/null || printf '')
BOLD=$(tput bold 2>/dev/null || printf '')
DIM=$(tput dim 2>/dev/null || printf '')
RESET=$(tput sgr0 2>/dev/null || printf '')

# ── State files (must be set by caller before use) ─────────────
PHASE_LOG="${PHASE_LOG:-${STATE:-/tmp/reflexionx_state}/phase_log}"
ACTIVITY_FILE="${ACTIVITY_FILE:-${STATE:-/tmp/reflexionx_state}/last_activity}"

# Initialize dot state files (used by state_get / state_inc)
_common_init_state() {
  [[ -z "${STATE:-}" ]] && return 0
  > "$STATE/done" 2>/dev/null || true
  > "$STATE/phase_done" 2>/dev/null || true
  > "$STATE/errors" 2>/dev/null || true
  > "$STATE/found" 2>/dev/null || true
  > "$STATE/xsstrike_hits" 2>/dev/null || true
  > "$STATE/running" 2>/dev/null || true
  > "$PHASE_LOG" 2>/dev/null || true
}

# ── Logging ────────────────────────────────────────────────────
log() {
  [[ -z "${LOG:-}" ]] && return 0
  echo "[$(date '+%H:%M:%S')] $*" >> "$LOG"
  printf '%s' "$*" > "$ACTIVITY_FILE"
}
log_only() { echo "[$(date '+%H:%M:%S')] $*" >> "$LOG"; }

# ── Debug Logging Helpers ──────────────────────────────────────
debug() {
  echo "[$(date '+%H:%M:%S')] [DEBUG] $*" >> "$LOG"
}
debug_tool_start() {
  local tool="$1"; shift
  echo "[$(date '+%H:%M:%S')] [DEBUG] >>>>>>>>>> STARTING: $tool <<<<<<<<<<" >> "$LOG"
  echo "[$(date '+%H:%M:%S')] [DEBUG]   Command: $*" >> "$LOG"
  echo "[$(date '+%H:%M:%S')] [DEBUG]   Working dir: $(pwd)" >> "$LOG"
  local base_tool="${tool%%/*}"
  local tool_path
  tool_path=$(command -v "$base_tool" 2>/dev/null || echo 'NOT FOUND')
  echo "[$(date '+%H:%M:%S')] [DEBUG]   Tool binary: $tool_path" >> "$LOG"
  if [[ "$tool_path" != "NOT FOUND" && -f "$tool_path" ]]; then
    local tool_version
    tool_version=$("$tool_path" --version 2>/dev/null | head -1 || echo "unknown")
    echo "[$(date '+%H:%M:%S')] [DEBUG]   Tool version: $tool_version" >> "$LOG"
  fi
}
debug_tool_end() {
  local tool="$1" exit_code="$2" output_file="${3:-}" duration="${4:-}"
  echo "[$(date '+%H:%M:%S')] [DEBUG] <<<<<<<<<< FINISHED: $tool (exit=$exit_code, time=${duration}s) >>>>>>>>>>" >> "$LOG"
  if [[ -n "$output_file" && -f "$output_file" ]]; then
    local lines size
    lines=$(wc -l < "$output_file" 2>/dev/null | tr -d ' ')
    size=$(wc -c < "$output_file" 2>/dev/null | tr -d ' ')
    echo "[$(date '+%H:%M:%S')] [DEBUG]   Output: $output_file ($lines lines, $size bytes)" >> "$LOG"
    if [[ "$lines" -gt 0 ]] 2>/dev/null; then
      echo "[$(date '+%H:%M:%S')] [DEBUG]   First 3 lines:" >> "$LOG"
      head -3 "$output_file" 2>/dev/null | while IFS= read -r _dbg_line; do
        echo "[$(date '+%H:%M:%S')] [DEBUG]     $_dbg_line" >> "$LOG"
      done
    fi
  elif [[ -n "$output_file" ]]; then
    echo "[$(date '+%H:%M:%S')] [DEBUG]   Output file NOT FOUND: $output_file" >> "$LOG"
  fi
}

# ── State helpers ──────────────────────────────────────────────
# Two storage schemes:
#   • Dot-counting (state_inc): file contains "...." — byte count = value
#   • Value files  (state_set): file contains the value string directly
state_set() {
  if [[ "$2" == "0" ]]; then
    > "$STATE/$1"
  else
    printf "%s" "$2" > "$STATE/$1"
  fi
}
state_get() {
  [[ -f "$STATE/$1" ]] || { echo 0; return; }
  local sz
  sz=$(wc -c < "$STATE/$1" 2>/dev/null | tr -d ' ')
  if [[ "$sz" -eq 0 ]] 2>/dev/null; then
    echo 0
    return
  fi
  local peek
  peek=$(head -c 1 "$STATE/$1" 2>/dev/null)
  if [[ "$peek" == "." ]]; then
    echo "$sz"
  else
    cat "$STATE/$1" 2>/dev/null
  fi
}
state_inc() {
  printf "." >> "$STATE/$1"
}

# ── Phase completion tracker (for the timeline) ──────────────
log_phase_complete() {
  printf "%s|%s|%s\n" "$(date +%s)" "$1" "${2:-}" >> "$PHASE_LOG"
}

# ── Scope functions ────────────────────────────────────────────
SCOPE_DOMAINS=()
is_in_scope() {
  local url="$1"
  local domain
  domain=$(echo "$url" | sed -E 's|^https?://||' | cut -d'/' -f1 | cut -d':' -f1 | tr '[:upper:]' '[:lower:]')
  [[ -z "$domain" ]] && return 1
  for scope_domain in "${SCOPE_DOMAINS[@]}"; do
    local sd
    sd=$(echo "$scope_domain" | cut -d':' -f1 | tr '[:upper:]' '[:lower:]')
    if [[ "$domain" == "$sd" || "$domain" == *."$sd" ]]; then
      return 0
    fi
  done
  return 1
}
enforce_scope() {
  local input_file="$1"
  local label="${2:-urls}"
  [[ ! -f "$input_file" || ! -s "$input_file" ]] && return 0
  local before; before=$(wc -l < "$input_file" | tr -d ' ')
  local tmpfile; tmpfile=$(mktemp)
  local removed=0
  while IFS= read -r url; do
    if is_in_scope "$url"; then
      echo "$url" >> "$tmpfile"
    else
      (( removed++ )) || true
    fi
  done < "$input_file"
  mv "$tmpfile" "$input_file"
  local after; after=$(wc -l < "$input_file" | tr -d ' ')
  if [[ $removed -gt 0 ]]; then
    log "[SCOPE] $label: $before -> $after (removed $removed out-of-scope URLs)"
    debug "[SCOPE] Enforced on $input_file: $removed removed"
  fi
}

# ── Checkpoint helpers ─────────────────────────────────────────
checkpoint_done() {
  if command -v python3 &>/dev/null && [[ -f "$SCRIPT_DIR/checkpoint.py" ]]; then
    python3 "$SCRIPT_DIR/checkpoint.py" --output-dir "$OUT" --domain "$DOMAIN" --mark-complete "$1" 2>/dev/null || true
  fi
}
checkpoint_check() {
  if [[ -n "${RESUME_DIR:-}" ]] && command -v python3 &>/dev/null && [[ -f "$SCRIPT_DIR/checkpoint.py" ]]; then
    python3 "$SCRIPT_DIR/checkpoint.py" --output-dir "$OUT" --is-complete "$1" 2>/dev/null && return 0
  fi
  return 1
}

# ── AI analysis helper ─────────────────────────────────────────
ai_analyze() {
  local phase="$1"
  [[ "${AI_AGENT:-0}" -eq 0 ]] && return 0
  log "AI analyzing: $phase"
  state_set "phase" "AI Analysis ($phase)"
  local max_iters=25
  [[ "${AI_DEPTH:-conservative}" == "aggressive" ]] && max_iters=100
  python3 "$SCRIPT_DIR/reflexion_agent.py" \
    --target "$DOMAIN" \
    --output-dir "$OUT" \
    --model "${AI_MODEL:-nvidia/nemotron-3-super-120b-a12b:free}" \
    --max-iterations "$max_iters" \
    --phase "$phase" \
    2>>"$OUT/logs/errors.log"
  local _ai_exit=$?
  if [[ $_ai_exit -ne 0 ]]; then
    log "WARN: AI analysis failed ($phase) — check $OUT/logs/errors.log"
  fi
}

# ── Telegram ───────────────────────────────────────────────────
send_telegram() {
  [[ -z "${BOT_TOKEN:-}" || -z "${CHAT_ID:-}" ]] && return 0
  local msg="$1"
  msg=$(echo "$msg" | sed -e 's/\_/\\_/g' -e 's/\*/\\*/g')
  curl -s -X POST "https://api.telegram.org/bot${BOT_TOKEN}/sendMessage" \
    -d chat_id="$CHAT_ID" -d text="$msg" -d parse_mode="Markdown" \
    >/dev/null 2>&1 || true
}

# ── Dependency check ───────────────────────────────────────────
check_deps() {
  local missing=()
  for cmd in gau waybackurls katana httpx uro dalfox xsstrike; do
    command -v "$cmd" &>/dev/null || missing+=("$cmd")
  done
  if [[ ${#missing[@]} -gt 0 ]]; then
    echo "${YELLOW}[!] Missing tools (will be skipped): ${missing[*]}${RESET}"
    printf '%s\n' "${missing[@]}" > "$OUT/logs/missing_tools.txt"
  fi
  if [[ ${VALIDATE:-0} -eq 1 || ${DOM_SCAN:-0} -eq 1 ]]; then
    if ! command -v python3 &>/dev/null; then
      echo "${YELLOW}[!] python3 not found — disabling -V/-D features${RESET}"
      VALIDATE=0; DOM_SCAN=0
    fi
  fi
}

# ── Timeout ────────────────────────────────────────────────────
smart_timeout() {
  local soft_limit=$1
  shift
  "$@" &
  local pid=$!
  local start_time=$(date +%s)
  local last_ticks=""
  local stuck_count=0
  while kill -0 "$pid" 2>/dev/null; do
    local now=$(date +%s)
    local elapsed=$((now - start_time))
    if [[ $elapsed -gt $soft_limit ]]; then
      local current_ticks=""
      if [[ -r "/proc/$pid/stat" ]]; then
        current_ticks=$(awk '{print $14+$15}' "/proc/$pid/stat" 2>/dev/null)
      elif command -v ps &>/dev/null; then
        current_ticks=$(ps -p "$pid" -o time= 2>/dev/null | tr -d ' :.')
      fi
      if [[ "$current_ticks" == "$last_ticks" && -n "$current_ticks" ]]; then
        ((stuck_count++))
      else
        stuck_count=0
        last_ticks="$current_ticks"
      fi
      if [[ $stuck_count -ge 3 ]]; then
        kill -TERM -"$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
        local grace=0
        while kill -0 "$pid" 2>/dev/null && [[ $grace -lt 5 ]]; do
          sleep 1
          ((grace++))
        done
        if kill -0 "$pid" 2>/dev/null; then
          kill -9 -"$pid" 2>/dev/null || kill -9 "$pid" 2>/dev/null || true
        fi
        wait "$pid" 2>/dev/null || true
        return 124
      fi
    fi
    sleep 10
  done
  wait "$pid" 2>/dev/null
  return $?
}
export -f smart_timeout

# ── URL priority scoring ───────────────────────────────────────
score_url() {
  local url="$1" score=0
  [[ $url == *"search"*   ]] && (( score += 5 ))
  [[ $url == *"q="*       ]] && (( score += 4 ))
  [[ $url == *"query="*   ]] && (( score += 4 ))
  [[ $url == *"redirect"* ]] && (( score += 3 ))
  [[ $url == *"url="*     ]] && (( score += 3 ))
  [[ $url == *"id="*      ]] && (( score += 2 ))
  [[ $url == *"page="*    ]] && (( score += 1 ))
  [[ $url == *"name="*    ]] && (( score += 1 ))
  [[ $url == *"callback="* ]] && (( score += 5 ))
  [[ $url == *"return="*   ]] && (( score += 4 ))
  [[ $url == *"next="*     ]] && (( score += 4 ))
  [[ $url == *"ref="*      ]] && (( score += 3 ))
  [[ $url == *"src="*      ]] && (( score += 3 ))
  [[ $url == *"href="*     ]] && (( score += 3 ))
  [[ $url == *"template="* ]] && (( score += 4 ))
  [[ $url == *"html="*     ]] && (( score += 5 ))
  [[ $url == *"content="*  ]] && (( score += 3 ))
  [[ $url == *"msg="*      ]] && (( score += 3 ))
  [[ $url == *"error="*    ]] && (( score += 3 ))
  [[ $url == *"text="*     ]] && (( score += 2 ))
  local hp_file="${_OUTDIR:-}/high_priority_targets.txt"
  if [[ -f "$hp_file" ]] && grep -qF "$url" "$hp_file" 2>/dev/null; then
    (( score += 10 ))
  fi
  local dom_file="${_OUTDIR:-}/dom_risks.txt"
  if [[ -f "$dom_file" ]]; then
    local domain_part
    domain_part=$(echo "$url" | grep -oP 'https?://[^/]+' 2>/dev/null || true)
    if [[ -n "$domain_part" ]] && grep -qF "$domain_part" "$dom_file" 2>/dev/null; then
      (( score += 5 ))
    fi
  fi
  printf "%02d %s\n" "$score" "$url"
}
export -f score_url

# ── Time Formatting Helper ─────────────────────────────────────
fmt_time() {
  local secs=$1
  if [[ $secs -lt 0 ]]; then secs=0; fi
  if [[ $secs -ge 86400 ]]; then
    printf "%dd %dh %dm" $((secs/86400)) $((secs%86400/3600)) $((secs%3600/60))
  elif [[ $secs -ge 3600 ]]; then
    printf "%dh %dm %ds" $((secs/3600)) $((secs%3600/60)) $((secs%60))
  elif [[ $secs -ge 60 ]]; then
    printf "%dm %ds" $((secs/60)) $((secs%60))
  else
    printf "%ds" "$secs"
  fi
}

# ── Scan workers (dalfox / XSStrike) ──────────────────────────
scan_url() {
  local url_file="$1"
  local _S="$2" _O="$3" _P="$4" _B="$5" _BOT="$6" _CID="$7" _DOM="$8"
  local url
  url=$(cat "$url_file" 2>/dev/null) || return 1
  if [[ -f "$_S/circuit_breaker" ]]; then
    rm -f "$url_file"
    return 1
  fi
  local _df_start; _df_start=$(date +%s)
  echo "[$(date '+%H:%M:%S')] [DEBUG] >>>>>>>>>> STARTING: dalfox <<<<<<<<<<<" >> "$_O/logs/reflexionx.log"
  echo "[$(date '+%H:%M:%S')] [DEBUG]   Target URL: $url" >> "$_O/logs/reflexionx.log"
  {
    flock 9
    printf '%s\n' "$url" >> "$_O/tmp/active.txt"
  } 9>"$_S/active_w.lock"
  local dalfox_args=("url" "$url" "--timeout" "30" "--no-color" "--no-spinner")
  dalfox_args+=("--waf-evasion")
  dalfox_args+=("--header" "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")
  dalfox_args+=("--header" "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
  dalfox_args+=("--header" "Accept-Language: en-US,en;q=0.9")
  if [[ ${STEALTH:-0} -eq 1 ]]; then
    dalfox_args+=("--delay" "1000")
  fi
  if [[ -f "$_S/skip_headless" ]]; then
    dalfox_args+=("--skip-headless" "--skip-mining-dom")
  fi
  [[ -n "$_P" ]] && dalfox_args+=("--proxy" "$_P")
  [[ -n "$_B" ]] && dalfox_args+=("--blind" "$_B")
  [[ -f "$_O/ai_payloads.txt" ]] && dalfox_args+=("--custom-payload" "$_O/ai_payloads.txt")
  [[ -n "${COOKIE:-}" ]] && dalfox_args+=("--cookie" "$COOKIE")
  echo "[$(date '+%H:%M:%S')] [DEBUG]   dalfox args: ${dalfox_args[*]}" >> "$_O/logs/reflexionx.log"
  local dalfox_exit=0
  local tmp_df="$_O/tmp/df_out_$(uuidgen 2>/dev/null || echo $RANDOM).txt"
  local tmp_err="$_O/tmp/df_err_$(uuidgen 2>/dev/null || echo $RANDOM).txt"
  GOTRACEBACK=none smart_timeout 120 dalfox "${dalfox_args[@]}" > "$tmp_df" 2> "$tmp_err" || dalfox_exit=$?
  cat "$tmp_err" >> "$_O/logs/dalfox_debug.log"
  if grep -qE "Finish Scan!|\[POC\]|\[\+\].*XSS|\[V\]" "$tmp_err" 2>/dev/null; then
    dalfox_exit=0
  fi
  local result=""
  result=$(cat "$tmp_df" 2>/dev/null || echo "")
  rm -f "$tmp_df" "$tmp_err"
  local _df_end; _df_end=$(date +%s)
  local _df_dur=$(( _df_end - _df_start ))
  echo "[$(date '+%H:%M:%S')] [DEBUG] <<<<<<<<<< FINISHED: dalfox (exit=$dalfox_exit, time=${_df_dur}s) >>>>>>>>>>" >> "$_O/logs/reflexionx.log"
  echo "[$(date '+%H:%M:%S')] [DEBUG]   Result length: ${#result} chars" >> "$_O/logs/reflexionx.log"
  if [[ $dalfox_exit -ne 0 ]]; then
    { flock 9; echo "$url" >> "$_S/failed_scans.txt"; } 9>"$_S/failed_w.lock"
    printf "." >> "$_S/errors"
    local err_count
    err_count=$(stat -c%s "$_S/errors" 2>/dev/null || echo 0)
    if [[ $err_count -ge 30 ]]; then
      touch "$_S/circuit_breaker"
      echo "[$(date '+%H:%M:%S')] [WARN] CIRCUIT BREAKER TRIPPED: >=30 dalfox errors. WAF blocking likely." >> "$_O/logs/reflexionx.log"
    fi
  fi
  {
    flock 9
    printf '%s\n' "$result" >> "$_O/dalfox.txt"
  } 9>"$_S/dalfox_w.lock"
  if printf '%s\n' "$result" | grep -qiE '\[POC\].*\[[GRV]\]|Found.*XSS|\[V\]\s|XSS\s+Found|Reflected.*XSS'; then
    echo "[$(date '+%H:%M:%S')] [DEBUG]   *** XSS DETECTED for $url ***" >> "$_O/logs/reflexionx.log"
    local hash; hash=$(printf '%s' "$url" | md5sum | cut -d' ' -f1)
    {
      flock 9
      printf '%s\n' "$url" >> "$_O/poc/poc.txt"
    } 9>"$_S/poc_w.lock"
    printf "URL: %s\n---\n%s\n" "$url" "$result" > "$_O/poc/${hash}.txt"
    printf "." >> "$_S/found"
    if [[ -n "$_BOT" && -n "$_CID" ]]; then
      curl -s -X POST \
        "https://api.telegram.org/bot${_BOT}/sendMessage" \
        -d chat_id="$_CID" \
        -d text="🚨 *XSS FOUND* 🚨
*Domain*: ${_DOM}
*URL*: \`${url}\`
*Payload info details*: \`poc/${hash}.txt\`" \
        >/dev/null 2>&1 || true
    fi
  else
    echo "[$(date '+%H:%M:%S')] [DEBUG]   No XSS found for $url" >> "$_O/logs/reflexionx.log"
  fi
  {
    flock 9
    grep -vF "$url" "$_O/tmp/active.txt" > "$_O/tmp/active.tmp" 2>/dev/null && \
      mv "$_O/tmp/active.tmp" "$_O/tmp/active.txt" || true
  } 9>"$_S/active_w.lock"
  printf "." >> "$_S/done"
  printf "." >> "$_S/phase_done"
  rm -f "$url_file"
}
export -f scan_url

# ── XSStrike Worker ────────────────────────────────────────────
scan_xsstrike() {
  local url_file="$1"
  local _S="$2" _O="$3" _P="$4" _DOM="$5"
  local url
  url=$(cat "$url_file" 2>/dev/null) || return 1
  if [[ -f "$_S/circuit_breaker" ]]; then
    rm -f "$url_file"
    return 1
  fi
  local _xs_start; _xs_start=$(date +%s)
  echo "[$(date '+%H:%M:%S')] [DEBUG] >>>>>>>>>> STARTING: xsstrike <<<<<<<<<<<" >> "$_O/logs/reflexionx.log"
  echo "[$(date '+%H:%M:%S')] [DEBUG]   Target URL: $url" >> "$_O/logs/reflexionx.log"
  { flock 9; printf '%s\n' "$url" >> "$_O/tmp/active.txt"; } 9>"$_S/active_w.lock"
  local result=""
  local xs_args=("--skip" "--skip-dom" "--timeout" "10")
  [[ -n "${COOKIE:-}" ]] && xs_args+=("--headers" "Cookie: $COOKIE")
  result=$(smart_timeout 180 xsstrike -u "$url" "${xs_args[@]}" 2>>"$_O/logs/xsstrike_debug.log") || true
  local _xs_end; _xs_end=$(date +%s)
  local _xs_dur=$(( _xs_end - _xs_start ))
  echo "[$(date '+%H:%M:%S')] [DEBUG] <<<<<<<<<< FINISHED: xsstrike (time=${_xs_dur}s) >>>>>>>>>>" >> "$_O/logs/reflexionx.log"
  { flock 9; printf '%s\n\n' "$result" >> "$_O/xsstrike_results.txt"; } 9>"$_S/xsstrike_w.lock"
  if printf '%s\n' "$result" | grep -qiE '\[\+\].*[Xx][Ss][Ss]|payload:|vulnerable'; then
    echo "[$(date '+%H:%M:%S')] [DEBUG]   *** XSStrike HIT for $url ***" >> "$_O/logs/reflexionx.log"
    local hash; hash=$(printf '%s' "$url" | md5sum | cut -d' ' -f1)
    { flock 9; printf '%s\n' "$url" >> "$_O/poc/poc.txt"; } 9>"$_S/poc_w.lock"
    printf "URL: %s\n[XSStrike Finding]\n---\n%s\n" "$url" "$result" > "$_O/poc/${hash}_xsstrike.txt"
    printf "." >> "$_S/found"
    printf "." >> "$_S/xsstrike_hits"
  else
    echo "[$(date '+%H:%M:%S')] [DEBUG]   No XSStrike hit for $url" >> "$_O/logs/reflexionx.log"
  fi
  { flock 9; grep -vF "$url" "$_O/tmp/active.txt" > "$_O/tmp/active.tmp" 2>/dev/null && mv "$_O/tmp/active.tmp" "$_O/tmp/active.txt" || true; } 9>"$_S/active_w.lock"
  printf "." >> "$_S/done"
  printf "." >> "$_S/phase_done"
  rm -f "$url_file"
}
export -f scan_xsstrike

# ── Dashboard ──────────────────────────────────────────────────
dashboard() {
  local spin=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
  local si=0
  while [[ -f "${STATE:-/tmp/reflexionx_state}/running" ]]; do
    local done_n errors found phase p_done p_total p_start
    done_n=$(state_get "done"); errors=$(state_get "errors")
    found=$(state_get "found"); phase=$(state_get "phase")
    p_done=$(state_get "phase_done"); p_total=$(state_get "phase_total")
    p_start=$(state_get "phase_start")
    done_n=$((done_n + 0)) 2>/dev/null || done_n=0
    errors=$((errors + 0)) 2>/dev/null || errors=0
    found=$((found + 0)) 2>/dev/null || found=0
    p_done=$((p_done + 0)) 2>/dev/null || p_done=0
    p_total=$((p_total + 0)) 2>/dev/null || p_total=0
    p_start=$((p_start + 0)) 2>/dev/null || p_start=0
    
    # Initialize variables for dashboard that were missing
    local load_str="-"
    if [[ -r /proc/loadavg ]]; then
      load_str=$(cut -d' ' -f1-3 /proc/loadavg 2>/dev/null)
    elif command -v uptime &>/dev/null; then
      load_str=$(uptime | awk -F'load average:' '{print $2}' | sed 's/^ *//' 2>/dev/null)
    fi
    
    local timeline=""
    if [[ -f "$PHASE_LOG" ]]; then
      # Read the last completed phase for the timeline
      timeline=$(tail -n 1 "$PHASE_LOG" 2>/dev/null | cut -d'|' -f2)
    fi
    
    local last_act="Initialising..."
    if [[ -f "$ACTIVITY_FILE" ]]; then
      last_act=$(tail -n 1 "$ACTIVITY_FILE" 2>/dev/null)
    fi

    local now elapsed p_elapsed rate_val remain pct
    now=$(date +%s); elapsed=$(( now - START_TIME ))
    if [[ $p_start -gt 1000000000 ]]; then
      p_elapsed=$(( now - p_start ))
    else
      p_elapsed=$elapsed
    fi
    [[ $p_elapsed -lt 0 ]] && p_elapsed=0
    remain=$(( p_total > p_done ? p_total - p_done : 0 ))
    local speed_label="req/s" eta_display
    if [[ $p_total -gt 0 && $p_done -gt 0 && $p_elapsed -gt 0 ]]; then
      rate_val=$(awk -v d="$p_done" -v e="$p_elapsed" 'BEGIN{printf "%.2f",d/e}')
      local es; es=$(awk -v r="$remain" -v v="$rate_val" 'BEGIN{if(v>0)printf "%d",r/v;else print 0}')
      eta_display=$(fmt_time "$es")
    elif [[ $p_total -eq 0 && $p_done -gt 0 && $p_elapsed -gt 0 ]]; then
      rate_val=$(awk -v d="$p_done" -v e="$p_elapsed" 'BEGIN{printf "%.2f",d/e}')
      speed_label="url/s"; eta_display="Collecting..."
    elif [[ $p_elapsed -gt 0 ]]; then
      rate_val="--"; eta_display="Working..."
    else
      rate_val="--"; eta_display="Starting..."
    fi
    if [[ $p_total -gt 0 ]]; then
      pct=$(( p_done * 100 / p_total )); [[ $pct -gt 100 ]] && pct=100
    else pct=0; fi
    local bw=40 bar="" bar_label=""
    if [[ $p_total -gt 0 ]]; then
      local filled=0 empty
      if [[ $p_done -le $p_total ]]; then
        filled=$(( p_done * bw / p_total ))
      else
        filled=$bw
      fi
      empty=$(( bw - filled ))
      [[ $filled -gt 0 ]] && bar=$(printf '#%.0s' $(seq 1 "$filled"))
      [[ $empty  -gt 0 ]] && bar+=$(printf '.%.0s' $(seq 1 "$empty"))
      bar_label=$(printf "%3d%%  %d/%d" "$pct" "$p_done" "$p_total")
    else
      local pulse_pos=$(( si % 20 ))
      local i
      for (( i=0; i<bw; i++ )); do
        local dist=$(( (i - pulse_pos * 2) ))
        [[ $dist -lt 0 ]] && dist=$(( -dist ))
        if [[ $dist -le 3 ]]; then
          bar+="#"
        else
          bar+="."
        fi
      done
      bar_label=$(printf " ~   %d collected" "$p_done")
    fi
    local elapsed_str; elapsed_str=$(fmt_time "$elapsed")
    local cpu_val="-" mem_val="-"
    if command -v ps &>/dev/null; then
      cpu_val=$(ps --ppid $$ -o pcpu= 2>/dev/null | awk '{s+=$1}END{printf "%.1f",s}' 2>/dev/null) || \
        cpu_val=$(ps -o pcpu= -p $$ 2>/dev/null | awk '{printf "%.1f",$1}' 2>/dev/null) || cpu_val="-"
      mem_val=$(ps --ppid $$ -o pmem= 2>/dev/null | awk '{s+=$1}END{printf "%.1f",s}' 2>/dev/null) || \
        mem_val=$(ps -o pmem= -p $$ 2>/dev/null | awk '{printf "%.1f",$1}' 2>/dev/null) || mem_val="-"
    fi
    local sep; sep=$(printf -- '-%.0s' $(seq 1 62))
    printf "\033[H"
    printf "\033[K\n"
    echo -e "  ${BOLD}${CYAN}  _____       __  __        _             __  __${RESET}\033[K"
    echo -e "  ${BOLD}${CYAN} |  __ \\     / _| | |      (_)           \\ \\/ /${RESET}\033[K"
    echo -e "  ${BOLD}${CYAN} | |__) |___| |_| | | _____ _  ___  _ __  \\  / ${RESET}\033[K"
    echo -e "  ${BOLD}${CYAN} |  _  // _ \\  _| | |/ _ \\ \\/ / |/ _ \\| '_ \\ /  \\ ${RESET}\033[K"
    echo -e "  ${BOLD}${CYAN} | | \\ \\  __/ | | | |  __/>  <| | (_) | | | / /\\ \\${RESET}\033[K"
    echo -e "  ${BOLD}${CYAN} |_|  \\_\\___|_| |_|_|\\___/_/\\_\\_|\\___/|_| |/_/  \\_\\${RESET}\033[K"
    printf "  ${DIM}v1.0.0  Production-Grade XSS Exploitation Framework${RESET}\033[K\n"
    printf "  ${DIM}${sep}${RESET}\033[K\n"
    printf "  ${CYAN}TARGET${RESET}    ${BOLD}${DOMAIN:0:50}${RESET}\033[K\n"
    printf "  ${CYAN}THREADS${RESET}   %-10s ${CYAN}MODE${RESET}  %s\033[K\n" "${THREADS}" "${mode_str:-standard}"
    printf "  ${CYAN}OUTPUT${RESET}    ${DIM}${OUT:0:50}${RESET}\033[K\n"
    printf "  ${DIM}${sep}${RESET}\033[K\n"
    printf "  ${CYAN}CURRENT PHASE:${RESET} ${YELLOW}${BOLD}${phase:0:48}${RESET} ${spin[$si]}\033[K\n"
    printf "  ${GREEN}[${bar}]${RESET} ${BOLD}%s${RESET}\033[K\n" "$bar_label"
    printf "  ${DIM}${sep}${RESET}\033[K\n"
    printf "  ${CYAN}STATS:${RESET} ${BOLD}scanned:${RESET} ${GREEN}%-6d${RESET} ${BOLD}errors:${RESET} ${RED}%-6d${RESET} ${BOLD}xss found:${RESET} ${GREEN}${BOLD}%d${RESET}\033[K\n" \
      "$done_n" "$errors" "$found"
    printf "  ${BOLD}speed${RESET}   ${MAGENTA}%s %s${RESET}    ${BOLD}elapsed${RESET} %-10s  ${BOLD}eta${RESET} %s\033[K\n" \
      "$rate_val" "$speed_label" "$elapsed_str" "$eta_display"
    printf "  ${DIM}cpu ${cpu_val}%%  ram ${mem_val}%%  load ${load_str}${RESET}\033[K\n"
    printf "  ${DIM}${sep}${RESET}\033[K\n"
    if [[ -n "$timeline" ]]; then
      printf "  ${DIM}done:${RESET} %b\033[K\n" "$timeline"
    fi
    if [[ -f "$OUT/poc/poc.txt" && -s "$OUT/poc/poc.txt" ]]; then
      printf "  ${GREEN}${BOLD}>> findings${RESET}\033[K\n"
      tail -n 3 "$OUT/poc/poc.txt" 2>/dev/null | while IFS= read -r rl; do
        printf "     ${GREEN}%s${RESET}\033[K\n" "${rl:0:60}"
      done
    fi
    printf "\033[K\n"
    printf "  ${DIM}>> ${YELLOW}${last_act}${RESET}\033[K\n"
    printf "\033[J"
    si=$(( (si + 1) % ${#spin[@]} ))
    sleep 1
  done
}

# ── Dispatchers ────────────────────────────────────────────────
dispatch_scan() {
  local input_file="$1"
  local tmp_dir="$OUT/tmp/urls"
  mkdir -p "$tmp_dir"
  local i=0
  while IFS= read -r url; do
    local tf="$tmp_dir/url_${i}.txt"
    printf '%s' "$url" > "$tf"
    printf '%s\n' "$tf"
    (( i++ ))
  done < "$input_file" | \
    xargs -P "${THREADS:-10}" -I{} \
      /bin/bash -c 'scan_url "$@"' _ \
        {} "$STATE" "$OUT" "$PROXY" "$BLIND_URL" "$BOT_TOKEN" "$CHAT_ID" "$DOMAIN"
}

dispatch_xsstrike() {
  local input_file="$1"
  local tmp_dir="$OUT/tmp/urls_xss"
  mkdir -p "$tmp_dir"
  local i=0
  while IFS= read -r url; do
    local tf="$tmp_dir/url_${i}.txt"
    printf '%s' "$url" > "$tf"
    printf '%s\n' "$tf"
    (( i++ ))
  done < "$input_file" | \
    xargs -P "${THREADS:-10}" -I{} \
      /bin/bash -c 'scan_xsstrike "$@"' _ \
        {} "$STATE" "$OUT" "$PROXY" "$DOMAIN"
}

# ── Utility helpers ─────────────────────────────────────────────
set_phase() {
  local prev_phase
  prev_phase=$(state_get "phase")
  local prev_total
  prev_total=$(state_get "phase_total")
  if [[ -n "$prev_phase" && "$prev_phase" != "Initialising" && "$prev_phase" != "$1" ]]; then
    log_phase_complete "$prev_phase" "$prev_total"
  fi
  state_set "phase"       "$1"
  state_set "phase_done"  0
  state_set "phase_total" "${2:-0}"
  state_set "phase_start" "$(date +%s)"
  log "Phase: $1  (count: ${2:-?})"
}
count_lines() {
  [[ ! -f "$1" ]] && { echo 0; return; }
  local _c
  _c=$(wc -l < "$1" 2>/dev/null) || { echo 0; return; }
  _c="${_c// /}"
  [[ -z "$_c" ]] && _c=0
  echo "$_c"
}
cleanup_logs_dir() {
  find "$OUT/logs" -mindepth 1 -type d -exec rm -rf {} + 2>/dev/null || true
}
export -f count_lines
