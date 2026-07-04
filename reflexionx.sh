#!/bin/bash
# ============================================================
#  XSS REFLEXIONX v1.0.0 — Production-Grade XSS Exploitation Framework
#  For authorized security testing / bug bounty only.
#
#  Required tools (Bash pipeline):
#    gau, waybackurls, katana, httpx, uro, kxss, dalfox
#
#  Optional tools (Python validation engine):
#    python3, pip3, playwright (chromium)
#
#  Install core tools:
#    go install github.com/lc/gau/v2/cmd/gau@latest
#    go install github.com/tomnomnom/waybackurls@latest
#    go install github.com/projectdiscovery/katana/cmd/katana@latest
#    go install github.com/projectdiscovery/httpx/cmd/httpx@latest
#    pip3 install uro
#    go install github.com/tomnomnom/kxss@latest
#    go install github.com/hahwul/dalfox/v2@latest
#
#  Install Python validation (optional):
#    pip3 install -r requirements.txt
#    playwright install chromium
# ============================================================

# Resolve script directory for locating Python modules / phases
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source .env file if it exists (handles API keys)
set -a
if [[ -f "$SCRIPT_DIR/.env" ]]; then
  source "$SCRIPT_DIR/.env"
elif [[ -f "$SCRIPT_DIR/../.env" ]]; then
  source "$SCRIPT_DIR/../.env"
fi
set +a

# Prioritize Go binaries over Python virtualenv bins (e.g. for httpx)
# kali: go tools live in ~/go/bin; /go/bin is not writable by normal users
export PATH="$HOME/go/bin:/usr/local/go/bin:$PATH"

set -uo pipefail

usage() {
  cat <<EOF
Usage: $0 -d <domain> [options]

  -d  Target domain        (required if not using -u or -l)
  -u  Direct single URL to scan (bypasses crawling)
  -l  Direct list of URLs to scan (bypasses crawling)
  -c  Cookie header for authenticated scans (e.g. "session=123")
  -t  Threads              (default: 10)
  -p  Proxy URL            (e.g. http://127.0.0.1:8080)
  -b  Blind XSS callback URL
  -V  Enable Playwright browser validation (requires Python)
  -D  Enable DOM XSS analysis (requires Python)
  -S  Enable stealth mode (v2: jitter + reduced concurrency)
  -F  Enable fragment/DOM injection for level 3/6 (requires Python)
  -R  Resume from previous output directory
  -P  POST data file for body parameter testing
  -T  Telegram bot token
  -C  Telegram chat ID
  -h  Show this help

  --ai     Enable AI agentic decision loop
  --model  OpenRouter model to use for the AI agent
  --ai-depth  Depth of AI agent (conservative, aggressive) default: conservative
  --scope  Path to scope file (one domain per line). Default: target domain + subdomains
EOF
  exit 1
}

# ── Args ─────────────────────────────────────────────────────
DOMAIN=""
THREADS=10
PROXY=""
BLIND_URL=""
DOM_SCAN=0
FRAGMENT_SCAN=0
STEALTH=0
RESUME_DIR=""
POST_DATA=""
AI_AGENT=0
AI_MODEL="nvidia/nemotron-3-super-120b-a12b:free"
SCOPE_FILE=""
AI_DEPTH="conservative"
DIRECT_URL=""
DIRECT_LIST=""
COOKIE=""
NUCLEI_SCAN=0
PARAM_MINE=0

args=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --ai) AI_AGENT=1; shift ;;
    --model) AI_MODEL="$2"; shift 2 ;;
    --ai-depth) AI_DEPTH="$2"; shift 2 ;;
    --scope) SCOPE_FILE="$2"; shift 2 ;;
    --nuclei) NUCLEI_SCAN=1; shift ;;
    --param-mine) PARAM_MINE=1; shift ;;
    *) args+=("$1"); shift ;;
  esac
done
set -- "${args[@]:-}"

while getopts "d:u:l:c:t:p:b:T:C:R:P:VDSFAh" opt; do
  case $opt in
    d) DOMAIN="$OPTARG"    ;;
    u) DIRECT_URL="$OPTARG" ;;
    l) DIRECT_LIST="$OPTARG" ;;
    c) COOKIE="$OPTARG"    ;;
    t) THREADS="$OPTARG"   ;;
    p) PROXY="$OPTARG"     ;;
    b) BLIND_URL="$OPTARG" ;;
    T) BOT_TOKEN="$OPTARG" ;;
    C) CHAT_ID="$OPTARG"   ;;
    R) RESUME_DIR="$OPTARG" ;;
    P) POST_DATA="$OPTARG" ;;
    V) VALIDATE=1          ;;
    D) DOM_SCAN=1          ;;
    S) STEALTH=1           ;;
    F) FRAGMENT_SCAN=1     ;;
    A) AUTO_FORMS=1        ;;
    h|*) usage ;;
  esac
done

if [[ -z "$DOMAIN" ]]; then
  if [[ -n "$DIRECT_URL" ]]; then
    DOMAIN=$(echo "$DIRECT_URL" | awk -F/ '{print $3}')
  elif [[ -n "$DIRECT_LIST" ]]; then
    DOMAIN=$(head -n 1 "$DIRECT_LIST" | awk -F/ '{print $3}')
  else
    echo "[-] Domain (-d), direct URL (-u), or direct list (-l) required."
    usage
  fi
fi

# ── Scope helper: populate SCOPE_DOMAINS array + persist for phase scripts
_init_scope() {
  SCOPE_DOMAINS=()
  SCOPE_DOMAINS+=("$DOMAIN")
  if [[ -n "${SCOPE_FILE:-}" && -f "$SCOPE_FILE" ]]; then
    while IFS= read -r scope_domain; do
      scope_domain=$(echo "$scope_domain" | tr -d '[:space:]' | sed 's/#.*//')
      [[ -n "$scope_domain" ]] && SCOPE_DOMAINS+=("$scope_domain")
    done < "$SCOPE_FILE"
    echo "[*] Scope loaded: ${#SCOPE_DOMAINS[@]} domains from $SCOPE_FILE"
  fi
  # Persist scope for standalone phase-script use
  printf '%s\n' "${SCOPE_DOMAINS[@]}" > "$STATE/scope_domains" 2>/dev/null || true
  printf '%s' "$DOMAIN" > "$STATE/domain" 2>/dev/null || true
  log "Scope: ${SCOPE_DOMAINS[*]}"
}

# ── All paths ABSOLUTE ───────────────────────────────────────
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
if [[ -n "${RESUME_DIR:-}" && -d "$RESUME_DIR" ]]; then
  OUT="$(cd "$RESUME_DIR" && pwd)"
  echo "[*] Resuming from: $OUT"
else
  OUT="$(pwd)/xss_${DOMAIN}_${TIMESTAMP}"
fi
STATE="$OUT/.state"

mkdir -p "$OUT/logs" "$OUT/poc" "$OUT/tmp" "$STATE"
LOG="$OUT/logs/reflexionx.log"
export COOKIE

# Source shared functions BEFORE any code that calls them
source "$SCRIPT_DIR/phases/common.sh"

_init_scope
_common_init_state

# ── Stealth mode adjustments (v2.0.0) ────────────────────────
if [[ $STEALTH -eq 1 ]]; then
  [[ $THREADS -gt 3 ]] && THREADS=3
  echo "[*] Stealth mode: threads reduced to $THREADS"
  export mode_str="stealth"
else
  export mode_str="standard"
fi

# Checkpoint helpers (from phases/common.sh — imported there)

# ══ Phase Dispatch ════════════════════════════════════════════

# ── MAIN ─────────────────────────────────────────────────────
main() {
  check_deps

  START_TIME=$(date +%s)
  export START_TIME OUT STATE LOG STEALTH COOKIE PROXY

  touch "$STATE/running"
  printf "\033[2J\033[H" # initial clear
  dashboard &
  DASH_PID=$!

  # ── Redirect pipeline stdout to log file ─────────────────
  # Only stdout (fd 1) is redirected. stderr (fd 2) is left
  # on the terminal so errors are visible to the user.
  # The dashboard runs in a background process with its own
  # stdout, so only the dashboard banner is visible.
  exec 1>>"$LOG"

  trap '
    # Ignore further interrupts during cleanup
    trap "" INT TERM
    echo "" >/dev/tty
    echo "[!] Interrupted by user. Stopping all background processes..." >/dev/tty
    rm -f "$STATE/running"
    kill "$DASH_PID" 2>/dev/null || true
    
    # Kill all direct background children of this shell
    pkill -P $$ 2>/dev/null || true
    
    # Terminate the entire process group (including xargs and all workers)
    kill -TERM -$$ 2>/dev/null || true
    sleep 1
    kill -9 -$$ 2>/dev/null || true
    
    # Restore stdout
    exec 1>/dev/tty
    exit 1
  ' INT TERM

  log "Session output: $OUT"
  send_telegram "XSS ReflexionX v1.0.0 started -- Domain: ${DOMAIN}"

  # ══ 1 · URL Collection ═══════════════════════════════════
  if checkpoint_check url_collection; then
    log "[RESUME] Skipping URL Collection (already complete)"
  elif [[ -n "$DIRECT_URL" ]]; then
    set_phase "URL Collection (Direct URL)" 0
    log "Direct URL provided (-u). Bypassing crawling..."
    echo "$DIRECT_URL" > "$OUT/all_urls.txt"
    TOTAL_URLS=1
    checkpoint_done url_collection
  elif [[ -n "$DIRECT_LIST" ]]; then
    set_phase "URL Collection (Direct List)" 0
    log "Direct URL list provided (-l). Bypassing crawling..."
    cat "$DIRECT_LIST" > "$OUT/all_urls.txt"
    TOTAL_URLS=$(count_lines "$OUT/all_urls.txt")
    checkpoint_done url_collection
else
  bash "$SCRIPT_DIR/phases/phase_collect.sh" \
    --output-dir "$OUT" \
    --domain "$DOMAIN" \
    --threads "$THREADS" \
    ${PROXY:+--proxy "$PROXY"} \
    ${STEALTH:+--stealth} \
    ${COOKIE:+--cookie "$COOKIE"} \
    ${DIRECT_URL:+--direct-url "$DIRECT_URL"} \
    ${DIRECT_LIST:+--direct-list "$DIRECT_LIST"}
  checkpoint_done url_collection
  fi  # end bypass check for url_collection

  TOTAL_URLS=$(count_lines "$OUT/all_urls.txt")
  ai_analyze "post_collection"

  # ══ 2 · Pre-Filter & Live Filter ═════════════════════════
  if checkpoint_check live_filter; then
    log "[RESUME] Skipping Live Filter (already complete)"
  else

  # ── 2a · Smart URL Pre-filtering (context_manager.py) ────
  # Feeding 100k+ raw URLs to httpx causes WAF blocks and timeouts.
  # Pre-filter: remove static assets, deduplicate by endpoint signature.
  local HTTPX_INPUT="$OUT/all_urls.txt"

  if command -v python3 &>/dev/null && [[ -f "$SCRIPT_DIR/context_manager.py" ]]; then
    set_phase "Pre-filtering URLs" "$TOTAL_URLS"
    log "Pre-filtering URLs (removing static files, deduplicating endpoints)..."

    local filter_result
    local _ctx_cmd="python3 $SCRIPT_DIR/context_manager.py --mode filter_urls --input $OUT/all_urls.txt --output $OUT/filtered_urls.txt"
    debug_tool_start "python3/context_manager" "$_ctx_cmd"
    local _ctx_start; _ctx_start=$(date +%s)
    
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
      local filtered_count
      filtered_count=$(count_lines "$OUT/filtered_urls.txt")
      log "Pre-filtered: $TOTAL_URLS → $filtered_count unique endpoints ($filter_result)"
    else
      log "Pre-filter produced no output, using all URLs"
    fi
  else
    log "context_manager.py not available, using all URLs for httpx"
  fi

  local HTTPX_COUNT
  HTTPX_COUNT=$(count_lines "$HTTPX_INPUT")

  # ── 2b · httpx live probing (tuned) ──────────────────────
  # Tuned: concurrency control, rate limiting, timeout, wider status codes.
  # Accept 401/403 — these endpoints exist and may still reflect input.
  set_phase "Live Filtering (httpx)" "$HTTPX_COUNT"
  log "Filtering live URLs (httpx) — $HTTPX_COUNT URLs..."

  local httpx_concurrency=25
  local httpx_rate_limit=100
  local httpx_timeout=10
  local httpx_max_time=900  # 15 min hard cap

  if [[ $STEALTH -eq 1 ]]; then
    httpx_concurrency=3
    httpx_rate_limit=10
    httpx_timeout=15
    httpx_max_time=1200
  fi

  touch "$OUT/live.txt"
  local _hx_cmd="httpx -silent -mc 200,201,204,301,302,307,308,401,403 -l $HTTPX_INPUT -o $OUT/live.txt -c $httpx_concurrency (watchdog: ${httpx_max_time}s)"
  debug_tool_start "httpx" "$_hx_cmd"
  local _hx_start; _hx_start=$(date +%s)
  
  # Build httpx as bash array (no eval, no quoting issues)
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
  [[ -n "$COOKIE" ]] && httpx_arr+=(-H "Cookie: $COOKIE")
  
  # Run httpx with a watchdog to prevent indefinite hangs.
  # smart_timeout is not used here because it can interfere with
  # backgrounded streaming I/O; the watchdog enforces a hard ceiling.
  local _httpx_max_time=${httpx_max_time:-600}
  ("${httpx_arr[@]}" > /dev/null 2>>"$OUT/logs/errors.log") &
  HTTPX_PID=$!
  # Watchdog: kill httpx after _httpx_max_time seconds
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

  # ── 2c · Fallback: bypass httpx if WAF blocked everything ─
  # If httpx returns 0 but we have collected URLs, the target's WAF
  # is likely blocking httpx probes. Directly extract parameterized
  # URLs from the collected data — they existed at some point and
  # are worth scanning even without fresh liveness confirmation.
  if [[ $LIVE -eq 0 && $HTTPX_COUNT -gt 0 ]]; then
    log "WARN: httpx returned 0 live URLs — WAF likely blocking probes"
    log "Fallback: extracting parameterized URLs directly from collected data"
    state_set "phase" "Fallback: extracting parameterized URLs..."

    # Extract URLs with query parameters (the ones most likely to reflect)
    grep '[?]' "$HTTPX_INPUT" | grep '=' | sort -u > "$OUT/live.txt" 2>/dev/null || true
    LIVE=$(count_lines "$OUT/live.txt")

    if [[ $LIVE -eq 0 ]]; then
      # Even broader fallback: use all filtered URLs
      cp "$HTTPX_INPUT" "$OUT/live.txt"
      LIVE=$(count_lines "$OUT/live.txt")
      log "Broad fallback: using all $LIVE filtered URLs"
    else
      log "Fallback: extracted $LIVE parameterized URLs (skipping liveness check)"
    fi

    # Scope enforcement on fallback URLs
    enforce_scope "$OUT/live.txt" "Fallback live URLs"
    LIVE=$(count_lines "$OUT/live.txt")
  fi

  checkpoint_done live_filter
  fi  # end resume check for live_filter

  LIVE=$(count_lines "$OUT/live.txt")
  ai_analyze "post_live_filter"

  # ══ 3 · Param Extraction ═════════════════════════════════
  if checkpoint_check param_extraction; then
    log "[RESUME] Skipping Param Extraction (already complete)"
  else
  set_phase "Extracting Parameters" "$LIVE"
  log "Extracting parameterised URLs..."

  grep -E '\?[^=]*=' "$OUT/live.txt" | grep -vE '\.(jpg|jpeg|png|gif|svg|css|js|ico|woff|woff2|pdf|zip|gz|tar|map|swf|wasm)(\?|$)' | sort -u > "$OUT/params.txt"

  # Scope enforcement on parameterized URLs before reflection check
  enforce_scope "$OUT/params.txt" "Parameterized URLs"
  PARAMS=$(count_lines "$OUT/params.txt")
  state_set "phase_done" "$PARAMS"
  log "Parameterised URLs (in-scope): $PARAMS"

  if [[ $PARAMS -eq 0 ]]; then
    log "No parameterised URLs found. Skipping reflection check."
    touch "$OUT/reflected_urls.txt"
  else

    # ══ 4 · Reflection Check (curl-based, PARALLEL) ═══════════
    # kxss has been REPLACED with a pure curl-based checker because:
    #   - kxss (Go binary) ignores SIGTERM/SIGKILL when blocked in network I/O
    #   - Go's process model + bash pipelines = unkillable zombie processes
    #
    # This curl-based checker does EXACTLY what kxss does:
    #   1. Inject a unique canary into each parameter
    #   2. Fetch the URL with curl (hard 10s timeout — guaranteed by kernel)
    #   3. Check if canary appears in response body (= parameter is reflected)
    #   4. If reflected, test special chars: < > " ' (= XSS potential)
    #
    # v2.0.0: Now runs in PARALLEL using xargs -P (same pattern as dalfox dispatch)
    set_phase "Reflection Check" "$PARAMS"
    log "Running reflection check on $PARAMS parameterized URLs (${THREADS} threads)..."

    local _rc_cmd="curl-based reflection checker on $OUT/params.txt"
    debug_tool_start "reflection_check" "$_rc_cmd"
    local _rc_start; _rc_start=$(date +%s)

    > "$OUT/kxss_raw.txt"
    > "$OUT/reflected_urls.txt"

    # ── Parallel worker function ────────────────────────────
    check_reflection() {
      local url_file="$1"
      local _S="$2" _O="$3"

      local url
      url=$(cat "$url_file" 2>/dev/null) || return 1

      # Common browser headers for WAF evasion
      local _UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"

      state_inc "phase_done"

      # V1.2.0 FIX: Use date +%s only (portable, %N removed for WSL compat)
      # V1.2.0 FIX: Do NOT use eval — build curl command as array to prevent shell injection
      local canary="rxss${RANDOM}$(date +%s)"
      local test_url
      # V1.2.0 FIX: Replace parameter value after each '=' up to next '&' or end of querystring
      # Use awk for reliable per-parameter replacement (handles += special chars in URL)
      if [[ "$url" == *"?"* ]]; then
        local _base="${url%%\?*}"
        local _query="${url#*\?}"
        local _newq
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

      # V1.2.0 FIX: Build curl as array — no eval, no shell re-interpretation of URL
      local curl_args=( -sS --max-time 10
        -H "User-Agent: $_UA"
        -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        -H "Accept-Language: en-US,en;q=0.9"
        --compressed )
      [[ -n "$COOKIE" ]] && curl_args+=(-H "Cookie: $COOKIE")
      curl_args+=(-- "$test_url")

      local _curl_rc=0
      local body=""
      body=$(curl "${curl_args[@]}" 2>/dev/null)
      _curl_rc=$?

      # V1.2.0 FIX: Log curl failures instead of silently returning 0
      if [[ $_curl_rc -ne 0 ]]; then
        { flock 9; printf '%s\n' "CURL_ERR:$_curl_rc: $url" >> "$_O/tmp/curl_errors.log"; } 9>"$_S/error_w.lock" 2>/dev/null
        return 0
      fi

      # Step 2: Check if canary is reflected in response
      if echo "$body" | grep -qF "$canary"; then
        { flock 9; printf '%s\n' "$url" >> "$_O/reflected_urls.txt"; } 9>"$_S/reflect_w.lock"

        # Step 3: Test special characters for XSS potential
        local chars_reflected=""
        for char in '"' "'" '<' '>'; do
          local char_canary="rxpfx${char}rxsfx"
          local char_url
          if [[ "$url" == *"?"* ]]; then
            local _cbase="${url%%\?*}"
            local _cquery="${url#*\?}"
            local _newcq
            _newcq=$(printf '%s' "$_cquery" | sed "s|=[^&]*|=${char_canary}|g")
            char_url="${_cbase}?${_newcq}"
          else
            char_url="$url"
          fi
          local char_curl_args=( -sS --max-time 10
            -H "User-Agent: $_UA"
            --compressed )
          [[ -n "$COOKIE" ]] && char_curl_args+=(-H "Cookie: $COOKIE")
          char_curl_args+=(-- "$char_url")

          local char_body
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

    # ── Dispatch: write URLs to temp files, run in parallel ─
    local _rc_tmp="$OUT/tmp/urls_reflect"
    mkdir -p "$_rc_tmp"
    local _rc_i=0
    while IFS= read -r url; do
      local tf="$_rc_tmp/url_${_rc_i}.txt"
      printf '%s' "$url" > "$tf"
      printf '%s\0' "$tf"
      (( _rc_i++ ))
    done < "$OUT/params.txt" | \
  xargs -0 -P "$THREADS" -I{} \
    /bin/bash -c 'check_reflection '\$@'' _ \
      "{}" "$STATE" "$OUT"

    # V1.2.0 FIX: Wait for ALL parallel workers to finish before reading results

    # V1.2.0 FIX: Optionally wait for file to stabilize (workers may still be writing)
    local _before=0 _after=0 _stable=0
    for _i in $(seq 1 5); do
      _before=$(count_lines "$OUT/reflected_urls.txt")
      sleep 1
      _after=$(count_lines "$OUT/reflected_urls.txt")
      [[ "$_before" == "$_after" ]] && { _stable=1; break; }
    done
    [[ $_stable -eq 0 ]] && sleep 2  # last-ditch settle

    local _rc_reflected; _rc_reflected=$(count_lines "$OUT/reflected_urls.txt")
    local _rc_specials; _rc_specials=$(wc -l < "$OUT/kxss_raw.txt" 2>/dev/null || echo 0)
    local _rc_dur=$(( $(date +%s) - _rc_start ))
    debug_tool_end "reflection_check" "0" "$OUT/reflected_urls.txt" "$_rc_dur"

    log "Reflection check complete: $PARAMS checked, $_rc_reflected reflected, $_rc_specials with special chars (${_rc_dur}s)"

  fi  # end if PARAMS -eq 0

  checkpoint_done param_extraction
  fi  # end resume check for param_extraction

  # Reload counts from files (needed when phases are skipped on resume)
  PARAMS=$(count_lines "$OUT/params.txt")
  REFLECTED=$(count_lines "$OUT/reflected_urls.txt")
  REFLECTED=${REFLECTED:-0}
  log "Reflected URLs for scanning: $REFLECTED"

  # ══ 4.5 · Reflection Validation (Python) ═════════════════
  if checkpoint_check reflection_validation; then
    log "[RESUME] Skipping Reflection Validation (already complete)"
  elif [[ $REFLECTED -gt 0 ]] && command -v python3 &>/dev/null && \
     python3 -c 'import requests' 2>/dev/null; then
    set_phase "Reflection Validation (Python)" "$REFLECTED"
    log "Running deep reflection validation..."
    local validator_args=("$SCRIPT_DIR/xss_validator.py"
      --input "$OUT/reflected_urls.txt"
      --output-dir "$OUT"
      --threads "$THREADS")
    [[ -n "$PROXY" ]] && validator_args+=(--proxy "$PROXY")
    [[ $STEALTH -eq 1 ]] && validator_args+=(--stealth)
    [[ -n "$POST_DATA" ]] && validator_args+=(--post-data "$POST_DATA")
    [[ -n "$COOKIE" ]] && validator_args+=(--cookie "$COOKIE")
    
    debug_tool_start "python3/xss_validator" "python3 ${validator_args[*]}"
    local _val_start; _val_start=$(date +%s)
    
    python3 "${validator_args[@]}" \
      2>>"$OUT/logs/errors.log"
    local _val_exit=$?
    
    local _val_dur=$(( $(date +%s) - _val_start ))
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
  ai_analyze "pre_scan"

  # ══ 4.6 · DOM XSS Analysis ═══════════════════════════════
  if [[ "$DOM_SCAN" -eq 1 ]]; then
    grep -iE '\.js(\?|$)' "$OUT/tmp/katana.txt" > "$OUT/tmp/katana_js.txt" 2>/dev/null || true
    JS_COUNT=$(count_lines "$OUT/tmp/katana_js.txt")
    if [[ $JS_COUNT -gt 0 ]]; then
      set_phase "DOM XSS Analysis" "$JS_COUNT"
      log "Analyzing $JS_COUNT JavaScript files for DOM XSS..."
      local _dom_cmd="python3 $SCRIPT_DIR/dom_analyzer.py --js-urls $OUT/tmp/katana_js.txt --output-dir $OUT"
      debug_tool_start "python3/dom_analyzer" "$_dom_cmd"
      local _dom_start; _dom_start=$(date +%s)
      
      python3 "$SCRIPT_DIR/dom_analyzer.py" \
        --js-urls "$OUT/tmp/katana_js.txt" \
        --output-dir "$OUT" \
        --threads 5 \
        2>>"$OUT/logs/errors.log"
      local _dom_exit=$?
      
      local _dom_dur=$(( $(date +%s) - _dom_start ))
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
  fi

  # ── 4.7 · Fragment URL Generation for Fragment/DOM XSS (v2.1.0) ──
  # Generates URLs with payloads in the URL fragment (#) for browser validation.
  # Critical for Level 3 (unescape-based DOM XSS) and Level 6 (fragment-only).
  if [[ "$FRAGMENT_SCAN" -eq 1 ]] && command -v python3 &>/dev/null; then
    local frag_base_input
    if [[ -f "$OUT/all_urls.txt" && -s "$OUT/all_urls.txt" ]]; then
      frag_base_input="$OUT/all_urls.txt"
    elif [[ -f "$OUT/live.txt" && -s "$OUT/live.txt" ]]; then
      frag_base_input="$OUT/live.txt"
    else
      frag_base_input=""
    fi
    if [[ -n "$frag_base_input" ]]; then
      local frag_count
      frag_count=$(count_lines "$frag_base_input")
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

  # ══ 4.7 · Cross-Page Parameter Flow Tracking (v2.1.0) ═══════
  # Detect params that are safe on one page but dangerous on another
  # (e.g. Level 5: next= HTML-encoded on signup, raw JS on confirm)
  if [[ -f "$OUT/reflection_contexts.json" ]] && command -v python3 &>/dev/null; then
    set_phase "Cross-Page Flow Tracking" "reflection_contexts.json"
    log "Analyzing cross-page parameter flow..."
    python3 "$SCRIPT_DIR/cross_page_tracker.py" \
      --contexts "$OUT/reflection_contexts.json" \
      ${URLS_FILE:+--urls "$URLS_FILE"} \
      --output-dir "$OUT" \
      2>>"$OUT/logs/errors.log"
    if [[ -f "$OUT/cross_page_flows.json" ]]; then
      FLOW_COUNT=$(python3 -c "import json; d=json.load(open('$OUT/cross_page_flows.json')); print(len(d))" 2>/dev/null || echo 0)
      log "Cross-page flow issues found: $FLOW_COUNT"
    fi
  fi

  # ══ 4.8 · Stored XSS Chain Verification (v2.1.0) ═════════════
  # Handles POST → store → GET → verify execution (e.g. Level 2)
  if [[ -n "$POST_DATA" ]] && [[ -f "$POST_DATA" ]] && command -v python3 &>/dev/null; then
    set_phase "Stored XSS Chain Verification" "$POST_DATA"
    log "Running stored XSS chain verification (POST → GET → check)..."
    # Build verify URLs from reflected targets or live URLs
    local verify_input
    if [[ -f "$OUT/reflected_urls.txt" && -s "$OUT/reflected_urls.txt" ]]; then
      verify_input="$OUT/reflected_urls.txt"
    elif [[ -f "$OUT/live.txt" && -s "$OUT/live.txt" ]]; then
      verify_input="$OUT/live.txt"
    fi
    if [[ -n "$verify_input" ]]; then
      python3 "$SCRIPT_DIR/stored_xss_chain.py" \
        --post-data "$POST_DATA" \
        --verify-urls "$verify_input" \
        --output-dir "$OUT" \
        ${COOKIE:+--cookie "$COOKIE"} \
        2>>"$OUT/logs/errors.log"
      if [[ -f "$OUT/stored_xss_findings.json" ]]; then
        STORED_COUNT=$(python3 -c "import json; d=json.load(open('$OUT/stored_xss_findings.json')); print(len(d))" 2>/dev/null || echo 0)
        log "Stored XSS confirmations: $STORED_COUNT"
      fi
    fi
  fi

  # ══ 5 · Prioritise (Enhanced v1.0.0) ═════════════════════════
  # Use validated reflections if available, else fall back to kxss output.
  # CRITICAL FIX: If kxss found 0 reflections but we have parameterized
  # URLs, fall back to params.txt. dalfox can find XSS that kxss misses
  # (e.g., server-side reflection, delayed reflection, WAF bypass).
  local scoring_input="$OUT/reflected_urls.txt"
  [[ -f "$OUT/reflected_validated.txt" && -s "$OUT/reflected_validated.txt" ]] && \
    scoring_input="$OUT/reflected_validated.txt"

  if [[ ! -s "$scoring_input" ]]; then
    if [[ -f "$OUT/params.txt" && -s "$OUT/params.txt" ]]; then
      scoring_input="$OUT/params.txt"
      log "No reflected URLs from kxss — falling back to parameterized URLs for dalfox"
    elif [[ -f "$OUT/live.txt" && -s "$OUT/live.txt" ]]; then
      scoring_input="$OUT/live.txt"
      log "No parameterized URLs — falling back to all live URLs for dalfox"
    fi
  fi

  # Ensure coverage for DOM/Stored XSS on small targets (like XSS Game)
  if [[ -f "$OUT/live.txt" ]] && [[ $(count_lines "$OUT/live.txt") -lt 50 ]] && [[ $(count_lines "$OUT/live.txt") -gt 0 ]]; then
    scoring_input="$OUT/live.txt"
    log "Small target surface (< 50 live URLs), scanning all live URLs for maximum coverage"
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

  # Scope enforcement on final targets before scanning
  enforce_scope "$OUT/final_targets.txt" "Final scan targets"
  FINAL=$(count_lines "$OUT/final_targets.txt")
  log "Final targets after scoring: $FINAL"

  if [[ $FINAL -eq 0 && ${DOM_RISKS:-0} -eq 0 ]]; then
    log "No targets or DOM XSS risks to scan. Done."
    rm -f "$STATE/running"; kill "$DASH_PID" 2>/dev/null || true
    exit 0
  fi

  send_telegram "Summary — Collected: ${TOTAL_URLS} | Live: ${LIVE} | Params: ${PARAMS} | Reflected: ${REFLECTED} | Final: ${FINAL}"

  # ══ 6 · XSS Scan (dalfox) ════════════════════════════════
  if checkpoint_check xss_scan_dalfox; then
    log "[RESUME] Skipping XSS Scan (already complete)"
  else
  set_phase "XSS Scanning (dalfox)" "$FINAL"
  state_set "done" 0
  log "Parallel dalfox scan — $THREADS threads..."

  local dalfox_input="$OUT/final_targets.txt"
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
  fi  # end resume check for xss_scan_dalfox

  # ══ 7 · Retry Errors ═════════════════════════════════════
  # FIX: Don't read from errors.log (which contains random stderr output).
  # Instead read from failed_scans.txt populated by scan_url when dalfox fails.
  if [[ -f "$STATE/failed_scans.txt" && -s "$STATE/failed_scans.txt" ]]; then
    mapfile -t RETRY_URLS < <(sort -u "$STATE/failed_scans.txt")
    if [[ ${#RETRY_URLS[@]} -gt 0 ]]; then
      set_phase "Retrying Failed URLs" "${#RETRY_URLS[@]}"
      log "Retrying ${#RETRY_URLS[@]} failed URLs..."
      
      local retry_file="$OUT/tmp/retry_targets.txt"
      printf '%s\n' "${RETRY_URLS[@]}" > "$retry_file"
      
      # Clear the failed_scans file before retry
      rm -f "$STATE/failed_scans.txt"
      
      dispatch_scan "$retry_file"
    fi
  else
    log "No failed scans to retry."
  fi

  # ══ 7.8 · AI Agentic Loop ════════════════════════════════
  if checkpoint_check ai_agentic_loop; then
    log "[RESUME] Skipping AI Agentic Loop (already complete)"
  else
    ai_analyze "deep_exploit"
    checkpoint_done ai_agentic_loop
  fi

  # ══ 7.5 · Secondary Validation (XSStrike) ════════════════
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

  # ══ 7.6 · Nuclei XSS Template Scanning (v1.0.0) ═══════════
  if [[ $NUCLEI_SCAN -eq 1 ]] && command -v python3 &>/dev/null && \
     [[ -f "$SCRIPT_DIR/nuclei_scanner.py" ]]; then
    local nuclei_input="$OUT/live.txt"
    local NUCLEI_COUNT
    NUCLEI_COUNT=$(count_lines "$nuclei_input")
    if [[ $NUCLEI_COUNT -gt 0 ]]; then
      set_phase "Nuclei XSS Scanning" "$NUCLEI_COUNT"
      log "Running nuclei XSS templates on $NUCLEI_COUNT live URLs..."
      local nuclei_args=("$SCRIPT_DIR/nuclei_scanner.py"
        --urls "$nuclei_input"
        --output-dir "$OUT"
        --threads "$THREADS")
      [[ -n "$PROXY" ]] && nuclei_args+=(--proxy "$PROXY")
      [[ -n "$COOKIE" ]] && nuclei_args+=(--cookie "$COOKIE")
      
      python3 "${nuclei_args[@]}" 2>>"$OUT/logs/errors.log" || \
        log "WARN: Nuclei scanning failed (optional)"
    fi
  fi

  # ══ 7.7 · Hidden Parameter Mining (v1.0.0) ════════════════
  if [[ $PARAM_MINE -eq 1 ]] && command -v python3 &>/dev/null && \
     [[ -f "$SCRIPT_DIR/param_miner.py" ]]; then
    local mine_input="$OUT/live.txt"
    local MINE_COUNT
    MINE_COUNT=$(count_lines "$mine_input")
    if [[ $MINE_COUNT -gt 0 ]]; then
      # Limit to top 100 URLs for param mining (expensive operation)
      head -n 100 "$mine_input" > "$OUT/tmp/param_mine_targets.txt"
      local mine_actual
      mine_actual=$(count_lines "$OUT/tmp/param_mine_targets.txt")
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
      
      # Merge mined params into dalfox targets for rescanning
      if [[ -f "$OUT/mined_params.txt" && -s "$OUT/mined_params.txt" ]]; then
        local mined_count
        mined_count=$(count_lines "$OUT/mined_params.txt")
        log "Mined $mined_count new reflected parameters — rescanning with dalfox"
        if [[ $mined_count -gt 0 ]]; then
          set_phase "Scanning Mined Params (dalfox)" "$mined_count"
          dispatch_scan "$OUT/mined_params.txt"
        fi
      fi
    fi
  fi

  # ══ 8 · Browser Validation (Playwright) ══════════════════
  if checkpoint_check browser_validation; then
    log "[RESUME] Skipping Browser Validation (already complete)"
  elif [[ "$VALIDATE" -eq 1 ]]; then
    local browser_input="$OUT/high_priority_targets.txt"
    [[ ! -f "$browser_input" || ! -s "$browser_input" ]] && \
      browser_input="$OUT/final_targets.txt"
    local BROWSER_COUNT
    BROWSER_COUNT=$(count_lines "$browser_input")
    if [[ $BROWSER_COUNT -gt 0 ]]; then
      set_phase "Browser Validation (Playwright)" "$BROWSER_COUNT"
      log "Validating top targets with headless browser..."
      local browser_args=("$SCRIPT_DIR/xss_browser.py"
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
      [[ -n "$COOKIE" ]] && browser_args+=(--cookie "$COOKIE")
      [[ "$FRAGMENT_SCAN" -eq 1 && -f "$OUT/fragment_urls.txt" ]] && \
        browser_args+=(--fragment-urls "$OUT/fragment_urls.txt")
      debug_tool_start "python3/xss_browser" "python3 ${browser_args[*]}"
      local _bw_start; _bw_start=$(date +%s)
      
      python3 "${browser_args[@]}" \
        2>>"$OUT/logs/errors.log"
      local _bw_exit=$?
      
      local _bw_dur=$(( $(date +%s) - _bw_start ))
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

  # ══ 8.8 · POC Triage (v2.0.0) ══════════════════════════════
  if checkpoint_check poc_triage; then
    log "[RESUME] Skipping POC Triage (already complete)"
  elif command -v python3 &>/dev/null && [[ -f "$SCRIPT_DIR/poc_triage.py" ]]; then
    local POC_COUNT
    POC_COUNT=$(find "$OUT/poc" -maxdepth 1 -name '*.txt' ! -name 'poc.txt' 2>/dev/null | wc -l)
    if [[ $POC_COUNT -gt 0 ]]; then
      set_phase "POC Triage" "$POC_COUNT"
      log "Triaging $POC_COUNT POC files..."
      local _poc_cmd="python3 $SCRIPT_DIR/poc_triage.py --output-dir $OUT --poc-dir $OUT/poc"
      debug_tool_start "python3/poc_triage" "$_poc_cmd"
      local _poc_start; _poc_start=$(date +%s)
      
      python3 "$SCRIPT_DIR/poc_triage.py" \
        --output-dir "$OUT" \
        --poc-dir "$OUT/poc" \
        2>>"$OUT/logs/errors.log"
      local _poc_exit=$?
      
      local _poc_dur=$(( $(date +%s) - _poc_start ))
      debug_tool_end "python3/poc_triage" "$_poc_exit" "$OUT/triage_report.txt" "$_poc_dur"
      
      if [[ $_poc_exit -ne 0 ]]; then
        log "WARN: POC triage failed"
      fi
      checkpoint_done poc_triage
    fi
  fi

  # ══ 8.5 · Blind XSS Injection (v2.0.0) ═══════════════════
  if checkpoint_check blind_xss_injection; then
    log "[RESUME] Skipping Blind XSS Injection (already complete)"
  elif [[ -n "$BLIND_URL" ]] && command -v python3 &>/dev/null && \
     [[ -f "$SCRIPT_DIR/oob_handler.py" ]]; then
    local oob_input="$OUT/high_priority_targets.txt"
    [[ ! -f "$oob_input" || ! -s "$oob_input" ]] && oob_input="$OUT/final_targets.txt"
    local OOB_COUNT
    OOB_COUNT=$(count_lines "$oob_input")
    if [[ $OOB_COUNT -gt 0 ]]; then
      set_phase "Blind XSS Injection" "$OOB_COUNT"
      log "Injecting OOB callback payloads → $BLIND_URL"
      local _oob_cmd="python3 $SCRIPT_DIR/oob_handler.py --input $oob_input --output-dir $OUT --oob-url $BLIND_URL"
      debug_tool_start "python3/oob_handler" "$_oob_cmd"
      local _oob_start; _oob_start=$(date +%s)
      
      python3 "$SCRIPT_DIR/oob_handler.py" \
        --input "$oob_input" \
        --output-dir "$OUT" \
        --oob-url "$BLIND_URL" \
        --threads "$THREADS" \
        ${PROXY:+--proxy "$PROXY"} \
        2>>"$OUT/logs/errors.log"
      local _oob_exit=$?
      
      local _oob_dur=$(( $(date +%s) - _oob_start ))
      debug_tool_end "python3/oob_handler" "$_oob_exit" "$OUT/blind_xss.txt" "$_oob_dur"
      
      if [[ $_oob_exit -ne 0 ]]; then
        log "WARN: OOB injection failed"
      fi
      checkpoint_done blind_xss_injection
    fi
  fi

  # ══ 9 · Report Generation (v2.0.0) ═══════════════════════
  if command -v python3 &>/dev/null && [[ -f "$SCRIPT_DIR/report.py" ]]; then
    set_phase "Generating Report" 0
    log "Generating HTML report..."
    debug_tool_start "python3/report" "python3 $SCRIPT_DIR/report.py --output-dir $OUT"
    local _rep_start; _rep_start=$(date +%s)
    
    python3 "$SCRIPT_DIR/report.py" --output-dir "$OUT" \
      2>>"$OUT/logs/errors.log"
    local _rep_exit=$?
    
    local _rep_dur=$(( $(date +%s) - _rep_start ))
    debug_tool_end "python3/report" "$_rep_exit" "$OUT/report.html" "$_rep_dur"
    
    if [[ $_rep_exit -ne 0 ]]; then
      log "WARN: Report generation failed"
    fi
    if [[ -f "$OUT/report.html" ]]; then
      log "Report: $OUT/report.html"
    fi
    checkpoint_done report_generation
  fi
  
  ai_analyze "post_browser"

  # ══ Done ══════════════════════════════════════════════════
  rm -f "$STATE/running"
  wait "$DASH_PID" 2>/dev/null || true

  # Clean stray directories inside logs/ (tools may create them)
  cleanup_logs_dir

  # Restore stdout to terminal for the completion summary
  exec 1>/dev/tty

  FOUND=$(state_get "found")
  DONE_N=$(state_get "done")
  ERRORS_N=$(state_get "errors")
  TOTAL_TIME=$(( $(date +%s) - START_TIME ))
  local TIME_STR
  TIME_STR=$(fmt_time "$TOTAL_TIME")

  # v2.0.0 outputs
  local V_COUNT=0 DOM_COUNT=0 CONF_COUNT=0 EVT_COUNT=0 MAN_COUNT=0 XSS_HITS=0 TRIAGE_UNCONF=0
  [[ -f "$OUT/reflected_validated.txt" ]] && V_COUNT=$(count_lines "$OUT/reflected_validated.txt")
  [[ -f "$OUT/dom_risks.txt" ]]          && DOM_COUNT=$(grep -c '^URL:' "$OUT/dom_risks.txt" 2>/dev/null || echo 0)
  [[ -f "$OUT/confirmed_execution.txt" ]] && CONF_COUNT=$(count_lines "$OUT/confirmed_execution.txt")
  [[ -f "$OUT/event_triggered.txt" ]]    && EVT_COUNT=$(count_lines "$OUT/event_triggered.txt")
  [[ -f "$OUT/manual_review.txt" ]]      && MAN_COUNT=$(count_lines "$OUT/manual_review.txt")
  [[ -d "$OUT/poc/unconfirmed" ]]        && TRIAGE_UNCONF=$(find "$OUT/poc/unconfirmed" -name '*.txt' 2>/dev/null | wc -l)
  XSS_HITS=$(state_get "xsstrike_hits")

  local hbar; hbar=$(printf '%.0s=' $(seq 1 60))
  local sbar; sbar=$(printf '%.0s-' $(seq 1 60))

  echo ""
  echo "  ${BOLD}${GREEN}+${hbar}+${RESET}"
  echo "  ${BOLD}${GREEN}|     SCAN COMPLETE - XSS ReflexionX v1.0.0                |${RESET}"
  echo "  ${BOLD}${GREEN}+${hbar}+${RESET}"
  echo ""
  echo "  ${BOLD}${CYAN}  Target${RESET}           $DOMAIN"
  echo "  ${BOLD}${CYAN}  Duration${RESET}         $TIME_STR"
  echo ""
  echo "  ${BOLD}${GREEN}+${sbar}+${RESET}"
  echo "  ${BOLD}  PIPELINE METRICS${RESET}"
  echo "  ${BOLD}${GREEN}+${sbar}+${RESET}"
  echo ""
  printf '%s    %-20s : %s%s%s\n' '' "URLs Collected"  "$WHITE" "$TOTAL_URLS"  "$RESET"
  printf '%s    %-20s : %s%s%s\n' '' "Live (httpx)"    "$WHITE" "$LIVE"        "$RESET"
  printf '%s    %-20s : %s%s%s\n' '' "With Parameters" "$WHITE" "$PARAMS"      "$RESET"
  printf '%s    %-20s : %s%s%s\n' '' "Reflected"       "$WHITE" "$REFLECTED"   "$RESET"
  printf '%s    %-20s : %s%s%s\n' '' "Validated"       "$WHITE" "$V_COUNT"     "$RESET"
  printf '%s    %-20s : %s%s%s\n' '' "Scanned"         "$WHITE" "$DONE_N"      "$RESET"
  echo ""
  echo "  ${BOLD}${GREEN}+${sbar}+${RESET}"
  echo "  ${BOLD}  FINDINGS${RESET}"
  echo "  ${BOLD}${GREEN}+${sbar}+${RESET}"
  echo ""
  printf '%s    %-20s : %s%s%s%s\n' '' "XSS Found"      "$GREEN" "$BOLD" "$FOUND"          "$RESET"
  printf '%s    %-20s : %s%s%s\n'   '' "XSStrike Hits"  "$GREEN" "$XSS_HITS"            "$RESET"
  printf '%s    %-20s : %s%s%s%s\n' '' "Confirmed"      "$GREEN" "$BOLD" "$CONF_COUNT"     "$RESET"
  printf '%s    %-20s : %s%s%s\n'   '' "Event-Based"    "$CYAN"  "$EVT_COUNT"           "$RESET"
  printf '%s    %-20s : %s%s%s\n'   '' "Unconfirmed"    "$YELLOW" "$TRIAGE_UNCONF"      "$RESET"
  printf '%s    %-20s : %s%s%s\n'   '' "DOM Risks"      "$YELLOW" "$DOM_COUNT"          "$RESET"
  printf '%s    %-20s : %s%s%s\n'   '' "Manual Review"  "$YELLOW" "$MAN_COUNT"          "$RESET"
  printf '%s    %-20s : %s%s%s\n'   '' "Errors"         "$RED"    "$ERRORS_N"           "$RESET"
  echo ""
  echo "  ${BOLD}${GREEN}+${sbar}+${RESET}"
  echo "  ${BOLD}  OUTPUT FILES${RESET}"
  echo "  ${BOLD}${GREEN}+${sbar}+${RESET}"
  echo ""
  echo "    ${BOLD}Core:${RESET}"
  echo "      poc/poc.txt               dalfox-confirmed XSS URLs"
  echo "      poc/<hash>.txt            per-finding detail"
  echo "      dalfox.txt                full dalfox output"
  echo "      kxss_raw.txt              raw kxss output"
  echo "      reflected_urls.txt        clean reflected URLs"
  echo "      xsstrike_results.txt      XSStrike raw results"
  echo ""
  echo "    ${BOLD}Analysis (v2.0.0):${RESET}"
  echo "      reflected_validated.txt    Python-validated reflections"
  echo "      reflection_contexts.json   context + CSP classification"
  echo "      high_priority_targets.txt  scored + prioritized targets"
  echo "      confirmed_execution.txt    browser-confirmed XSS"
  echo "      event_triggered.txt        event-triggered XSS"
  echo "      dom_risks.txt              DOM XSS source→sink risks"
  echo "      manual_review.txt          needs manual inspection"
  echo "      report.html                HTML assessment report"
  echo "      triage_report.txt          POC false positive analysis"
  echo "      scan_log.jsonl             structured JSON event log"
  echo "      scan_state.json            checkpoint / resume state"
  echo "      blind_xss_hits.txt         OOB callback hits"
  echo ""
  echo "    ${DIM}Output: ${OUT}${RESET}"
  echo "    ${DIM}Log:    ${LOG}${RESET}"
  echo ""
  echo "  ${BOLD}${GREEN}+${hbar}+${RESET}"
  echo ""

  # Build Telegram summary with v2.0.0 data
  local tg_msg="Scan Complete — ${DOMAIN}"
  tg_msg+=" | XSS: ${FOUND} | Confirmed: ${CONF_COUNT}"
  tg_msg+=" | DOM Risks: ${DOM_COUNT} | Scanned: ${DONE_N}"
  tg_msg+=" | Time: ${TIME_STR}"
  send_telegram "$tg_msg"
  log "Done. XSS: $FOUND / $DONE_N scanned. Confirmed: $CONF_COUNT. DOM Risks: $DOM_COUNT. Time: $TIME_STR"
}

main
