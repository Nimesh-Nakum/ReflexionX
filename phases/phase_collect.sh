#!/bin/bash
# =============================================================
#  phases/phase_collect.sh — URL Collection
#  Sources: gau, waybackurls, katana
#  Usage: bash phases/phase_collect.sh --output-dir <out> --domain <d> [options]
# =============================================================
set -euo pipefail

# ── Args ──────────────────────────────────────────────────────
OUTPUT_DIR=""
DOMAIN=""
THREADS=10
PROXY=""
DIRECT_URL=""
DIRECT_LIST=""
STEALTH=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir)  OUTPUT_DIR="$2"; shift 2 ;;
    --domain)      DOMAIN="$2";     shift 2 ;;
    --threads)     THREADS="$2";    shift 2 ;;
    --proxy)       PROXY="$2";      shift 2 ;;
    --direct-url)  DIRECT_URL="$2"; shift 2 ;;
    --direct-list) DIRECT_LIST="$2"; shift 2 ;;
    --stealth)     STEALTH=1; shift ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

if [[ -z "$OUTPUT_DIR" ]]; then
  echo "Usage: $0 --output-dir <dir> --domain <domain> [--threads N] [--proxy URL] [--direct-url URL] [--direct-list FILE] [--stealth]"
  exit 1
fi

if [[ -z "$DOMAIN" ]]; then
  if [[ -n "$DIRECT_URL" ]]; then
    DOMAIN=$(echo "$DIRECT_URL" | awk -F/ '{print $3}')
  elif [[ -n "$DIRECT_LIST" ]]; then
    DOMAIN=$(head -n 1 "$DIRECT_LIST" | awk -F/ '{print $3}')
  else
    echo "Error: --domain, --direct-url, or --direct-list required"
    exit 1
  fi
fi

# ── Initialize output (BEFORE sourcing common.sh so log() works) ──
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
check_deps

main() {
# ── Scope ─────────────────────────────────────────────────────
SCOPE_DOMAINS=("$DOMAIN")
log "Scope: ${SCOPE_DOMAINS[*]}"

if [[ $STEALTH -eq 1 ]]; then
  [[ $THREADS -gt 3 ]] && THREADS=3
fi

# ── Phase: URL Collection ─────────────────────────────────────
if [[ -n "$DIRECT_URL" ]]; then
  set_phase "URL Collection (Direct URL)" 0
  log "Direct URL provided. Bypassing crawling..."
  echo "$DIRECT_URL" > "$OUT/all_urls.txt"
  checkpoint_done url_collection
elif [[ -n "$DIRECT_LIST" ]]; then
  set_phase "URL Collection (Direct List)" 0
  log "Direct URL list provided. Bypassing crawling..."
  cat "$DIRECT_LIST" > "$OUT/all_urls.txt"
  checkpoint_done url_collection
else
  set_phase "URL Collection (gau + wayback + katana)" 0

  count_collected() {
    local total=0 c=0
    [[ -f "$OUT/tmp/gau.txt" ]] && { c=$(wc -l < "$OUT/tmp/gau.txt" 2>/dev/null | tr -d ' '); total=$((total + c)); }
    [[ -f "$OUT/tmp/wayback.txt" ]] && { c=$(wc -l < "$OUT/tmp/wayback.txt" 2>/dev/null | tr -d ' '); total=$((total + c)); }
    [[ -f "$OUT/tmp/katana.txt" ]] && { c=$(wc -l < "$OUT/tmp/katana.txt" 2>/dev/null | tr -d ' '); total=$((total + c)); }
    echo "$total"
  }

  local is_ephemeral=0
  if [[ "$DOMAIN" =~ ^[a-f0-9]{32}\. ]] || \
     [[ "$DOMAIN" == *"web-security-academy.net"* ]] || \
     [[ "$DOMAIN" == *"burpcollaborator"* ]]; then
    is_ephemeral=1
    debug "Detected ephemeral/lab domain — skipping passive URL collection"
    log "Detected lab domain — skipping gau/waybackurls"
  fi

  local base_domain="${DOMAIN#www.}"

  if [[ $is_ephemeral -eq 0 ]]; then
    log "Running gau (providers: commoncrawl,otx,urlscan)..."
    touch "$OUT/tmp/gau.txt"
    local _gau_args="--verbose --providers commoncrawl,otx,urlscan --threads 5 --timeout 30"
    [[ "$DOMAIN" == *"www."* ]] && _gau_args="$_gau_args --subs"
    local _gau_cmd="stdbuf -oL timeout 120 gau $_gau_args \"$DOMAIN\""
    debug_tool_start "gau" "$_gau_cmd"
    local _gau_start; _gau_start=$(date +%s)
    stdbuf -oL timeout 120 gau $_gau_args "$DOMAIN" \
      >> "$OUT/tmp/gau.txt" 2>>"$OUT/logs/gau_debug.log" &
    GAU_PID=$!

    log "Running waybackurls..."
    touch "$OUT/tmp/wayback.txt"
    local _wb_cmd="stdbuf -oL timeout 180 waybackurls \"$DOMAIN\""
    debug_tool_start "waybackurls" "$_wb_cmd"
    local _wb_start; _wb_start=$(date +%s)
    stdbuf -oL timeout 180 waybackurls "$DOMAIN" \
      >> "$OUT/tmp/wayback.txt" 2>>"$OUT/logs/errors.log" &
    WB_PID=$!

    while kill -0 $GAU_PID 2>/dev/null || kill -0 $WB_PID 2>/dev/null; do
      local total_c; total_c=$(count_collected)
      state_set "phase_done" "$total_c"
      local gau_c=0 wb_c=0
      [[ -f "$OUT/tmp/gau.txt" ]] && gau_c=$(wc -l < "$OUT/tmp/gau.txt" 2>/dev/null | tr -d ' ')
      [[ -f "$OUT/tmp/wayback.txt" ]] && wb_c=$(wc -l < "$OUT/tmp/wayback.txt" 2>/dev/null | tr -d ' ')
      state_set "phase" "Collecting URLs: gau(${gau_c}) wayback(${wb_c}) = ${total_c}"
      sleep 2
    done
    wait $GAU_PID 2>/dev/null; local _gau_exit=$?
    wait $WB_PID 2>/dev/null; local _wb_exit=$?
    local _gau_dur=$(( $(date +%s) - _gau_start ))
    local _wb_dur=$(( $(date +%s) - _wb_start ))
    debug_tool_end "gau" "$_gau_exit" "$OUT/tmp/gau.txt" "$_gau_dur"
    debug_tool_end "waybackurls" "$_wb_exit" "$OUT/tmp/wayback.txt" "$_wb_dur"
  else
    touch "$OUT/tmp/gau.txt" "$OUT/tmp/wayback.txt"
  fi

  # ── gau provider fallback ───────────────────────────────────
  if [[ $is_ephemeral -eq 0 ]]; then
    local gau_count; gau_count=$(count_lines "$OUT/tmp/gau.txt")
    if [[ $gau_count -eq 0 ]]; then
      log "gau returned 0 URLs — providers likely blocking this IP"
      if [[ -f "$OUT/logs/gau_debug.log" && -s "$OUT/logs/gau_debug.log" ]]; then
        log "gau debug output: $(tail -5 "$OUT/logs/gau_debug.log")"
      fi
      local gau_target="${base_domain:-$DOMAIN}"
      [[ "${base_domain:-}" != "$DOMAIN" ]] && gau_target="$base_domain"
      for provider in otx urlscan commoncrawl; do
        state_set "phase" "gau fallback: trying $provider..."
        log "gau fallback: trying provider=$provider domain=$gau_target..."
        stdbuf -oL timeout 60 gau --providers "$provider" --timeout 30 \
          "$gau_target" >> "$OUT/tmp/gau.txt" 2>>"$OUT/logs/gau_debug.log" || true
        local pc; pc=$(count_lines "$OUT/tmp/gau.txt")
        if [[ $pc -gt 0 ]]; then
          log "gau provider=$provider returned $pc URLs"
          break
        fi
      done
    fi

    # ── Direct API fallbacks ──────────────────────────────────
    gau_count=$(count_lines "$OUT/tmp/gau.txt")
    local wb_count; wb_count=$(count_lines "$OUT/tmp/wayback.txt")
    local total_passive=$((gau_count + wb_count))

    if [[ $total_passive -eq 0 ]] && command -v curl &>/dev/null; then
      log "All passive collectors returned 0 — trying direct API calls..."
      state_set "phase" "Fallback: Wayback CDX API..."
      log "Trying Wayback CDX API directly..."
      curl -sS --max-time 90 -A "Mozilla/5.0 (compatible; ReflexionX/2.0)" \
        "https://web.archive.org/cdx/search/cdx?url=*.${DOMAIN}/*&output=text&fl=original&collapse=urlkey&limit=10000" \
        2>>"$OUT/logs/errors.log" \
        | grep -E '^https?://' | sort -u >> "$OUT/tmp/wayback.txt" || true
      if [[ -n "${base_domain:-}" && "$base_domain" != "$DOMAIN" ]]; then
        curl -sS --max-time 90 -A "Mozilla/5.0 (compatible; ReflexionX/2.0)" \
          "https://web.archive.org/cdx/search/cdx?url=*.${base_domain}/*&output=text&fl=original&collapse=urlkey&limit=10000" \
          2>>"$OUT/logs/errors.log" \
          | grep -E '^https?://' | sort -u >> "$OUT/tmp/wayback.txt" || true
      fi
      state_set "phase" "Fallback: OTX API..."
      log "Trying OTX AlienVault API directly..."
      local otx_domain="${base_domain:-$DOMAIN}"
      local otx_page=1
      while [[ $otx_page -le 5 ]]; do
        local otx_result
        otx_result=$(curl -sS --max-time 30 -A "Mozilla/5.0" \
          "https://otx.alienvault.com/api/v1/indicators/domain/${otx_domain}/url_list?limit=200&page=${otx_page}" \
          2>>"$OUT/logs/errors.log") || break
        echo "$otx_result" | grep -oP '"url":\s*"\K[^"]+' >> "$OUT/tmp/gau.txt" 2>/dev/null || true
        local has_next
        has_next=$(echo "$otx_result" | grep -c '"has_next": true' 2>/dev/null) || has_next=0
        [[ "$has_next" -eq 0 ]] && break
        ((otx_page++))
      done
    fi
  fi

  gau_count=$(count_lines "$OUT/tmp/gau.txt")
  wb_count=$(count_lines "$OUT/tmp/wayback.txt")
  log "gau done: $gau_count URLs"
  log "waybackurls done: $wb_count URLs"
  log "Total passive collection: $((gau_count + wb_count)) URLs"

  # ── Katana deep crawl ───────────────────────────────────────
  grep -oE '^https?://[^/?#]+' "$OUT/tmp/gau.txt" "$OUT/tmp/wayback.txt" 2>/dev/null | sort -u > "$OUT/tmp/passive_domains.txt" || true
  echo "http://$DOMAIN" >> "$OUT/tmp/passive_domains.txt"
  echo "https://$DOMAIN" >> "$OUT/tmp/passive_domains.txt"
  sort -u -o "$OUT/tmp/passive_domains.txt" "$OUT/tmp/passive_domains.txt"
  local domain_count; domain_count=$(count_lines "$OUT/tmp/passive_domains.txt")

  state_set "phase" "Deep Crawl (katana)..."
  log "Running katana (deep crawl) on $domain_count unique domains..."
  debug_tool_start "katana" "katana -list $OUT/tmp/passive_domains.txt ..."
  local _kat_start; _kat_start=$(date +%s)
  local katana_concurrency=10
  local katana_rate_limit=100
  local katana_delay=0
  local katana_max_time=600
  if [[ $STEALTH -eq 1 ]]; then
    katana_concurrency=2
    katana_rate_limit=10
    katana_delay=1
    katana_max_time=900
  fi
  local katana_arr=(
    katana
    -list "$OUT/tmp/passive_domains.txt"
    -d 5 -jc -kf all
    -o "$OUT/tmp/katana.txt"
    -c "$katana_concurrency"
    -rl "$katana_rate_limit"
    -rd "$katana_delay"
    -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
    -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    -H "Accept-Language: en-US,en;q=0.9"
  )
  [[ -n "${COOKIE:-}" ]] && katana_arr+=(-H "Cookie: $COOKIE")
  GOTRACEBACK=none smart_timeout "$katana_max_time" "${katana_arr[@]}" \
    > /dev/null 2>>"$OUT/logs/errors.log" &
  KATANA_PID=$!
  while kill -0 $KATANA_PID 2>/dev/null; do
    local total_c; total_c=$(count_collected)
    state_set "phase_done" "$total_c"
    local kat_c=0
    [[ -f "$OUT/tmp/katana.txt" ]] && kat_c=$(wc -l < "$OUT/tmp/katana.txt" 2>/dev/null | tr -d ' ')
    state_set "phase" "Deep Crawl (katana): ${kat_c} new, ${total_c} total"
    sleep 2
  done
  wait $KATANA_PID 2>/dev/null; local _kat_exit=$?
  local _kat_dur=$(( $(date +%s) - _kat_start ))
  debug_tool_end "katana" "$_kat_exit" "$OUT/tmp/katana.txt" "$_kat_dur"
  log "katana done: $(count_lines "$OUT/tmp/katana.txt") URLs"
  if [[ -f "$OUT/tmp/katana.txt" && -s "$OUT/tmp/katana.txt" ]]; then
    grep -oE '^https?://[^ ]+' "$OUT/tmp/katana.txt" | sort -u > "$OUT/tmp/katana_clean.txt" 2>/dev/null || true
    if [[ -s "$OUT/tmp/katana_clean.txt" ]]; then
      mv "$OUT/tmp/katana_clean.txt" "$OUT/tmp/katana.txt"
    else
      rm -f "$OUT/tmp/katana_clean.txt"
    fi
  fi

  # ── Merge & dedup ───────────────────────────────────────────
  state_set "phase" "Merging & deduplicating..."
  log "Merging & deduplicating..."
  local _merge_tmp="$OUT/tmp/merged_sorted.txt"
  cat "$OUT/tmp/gau.txt" "$OUT/tmp/wayback.txt" "$OUT/tmp/katana.txt" 2>/dev/null \
    | sort -u > "$_merge_tmp"
  if command -v uro &>/dev/null && [[ -s "$_merge_tmp" ]]; then
    uro < "$_merge_tmp" > "$OUT/all_urls.txt" 2>>"$OUT/logs/errors.log" \
      || cp "$_merge_tmp" "$OUT/all_urls.txt"
  else
    cp "$_merge_tmp" "$OUT/all_urls.txt"
  fi
  rm -f "$_merge_tmp"

  local TOTAL_URLS; TOTAL_URLS=$(count_lines "$OUT/all_urls.txt")
  log "Total unique URLs (before scope): $TOTAL_URLS"
  enforce_scope "$OUT/all_urls.txt" "Collected URLs"
  TOTAL_URLS=$(count_lines "$OUT/all_urls.txt")
  log "Total in-scope URLs: $TOTAL_URLS"
  if [[ $TOTAL_URLS -eq 0 ]]; then
    echo "ERROR: No URLs collected, or all URLs were removed by scope enforcer." >> "$OUT/logs/errors.log"
    log "ERROR: No URLs collected."
    exit 1
  fi
  checkpoint_done url_collection
fi

echo "Phase collection complete: $(count_lines "$OUT/all_urls.txt") URLs in $OUT/all_urls.txt"
}

main "$@"
