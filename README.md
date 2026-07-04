<h1 align="center">
  ReflexionX
</h1>

<p align="center">
  <b>Autonomous XSS hunting framework for red teamers and bug bounty hunters.</b><br>
  AI-driven payload generation • Playwright browser validation • Multi-layer pipeline<br>
</p>

<p align="center">
<a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-MIT-red.svg"></a>
<a href="https://www.python.org/"><img src="https://img.shields.io/badge/python-3.8+-blue.svg"></a>
<img src="https://img.shields.io/badge/version-1.0.0-green.svg">
</p>

---

ReflexionX automates the hardest parts of XSS hunting — **finding reflected parameters, classifying injection contexts, generating context-aware payloads, and confirming execution in a real browser**. It chains together passive recon, active crawling, reflection analysis, multi-scanner exploitation, and headless browser validation into a single pipeline that runs unattended.

The AI layer (powered by OpenRouter, OpenAI, Anthropic, Gemini, Ollama, and others) analyzes your attack surface, generates custom bypass payloads based on the exact reflection context and CSP policy, runs an autonomous exploitation loop when standard scanners miss something, and produces client-ready reports.

## Why ReflexionX?

Most XSS scanners stop at "parameter is reflected." That's not a vulnerability — that's a starting point. ReflexionX goes further:

1. **Context classification** — Is the reflection in HTML body, an attribute, inside `<script>`, or in JSON? Each needs a different breakout strategy.
2. **CSP-aware payloads** — If `script-src` blocks inline scripts, don't waste time with `<script>` tags. Use event handlers instead.
3. **Browser confirmation** — A payload that renders in the response but doesn't execute is a false positive. Playwright confirms actual JS execution.
4. **Adaptive retry** — If `<img onerror>` didn't fire, mutate the payload: try `<svg onload>`, encoding bypass, case mutation, DOM clobbering.
5. **AI reasoning** — When pattern-matching fails, the LLM analyzes the context and crafts novel bypass payloads.
6. **Multi-provider LLM** — OpenAI, Anthropic, Gemini, OpenRouter, Ollama, LM Studio, vLLM, Together, Groq. Free models work.
7. **Auto form extraction** — Automatically detects POST forms and builds `post_targets.txt` for stored XSS testing. No manual file creation.
8. **Stored XSS chains** — POST payload → GET stored page → confirm execution. Automated end-to-end.
9. **Fragment injection** — URL fragment (`#`) payloads for DOM XSS (Level 3/6 of Google XSS Game).
10. **Cross-page flow tracking** — Detects params safe on page A but dangerous on page B (e.g., OAuth redirects, multi-step forms).
11. **WAF Evasion & Circuit Breaker** — Adaptive mutation chains, mXSS exploitation, polyglot payloads, rare event handlers, and mid-scan WAF detection circuit breaker.
12. **Hidden Param Mining** — Arjun-style brute-force discovery of 500+ common parameters and header injection testing.
13. **Nuclei Integration** — Template-based XSS detection with ProjectDiscovery’s nuclei scanner.
14. **CVSS 3.1 Scoring** — Professional reports with CVSS scores, risk charts, and remediation recommendations.

## Quick Start

```bash
git clone https://github.com/Nimesh-Nakum/ReflexionX.git
cd ReflexionX
chmod +x setup.sh reflexionx.sh
./setup.sh
```

```bash
# Basic scan
./reflexionx.sh -d target.com

# Full power: browser validation + DOM analysis + AI
./reflexionx.sh -d target.com -V -D -F --ai

# Stealth mode (slower, harder to detect)
./reflexionx.sh -d target.com -V -S

# Resume an interrupted scan
./reflexionx.sh -d target.com -R ./xss_target.com_20250520_143000/

# Auto-detect forms and test stored XSS (no manual post_targets.txt needed)
./reflexionx.sh -d target.com -V -A
```

## Requirements

- **Linux/macOS** with Bash 4+ (or WSL2 on Windows)
- **Go 1.21+** — for installing recon tools
- **Python 3.8+** — for validation engines
- **Playwright** — for browser validation (`playwright install chromium`)
- Optional: Any LLM API key (OpenRouter, OpenAI, Anthropic, Gemini, Ollama, etc.)

`setup.sh` handles everything: Go tools, Python packages, Playwright browser, and API key setup.

## How It Works

```
 ┌─────────────────────────────────────────────────────────────────────────┐
 │                     ReflexionX v1.0.0 Pipeline                         │
 ├─────────────────────────────────────────────────────────────────────────┤
 │                                                                         │
 │  Phase 1 · URL Collection ─── gau + waybackurls + katana               │
 │  Phase 2 · Pre-Filter ──────── context_manager.py (dedup + filter)     │
 │  Phase 3 · Live Filter ─────── httpx probe + WAF fallback              │
 │  Phase 4 · Validate ────────── curl canary + xss_validator.py          │
 │  Phase 5 · Analyse ─────────── dom_analyzer + cross_page_tracker       │
 │  Phase 6 · Prioritise ──────── score_url() → final_targets.txt         │
 │  Phase 7 · Scan ────────────── dalfox + XSStrike + nuclei + param mine │
 │  Phase 8 · AI Agent ────────── reflexion_agent.py (via ai_core.py)    │
 │  Phase 9 · Browser ─────────── Playwright + blind XSS + POC triage     │
 │  Phase 10 · Report ─────────── report.py + ai_report_generator.py      │
 │                                                                         │
 │  Shared modules: context_loader.py | ai_core.py | chain_synthesizer.py │
 └─────────────────────────────────────────────────────────────────────────┘
```

## Flags

```
Usage: ./reflexionx.sh -d <domain> [options]

Target:
  -d    Target domain (required)
  -u    Direct single URL to scan (bypasses crawling)
  -l    Direct list of URLs to scan (bypasses crawling)
  -t    Threads (default: 10)
  -p    HTTP proxy (e.g. http://127.0.0.1:8080)
  -c    Cookie header for authenticated scans (e.g. "session=123")

Scanning:
  -V    Enable Playwright browser validation
  -D    Enable DOM XSS analysis (AST + LLM semantic oracle)
  -F    Enable fragment/DOM injection for Level 3/6 DOM XSS
  -S    Stealth mode — reduced concurrency, request jitter
  -b    Blind XSS callback URL for OOB injection
  -P    POST data file for body parameter testing

Advanced:
  --nuclei        Run nuclei XSS templates against live URLs
  --param-mine    Brute-force hidden parameters (Arjun-style)

Auto Forms:
  -A    Auto-extract POST forms from crawled pages and build post_targets.txt
        No manual file creation needed. Uses katana/live URL output.

AI:
  --ai          Enable AI agentic decision loop (requires LLM API key)
  --model       OpenRouter or provider model (default: meta-llama/llama-4-maverick)
  --ai-depth    conservative (default) or aggressive
  --scope       Scope file — one domain per line

Resume:
  -R    Resume from previous output directory

Notifications:
  -T    Telegram bot token
  -C    Telegram chat ID
```

## Usage Examples

```bash
# Scan with browser validation and AI payload generation
./reflexionx.sh -d example.com -V --ai

# Full coverage: DOM analysis + fragment injection + AI
./reflexionx.sh -d example.com -V -D -F --ai

# Stealth scan through Burp proxy
./reflexionx.sh -d example.com -V -S -p http://127.0.0.1:8080

# Blind XSS with OOB callback
./reflexionx.sh -d example.com -b https://your-xss-hunter.com/probe

# POST parameter testing (manual post_targets.txt)
./reflexionx.sh -d example.com -V -P post_targets.txt

# Auto-detect and test stored XSS (no manual post_targets.txt needed)
./reflexionx.sh -d example.com -V -A

# AI with aggressive depth and specific model
./reflexionx.sh -d example.com -V -D -F --ai --ai-depth aggressive --model google/gemini-2.5-flash:free

# Restrict scope to specific subdomains
echo -e "app.example.com\napi.example.com" > scope.txt
./reflexionx.sh -d example.com --scope scope.txt

# Scan Google XSS Game (all 6 levels)
./reflexionx.sh -d xss-game.appspot.com -V -D -F -A
```

### POST data format (if manual)

```
https://target.com/form-endpoint	param1=<PAYLOAD_PLACEHOLDER>&param2=default	application/x-www-form-urlencoded
```

`<PAYLOAD_PLACEHOLDER>` is automatically replaced with the actual XSS payload during scanning.

### Auto form extraction

```bash
# Extract forms from katana output
python3 form_extractor.py --katana katana.txt --output post_targets.txt

# Extract forms from live URLs
python3 form_extractor.py --live live.txt --output post_targets.txt

# With session cookie
python3 form_extractor.py --katana katana.txt --cookie "session=abc123" --output post_targets.txt
```

### Using individual Python modules

```bash
# Validate reflections and classify contexts
python3 xss_validator.py --input urls.txt --output-dir ./out --threads 10

# Browser-confirm XSS with event simulation
python3 xss_browser.py --input targets.txt --output-dir ./out --retry

# Analyze JS files for DOM XSS (source→sink flows)
python3 dom_analyzer.py --js-urls js_files.txt --output-dir ./out

# Cross-page parameter flow tracking
python3 cross_page_tracker.py --contexts reflection_contexts.json --urls all_urls.txt --output-dir ./out

# Stored XSS chain verification
python3 stored_xss_chain.py --post-data post_targets.txt --verify-urls reflected_urls.txt --output-dir ./out

# Fragment injection for DOM XSS
python3 fragment_injector.py --base-urls urls.txt --output-dir ./out --encode-fn unescape

# Chain synthesis engine
python3 chain_synthesizer.py --contexts reflection_contexts.json --urls all_urls.txt --output-dir ./out

# AI agent (autonomous exploitation loop)
python3 reflexion_agent.py --target example.com --output-dir ./out --phase post_collection

# Generate HTML report
python3 report.py --output-dir ./xss_target.com_20250520/
python3 ai_report_generator.py --output-dir ./xss_target.com_20250520/

# Python orchestrator (alternative entry point)
python3 orchestrator.py -d target.com -V -D --stealth
```

## AI Configuration

Set these environment variables to enable AI features:

```bash
# OpenRouter (recommended — supports 100+ models including free ones)
export REFLEXIONX_LLM_PROVIDER="openrouter"
export REFLEXIONX_LLM_API_KEY="sk-or-..."
export REFLEXIONX_LLM_MODEL="meta-llama/llama-4-maverick"  # or any free model

# OpenAI
export REFLEXIONX_LLM_PROVIDER="openai"
export REFLEXIONX_LLM_API_KEY="sk-..."

# Anthropic (Claude)
export REFLEXIONX_LLM_PROVIDER="anthropic"
export REFLEXIONX_LLM_API_KEY="sk-ant-..."

# Google (Gemini)
export REFLEXIONX_LLM_PROVIDER="gemini"
export REFLEXIONX_LLM_API_KEY="..."

# Local models (Ollama, LM Studio, vLLM)
export REFLEXIONX_LLM_PROVIDER="ollama"
export REFLEXIONX_LLM_MODEL="llama3"
# No API key needed for local models
```

Free models that work well:
- `meta-llama/llama-4-maverick` (OpenRouter)
- `google/gemini-2.5-flash:free` (OpenRouter)
- `nvidia/nemotron-3-super-120b-a12b:free` (OpenRouter, default)
- `llama3` (Ollama, local)

## Output

After a scan, the output directory contains:

| File | What it is |
|------|------------|
| `poc/poc.txt` | Confirmed XSS URLs |
| `poc/<hash>.txt` | Per-finding detail + payload |
| `confirmed_execution.txt` | Browser-confirmed XSS (Playwright) |
| `event_triggered.txt` | XSS triggered by user events (click, hover, focus) |
| `reflection_contexts.json` | Per-URL context classification + CSP analysis |
| `high_priority_targets.txt` | Scored targets ordered by exploitability |
| `dom_risks.txt` | DOM XSS source→sink analysis |
| `js_semantic_flows.txt` | LLM-enhanced DOM XSS analysis |
| `cross_page_flows.json` | Cross-page parameter flow anomalies |
| `xss_chains.json` | Multi-step exploit chains |
| `stored_xss_findings.json` | Stored XSS chain confirmations |
| `fragment_urls.txt` | Fragment injection URLs for DOM XSS |
| `waf_analysis.json` | WAF fingerprint + bypass payloads |
| `manual_review.txt` | Encoded reflections needing manual inspection |
| `triage_report.txt` | False positive analysis |
| `ai_triage_results.json` | AI-powered FP/TP classification |
| `report.html` | Self-contained HTML assessment report |
| `report.json` | Machine-readable JSON report |
| `scan_state.json` | Checkpoint state for resume |
| `post_targets.txt` | Auto-extracted POST forms (with -A flag) |

## Architecture

```
reflexionx.sh               Main pipeline (bash, phase-dispatched)
├── phases/                  Explicit phase modules (bash)
│   ├── common.sh            Shared functions: logging, state, scoring, dashboard
│   ├── phase_collect.sh     URL collection (gau + waybackurls + katana)
│   ├── phase_filter.sh      Pre-filter + live filter (httpx)
│   ├── phase_validate.sh    Reflection check + xss_validator.py
│   ├── phase_analysis.sh    DOM XSS + fragment + cross-page + stored chain
│   ├── phase_prioritize.sh  URL scoring + final_targets.txt
│   ├── phase_scan.sh        dalfox + XSStrike + nuclei + param mining
│   ├── phase_ai.sh          AI agentic loop (reflexion_agent.py)
│   ├── phase_browser.sh     Playwright validation + blind XSS + POC triage
│   └── phase_report.sh      HTML/JSON report generation
├── context_loader.py        Single source of truth for reflection_contexts.json
├── context_manager.py       URL dedup + smart filtering
├── xss_validator.py         Reflection validation + context classification
├── dom_analyzer.py          AST-based DOM XSS detection
├── cross_page_tracker.py    Cross-page parameter flow tracking
├── chain_synthesizer.py     Multi-step exploit chain detection + LLM
├── stored_xss_chain.py      POST → GET → confirm stored XSS
├── fragment_injector.py     URL fragment payload injection for DOM XSS
├── xss_browser.py           Playwright browser validation
├── oob_handler.py           Blind/OOB XSS injection + listener
├── poc_triage.py            False positive elimination
├── ai_core.py               Unified LLM client (9 providers, single abstraction)
├── reflexion_agent.py       Phase-aware AI agent (uses ai_core.py)
├── ai_report_generator.py   Professional HTML/JSON report generation
├── report.py                HTML report generation
├── checkpoint.py            Scan state persistence for resume
├── orchestrator.py          Python alternative entry point
└── setup.sh                 Dependency installer
```

## AI Modules

| Module | What it does |
|--------|--------------|
| `ai_core.py` | Unified LLM client — single abstraction for OpenAI, Anthropic, Gemini, OpenRouter, Ollama, LM Studio, vLLM, Together, Groq |
| `reflexion_agent.py` | Phase-aware AI agent driven through ai_core.py; handles post_collection, pre_scan, deep_exploit, post_browser |
| `ai_report_generator.py` | Professional dark-themed HTML reports + AI exploitation narrative |
| `chain_synthesizer.py` | Multi-step exploit chain detection + LLM validation via ai_core |


## Testing Against Vulnerable Apps

### Google XSS Game
```bash
# All 6 levels covered
./reflexionx.sh -d xss-game.appspot.com -V -D -F -A
```

### DVWA (recommended for beginners)
```bash
docker run -d -p 8080:80 vulnerables/web-dvwa
# Login: admin/password → Security Level: Low
# Test: http://localhost:8080/vulnerabilities/xss_r/?name=test
```

### PortSwigger Web Security Academy
```bash
# ReflexionX auto-detects lab domains and skips passive recon
./reflexionx.sh -d <lab-id>.web-security-academy.net -V -D --ai
```

### Manual POST data format
```
POST https://target.com/api/search
Content-Type: application/x-www-form-urlencoded
q=test&page=1
---
POST https://target.com/api/data
Content-Type: application/json
{"query":"test","limit":10}
---
```

## Contributing

PRs welcome. The codebase is modular — each Python file is a self-contained module with its own `--test` flag for self-testing.

```bash
# Run module self-tests
python3 xss_validator.py --test
python3 xss_browser.py --test
python3 dom_analyzer.py --test
python3 cross_page_tracker.py --test
python3 chain_synthesizer.py --test
python3 stored_xss_chain.py --test
python3 fragment_injector.py --test
python3 reflexion_agent.py --test
python3 ai_core.py --test
python3 ai_report_generator.py --test
python3 poc_triage.py --test
python3 report.py --test
python3 orchestrator.py --test
```

## Roadmap

- [x] **v1.0.0 (Current)** — Phase-module pipeline, shared context_loader.py, unified ai_core.py LLM abstraction, contract-first architecture
- [ ] **v1.1.0** — Full phase dispatch for all phases in reflexionx.sh, expanded AI tool use
- [ ] **v2.0.0** — Distributed scanning, real-time collaboration, Slack/Discord webhooks

## Legal

This tool is for **authorized penetration testing and bug bounty programs only**. You are responsible for complying with applicable laws. The author is not liable for misuse.

## Credits

Built by [Nimesh Nakum](https://github.com/Nimesh-Nakum)

Uses: [dalfox](https://github.com/hahwul/dalfox) · [gau](https://github.com/lc/gau) · [waybackurls](https://github.com/tomnomnom/waybackurls) · [katana](https://github.com/projectdiscovery/katana) · [httpx](https://github.com/projectdiscovery/httpx) · [Playwright](https://playwright.dev/) · [OpenRouter](https://openrouter.ai/) · [Anthropic](https://anthropic.com/) · [OpenAI](https://openai.com/) · [Google AI](https://ai.google.dev/)

## License

MIT — see [LICENSE.md](LICENSE.md)
