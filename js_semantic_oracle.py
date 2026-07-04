#!/usr/bin/env python3
"""
XSS ReflexionX v1.0.0 — JS Semantic Oracle
LLM-powered DOM XSS source→sink analysis that supersedes regex-based detection.

Unlike dom_analyzer.py which uses regex/AST, this module uses an LLM to:
  - Understand minified JS variable flows across scope boundaries
  - Identify indirect taint (var a = hash; var b = a; sink(b))
  - Recognize framework-specific sinks (React dangerouslySetInnerHTML, Vue v-html, etc.)
  - Assess sanitizer limitations (DOMPurify configs, custom sanitizers)
  - Provide concrete bypass payloads for each identified flow

Usage:
    python3 js_semantic_oracle.py --js-file script.js --base-url http://target.com
    python3 js_semantic_oracle.py --js-urls katana_js.txt --output-dir output/
"""

import argparse, hashlib, json, os, re, sys, time
from pathlib import Path

try:
    from ai_core import get_llm_client, SYSTEM_PROMPTS, LLMClient
    HAS_AI = True
except ImportError:
    HAS_AI = False

try:
    from dom_analyzer import analyze_js, ASTFlowAnalyzer, regex_analyze
    HAS_DOM = True
except ImportError:
    HAS_DOM = False

CACHE_DIR = ".ai_js_cache"
MAX_JS_BYTES = 50000  # truncate large files for LLM context


def _cache_key(js_src, url):
    h = hashlib.sha256(f"{url}:{js_src[:5000]}".encode()).hexdigest()[:16]
    return h


def _get_cached(key):
    os.makedirs(CACHE_DIR, exist_ok=True)
    fpath = os.path.join(CACHE_DIR, f"{key}.json")
    if os.path.isfile(fpath):
        try:
            with open(fpath) as f:
                data = json.load(f)
            if time.time() - data.get("ts", 0) < 86400:
                return data.get("flows", [])
        except Exception:
            pass
    return None


def _set_cached(key, flows):
    os.makedirs(CACHE_DIR, exist_ok=True)
    with open(os.path.join(CACHE_DIR, f"{key}.json"), "w") as f:
        json.dump({"ts": time.time(), "flows": flows}, f)


def truncate_js(source, max_bytes=MAX_JS_BYTES):
    """Truncate large JS files intelligently — keep first + last portions."""
    if len(source.encode()) <= max_bytes:
        return source
    half = max_bytes // 2
    first = source[:half]
    last = source[-half:]
    return first + f"\n\n/* ... TRUNCATED {len(source.encode()) - max_bytes} bytes ... */\n\n" + last


def parse_llm_flows(raw_text):
    """Parse LLM output into structured flow list."""
    flows = []
    current = {}
    for line in raw_text.splitlines():
        line = line.strip()
        if not line:
            if current.get("source"):
                flows.append(current)
                current = {}
            continue
        if line.startswith("FLOW:"):
            current["source"] = line.replace("FLOW:", "").strip()
        elif line.startswith("PATH:"):
            current["path"] = line.replace("PATH:", "").strip()
        elif line.startswith("SANITIZER:"):
            current["sanitizer"] = line.replace("SANITIZER:", "").strip()
        elif line.startswith("RISK:"):
            current["risk"] = line.replace("RISK:", "").strip().upper()
        elif line.startswith("BYPASS:"):
            current["bypass"] = line.replace("BYPASS:", "").strip()
    if current.get("source"):
        flows.append(current)
    return flows


def analyze_js_semantic(url, js_source, llm_client=None):
    """Analyze a single JS file using the LLM semantic oracle.

    Returns list of flow dicts.
    Falls back to dom_analyzer.py regex mode if LLM unavailable.
    """
    if not js_source or not js_source.strip():
        return []

    # Check cache
    cache_key = _cache_key(js_source, url)
    cached = _get_cached(cache_key)
    if cached is not None:
        return cached

    flows = []

    # 1. Always run regex-based analysis as baseline (fast, no API cost)
    if HAS_DOM:
        try:
            baseline = regex_analyze(js_source, url)
            if baseline and "flows" in baseline:
                for f in baseline["flows"]:
                    flows.append({
                        "source": f.get("source", ""),
                        "sink": f.get("sink", ""),
                        "path": f.get("path", ""),
                        "sanitizer": f.get("sanitizer", "none") or "none",
                        "risk": "HIGH" if not f.get("sanitizer") else "MEDIUM",
                        "bypass": "NONE",
                        "method": "regex",
                    })
        except Exception:
            pass

    # 2. LLM semantic analysis for deeper insight
    if llm_client is None and HAS_AI:
        llm_client = get_llm_client()

    if llm_client and llm_client.is_configured and js_source.strip():
        truncated = truncate_js(js_source)
        prompt = f"""Analyze this JavaScript code from URL: {url}

{truncated}

{__import__('ai_core', fromlist=['SYSTEM_PROMPTS']).SYSTEM_PROMPTS['dom_oracle'] if HAS_AI else ''}

Be specific about variable names and line numbers. Identify ALL source→sink flows."""

        raw = llm_client.chat(prompt, role="dom_oracle", max_tokens=2048, temperature=0.3)
        if raw:
            llm_flows = parse_llm_flows(raw)
            # Merge with baseline — LLM flows are authoritative for source/sink
            seen_sources = {f["source"] + "|" + f.get("sink", "") for f in flows}
            for lf in llm_flows:
                key = lf["source"] + "|" + lf.get("sink", "")
                if key not in seen_sources:
                    lf["method"] = "llm"
                    flows.append(lf)
                    seen_sources.add(key)
                else:
                    # Update existing flow with LLM bypass info
                    for ef in flows:
                        if ef["source"] + "|" + ef.get("sink", "") == key:
                            ef["bypass"] = lf.get("bypass", ef.get("bypass", "NONE"))
                            ef["sanitizer"] = lf.get("sanitizer", ef.get("sanitizer", "none"))
                            break

    # 3. Enrich flows with exploitability assessment
    for f in flows:
        if not f.get("risk"):
            sanitizer = f.get("sanitizer", "none").lower()
            if sanitizer in ("none", "no", "false", "none detected", "bypassable"):
                f["risk"] = "HIGH"
                f["bypass"] = f.get("bypass", "DIRECT_INJECTION")
            elif "encodeuri" in sanitizer:
                f["risk"] = "HIGH"
                f["bypass"] = "Use encoded payloads or double-encode"
            elif "dompurify" in sanitizer:
                f["risk"] = "MEDIUM"
                f["bypass"] = f.get("bypass", "Try attribute-based events, protocol-relative URLs")
            elif "textcontent" in sanitizer or "innertext" in sanitizer:
                f["risk"] = "LOW"
                f["bypass"] = "SAFE — textContent/InnerText does not parse HTML"
            else:
                f["risk"] = "MEDIUM"
                f["bypass"] = f.get("bypass", "Manual review required")

    _set_cached(cache_key, flows)
    return flows


def batch_analyze(js_urls_file, output_dir, threads=5, llm_client=None):
    """Analyze multiple JS URLs from a file."""
    results = {}
    if not os.path.isfile(js_urls_file):
        return results

    urls = [l.strip() for l in open(js_urls_file) if l.strip()]
    print(f"[*] JS Semantic Oracle: analyzing {len(urls)} JavaScript files...")

    for i, url in enumerate(urls, 1):
        print(f"  [{i}/{len(urls)}] {url[:80]}")
        try:
            import requests
            try:
                resp = requests.get(url, timeout=15, headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                }, verify=False)
                js_src = resp.text
            except Exception:
                js_src = ""
            flows = analyze_js_semantic(url, js_src, llm_client=llm_client)
            if flows:
                results[url] = flows
                high = sum(1 for f in flows if f.get("risk") == "HIGH")
                print(f"    → {len(flows)} flows ({high} HIGH risk)")
            else:
                print(f"    → no flows")
        except Exception as e:
            print(f"    → error: {e}")

    # Save results
    os.makedirs(output_dir, exist_ok=True)
    out = os.path.join(output_dir, "js_semantic_analysis.json")
    with open(out, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n[OK] JS Semantic Oracle: {len(results)} files with flows → {out}")

    # Human-readable summary
    summary_out = os.path.join(output_dir, "js_semantic_flows.txt")
    with open(summary_out, "w") as f:
        for url, flows in results.items():
            f.write(f"URL: {url}\n")
            for fl in flows:
                f.write(f"  SOURCE: {fl.get('source','')}\n")
                f.write(f"  SINK: {fl.get('sink','')}\n")
                f.write(f"  PATH: {fl.get('path','')}\n")
                f.write(f"  RISK: {fl.get('risk','')}\n")
                f.write(f"  BYPASS: {fl.get('bypass','NONE')}\n")
                f.write(f"  METHOD: {fl.get('method','unknown')}\n\n")
    return results


# ── CLI ────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="JS Semantic Oracle")
    parser.add_argument("--js-file", default=None, help="Single JS file to analyze")
    parser.add_argument("--js-url", default=None, help="URL to fetch and analyze")
    parser.add_argument("--js-urls", default=None, help="File of JS URLs (one per line)")
    parser.add_argument("--output-dir", default=".")
    parser.add_argument("--threads", type=int, default=5)
    parser.add_argument("--test", action="store_true")
    args = parser.parse_args()

    if args.test:
        # Test flow parsing
        sample = """FLOW: location.hash
PATH: location.hash → unescape() → chooseTab → $('#tabContent').html()
SANITIZER: none
RISK: HIGH
BYPASS: URL-encode payload for unescape() to decode

FLOW: document.cookie
PATH: document.cookie → jQuery.ajax data → eval()
SANITIZER: JSON.parse (bypassable with ]} payload)
RISK: MEDIUM
BYPASS: Use ]} JSON breakout before script tag"""
        flows = parse_llm_flows(sample)
        assert len(flows) == 2
        assert flows[0]["risk"] == "HIGH"
        assert "unescape" in flows[0]["path"]

        # Test truncation
        big = "x" * 60000
        trunc = truncate_js(big)
        assert len(trunc) < 60000

        print("[OK] JS Semantic Oracle self-test passed")
        print(f"  Parsed {len(flows)} flows from sample")
        sys.exit(0)

    client = None
    if HAS_AI:
        client = get_llm_client()

    if args.js_file:
        src = open(args.js_file, encoding="utf-8", errors="replace").read()
        url = args.js_file
        flows = analyze_js_semantic(url, src, llm_client=client)
        print(f"[*] {url}: {len(flows)} flows found")
        for f in flows:
            print(f"  [{f['risk']}] {f['source']} → {f['sink']} | bypass: {f.get('bypass','NONE')}")
    elif args.js_urls:
        batch_analyze(args.js_urls, args.output_dir, threads=args.threads, llm_client=client)
    elif args.js_url:
        try:
            import requests
            resp = requests.get(args.js_url, timeout=15, headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }, verify=False)
            flows = analyze_js_semantic(args.js_url, resp.text, llm_client=client)
            print(f"[*] {args.js_url}: {len(flows)} flows")
        except Exception as e:
            print(f"[!] Failed to fetch JS: {e}")
    else:
        parser.error("Provide --js-file, --js-url, or --js-urls")
