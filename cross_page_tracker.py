#!/usr/bin/env python3
"""
XSS ReflexionX v1.0.0 — Cross-Page Parameter Flow Tracker
Detects when the same parameter name is reflected differently across pages
(i.e. HTML-entity encoded on page A, raw in JS on page B).

This is critical for Google XSS Game Level 5 (Breaking Protocol):
  - signup page: next=<script> gets HTML-entity encoded (safe)
  - confirm page: window.location = "NEXT" — raw JS (vulnerable)

Usage:
    python3 cross_page_tracker.py --contexts reflection_contexts.json --domains domains.txt \\
        --output-dir output/
"""

import argparse, json, os, re, sys
from urllib.parse import parse_qs, urlparse


from context_loader import load_contexts, get_contexts_path


def extract_param_contexts(contexts_data):
    """Build param_name -> [(url, encoding, context_list)] mapping."""
    param_map = {}
    for entry in contexts_data:
        url = entry.get("url", entry.get("target_url", ""))
        params = entry.get("params", entry.get("parameters", {}))
        if isinstance(params, dict):
            for pname, pinfo in params.items():
                enc = pinfo.get("encoding", "unknown")
                ctx = pinfo.get("contexts", pinfo.get("context", ["unknown"]))
                if isinstance(ctx, str):
                    ctx = [ctx]
                param_map.setdefault(pname, []).append((url, enc, ctx))
        elif isinstance(params, list):
            for pinfo in params:
                pname = pinfo.get("name", pinfo.get("param", ""))
                enc = pinfo.get("encoding", "unknown")
                ctx = pinfo.get("contexts", pinfo.get("context", ["unknown"]))
                if isinstance(ctx, str):
                    ctx = [ctx]
                param_map.setdefault(pname, []).append((url, enc, ctx))
    return param_map


def find_cross_page_flows(param_map, suspicious_params=None):
    """Find param names that appear safe on one page but dangerous on another.

    Heuristics:
      - html_encoded on page A + raw on page B  => flag (Level 5 pattern)
      - CTX_HTML_ATTR (href) on page A + CTX_JAVASCRIPT on page B  => flag
      - any encoding downgrade (raw -> html_encoded is safe upgrade; reverse is danger)
    """
    if suspicious_params is None:
        suspicious_params = {"next", "redirect", "url", "return", "goto", "target",
                             "callback", "continue", "dest", "link", "path"}

    findings = []
    for pname, pages in param_map.items():
        if len(pages) < 2:
            continue
        # Group pages by their encoding+context signature
        sig_groups = {}
        for url, enc, ctxs in pages:
            sig = (enc, tuple(sorted(ctxs)))
            sig_groups.setdefault(sig, []).append(url)

        if len(sig_groups) < 2:
            continue

        # Check for cross-page downgrade
        has_raw_js = any(
            "javascript" in str(ctx).lower() and enc == "raw"
            for enc, ctxs in sig_groups
            for ctx in ctxs
        )
        has_encoded_safe = any(
            enc == "html_encoded" or enc == "html"
            for enc, ctxs in sig_groups
        )
        has_raw_attr = any(
            enc == "raw" and any("html_attr" in str(c).lower() for c in ctxs)
            for enc, ctxs in sig_groups
        )

        if has_raw_js and (has_encoded_safe or has_raw_attr):
            findings.append({
                "param": pname,
                "detection": "cross_page_encoding_varies",
                "page_signatures": {str(k): v for k, v in sig_groups.items()},
                "recommended_action": "Investigate pages where param is raw/JS context. "
                                      "This pattern typically indicates a cross-page XSS "
                                      "(e.g. param HTML-entity-encoded safely on page A, "
                                      "but raw into JavaScript on page B).",
                "priority": "high" if pname in suspicious_params else "medium",
            })
        elif len(sig_groups) >= 2 and pname in suspicious_params:
            findings.append({
                "param": pname,
                "detection": "param_appears_in_multiple_contexts",
                "page_signatures": {str(k): v for k, v in sig_groups.items()},
                "recommended_action": "Review all pages where this high-value param appears. "
                                      "Context may differ per page.",
                "priority": "medium",
            })

    return findings


def find_multi_step_flows(urls_file, contexts_data):
    """Heuristic: detect URLs that might be part of a multi-step form flow.

    Looks for:
      - Signup/test/create endpoints followed by confirm/success pages
      - Same param (next, redirect) appearing across sequential paths
    """
    flows = []
    url_list = []
    if os.path.isfile(urls_file):
        with open(urls_file) as f:
            url_list = [l.strip() for l in f if l.strip()]

    step_keywords = ["signup", "register", "create", "test", "login", "submit",
                     "save", "post", "send", "confirm", "success", "verify", "next"]
    confirm_keywords = ["confirm", "success", "verify", "complete", "done", "result"]

    for i, url in enumerate(url_list):
        path = urlparse(url).path.lower()
        is_step = any(kw in path for kw in step_keywords)
        is_confirm = any(kw in path for kw in confirm_keywords)
        if is_step:
            params_in_url = parse_qs(urlparse(url).query)
            for pname in params_in_url:
                # Look ahead for a confirm page with the same param
                for j in range(i + 1, min(i + 5, len(url_list))):
                    next_url = url_list[j]
                    next_path = urlparse(next_url).path.lower()
                    if any(kw in next_path for kw in confirm_keywords):
                        next_params = parse_qs(urlparse(next_url).query)
                        if pname in next_params:
                            flows.append({
                                "type": "multi_step_form",
                                "step_url": url,
                                "confirm_url": next_url,
                                "shared_param": pname,
                                "recommended_action": (
                                    f"Test {pname} on confirm page. "
                                    f"If safe on {urlparse(url).path} but raw on "
                                    f"{urlparse(next_url).path}, this is a cross-page XSS."
                                ),
                            })
    return flows


def main():
    parser = argparse.ArgumentParser(
        description="ReflexionX v1.0.0 — Cross-Page Parameter Flow Tracker")
    parser.add_argument("--contexts", required=True,
                        help="reflection_contexts.json from xss_validator.py, or output-dir")
    parser.add_argument("--urls", default=None, help="all_urls.txt for multi-step flow detection")
    parser.add_argument("--output-dir", default=".", help="Output directory")
    args = parser.parse_args()

    ctx_path = args.contexts
    if os.path.isdir(ctx_path):
        ctx_path = get_contexts_path(ctx_path)
    ctx_data = load_contexts(filepath=ctx_path)
    if not ctx_data:
        print(f"[!] No context data loaded from {ctx_path}", file=sys.stderr)
        sys.exit(1)

    param_map = extract_param_contexts(ctx_data)
    findings = find_cross_page_flows(param_map)

    if args.urls:
        flows = find_multi_step_flows(args.urls, ctx_data)
        findings.extend(flows)

    os.makedirs(args.output_dir, exist_ok=True)
    out = os.path.join(args.output_dir, "cross_page_flows.json")
    with open(out, "w") as f:
        json.dump(findings, f, indent=2)

    print(f"[DONE] Found {len(findings)} cross-page flow issues in {out}")
    if findings:
        print("[!] CROSS-PAGE XSS RISKS DETECTED — review cross_page_flows.json")


if __name__ == "__main__":
    main()
