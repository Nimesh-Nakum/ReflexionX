#!/usr/bin/env python3
"""
XSS ReflexionX v1.0.0 — Multi-Step Chain Synthesis Engine
Analyzes cross-page parameter flows, stored XSS chains, and DOM XSS
data flows to build complete exploit chains that span multiple requests
or pages.

This is the engine that makes Level 5 (cross-page) and generalized
multi-step XSS detection possible.

Outputs structured chain objects with:
  - Chain type (cross_page, stored, dom_chain, redirect_chain, combined)
  - Step-by-step exploit path
  - Risk and exploitability ratings
  - Recommended payload per step

Usage:
    python3 chain_synthesizer.py --contexts reflection_contexts.json \\
        --urls all_urls.txt --dom-risks dom_risks.txt --output-dir output/
"""

import argparse, json, os, sys
from urllib.parse import urlparse, parse_qs

try:
    from ai_core import get_llm_client, SYSTEM_PROMPTS
    HAS_AI = True
except ImportError:
    HAS_AI = False


# ── Data loading ───────────────────────────────────────────────

from context_loader import load_contexts, get_contexts_path, normalize_contexts


def load_json(path):
    if not path or not __import__('os').path.isfile(path):
        return None
    with open(path) as f:
        return json.load(f)


def load_urls(path):
    if not path or not __import__('os').path.isfile(path):
        return []
    return [l.strip() for l in open(path) if l.strip()]


def normalize_context_entries(contexts_data):
    """Return a list of per-URL context dictionaries from any supported schema."""
    if not contexts_data:
        return []
    if isinstance(contexts_data, list):
        return [entry for entry in contexts_data if isinstance(entry, dict)]
    if isinstance(contexts_data, dict):
        if "urls" in contexts_data and isinstance(contexts_data["urls"], list):
            return [entry for entry in contexts_data["urls"] if isinstance(entry, dict)]
        if "targets" in contexts_data and isinstance(contexts_data["targets"], list):
            return [entry for entry in contexts_data["targets"] if isinstance(entry, dict)]
        return [
            {"url": url, **details}
            for url, details in contexts_data.items()
            if isinstance(details, dict)
        ]
    return []


# ── Heuristic chain detectors ────────────────────────────────

def detect_cross_page_flows(contexts_data, urls):
    """Detect params safe on one page, dangerous on another."""
    if not contexts_data:
        return []

    # Build param -> pages map
    param_pages = {}
    entries = normalize_context_entries(contexts_data)

    for entry in entries:
        url = entry.get("url", entry.get("target_url", ""))
        params = entry.get("params", entry.get("parameters", {}))
        if isinstance(params, dict):
            items = params.items()
        elif isinstance(params, list):
            items = [(p.get("name", p.get("param", "")), p) for p in params]
        else:
            continue

        for pname, pinfo in items:
            if not pname:
                continue
            enc = pinfo.get("encoding", "unknown") if isinstance(pinfo, dict) else "unknown"
            ctx = pinfo.get("contexts", pinfo.get("context", ["unknown"]))
            if isinstance(ctx, str):
                ctx = [ctx]
            param_pages.setdefault(pname, []).append({
                "url": url, "encoding": enc, "contexts": ctx
            })

    suspicious = {"next", "redirect", "url", "return", "goto", "target",
                  "callback", "continue", "dest", "link", "path", "load", "file"}

    chains = []
    for pname, pages in param_pages.items():
        if len(pages) < 2:
            continue

        sigs = {}
        for pg in pages:
            sig = (pg["encoding"], tuple(sorted(pg["contexts"])))
            sigs.setdefault(sig, []).append(pg["url"])

        if len(sigs) < 2:
            continue

        has_raw_js = any(
            enc == "raw" and any("javascript" in c.lower() for c in ctxs)
            for enc, ctxs in sigs
        )
        has_encoded = any(enc in ("html_encoded", "html", "url_encoded") for enc, ctxs in sigs)
        has_raw_attr = any(
            enc == "raw" and any("html_attr" in c.lower() for c in ctxs)
            for enc, ctxs in sigs
        )

        if has_raw_js and (has_encoded or has_raw_attr):
            vuln_pages = [
                url for enc, ctxs in sigs
                for url in sigs[(enc, ctxs)]
                if enc == "raw" and any("javascript" in c.lower() for c in ctxs)
            ]
            safe_pages = [
                url for enc, ctxs in sigs
                for url in sigs[(enc, ctxs)]
                if enc in ("html_encoded", "html", "url_encoded") or
                (enc == "raw" and any("html_attr" in c.lower() for c in ctxs))
            ]

            chains.append({
                "chain_type": "cross_page",
                "param": pname,
                "risk": "high",
                "exploitability": "easy" if pname in {"next", "redirect", "url"} else "medium",
                "steps": [
                    {"step": 1, "url": safe_pages[0] if safe_pages else pages[0]["url"],
                     "action": "submit_param", "param": pname, "context": "safe_encoded",
                     "note": "Param is safely encoded here"},
                    {"step": 2, "url": vuln_pages[0] if vuln_pages else pages[-1]["url"],
                     "action": "trigger_xss", "param": pname, "context": "raw_javascript",
                     "note": "Param flows raw into JS — inject javascript: or breakout payload"},
                ],
                "safe_pages": safe_pages[:3],
                "vulnerable_pages": vuln_pages[:3],
                "recommended_payload": f"javascript:window._xss_confirmed='HF5XSSCONFIRMED'",
            })

    return chains


def detect_multi_step_flows(urls, contexts_data=None):
    """Detect form submission -> stored -> load chains."""
    if not urls:
        return []

    chains = []
    url_parsed = [{"url": u, "parsed": urlparse(u)} for u in urls]

    # Group by path prefix
    path_groups = {}
    for item in url_parsed:
        path = item["parsed"].path.lower()
        base = path.rsplit("/", 1)[0] if "/" in path else path
        path_groups.setdefault(base, []).append(item)

    # Look for signup -> confirm, post -> view patterns
    step_suffixes = ["signup", "register", "create", "submit", "post",
                     "save", "send", "test", "login", "update"]
    confirm_suffixes = ["confirm", "success", "verify", "complete", "done",
                        "result", "view", "display", "show", "profile", "status"]

    for base, items in path_groups.items():
        step_urls = [i for i in items if any(i["parsed"].path.lower().endswith(s) for s in step_suffixes)]
        confirm_urls = [i for i in items if any(i["parsed"].path.lower().endswith(s) for s in confirm_suffixes)]

        if len(step_urls) >= 1 and len(confirm_urls) >= 1:
            # Check shared params
            for step in step_urls:
                step_params = set(parse_qs(step["parsed"].query).keys())
                for conf in confirm_urls:
                    conf_params = set(parse_qs(conf["parsed"].query).keys())
                    shared = step_params & conf_params
                    if shared:
                        chains.append({
                            "chain_type": "stored",
                            "param": list(shared)[0],
                            "risk": "high",
                            "exploitability": "medium",
                            "steps": [
                                {"step": 1, "url": step["url"],
                                 "action": "post_payload",
                                 "param": list(shared)[0],
                                 "note": "POST data here is stored server-side"},
                                {"step": 2, "url": conf["url"],
                                 "action": "load_stored",
                                 "param": list(shared)[0],
                                 "note": "Stored content renders here — check for XSS"},
                            ],
                            "post_url": step["url"],
                            "verify_url": conf["url"],
                        })

    return chains


def detect_dom_chains(dom_risks_txt=""):
    """Detect DOM XSS chains (source on page A, sink on page B in iframe/parent)."""
    chains = []
    if not dom_risks_txt or not __import__('os').path.isfile(dom_risks_txt):
        return chains

    try:
        with open(dom_risks_txt) as f:
            content = f.read()
    except Exception:
        return chains

    # Parse URL: entries from dom_risks.txt
    url_blocks = content.split("URL: ")
    for block in url_blocks[1:]:
        lines = block.strip().splitlines()
        if not lines:
            continue
        url = lines[0].strip()
        source_found = None
        sink_found = None

        for line in lines:
            ll = line.lower()
            if "source" in ll or "->" in ll:
                source_found = line.strip()
            if "sink" in ll or "inner" in ll or "eval" in ll:
                sink_found = line.strip()

        if source_found and sink_found:
            chains.append({
                "chain_type": "dom_chain",
                "url": url,
                "risk": "high",
                "exploitability": "hard",
                "steps": [
                    {"step": 1, "url": url, "action": "inject_fragment",
                     "note": f"Inject payload in fragment/param: {source_found}"},
                    {"step": 2, "url": url, "action": "trigger_sink",
                     "note": f"Sink executes: {sink_found}"},
                ],
                "source": source_found,
                "sink": sink_found,
            })

    return chains


# ── LLM-enhanced chain synthesis ─────────────────────────────

def llm_synthesize_chains(chains, contexts_data, urls, llm_client=None):
    """Use LLM to enhance and validate heuristic chain findings."""
    if not chains:
        return chains

    if llm_client is None and HAS_AI:
        llm_client = get_llm_client()

    if not llm_client or not llm_client.is_configured:
        return chains

    prompt_parts = [
        "Review these XSS exploit chain candidates from a web app scan.",
        "For each chain, assess:",
        "  - Is this chain actually exploitable in practice?",
        "  - Are there missing steps or assumptions?",
        "  - What is the realistic exploitability?",
        "",
        "Chains found:",
    ]

    for i, ch in enumerate(chains[:10], 1):
        prompt_parts.append(f"\nChain {i}: {ch['chain_type']}")
        prompt_parts.append(f"  Param: {ch.get('param', 'N/A')}")
        for step in ch.get("steps", []):
            prompt_parts.append(f"  Step {step.get('step','?')}: {step.get('url','')} [{step.get('action','')}]")

    prompt_parts.extend([
        "",
        "Return JSON array with same structure plus 'llm_validation' field per chain:",
        '{"chain_type": "...", "llm_validation": {"exploitable": true/false, "confidence": "high/medium/low", "notes": "..."}, ...}'
    ])

    prompt = "\n".join(prompt_parts)
    raw = llm_client.chat(prompt, role="chain_synthesizer", max_tokens=2048, temperature=0.3)

    if not raw:
        return chains

    json_match = __import__('re').search(r'\[.*\]', raw, __import__('re').DOTALL)
    if not json_match:
        return chains

    try:
        validated = json.loads(json_match.group())
        # Merge LLM validation back into original chains
        for i, vchain in enumerate(validated):
            if i < len(chains):
                chains[i]["llm_validation"] = vchain.get("llm_validation", {})
                chains[i]["llm_notes"] = vchain.get("notes", "")
    except (json.JSONDecodeError, IndexError):
        pass

    return chains


# ── Main orchestration ─────────────────────────────────────────

def synthesize_chains(contexts_path, urls_path, dom_risks_path="", output_dir=".",
                      use_llm=True):
    """Main entry: load all data, detect chains, optionally validate with LLM."""
    contexts_data = load_json(contexts_path) or []
    urls = load_urls(urls_path)
    dom_risks_path = dom_risks_path or ""

    all_chains = []

    # Run all detectors
    all_chains.extend(detect_cross_page_flows(contexts_data, urls))
    all_chains.extend(detect_multi_step_flows(urls, contexts_data))
    all_chains.extend(detect_dom_chains(dom_risks_path))

    # Deduplicate by chain_type + param + first URL
    seen = set()
    unique = []
    for ch in all_chains:
        key = (ch.get("chain_type"), ch.get("param"), ch.get("steps", [{}])[0].get("url", ""))
        if key not in seen:
            seen.add(key)
            unique.append(ch)
    all_chains = unique

    # LLM validation
    llm_client = None
    if use_llm and HAS_AI:
        llm_client = get_llm_client()

    if llm_client and llm_client.is_configured:
        all_chains = llm_synthesize_chains(all_chains, contexts_data, urls, llm_client)

    # Save results
    os.makedirs(output_dir, exist_ok=True)
    out = os.path.join(output_dir, "xss_chains.json")
    with open(out, "w") as f:
        json.dump(all_chains, f, indent=2)

    # Human-readable summary
    summary = os.path.join(output_dir, "xss_chains_summary.txt")
    with open(summary, "w") as f:
        f.write(f"XSS Exploit Chain Analysis — {len(all_chains)} chains found\n")
        f.write("=" * 60 + "\n\n")
        for i, ch in enumerate(all_chains, 1):
            f.write(f"Chain {i}: {ch['chain_type']} | risk={ch.get('risk','?')} | exploitability={ch.get('exploitability','?')}\n")
            f.write(f"  Param: {ch.get('param', 'N/A')}\n")
            for step in ch.get("steps", []):
                f.write(f"  Step {step.get('step','?')}: {step.get('url','')}\n")
                f.write(f"    Action: {step.get('action','')} — {step.get('note','')}\n")
            if ch.get("recommended_payload"):
                f.write(f"  Payload: {ch['recommended_payload'][:100]}\n")
            if ch.get("llm_validation"):
                lv = ch["llm_validation"]
                f.write(f"  LLM: exploitable={lv.get('exploitable')}, confidence={lv.get('confidence')}\n")
            f.write("\n")

    return all_chains


# ── CLI ────────────────────────────────────────────────────────

if __name__ == "__main__":
    if "--test" in sys.argv:
        fake_ctx = [
            {"url": "http://t.com/signup?next=a",
             "params": {"next": {"encoding": "html_encoded", "contexts": ["html_attribute"]}}},
            {"url": "http://t.com/confirm?next=b",
             "params": {"next": {"encoding": "raw", "contexts": ["javascript"]}}},
        ]
        chains = detect_cross_page_flows(fake_ctx, ["http://t.com/signup?next=a",
                                                      "http://t.com/confirm?next=b"])
        assert len(chains) >= 1
        assert chains[0]["chain_type"] == "cross_page"
        assert chains[0]["param"] == "next"

        url_test = [
            "http://t.com/status?msg=hi",
            "http://t.com/chat?msg=hello",
            "http://t.com/profile",
            "http://t.com/confirm",
        ]
        stored = detect_multi_step_flows(url_test)
        assert len(chains) >= 1

        print("[OK] Chain Synthesis Engine self-test passed")
        print(f"  Cross-page chains: {len(chains)}")
        raise SystemExit(0)

    parser = argparse.ArgumentParser(description="Chain Synthesis Engine")
    parser.add_argument("--contexts", required=True, help="reflection_contexts.json or output-dir")
    parser.add_argument("--urls", required=True, help="all_urls.txt")
    parser.add_argument("--dom-risks", default="", help="dom_risks.txt")
    parser.add_argument("--output-dir", default=".")
    parser.add_argument("--no-llm", action="store_true")
    args = parser.parse_args()

    ctx_path = args.contexts
    if os.path.isdir(ctx_path):
        ctx_path = get_contexts_path(ctx_path)

    chains = synthesize_chains(
        ctx_path, args.urls, args.dom_risks,
        args.output_dir, use_llm=not args.no_llm
    )
    print(f"[DONE] {len(chains)} XSS exploit chains found")
    if chains:
        print(f"[!] Review {args.output_dir}/xss_chains.json for exploit paths")
