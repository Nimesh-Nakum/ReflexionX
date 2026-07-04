#!/usr/bin/env python3
"""
XSS ReflexionX v1.0.0 — AI False Positive Triage Oracle
Uses LLM to classify scanner detections as TRUE POSITIVE, FALSE POSITIVE,
or MANUAL REVIEW, dramatically reducing false positives in final reports.

Also suggests specific breakout payloads for borderline findings.

Usage:
    python3 ai_fp_triage.py --finding finding.json --output-dir output/
    python3 ai_fp_triage.py --bulk findings_dir/ --output-dir output/
"""

import argparse, hashlib, json, os, re, sys, time

try:
    from ai_core import get_llm_client, SYSTEM_PROMPTS, LLMClient
    HAS_AI = True
except ImportError:
    HAS_AI = False

CACHE_DIR = ".ai_fp_cache"
CACHE_TTL = 3600  # 1 hour — findings don't change


def _cache_key(finding):
    raw = json.dumps(finding, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _get_cached(key):
    os.makedirs(CACHE_DIR, exist_ok=True)
    fpath = os.path.join(CACHE_DIR, f"{key}.json")
    if os.path.isfile(fpath):
        try:
            with open(fpath) as f:
                data = json.load(f)
            if time.time() - data.get("ts", 0) < CACHE_TTL:
                return data.get("result")
        except Exception:
            pass
    return None


def _set_cached(key, result):
    os.makedirs(CACHE_DIR, exist_ok=True)
    with open(os.path.join(CACHE_DIR, f"{key}.json"), "w") as f:
        json.dump({"ts": time.time(), "result": result}, f)


def build_fp_prompt(finding):
    """Build the triage prompt from a finding dict."""
    url = finding.get("url", finding.get("test_url", ""))
    param = finding.get("param", finding.get("parameter", "unknown"))
    payload = finding.get("payload", finding.get("test_payload", ""))[:500]
    context = finding.get("context", finding.get("contexts", ["unknown"]))
    encoding = finding.get("encoding", "unknown")
    trigger = finding.get("trigger", "unknown")
    csp = finding.get("csp", finding.get("csp_data", {}))
    response_snippet = finding.get("response_snippet",
                                    finding.get("reflected_html", ""))[:2000]
    source_method = finding.get("source", finding.get("tool", "unknown"))

    if isinstance(context, list):
        context = context[0] if context else "unknown"

    csp_str = "None"
    if csp:
        parts = []
        if csp.get("inline_allowed") is False:
            parts.append("inline-script BLOCKED")
        if csp.get("nonce_required"):
            parts.append(f"nonce-required: {csp.get('nonce_value','?')}")
        if parts:
            csp_str = "; ".join(parts)

    return f"""Classify this XSS scanner detection:

URL: {url}
Parameter: {param}
Payload tested: {payload[:200]}
Detected context: {context}
Encoding observed: {encoding}
Trigger method: {trigger}
CSP: {csp_str}
Scanner source: {source_method}

Response HTML snippet (payload reflection):
{response_snippet if response_snippet else "(not provided)"}

Determine:
1. VERDICT: TRUE_POSITIVE, FALSE_POSITIVE, or MANUAL_REVIEW
2. CONFIDENCE: high, medium, low
3. REASON: one sentence explaining why
4. SUGGESTION: if FP, what payload might work? if TP, exploitation steps
5. BREAKOUT_PAYLOAD: if TP in {context} context with {encoding} encoding and {csp_str} CSP, give one highly specific payload that exploits it

Output as JSON:
{{"verdict": "...", "confidence": "...", "reason": "...", "suggestion": "...", "breakout_payload": "..."}}"""


def triage_finding(finding, llm_client=None):
    """Triage a single finding. Returns dict with verdict + metadata."""
    cache_key = _cache_key(finding)
    cached = _get_cached(cache_key)
    if cached is not None:
        return cached

    if llm_client is None and HAS_AI:
        llm_client = get_llm_client()

    result = {
        "verdict": "MANUAL_REVIEW",
        "confidence": "low",
        "reason": "No LLM available, defaulting to MANUAL_REVIEW",
        "suggestion": "Review manually",
        "breakout_payload": "",
        "source": "fallback",
    }

    if llm_client and llm_client.is_configured:
        prompt = build_fp_prompt(finding)
        raw = llm_client.chat(prompt, role="fp_triage", temperature=0.2, max_tokens=512)
        if raw:
            # Extract JSON from response
            json_match = re.search(r'\{.*\}', raw, re.DOTALL)
            if json_match:
                try:
                    parsed = json.loads(json_match.group())
                    result.update(parsed)
                    result["source"] = "llm"
                    result["_raw"] = raw[:300]
                except json.JSONDecodeError:
                    result["reason"] = f"LLM response unparseable: {raw[:100]}"
            else:
                # Try to extract verdict from text
                verdict_map = {
                    "true positive": "TRUE_POSITIVE",
                    "false positive": "FALSE_POSITIVE",
                    "manual review": "MANUAL_REVIEW",
                }
                lower = raw.lower()
                for k, v in verdict_map.items():
                    if k in lower:
                        result["verdict"] = v
                        result["reason"] = raw[:200]
                        result["source"] = "llm_text"
                        break

    _set_cached(cache_key, result)
    return result


def apply_rule_based_triage(finding):
    """Fast rule-based triage when LLM unavailable."""
    verdict = "MANUAL_REVIEW"
    confidence = "medium"
    reason = ""
    context = finding.get("context", finding.get("contexts", ["unknown"]))
    if isinstance(context, list):
        context = context[0] if context else "unknown"
    encoding = finding.get("encoding", "unknown")
    csp = finding.get("csp", finding.get("csp_data", {}))
    trigger = finding.get("trigger", "")

    # Strong TP signals
    if context in ("javascript", "json") and encoding == "raw":
        verdict, confidence = "TRUE_POSITIVE", "high"
        reason = "Raw reflection in JS/JSON context — executable with quote breakout"
    elif context == "html_body" and encoding == "raw":
        verdict, confidence = "TRUE_POSITIVE", "high"
        reason = "Raw reflection in HTML body — direct tag injection possible"
    elif context == "html_attribute" and encoding == "raw":
        verdict, confidence = "TRUE_POSITIVE", "medium"
        reason = "Raw reflection in HTML attribute — breakout possible with quote manipulation"
    elif encoding in ("html_encoded", "url_encoded"):
        verdict, confidence = "MANUAL_REVIEW", "medium"
        reason = f"Encoded reflection ({encoding}) — may require decode bypass"
    elif csp and not csp.get("inline_allowed", True):
        verdict, confidence = "MANUAL_REVIEW", "medium"
        reason = "CSP blocks inline scripts but event handlers may still work"
    elif "dialog" in trigger:
        verdict, confidence = "TRUE_POSITIVE", "high"
        reason = "JavaScript dialog detected — code executed"

    return {
        "verdict": verdict,
        "confidence": confidence,
        "reason": reason,
        "suggestion": "Review context and test with context-appropriate payload",
        "breakout_payload": "",
        "source": "rule_based",
    }


def triage_finding_hybrid(finding, llm_client=None):
    """Triage with rule-based pre-filter + LLM for uncertain cases."""
    rule_result = apply_rule_based_triage(finding)

    if rule_result["verdict"] == "TRUE_POSITIVE" and rule_result["confidence"] == "high":
        return rule_result
    if rule_result["verdict"] == "FALSE_POSITIVE" and rule_result["confidence"] == "high":
        return rule_result

    # Uncertain — ask LLM
    if llm_client and llm_client.is_configured:
        return triage_finding(finding, llm_client=llm_client)

    return rule_result


def bulk_triage(findings, llm_client=None):
    """Triage a list of findings. Returns triaged list."""
    results = []
    for f in findings:
        triaged = triage_finding_hybrid(f, llm_client=llm_client)
        merged = dict(f)
        merged.update(triaged)
        results.append(merged)
    return results


# ── CLI ────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AI FP Triage Oracle")
    parser.add_argument("--finding", default=None, help="Single finding JSON file")
    parser.add_argument("--bulk", default=None, help="Directory of finding JSON files")
    parser.add_argument("--input", default=None, help="JSON/JSONL file of findings")
    parser.add_argument("--output-dir", default=".")
    parser.add_argument("--no-llm", action="store_true")
    parser.add_argument("--test", action="store_true")
    args = parser.parse_args()

    if args.test:
        # Test rule-based triage
        tp_html = {"url": "http://test.com", "param": "q", "context": "html_body",
                    "encoding": "raw", "trigger": "immediate"}
        r = apply_rule_based_triage(tp_html)
        assert r["verdict"] == "TRUE_POSITIVE"
        assert r["confidence"] == "high"

        fp_encoded = {"url": "http://test.com", "param": "q", "context": "html_body",
                       "encoding": "html_encoded"}
        r2 = apply_rule_based_triage(fp_encoded)
        assert r2["verdict"] == "MANUAL_REVIEW"

        # Test prompt building
        prompt = build_fp_prompt(tp_html)
        assert "html_body" in prompt
        assert "raw" in prompt

        print("[OK] FP Triage Oracle self-test passed")
        sys.exit(0)

    client = None
    if not args.no_llm and HAS_AI:
        client = get_llm_client()

    findings = []
    if args.finding and os.path.isfile(args.finding):
        with open(args.finding) as f:
            findings = [json.load(f)]
    elif args.input and os.path.isfile(args.input):
        with open(args.input) as f:
            content = f.read().strip()
            if content.startswith('['):
                findings = json.loads(content)
            else:
                findings = [json.loads(l) for l in content.splitlines() if l.strip()]
    elif args.bulk and os.path.isdir(args.bulk):
        for fname in os.listdir(args.bulk):
            if fname.endswith('.json'):
                try:
                    with open(os.path.join(args.bulk, fname)) as f:
                        findings.append(json.load(f))
                except Exception:
                    pass

    if not findings:
        print("[!] No findings to triage", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Triaging {len(findings)} findings...")
    triaged = bulk_triage(findings, llm_client=client)

    tp = sum(1 for f in triaged if f.get("verdict") == "TRUE_POSITIVE")
    fp = sum(1 for f in triaged if f.get("verdict") == "FALSE_POSITIVE")
    mr = sum(1 for f in triaged if f.get("verdict") == "MANUAL_REVIEW")

    print(f"    TRUE POSITIVE: {tp}")
    print(f"    FALSE POSITIVE: {fp}")
    print(f"    MANUAL REVIEW: {mr}")

    os.makedirs(args.output_dir, exist_ok=True)
    out = os.path.join(args.output_dir, "ai_triage_results.json")
    with open(out, "w") as f:
        json.dump(triaged, f, indent=2)
    print(f"\n[OK] Triage results saved to {out}")
