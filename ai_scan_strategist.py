#!/usr/bin/env python3
"""
XSS ReflexionX v1.0.0 — AI Scan Strategist
Analyzes target characteristics and produces an optimal scan strategy
to maximize XSS detection while avoiding wasted work.

Input: collection statistics + initial recon results
Output: JSON scan plan with phase recommendations, priority targets, thread settings

Usage:
    python3 ai_scan_strategist.py --stats collection_stats.json --dom-risks dom_risks.txt \\
        --output-dir output/ --plan-out scan_plan.json
"""

import argparse, json, os, sys

try:
    from ai_core import get_llm_client, LLMClient
    HAS_AI = True
except ImportError:
    HAS_AI = False


def estimate_stats(urls_file, live_file, katana_file, dom_risks_file):
    """Compute target surface statistics from collected data."""
    stats = {
        "total_urls": 0,
        "live_urls": 0,
        "katana_urls": 0,
        "param_urls": 0,
        "dom_risks": 0,
        "unique_params": set(),
        "post_forms": 0,
        "target_hint": "unknown",
        "waf_status": "unknown",
    }

    if urls_file and os.path.isfile(urls_file):
        stats["total_urls"] = sum(1 for _ in open(urls_file) if _.strip())

    if live_file and os.path.isfile(live_file):
        stats["live_urls"] = sum(1 for _ in open(live_file) if _.strip())

    if katana_file and os.path.isfile(katana_file):
        stats["katana_urls"] = sum(1 for _ in open(katana_file) if _.strip())

    if urls_file and os.path.isfile(urls_file):
        try:
            from urllib.parse import urlparse, parse_qs
            params_seen = set()
            post_count = 0
            for line in open(urls_file):
                u = line.strip()
                if not u:
                    continue
                pq = parse_qs(urlparse(u).query)
                params_seen.update(pq.keys())
                # heuristic: .py, .asp, .php in path = likely form handler
                path = urlparse(u).path.lower()
                if any(ext in path for ext in ['.py', '.asp', '.php', '.jsp', 'submit', 'form', 'post']):
                    post_count += 1
            stats["param_urls"] = len(params_seen)
            stats["unique_params"] = list(params_seen)
            stats["post_forms"] = post_count
        except Exception:
            pass

    if dom_risks_file and os.path.isfile(dom_risks_file):
        try:
            with open(dom_risks_file) as f:
                stats["dom_risks"] = sum(1 for l in f if l.startswith("URL:"))
        except Exception:
            pass

    # Target type hints
    low_count = stats["total_urls"] < 30
    high_param = stats["param_urls"] > 5
    has_dom = stats["dom_risks"] > 0

    if low_count and high_param:
        stats["target_hint"] = "small_app_focused"
    elif low_count and has_dom:
        stats["target_hint"] = "dom_xss_game"
    elif stats["total_urls"] > 1000:
        stats["target_hint"] = "large_surface"
    elif stats["post_forms"] > 3:
        stats["target_hint"] = "form_heavy"
    else:
        stats["target_hint"] = "standard_webapp"

    return stats


def build_llm_prompt(stats):
    """Build the prompt for the scan strategist."""
    risky_params = [p for p in stats.get("unique_params", [])
                    if p.lower() in {"next", "redirect", "url", "return", "goto",
                                     "callback", "continue", "dest", "link", "path",
                                     "q", "query", "search", "file", "page", "load"}][:15]
    prompt = f"""You are an XSS scan strategist. Design an optimal scan strategy.

Target surface statistics:
- Total URLs collected: {stats['total_urls']}
- Live URLs (httpx alive): {stats['live_urls']}
- Crawled URLs (katana): {stats['katana_urls']}
- Unique GET parameters: {stats['param_urls']}
- High-risk parameter names: {risky_params}
- DOM XSS risks found: {stats['dom_risks']}
- POST-form endpoints detected: {stats['post_forms']}
- Target type hint: {stats['target_hint']}
- WAF status: {stats['waf_status']}

Provide a JSON object with these keys:
{{
  "plan_name": "short descriptive name",
  "skip_phases": ["phase_name"],
  "priority_params": ["param1", "param2"],
  "priority_urls_count": N,
  "thread_level": "low|medium|high",
  "payload_strategy": "standard|heavy_mutations|dom_focused|waf_evasion",
  "browser_validation_urls": N,
  "dalfox_time_limit_seconds": N,
  "katana_time_limit_seconds": N,
  "estimated_total_minutes": N,
  "reasoning": "2-3 sentences",
  "key_decisions": ["decision 1", "decision 2"]
}}

Be specific with numeric values. Choose LOW thread_level if target looks WAF-protected or is a small game. Choose HIGH if large surface with no WAF evidence."""
    return prompt


def run_strategist(stats, llm_client=None):
    """Run the AI strategist and return scan plan dict."""
    if llm_client is None and HAS_AI:
        llm_client = get_llm_client()

    plan = None
    if llm_client and llm_client.is_configured:
        prompt = build_llm_prompt(stats)
        raw = llm_client.chat(prompt, role="scan_strategist", max_tokens=1024)
        if raw:
            json_match = __import__('re').search(r'\{.*\}', raw, __import__('re').DOTALL)
            if json_match:
                try:
                    plan = json.loads(json_match.group())
                except json.JSONDecodeError:
                    pass

    if plan is None:
        # Rule-based fallback
        plan = _fallback_strategy(stats)

    # Merge stats into plan
    plan["stats"] = {k: (list(v) if isinstance(v, set) else v)
                     for k, v in stats.items()}
    return plan


def _fallback_strategy(stats):
    total = stats.get("total_urls", 0)
    live = stats.get("live_urls", 0)
    risks = stats.get("dom_risks", 0)
    post = stats.get("post_forms", 0)

    skip_phases = []
    if total > 5000:
        skip_phases.append("katana_deep_crawl")  # already have enough URLs
    if risks == 0 and total > 100:
        skip_phases.append("dom_analysis")

    if total < 30:
        thread_level = "low"
        browser_urls = min(live, 20)
        dalfox_limit = 60
        katana_limit = 120
    elif total < 200:
        thread_level = "medium"
        browser_urls = min(live, 50)
        dalfox_limit = 120
        katana_limit = 300
    else:
        thread_level = "high"
        browser_urls = min(live, 100)
        dalfox_limit = 180
        katana_limit = 600

    payload_strategy = "standard"
    if stats.get("target_hint") == "dom_xss_game" or risks > 0:
        payload_strategy = "dom_focused"
        skip_phases = [p for p in skip_phases if p != "dom_analysis"]
    if post > 3:
        payload_strategy = "heavy_mutations"
    if stats.get("waf_status") == "blocked":
        payload_strategy = "waf_evasion"

    est_minutes = (total // 200) + (browser_urls // 10) + (risks * 2)

    return {
        "plan_name": f"auto_strategy_{stats.get('target_hint', 'default')}",
        "skip_phases": skip_phases,
        "priority_params": ["q", "query", "search", "next", "redirect", "callback",
                            "url", "return", "file", "page", "load"],
        "priority_urls_count": browser_urls,
        "thread_level": thread_level,
        "payload_strategy": payload_strategy,
        "browser_validation_urls": browser_urls,
        "dalfox_time_limit_seconds": dalfox_limit,
        "katana_time_limit_seconds": katana_limit,
        "estimated_total_minutes": max(5, est_minutes),
        "reasoning": (f"Target has {total} URLs ({live} live), {risks} DOM risks, "
                      f"{post} POST forms. Strategy optimized for {stats.get('target_hint', 'unknown')}."),
        "key_decisions": [
            f"Scan top {browser_urls} URLs in browser",
            f"Use {payload_strategy} payload strategy",
            f"Estimated: {max(5, est_minutes)} minutes",
        ],
        "source": "rule_based_fallback",
    }


# ── CLI ────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AI Scan Strategist")
    parser.add_argument("--urls", default=None, help="all_urls.txt")
    parser.add_argument("--live", default=None, help="live.txt")
    parser.add_argument("--katana", default=None, help="katana.txt")
    parser.add_argument("--dom-risks", default=None, help="dom_risks.txt")
    parser.add_argument("--output-dir", default=".", help="Output directory")
    parser.add_argument("--plan-out", default=None, help="Output plan JSON path")
    parser.add_argument("--no-llm", action="store_true", help="Skip LLM, use rule-based only")
    args = parser.parse_args()

    stats = estimate_stats(args.urls, args.live, args.katana, args.dom_risks)

    if args.no_llm:
        plan = run_strategist(stats, llm_client=None)
    else:
        plan = run_strategist(stats)

    print(f"[*] Strategy: {plan['plan_name']}")
    print(f"    Payload strategy: {plan['payload_strategy']}")
    print(f"    Thread level: {plan['thread_level']}")
    print(f"    Browser URLs: {plan['browser_validation_urls']}")
    print(f"    Estimated: {plan['estimated_total_minutes']} min")
    print(f"    Skip phases: {plan.get('skip_phases', [])}")
    print(f"    Reasoning: {plan.get('reasoning', 'N/A')}")

    if args.plan_out or args.output_dir:
        os.makedirs(args.output_dir or ".", exist_ok=True)
        out = args.plan_out or os.path.join(args.output_dir or ".", "scan_plan.json")
        with open(out, "w") as f:
            json.dump(plan, f, indent=2)
        print(f"\n[OK] Scan plan saved to {out}")
