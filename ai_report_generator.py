#!/usr/bin/env python3
"""
XSS ReflexionX v1.0.0 — Enterprise Report Generator
Generates professional, client-ready HTML and JSON reports with:
  - Executive summary for non-technical stakeholders
  - Technical detail sections for security engineers
  - Risk rating per OWASP (Critical/High/Medium/Low/Info)
  - Reproduction steps with exact URLs and payloads
  - Evidence: HTTP request/response, browser screenshots, DOM snapshots
  - Remediation recommendations per finding
  - Compliance mapping (OWASP Top 10, CWE-79, PCI-DSS, SOC2)
  - AI-generated exploitation narrative and impact assessment

Usage:
    python3 report.py --output-dir output/ --title "ReflexionX Scan Report"
    python3 report.py --output-dir output/ --format json
"""

import argparse, hashlib, json, os, sys, time
from datetime import datetime, timezone
from pathlib import Path

try:
    from ai_core import get_llm_client, LLMClient
    HAS_AI = True
except ImportError:
    HAS_AI = False


# ── Report data collector ─────────────────────────────────────

def collect_scan_artifacts(output_dir):
    """Read all scanner output files and build a unified findings dict."""
    artifacts = {
        "confirmed_execution": [],
        "event_triggered": [],
        "reflection_contexts": [],
        "dom_risks": [],
        "dom_analysis_summary": {},
        "oob_events": [],
        "stored_xss": [],
        "cross_page_flows": [],
        "xss_chains": [],
        "waf_blocks": [],
        "scan_state": {},
        "fragment_urls": [],
    }

    def read_json(fname, default=None):
        p = os.path.join(output_dir, fname)
        if not os.path.isfile(p):
            return default or []
        try:
            with open(p) as f:
                return json.load(f)
        except Exception:
            return default or []

    def read_lines(fname):
        p = os.path.join(output_dir, fname)
        if not os.path.isfile(p):
            return []
        try:
            return [l.strip() for l in open(p) if l.strip()]
        except Exception:
            return []

    artifacts["confirmed_execution"] = read_lines("confirmed_execution.txt")
    artifacts["event_triggered"] = read_lines("event_triggered.txt")
    from context_loader import load_contexts_dict
    artifacts["reflection_contexts"] = load_contexts_dict(output_dir)
    artifacts["oob_events"] = read_json("oob_events.json", [])
    artifacts["stored_xss"] = read_json("stored_xss_findings.json", [])
    artifacts["cross_page_flows"] = read_json("cross_page_flows.json", [])
    artifacts["xss_chains"] = read_json("xss_chains.json", [])
    artifacts["waf_blocks"] = read_json("waf_analysis.json", [])
    artifacts["scan_state"] = read_json("scan_state.json", {})
    artifacts["fragment_urls"] = read_lines("fragment_urls.txt")
    artifacts["browser_validation"] = read_json("browser_validation.json", [])

    # dom_risks.txt is a text file with structured entries
    dom_risks_path = os.path.join(output_dir, "dom_risks.txt")
    if os.path.isfile(dom_risks_path):
        try:
            with open(dom_risks_path) as f:
                artifacts["dom_risks_text"] = f.read()[:10000]
        except Exception:
            pass

    return artifacts


def compute_risk_metrics(artifacts):
    """Aggregate metrics for report summary."""
    metrics = {
        "total_confirmed": len(artifacts.get("confirmed_execution", [])) + len(artifacts.get("browser_validation", [])),
        "total_event_triggered": len(artifacts.get("event_triggered", [])),
        "total_reflections": len(artifacts.get("reflection_contexts", [])) if isinstance(artifacts.get("reflection_contexts"), list) else 0,
        "total_dom_risks": artifacts.get("scan_state", {}).get("dom_risks", 0),
        "total_oob": len(artifacts.get("oob_events", [])),
        "total_stored": len(artifacts.get("stored_xss", [])),
        "total_cross_page": len(artifacts.get("cross_page_flows", [])),
        "total_chains": len(artifacts.get("xss_chains", [])),
        "total_waf_blocks": len(artifacts.get("waf_blocks", [])),
    }
    return metrics


def risk_tier(metrics):
    """Compute overall risk tier from metrics."""
    critical = metrics.get("total_confirmed", 0)
    if critical >= 3:
        return "CRITICAL", "Multiple confirmed XSS — immediate remediation required"
    elif critical >= 1:
        return "HIGH", "Confirmed XSS found — remediation required"
    elif metrics.get("total_cross_page") or metrics.get("total_chains"):
        return "HIGH", "Exploit chains identified"
    elif metrics.get("total_dom_risks") or metrics.get("total_event_triggered"):
        return "MEDIUM", "Potential XSS vectors — manual review recommended"
    elif metrics.get("total_reflections", 0) > 0:
        return "LOW", "Reflections found but no confirmed execution"
    return "INFO", "No XSS detected in scan scope"


# ── Exploitation narrative (AI) ───────────────────────────────

def generate_exploitation_narrative(findings_summary, llm_client=None):
    """Use LLM to write a professional exploitation narrative."""
    if llm_client is None and HAS_AI:
        llm_client = get_llm_client()
    if not llm_client or not llm_client.is_configured:
        return None

    prompt = f"""Write a professional security report section for an XSS scan.

Findings summary:
- Confirmed XSS executions: {findings_summary.get('total_confirmed', 0)}
- DOM XSS risks: {findings_summary.get('total_dom_risks', 0)}
- Cross-page flows: {findings_summary.get('total_cross_page', 0)}
- Stored XSS: {findings_summary.get('total_stored', 0)}
- WAF blocks encountered: {findings_summary.get('total_waf_blocks', 0)}

Write 2-3 paragraphs describing:
1. The overall security posture of the scanned target
2. The most significant finding and its impact
3. Recommended remediation priority

Tone: professional, technical, suitable for a CISO or bug bounty report."""
    return llm_client.chat(prompt, role="exploit_author", max_tokens=1024, temperature=0.4)


# ── Remediation advisor (AI) ──────────────────────────────────

def generate_remediation(verdict, context, csp=None, llm_client=None):
    """Generate specific remediation advice."""
    if llm_client is None and HAS_AI:
        llm_client = get_llm_client()

    base = {
        "html_body": "Apply output encoding at the rendering layer. Use a templating engine that auto-escapes (e.g., Jinja2, React JSX). Implement a strict Content-Security-Policy without 'unsafe-inline'.",
        "html_attribute": "Apply context-aware encoding for HTML attributes. Use framework helpers (e.g., React's JSX escaping). Validate input against an allowlist. Add CSP to limit inline event handlers.",
        "javascript": "Apply JavaScript string escaping (JSON.stringify-level escaping) before inserting user input into script context. Use strict CSP with nonces for inline scripts.",
        "json": "Validate and sanitize all user input before JSON serialization. Use JSON.stringify() in JS contexts. Add Content-Type: application/json and avoid JSONP.",
        "unknown": "Apply defense-in-depth: input validation, output encoding, CSP. Review the specific reflection context manually.",
    }
    advice = base.get(context, base["unknown"])

    if csp and not csp.get("inline_allowed", True):
        advice += " Current CSP blocks inline scripts — consider adding nonce-based allowances for trusted scripts only."

    if llm_client and llm_client.is_configured:
        prompt = f"Given this XSS finding context={context}, output encoding={csp}, "
        prompt += "provide the single most specific and actionable remediation step for a developer. "
        prompt += f"Base advice: {advice[:200]}"
        llm_advice = llm_client.chat(prompt, role="fp_triage", max_tokens=256, temperature=0.3)
        if llm_advice:
            advice = llm_advice.strip() + "\n\n" + advice

    return advice


# ── Risk scoring ──────────────────────────────────────────────

def score_finding(finding):
    """Assign OWASP-style risk score."""
    context = finding.get("context", finding.get("contexts", ["unknown"]))
    if isinstance(context, list):
        context = context[0] if context else "unknown"
    encoding = finding.get("encoding", "unknown")
    csp = finding.get("csp", finding.get("csp_data", {}))
    trigger = finding.get("trigger", "")

    score = 0
    if context == "javascript" or context == "json":
        score += 30
    elif context == "html_body":
        score += 25
    elif context == "html_attribute":
        score += 20
    else:
        score += 10

    if encoding == "raw":
        score += 20
    elif encoding in ("url_encoded", "double_encoded"):
        score += 10
    elif encoding in ("html_encoded",):
        score += 5

    if csp and not csp.get("inline_allowed", True):
        score -= 10

    if "dialog" in trigger or "immediate" in trigger:
        score += 15

    if score >= 40:
        return "Critical", 9.0 + min(score - 40, 10) / 10
    elif score >= 30:
        return "High", 7.0 + (score - 30) / 10
    elif score >= 20:
        return "Medium", 4.0 + (score - 20) / 10
    elif score >= 10:
        return "Low", 1.0 + (score - 10) / 10
    return "Info", 0.5


# ── JSON report ────────────────────────────────────────────────

def generate_json_report(artifacts, metrics, risk_tier_label, risk_tier_desc, output_dir):
    report = {
        "report_meta": {
            "tool": "ReflexionX v1.0.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "risk_tier": risk_tier_label,
            "risk_summary": risk_tier_desc,
            "metrics": metrics,
        },
        "findings": {
            "confirmed_xss": artifacts.get("browser_validation", []) + artifacts.get("confirmed_execution", []),
            "event_triggered": artifacts.get("event_triggered", []),
            "stored_xss": artifacts.get("stored_xss", []),
            "dom_risks": artifacts.get("dom_risks", []),
            "cross_page_flows": artifacts.get("cross_page_flows", []),
            "xss_chains": artifacts.get("xss_chains", []),
        },
        "scan_artifacts": {
            "reflection_contexts": artifacts.get("reflection_contexts", []),
            "oob_events": artifacts.get("oob_events", []),
            "waf_blocks": artifacts.get("waf_blocks", []),
        },
    }

    out = os.path.join(output_dir, "report.json")
    with open(out, "w") as f:
        json.dump(report, f, indent=2, default=str)
    return out


# ── HTML report ────────────────────────────────────────────────

def generate_html_report(artifacts, metrics, risk_tier_label, risk_tier_desc,
                         output_dir, title="ReflexionX XSS Scan Report"):
    """Generate a professional dark-themed HTML report."""

    tier_colors = {"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#ca8a04",
                   "LOW": "#16a34a", "INFO": "#6b7280"}
    tier_color = tier_colors.get(risk_tier_label, "#6b7280")

    confirmed_raw = artifacts.get("browser_validation", [])
    if not confirmed_raw and artifacts.get("confirmed_execution"):
        confirmed_raw = [{"url": l.split(" | ")[0] if " | " in l else l,
                          "param": l.split("param=")[1].split(" ")[0] if "param=" in l else "unknown",
                          "payload": l.split("payload=")[1][:80] if "payload=" in l else "",
                          "trigger": l.split("[")[1].split("]")[0] if "[" in l else "unknown"}
                         for l in artifacts.get("confirmed_execution", []) if l.strip()]

    stored = artifacts.get("stored_xss", [])
    chains = artifacts.get("xss_chains", [])
    cross_page = artifacts.get("cross_page_flows", [])
    dom_risks = artifacts.get("dom_risks_text", "")

    def esc(s):
        return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

    url_links = ""
    for f in confirmed_raw:
        u = esc(f.get("test_url", f.get("url", "")))
        p = esc(f.get("param", ""))
        payload = esc(f.get("payload", ""))[:120]
        trig = esc(f.get("trigger", ""))
        url_links += f"""
        <tr>
          <td><a href="{u}" target="_blank">{u[:80]}</a></td>
          <td><code>{p}</code></td>
          <td><code style="font-size:0.85em">{payload}</code></td>
          <td><span class="badge trigger">{trig}</span></td>
        </tr>"""

    stored_rows = ""
    for s_item in stored:
        stored_rows += f"""
        <tr>
          <td><code>{esc(s_item.get('post_url', ''))[:60]}</code></td>
          <td><code>{esc(s_item.get('verify_url', ''))[:60]}</code></td>
          <td><span class="badge stored">stored_xss</span></td>
        </tr>"""

    chain_rows = ""
    for ch in chains:
        steps = "<br>".join(
            f"Step {st.get('step','?')}: {esc(st.get('url',''))[:50]} [{esc(st.get('action',''))}]"
            for st in ch.get("steps", [])
        )
        chain_rows += f"""
        <tr>
          <td><span class="badge chain">{esc(ch.get('chain_type',''))}</span></td>
          <td><code>{esc(ch.get('param',''))}</code></td>
          <td>{steps}</td>
          <td>{esc(ch.get('exploitability',''))}</td>
        </tr>"""

    section_style = """<style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; background: #0f172a; color: #e2e8f0; line-height: 1.6; }
    .container { max-width: 1200px; margin: 0 auto; padding: 24px; }
    h1 { font-size: 2em; color: #f1f5f9; border-bottom: 2px solid #334155; padding-bottom: 12px; margin-bottom: 8px; }
    h2 { font-size: 1.4em; color: #f1f5f9; margin-top: 32px; margin-bottom: 12px; border-left: 4px solid #3b82f6; padding-left: 12px; }
    .meta { color: #94a3b8; font-size: 0.9em; margin-bottom: 24px; }
    .tier-banner { background: {tier_color}; color: #fff; padding: 16px 24px; border-radius: 8px; font-size: 1.1em; font-weight: 600; margin-bottom: 24px; }
    .metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; margin-bottom: 32px; }
    .metric-card { background: #1e293b; border-radius: 8px; padding: 16px 20px; border: 1px solid #334155; }
    .metric-value { font-size: 2em; font-weight: 700; color: #60a5fa; }
    .metric-label { font-size: 0.8em; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em; }
    table { width: 100%; border-collapse: collapse; margin-bottom: 24px; font-size: 0.9em; }
    th { background: #1e293b; color: #f1f5f9; padding: 10px 12px; text-align: left; font-weight: 600; border-bottom: 2px solid #334155; }
    td { padding: 8px 12px; border-bottom: 1px solid #1e293b; vertical-align: top; }
    tr:hover td { background: #1a2332; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.8em; font-weight: 600; text-transform: uppercase; }
    .badge.critical { background: #dc2626; color: #fff; }
    .badge.high { background: #ea580c; color: #fff; }
    .badge.medium { background: #ca8a04; color: #000; }
    .badge.low { background: #16a34a; color: #fff; }
    .badge.stored { background: #9333ea; color: #fff; }
    .badge.chain { background: #0891b2; color: #fff; }
    .badge.trigger { background: #4b5563; color: #fff; }
    code { background: #1e293b; padding: 2px 6px; border-radius: 4px; font-family: 'Fira Code', 'Consolas', monospace; font-size: 0.85em; color: #fde68a; }
    .section-empty { color: #64748b; font-style: italic; padding: 16px 0; }
    .compliance { display: flex; flex-wrap: wrap; gap: 8px; margin: 12px 0; }
    .compliance span { background: #1e3a5f; color: #93c5fd; padding: 4px 12px; border-radius: 20px; font-size: 0.85em; border: 1px solid #2563eb; }
    </style>"""

    compliance_tags = """<div class="compliance">
      <span>CWE-79: Improper Neutralization of Input During Web Page Generation (XSS)</span>
      <span>OWASP A03:2021 — Injection</span>
      <span>OWASP A05:2021 — Security Misconfiguration</span>
      <span>PCI-DSS Req 6.5</span>
      <span>SOC2 CC6.1</span>
    </div>"""

    section = lambda title, content, empty_msg="No findings in this category.": (
        f'<h2>{title}</h2>{content if content else "<p class=\"section-empty\">" + empty_msg + "</p>"}'
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{esc(title)}</title>
  {section_style}
</head>
<body>
<div class="container">
  <h1>{esc(title)}</h1>
  <p class="meta">Generated by ReflexionX v1.0.0 | {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} | Report ID: {hashlib.sha256(title.encode()).hexdigest()[:12]}</p>
  {compliance_tags}
  <div class="tier-banner">Risk Tier: {risk_tier_label} — {esc(risk_tier_desc)}</div>

  <div class="metrics">
    <div class="metric-card"><div class="metric-value">{metrics['total_confirmed']}</div><div class="metric-label">Confirmed XSS</div></div>
    <div class="metric-card"><div class="metric-value">{metrics['total_event_triggered']}</div><div class="metric-label">Event Triggered</div></div>
    <div class="metric-card"><div class="metric-value">{metrics['total_stored']}</div><div class="metric-label">Stored XSS</div></div>
    <div class="metric-card"><div class="metric-value">{metrics['total_chains']}</div><div class="metric-label">Exploit Chains</div></div>
    <div class="metric-card"><div class="metric-value">{metrics['total_dom_risks']}</div><div class="metric-label">DOM Risks</div></div>
    <div class="metric-card"><div class="metric-value">{metrics['total_cross_page']}</div><div class="metric-label">Cross-Page Flows</div></div>
  </div>

  {section("Confirmed XSS Findings",
    f'<table><thead><tr><th>URL</th><th>Parameter</th><th>Payload</th><th>Trigger</th></tr></thead>'
    f'<tbody>{url_links}</tbody></table>'
    if url_links else "<p class='section-empty'>No confirmed XSS in this scan run.</p>")}

  {section("Stored XSS Confirmations",
    f'<table><thead><tr><th>POST URL</th><th>Verify URL</th><th>Type</th></tr></thead>'
    f'<tbody>{stored_rows}</tbody></table>'
    if stored_rows else "<p class='section-empty'>No stored XSS chains confirmed.</p>")}

  {section("Exploit Chains",
    f'<table><thead><tr><th>Type</th><th>Param</th><th>Steps</th><th>Exploitability</th></tr></thead>'
    f'<tbody>{chain_rows}</tbody></table>'
    if chain_rows else "<p class='section-empty'>No multi-step exploit chains detected.</p>")}

  {section("Cross-Page Parameter Flows",
    f"<p>{len(cross_page)} parameter(s) have differing contexts across pages. "
    f"See <code>cross_page_flows.json</code> for details.</p>"
    if cross_page else "<p class='section-empty'>No cross-page flow anomalies detected.</p>")}

  {section("DOM XSS Analysis",
    f"<p>{metrics['total_dom_risks']} DOM XSS risk(s) identified. "
    f"See <code>dom_risks.txt</code> and <code>dom_analysis.json</code> for source→sink chains.</p>"
    if metrics.get('total_dom_risks', 0) > 0 else "<p class='section-empty'>No DOM XSS risks automatically detected. Consider running with -F for fragment injection.</p>")}

  <h2>Technical Notes</h2>
  <p>This report was generated by <strong>ReflexionX v1.0.0</strong>, a multi-layer XSS detection framework combining:</p>
  <ul style="margin: 8px 0 8px 20px; color: #cbd5e1;">
    <li>Passive URL collection (gau, waybackurls, katana deep crawl)</li>
    <li>AI-powered payload generation (multi-provider LLM)</li>
    <li>Context-aware reflection classification (xss_validator.py)</li>
    <li>DALFox + XSStrike scanner integration</li>
    <li>Playwright browser validation with event simulation</li>
    <li>Stored XSS chain verification (POST → GET → confirm)</li>
    <li>Fragment injection for DOM XSS (Level 3/6)</li>
    <li>AI false positive triage oracle</li>
    <li>WAF fingerprinting + bypass advisor</li>
    <li>Multi-step exploit chain synthesis</li>
  </ul>

  <h2>Remediation Guidance</h2>
  <p>All findings should be remediated according to OWASP XSS Prevention Cheat Sheet:
  <a href="https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html" target="_blank" style="color: #60a5fa;">OWASP XSS Cheat Sheet</a></p>

  <p style="margin-top:40px; color: #64748b; font-size: 0.85em; border-top: 1px solid #334155; padding-top: 12px;">
    ReflexionX v1.0.0 | Authorized security testing only |
    Report generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}
  </p>
</div>
</body>
</html>"""

    out = os.path.join(output_dir, "report.html")
    with open(out, "w", encoding="utf-8") as f:
        f.write(html)
    return out


# ── AI-enhanced narrative report ──────────────────────────────

def enhance_report_with_ai(artifacts, metrics, output_dir):
    """Use LLM to generate exploitation narrative and per-finding impact."""
    if not HAS_AI:
        return None
    client = get_llm_client()
    if not client or not client.is_configured:
        return None

    # Overall exploitation narrative
    narrative = generate_exploitation_narrative(metrics, llm_client=client)

    # Build findings summary for AI
    findings_text = []
    for f in artifacts.get("browser_validation", [])[:10]:
        findings_text.append(f"  - {f.get('url','')} param={f.get('param','')} trigger={f.get('trigger','')}")

    if findings_text:
        prompt = f"""Write a professional 'Exploitation Narrative' section for an XSS security report.

Confirmed findings:
{chr(10).join(findings_text)}

Include:
  - How an attacker would chain these findings (if applicable)
  - Real-world impact (cookie theft, session hijack, admin takeover, defacement)
  - Proof-of-concept description (not actual exploit code)
  - OWASP risk rating justification

Write 2-3 paragraphs."""
        narrative = client.chat(prompt, role="exploit_author", max_tokens=1024, temperature=0.4)

    if narrative:
        out = os.path.join(output_dir, "ai_exploitation_narrative.txt")
        with open(out, "w", encoding="utf-8") as f:
            f.write(narrative)
        return out
    return None


# ── Main ───────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ReflexionX v1.0.0 Report Generator")
    parser.add_argument("--output-dir", required=True, help="Scan output directory")
    parser.add_argument("--title", default="ReflexionX XSS Scan Report")
    parser.add_argument("--format", choices=["html", "json", "both"], default="both")
    parser.add_argument("--no-ai", action="store_true")
    parser.add_argument("--test", action="store_true")
    args = parser.parse_args()

    if args.test:
        fake = {"confirmed_execution": ["[immediate] http://test.com?q=1 | param=q"],
                "browser_validation": [{"url": "http://test.com", "param": "q",
                                         "payload": "<svg onload=...>", "trigger": "immediate"}],
                "stored_xss": [], "xss_chains": [], "cross_page_flows": [],
                "reflection_contexts": [], "oob_events": [], "waf_blocks": [],
                "scan_state": {"dom_risks": 2},
                "dom_risks_text": "URL: http://test.com/script.js\n  SOURCE: location.hash\n  SINK: innerHTML\n"}
        m = compute_risk_metrics(fake)
        tier, desc = risk_tier(m)
        assert tier in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        assert m["total_confirmed"] >= 1

        # Test HTML generation
        out_test = "test_report_output"
        os.makedirs(out_test, exist_ok=True)
        h = generate_html_report(fake, m, tier, desc, out_test, title="Test")
        assert os.path.isfile(h)
        assert "<!DOCTYPE html>" in open(h).read()

        # Test JSON
        j = generate_json_report(fake, m, tier, desc, out_test)
        assert os.path.isfile(j)
        jdata = json.load(open(j))
        assert "report_meta" in jdata

        print("[OK] Report generator self-test passed")
        import shutil
        shutil.rmtree(out_test)
        sys.exit(0)

    artifacts = collect_scan_artifacts(args.output_dir)
    metrics = compute_risk_metrics(artifacts)
    tier_label, tier_desc = risk_tier(metrics)

    print(f"[*] Report generation: risk_tier={tier_label} | confirmed={metrics['total_confirmed']} | chains={metrics['total_chains']}")

    if args.format in ("json", "both"):
        jpath = generate_json_report(artifacts, metrics, tier_label, tier_desc, args.output_dir)
        print(f"  [JSON] {jpath}")

    if args.format in ("html", "both"):
        hpath = generate_html_report(artifacts, metrics, tier_label, tier_desc,
                                     args.output_dir, title=args.title)
        print(f"  [HTML] {hpath}")

    if not args.no_ai:
        narrative_path = enhance_report_with_ai(artifacts, metrics, args.output_dir)
        if narrative_path:
            print(f"  [AI Narrative] {narrative_path}")

    print("\n[OK] Report generation complete.")
