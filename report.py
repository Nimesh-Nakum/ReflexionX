#!/usr/bin/env python3
"""
XSS ReflexionX v1.0.0 — Professional HTML Report Generator
Aggregates all scan outputs into a professional, self-contained HTML report.

Usage:
    python3 report.py --output-dir ./xss_target.com_20260505_100000
"""

import argparse, json, os, sys
from datetime import datetime, timezone
from pathlib import Path
from html import escape as html_escape


def load_json(filepath, default=None):
    if os.path.isfile(filepath):
        try:
            with open(filepath) as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            pass
    return default if default is not None else {}


def load_lines(filepath):
    if os.path.isfile(filepath):
        with open(filepath) as f:
            return [l.strip() for l in f if l.strip()]
    return []


def classify_severity(finding):
    trigger = finding.get("trigger", "")
    if trigger in ("immediate", "deferred"):
        return "Critical"
    if trigger.startswith("event:"):
        return "High"
    if trigger.startswith("retry:"):
        return "High"
    if trigger == "dialog":
        return "High"
    if trigger == "stored_chain":
        return "Critical"
    if trigger == "fragment_injection":
        return "High"
    return "Medium"


def compute_cvss(finding):
    """Compute CVSS 3.1 base score for an XSS finding."""
    trigger = finding.get("trigger", "")
    # XSS base: AV:N/AC:L/PR:N/UI:R/S:C (Network, Low complexity, No privs, User interaction)
    # Impact varies by trigger type
    if trigger in ("immediate", "deferred", "stored_chain"):
        return 9.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N"  # Critical
    elif trigger.startswith("event:") or trigger == "dialog":
        return 8.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N"  # High
    elif trigger.startswith("retry:"):
        return 7.5, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:L/A:N"  # High
    elif trigger == "fragment_injection":
        return 6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"  # Medium
    return 5.4, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"  # Medium


def generate_risk_chart_svg(sev):
    """Generate inline SVG donut chart for risk distribution."""
    total = max(sum(sev.values()), 1)
    colors = {"Critical": "#f85149", "High": "#f0883e", "Medium": "#d29922", "Low": "#58a6ff"}
    radius = 60
    cx, cy = 80, 80
    circumference = 2 * 3.14159 * radius
    offset = 0
    arcs = ""
    for label, count in sev.items():
        if count == 0:
            continue
        pct = count / total
        dash = pct * circumference
        gap = circumference - dash
        arcs += (f'<circle cx="{cx}" cy="{cy}" r="{radius}" fill="none" '
                 f'stroke="{colors[label]}" stroke-width="20" '
                 f'stroke-dasharray="{dash:.1f} {gap:.1f}" '
                 f'stroke-dashoffset="{-offset:.1f}" '
                 f'style="transition:all 0.5s"/>')
        offset += dash

    legend = ""
    ly = 20
    for label, count in sev.items():
        if count == 0:
            continue
        legend += (f'<rect x="175" y="{ly}" width="12" height="12" rx="2" '
                   f'fill="{colors[label]}"/>'
                   f'<text x="192" y="{ly+10}" fill="#c9d1d9" '
                   f'font-size="12">{label}: {count}</text>')
        ly += 22

    return (f'<svg viewBox="0 0 280 160" xmlns="http://www.w3.org/2000/svg" '
            f'style="max-width:280px;margin:0 auto;display:block;">'
            f'{arcs}{legend}'
            f'<text x="{cx}" y="{cy+5}" text-anchor="middle" fill="#c9d1d9" '
            f'font-size="22" font-weight="700">{total}</text></svg>')


def generate_report(output_dir):
    """Generate report.html from scan outputs."""
    # Load all data
    confirmed = load_json(os.path.join(output_dir, "browser_validation.json"), [])
    from context_loader import load_contexts_dict
    contexts = load_contexts_dict(output_dir)
    dom_data = load_json(os.path.join(output_dir, "dom_analysis.json"), [])
    scan_state = load_json(os.path.join(output_dir, "scan_state.json"))
    oob_events = load_json(os.path.join(output_dir, "oob_events.json"), [])

    poc_lines = load_lines(os.path.join(output_dir, "poc", "poc.txt"))
    blind_hits = load_lines(os.path.join(output_dir, "blind_xss_hits.txt"))
    confirmed_lines = load_lines(os.path.join(output_dir, "confirmed_execution.txt"))
    event_lines = load_lines(os.path.join(output_dir, "event_triggered.txt"))
    manual_lines = load_lines(os.path.join(output_dir, "manual_review.txt"))
    dom_risks = load_lines(os.path.join(output_dir, "dom_risks.txt"))

    domain = scan_state.get("domain", os.path.basename(output_dir))
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # Severity counts
    sev = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for c in confirmed:
        s = classify_severity(c)
        sev[s] += 1
    risky_dom = [d for d in dom_data if d.get("risk_score", 0) > 10]
    sev["Low"] += len(risky_dom)

    total_findings = sev["Critical"] + sev["High"] + sev["Medium"] + sev["Low"]

    # Build HTML
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ReflexionX Report — {html_escape(domain)}</title>
<style>
:root {{
    --bg: #0d1117; --surface: #161b22; --surface2: #21262d;
    --border: #30363d; --text: #c9d1d9; --text-dim: #8b949e;
    --critical: #f85149; --high: #f0883e; --medium: #d29922; --low: #58a6ff;
    --green: #3fb950; --cyan: #39d2c0; --gradient: linear-gradient(135deg, #58a6ff, #39d2c0);
}}
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ background:var(--bg); color:var(--text); font-family:'Segoe UI',system-ui,sans-serif;
       line-height:1.6; padding:20px; max-width:1200px; margin:0 auto; }}
.header {{ text-align:center; padding:40px 20px; margin-bottom:30px;
           background:var(--surface); border:1px solid var(--border); border-radius:12px; }}
.header h1 {{ font-size:2.2em; background:var(--gradient); -webkit-background-clip:text;
              -webkit-text-fill-color:transparent; margin-bottom:8px; }}
.header .subtitle {{ color:var(--text-dim); font-size:1.1em; }}
.header .meta {{ color:var(--text-dim); font-size:0.9em; margin-top:12px; }}
.stats {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr));
          gap:12px; margin-bottom:30px; }}
.stat {{ background:var(--surface); border:1px solid var(--border); border-radius:10px;
         padding:20px; text-align:center; }}
.stat .value {{ font-size:2em; font-weight:700; }}
.stat .label {{ color:var(--text-dim); font-size:0.85em; text-transform:uppercase; letter-spacing:1px; }}
.stat.critical .value {{ color:var(--critical); }}
.stat.high .value {{ color:var(--high); }}
.stat.medium .value {{ color:var(--medium); }}
.stat.low .value {{ color:var(--low); }}
.stat.total .value {{ color:var(--green); }}
section {{ background:var(--surface); border:1px solid var(--border); border-radius:12px;
           padding:24px; margin-bottom:20px; }}
section h2 {{ font-size:1.4em; margin-bottom:16px; padding-bottom:8px;
              border-bottom:1px solid var(--border); }}
table {{ width:100%; border-collapse:collapse; font-size:0.9em; }}
th {{ background:var(--surface2); color:var(--cyan); text-align:left;
      padding:10px 12px; font-weight:600; }}
td {{ padding:10px 12px; border-bottom:1px solid var(--border); word-break:break-all; }}
tr:hover td {{ background:var(--surface2); }}
.badge {{ display:inline-block; padding:2px 8px; border-radius:4px; font-size:0.8em; font-weight:600; }}
.badge.critical {{ background:rgba(248,81,73,0.2); color:var(--critical); }}
.badge.high {{ background:rgba(240,136,62,0.2); color:var(--high); }}
.badge.medium {{ background:rgba(210,153,34,0.2); color:var(--medium); }}
.badge.low {{ background:rgba(88,166,255,0.2); color:var(--low); }}
.code {{ background:var(--surface2); padding:2px 6px; border-radius:4px; font-family:monospace;
         font-size:0.85em; color:var(--cyan); }}
.flow {{ background:var(--surface2); padding:8px 12px; border-radius:6px; margin:4px 0;
         font-family:monospace; font-size:0.85em; }}
.flow .arrow {{ color:var(--critical); }}
.sanitized {{ color:var(--green); }}
.unsanitized {{ color:var(--critical); }}
pre {{ background:var(--surface2); padding:16px; border-radius:8px; overflow-x:auto;
       font-size:0.85em; color:var(--text); }}
.empty {{ color:var(--text-dim); font-style:italic; padding:20px; text-align:center; }}
.footer {{ text-align:center; color:var(--text-dim); padding:30px; font-size:0.85em; }}
</style>
</head>
<body>

<div class="header">
    <h1>⚡ ReflexionX v1.0.0</h1>
    <div class="subtitle">XSS Security Assessment Report</div>
    <div class="meta">
        Target: <strong>{html_escape(domain)}</strong> &nbsp;|&nbsp;
        Generated: {timestamp} &nbsp;|&nbsp;
        Findings: {total_findings}
    </div>
</div>

<div class="stats">
    <div class="stat total"><div class="value">{total_findings}</div><div class="label">Total</div></div>
    <div class="stat critical"><div class="value">{sev['Critical']}</div><div class="label">Critical</div></div>
    <div class="stat high"><div class="value">{sev['High']}</div><div class="label">High</div></div>
    <div class="stat medium"><div class="value">{sev['Medium']}</div><div class="label">Medium</div></div>
    <div class="stat low"><div class="value">{sev['Low']}</div><div class="label">Low</div></div>
    <div class="stat"><div class="value">{len(poc_lines)}</div><div class="label">PoC URLs</div></div>
    <div class="stat"><div class="value">{len(blind_hits)}</div><div class="label">Blind XSS</div></div>
</div>
"""

    # ── Confirmed XSS Table ──────────────────────────────────
    html += '<section><h2>🎯 Confirmed XSS Findings</h2>\n'
    if confirmed:
        html += '<table><tr><th>Severity</th><th>URL</th><th>Parameter</th><th>Trigger</th><th>Payload</th></tr>\n'
        for c in confirmed:
            s = classify_severity(c)
            html += f"""<tr>
<td><span class="badge {s.lower()}">{s}</span></td>
<td>{html_escape(c.get('url','')[:80])}</td>
<td><span class="code">{html_escape(c.get('param',''))}</span></td>
<td>{html_escape(c.get('trigger',''))}</td>
<td><span class="code">{html_escape(c.get('payload','')[:60])}</span></td>
</tr>\n"""
        html += '</table>\n'
    else:
        html += '<div class="empty">No browser-confirmed XSS found.</div>\n'
    html += '</section>\n'

    # ── Executive Summary (v1.0.0) ───────────────────────────────────
    html += '<section><h2>📊 Executive Summary</h2>\n'
    risk_chart = generate_risk_chart_svg(sev)
    risk_level = "Critical" if sev["Critical"] > 0 else "High" if sev["High"] > 0 else "Medium" if sev["Medium"] > 0 else "Low" if sev["Low"] > 0 else "Clean"
    html += f'<div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;align-items:center;">'
    html += f'<div>{risk_chart}</div>'
    html += f'<div><p>Overall Risk Level: <span class="badge {risk_level.lower()}">{risk_level}</span></p>'
    html += f'<p>This assessment identified <strong>{total_findings}</strong> cross-site scripting vulnerabilities '
    html += f'across the target domain <code>{html_escape(domain)}</code>.</p>'
    if sev["Critical"] > 0:
        html += f'<p style="color:var(--critical);"><strong>⚠️ {sev["Critical"]} critical finding(s)</strong> require immediate remediation. '
        html += f'These allow arbitrary JavaScript execution without user interaction.</p>'
    html += '</div></div></section>\n'

    # ── Reproduction Steps ───────────────────────────────────
    if confirmed:
        html += '<section><h2>📋 Reproduction Steps</h2>\n'
        for i, c in enumerate(confirmed[:20], 1):
            html += f"""<div style="margin-bottom:16px;">
<strong>Finding #{i}</strong> — <span class="badge {classify_severity(c).lower()}">{classify_severity(c)}</span><br>
<strong>URL:</strong> <span class="code">{html_escape(c.get('test_url','')[:120])}</span><br>
<strong>Parameter:</strong> <span class="code">{html_escape(c.get('param',''))}</span><br>
<strong>Payload:</strong><pre>{html_escape(c.get('payload',''))}</pre>
<strong>Steps:</strong><ol>
<li>Open the URL above in a browser</li>
<li>{"Interact with the page (trigger: " + html_escape(c.get('trigger','')) + ")" if 'event:' in c.get('trigger','') else 'The payload executes automatically on page load'}</li>
<li>Verify <code>window._xss_confirmed</code> is set (or observe the injected element)</li>
</ol></div>\n"""
        html += '</section>\n'

    # ── CSP Analysis ─────────────────────────────────────────
    csp_entries = [(u, d.get("csp", {})) for u, d in contexts.items() if d.get("csp", {}).get("raw_csp")]
    if csp_entries:
        html += '<section><h2>🛡️ CSP Analysis</h2>\n'
        html += '<table><tr><th>URL</th><th>Inline</th><th>Eval</th><th>Nonce</th><th>Policy</th></tr>\n'
        for url, csp in csp_entries[:30]:
            inline = "✅" if csp.get("inline_allowed") else "❌"
            evl = "✅" if csp.get("eval_allowed") else "❌"
            nonce = "Required" if csp.get("nonce_required") else "No"
            html += f"""<tr>
<td>{html_escape(url[:60])}</td><td>{inline}</td><td>{evl}</td><td>{nonce}</td>
<td><span class="code">{html_escape(csp.get('raw_csp','')[:80])}</span></td></tr>\n"""
        html += '</table></section>\n'

    # ── DOM XSS Risks ────────────────────────────────────────
    risky_dom_sorted = sorted(risky_dom, key=lambda x: x.get("risk_score", 0), reverse=True)
    if risky_dom_sorted:
        html += '<section><h2>🔍 DOM XSS Risks</h2>\n'
        for r in risky_dom_sorted[:20]:
            method = r.get("analysis_method", "regex")
            html += f"""<div style="margin-bottom:12px; padding:12px; background:var(--surface2); border-radius:8px;">
<strong>{html_escape(r['url'][:80])}</strong>
<span class="badge low">Score: {r['risk_score']}</span>
<span class="code">{method}</span><br>
Sources: {len(r.get('sources',[]))} | Sinks: {len(r.get('sinks',[]))} | Flows: {len(r.get('flows',[]))}<br>\n"""
            for fl in r.get("flows", [])[:5]:
                path = fl.get("flow_path", [fl.get("source", "?"), fl.get("sink", "?")])
                san_class = "sanitized" if fl.get("sanitized") else "unsanitized"
                san_label = "[SANITIZED]" if fl.get("sanitized") else "[UNSANITIZED]"
                arrow_sep = ' <span class="arrow">&rarr;</span> '
                flow_html = arrow_sep.join(html_escape(str(p)) for p in path)
                html += f'<div class="flow">{flow_html} <span class="{san_class}">{san_label}</span></div>\n'
            html += '</div>\n'
        html += '</section>\n'

    # ── Blind XSS ────────────────────────────────────────────
    if blind_hits:
        html += '<section><h2>👁️ Blind XSS Hits</h2>\n<pre>'
        for line in blind_hits:
            html += html_escape(line) + '\n'
        html += '</pre></section>\n'

    # ── Manual Review ────────────────────────────────────────
    if manual_lines:
        html += '<section><h2>📝 Manual Review Required</h2>\n'
        html += f'<p style="color:var(--text-dim);">{len(manual_lines)} endpoints with encoded reflection that may be bypassable with manual crafting.</p>\n<pre>'
        for line in manual_lines[:50]:
            html += html_escape(line) + '\n'
        html += '</pre></section>\n'

    # ── Remediation Recommendations (v1.0.0) ──────────────────────
    if total_findings > 0:
        html += '<section><h2>🛡️ Remediation Recommendations</h2>\n'
        html += '''<table>
<tr><th>Priority</th><th>Recommendation</th><th>Impact</th></tr>
<tr><td><span class="badge critical">P0</span></td>
<td>Implement context-aware output encoding (HTML entity, JS string, URL encoding) at all reflection points</td>
<td>Eliminates all reflected XSS</td></tr>
<tr><td><span class="badge critical">P0</span></td>
<td>Deploy a strict Content Security Policy: <code>script-src \'nonce-{random}\'</code></td>
<td>Blocks inline script execution even if encoding is bypassed</td></tr>
<tr><td><span class="badge high">P1</span></td>
<td>Enable Trusted Types API to lock down dangerous DOM sinks (<code>innerHTML</code>, <code>eval</code>)</td>
<td>Prevents DOM XSS</td></tr>
<tr><td><span class="badge high">P1</span></td>
<td>Add <code>HttpOnly</code> and <code>Secure</code> flags to all session cookies</td>
<td>Limits impact of successful XSS</td></tr>
<tr><td><span class="badge medium">P2</span></td>
<td>Implement DOMPurify for all user-generated HTML rendering</td>
<td>Sanitizes HTML input on client side</td></tr>
<tr><td><span class="badge medium">P2</span></td>
<td>Set <code>X-Content-Type-Options: nosniff</code> and <code>X-Frame-Options: DENY</code> headers</td>
<td>Reduces MIME-type confusion and clickjacking risk</td></tr>
</table></section>\n'''

    # ── CVSS Detail Table (v1.0.0) ───────────────────────────────
    if confirmed:
        html += '<section><h2>📋 CVSS 3.1 Scoring</h2>\n'
        html += '<table><tr><th>Finding</th><th>Score</th><th>Vector</th><th>Severity</th></tr>\n'
        for i, c in enumerate(confirmed[:30], 1):
            score, vector = compute_cvss(c)
            sev_label = classify_severity(c)
            html += f'<tr><td>#{i} {html_escape(c.get("param",""))}</td>'
            html += f'<td><strong>{score}</strong></td>'
            html += f'<td><span class="code">{vector}</span></td>'
            html += f'<td><span class="badge {sev_label.lower()}">{sev_label}</span></td></tr>\n'
        html += '</table></section>\n'

    # ── Footer ───────────────────────────────────────────────
    html += f"""
<div class="footer">
    Generated by <strong>ReflexionX v1.0.0</strong> — Production-Grade XSS Exploitation Framework<br>
    For authorized security testing only. &nbsp;|&nbsp; {timestamp}
</div>

</body>
</html>"""

    report_path = os.path.join(output_dir, "report.html")
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(html)
    return report_path


def main():
    parser = argparse.ArgumentParser(description="ReflexionX v1.0.0 — Professional Report Generator")
    parser.add_argument("--output-dir", default=None, help="Scan output directory")
    parser.add_argument("--test", action="store_true")
    args = parser.parse_args()

    if args.test:
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            # Create minimal test data
            with open(os.path.join(td, "browser_validation.json"), 'w') as f:
                json.dump([{"url": "http://test.com?q=x", "test_url": "http://test.com?q=payload",
                            "param": "q", "payload": "<img src=x>", "trigger": "immediate",
                            "confirmed": True}], f)
            os.makedirs(os.path.join(td, "poc"), exist_ok=True)
            with open(os.path.join(td, "poc", "poc.txt"), 'w') as f:
                f.write("http://test.com?q=x\n")
            path = generate_report(td)
            size = os.path.getsize(path)
            print(f"[OK] Report generated: {path} ({size} bytes)")
        return

    if not os.path.isdir(args.output_dir):
        print(f"[!] Directory not found: {args.output_dir}", file=sys.stderr)
        sys.exit(1)

    path = generate_report(args.output_dir)
    size = os.path.getsize(path)
    print(f"[OK] Report generated: {path} ({size:,} bytes)")


if __name__ == "__main__":
    main()
