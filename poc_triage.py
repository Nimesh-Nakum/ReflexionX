#!/usr/bin/env python3
"""
XSS ReflexionX v1.0.0 — POC Triage Engine
Eliminates dalfox false positives by cross-referencing with browser-confirmed
executions and provides detailed failure reason classification.
For authorized security testing only.

Usage:
    python3 poc_triage.py --output-dir ./out --poc-dir ./out/poc
"""

import argparse, json, os, re, sys, shutil, time
from urllib.parse import urlparse, parse_qs, unquote
from datetime import datetime

try:
    from logger import ScanLogger
except ImportError:
    ScanLogger = None

# Failure Reasons
F_CONCAT = "CONCAT"
F_NO_EXEC = "NO_EXEC"
F_ENCODED = "ENCODED"
F_NO_BREAKOUT = "NO_BREAKOUT"
F_CSP = "CSP"
F_SANITIZED = "SANITIZED"
F_ATTR_CONTEXT = "ATTR_CONTEXT"

from context_loader import load_contexts

def load_confirmed(output_dir):
    conf_file = os.path.join(output_dir, "confirmed_execution.txt")
    confirmed = set()
    if os.path.isfile(conf_file):
        with open(conf_file) as f:
            for line in f:
                parts = line.split(" | ")
                if parts:
                    url_part = parts[0].strip()
                    if "] " in url_part:
                        url_part = url_part.split("] ", 1)[1]
                    url_part = url_part.strip()
                    if url_part:
                        confirmed.add(url_part)
    dalfox_file = os.path.join(output_dir, "dalfox.txt")
    if os.path.isfile(dalfox_file):
        with open(dalfox_file, errors='ignore') as f:
            for line in f:
                if "[POC][V]" in line or "[POC][G]" in line:
                    m = re.search(r'https?://[^\s]+', line)
                    if m:
                        confirmed.add(m.group(0))
    return confirmed

def detect_failure(poc_content, poc_url, contexts_data):
    if "-none" in poc_content:
        return F_NO_EXEC, "dalfox flagged -none context (e.g., inJS-none)", None, None

    parsed_url = urlparse(poc_url)
    params = parse_qs(parsed_url.query, keep_blank_values=True)
    
    injected_param = None
    injected_val = None
    
    for param, vals in params.items():
        val = vals[0]
        if re.search(r'(alert|confirm|prompt|<script|<img)', val, re.IGNORECASE):
            injected_param = param
            injected_val = val
            break
            
    if not injected_param and params:
        injected_param = max(params.keys(), key=lambda k: len(params[k][0]))
        injected_val = params[injected_param][0]
        
    if not injected_param:
        m = re.search(r'(?:DOM Object\):\s*|\[POC\].*\?|payload:\s*)([\w\[\]_-]+)=([^\s\n]+)', poc_content)
        if m:
            injected_param = m.group(1)
            injected_val = unquote(m.group(2))
        
    base_url = poc_url.split("?")[0] if "?" in poc_url else poc_url
    url_context = {}
    if isinstance(contexts_data, dict):
        url_context = contexts_data.get(base_url, {})
    elif isinstance(contexts_data, list):
        for entry in contexts_data:
            if entry.get("url") == base_url or entry.get("target_url") == base_url:
                url_context = entry
                break
                
    param_context_info = {}
    if url_context:
        for p in url_context.get("parameters", []):
            if p.get("name") == injected_param:
                param_context_info = p
                break
                
    contexts = param_context_info.get("contexts", ["unknown"])
    encodings = param_context_info.get("encodings", [])
    
    if injected_param:
        val = injected_val
        if val and re.search(r'[a-zA-Z0-9](alert|confirm|prompt|<script|<img|<svg)', val, re.IGNORECASE):
            return F_CONCAT, f"Payload '{val}' appended directly with no breakout character", injected_param, injected_val

    if injected_param:
        val = injected_val
        # Check if payload contains URL-encoded special chars
        if val and ("%3C" in val or "%3E" in val or "%22" in val or "%27" in val):
            raw_val = unquote(val)
            # If decoded payload doesn't appear in the server response, encoding was preserved
            if raw_val not in poc_content:
                return F_ENCODED, "Payload characters are URL-encoded and server does not decode them", injected_param, injected_val

    csp = url_context.get("csp", {})
    if csp and (not csp.get("inline_allowed", True) or csp.get("nonce_required", False)):
        return F_CSP, "Blocked by Content-Security-Policy (inline blocked or nonce required)", injected_param, injected_val
        
    if "javascript" in contexts or "json" in contexts:
        if injected_param:
            val = injected_val
            if val and not any(q in val for q in ["'", '"', "`", "</script>"]):
                 return F_NO_BREAKOUT, "Inside JS string but no quote breakout character present", injected_param, injected_val

    if "html_encoded" in encodings:
        return F_SANITIZED, "Payload was HTML-entity encoded by the application", injected_param, injected_val
        
    if "html_attribute" in contexts and "raw" not in encodings:
         return F_ATTR_CONTEXT, "In HTML attribute but event handler breakout failed or encoded", injected_param, injected_val

    return "UNKNOWN", "Failed to determine specific execution blocker", injected_param, injected_val

def generate_fix_suggestion(reason, param_name, contexts):
    if reason == F_CONCAT:
        return f"Try: ?{param_name}=VALUE\"><img src=x onerror=alert(1)> (break out of value context first)"
    elif reason == F_NO_EXEC:
        return "Manual review required. Check if execution is possible despite dalfox label."
    elif reason == F_ENCODED:
        return "Try double URL encoding or check if backend decodes specific sequences."
    elif reason == F_NO_BREAKOUT:
        return f"Try escaping JS string: ?{param_name}=VALUE'-alert(1)-' or ?{param_name}=VALUE\\\"-alert(1)//"
    elif reason == F_CSP:
        return "Analyze CSP. Look for JSONP endpoints, open redirects, or angularjs bypasses."
    elif reason == F_SANITIZED:
        return "Look for alternative contexts or parameters that might not be sanitized."
    elif reason == F_ATTR_CONTEXT:
        return f"Try specific attribute breakouts like ' autofocus onfocus=alert(1) x='"
    return "Manual review required in browser."

class PoCTriage:
    """Manages PoC triage by merging results from multiple scanners."""

    def __init__(self, output_dir, target):
        self.output_dir = output_dir
        self.target = target
        self._confirmed = set()
        self._unconfirmed = []

    def _merge_dalfox(self, filepath):
        with open(filepath) as f:
            for line in f:
                line = line.strip()
                if not line or not line.startswith("[POC]"):
                    continue
                m = re.search(r'https?://[^\s]+', line)
                if m:
                    self._confirmed.add(m.group(0))

    def _merge_xsstrike(self, filepath):
        with open(filepath) as f:
            content = f.read()
        if "alert(1)" in content:
            m = re.search(r'https?://[^\s]+', content)
            url = m.group(0) if m else f"http://{self.target}/"
            self._confirmed.add(url)

    def _save_all(self):
        os.makedirs(os.path.join(self.output_dir, "poc", "confirmed"), exist_ok=True)
        os.makedirs(os.path.join(self.output_dir, "poc", "unconfirmed"), exist_ok=True)
        conf_file = os.path.join(self.output_dir, "confirmed_execution.txt")
        with open(conf_file, "w") as f:
            for url in sorted(self._confirmed):
                f.write(f"[CONFIRMED] {url}\n")

    def get_confirmed(self):
        return list(self._confirmed)


def main():
    parser = argparse.ArgumentParser(description="XSS ReflexionX v1.0.0 — POC Triage Engine")
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--poc-dir", default=None)
    parser.add_argument("--test", action="store_true")
    args = parser.parse_args()

    if args.test:
        import tempfile
        import time

        with tempfile.TemporaryDirectory() as td:
            df = os.path.join(td, "dalfox.txt")
            xs = os.path.join(td, "xsstrike.txt")
            with open(df, 'w') as f:
                f.write("[POC][G]http://test.com?q=1\n[POC][V]Reflected: http://test.com?q=1 on parameter q [GET]\n")
            with open(xs, 'w') as f:
                f.write("  reflecting input: |<script>alert(1)</script>| back into the page\n")

            triage = PoCTriage(output_dir=td, target="test.com")
            triage._merge_dalfox(df)
            triage._merge_xsstrike(xs)
            triage._save_all()

            time.sleep(0.5)
            confirmed = triage.get_confirmed()
            print(f"[TEST] PoC Triage: {len(confirmed)} confirmed items")
            assert len(confirmed) >= 1, f"Expected at least 1 confirmed, got {len(confirmed)}"
            print(f"[TEST] Confirmed items: {confirmed[:2]}")
            print("[OK] poc_triage.py self-test passed")
        sys.exit(0)

    if not args.output_dir or not args.poc_dir:
        parser.error("--output-dir and --poc-dir are required (use --test for self-test)")

    if not os.path.isdir(args.poc_dir):
        print(f"[!] POC directory not found: {args.poc_dir}", file=sys.stderr)
        sys.exit(1)

    logger = None
    if ScanLogger:
        logger = ScanLogger(args.output_dir, component="poc_triage")
        logger.log_phase("poc_triage", status="started")

    print("[*] Starting POC Triage...")
    
    contexts_data = load_contexts(args.output_dir)
    confirmed_urls = load_confirmed(args.output_dir)
    
    poc_files = [f for f in os.listdir(args.poc_dir) if f.endswith(".txt") and f != "poc.txt"]
    
    confirmed_dir = os.path.join(args.poc_dir, "confirmed")
    unconfirmed_dir = os.path.join(args.poc_dir, "unconfirmed")
    
    os.makedirs(confirmed_dir, exist_ok=True)
    os.makedirs(unconfirmed_dir, exist_ok=True)
    
    confirmed_count = 0
    unconfirmed_count = 0
    failure_stats = {F_CONCAT: 0, F_NO_EXEC: 0, F_ENCODED: 0, F_NO_BREAKOUT: 0, F_CSP: 0, F_SANITIZED: 0, F_ATTR_CONTEXT: 0, "UNKNOWN": 0}
    unconfirmed_details = []

    for filename in poc_files:
        filepath = os.path.join(args.poc_dir, filename)
        with open(filepath, "r") as f:
            content = f.read()
            
        url_match = re.search(r'URL:\s*(https?://[^\s]+)', content)
        if not url_match:
            continue
            
        poc_url = url_match.group(1)
        
        is_confirmed = (
            "[POC][V]" in content or
            "[POC][G]" in content or
            poc_url in confirmed_urls or
            any(c in content or content in c or (c.split("?")[0] == poc_url.split("?")[0] and c.split("?")[0] != c) for c in confirmed_urls)
        )
        if is_confirmed:
            confirmed_count += 1
            dest = os.path.join(confirmed_dir, filename)
            if os.path.exists(dest):
                try: os.remove(dest)
                except OSError: pass
            shutil.move(filepath, dest)
        else:
            unconfirmed_count += 1
            dest = os.path.join(unconfirmed_dir, filename)
            if os.path.exists(dest):
                try: os.remove(dest)
                except OSError: pass
            shutil.move(filepath, dest)
            
            reason, desc, injected_param, injected_val = detect_failure(content, poc_url, contexts_data)
            failure_stats[reason] += 1
            
            injected_param = injected_param if injected_param else "?"
            
            base_url = poc_url.split("?")[0] if "?" in poc_url else poc_url
            url_context = {}
            if isinstance(contexts_data, dict):
                url_context = contexts_data.get(base_url, {})
            elif isinstance(contexts_data, list):
                for entry in contexts_data:
                    if entry.get("url") == base_url or entry.get("target_url") == base_url:
                        url_context = entry
                        break
            ctx_str = "unknown"
            if url_context:
                for p in url_context.get("parameters", []):
                    if p.get("name") == injected_param:
                        ctx_str = f"{','.join(p.get('contexts', ['unknown']))} ({','.join(p.get('encodings', ['raw']))})"
                        break
            
            fix = generate_fix_suggestion(reason, injected_param, ctx_str)
            
            unconfirmed_details.append({
                "url": poc_url,
                "param": injected_param,
                "context": ctx_str,
                "reason_code": reason,
                "reason_desc": desc,
                "fix": fix
            })

    total = confirmed_count + unconfirmed_count
    
    report_path = os.path.join(args.output_dir, "triage_report.txt")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("═══════════════════════════════════════════════════════════════\n")
        f.write("  POC TRIAGE REPORT — ReflexionX v1.0.0\n")
        f.write(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("═══════════════════════════════════════════════════════════════\n\n")
        
        f.write("  SUMMARY\n")
        f.write("  ───────────────────────────────────────────────────────────\n")
        f.write(f"  Total POCs analyzed : {total}\n")
        if total > 0:
            f.write(f"  ✓ Confirmed (exec)  : {confirmed_count}   ({(confirmed_count/total)*100:.1f}%)\n")
            f.write(f"  ✗ Unconfirmed       : {unconfirmed_count}   ({(unconfirmed_count/total)*100:.1f}%)\n\n")
        else:
             f.write(f"  ✓ Confirmed (exec)  : 0   (0.0%)\n")
             f.write(f"  ✗ Unconfirmed       : 0   (0.0%)\n\n")

        f.write("  FAILURE BREAKDOWN\n")
        f.write("  ───────────────────────────────────────────────────────────\n")
        for reason, count in sorted(failure_stats.items(), key=lambda x: x[1], reverse=True):
            if count > 0:
                percent = (count/unconfirmed_count)*100 if unconfirmed_count > 0 else 0
                desc = "Unknown"
                if reason == F_CONCAT: desc = "payload concatenated, no breakout"
                elif reason == F_NO_EXEC: desc = "dalfox flagged -none context"
                elif reason == F_ENCODED: desc = "payload URL-encoded in context"
                elif reason == F_NO_BREAKOUT: desc = "in JS string without quote escape"
                elif reason == F_CSP: desc = "blocked by Content-Security-Policy"
                elif reason == F_SANITIZED: desc = "payload was HTML-entity encoded"
                elif reason == F_ATTR_CONTEXT: desc = "in HTML attribute but event handler failed"
                f.write(f"  {reason:<12} : {count} ({percent:.1f}%) — {desc}\n")
        f.write("\n")
        
        f.write("  UNCONFIRMED DETAILS\n")
        f.write("  ───────────────────────────────────────────────────────────\n")
        for i, det in enumerate(unconfirmed_details, 1):
            f.write(f"  [{i}] {det['reason_code']} — {det['url']}\n")
            f.write(f"      Param    : {det['param']}\n")
            f.write(f"      Context  : {det['context']}\n")
            f.write(f"      Reason   : {det['reason_desc']}\n")
            f.write(f"      Fix      : {det['fix']}\n")
            if i < len(unconfirmed_details):
                 f.write("  ...\n")

    print(f"[OK] POC Triage complete: {confirmed_count} confirmed, {unconfirmed_count} unconfirmed.")
    print(f"[*] Report saved to {report_path}")
    
    if logger:
        logger.log_info(f"POC Triage complete. Confirmed: {confirmed_count}, Unconfirmed: {unconfirmed_count}")
        logger.log_phase("poc_triage", status="completed", confirmed=confirmed_count, unconfirmed=unconfirmed_count)

if __name__ == "__main__":
    main()
