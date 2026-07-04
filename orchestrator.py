#!/usr/bin/env python3
"""
XSS ReflexionX v1.0.0 — Python Orchestrator (Optional)
Secondary entry point that wraps the bash pipeline for programmatic use.
reflexionx.sh remains the primary and fully functional entry point.

Usage:
    python3 orchestrator.py -d target.com -V -D --stealth
    python3 orchestrator.py -d target.com --resume ./xss_target.com_prev/
"""

import argparse, json, os, subprocess, sys, time
from datetime import datetime, timezone
from pathlib import Path

try:
    from context_loader import load_contexts_dict
except ImportError:
    load_contexts_dict = None

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


class ReflexionXOrchestrator:
    """Python wrapper for the ReflexionX pipeline.

    Can either delegate to reflexionx.sh (full pipeline) or run
    individual Python phases directly.
    """

    def __init__(self, domain, output_dir=None, threads=10, proxy=None,
                 validate=False, dom_scan=False, fragment_scan=False, stealth=False,
                 blind_url=None, post_data=None, resume_dir=None):
        self.domain = domain
        self.threads = threads
        self.proxy = proxy
        self.validate = validate
        self.dom_scan = dom_scan
        self.fragment_scan = fragment_scan
        self.stealth = stealth
        self.blind_url = blind_url
        self.post_data = post_data
        self.resume_dir = resume_dir

        if output_dir:
            self.output_dir = output_dir
        else:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.output_dir = os.path.join(os.getcwd(), f"xss_{domain}_{ts}")

        os.makedirs(self.output_dir, exist_ok=True)

    def run_full_pipeline(self):
        """Delegate to reflexionx.sh for the full pipeline."""
        cmd = [
            "bash", os.path.join(SCRIPT_DIR, "reflexionx.sh"),
            "-d", self.domain,
            "-t", str(self.threads),
        ]
        if self.proxy:
            cmd.extend(["-p", self.proxy])
        if self.blind_url:
            cmd.extend(["-b", self.blind_url])
        if self.validate:
            cmd.append("-V")
        if self.dom_scan:
            cmd.append("-D")
        if self.fragment_scan:
            cmd.append("-F")
        if self.stealth:
            cmd.append("-S")
        if self.post_data:
            cmd.extend(["-P", self.post_data])
        if self.resume_dir:
            cmd.extend(["-R", self.resume_dir])

        print(f"[*] Launching ReflexionX pipeline: {' '.join(cmd)}")
        try:
            proc = subprocess.Popen(cmd, cwd=os.getcwd())
            proc.wait()
            return proc.returncode
        except KeyboardInterrupt:
            proc.terminate()
            print("\n[!] Pipeline interrupted")
            return 1

    def run_validator(self, input_file):
        """Run xss_validator.py directly."""
        cmd = [
            sys.executable, os.path.join(SCRIPT_DIR, "xss_validator.py"),
            "--input", input_file,
            "--output-dir", self.output_dir,
            "--threads", str(self.threads),
        ]
        if self.proxy:
            cmd.extend(["--proxy", self.proxy])
        if self.stealth:
            cmd.append("--stealth")
        if self.post_data:
            cmd.extend(["--post-data", self.post_data])
        return subprocess.call(cmd)

    def run_dom_analyzer(self, js_urls_file):
        """Run dom_analyzer.py directly."""
        cmd = [
            sys.executable, os.path.join(SCRIPT_DIR, "dom_analyzer.py"),
            "--js-urls", js_urls_file,
            "--output-dir", self.output_dir,
            "--threads", str(min(self.threads, 5)),
        ]
        if self.proxy:
            cmd.extend(["--proxy", self.proxy])
        return subprocess.call(cmd)

    def run_browser_validator(self, input_file):
        """Run xss_browser.py directly."""
        cmd = [
            sys.executable, os.path.join(SCRIPT_DIR, "xss_browser.py"),
            "--input", input_file,
            "--output-dir", self.output_dir,
            "--retry",
        ]
        if self.proxy:
            cmd.extend(["--proxy", self.proxy])
        if self.stealth:
            cmd.append("--stealth")
        if self.post_data:
            cmd.extend(["--post-data", self.post_data])
        return subprocess.call(cmd)

    def run_oob_handler(self, input_file):
        """Run oob_handler.py directly."""
        if not self.blind_url:
            print("[!] No --blind-url specified for OOB handler")
            return 1
        cmd = [
            sys.executable, os.path.join(SCRIPT_DIR, "oob_handler.py"),
            "--input", input_file,
            "--output-dir", self.output_dir,
            "--oob-url", self.blind_url,
            "--threads", str(self.threads),
        ]
        if self.proxy:
            cmd.extend(["--proxy", self.proxy])
        return subprocess.call(cmd)

    def generate_report(self):
        """Run report.py to generate HTML report."""
        cmd = [
            sys.executable, os.path.join(SCRIPT_DIR, "report.py"),
            "--output-dir", self.output_dir,
        ]
        return subprocess.call(cmd)

    def load_results(self):
        """Load scan results for programmatic access."""
        results = {}
        files = {
            "confirmed": "browser_validation.json",
            "contexts": "reflection_contexts.json",
            "dom_analysis": "dom_analysis.json",
            "scan_state": "scan_state.json",
            "oob_events": "oob_events.json",
            "cross_page_flows": "cross_page_flows.json",
            "stored_xss": "stored_xss_findings.json",
            "fragment_urls": "fragment_urls.txt",
        }
        for key, fname in files.items():
            fpath = os.path.join(self.output_dir, fname)
            if os.path.isfile(fpath):
                try:
                    with open(fpath) as f:
                        results[key] = json.load(f)
                except (json.JSONDecodeError, OSError):
                    results[key] = None
            elif key == "contexts" and load_contexts_dict is not None:
                results[key] = load_contexts_dict(self.output_dir)
        return results


def main():
    parser = argparse.ArgumentParser(
        description="ReflexionX v1.0.0 — Python Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="This is an optional secondary entry point.\n"
               "The primary entry point remains: ./reflexionx.sh -d <domain>")
    parser.add_argument("-d", "--domain", default=None, help="Target domain")
    parser.add_argument("-t", "--threads", type=int, default=10)
    parser.add_argument("-p", "--proxy", default=None)
    parser.add_argument("-b", "--blind-url", default=None)
    parser.add_argument("-V", "--validate", action="store_true", help="Enable browser validation")
    parser.add_argument("-D", "--dom-scan", action="store_true", help="Enable DOM XSS analysis")
    parser.add_argument("-F", "--fragment-scan", action="store_true", help="Enable fragment URL injection for DOM XSS (Level 3/6)")
    parser.add_argument("-S", "--stealth", action="store_true", help="Enable stealth mode")
    parser.add_argument("-P", "--post-data", default=None, help="POST data file")
    parser.add_argument("-R", "--resume", default=None, dest="resume_dir",
                        help="Resume from previous output directory")
    parser.add_argument("--report-only", default=None,
                        help="Only generate report for existing output dir")
    parser.add_argument("--test", action="store_true")
    args = parser.parse_args()

    if args.test:
        print("[OK] Python orchestrator self-test passed")
        print(f"  Script dir: {SCRIPT_DIR}")
        print(f"  reflexionx.sh: {'found' if os.path.isfile(os.path.join(SCRIPT_DIR, 'reflexionx.sh')) else 'NOT FOUND'}")
        return

    if args.report_only:
        orch = ReflexionXOrchestrator(domain="report", output_dir=args.report_only)
        orch.generate_report()
        return

    if not args.domain:
        parser.error("--domain (-d) is required (use --report-only for existing scans)")

    orch = ReflexionXOrchestrator(
        domain=args.domain, threads=args.threads, proxy=args.proxy,
        validate=args.validate, dom_scan=args.dom_scan,
        fragment_scan=args.fragment_scan, stealth=args.stealth,
        blind_url=args.blind_url, post_data=args.post_data,
        resume_dir=args.resume_dir)

    rc = orch.run_full_pipeline()
    if rc == 0:
        orch.generate_report()
    sys.exit(rc)


if __name__ == "__main__":
    main()
