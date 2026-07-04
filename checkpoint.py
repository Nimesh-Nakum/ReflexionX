#!/usr/bin/env python3
"""
XSS ReflexionX v1.0.0 — Checkpoint / Resume System
Persists pipeline state to ``scan_state.json`` so interrupted scans
can be resumed with ``--resume``.

CLI usage (from shell):
    python3 checkpoint.py --output-dir ./out --mark-complete url_collection
    python3 checkpoint.py --output-dir ./out --is-complete url_collection
    python3 checkpoint.py --output-dir ./out --show

Programmatic:
    from checkpoint import ScanCheckpoint
    ckpt = ScanCheckpoint(output_dir)
    if not ckpt.is_phase_complete("url_collection"):
        run_url_collection()
        ckpt.mark_phase_complete("url_collection", stats={"total_urls": 1500})
"""

import argparse, json, os, sys
from datetime import datetime, timezone


STATE_FILE = "scan_state.json"

# Canonical phase names (order matters)
PHASE_ORDER = [
    "url_collection",
    "live_filter",
    "param_extraction",
    "reflection_check",
    "reflection_validation",
    "dom_analysis",
    "target_scoring",
    "xss_scan_dalfox",
    "retry_errors",
    "xsstrike_validation",
    "browser_validation",
    "blind_xss_injection",
    "report_generation",
]


class ScanCheckpoint:
    """Manages scan state persistence for resume capability."""

    def __init__(self, output_dir, domain=""):
        self.output_dir = output_dir
        self._path = os.path.join(output_dir, STATE_FILE)
        self.state = self._load(domain)
        # Shadow set for O(1) URL lookups (list kept for JSON serialization)
        self._processed_set = set(self.state.get("processed_urls", []))

    def _load(self, domain=""):
        if os.path.isfile(self._path):
            try:
                with open(self._path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                pass
        # Fresh state
        return {
            "version": "2.0.0",
            "domain": domain,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "last_updated": datetime.now(timezone.utc).isoformat(),
            "completed_phases": [],
            "current_phase": "",
            "processed_urls": [],
            "stats": {},
        }

    def save(self):
        self.state["last_updated"] = datetime.now(timezone.utc).isoformat()
        os.makedirs(self.output_dir, exist_ok=True)
        tmp = self._path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.state, f, indent=2, default=str)
        # Atomic rename (as close as we can get on Windows)
        if os.path.exists(self._path):
            os.replace(tmp, self._path)
        else:
            os.rename(tmp, self._path)

    def mark_phase_complete(self, phase_name, stats=None):
        if phase_name not in self.state["completed_phases"]:
            self.state["completed_phases"].append(phase_name)
        if stats:
            self.state["stats"].update(stats)
        self.state["current_phase"] = ""
        self.save()

    def set_current_phase(self, phase_name):
        self.state["current_phase"] = phase_name
        self.save()

    def is_phase_complete(self, phase_name):
        return phase_name in self.state["completed_phases"]

    def add_processed_url(self, url):
        if url not in self._processed_set:
            self._processed_set.add(url)
            self.state["processed_urls"].append(url)

    def is_url_processed(self, url):
        return url in self._processed_set

    def get_stat(self, key, default=0):
        return self.state["stats"].get(key, default)

    def set_stat(self, key, value):
        self.state["stats"][key] = value
        self.save()

    @property
    def completed_phases(self):
        return list(self.state["completed_phases"])

    @property
    def domain(self):
        return self.state.get("domain", "")

    @domain.setter
    def domain(self, value):
        self.state["domain"] = value

    def summary(self):
        lines = [
            f"ReflexionX Scan State — {self.state.get('domain', 'unknown')}",
            f"  Started  : {self.state.get('started_at', '?')}",
            f"  Updated  : {self.state.get('last_updated', '?')}",
            f"  Current  : {self.state.get('current_phase', 'idle')}",
            f"  Completed: {', '.join(self.state.get('completed_phases', [])) or 'none'}",
        ]
        stats = self.state.get("stats", {})
        if stats:
            lines.append("  Stats:")
            for k, v in stats.items():
                lines.append(f"    {k}: {v}")
        return "\n".join(lines)


# ── CLI interface (called from reflexionx.sh) ────────────────
def main():
    parser = argparse.ArgumentParser(description="ReflexionX v1.0.0 — Checkpoint Manager")
    parser.add_argument("--output-dir", default=None, help="Scan output directory")
    parser.add_argument("--domain", default="", help="Target domain")
    parser.add_argument("--mark-complete", default=None, help="Mark a phase as complete")
    parser.add_argument("--is-complete", default=None, help="Check if phase is complete (exit 0/1)")
    parser.add_argument("--set-phase", default=None, help="Set current active phase")
    parser.add_argument("--set-stat", nargs=2, default=None, metavar=("KEY", "VALUE"),
                        help="Set a stat key=value")
    parser.add_argument("--show", action="store_true", help="Show current state")
    parser.add_argument("--test", action="store_true", help="Self-test")
    args = parser.parse_args()

    if args.test:
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            ck = ScanCheckpoint(td, domain="test.com")
            assert not ck.is_phase_complete("url_collection")
            ck.set_current_phase("url_collection")
            ck.mark_phase_complete("url_collection", stats={"total_urls": 100})
            assert ck.is_phase_complete("url_collection")
            assert ck.get_stat("total_urls") == 100

            # Reload from disk
            ck2 = ScanCheckpoint(td)
            assert ck2.is_phase_complete("url_collection")
            assert ck2.domain == "test.com"

            print("[OK] Checkpoint self-test passed")
            print(ck2.summary())
        return

    if not args.output_dir:
        parser.error("--output-dir is required (use --test for self-test)")

    ck = ScanCheckpoint(args.output_dir, domain=args.domain)

    if args.mark_complete:
        ck.mark_phase_complete(args.mark_complete)
        print(f"[OK] Phase '{args.mark_complete}' marked complete")

    elif args.is_complete:
        if ck.is_phase_complete(args.is_complete):
            print(f"[OK] Phase '{args.is_complete}' is complete")
            sys.exit(0)
        else:
            print(f"[-] Phase '{args.is_complete}' is NOT complete")
            sys.exit(1)

    elif args.set_phase:
        ck.set_current_phase(args.set_phase)
        print(f"[OK] Current phase set to '{args.set_phase}'")

    elif args.set_stat:
        key, val = args.set_stat
        # Try to store as int/float if possible
        try:
            val = int(val)
        except ValueError:
            try:
                val = float(val)
            except ValueError:
                pass
        ck.set_stat(key, val)
        print(f"[OK] Stat '{key}' = {val}")

    elif args.show:
        print(ck.summary())

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
