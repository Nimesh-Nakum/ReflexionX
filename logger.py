#!/usr/bin/env python3
"""
XSS ReflexionX v1.0.0 — Structured Logging System
Thread-safe JSON line logger for all pipeline components.

Usage:
    from logger import ScanLogger
    log = ScanLogger(output_dir="./out")
    log.log_attempt(url="...", param="q", context="html_body", payload="...", executed=False)
    log.log_finding(url="...", param="q", payload="...", trigger="event:click")
"""

import json, os, sys, threading, time
from datetime import datetime, timezone


class ScanLogger:
    """Thread-safe structured JSON line logger.

    All entries are appended to ``scan_log.jsonl`` inside *output_dir*.
    Existing output files produced by the pipeline are **never** modified.
    """

    def __init__(self, output_dir, component="unknown"):
        self.output_dir = output_dir
        self.component = component
        self._lock = threading.Lock()
        self._log_path = os.path.join(output_dir, "scan_log.jsonl")
        # Ensure directory exists
        os.makedirs(output_dir, exist_ok=True)

    # ── internal ─────────────────────────────────────────────
    def _ts(self):
        return datetime.now(timezone.utc).isoformat()

    def _write(self, entry):
        entry["timestamp"] = self._ts()
        entry["component"] = self.component
        line = json.dumps(entry, default=str) + "\n"
        with self._lock:
            with open(self._log_path, "a", encoding="utf-8") as f:
                f.write(line)

    # ── public API ───────────────────────────────────────────
    def log_phase(self, phase, status="started", **extra):
        """Log a pipeline phase transition."""
        self._write({"event": "phase", "phase": phase, "status": status, **extra})

    def log_attempt(self, url, param="", context="", payload="",
                    attempt=1, executed=False, csp_blocked=False,
                    duration_ms=0, **extra):
        """Log a single payload injection attempt."""
        self._write({
            "event": "attempt",
            "url": url,
            "param": param,
            "context": context,
            "payload": payload[:200],  # truncate long payloads
            "attempt": attempt,
            "executed": executed,
            "csp_blocked": csp_blocked,
            "duration_ms": duration_ms,
            **extra,
        })

    def log_finding(self, url, param="", payload="", trigger="",
                    context="", severity="", **extra):
        """Log a confirmed XSS finding."""
        self._write({
            "event": "finding",
            "url": url,
            "param": param,
            "payload": payload[:200],
            "trigger": trigger,
            "context": context,
            "severity": severity,
            **extra,
        })

    def log_error(self, url="", message="", phase="", **extra):
        """Log an error encountered during scanning."""
        self._write({
            "event": "error",
            "url": url,
            "message": str(message)[:500],
            "phase": phase,
            **extra,
        })

    def log_info(self, message, **extra):
        """Log an informational message."""
        self._write({"event": "info", "message": message, **extra})

    def log_csp(self, url, csp_data, **extra):
        """Log CSP analysis result for a URL."""
        self._write({"event": "csp_analysis", "url": url, "csp": csp_data, **extra})

    def log_oob(self, url, param="", oob_id="", callback_url="", **extra):
        """Log a blind/OOB XSS injection."""
        self._write({
            "event": "oob_injection",
            "url": url,
            "param": param,
            "oob_id": oob_id,
            "callback_url": callback_url,
            **extra,
        })

    def log_retry(self, url, param="", original_payload="",
                  new_payload="", strategy="", attempt=1, **extra):
        """Log an adaptive retry attempt."""
        self._write({
            "event": "retry",
            "url": url,
            "param": param,
            "original_payload": original_payload[:200],
            "new_payload": new_payload[:200],
            "strategy": strategy,
            "attempt": attempt,
            **extra,
        })


# ── CLI self-test ────────────────────────────────────────────
if __name__ == "__main__":
    import argparse, tempfile
    parser = argparse.ArgumentParser(description="ReflexionX v1.0.0 — Logger self-test")
    parser.add_argument("--test", action="store_true")
    args = parser.parse_args()

    if args.test:
        with tempfile.TemporaryDirectory() as td:
            log = ScanLogger(td, component="self_test")
            log.log_phase("test_phase", status="started")
            log.log_attempt(url="http://test.com?q=1", param="q",
                            context="html_body", payload="<img src=x>",
                            attempt=1, executed=True, duration_ms=150)
            log.log_finding(url="http://test.com?q=1", param="q",
                            payload="<img src=x>", trigger="immediate",
                            severity="critical")
            log.log_error(url="http://fail.com", message="timeout",
                          phase="browser_validation")
            log.log_phase("test_phase", status="completed")

            # Verify
            path = os.path.join(td, "scan_log.jsonl")
            with open(path) as f:
                lines = f.readlines()
            assert len(lines) == 5, f"Expected 5 log lines, got {len(lines)}"
            for line in lines:
                entry = json.loads(line)
                assert "timestamp" in entry
                assert "component" in entry
            print("[OK] Logger self-test passed — 5 entries written and validated")
    else:
        print("Usage: python3 logger.py --test")
