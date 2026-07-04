#!/usr/bin/env python3
"""
XSS ReflexionX v1.0.0 — Autonomous AI Agent
Phase-aware agent that drives the XSS hunting process.
"""

import argparse
import json
import os
import sys
import time
import hashlib
import subprocess
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# Import context management for smart chunking
try:
    from context_manager import URLChunker, DOMExtractor, SmartSplitter
    HAS_CONTEXT_MANAGER = True
except ImportError:
    HAS_CONTEXT_MANAGER = False

try:
    from context_loader import load_contexts_dict
except ImportError:
    def load_contexts_dict(output_dir=None, filepath=None): return {}

try:
    from ai_core import get_llm_client
except ImportError:
    print("[!] 'ai_core' not available. Run: pip3 install -r requirements.txt", file=sys.stderr)
    get_llm_client = None

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    print("[!] 'requests' not installed. Run: pip3 install requests", file=sys.stderr)
    sys.exit(1)

RATE_LIMIT_DELAY = 1.5
MAX_HTTP_REQUESTS = 500


# ── Logging ───────────────────────────────────────────────────
# print_log → stdout (captured by reflexionx.sh into reflexionx.log)
# ai_debug  → dedicated ai_debug.log file with timestamps & detail

_AI_DEBUG_FILE = None

def print_log(prefix, msg):
    """Print to stdout (shows in reflexionx.log and dashboard)."""
    print(f"[{prefix}] {msg}")

def ai_debug(msg):
    """Write detailed debug line to ai_debug.log with timestamp."""
    global _AI_DEBUG_FILE
    if _AI_DEBUG_FILE:
        ts = datetime.now().strftime("%H:%M:%S")
        _AI_DEBUG_FILE.write(f"[{ts}] {msg}\n")
        _AI_DEBUG_FILE.flush()

def init_debug_log(output_dir):
    """Initialize the AI debug log file."""
    global _AI_DEBUG_FILE
    if _AI_DEBUG_FILE:
        try:
            _AI_DEBUG_FILE.close()
        except Exception:
            pass
    log_path = os.path.join(output_dir, "logs", "ai_debug.log")
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    _AI_DEBUG_FILE = open(log_path, "a", encoding="utf-8")
    ai_debug("=" * 60)
    ai_debug(f"AI Agent session started")
    ai_debug(f"=" * 60)


def read_file(filepath):
    if not os.path.exists(filepath): return ""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return f.read()
    except Exception: return ""

def write_file(filepath, content):
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)

def load_json(filepath):
    if not os.path.exists(filepath): return None
    try:
        with open(filepath, 'r') as f: return json.load(f)
    except Exception: return None

def write_json(filepath, data):
    with open(filepath, 'w') as f: json.dump(data, f, indent=2)


class ReflexionAgent:
    def __init__(self, target, output_dir, model, max_iterations, phase, test_mode):
        self.target = target
        self.output_dir = output_dir
        self.model = model
        self.max_iterations = max_iterations
        self.phase = phase
        self.test_mode = test_mode
        self.http_count = 0
        self.last_request_time = 0
        self.api_calls = 0
        self.api_total_time = 0.0

        self.agent_log_path = os.path.join(output_dir, "agent_log.json")
        self.agent_state_path = os.path.join(output_dir, "agent_state.json")

        self.state = load_json(self.agent_state_path) or {
            "target": target,
            "iterations_completed": 0,
            "decisions": [],
            "confirmed_findings": []
        }

        # Initialize debug log
        init_debug_log(output_dir)
        ai_debug(f"Target: {target}")
        ai_debug(f"Phase: {phase}")
        ai_debug(f"Model: {model}")
        ai_debug(f"Max iterations: {max_iterations}")
        ai_debug(f"Test mode: {test_mode}")
        ai_debug(f"Context manager available: {HAS_CONTEXT_MANAGER}")

        api_key = os.environ.get("OPENROUTER_API_KEY")
        if not api_key and not self.test_mode:
            print_log("!", "OPENROUTER_API_KEY is not set.")
            ai_debug("FATAL: OPENROUTER_API_KEY is not set — exiting")
            sys.exit(1)

        if not self.test_mode:
            if get_llm_client is None:
                print_log("!", "ai_core not available — cannot initialize LLM client")
                ai_debug("FATAL: ai_core import failed — exiting")
                sys.exit(1)
            self.client = get_llm_client(provider="openrouter", api_key=api_key)
            if not self.client.is_configured:
                print_log("!", "LLM client not configured. Check OPENROUTER_API_KEY.")
                ai_debug("FATAL: LLM client not configured — exiting")
                sys.exit(1)
            ai_debug(f"LLM client initialized via ai_core (provider={self.client.provider}, model={self.client.model})")

    def ask_llm(self, system_prompt, user_prompt, expect_json=True):
        """Send request to LLM with full debug logging."""
        if self.test_mode:
            ai_debug("ask_llm: TEST MODE — returning empty response")
            if expect_json:
                return {}
            return "Test mode output"

        self.api_calls += 1
        call_num = self.api_calls
        prompt_len = len(system_prompt) + len(user_prompt)

        ai_debug(f"─── API CALL #{call_num} ───")
        ai_debug(f"  Model: {self.model}")
        ai_debug(f"  Expect JSON: {expect_json}")
        ai_debug(f"  System prompt: {system_prompt[:120]}...")
        ai_debug(f"  User prompt length: {len(user_prompt)} chars")
        ai_debug(f"  Total prompt: ~{prompt_len} chars")

        try:
            start_time = time.time()
            ai_debug("  Sending request via ai_core.LLMClient...")

            if expect_json:
                content = self.client.chat_json(
                    user_prompt,
                    role="scan_strategist",
                    system_prompt=system_prompt,
                    max_tokens=2048,
                )
                if content is None:
                    ai_debug("  ✗ LLM returned None for JSON request")
                    print_log("!", "LLM returned invalid/empty JSON response")
                    return {}
                if isinstance(content, list):
                    content = content[0] if content and isinstance(content[0], dict) else {}
                elif not isinstance(content, dict):
                    content = {}
                ai_debug(f"  Parsed JSON type: {type(content).__name__}")
                if isinstance(content, dict):
                    ai_debug(f"  Parsed JSON keys: {list(content.keys())}")
                return content
            else:
                content = self.client.chat(
                    user_prompt,
                    role="scan_strategist",
                    system_prompt=system_prompt,
                    max_tokens=2048,
                )
                if content is None:
                    ai_debug("  ✗ LLM returned None")
                    print_log("!", "LLM returned empty response")
                    return ""
                elapsed = time.time() - start_time
                self.api_total_time += elapsed
                ai_debug(f"  ✓ Response received in {elapsed:.1f}s")
                ai_debug(f"  Response length: {len(content)} chars")
                ai_debug(f"  Response preview: {content[:200]}...")
                return content

        except json.JSONDecodeError as e:
            ai_debug(f"  ✗ JSON parse error: {e}")
            print_log("!", f"LLM returned invalid JSON: {e}")
            return {} if expect_json else ""
        except Exception as e:
            ai_debug(f"  ✗ Unexpected error: {e}")
            print_log("!", f"LLM Error: {e}")
            return {} if expect_json else ""

    def run_phase(self):
        ai_debug(f"")
        ai_debug(f"══════════════════════════════════════════════")
        ai_debug(f"  RUNNING PHASE: {self.phase}")
        ai_debug(f"══════════════════════════════════════════════")

        print_log("AI", f"Running phase: {self.phase}")
        phase_start = time.time()

        if self.phase == "post_collection":
            self.analyze_surface()
        elif self.phase == "pre_scan":
            self.generate_custom_payloads()
        elif self.phase == "deep_exploit":
            self.autonomous_loop()
        elif self.phase == "post_browser":
            self.write_pentest_report()
        else:
            print_log("AI", f"Phase '{self.phase}' has no specific AI action.")
            ai_debug(f"Phase '{self.phase}' — no handler defined, skipping")

        phase_dur = time.time() - phase_start
        ai_debug(f"")
        ai_debug(f"── PHASE COMPLETE: {self.phase} ──")
        ai_debug(f"  Duration: {phase_dur:.1f}s")
        ai_debug(f"  API calls made: {self.api_calls}")
        ai_debug(f"  Total API time: {self.api_total_time:.1f}s")
        ai_debug(f"══════════════════════════════════════════════")

    def analyze_surface(self):
        ai_debug("analyze_surface: Loading all_urls.txt...")
        urls = read_file(os.path.join(self.output_dir, "all_urls.txt")).splitlines()
        if not urls:
            ai_debug("analyze_surface: No URLs found — skipping")
            print_log("AI", "No URLs found for surface analysis")
            return

        ai_debug(f"analyze_surface: Loaded {len(urls)} raw URLs")

        # Smart chunking: deduplicate and filter before sending to LLM
        if HAS_CONTEXT_MANAGER:
            chunker = URLChunker()
            filtered_urls = chunker.process_urls(urls)
            print_log("AI", f"Context reduced: {len(urls)} -> {len(filtered_urls)} unique endpoints")
            ai_debug(f"analyze_surface: Context manager reduced {len(urls)} → {len(filtered_urls)} URLs")
        else:
            # Fallback: basic dedup
            filtered_urls = list(dict.fromkeys(urls))
            ai_debug(f"analyze_surface: Basic dedup {len(urls)} → {len(filtered_urls)} URLs (no context_manager)")

        # Send in batches if too many (map-reduce pattern)
        all_prioritized = []
        batch_size = 500
        batches = [filtered_urls[i:i+batch_size] for i in range(0, min(len(filtered_urls), 2000), batch_size)]
        ai_debug(f"analyze_surface: Split into {len(batches)} batches (batch_size={batch_size})")

        sys_prompt = ("You are analyzing collected URLs to find high-value XSS targets. "
                      "Focus on: search/query params, redirect/callback endpoints, API routes, "
                      "login/auth pages, error handlers, and template rendering endpoints. "
                      "Respond with a JSON object containing a 'prioritized_urls' array of strings.")

        for i, batch in enumerate(batches):
            print_log("AI", f"Analyzing URL batch {i+1}/{len(batches)} ({len(batch)} URLs)")
            ai_debug(f"analyze_surface: Sending batch {i+1}/{len(batches)} ({len(batch)} URLs)")
            ai_debug(f"  Sample URLs from batch: {batch[:3]}")

            user_prompt = f"Analyze these URLs for XSS potential. Return only the highest-value targets.\n\nURLs:\n{chr(10).join(batch)}"
            res = self.ask_llm(sys_prompt, user_prompt)

            batch_hits = res.get("prioritized_urls", [])
            all_prioritized.extend(batch_hits)
            ai_debug(f"  Batch {i+1} returned {len(batch_hits)} prioritized URLs")
            if batch_hits:
                ai_debug(f"  Top 5 prioritized: {batch_hits[:5]}")

        if all_prioritized:
            # Deduplicate final results
            all_prioritized = list(dict.fromkeys(all_prioritized))
            write_file(os.path.join(self.output_dir, "ai_priority_targets.txt"), "\n".join(all_prioritized))
            print_log("AI", f"Prioritized {len(all_prioritized)} targets across {len(batches)} batches.")
            ai_debug(f"analyze_surface: RESULT — {len(all_prioritized)} unique prioritized URLs saved")
            ai_debug(f"  Written to: ai_priority_targets.txt")
            for j, url in enumerate(all_prioritized[:10]):
                ai_debug(f"  [{j+1}] {url}")
            if len(all_prioritized) > 10:
                ai_debug(f"  ... and {len(all_prioritized) - 10} more")
        else:
            ai_debug("analyze_surface: AI returned 0 prioritized URLs")
            print_log("AI", "AI found no high-priority XSS targets in collected URLs")

    def generate_custom_payloads(self):
        ctx_data = load_contexts_dict(self.output_dir)
        ctx_file = os.path.join(self.output_dir, "reflection_contexts.json")
        ai_debug(f"generate_custom_payloads: Loading {ctx_file}")

        if not ctx_data:
            ai_debug("generate_custom_payloads: No reflection context data found — skipping")
            print_log("AI", "No reflection contexts found — skipping payload generation")
            return

        ai_debug(f"generate_custom_payloads: Loaded {len(ctx_data)} context entries")

        # Chunk large context data using SmartSplitter (map-reduce)
        all_payloads = []
        sys_prompt = ("You are crafting bypass payloads for XSS based on reflection contexts. "
                      "Consider: tag closing, attribute breakout, event handlers, encoding bypass, "
                      "JS template literals, DOM clobbering, and CSP bypass techniques. "
                      "Respond with a JSON object containing a 'payloads' array of strings.")

        if HAS_CONTEXT_MANAGER and len(ctx_data) > 10:
            # Split large context into batches
            splitter = SmartSplitter()
            for i, batch in enumerate(splitter.split_json_report(ctx_data, batch_size=10)):
                print_log("AI", f"Generating payloads for context batch {i+1}")
                ai_debug(f"generate_custom_payloads: Context batch {i+1}")
                user_prompt = (f"Given these reflection contexts, generate 10 unique bypass payloads "
                               f"tailored to these specific contexts.\n\nContexts: {json.dumps(batch)}")
                res = self.ask_llm(sys_prompt, user_prompt)
                batch_payloads = res.get("payloads", [])
                all_payloads.extend(batch_payloads)
                ai_debug(f"  Batch {i+1} generated {len(batch_payloads)} payloads")
        else:
            # Small context — single request
            ai_debug("generate_custom_payloads: Small context — single API call")
            user_prompt = (f"Given these contexts, generate 10 unique, highly effective bypass payloads "
                           f"(e.g., closing tags, encoding, specific handlers).\n\n"
                           f"Contexts: {json.dumps(dict(list(ctx_data.items())[:10]))}")
            res = self.ask_llm(sys_prompt, user_prompt)
            all_payloads = res.get("payloads", [])

        if all_payloads:
            # Deduplicate payloads
            all_payloads = list(dict.fromkeys(all_payloads))
            write_file(os.path.join(self.output_dir, "ai_payloads.txt"), "\n".join(all_payloads))
            print_log("AI", f"Generated {len(all_payloads)} custom payloads.")
            ai_debug(f"generate_custom_payloads: RESULT — {len(all_payloads)} unique payloads")
            for j, p in enumerate(all_payloads[:5]):
                ai_debug(f"  [{j+1}] {p}")
        else:
            ai_debug("generate_custom_payloads: AI returned 0 payloads")
            print_log("AI", "AI generated 0 custom payloads")

    def autonomous_loop(self):
        # Similar to the original run() loop but focused on deep exploitation
        print_log("AI", "Starting Deep Exploitation loop.")
        ai_debug("autonomous_loop: Starting deep exploitation")
        sys_prompt = """You are an autonomous XSS pentester. Analyze the current state and decide the next action.
Respond ONLY with this JSON schema:
{
  "action": "RETRY_PAYLOAD|ESCALATE_BROWSER|STOP",
  "target_url": "url",
  "target_param": "param",
  "payload": "payload",
  "reason": "reason",
  "confidence": 0-100
}"""
        for i in range(self.max_iterations):
            unconf_dir = os.path.join(self.output_dir, "poc", "unconfirmed")
            poc_dir = os.path.join(self.output_dir, "poc")
            unconf_list = []
            if os.path.exists(unconf_dir):
                unconf_list.extend(os.listdir(unconf_dir))
            if not unconf_list and os.path.exists(poc_dir):
                unconf_list = [f for f in os.listdir(poc_dir) if f.endswith(".txt") and f != "poc.txt" and not f.startswith("rxoob")]
            context = {
                "iteration": i,
                "confirmed": len(self.state["confirmed_findings"]),
                "poc_unconfirmed": unconf_list
            }
            ai_debug(f"autonomous_loop: Iteration {i+1}/{self.max_iterations}, context={json.dumps(context)}")

            if not context["poc_unconfirmed"] and i > 0:
                print_log("AI", "No more unconfirmed PoCs to exploit. Stopping.")
                ai_debug("autonomous_loop: No unconfirmed PoCs — stopping loop")
                break

            res = self.ask_llm(sys_prompt, f"Current state: {json.dumps(context)}")
            action = res.get("action")
            if action == "STOP" or not action:
                ai_debug(f"autonomous_loop: AI decided to STOP (action={action})")
                break

            print_log("AI", f"Iter {i+1}: {action} - {res.get('reason')}")
            ai_debug(f"autonomous_loop: AI action={action}, target={res.get('target_url')}, "
                     f"param={res.get('target_param')}, confidence={res.get('confidence')}")
            ai_debug(f"  Reason: {res.get('reason')}")
            if res.get('payload'):
                ai_debug(f"  Payload: {res.get('payload')}")

            # Placeholder for actual exploitation logic (HTTP requests, browser escalation)
            # To keep it safe and functional within the framework, we simulate or use basic checks.
            if action == "ESCALATE_BROWSER":
                ai_debug(f"autonomous_loop: Escalating to browser for {res.get('target_url')}")
                tmp_url_file = os.path.join(self.output_dir, "tmp_ai_browser_target.txt")
                write_file(tmp_url_file, f"{res.get('target_url')}\n")
                script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "xss_browser.py")
                try:
                    subprocess.run(["python3", script_path, "--input", tmp_url_file, "--output-dir", self.output_dir])
                except Exception:
                    pass

            self.state["decisions"].append(res)
            self.state["iterations_completed"] += 1
            write_json(self.agent_state_path, self.state)

        ai_debug(f"autonomous_loop: Completed — {self.state['iterations_completed']} iterations, "
                 f"{len(self.state['confirmed_findings'])} confirmed findings")

    def write_pentest_report(self):
        print_log("AI", "Generating Executive Pentest Report.")
        ai_debug("write_pentest_report: Starting report generation")

        sys_prompt = "You are a senior security consultant. Write a professional markdown pentest report based on the provided data. Do NOT use JSON."
        confirmed_list = list(self.state["confirmed_findings"])
        conf_dir = os.path.join(self.output_dir, "poc", "confirmed")
        if os.path.isdir(conf_dir):
            for f in os.listdir(conf_dir):
                if f.endswith(".txt"):
                    confirmed_list.append(f)
        conf_exec = os.path.join(self.output_dir, "confirmed_execution.txt")
        if os.path.isfile(conf_exec):
            for line in read_file(conf_exec).splitlines():
                if line.strip(): confirmed_list.append(line.strip())
        dalfox_file = os.path.join(self.output_dir, "dalfox.txt")
        if os.path.isfile(dalfox_file):
            for line in read_file(dalfox_file).splitlines():
                if "[POC][V]" in line or "[POC][G]" in line:
                    confirmed_list.append(line.strip())
        confirmed_list = list(set(confirmed_list))

        stats = {
            "target": self.target,
            "confirmed_xss": len(confirmed_list),
            "confirmed_details": confirmed_list[:10],
            "ai_decisions": len(self.state["decisions"])
        }
        ai_debug(f"write_pentest_report: Stats = {json.dumps(stats)}")

        report_content = self.ask_llm(sys_prompt, f"Generate a report for these results: {json.dumps(stats)}", expect_json=False)
        if report_content:
            report_path = os.path.join(self.output_dir, "AI_PENTEST_REPORT.md")
            write_file(report_path, report_content)
            print_log("AI", "Report written to AI_PENTEST_REPORT.md")
            ai_debug(f"write_pentest_report: Report written ({len(report_content)} chars) to {report_path}")
        else:
            ai_debug("write_pentest_report: AI returned empty report")


def main():
    global _AI_DEBUG_FILE
    parser = argparse.ArgumentParser(description="ReflexionX v1.0.0 — AI Agent")
    parser.add_argument("--target", default=None)
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--model", default="google/gemini-2.5-flash:free")
    parser.add_argument("--max-iterations", type=int, default=25)
    parser.add_argument("--phase", default=None, help="Current pipeline phase")
    parser.add_argument("--test", action="store_true")
    args = parser.parse_args()

    if args.test:
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            with open(os.path.join(td, "all_urls.txt"), 'w') as f:
                f.write("https://example.com/search?q=test\nhttps://example.com/page?id=1\n")

            agent = ReflexionAgent(
                target="test.com",
                output_dir=td,
                model="google/gemini-2.5-flash:free",
                max_iterations=3,
                phase="post_collection",
                test_mode=True
            )
            agent.analyze_surface()

            ctx = {"https://example.com/search?q=test": {"params": ["q"], "codes": [200]}}
            with open(os.path.join(td, "reflection_contexts.json"), 'w') as f:
                json.dump(ctx, f)

            agent2 = ReflexionAgent(
                target="test.com",
                output_dir=td,
                model="google/gemini-2.5-flash:free",
                max_iterations=1,
                phase="pre_scan",
                test_mode=True
            )
            agent2.generate_custom_payloads()

            if _AI_DEBUG_FILE:
                _AI_DEBUG_FILE.close()
                _AI_DEBUG_FILE = None

        print("[OK] reflexion_agent.py self-test passed")
        sys.exit(0)

    agent = ReflexionAgent(args.target, args.output_dir, args.model, args.max_iterations, args.phase, args.test)
    agent.run_phase()

    if _AI_DEBUG_FILE:
        _AI_DEBUG_FILE.close()


if __name__ == "__main__":
    main()
