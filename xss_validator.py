#!/usr/bin/env python3
"""
XSS ReflexionX v1.0.0 — Reflection Validator & Context Classifier
Validates reflected parameters, classifies injection contexts, parses CSP,
and supports POST body parameter testing.
For authorized security testing only.

Usage:
    python3 xss_validator.py --input reflected_urls.txt --output-dir ./out --threads 10
    python3 xss_validator.py --input urls.txt --output-dir ./out --post-data post_targets.txt
"""

import argparse, hashlib, json, os, re, sys, time, html as html_lib
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    print("[!] 'requests' not installed. Run: pip3 install requests", file=sys.stderr)
    sys.exit(1)

# v2.0.0 imports (graceful)
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

CANARY_PREFIX = "hfcnry"
TIMEOUT = 10

CTX_HTML_BODY = "html_body"
CTX_HTML_ATTR = "html_attribute"
CTX_JAVASCRIPT = "javascript"
CTX_JSON = "json"
CTX_UNKNOWN = "unknown"

ENC_RAW = "raw"
ENC_HTML = "html_encoded"
ENC_URL = "url_encoded"
ENC_JS_ESCAPED = "js_escaped"


def generate_canary(url, param):
    h = hashlib.md5(f"{url}:{param}".encode()).hexdigest()[:16]
    return f"{CANARY_PREFIX}{h}"


def build_session(proxy=None, cookie=None):
    s = requests.Session()
    retry = Retry(total=2, backoff_factor=0.3, status_forcelist=[429, 500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=20)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    if proxy:
        s.proxies = {"http": proxy, "https": proxy}
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    })
    if cookie:
        s.headers.update({"Cookie": cookie})
    s.verify = False
    return s


def detect_encoding(canary, body):
    encodings = []
    if canary in body:
        encodings.append(ENC_RAW)
    he = html_lib.escape(canary)
    if he != canary and he in body:
        encodings.append(ENC_HTML)
    ue = quote(canary)
    if ue != canary and ue in body:
        encodings.append(ENC_URL)
    je = canary.replace("'", "\\'").replace('"', '\\"')
    if je != canary and je in body:
        encodings.append(ENC_JS_ESCAPED)
    return encodings


def classify_context(canary, body):
    contexts = []
    script_re = re.compile(r'<script[^>]*>(.*?)(?:</script>|$)', re.DOTALL | re.IGNORECASE)
    for m in script_re.finditer(body):
        sc = m.group(1)
        if canary in sc:
            idx = sc.index(canary)
            window = sc[max(0, idx - 50):idx + 50]
            if any(x in window for x in ['{"', ':[', '",', '":', "'{", "['"]):
                contexts.append(CTX_JSON)
            else:
                contexts.append(CTX_JAVASCRIPT)
    attr_re = re.compile(
        r'''<[^>]+?\s+[\w-]+\s*=\s*["']([^"']*?)''' + re.escape(canary) + r'''([^"']*?)["'][^>]*>''',
        re.IGNORECASE)
    if attr_re.search(body):
        contexts.append(CTX_HTML_ATTR)
    stripped = script_re.sub('', body)
    text_only = re.sub(r'<[^>]+>', ' ', stripped)
    if canary in text_only:
        contexts.append(CTX_HTML_BODY)
    seen = set()
    unique = [c for c in contexts if c not in seen and not seen.add(c)]
    return unique if unique else [CTX_UNKNOWN]


def detect_quote_type(canary, body):
    """Detect the quote type surrounding the canary in attribute context.
    
    Returns 'double', 'single', or 'none'.
    Matches: ="<canary>", ="text<canary>text", ='<canary>', etc.
    Uses non-greedy matching and anchor-to-closing-quote to prevent
    cross-quote-type false matches (e.g., double-quote attr containing ').
    """
    escaped = re.escape(canary)
    # Check double-quoted attribute: ="<canary>" or ="any-<canary>-text"
    dq = re.search(r'="[^"]*' + escaped + r'[^"]*"', body)
    if dq:
        return "double"
    # Check single-quoted attribute: ='<canary>' or ='any-<canary>-text'
    sq = re.search(r"='[^']*" + escaped + r"[^']*'", body)
    if sq:
        return "single"
    return "none"


# ══════════════════════════════════════════════════════════════
#  CSP PARSER (v2.0.0)
# ══════════════════════════════════════════════════════════════
def parse_csp(headers):
    """Extract and parse Content-Security-Policy header.

    Returns dict with:
      inline_allowed, eval_allowed, nonce_required, nonce_value, raw_csp
    """
    csp_header = headers.get("Content-Security-Policy", "")
    if not csp_header:
        return {"inline_allowed": True, "eval_allowed": True,
                "nonce_required": False, "nonce_value": None, "raw_csp": ""}

    directives = {}
    for part in csp_header.split(';'):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        if tokens:
            directives[tokens[0].lower()] = [t.lower() for t in tokens[1:]]

    script_src = directives.get('script-src', directives.get('default-src', []))

    inline_allowed = "'unsafe-inline'" in script_src or not script_src
    eval_allowed = "'unsafe-eval'" in script_src or not script_src

    nonce_value = None
    nonce_required = False
    for token in script_src:
        if token.startswith("'nonce-"):
            nonce_required = True
            nonce_value = token[7:-1] if token.endswith("'") else token[7:]
            # Nonce presence overrides unsafe-inline in modern browsers
            inline_allowed = False
            break

    # strict-dynamic also overrides unsafe-inline
    if "'strict-dynamic'" in script_src:
        inline_allowed = False

    return {
        "inline_allowed": inline_allowed,
        "eval_allowed": eval_allowed,
        "nonce_required": nonce_required,
        "nonce_value": nonce_value,
        "raw_csp": csp_header,
    }


def score_reflection(contexts, encodings, param_name):
    score = 0
    ctx_scores = {CTX_JAVASCRIPT: 15, CTX_HTML_ATTR: 12, CTX_HTML_BODY: 10, CTX_JSON: 8, CTX_UNKNOWN: 3}
    score += ctx_scores.get(contexts[0], 0) if contexts else 0
    if ENC_RAW in encodings:
        score += 10
    elif ENC_JS_ESCAPED in encodings:
        score += 5
    elif ENC_HTML in encodings:
        score += 2
    high_value = {'q', 'query', 'search', 'keyword', 'text', 'input', 'message',
                  'name', 'title', 'body', 'content', 'value', 'data', 'html',
                  'callback', 'redirect', 'url', 'return', 'next', 'ref', 'src', 'href'}
    if param_name.lower() in high_value:
        score += 8
    return score


def validate_url(url, session, rate_ctrl=None, logger=None):
    result = {"url": url, "reflected": False, "parameters": [],
              "total_score": 0, "error": None, "csp": None}
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            result["error"] = "no_parameters"
            return result
        for pname, pvals in params.items():
            if rate_ctrl:
                rate_ctrl.wait()
            canary = generate_canary(url, pname)
            test_params = {k: list(v) for k, v in params.items()}
            test_params[pname] = [canary]
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                   parsed.params, urlencode(test_params, doseq=True), parsed.fragment))
            try:
                t0 = time.time()
                resp = session.get(test_url, timeout=TIMEOUT, allow_redirects=True)
                duration_ms = int((time.time() - t0) * 1000)
                body = resp.text
            except requests.RequestException as e:
                result["error"] = f"Param {pname}: {str(e)}"
                continue
            encodings = detect_encoding(canary, body)
            if not encodings:
                continue
            contexts = classify_context(canary, body)
            quote_type = detect_quote_type(canary, body)
            pscore = score_reflection(contexts, encodings, pname)

            # CSP parsing (once per URL, on first reflected param)
            if result["csp"] is None:
                result["csp"] = parse_csp(resp.headers)
                if logger:
                    logger.log_csp(url, result["csp"])

            result["parameters"].append({
                "name": pname, "canary": canary, "reflected": True,
                "encodings": encodings, "contexts": contexts,
                "quote_type": quote_type,
                "score": pscore,
                "response_code": resp.status_code,
                "content_type": resp.headers.get("Content-Type", ""),
            })
            result["reflected"] = True
            result["total_score"] += pscore

            if logger:
                logger.log_attempt(url=url, param=pname, context=','.join(contexts),
                                   executed=False, duration_ms=duration_ms)
    except Exception as e:
        result["error"] = str(e)
    return result


# ══════════════════════════════════════════════════════════════
#  POST PARAMETER SUPPORT (v2.0.0)
# ══════════════════════════════════════════════════════════════
def parse_post_data(filepath):
    """Parse POST data file. Format:
    POST https://target.com/api/search
    Content-Type: application/x-www-form-urlencoded
    q=test&page=1
    ---
    """
    entries = []
    if not os.path.isfile(filepath):
        return entries
    with open(filepath) as f:
        content = f.read()
    blocks = content.split('---')
    for block in blocks:
        lines = [l.strip() for l in block.strip().split('\n') if l.strip()]
        if len(lines) < 3:
            continue
        method_line = lines[0]
        if not method_line.upper().startswith('POST'):
            continue
        url = method_line.split(None, 1)[1] if ' ' in method_line else ''
        ct = "application/x-www-form-urlencoded"
        body = lines[-1]
        for line in lines[1:-1]:
            if line.lower().startswith('content-type:'):
                ct = line.split(':', 1)[1].strip()
        entries.append({"url": url, "content_type": ct, "body": body})
    return entries


def validate_post(entry, session, rate_ctrl=None, logger=None):
    """Validate a POST endpoint for reflection."""
    url = entry["url"]
    ct = entry["content_type"]
    body = entry["body"]
    result = {"url": url, "method": "POST", "reflected": False,
              "parameters": [], "total_score": 0, "error": None, "csp": None}

    try:
        if "json" in ct:
            try:
                data = json.loads(body)
            except json.JSONDecodeError:
                result["error"] = "invalid_json_body"
                return result
            for key in data:
                if rate_ctrl:
                    rate_ctrl.wait()
                canary = generate_canary(url, key)
                test_data = dict(data)
                test_data[key] = canary
                try:
                    resp = session.post(url, json=test_data, timeout=TIMEOUT)
                    resp_body = resp.text
                except requests.RequestException as e:
                    result["error"] = str(e)
                    continue
                encodings = detect_encoding(canary, resp_body)
                if not encodings:
                    continue
                contexts = classify_context(canary, resp_body)
                pscore = score_reflection(contexts, encodings, key)
                if result["csp"] is None:
                    result["csp"] = parse_csp(resp.headers)
                result["parameters"].append({
                    "name": key, "canary": canary, "reflected": True,
                    "encodings": encodings, "contexts": contexts,
                    "score": pscore, "method": "POST",
                })
                result["reflected"] = True
                result["total_score"] += pscore
        else:
            # Form-urlencoded
            pairs = {}
            for pair in body.split('&'):
                if '=' in pair:
                    k, v = pair.split('=', 1)
                    pairs[k] = v
            for key in pairs:
                if rate_ctrl:
                    rate_ctrl.wait()
                canary = generate_canary(url, key)
                test_pairs = dict(pairs)
                test_pairs[key] = canary
                try:
                    resp = session.post(url, data=test_pairs, timeout=TIMEOUT)
                    resp_body = resp.text
                except requests.RequestException as e:
                    result["error"] = str(e)
                    continue
                encodings = detect_encoding(canary, resp_body)
                if not encodings:
                    continue
                contexts = classify_context(canary, resp_body)
                pscore = score_reflection(contexts, encodings, key)
                if result["csp"] is None:
                    result["csp"] = parse_csp(resp.headers)
                result["parameters"].append({
                    "name": key, "canary": canary, "reflected": True,
                    "encodings": encodings, "contexts": contexts,
                    "score": pscore, "method": "POST",
                })
                result["reflected"] = True
                result["total_score"] += pscore
    except Exception as e:
        result["error"] = str(e)
    return result


# ══════════════════════════════════════════════════════════════
#  HEADER INJECTION TESTING (v1.0.0)
# ══════════════════════════════════════════════════════════════
INJECTABLE_HEADERS = [
    "Referer", "X-Forwarded-For", "X-Forwarded-Host",
    "X-Original-URL", "X-Rewrite-URL", "True-Client-IP",
    "Client-IP", "X-Client-IP", "X-Real-IP",
    "X-Originating-IP", "CF-Connecting-IP", "From",
    "Contact", "Forwarded",
]


def validate_headers(url, session, rate_ctrl=None, logger=None):
    """Test if any HTTP request headers are reflected in the response body.
    This catches header injection XSS vectors that crawlers miss."""
    results = []
    parsed = urlparse(url)
    base_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))

    for header_name in INJECTABLE_HEADERS:
        if rate_ctrl:
            rate_ctrl.wait()
        canary = generate_canary(url, header_name)
        try:
            resp = session.get(base_url, timeout=TIMEOUT,
                               headers={header_name: canary},
                               allow_redirects=True)
            body = resp.text
        except requests.RequestException:
            continue

        encodings = detect_encoding(canary, body)
        if not encodings:
            continue

        contexts = classify_context(canary, body)
        results.append({
            "url": url, "header": header_name,
            "canary": canary, "reflected": True,
            "encodings": encodings, "contexts": contexts,
            "response_code": resp.status_code,
        })

        if logger:
            logger.log_finding(
                url=url, param=f"header:{header_name}",
                payload=canary, trigger="header_injection",
                severity="high",
            )

    return results


def main():
    parser = argparse.ArgumentParser(description="XSS ReflexionX v1.0.0 — Reflection Validator")
    parser.add_argument("--input", default=None)
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--threads", type=int, default=10)
    parser.add_argument("--proxy", default=None)
    parser.add_argument("--cookie", default=None)
    parser.add_argument("--post-data", default=None, help="POST targets file (v2.0.0)")
    parser.add_argument("--test", action="store_true")
    if add_rate_args:
        add_rate_args(parser)
    else:
        parser.add_argument("--stealth", action="store_true")
    args = parser.parse_args()

    if args.test:
        canary = generate_canary("http://test.com?q=1", "q")
        body = f'<html><body><p>{canary}</p></body></html>'
        enc = detect_encoding(canary, body)
        ctx = classify_context(canary, body)
        sc = score_reflection(ctx, enc, "q")
        # Test CSP parser
        csp = parse_csp({"Content-Security-Policy": "default-src 'self'; script-src 'self' 'nonce-abc123'"})
        assert csp["nonce_required"] == True
        assert csp["inline_allowed"] == False
        assert csp["nonce_value"] == "abc123"
        # Test quote detection
        qt = detect_quote_type(canary, f'<input value="{canary}">')
        assert qt == "double"
        print(f"[OK] canary={canary} ctx={ctx} enc={enc} score={sc} csp={csp} quote={qt}")
        return

    if not args.input or not args.output_dir:
        parser.error("--input and --output-dir are required (use --test for self-test)")

    if not os.path.isfile(args.input):
        print(f"[!] Input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    with open(args.input) as f:
        urls = [l.strip() for l in f if l.strip()]
    if not urls:
        print("[!] No URLs in input file", file=sys.stderr)
        sys.exit(1)

    # Setup v2.0.0 components
    rate_ctrl = None
    if build_rate_controller:
        rate_ctrl = build_rate_controller(args)
    elif getattr(args, 'stealth', False) and RateController:
        rate_ctrl = RateController(stealth=True)

    logger = None
    if ScanLogger:
        logger = ScanLogger(args.output_dir, component="xss_validator")
        logger.log_phase("reflection_validation", status="started", total_urls=len(urls))

    print(f"[*] Validating {len(urls)} reflected URLs ({args.threads} threads)...")
    if rate_ctrl and rate_ctrl.is_stealth:
        print(f"[*] Stealth mode: {rate_ctrl}")
    session = build_session(proxy=args.proxy, cookie=args.cookie)
    results, validated, all_ctx = [], [], {}

    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        fmap = {ex.submit(validate_url, u, session, rate_ctrl, logger): u for u in urls}
        done_n = 0
        for fut in as_completed(fmap):
            done_n += 1
            try:
                r = fut.result()
                results.append(r)
                if r["reflected"]:
                    validated.append(r["url"])
                    all_ctx[r["url"]] = {
                        "parameters": r["parameters"],
                        "total_score": r["total_score"],
                        "csp": r.get("csp"),
                    }
                if done_n % 50 == 0:
                    print(f"  [{done_n}/{len(urls)}] — {len(validated)} confirmed")
            except Exception as e:
                print(f"  [!] {e}", file=sys.stderr)

    # POST data processing (v2.0.0)
    if args.post_data:
        post_entries = parse_post_data(args.post_data)
        if post_entries:
            print(f"[*] Validating {len(post_entries)} POST endpoints...")
            for entry in post_entries:
                r = validate_post(entry, session, rate_ctrl, logger)
                results.append(r)
                if r["reflected"]:
                    key = f"POST:{r['url']}"
                    validated.append(key)
                    all_ctx[key] = {
                        "parameters": r["parameters"],
                        "total_score": r["total_score"],
                        "csp": r.get("csp"),
                        "method": "POST",
                    }

    od = args.output_dir
    with open(os.path.join(od, "reflected_validated.txt"), 'w') as f:
        f.writelines(u + "\n" for u in validated)
    from context_loader import save_contexts
    save_contexts(od, all_ctx)
    scored = sorted(all_ctx.items(), key=lambda x: x[1]["total_score"], reverse=True)
    with open(os.path.join(od, "high_priority_targets.txt"), 'w') as f:
        f.writelines(u + "\n" for u, _ in scored)
    with open(os.path.join(od, "manual_review.txt"), 'w') as f:
        for u, d in all_ctx.items():
            for p in d["parameters"]:
                if p["reflected"] and ENC_RAW not in p["encodings"]:
                    f.write(f"{u} | param={p['name']} | enc={','.join(p['encodings'])} | ctx={','.join(p['contexts'])}\n")
                    break

    raw_n = sum(1 for r in results if r["reflected"] and any(ENC_RAW in p["encodings"] for p in r["parameters"]))
    csp_count = sum(1 for r in results if r.get("csp") and r["csp"].get("raw_csp"))
    print(f"\n[OK] Validated: {len(validated)}/{len(urls)} | Raw: {raw_n} | "
          f"Encoded-only: {len(validated)-raw_n} | CSP parsed: {csp_count}")

    if logger:
        logger.log_phase("reflection_validation", status="completed",
                         validated=len(validated), total=len(urls))


if __name__ == "__main__":
    main()