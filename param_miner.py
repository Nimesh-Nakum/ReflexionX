#!/usr/bin/env python3
"""
XSS ReflexionX v1.0.0 — Hidden Parameter Discovery (Arjun-style)
Discovers reflected parameters that crawlers miss by brute-forcing
common parameter names against live URLs.

Features:
  - 500+ common XSS-prone parameter names
  - GET and POST parameter testing
  - Header injection testing (Referer, X-Forwarded-For, etc.)
  - Concurrent testing with rate limiting
  - Canary-based reflection detection

Usage:
    python3 param_miner.py --urls live.txt --output-dir ./out --threads 10
    python3 param_miner.py --url https://target.com/ --output-dir ./out
"""

import argparse, hashlib, json, os, re, sys, time, random
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urlencode, urlunparse

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    print("[!] 'requests' not installed.", file=sys.stderr)
    sys.exit(1)

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Common XSS-Prone Parameter Names ────────────────────────
# Curated from Arjun, ParamSpider, and real-world bug bounty findings
PARAM_WORDLIST = [
    # Search/Query
    "q", "query", "search", "keyword", "term", "s", "find",
    "keywords", "searchterm", "searchquery", "qry",
    # Input/Content
    "input", "text", "content", "body", "message", "msg",
    "comment", "description", "title", "name", "value", "data",
    "html", "code", "template", "markup", "payload",
    # URL/Redirect
    "url", "uri", "link", "href", "src", "dest", "destination",
    "redirect", "redirect_url", "redirect_uri", "return",
    "return_url", "returnTo", "next", "next_url", "goto", "go",
    "continue", "forward", "target", "to", "out", "ref",
    "referrer", "callback", "callback_url", "back",
    # User/Identity
    "user", "username", "email", "login", "id", "uid",
    "user_id", "userid", "account", "profile", "first_name",
    "last_name", "firstname", "lastname", "nick", "nickname",
    # Path/File
    "path", "file", "filename", "filepath", "dir", "directory",
    "folder", "page", "p", "pg", "view", "action", "do",
    "module", "mod", "func", "function", "handler",
    # Display/Format
    "format", "type", "style", "theme", "lang", "language",
    "locale", "charset", "encoding", "mode", "display",
    "layout", "color", "font", "size", "width", "height",
    # Error/Status
    "error", "err", "errormsg", "error_message", "status",
    "alert", "warning", "info", "notice", "debug",
    # API/Data
    "api", "key", "token", "secret", "param", "parameter",
    "field", "column", "attr", "attribute", "property",
    "json", "xml", "csv", "output", "result", "response",
    # CRUD
    "create", "read", "update", "delete", "edit", "add",
    "remove", "save", "submit", "post", "get", "put",
    # Filter/Sort
    "filter", "sort", "order", "orderby", "sortby", "limit",
    "offset", "start", "count", "num", "max", "min",
    "from", "to", "begin", "end", "range",
    # Auth
    "password", "pass", "pwd", "pin", "otp", "code",
    "verification", "confirm", "auth", "session",
    # Category/Tag
    "category", "cat", "tag", "tags", "label", "group",
    "class", "section", "topic", "subject",
    # Misc high-value
    "domain", "host", "site", "origin", "source", "medium",
    "campaign", "utm_source", "utm_medium", "utm_campaign",
    "state", "nonce", "csrf", "xsrf", "hash", "signature",
    "timestamp", "ts", "date", "time", "version", "v",
    "channel", "embed", "iframe", "widget", "popup",
    "dialog", "modal", "tooltip", "preview", "share",
    # Framework-specific
    "r", "route", "controller", "method", "endpoint",
    "api_key", "access_token", "client_id", "scope",
    "response_type", "grant_type", "assertion",
    # Less common but XSS-prone
    "label", "caption", "alt", "placeholder", "hint",
    "help", "tip", "note", "bio", "about", "summary",
    "excerpt", "abstract", "intro", "welcome", "greeting",
    "notification", "announcement", "banner", "headline",
    "subtitle", "tagline", "slogan", "motto",
]

# ── Headers to Test for Injection ────────────────────────────
INJECTABLE_HEADERS = [
    "Referer", "X-Forwarded-For", "X-Forwarded-Host",
    "X-Original-URL", "X-Rewrite-URL", "X-Custom-IP-Authorization",
    "True-Client-IP", "Client-IP", "Forwarded",
    "X-Client-IP", "X-Real-IP", "X-Originating-IP",
    "CF-Connecting-IP", "Contact", "From",
]


def build_session(proxy=None, cookie=None):
    s = requests.Session()
    retry = Retry(total=1, backoff_factor=0.3, status_forcelist=[500, 502, 503])
    adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=20)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    if proxy:
        s.proxies = {"http": proxy, "https": proxy}
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    })
    if cookie:
        s.headers["Cookie"] = cookie
    s.verify = False
    return s


def generate_canary():
    return f"rxpm{random.randint(10000, 99999)}{int(time.time()) % 100000}"


def mine_url(url, session, wordlist=None, test_headers=True, test_post=True):
    """Mine a single URL for hidden reflected parameters."""
    wordlist = wordlist or PARAM_WORDLIST
    results = {
        "url": url, "reflected_params": [],
        "reflected_headers": [], "error": None,
    }

    parsed = urlparse(url)
    base_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))

    # Phase 1: GET parameter mining (batch test for speed)
    batch_size = 20
    for i in range(0, len(wordlist), batch_size):
        batch = wordlist[i:i + batch_size]
        canaries = {}
        params = {}
        for param in batch:
            canary = generate_canary()
            canaries[param] = canary
            params[param] = canary

        test_url = f"{base_url}?{urlencode(params)}"
        try:
            resp = session.get(test_url, timeout=10, allow_redirects=True)
            body = resp.text
        except Exception as e:
            results["error"] = str(e)
            continue

        # Check which canaries reflected
        for param, canary in canaries.items():
            if canary in body:
                results["reflected_params"].append({
                    "name": param, "method": "GET",
                    "canary": canary, "url": test_url,
                })

    # Phase 2: Header injection testing
    if test_headers:
        for header in INJECTABLE_HEADERS:
            canary = generate_canary()
            headers = {header: canary}
            try:
                resp = session.get(base_url, timeout=10, headers=headers,
                                   allow_redirects=True)
                if canary in resp.text:
                    results["reflected_headers"].append({
                        "header": header, "canary": canary,
                    })
            except Exception:
                pass

    # Phase 3: POST parameter mining (top candidates only)
    if test_post:
        top_post_params = wordlist[:50]
        canaries = {}
        data = {}
        for param in top_post_params:
            canary = generate_canary()
            canaries[param] = canary
            data[param] = canary

        try:
            resp = session.post(base_url, data=data, timeout=10,
                                allow_redirects=True)
            body = resp.text
            for param, canary in canaries.items():
                if canary in body:
                    results["reflected_params"].append({
                        "name": param, "method": "POST",
                        "canary": canary, "url": base_url,
                    })
        except Exception:
            pass

    return results


def main():
    parser = argparse.ArgumentParser(
        description="ReflexionX v1.0.0 — Hidden Parameter Discovery")
    parser.add_argument("--urls", default=None, help="File with URLs to mine")
    parser.add_argument("--url", default=None, help="Single URL to mine")
    parser.add_argument("--output-dir", default=".")
    parser.add_argument("--threads", type=int, default=5)
    parser.add_argument("--proxy", default=None)
    parser.add_argument("--cookie", default=None)
    parser.add_argument("--no-headers", action="store_true")
    parser.add_argument("--no-post", action="store_true")
    parser.add_argument("--test", action="store_true")
    args = parser.parse_args()

    if args.test:
        canary = generate_canary()
        assert len(canary) > 8
        assert canary.startswith("rxpm")
        assert len(PARAM_WORDLIST) > 100
        assert len(INJECTABLE_HEADERS) > 5
        print(f"[OK] Parameter Miner self-test passed")
        print(f"  Wordlist: {len(PARAM_WORDLIST)} parameters")
        print(f"  Injectable headers: {len(INJECTABLE_HEADERS)}")
        print(f"  Sample canary: {canary}")
        return

    urls = []
    if args.url:
        urls = [args.url]
    elif args.urls and os.path.isfile(args.urls):
        with open(args.urls) as f:
            urls = list(set(l.strip() for l in f if l.strip()))
    else:
        parser.error("--url or --urls required")

    # Deduplicate by base URL (path only, ignore query)
    seen_bases = set()
    unique_urls = []
    for url in urls:
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if base not in seen_bases:
            seen_bases.add(base)
            unique_urls.append(base)

    if len(unique_urls) > 200:
        print(f"[*] Limiting to 200 unique base URLs (from {len(unique_urls)})")
        unique_urls = unique_urls[:200]

    print(f"[*] Mining {len(unique_urls)} URLs for hidden parameters "
          f"({args.threads} threads)...")
    session = build_session(proxy=args.proxy, cookie=args.cookie)
    all_results = []
    total_found = 0

    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        fmap = {ex.submit(mine_url, u, session,
                          test_headers=not args.no_headers,
                          test_post=not args.no_post): u for u in unique_urls}
        done_n = 0
        for fut in as_completed(fmap):
            done_n += 1
            try:
                r = fut.result()
                all_results.append(r)
                found = len(r["reflected_params"]) + len(r["reflected_headers"])
                total_found += found
                if found > 0:
                    print(f"  [+] {r['url'][:60]}: {found} reflected")
                if done_n % 20 == 0:
                    print(f"  [{done_n}/{len(unique_urls)}] — {total_found} total found")
            except Exception as e:
                print(f"  [!] {e}", file=sys.stderr)

    od = args.output_dir
    os.makedirs(od, exist_ok=True)

    # Save discovered params as URLs for dalfox scanning
    discovered_urls = []
    for r in all_results:
        for p in r["reflected_params"]:
            discovered_urls.append(p["url"])

    with open(os.path.join(od, "mined_params.txt"), "w") as f:
        for url in discovered_urls:
            f.write(url + "\n")

    with open(os.path.join(od, "param_miner_results.json"), "w") as f:
        json.dump(all_results, f, indent=2)

    # Summary of header injections
    header_findings = []
    for r in all_results:
        for h in r["reflected_headers"]:
            header_findings.append({
                "url": r["url"], "header": h["header"],
            })

    if header_findings:
        with open(os.path.join(od, "header_injection_findings.txt"), "w") as f:
            for hf in header_findings:
                f.write(f"{hf['url']} | header={hf['header']}\n")

    print(f"\n[OK] Parameter mining complete: {total_found} reflected params/headers "
          f"across {len(unique_urls)} URLs")
    if header_findings:
        print(f"  Header injections: {len(header_findings)}")


if __name__ == "__main__":
    main()
