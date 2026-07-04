#!/usr/bin/env python3
"""
XSS ReflexionX v1.0.0 — Auto Form Extractor
Crawls katana output (or direct URLs), fetches HTML pages, extracts <form>
elements, and generates the post_targets.txt file needed by stored_xss_chain.py
and xss_browser.py --post-data.

Output format (tab-separated):
  URL<TAB>data<TAB>content_type

Where <PAYLOAD_PLACEHOLDER> marks where the XSS payload should be injected.

Usage:
    python3 form_extractor.py --urls katana.txt --output post_targets.txt
    python3 form_extractor.py --urls live.txt --content-type json --output post_targets.json
"""

import argparse, json, os, re, sys
from urllib.parse import urljoin, urlparse

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# ── HTML form parsing ──────────────────────────────────────────

def extract_forms(html, base_url=""):
    """Extract <form> elements from HTML. Returns list of form dicts."""
    forms = []
    # Pattern: <form ...> ... </form>
    form_pattern = re.compile(r'<form\b[^>]*>(.*?)</form>', re.IGNORECASE | re.DOTALL)
    # Extract attributes: key="val", key='val', key=val, or standalone key
    attr_pattern = re.compile(r'([a-zA-Z0-9_-]+)(?:\s*=\s*(?:["\']([^"\']*)["\']|([^\s>]+)))?')

    for form_match in form_pattern.finditer(html):
        form_tag = form_match.group(0)
        form_inner = form_match.group(1)
        # Extract just the opening tag e.g. <form action="..." method="post">
        open_tag = re.match(r'<form\b[^>]*>', form_tag, re.IGNORECASE)
        open_tag_str = open_tag.group(0) if open_tag else "<form>"

        # Parse form tag attributes
        attrs = {}
        for am in attr_pattern.finditer(open_tag_str[5:-1]):
            key = am.group(1).lower()
            val = am.group(2) if am.group(2) is not None else (am.group(3) if am.group(3) is not None else "")
            attrs[key] = val

        action = attrs.get("action", "")
        method = attrs.get("method", "get").lower()
        enctype = attrs.get("enctype", "application/x-www-form-urlencoded").lower()
        form_id = attrs.get("id", "")

        # Resolve relative action URLs
        if action and base_url:
            action = urljoin(base_url, action)
        elif not action:
            action = base_url

        # Extract input/select/textarea names
        params = []
        input_pattern = re.compile(r'<input\b[^>]*>', re.IGNORECASE)
        select_pattern = re.compile(r'<select\b[^>]*>(.*?)</select>', re.IGNORECASE | re.DOTALL)
        textarea_pattern = re.compile(r'<textarea\b[^>]*>(.*?)</textarea>', re.IGNORECASE | re.DOTALL)

        for inp in input_pattern.finditer(form_inner):
            inp_attrs = {}
            for am in attr_pattern.finditer(inp.group(0)):
                key = am.group(1).lower()
                val = am.group(2) if am.group(2) is not None else (am.group(3) if am.group(3) is not None else "")
                inp_attrs[key] = val

            name = inp_attrs.get("name", "")
            if not name:
                continue
            input_type = inp_attrs.get("type", "text").lower()
            value = inp_attrs.get("value", "")
            if input_type in ("submit", "button", "image", "reset"):
                continue
            params.append({"name": name, "type": input_type, "value": value})

        for sel in select_pattern.finditer(form_inner):
            sel_attrs = {}
            for am in attr_pattern.finditer(sel.group(0)[:50]):
                key = am.group(1).lower()
                val = am.group(2) if am.group(2) is not None else (am.group(3) if am.group(3) is not None else "")
                sel_attrs[key] = val
            name = sel_attrs.get("name", "")
            if not name:
                continue
            # Find first option value
            opt_match = re.search(r'<option\b[^>]*value=["\']([^"\']*)["\']', sel.group(1), re.IGNORECASE)
            value = opt_match.group(1) if opt_match else ""
            params.append({"name": name, "type": "select", "value": value})

        for ta in textarea_pattern.finditer(form_inner):
            ta_attrs = {}
            for am in attr_pattern.finditer(ta.group(0)[:80]):
                key = am.group(1).lower()
                val = am.group(2) if am.group(2) is not None else (am.group(3) if am.group(3) is not None else "")
                ta_attrs[key] = val
            name = ta_attrs.get("name", "")
            if not name:
                continue
            params.append({"name": name, "type": "textarea", "value": ""})

        if not params:
            continue

        forms.append({
            "action": action,
            "method": method,
            "enctype": enctype,
            "form_id": form_id,
            "params": params,
            "base_url": base_url,
        })

    return forms


def build_post_data_str(form, placeholder="<PAYLOAD_PLACEHOLDER>", target_param=None):
    """Build the data string for a single form.

    If target_param is given, inject placeholder only into that param.
    Otherwise, inject into the first text-like param.
    """
    pairs = []
    text_params = [p for p in form["params"]
                   if p["type"] in ("text", "search", "url", "tel", "email", "textarea", "select")]
    for p in form["params"]:
        if target_param and p["name"] == target_param:
            pairs.append(f"{p['name']}={placeholder}")
        elif not target_param and p in (text_params[:1] if text_params else form["params"][:1]):
            pairs.append(f"{p['name']}={placeholder}")
        else:
            val = p.get("value", "")
            if val:
                pairs.append(f"{p['name']}={val}")
            else:
                pairs.append(f"{p['name']}=")
    return "&".join(pairs)


# ── URL fetching ───────────────────────────────────────────────

def fetch_page(url, timeout=15, cookie=None):
    """Fetch a URL and return (status, html)."""
    if not HAS_REQUESTS:
        return 0, ""
    try:
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
        if cookie:
            headers["Cookie"] = cookie
        resp = requests.get(url, headers=headers, timeout=timeout, verify=False, allow_redirects=True)
        return resp.status_code, resp.text
    except Exception:
        return 0, ""


# ── Main extraction logic ─────────────────────────────────────

def extract_from_urls(urls, cookie=None, max_pages=100, placeholder="<PAYLOAD_PLACEHOLDER>"):
    """Extract forms from a list of URLs. Returns list of post target dicts."""
    targets = []
    seen_actions = set()

    for i, url in enumerate(urls[:max_pages]):
        status, html = fetch_page(url, cookie=cookie)
        if not html:
            continue

        forms = extract_forms(html, base_url=url)
        for form in forms:
            action = form["action"]
            if not action or action in seen_actions:
                continue
            seen_actions.add(action)

            data_str = build_post_data_str(form, placeholder=placeholder)
            targets.append({
                "url": action,
                "data": data_str,
                "content_type": form["enctype"],
                "method": form["method"],
                "source_url": url,
                "params": [p["name"] for p in form["params"]],
            })

    return targets


def extract_from_katana(katana_file, cookie=None, max_pages=200):
    """Extract forms from katana output file (one URL per line)."""
    if not os.path.isfile(katana_file):
        print(f"[!] katana file not found: {katana_file}", file=sys.stderr)
        return []

    urls = [l.strip() for l in open(katana_file) if l.strip() and l.strip().startswith("http")]
    # Deduplicate by netloc + path (drop query/fragment for form fetching)
    seen = set()
    deduped = []
    for u in urls:
        p = urlparse(u)
        key = (p.scheme, p.netloc, p.path)
        if key not in seen:
            seen.add(key)
            deduped.append(u)

    print(f"[*] Form extractor: {len(deduped)} unique URLs from katana output")
    return extract_from_urls(deduped, cookie=cookie, max_pages=max_pages)


# ── Output writers ─────────────────────────────────────────────

def write_tab_separated(targets, output_path):
    """Write post_targets.txt in tab-separated format."""
    with open(output_path, "w", encoding="utf-8") as f:
        for t in targets:
            f.write(f"{t['url']}\t{t['data']}\t{t['content_type']}\n")
    return len(targets)


def write_json(targets, output_path):
    """Write post_targets.json."""
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(targets, f, indent=2)
    return len(targets)


# ── CLI ────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ReflexionX v1.0.0 — Auto Form Extractor")
    parser.add_argument("--urls", default=None, help="File of URLs (one per line)")
    parser.add_argument("--katana", default=None, help="katana.txt output file")
    parser.add_argument("--live", default=None, help="live.txt output file")
    parser.add_argument("--content-type", default=None,
                        choices=["urlencoded", "form-data", "json"],
                        help="Force content type for all forms")
    parser.add_argument("--cookie", default=None, help="Session cookie")
    parser.add_argument("--max-pages", type=int, default=200)
    parser.add_argument("--output", default="post_targets.txt")
    parser.add_argument("--format", choices=["txt", "json"], default="txt")
    parser.add_argument("--placeholder", default="<PAYLOAD_PLACEHOLDER>")
    parser.add_argument("--test", action="store_true")
    args = parser.parse_args()

    if args.test:
        test_html = """
        <html><body>
        <form action="/login" method="POST">
            <input type="text" name="username" value="">
            <input type="password" name="password" value="">
            <input type="submit" name="submit" value="Go">
        </form>
        <form action="/search" method="GET">
            <input type="search" name="q" value="">
        </form>
        </body></html>
        """
        forms = extract_forms(test_html, base_url="https://example.com/")
        assert len(forms) >= 1
        assert forms[0]["action"] == "https://example.com/login"
        assert forms[0]["method"] == "post"
        assert any(p["name"] == "username" for p in forms[0]["params"])
        assert any(p["name"] == "password" for p in forms[0]["params"])

        data_str = build_post_data_str(forms[0])
        assert "username=" in data_str
        assert "<PAYLOAD_PLACEHOLDER>" in data_str

        # Test JSON extraction
        test_html2 = """<form action="/api/comment" method="POST" enctype="application/json">
            <input type="text" name="comment" value="">
            <input type="hidden" name="csrf" value="abc123">
        </form>"""
        forms2 = extract_forms(test_html2, base_url="https://example.com/page")
        assert len(forms2) == 1
        assert forms2[0]["enctype"] == "application/json"
        assert forms2[0]["action"] == "https://example.com/api/comment"

        print("[OK] Form extractor self-test passed")
        print(f"  Detected {len(forms)} forms from test HTML")
        raise SystemExit(0)

    # Determine input source
    input_urls = []
    targets = []
    if args.urls and os.path.isfile(args.urls):
        raw_urls = [l.strip() for l in open(args.urls) if l.strip() and l.startswith("http")]
    elif args.katana and os.path.isfile(args.katana):
        targets = extract_from_katana(args.katana, cookie=args.cookie, max_pages=args.max_pages)
        raw_urls = []
    elif args.live and os.path.isfile(args.live):
        raw_urls = [l.strip() for l in open(args.live) if l.strip() and l.startswith("http")]
    else:
        print("[!] Provide --urls, --katana, or --live", file=sys.stderr)
        sys.exit(1)

    if raw_urls:
        seen = set()
        for u in raw_urls:
            p = urlparse(u)
            key = (p.scheme, p.netloc, p.path)
            if key not in seen:
                seen.add(key)
                input_urls.append(u)
        targets = extract_from_urls(input_urls, cookie=args.cookie, max_pages=args.max_pages)

    if not targets:
        print("[*] No forms found in any fetched pages")
        sys.exit(0)

    # Apply content type override if specified
    if args.content_type:
        ct_map = {
            "urlencoded": "application/x-www-form-urlencoded",
            "form-data": "multipart/form-data",
            "json": "application/json",
        }
        for t in targets:
            t["content_type"] = ct_map.get(args.content_type, t["content_type"])

    # Write output
    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    if args.format == "json":
        count = write_json(targets, args.output)
    else:
        count = write_tab_separated(targets, args.output)

    print(f"[DONE] Extracted {count} forms -> {args.output}")
    print(f"[!] Review {args.output} before scanning. Verify content-type and action URLs.")
    for t in targets[:5]:
        print(f"  {t['url'][:70]}  params={t['params']}")
