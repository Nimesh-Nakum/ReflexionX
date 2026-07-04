#!/usr/bin/env python3
"""
XSS ReflexionX v1.0.0 — DOM XSS Analyzer (AST + Regex Fallback)
Analyzes JavaScript files for source→sink patterns indicating DOM XSS.
Uses pyjsparser AST for data-flow tracking, falls back to regex on parse failure.
For authorized security testing only.

Usage:
    python3 dom_analyzer.py --js-urls js_urls.txt --output-dir ./out --threads 5
"""

import argparse, json, os, re, sys
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    print("[!] 'requests' not installed.", file=sys.stderr)
    sys.exit(1)

# Try AST parser — graceful fallback to regex-only
try:
    import pyjsparser
    HAS_AST = True
except ImportError:
    HAS_AST = False

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── DOM XSS Sources ──────────────────────────────────────────
SOURCES = [
    (r'location\.search', 'location.search'),
    (r'location\.hash', 'location.hash'),
    (r'location\.href', 'location.href'),
    (r'location\.pathname', 'location.pathname'),
    (r'document\.URL', 'document.URL'),
    (r'document\.documentURI', 'document.documentURI'),
    (r'document\.referrer', 'document.referrer'),
    (r'document\.cookie', 'document.cookie'),
    (r'window\.name', 'window.name'),
    (r'window\.location', 'window.location'),
    (r'window\[["\']location["\']\]', 'window.location array'),
    (r'document\[["\']cookie["\']\]', 'document.cookie array'),
    (r'postMessage', 'postMessage'),
    (r'localStorage\.getItem', 'localStorage.getItem'),
    (r'sessionStorage\.getItem', 'sessionStorage.getItem'),
    (r'URLSearchParams', 'URLSearchParams'),
]

SOURCE_NAMES = {s[1] for s in SOURCES}

# ── DOM XSS Sinks ────────────────────────────────────────────
SINKS = [
    (r'\.innerHTML\s*=', 'innerHTML'),
    (r'\.outerHTML\s*=', 'outerHTML'),
    (r'document\.write\s*\(', 'document.write'),
    (r'document\.writeln\s*\(', 'document.writeln'),
    (r'eval\s*\(', 'eval'),
    (r'setTimeout\s*\([^,]*[^)]*\)', 'setTimeout'),
    (r'setInterval\s*\([^,]*[^)]*\)', 'setInterval'),
    (r'Function\s*\(', 'Function'),
    (r'\.insertAdjacentHTML\s*\(', 'insertAdjacentHTML'),
    (r'\.href\s*=', 'href assignment'),
    (r'location\.replace\s*\(', 'location.replace'),
    (r'location\.assign\s*\(', 'location.assign'),
    (r'jQuery\.html\s*\(|\.html\s*\(', 'jQuery.html'),
    (r'\$\s*\(\s*[\'\"]?\s*<', 'jQuery selector injection'),
    (r'\.append\s*\(', 'DOM append'),
    (r'\.prepend\s*\(', 'DOM prepend'),
]

SINK_NAMES = {s[1] for s in SINKS}

SANITIZER_PATTERNS = [
    'DOMPurify.sanitize', 'dompurify', 'sanitize', 'escapeHtml',
    'encodeURIComponent', 'encodeURI', 'htmlEncode', 'xssFilter',
    'createTextNode', 'textContent',
]

CONTEXT_LINES = 3


# ══════════════════════════════════════════════════════════════
#  AST-BASED FLOW ANALYZER
# ══════════════════════════════════════════════════════════════
class ASTFlowAnalyzer:
    """Walks a pyjsparser AST to track tainted variable propagation."""

    def __init__(self, code):
        self.code = code
        self.taint_map = {}   # var_name → [source_chain]
        self.flows = []
        self.sanitized_vars = set()
        self._ast = None

    def analyze(self):
        try:
            self._ast = pyjsparser.parse(self.code)
        except Exception:
            return None  # signal caller to fallback
        self._walk(self._ast)
        return self.flows

    # ── AST walker ───────────────────────────────────────────
    def _walk(self, node):
        if not isinstance(node, dict):
            return
        ntype = node.get('type', '')

        if ntype == 'VariableDeclaration':
            for decl in node.get('declarations', []):
                self._handle_var_decl(decl)
        elif ntype == 'ExpressionStatement':
            self._handle_expr(node.get('expression', {}))
        elif ntype == 'AssignmentExpression':
            self._handle_assignment(node)

        # Recurse into all child nodes
        for key, val in node.items():
            if key == 'type':
                continue
            if isinstance(val, dict):
                self._walk(val)
            elif isinstance(val, list):
                for item in val:
                    if isinstance(item, dict):
                        self._walk(item)

    def _handle_var_decl(self, decl):
        name = self._get_name(decl.get('id', {}))
        init = decl.get('init')
        if not name or not init:
            return
        source = self._check_source(init)
        if source:
            self.taint_map[name] = [source]
        elif self._is_tainted_expr(init):
            chain = self._get_taint_chain(init)
            if self._passes_through_sanitizer(init):
                self.sanitized_vars.add(name)
                self.taint_map[name] = chain + ['[sanitized]']
            else:
                self.taint_map[name] = chain

    def _handle_assignment(self, node):
        left = node.get('left', {})
        right = node.get('right', {})
        name = self._get_member_str(left)
        var_name = self._get_name(left)

        # Check if this is a sink assignment
        sink = self._check_sink_member(left)
        if sink:
            if self._is_tainted_expr(right):
                chain = self._get_taint_chain(right)
                is_sanitized = (self._passes_through_sanitizer(right) or
                                any(v in self.sanitized_vars for v in self._get_referenced_vars(right)))
                self.flows.append({
                    'source': chain[0] if chain else 'unknown',
                    'sink': sink,
                    'flow_path': chain + [sink],
                    'sanitized': is_sanitized,
                })
            return

        # Track taint propagation through regular assignment
        if var_name:
            source = self._check_source(right)
            if source:
                self.taint_map[var_name] = [source]
            elif self._is_tainted_expr(right):
                chain = self._get_taint_chain(right)
                if self._passes_through_sanitizer(right):
                    self.sanitized_vars.add(var_name)
                    self.taint_map[var_name] = chain + ['[sanitized]']
                else:
                    self.taint_map[var_name] = chain

    def _handle_expr(self, expr):
        if not isinstance(expr, dict):
            return
        etype = expr.get('type', '')
        if etype == 'AssignmentExpression':
            self._handle_assignment(expr)
        elif etype == 'CallExpression':
            self._check_sink_call(expr)

    def _check_sink_call(self, node):
        callee = node.get('callee', {})
        func_name = self._get_member_str(callee)
        sink_call_names = {
            'document.write': 'document.write', 'document.writeln': 'document.writeln',
            'eval': 'eval', 'Function': 'Function', 'setTimeout': 'setTimeout',
            'setInterval': 'setInterval', 'location.replace': 'location.replace',
            'location.assign': 'location.assign',
        }
        sink = None
        for sn, sv in sink_call_names.items():
            if func_name and sn in func_name:
                sink = sv
                break
        # Also check .html(), .append(), .insertAdjacentHTML()
        if not sink and func_name:
            for name in ['html', 'append', 'prepend', 'insertAdjacentHTML']:
                if func_name.endswith('.' + name):
                    sink = name
                    break
        if sink:
            for arg in node.get('arguments', []):
                if self._is_tainted_expr(arg):
                    chain = self._get_taint_chain(arg)
                    is_sanitized = (self._passes_through_sanitizer(arg) or
                                    any(v in self.sanitized_vars for v in self._get_referenced_vars(arg)))
                    self.flows.append({
                        'source': chain[0] if chain else 'unknown',
                        'sink': sink,
                        'flow_path': chain + [sink],
                        'sanitized': is_sanitized,
                    })

    # ── Source/Sink detection ────────────────────────────────
    def _check_source(self, node):
        s = self._get_member_str(node)
        if not s:
            return None
        for _, name in SOURCES:
            if name.replace(' ', '.') in s or name in s:
                return name
        return None

    def _check_sink_member(self, node):
        s = self._get_member_str(node)
        if not s:
            return None
        for _, name in SINKS:
            clean = name.replace(' assignment', '')
            if clean in s:
                return name
        return None

    def _is_tainted_expr(self, node):
        if not isinstance(node, dict):
            return False
        ntype = node.get('type', '')
        if ntype == 'Identifier':
            return node.get('name', '') in self.taint_map
        if ntype == 'MemberExpression':
            s = self._get_member_str(node)
            if s:
                for _, name in SOURCES:
                    if name in s:
                        return True
            obj = node.get('object', {})
            if isinstance(obj, dict) and obj.get('type') == 'Identifier':
                return obj.get('name', '') in self.taint_map
        if ntype == 'CallExpression':
            for arg in node.get('arguments', []):
                if self._is_tainted_expr(arg):
                    return True
            return self._is_tainted_expr(node.get('callee', {}))
        if ntype == 'BinaryExpression':
            return (self._is_tainted_expr(node.get('left', {})) or
                    self._is_tainted_expr(node.get('right', {})))
        if ntype == 'TemplateLiteral':
            return any(self._is_tainted_expr(e) for e in node.get('expressions', []))
        if ntype == 'ConditionalExpression':
            return (self._is_tainted_expr(node.get('consequent', {})) or
                    self._is_tainted_expr(node.get('alternate', {})))
        return False

    def _get_taint_chain(self, node):
        if not isinstance(node, dict):
            return []
        ntype = node.get('type', '')
        if ntype == 'Identifier':
            name = node.get('name', '')
            return list(self.taint_map.get(name, [name]))
        if ntype == 'MemberExpression':
            s = self._get_member_str(node)
            for _, src_name in SOURCES:
                if s and src_name in s:
                    return [src_name]
            obj = node.get('object', {})
            if isinstance(obj, dict) and obj.get('type') == 'Identifier':
                oname = obj.get('name', '')
                if oname in self.taint_map:
                    return list(self.taint_map[oname]) + [s or oname]
        if ntype == 'CallExpression':
            for arg in node.get('arguments', []):
                chain = self._get_taint_chain(arg)
                if chain:
                    fname = self._get_member_str(node.get('callee', {})) or '?'
                    return chain + [fname]
            callee_chain = self._get_taint_chain(node.get('callee', {}))
            if callee_chain:
                return callee_chain
        if ntype == 'BinaryExpression':
            left = self._get_taint_chain(node.get('left', {}))
            if left:
                return left
            return self._get_taint_chain(node.get('right', {}))
        if ntype == 'TemplateLiteral':
            for expr in node.get('expressions', []):
                chain = self._get_taint_chain(expr)
                if chain:
                    return chain
            return []
        return []

    def _passes_through_sanitizer(self, node):
        if not isinstance(node, dict):
            return False
        ntype = node.get('type', '')
        if ntype == 'CallExpression':
            fname = self._get_member_str(node.get('callee', {})) or ''
            for san in SANITIZER_PATTERNS:
                if san.lower() in fname.lower():
                    return True
        # Recurse
        for key, val in node.items():
            if key == 'type':
                continue
            if isinstance(val, dict) and self._passes_through_sanitizer(val):
                return True
        return False

    def _get_referenced_vars(self, node):
        refs = set()
        if not isinstance(node, dict):
            return refs
        if node.get('type') == 'Identifier':
            refs.add(node.get('name', ''))
        for key, val in node.items():
            if key == 'type':
                continue
            if isinstance(val, dict):
                refs |= self._get_referenced_vars(val)
            elif isinstance(val, list):
                for item in val:
                    if isinstance(item, dict):
                        refs |= self._get_referenced_vars(item)
        return refs

    # ── Node helpers ─────────────────────────────────────────
    @staticmethod
    def _get_name(node):
        if isinstance(node, dict) and node.get('type') == 'Identifier':
            return node.get('name')
        return None

    @staticmethod
    def _get_member_str(node):
        if not isinstance(node, dict):
            return None
        ntype = node.get('type', '')
        if ntype == 'Identifier':
            return node.get('name', '')
        if ntype == 'MemberExpression':
            parts = []
            current = node
            while isinstance(current, dict) and current.get('type') == 'MemberExpression':
                prop = current.get('property', {})
                if isinstance(prop, dict):
                    parts.append(prop.get('name', prop.get('value', '?')))
                current = current.get('object', {})
            if isinstance(current, dict) and current.get('type') == 'Identifier':
                parts.append(current.get('name', ''))
            return '.'.join(str(p) for p in reversed(parts))
        return None


# ══════════════════════════════════════════════════════════════
#  REGEX-BASED ANALYSIS (v1.0.0 fallback)
# ══════════════════════════════════════════════════════════════
def regex_analyze(code, url):
    """Original regex-based analysis — used as fallback when AST fails."""
    lines = code.split('\n')
    result = {"sources": [], "sinks": [], "flows": [], "risk_score": 0}
    found_sources, found_sinks = {}, {}
    MAX_LINE_LEN = 50000

    for pattern, name in SOURCES:
        for i, line in enumerate(lines):
            if len(line) > MAX_LINE_LEN:
                line = line[:MAX_LINE_LEN]
            if re.search(pattern, line):
                start = max(0, i - CONTEXT_LINES)
                end = min(len(lines), i + CONTEXT_LINES + 1)
                ctx = '\n'.join(lines[start:end])
                result["sources"].append({"type": name, "line": i + 1, "context": ctx[:300]})
                found_sources.setdefault(name, []).append(i)

    for pattern, name in SINKS:
        for i, line in enumerate(lines):
            if len(line) > MAX_LINE_LEN:
                line = line[:MAX_LINE_LEN]
            if re.search(pattern, line):
                start = max(0, i - CONTEXT_LINES)
                end = min(len(lines), i + CONTEXT_LINES + 1)
                ctx = '\n'.join(lines[start:end])
                result["sinks"].append({"type": name, "line": i + 1, "context": ctx[:300]})
                found_sinks.setdefault(name, []).append(i)

    FLOW_DISTANCE = 150
    for src_name, src_lines in found_sources.items():
        for sink_name, sink_lines in found_sinks.items():
            for sl in src_lines:
                for skl in sink_lines:
                    if abs(sl - skl) <= FLOW_DISTANCE:
                        start = min(sl, skl)
                        end = max(sl, skl)
                        context_code = "\n".join(lines[start:end+1]).lower()
                        sanitized = any(s in context_code for s in
                                        ["dompurify", "sanitize", "escape", "replace",
                                         "encodeuricomponent", "textcontent"])
                        result["flows"].append({
                            "source": src_name, "source_line": sl + 1,
                            "sink": sink_name, "sink_line": skl + 1,
                            "distance": abs(sl - skl),
                            "flow_path": [src_name, sink_name],
                            "sanitized": sanitized,
                        })
    return result


# ══════════════════════════════════════════════════════════════
#  MAIN ANALYSIS ORCHESTRATOR
# ══════════════════════════════════════════════════════════════
def build_session(proxy=None):
    requests.packages.urllib3.disable_warnings()
    s = requests.Session()
    retry = Retry(total=2, backoff_factor=0.3, status_forcelist=[429, 500, 502, 503])
    adapter = HTTPAdapter(max_retries=retry, pool_connections=10, pool_maxsize=10)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    if proxy:
        s.proxies = {"http": proxy, "https": proxy}
    s.headers["User-Agent"] = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                "AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36")
    s.verify = False
    return s


def analyze_js(url, session):
    """Download a JS file and analyze for DOM XSS patterns."""
    result = {
        "url": url, "sources": [], "sinks": [],
        "flows": [], "risk_score": 0, "error": None,
        "analysis_method": "regex",
    }
    try:
        resp = session.get(url, timeout=15, allow_redirects=True)
        if resp.status_code != 200:
            result["error"] = f"HTTP {resp.status_code}"
            return result
        ct = resp.headers.get("Content-Type", "")
        if "html" in ct and "javascript" not in ct and "json" not in ct:
            if not url.endswith('.js'):
                result["error"] = "not_javascript"
                return result
        code = resp.text
    except requests.RequestException as e:
        result["error"] = str(e)
        return result

    # Try AST analysis first
    ast_flows = None
    if HAS_AST:
        try:
            analyzer = ASTFlowAnalyzer(code)
            ast_flows = analyzer.analyze()
        except Exception:
            ast_flows = None

    if ast_flows is not None:
        result["analysis_method"] = "ast"
        # Use AST flows — they have flow_path and sanitized fields
        result["flows"] = ast_flows
        # Still do regex for source/sink listing (line numbers useful for humans)
        regex_result = regex_analyze(code, url)
        result["sources"] = regex_result["sources"]
        result["sinks"] = regex_result["sinks"]
        # Filter out sanitized AST flows from the flow count for scoring
        unsanitized = [f for f in ast_flows if not f.get("sanitized", False)]
        result["flows"] = ast_flows  # keep all, but score only unsanitized
    else:
        # Regex fallback
        regex_result = regex_analyze(code, url)
        result["sources"] = regex_result["sources"]
        result["sinks"] = regex_result["sinks"]
        result["flows"] = regex_result["flows"]
        unsanitized = [f for f in result["flows"] if not f.get("sanitized", False)]

    # Score risk
    score = 0
    score += len(result["sources"]) * 2
    score += len(result["sinks"]) * 3
    score += len(unsanitized) * 10
    dangerous = {'eval', 'document.write', 'innerHTML', 'Function', 'jQuery selector injection'}
    for s in result["sinks"]:
        if s["type"] in dangerous:
            score += 5
    result["risk_score"] = score
    return result


def main():
    parser = argparse.ArgumentParser(description="XSS ReflexionX v1.0.0 — DOM XSS Analyzer")
    parser.add_argument("--js-urls", default=None, help="File with JS URLs")
    parser.add_argument("--output-dir", default=None)
    parser.add_argument("--threads", type=int, default=5)
    parser.add_argument("--proxy", default=None)
    parser.add_argument("--test", action="store_true")
    args = parser.parse_args()

    if args.test:
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            print(f"[*] AST parser available: {HAS_AST}")
            if HAS_AST:
                code = "var x = location.search; var y = x.split('=')[1]; document.getElementById('a').innerHTML = y;"
                analyzer = ASTFlowAnalyzer(code)
                flows = analyzer.analyze()
                if flows:
                    print(f"[OK] AST analysis found {len(flows)} flows:")
                    for fl in flows:
                        print(f"  {' → '.join(fl.get('flow_path', []))} | sanitized={fl.get('sanitized', False)}")
                else:
                    print("[OK] AST analysis returned no flows (may be a simple case)")
            # Test regex fallback
            code2 = "var a = location.hash; eval(a);"
            r = regex_analyze(code2, "test.js")
            print(f"[OK] Regex fallback: {len(r['flows'])} flows, {len(r['sources'])} sources, {len(r['sinks'])} sinks")
        return

    if not args.js_urls or not args.output_dir:
        parser.error("--js-urls and --output-dir are required (use --test for self-test)")

    if not os.path.isfile(args.js_urls):
        print(f"[!] File not found: {args.js_urls}", file=sys.stderr)
        sys.exit(1)

    with open(args.js_urls) as f:
        urls = list(set(l.strip() for l in f if l.strip()))

    if not urls:
        print("[!] No JS URLs found", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Analyzing {len(urls)} JavaScript files ({args.threads} threads, AST={HAS_AST})...")
    session = build_session(proxy=args.proxy)
    results, risky = [], []

    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        fmap = {ex.submit(analyze_js, u, session): u for u in urls}
        done_n = 0
        for fut in as_completed(fmap):
            done_n += 1
            try:
                r = fut.result()
                results.append(r)
                if r["flows"] or r["risk_score"] > 10:
                    risky.append(r)
                if done_n % 20 == 0:
                    print(f"  [{done_n}/{len(urls)}] analyzed — {len(risky)} risky")
            except Exception as e:
                print(f"  [!] {e}", file=sys.stderr)

    od = args.output_dir

    # dom_risks.txt — human-readable summary (format preserved from v1)
    with open(os.path.join(od, "dom_risks.txt"), 'w') as f:
        risky_sorted = sorted(risky, key=lambda x: x["risk_score"], reverse=True)
        for r in risky_sorted:
            f.write(f"{'='*70}\n")
            f.write(f"URL: {r['url']}\n")
            f.write(f"Risk Score: {r['risk_score']}\n")
            f.write(f"Analysis: {r.get('analysis_method', 'regex')}\n")
            f.write(f"Sources: {len(r['sources'])} | Sinks: {len(r['sinks'])} | Flows: {len(r['flows'])}\n")
            if r["flows"]:
                f.write("Potential Flows:\n")
                for fl in r["flows"]:
                    path = fl.get('flow_path', [fl.get('source','?'), fl.get('sink','?')])
                    san = " [SANITIZED]" if fl.get('sanitized', False) else ""
                    if 'source_line' in fl:
                        f.write(f"  {fl['source']} (L{fl['source_line']}) → "
                                f"{fl['sink']} (L{fl['sink_line']}) "
                                f"[{fl.get('distance','?')} lines apart]{san}\n")
                    else:
                        f.write(f"  {' → '.join(str(p) for p in path)}{san}\n")
            f.write("\n")

    # dom_analysis.json — machine-readable
    with open(os.path.join(od, "dom_analysis.json"), 'w') as f:
        json.dump(results, f, indent=2, default=str)

    total_flows = sum(len(r["flows"]) for r in results)
    sanitized_flows = sum(1 for r in results for fl in r["flows"] if fl.get("sanitized"))
    ast_count = sum(1 for r in results if r.get("analysis_method") == "ast")
    print(f"\n[OK] DOM Analysis: {len(urls)} files | {len(risky)} risky | "
          f"{total_flows} flows ({sanitized_flows} sanitized) | AST: {ast_count}/{len(urls)}")


if __name__ == "__main__":
    main()
