#!/usr/bin/env python3
"""
XSS ReflexionX v1.0.0 — AI Core Infrastructure
Multi-provider LLM abstraction, prompt templates, token management,
and unified interface for all AI-powered modules.

Supports:
  - OpenAI (GPT-4o, GPT-4o-mini, o1-preview)
  - Anthropic (Claude 4 Sonnet, Claude 4 Opus)
  - Google (Gemini 2.5 Pro, Gemini 2.5 Flash)
  - Local models (Ollama, LM Studio, vLLM)
  - OpenRouter (multi-model gateway)

Usage:
    from ai_core import LLMClient, get_llm_client
    client = get_llm_client()
    resp = client.chat("Generate XSS payloads for HTML attribute context", role="payload_generator")
"""

import argparse, json, os, re, sys, time, urllib.request, urllib.error
from pathlib import Path

# ── Provider endpoints ──────────────────────────────────────────
PROVIDER_ENDPOINTS = {
    "openai":     "https://api.openai.com/v1/chat/completions",
    "anthropic":  "https://api.anthropic.com/v1/messages",
    "gemini":     None,  # handled via REST with API key in URL
    "openrouter": "https://openrouter.ai/api/v1/chat/completions",
    "ollama":     "http://localhost:11434/api/chat",
    "lmstudio":   "http://localhost:1234/v1/chat/completions",
    "vllm":       "http://localhost:8000/v1/chat/completions",
    "together":   "https://api.together.xyz/v1/chat/completions",
    "groq":       "https://api.groq.com/openai/v1/chat/completions",
}

PROVIDER_MODELS = {
    "openai":     "gpt-4o",
    "anthropic":  "claude-sonnet-4-20250514",
    "gemini":     "gemini-2.5-pro",
    "openrouter": "meta-llama/llama-4-maverick",
    "ollama":     "llama3",
    "lmstudio":   "local-model",
    "vllm":       "meta-llama/Meta-Llama-3.1-70B-Instruct",
    "together":   "meta-llama/Meta-Llama-3.1-70B-Instruct-Together",
    "groq":       "llama-3.3-70b-versatile",
}

# ── Role / System Prompt Templates ─────────────────────────────

SYSTEM_PROMPTS = {
    "payload_generator": """You are an expert XSS (Cross-Site Scripting) payload generator for authorized penetration testing.
Your task: given a reflection CONTEXT, generate payloads that execute JavaScript and set the canary
`window._xss_confirmed='HF5XSSCONFIRMED'`.

Rules:
- Output ONLY payload strings, one per line. No explanations, no markdown, no code fences.
- Every payload MUST contain: window._xss_confirmed='HF5XSSCONFIRMED'
- Never use alert() alone — always set the canary.
- Be creative: use rare event handlers, unusual tag combinations, encoding tricks.
- Consider CSP: if CSP blocks inline scripts, use external resource URIs or event handlers.
- For javascript: context, close the string and comment the rest.
- For HTML attributes, break out with the appropriate quote type.

Context information:
{context_info}""",

    "dom_oracle": """You are a JavaScript security analyst specializing in DOM-based XSS (DOMXSS).
Given a JS code snippet, your task is to identify all source→sink data flows that could lead to XSS.

For each flow found, provide:
  - SOURCE: the variable/expression reading user input (location.hash, location.search, document.cookie, etc.)
  - SINK: the dangerous function (innerHTML, outerHTML, document.write, eval, jQuery.html, etc.)
  - PATH: all intermediate assignments/variables data flows through
  - SANITIZER: any filtering/encoding applied (e.g. encodeURI, DOMPurify, textContent) and whether it's bypassable
  - RISK: HIGH (unescaped raw taint), MEDIUM (encoded but trivially decodable), LOW (properly sanitized)
  - BYPASS: if there's a sanitizer, how to bypass it

Format each finding as:
  FLOW: source → sink
  PATH: var1 → var2 → sink
  SANITIZER: what/whether bypassable
  RISK: HIGH|MEDIUM|LOW
  BYPASS: technique or NONE

Be thorough. Minified code is still analyzable — trace variable assignments carefully.""",

    "waf_advisor": """You are a WAF (Web Application Firewall) evasion specialist.
Given an HTTP response that appears to be a WAF block, identify the WAF product and suggest specific bypass techniques.

For each finding, provide:
  - WAF: likely product name
  - CONFIDENCE: high/medium/low
  - BLOCKED_PATTERN: what triggered the block
  - BYPASS_HEADERS: [list] specific HTTP header modifications
  - BYPASS_PAYLOAD: [list] specific payload transformations
  - TECHNIQUE: brief explanation of why the bypass works

Output as JSON array of objects.""",

    "fp_triage": """You are a web security analyst specializing in XSS false positive reduction.
Given a detection event from an automated XSS scanner, determine if it's a TRUE POSITIVE, FALSE POSITIVE, or needs MANUAL REVIEW.

Evaluate based on:
  - Context where payload reflected (HTML body, attribute, JS, JSON, comment)
  - Whether the payload can actually execute (breakout possible?)
  - CSP headers that might block execution
  - Whether the reflection is inside a sandboxed context (iframe sandbox, CSP nonce)
  - Browser-specific rendering differences
  - Encoding that prevents execution

Output format:
  VERDICT: TRUE_POSITIVE | FALSE_POSITIVE | MANUAL_REVIEW
  CONFIDENCE: high|medium|low
  REASON: one sentence
  SUGGESTION: if FP, what would make it real? if TP, exploitation steps.""",

    "chain_synthesizer": """You are an XSS chain analysis expert specializing in multi-step exploit paths.
Given a set of URLs and their parameter reflection contexts, identify multi-step chains where:
  - Parameter is safe on page A but vulnerable on page B
  - POST submission triggers stored content on page C
  - DOM XSS on page A enables XSS on page B via parent/child frame communication
  - Open redirect + stored XSS combine

For each chain found, provide:
  - CHAIN_TYPE: cross_page | stored | dom_chain | redirect_chain | combined
  - STEPS: [step1, step2, ...] each with url, param, context
  - PAYLOAD: recommended payload for the vulnerable step
  - RISK: high|medium|low
  - EXPLOITABILITY: how easy is this chain to trigger in practice

Output as JSON array of objects.""",

    "scan_strategist": """You are an XSS scan strategist. Given target information, design an optimal scan strategy.

Input:
  - URL count: {url_count}
  - DOM risks found: {dom_risks}
  - GET params detected: {get_params}
  - POST forms detected: {post_forms}
  - Target type hint: {target_hint}
  - WAF status: {waf_status}

Provide:
  - SKIP_PHASES: [list] phases to skip and why
  - PRIORITY_URLS: top N URLs to scan first and why
  - THREAD_LEVEL: low/medium/high
  - PAYLOAD_STRATEGY: standard | heavy_mutations | dom_focused | waf_evasion
  - ESTIMATED_TIME: rough minutes estimate
  - REASONING: 2-3 sentences explaining the plan

Output as JSON.""",

    "exploit_author": """You are a professional XSS exploit author for authorized bug bounty hunting.
Your task: craft a complete, ready-to-use exploit for the given XSS finding.

Provide:
  - POC_HTML: a self-contained HTML page that demonstrates the XSS
  - POC_URL: the exact URL with the payload pre-encoded
  - PAYLOAD: the raw payload
  - EXPLANATION: how the XSS works, context, and bypass used
  - IMPACT: cookie theft, session hijack, defacement, etc.
  - SEVERITY: Critical/High/Medium/Low per OWASP risk rating
  - REMEDIATION: specific fix for the developer

The POC should be copy-paste ready for a bug bounty report.""",
}

# ── Core LLM Client ────────────────────────────────────────────

class LLMClient:
    """Unified LLM client supporting multiple providers."""

    def __init__(self, provider="openrouter", api_key=None, model=None,
                 base_url=None, timeout=120, max_retries=3, temperature=0.7):
        self.provider = provider.lower()
        self.api_key = api_key or os.environ.get(
            f"REFLEXIONX_{self.provider.upper()}_API_KEY", "")
        self.model = model or PROVIDER_MODELS.get(self.provider, "gpt-4o")
        self.base_url = base_url or PROVIDER_ENDPOINTS.get(self.provider)
        self.timeout = timeout
        self.max_retries = max_retries
        self.temperature = temperature
        self._total_tokens = 0
        self._call_count = 0
        self._last_error = None

    @property
    def is_configured(self):
        if self.provider in ("ollama", "lmstudio", "vllm"):
            return True  # local, no key needed
        return bool(self.api_key)

    def _estimate_tokens(self, text):
        return max(1, len(text) // 4)

    def chat(self, prompt, role="payload_generator", system_prompt=None,
             max_tokens=2048, temperature=None):
        """Send a chat completion request.

        Parameters
        ----------
        prompt : str
            The user prompt.
        role : str
            Key into SYSTEM_PROMPTS dict for the system message.
        system_prompt : str or None
            Override the system prompt entirely.
        max_tokens : int
            Max tokens in response.
        temperature : float or None
            Override default temperature.

        Returns
        -------
        str or None
            The LLM response text, or None on failure.
        """
        if not self.is_configured:
            self._last_error = f"Provider '{self.provider}' not configured (no API key)"
            return None

        sys_msg = system_prompt or SYSTEM_PROMPTS.get(
            role, SYSTEM_PROMPTS["payload_generator"])

        messages = [
            {"role": "system", "content": sys_msg},
            {"role": "user", "content": prompt},
        ]

        self._call_count += 1
        self._total_tokens += self._estimate_tokens(prompt) + self._estimate_tokens(sys_msg)

        for attempt in range(self.max_retries):
            try:
                return self._call_api(messages, max_tokens, temperature or self.temperature)
            except Exception as e:
                self._last_error = str(e)
                if attempt < self.max_retries - 1:
                    time.sleep(2 ** attempt)
        return None

    def chat_json(self, prompt, role="chain_synthesizer", system_prompt=None,
                  max_tokens=2048):
        """Chat with JSON-mode constraint (OpenAI/OpenRouter only)."""
        resp = self.chat(prompt, role=role, system_prompt=system_prompt,
                         max_tokens=max_tokens)
        if not resp:
            return None
        # Try to extract JSON from response
        json_match = re.search(r'\[.*\]|\{.*\}', resp, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group())
            except json.JSONDecodeError:
                pass
        return None

    def _call_api(self, messages, max_tokens, temperature):
        provider = self.provider

        if provider in ("openai", "openrouter", "together", "groq", "lmstudio", "vllm"):
            return self._call_openai_compatible(messages, max_tokens, temperature)

        elif provider == "anthropic":
            return self._call_anthropic(messages, max_tokens, temperature)

        elif provider == "gemini":
            return self._call_gemini(messages, max_tokens, temperature)

        elif provider == "ollama":
            return self._call_ollama(messages, max_tokens, temperature)

        else:
            raise ValueError(f"Unsupported provider: {provider}")

    def _call_openai_compatible(self, messages, max_tokens, temperature):
        headers = {
            "Content-Type": "application/json",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        payload = {
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }

        req = urllib.request.Request(
            self.base_url,
            data=json.dumps(payload).encode(),
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode())
                choice = data.get("choices", [{}])[0]
                content = choice.get("message", {}).get("content", "")
                # Track token usage
                usage = data.get("usage", {})
                self._total_tokens += usage.get("total_tokens", 0)
                return content.strip() if content else None
        except urllib.error.HTTPError as e:
            body = e.read().decode()[:300]
            raise RuntimeError(f"HTTP {e.code}: {body}")
        except Exception as e:
            raise RuntimeError(str(e))

    def _call_anthropic(self, messages, max_tokens, temperature):
        headers = {
            "Content-Type": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
        }
        # Anthropic uses separate system + messages
        sys_msg = messages[0]["content"] if messages and messages[0]["role"] == "system" else ""
        chat_msgs = [{"role": m["role"], "content": m["content"]}
                     for m in messages if m["role"] != "system"]
        payload = {
            "model": self.model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "system": sys_msg,
            "messages": chat_msgs,
        }
        req = urllib.request.Request(
            self.base_url,
            data=json.dumps(payload).encode(),
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            data = json.loads(resp.read().decode())
            return data.get("content", [{}])[0].get("text", "").strip()

    def _call_gemini(self, messages, max_tokens, temperature):
        # Gemini uses REST with ?key= in URL
        url = f"{self.base_url}?key={self.api_key}&alt=sse"
        # Flatten messages to Gemini format
        contents = []
        for m in messages:
            role = "user" if m["role"] == "user" else "model"
            contents.append({"role": role, "parts": [{"text": m["content"]}]})
        payload = {
            "contents": contents,
            "generationConfig": {"maxOutputTokens": max_tokens, "temperature": temperature},
        }
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            data = json.loads(resp.read().decode())
            candidates = data.get("candidates", [{}])
            return (candidates[0].get("content", {})
                    .get("parts", [{}])[0].get("text", "")).strip()

    def _call_ollama(self, messages, max_tokens, temperature):
        headers = {"Content-Type": "application/json"}
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {"num_predict": max_tokens, "temperature": temperature},
        }
        req = urllib.request.Request(
            self.base_url,
            data=json.dumps(payload).encode(),
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            data = json.loads(resp.read().decode())
            return (data.get("message", {}) or {}).get("content", "").strip()

    def summarize(self, text, max_tokens=256):
        """Summarize long text cheaply."""
        short_prompt = f"Summarize the following in 3 sentences:\n\n{text[:4000]}"
        return self.chat(short_prompt, role="scan_strategist", max_tokens=max_tokens)

    @property
    def usage_stats(self):
        return {"calls": self._call_count, "tokens": self._total_tokens}

    @property
    def last_error(self):
        return self._last_error


# ── Singleton / factory ────────────────────────────────────────

_client_singleton = None

def get_llm_client(provider=None, api_key=None, model=None) -> LLMClient:
    """Get or create the global LLM client singleton."""
    global _client_singleton
    if _client_singleton is None:
        provider = provider or os.environ.get("REFLEXIONX_LLM_PROVIDER", "openrouter")
        api_key = api_key or os.environ.get("REFLEXIONX_LLM_API_KEY", "")
        model = model or os.environ.get("REFLEXIONX_LLM_MODEL", "")
        _client_singleton = LLMClient(
            provider=provider, api_key=api_key, model=model or None)
    return _client_singleton

def configure_llm(provider=None, api_key=None, model=None, **kwargs):
    """Configure or reconfigure the global LLM client."""
    global _client_singleton
    provider = provider or os.environ.get("REFLEXIONX_LLM_PROVIDER", "openrouter")
    api_key = api_key or os.environ.get("REFLEXIONX_LLM_API_KEY", "")
    model = model or os.environ.get("REFLEXIONX_LLM_MODEL", "")
    _client_singleton = LLMClient(
        provider=provider, api_key=api_key, model=model or None, **kwargs)
    return _client_singleton

# ── Prompt helpers ─────────────────────────────────────────────

def format_context_info(context, encoding, quote_type, csp=None, url="", param=""):
    """Format context data into the template string used by payload_generator."""
    csp_info = "No CSP detected"
    if csp:
        parts = []
        if csp.get("inline_allowed"):
            parts.append("inline scripts allowed")
        else:
            parts.append("inline scripts BLOCKED (use event handlers)")
        if csp.get("nonce_required"):
            parts.append(f"nonce-required: {csp.get('nonce_value', '?')}")
        if csp.get("script_src"):
            parts.append(f"script-src: {csp['script_src'][:80]}")
        csp_info = "; ".join(parts) if parts else "No specific CSP restrictions"
    return (
        f"URL: {url}\n"
        f"Parameter: {param}\n"
        f"Context: {context}\n"
        f"Encoding: {encoding}\n"
        f"Quote type: {quote_type}\n"
        f"CSP: {csp_info}"
    )


# ── CLI self-test ─────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AI Core self-test")
    parser.add_argument("--test", action="store_true")
    parser.add_argument("--provider", default=None)
    parser.add_argument("--api-key", default=None)
    parser.add_argument("--prompt", default="Generate 3 XSS payloads for HTML body context")
    args = parser.parse_args()

    if args.test:
        # Test prompt formatting
        fake_csp = {"inline_allowed": False, "nonce_required": True, "nonce_value": "abc123"}
        ctx = format_context_info("html_attribute", "raw", "double", csp=fake_csp,
                                   url="http://test.com/search?q=1", param="q")
        assert "html_attribute" in ctx
        assert "inline scripts BLOCKED" in ctx
        assert "nonce-required" in ctx

        # Test client creation
        client = LLMClient(provider="openrouter")
        assert client.provider == "openrouter"
        assert not client.is_configured  # no key, expected

        # Test template availability
        assert "payload_generator" in SYSTEM_PROMPTS
        assert "dom_oracle" in SYSTEM_PROMPTS
        assert "chain_synthesizer" in SYSTEM_PROMPTS

        print("[OK] AI Core self-test passed")
        print(f"  Registered roles: {list(SYSTEM_PROMPTS.keys())}")
        print(f"  Supported providers: {list(PROVIDER_ENDPOINTS.keys())}")
        raise SystemExit(0)

    client = get_llm_client(provider=args.provider, api_key=args.api_key)
    if not client.is_configured:
        print("[!] LLM not configured. Set REFLEXIONX_LLM_API_KEY or pass --api-key")
        sys.exit(1)
    print(f"[*] Provider: {client.provider} | Model: {client.model}")
    resp = client.chat(args.prompt, max_tokens=512)
    if resp:
        print(f"\n--- Response ---\n{resp[:500]}")
    else:
        print(f"[!] No response. Last error: {client.last_error}")
