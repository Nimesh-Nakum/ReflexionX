#!/usr/bin/env python3
"""
XSS ReflexionX v1.0.0 — Context Manager
Smart chunking, URL deduplication, and DOM filtering to reduce
AI context size and improve httpx/scan efficiency.

Usage (CLI):
  # Deduplicate & filter URLs before httpx
  python3 context_manager.py --mode filter_urls --input all_urls.txt --output filtered.txt

  # Extract attack surface from HTML
  python3 context_manager.py --mode extract_dom --input page.html --output surface.txt

  # Split large text with overlap
  python3 context_manager.py --mode split --input big.js --output chunks_prefix
"""

import argparse
import json
import os
import re
import sys
from urllib.parse import urlparse, parse_qs
from collections import defaultdict

# ── Static extensions to filter out ──────────────────────────
STATIC_EXTENSIONS = {
    # Images
    '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico', '.bmp', '.webp', '.avif',
    # Fonts
    '.woff', '.woff2', '.ttf', '.eot', '.otf',
    # Media
    '.mp4', '.mp3', '.avi', '.mov', '.wmv', '.flv', '.webm', '.ogg',
    # Documents
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    # Archives
    '.zip', '.tar', '.gz', '.rar', '.7z', '.bz2',
    # Other
    '.map', '.swf', '.wasm',
}

# Extensions that are static UNLESS they have query parameters
CONDITIONAL_STATIC = {'.css', '.js'}

# ── High-value parameter names (boost priority) ─────────────
HIGH_VALUE_PARAMS = {
    'q', 'query', 'search', 'keyword', 'term', 's',          # Search
    'url', 'redirect', 'return', 'next', 'goto', 'continue',  # Redirects
    'callback', 'cb', 'jsonp',                                 # JSONP
    'ref', 'src', 'href', 'link', 'path',                     # URL refs
    'template', 'html', 'content', 'body', 'data',            # Content injection
    'msg', 'message', 'error', 'text', 'title', 'name',       # Text reflection
    'page', 'view', 'action', 'type', 'mode', 'lang',         # App logic
    'file', 'filename', 'include', 'load',                     # File inclusion
    'id', 'uid', 'user', 'account',                            # Identifiers
}


class URLChunker:
    """Deduplicate and filter massive URL lists for efficient scanning."""

    def __init__(self, keep_js=False):
        self.keep_js = keep_js
        self.stats = {"original": 0, "filtered": 0, "static_removed": 0,
                       "duplicates_removed": 0, "no_params_removed": 0}

    def _get_extension(self, path):
        """Extract file extension from URL path."""
        # Remove query string and fragments
        clean = path.split('?')[0].split('#')[0]
        _, ext = os.path.splitext(clean)
        return ext.lower()

    def _is_static(self, url):
        """Check if URL points to a static resource."""
        parsed = urlparse(url)
        ext = self._get_extension(parsed.path)

        if ext in STATIC_EXTENSIONS:
            return True

        if ext in CONDITIONAL_STATIC:
            # Keep .js/.css only if they have query params (possible reflection)
            if self.keep_js and ext == '.js':
                return False
            if parsed.query:
                return False
            return True

        return False

    def _get_signature(self, url):
        """
        Create a signature from path + sorted parameter names.
        URLs with the same signature are considered duplicates.
        e.g. /api?id=1&name=foo and /api?id=2&name=bar → same signature
        """
        parsed = urlparse(url)
        # Normalize path
        path = parsed.path.rstrip('/').lower()
        if not path:
            path = '/'
        # Get sorted parameter names (ignore values)
        params = sorted(parse_qs(parsed.query, keep_blank_values=True).keys())
        return f"{parsed.netloc.lower()}{path}|{'&'.join(params)}"

    def _score_url(self, url):
        """Score URL by parameter value for prioritization."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        score = 0

        for param_name in params:
            if param_name.lower() in HIGH_VALUE_PARAMS:
                score += 5
            elif '=' in parsed.query:
                score += 1

        # Bonus for paths containing interesting keywords
        path_lower = parsed.path.lower()
        for keyword in ('api', 'search', 'login', 'auth', 'admin', 'debug',
                        'test', 'dev', 'staging', 'callback', 'webhook'):
            if keyword in path_lower:
                score += 3

        return score

    def process_urls(self, urls, prioritize=True):
        """
        Filter and deduplicate URLs.
        Returns a list of unique, high-value URLs sorted by priority.
        """
        self.stats["original"] = len(urls)
        seen_signatures = {}
        parameterized = []
        no_params = []

        for url in urls:
            url = url.strip()
            if not url or not url.startswith(('http://', 'https://')):
                continue

            # Filter static files
            if self._is_static(url):
                self.stats["static_removed"] += 1
                continue

            # Deduplicate by signature
            sig = self._get_signature(url)
            if sig in seen_signatures:
                self.stats["duplicates_removed"] += 1
                continue

            seen_signatures[sig] = url

            # Separate parameterized from non-parameterized
            if '?' in url and '=' in url:
                parameterized.append(url)
            else:
                no_params.append(url)

        # Prioritize: parameterized URLs first, sorted by score
        if prioritize:
            parameterized.sort(key=lambda u: self._score_url(u), reverse=True)

        # Include some non-parameterized URLs (for crawling/DOM analysis)
        # but cap them to avoid flooding httpx
        max_no_params = min(len(no_params), 2000)
        result = parameterized + no_params[:max_no_params]

        self.stats["filtered"] = len(result)
        self.stats["no_params_removed"] = len(no_params) - max_no_params
        return result

    def chunk(self, urls, chunk_size=500):
        """Split URL list into manageable batches."""
        for i in range(0, len(urls), chunk_size):
            yield urls[i:i + chunk_size]


class DOMExtractor:
    """Extract only the attack surface from HTML pages."""

    @staticmethod
    def extract_attack_surface(html, reflection_marker=None):
        """
        Parse HTML and return only security-relevant elements:
        - <script> tags (inline and external)
        - <form> tags with inputs
        - Standalone <input>, <textarea>, <select>
        - CSP/security meta tags
        - Elements containing reflection markers
        """
        try:
            from bs4 import BeautifulSoup
        except ImportError:
            # Fallback: return truncated raw HTML
            return html[:8000]

        soup = BeautifulSoup(html, 'html.parser')
        parts = []

        # Extract all script tags
        for script in soup.find_all('script'):
            content = script.string
            src = script.get('src', '')
            if content:
                # Inline script — include full content
                parts.append(f"<script>{content.strip()}</script>")
            elif src:
                parts.append(f'<script src="{src}"></script>')

        # Extract forms with their inputs
        for form in soup.find_all('form'):
            parts.append(str(form))

        # Extract standalone inputs (not inside forms)
        for tag_name in ('input', 'textarea', 'select'):
            for tag in soup.find_all(tag_name):
                if not tag.find_parent('form'):
                    parts.append(str(tag))

        # Extract event handlers on any element
        event_attrs = [attr for attr in ['onclick', 'onload', 'onerror',
                       'onmouseover', 'onfocus', 'onblur', 'onsubmit',
                       'onchange', 'onkeyup', 'onkeydown']
                       if soup.find(attrs={attr: True})]
        for attr in event_attrs:
            for tag in soup.find_all(attrs={attr: True}):
                parts.append(str(tag))

        # Extract security-related meta tags
        for meta in soup.find_all('meta'):
            equiv = meta.get('http-equiv', '').lower()
            if equiv in ('content-security-policy', 'x-xss-protection',
                         'x-content-type-options', 'refresh'):
                parts.append(str(meta))

        # Extract elements containing reflection marker
        if reflection_marker:
            try:
                for tag in soup.find_all(string=re.compile(re.escape(reflection_marker))):
                    # Walk up 3 parent levels for context
                    parent = tag.parent
                    for _ in range(3):
                        if parent and parent.parent:
                            parent = parent.parent
                    if parent:
                        parent_str = str(parent)
                        if parent_str not in parts:
                            parts.append(parent_str)
            except Exception:
                pass

        # Extract <a> tags with javascript: hrefs
        for a_tag in soup.find_all('a', href=True):
            if a_tag['href'].strip().lower().startswith('javascript:'):
                parts.append(str(a_tag))

        return '\n'.join(parts) if parts else html[:8000]


class SmartSplitter:
    """Split large text files with overlap to preserve vulnerability context."""

    @staticmethod
    def split(text, chunk_size=4000, overlap=500):
        """
        Split text into overlapping chunks, breaking at newline boundaries.
        Ensures source→sink relationships aren't split across chunks.
        """
        if len(text) <= chunk_size:
            return [text]

        chunks = []
        start = 0
        text_len = len(text)

        while start < text_len:
            end = min(start + chunk_size, text_len)

            if end < text_len:
                # Try to break at a newline to keep code blocks intact
                chunk = text[start:end]
                last_newline = chunk.rfind('\n')
                if last_newline > chunk_size // 2:
                    end = start + last_newline + 1

            chunks.append(text[start:end])

            # Move forward, keeping overlap
            next_start = end - overlap
            if next_start <= start:
                next_start = end  # Prevent infinite loop
            start = next_start

        return chunks

    @staticmethod
    def split_json_report(data, batch_size=20):
        """Split a JSON array/dict into batches for map-reduce analysis."""
        if isinstance(data, list):
            for i in range(0, len(data), batch_size):
                yield data[i:i + batch_size]
        elif isinstance(data, dict):
            items = list(data.items())
            for i in range(0, len(items), batch_size):
                yield dict(items[i:i + batch_size])


# ── CLI Interface ────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description='ReflexionX v1.0.0 — Context Manager')
    parser.add_argument('--mode',
        choices=['filter_urls', 'extract_dom', 'split'],
        default=None, help='Operation mode')
    parser.add_argument('--input', default=None,
        help='Input file path')
    parser.add_argument('--output', default=None,
        help='Output file path (or prefix for split mode)')
    parser.add_argument('--keep-js', action='store_true',
        help='Keep .js URLs (for DOM analysis)')
    parser.add_argument('--chunk-size', type=int, default=4000,
        help='Chunk size for split mode')
    parser.add_argument('--overlap', type=int, default=500,
        help='Overlap size for split mode')
    parser.add_argument('--marker', default=None,
        help='Reflection marker to search for in DOM mode')
    parser.add_argument("--test", action="store_true",
        help="Run self-test and exit")
    args = parser.parse_args()

    if args.test:
        chunker = URLChunker()
        sample_urls = [
            "https://example.com/page?id=1&q=test",
            "https://example.com/page?id=2&q=test",
            "https://other.com/page?id=1",
            "https://example.com/page?foo=bar&baz=qux",
            "https://api.example.com/users/123",
        ]
        result = chunker.process_urls(sample_urls)
        print(f"[TEST] URLChunker: {len(result)} unique endpoints from {len(sample_urls)} URLs")
        assert len(result) > 0, "URLChunker returned empty"
        print("[OK] context_manager.py self-test passed")
        sys.exit(0)

    if args.mode == 'filter_urls':
        if not os.path.exists(args.input):
            print(json.dumps({"error": "Input file not found"}))
            sys.exit(1)

        with open(args.input, 'r', encoding='utf-8', errors='ignore') as f:
            urls = f.read().splitlines()

        chunker = URLChunker(keep_js=args.keep_js)
        filtered = chunker.process_urls(urls)

        with open(args.output, 'w', encoding='utf-8') as f:
            f.write('\n'.join(filtered) + '\n' if filtered else '')

        # Print stats as JSON for the shell script to parse
        print(json.dumps(chunker.stats))

    elif args.mode == 'extract_dom':
        if not os.path.exists(args.input):
            print(json.dumps({"error": "Input file not found"}))
            sys.exit(1)

        with open(args.input, 'r', encoding='utf-8', errors='ignore') as f:
            html = f.read()

        extractor = DOMExtractor()
        surface = extractor.extract_attack_surface(
            html, reflection_marker=args.marker)

        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(surface)

        print(json.dumps({
            "original_size": len(html),
            "surface_size": len(surface),
            "reduction_pct": round(
                (1 - len(surface) / max(len(html), 1)) * 100, 1)
        }))

    elif args.mode == 'split':
        if not os.path.exists(args.input):
            print(json.dumps({"error": "Input file not found"}))
            sys.exit(1)

        with open(args.input, 'r', encoding='utf-8', errors='ignore') as f:
            text = f.read()

        splitter = SmartSplitter()
        chunks = splitter.split(
            text, chunk_size=args.chunk_size, overlap=args.overlap)

        for i, chunk in enumerate(chunks):
            chunk_file = f"{args.output}.chunk_{i}.txt"
            with open(chunk_file, 'w', encoding='utf-8') as f:
                f.write(chunk)

        print(json.dumps({"chunks": len(chunks),
                           "original_size": len(text)}))


if __name__ == '__main__':
    main()
