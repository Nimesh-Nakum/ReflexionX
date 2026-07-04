#!/bin/bash
# ============================================================
#  XSS REFLEXIONX v1.0.0 — Setup Script
#  Installs Python dependencies and Playwright browser
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[*] Installing Python dependencies..."
pip3 install -r "$SCRIPT_DIR/requirements.txt"
pip3 install uro

echo "[*] Installing XSStrike (optional secondary scanner)..."
pip3 install xsstrike || echo "[!] XSStrike install failed (optional — scan will still work)"

echo "[*] Installing Go tools (gau, waybackurls, katana, httpx, kxss, dalfox)..."
go install github.com/lc/gau/v2/cmd/gau@latest || echo "[!] Failed to install gau"
go install github.com/tomnomnom/waybackurls@latest || echo "[!] Failed to install waybackurls"
go install github.com/projectdiscovery/katana/cmd/katana@latest || echo "[!] Failed to install katana"
go install github.com/projectdiscovery/httpx/cmd/httpx@latest || echo "[!] Failed to install httpx"
echo "[*] Compiling custom kxss with HTTP timeout fix..."
if ! command -v git &> /dev/null; then
  echo "[!] git not found, falling back to standard kxss..."
  go install github.com/tomnomnom/hacks/kxss@latest || echo "[!] Failed to install kxss"
else
  rm -rf /tmp/kxss_hacks 2>/dev/null
  git clone https://github.com/tomnomnom/hacks.git /tmp/kxss_hacks -q
  cd /tmp/kxss_hacks/kxss || exit 1
  # Inject HTTP timeout + realistic User-Agent to avoid WAF blocks
  python3 -c "
content = open('main.go').read()
# Add HTTP client timeout (prevents indefinite hangs on WAF tarpits)
content = content.replace('Transport: transport,', 'Transport: transport,\n\tTimeout: 15 * time.Second,')
# Replace the outdated User-Agent with a modern Chrome UA to avoid WAF fingerprinting
content = content.replace(
    'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.100 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36'
)
open('main.go', 'w').write(content)
"
  go mod init kxss >/dev/null 2>&1 || true
  go mod tidy >/dev/null 2>&1 || true
  go build -o "$HOME/go/bin/kxss" || echo "[!] Failed to compile custom kxss"
  cd - > /dev/null
  rm -rf /tmp/kxss_hacks
fi
go install github.com/hahwul/dalfox/v2@latest || echo "[!] Failed to install dalfox"

echo "[*] Installing Nuclei (optional XSS template scanner)..."
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest || echo "[!] Failed to install nuclei (optional)"

echo "[*] Ensuring ~/go/bin is in PATH..."
if [[ ":$PATH:" != *":$HOME/go/bin:"* ]]; then
  echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
  echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.zshrc 2>/dev/null || true
  export PATH=$PATH:$HOME/go/bin
fi

echo "[*] Installing Playwright Chromium browser..."
playwright install chromium

# ── API Key Persistence ──────────────────────────────────────
# Save OPENROUTER_API_KEY to shell profile so it persists across sessions.
setup_api_key() {
  local shell_rc=""
  if [[ -f "$HOME/.zshrc" ]]; then
    shell_rc="$HOME/.zshrc"
  elif [[ -f "$HOME/.bashrc" ]]; then
    shell_rc="$HOME/.bashrc"
  else
    shell_rc="$HOME/.bashrc"
  fi

  # Check if already set in profile
  if grep -q 'OPENROUTER_API_KEY' "$shell_rc" 2>/dev/null; then
    echo "[✓] OPENROUTER_API_KEY already configured in $(basename "$shell_rc")"
    return
  fi

  echo ""
  echo "[?] Enter your OpenRouter API key (get one at https://openrouter.ai/keys)"
  echo "    Press ENTER to skip (AI features will be disabled):"

  # Skip interactive prompt in non-TTY environments (CI/CD, pipes)
  if [[ ! -t 0 ]]; then
    echo "[!] Non-interactive shell detected — skipping API key setup."
    echo "    Set it manually: export OPENROUTER_API_KEY=your_key"
    return
  fi

  read -r api_key

  if [[ -n "$api_key" ]]; then
    echo "" >> "$shell_rc"
    echo "# ReflexionX — OpenRouter API Key" >> "$shell_rc"
    echo "export OPENROUTER_API_KEY=\"$api_key\"" >> "$shell_rc"
    export OPENROUTER_API_KEY="$api_key"
    echo "[✓] API key saved to $(basename "$shell_rc") — persists across sessions"
  else
    echo "[!] Skipped. Set it later with:"
    echo "    echo 'export OPENROUTER_API_KEY=your_key' >> $(basename "$shell_rc")"
  fi
}

setup_api_key

echo ""
echo "[✓] Setup complete. You can now run:"
echo "    ./reflexionx.sh -d example.com -V -D --ai"
echo ""
echo "    Flags:"
echo "    -V            Enable Playwright browser validation"
echo "    -D            Enable DOM XSS analysis (AST-powered)"
echo "    -S            Enable stealth mode (jitter + reduced concurrency)"
echo "    -R            Resume from previous scan output directory"
echo "    -P            POST data file for body parameter testing"
echo "    -b            Blind XSS callback URL (OOB injection)"
echo "    --ai          Enable AI-powered agentic decision layer"
echo "    --model       Swap OpenRouter model at runtime"
echo "    --nuclei      Run nuclei XSS templates"
echo "    --param-mine  Brute-force hidden parameters"
echo ""
echo "    Python orchestrator (optional):"
echo "    python3 orchestrator.py -d example.com -V -D --stealth"

