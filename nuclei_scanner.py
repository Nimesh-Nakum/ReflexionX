#!/usr/bin/env python3
"""
XSS ReflexionX v1.0.0 — Nuclei XSS Template Scanner
Integrates ProjectDiscovery's Nuclei for template-based XSS detection.
Merges nuclei findings with ReflexionX's own results.

Usage:
    python3 nuclei_scanner.py --urls live.txt --output-dir ./out
    python3 nuclei_scanner.py --test
"""

import argparse, json, os, subprocess, sys, tempfile, time, shutil


def check_nuclei():
    """Check if nuclei is installed and return version."""
    try:
        result = subprocess.run(["nuclei", "-version"],
                                capture_output=True, text=True, timeout=10)
        version = result.stderr.strip() or result.stdout.strip()
        return version
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


def install_nuclei():
    """Attempt to install nuclei via go install."""
    print("[*] Installing nuclei...")
    try:
        env = os.environ.copy()
        env["GOPATH"] = os.path.expanduser("~/go")
        env["PATH"] = f"{env['GOPATH']}/bin:/usr/local/go/bin:{env.get('PATH', '')}"
        subprocess.run(
            ["go", "install", "-v",
             "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"],
            env=env, timeout=300, check=True,
        )
        print("[OK] nuclei installed successfully")
        return True
    except Exception as e:
        print(f"[!] Failed to install nuclei: {e}", file=sys.stderr)
        return False


def update_templates():
    """Update nuclei templates to latest."""
    try:
        subprocess.run(["nuclei", "-update-templates", "-silent"],
                        capture_output=True, timeout=120)
        return True
    except Exception:
        return False


def run_nuclei_scan(urls_file, output_dir, threads=10, timeout_per_url=30,
                    proxy=None, cookie=None, tags=None):
    """Run nuclei with XSS-focused templates against URLs.

    Returns list of finding dicts.
    """
    json_output = os.path.join(output_dir, "nuclei_xss_results.jsonl")

    cmd = [
        "nuclei",
        "-l", urls_file,
        "-tags", ",".join(tags or ["xss"]),
        "-severity", "low,medium,high,critical",
        "-jsonl",
        "-o", json_output,
        "-c", str(threads),
        "-timeout", str(timeout_per_url),
        "-silent",
        "-no-color",
        "-retries", "1",
        "-bulk-size", "25",
        "-rate-limit", "100",
        "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
              "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    ]

    if proxy:
        cmd.extend(["-proxy", proxy])
    if cookie:
        cmd.extend(["-H", f"Cookie: {cookie}"])

    # Run with headless if available
    headless_check = subprocess.run(["nuclei", "-headless", "-h"],
                                     capture_output=True, timeout=5)
    if headless_check.returncode == 0:
        cmd.append("-headless")

    print(f"[*] Running nuclei: {' '.join(cmd[:8])}...")
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, text=True)
        stdout, stderr = proc.communicate(timeout=1800)  # 30 min max
    except subprocess.TimeoutExpired:
        proc.kill()
        print("[!] Nuclei scan timed out after 30 minutes")
        stdout, stderr = proc.communicate()
    except Exception as e:
        print(f"[!] Nuclei error: {e}", file=sys.stderr)
        return []

    # Parse JSONL output
    findings = []
    if os.path.isfile(json_output):
        with open(json_output) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    findings.append({
                        "url": entry.get("matched-at", entry.get("host", "")),
                        "template_id": entry.get("template-id", ""),
                        "template_name": entry.get("info", {}).get("name", ""),
                        "severity": entry.get("info", {}).get("severity", "unknown"),
                        "type": entry.get("type", ""),
                        "matched_at": entry.get("matched-at", ""),
                        "extracted": entry.get("extracted-results", []),
                        "curl_command": entry.get("curl-command", ""),
                        "source": "nuclei",
                    })
                except json.JSONDecodeError:
                    pass

    return findings


def merge_with_reflexionx(nuclei_findings, output_dir):
    """Merge nuclei findings into ReflexionX's poc directory."""
    poc_dir = os.path.join(output_dir, "poc")
    os.makedirs(poc_dir, exist_ok=True)

    poc_file = os.path.join(poc_dir, "poc.txt")

    added = 0
    existing_urls = set()
    if os.path.isfile(poc_file):
        with open(poc_file) as f:
            existing_urls = set(l.strip() for l in f)

    with open(poc_file, "a") as poc_f:
        for finding in nuclei_findings:
            url = finding["url"]
            if url not in existing_urls:
                poc_f.write(url + "\n")
                existing_urls.add(url)
                added += 1

                # Write individual POC file
                import hashlib
                h = hashlib.md5(url.encode()).hexdigest()
                with open(os.path.join(poc_dir, f"{h}_nuclei.txt"), "w") as f:
                    f.write(f"URL: {url}\n")
                    f.write(f"[Nuclei Finding]\n")
                    f.write(f"Template: {finding['template_id']}\n")
                    f.write(f"Name: {finding['template_name']}\n")
                    f.write(f"Severity: {finding['severity']}\n")
                    if finding.get("curl_command"):
                        f.write(f"Reproduce: {finding['curl_command']}\n")

    return added


def main():
    parser = argparse.ArgumentParser(
        description="ReflexionX v1.0.0 — Nuclei XSS Scanner")
    parser.add_argument("--urls", default=None, help="URLs file to scan")
    parser.add_argument("--output-dir", default=".")
    parser.add_argument("--threads", type=int, default=10)
    parser.add_argument("--proxy", default=None)
    parser.add_argument("--cookie", default=None)
    parser.add_argument("--tags", default="xss",
                        help="Nuclei tags (comma-separated)")
    parser.add_argument("--install", action="store_true",
                        help="Install nuclei if not found")
    parser.add_argument("--test", action="store_true")
    args = parser.parse_args()

    if args.test:
        version = check_nuclei()
        if version:
            print(f"[OK] Nuclei found: {version}")
        else:
            print("[OK] Nuclei not installed (optional dependency)")
        print("[OK] Nuclei scanner self-test passed")
        return

    # Check nuclei installation
    version = check_nuclei()
    if not version:
        if args.install:
            if not install_nuclei():
                sys.exit(1)
        else:
            print("[!] Nuclei not found. Run with --install or: "
                  "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
            sys.exit(1)

    if not args.urls or not os.path.isfile(args.urls):
        parser.error("--urls is required and must point to existing file")

    # Update templates
    print("[*] Updating nuclei templates...")
    update_templates()

    tags = [t.strip() for t in args.tags.split(",")]
    findings = run_nuclei_scan(
        args.urls, args.output_dir,
        threads=args.threads, proxy=args.proxy,
        cookie=args.cookie, tags=tags,
    )

    os.makedirs(args.output_dir, exist_ok=True)

    # Save nuclei-specific results
    with open(os.path.join(args.output_dir, "nuclei_findings.json"), "w") as f:
        json.dump(findings, f, indent=2)

    # Merge into ReflexionX POC
    added = merge_with_reflexionx(findings, args.output_dir)

    print(f"\n[OK] Nuclei scan: {len(findings)} findings | {added} new POCs added")
    for f_item in findings:
        sev_color = {"critical": "🔴", "high": "🟠",
                     "medium": "🟡", "low": "🔵"}.get(f_item["severity"], "⚪")
        print(f"  {sev_color} [{f_item['severity']}] {f_item['template_name']}: "
              f"{f_item['url'][:80]}")


if __name__ == "__main__":
    main()
