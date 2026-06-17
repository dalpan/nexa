# NEXA
**N**ative **E**xposure & **X**-ray **A**nalyzer

> Frontend Exposure & Secret Detection — for authorized security assessments only.

NEXA is a passive frontend security scanner that discovers exposed secrets, API keys, credentials, and sensitive data in JavaScript bundles, source maps, and HTML of web applications.

---

## Features

- **Secret detection** — AWS keys, Google API keys, Stripe keys, GitHub PATs, JWTs, Slack tokens, Sentry DSNs, and 25+ patterns
- **Framework fingerprinting** — Next.js, Nuxt, React, Vue, Angular, Vite, Svelte, Webpack, Astro, Gatsby
- **Source map detection** — publicly accessible `.map` files that expose original source code
- **`__NEXT_DATA__` extraction** — scans SSR props for embedded credentials
- **Subdomain discovery** — passive enumeration via crt.sh + HackerTarget
- **WAF/ISP detection** — detects Cloudflare, Akamai, Sucuri, ISP blocks with clear warnings
- **WAF bypass mode** — User-Agent rotation, Sec-Fetch headers, jitter, cookie persistence
- **Pipe-friendly** — works with `subfinder`, `httpx`, `jq`, and other tools
- **Multiple output formats** — rich terminal table, JSON, JSON Lines (JSONL)
- **Passive only** — no state-changing requests, safe for authorized assessments

---

## Install

### System-wide (recommended)
```bash
git clone https://github.com/dalpan/nexa
cd nexa
make install     # uses pipx — nexa available anywhere in terminal
```

### Requirements
- Python 3.11+
- [pipx](https://pipx.pypa.io/stable/) (`brew install pipx` on macOS)

### Update after changes
```bash
cd nexa && make update
```

---

## Usage

```bash
# Basic scan
nexa scan target.com

# Deeper scan with WAF bypass
nexa scan target.com --depth 3 --waf-bypass --waf-strategy aggressive

# Skip subdomain discovery (faster)
nexa scan target.com --no-subdomain

# Only show HIGH and above
nexa scan target.com --min-severity HIGH

# Export CSV
nexa scan target.com --export-csv
```

### Pipe Mode (combine with other tools)

```bash
# subfinder -> httpx -> nexa
subfinder -d target.com | httpx | nexa scan

# Filter HIGH+ findings with jq
subfinder -d target.com | httpx | nexa scan --format jsonl \
  | jq 'select(.severity=="HIGH" or .severity=="CRITICAL")'

# Scan a list of targets
cat targets.txt | nexa scan --format jsonl

# or use --list flag
nexa scan --list targets.txt

# Full pipeline example
nexa scan target.com --format jsonl \
  | jq -r 'select(.severity=="CRITICAL") | "\(.title): \(.value)"'
```

### Output Formats

| Flag | Description |
|------|-------------|
| `--format text` | Rich terminal table (default) |
| `--format jsonl` | One JSON per line — pipe-friendly |
| `--format json` | Full JSON report to stdout |

Progress output always goes to **stderr** so stdout stays clean for piping.

---

## Options

| Option | Default | Description |
|--------|---------|-------------|
| `--depth` | 2 | Crawl depth |
| `--max-pages` | 50 | Max pages to crawl |
| `--concurrency` | 10 | Concurrent requests |
| `--timeout` | 15 | Request timeout (seconds) |
| `--rate-limit` | 5.0 | Requests per second |
| `--min-severity` | INFO | Filter by severity |
| `--no-subdomain` | — | Skip subdomain discovery |
| `--no-www` | — | Skip www. variant crawl |
| `--crawl-subdomains` | — | Also crawl discovered subdomains |
| `--historical-urls` | — | Fetch URLs from Wayback Machine |
| `--waf-bypass` | — | Enable WAF bypass mode |
| `--waf-strategy` | rotate | rotate / random / aggressive |
| `--format / -f` | text | text / json / jsonl |
| `--quiet / -q` | — | Suppress progress output |
| `--export-csv` | — | Export findings to CSV |
| `--list / -l` | — | File with one target per line |
| `--url` | — | Extra URL to include (repeatable) |

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Scan complete, no CRITICAL findings |
| 1 | Error |
| 2 | CRITICAL findings detected |
| 130 | Interrupted (Ctrl+C) |

---

## Severity Levels

| Level | Examples |
|-------|---------|
| CRITICAL | AWS keys, Stripe secret keys, GitHub PATs, private keys |
| HIGH | Google API keys, JWT tokens, hardcoded passwords |
| MEDIUM | Generic API keys, Sentry DSNs, source maps, internal routes |
| LOW | Email addresses, internal IPs, admin paths |
| INFO | Public env vars, framework info, WAF detection |

---

## Disclaimer

NEXA is intended for **authorized security assessments only**. Only scan targets you have explicit permission to test. The authors are not responsible for misuse.

---

## Development

```bash
make dev      # setup .venv
make test     # run tests
```
