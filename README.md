<div align="center">

<h1>NEXA</h1>
<h4>Frontend Exposure & Secret Detection</h4>

<p>
  <a href="#install">Install</a> •
  <a href="#usage">Usage</a> •
  <a href="#pipe-mode">Pipe Mode</a> •
  <a href="#options">Options</a> •
  <a href="#detection-coverage">Detection Coverage</a>
</p>

</div>

---

NEXA is a fast, passive frontend security scanner that crawls web applications and detects exposed secrets, API keys, credentials, and sensitive data inside JavaScript bundles, source maps, and HTML.

Built for bug bounty hunters and pentesters. Works standalone or chained with tools like `subfinder`, `httpx`, and `jq`.

---

## Features

- Detects **AWS, Google, Stripe, GitHub, Slack, Sentry, Twilio**, and 25+ secret patterns
- **High-entropy string detection** with context-aware scoring
- **Source map discovery** — `.map` files that leak original source code
- **`__NEXT_DATA__` extraction** — scans Next.js SSR props for embedded credentials
- **Framework fingerprinting** — Next.js, Nuxt, React, Vue, Angular, Vite, Svelte, Astro
- **Subdomain discovery** — passive enumeration via crt.sh + HackerTarget
- **WAF/ISP detection** — Cloudflare, Akamai, Sucuri, ISP blocks with clear warnings
- **WAF bypass mode** — UA rotation, jitter, cookie persistence, Sec-Fetch headers
- **Pipe-friendly** — progress to stderr, findings to stdout, JSONL output for chaining
- **Passive only** — no state-changing requests

---

## Install

**Requirements:** Python 3.11+ and [pipx](https://pipx.pypa.io/stable/) (`brew install pipx` on macOS)

```bash
git clone https://github.com/dalpan/nexa
cd nexa
make install
```

`nexa` will be available system-wide — no need to activate a venv.

### Update

```bash
make update
```

Output will show the installed version, e.g. `installed package nexa 1.1.0`.

---

## Usage

```bash
nexa scan <target>
```

```bash
# Basic scan
nexa scan target.com

# Deeper crawl
nexa scan target.com --depth 3 --max-pages 100

# Skip subdomain discovery (faster)
nexa scan target.com --no-subdomain

# Show only HIGH and above
nexa scan target.com --min-severity HIGH

# WAF bypass mode
nexa scan target.com --waf-bypass

# Save JSON + CSV report
nexa scan target.com --output-dir ./results --export-csv

# Check version
nexa version
```

---

## Pipe Mode

NEXA reads targets from stdin when no target argument is given — progress goes to stderr, findings to stdout, so pipes stay clean.

```bash
# subfinder → httpx → nexa
subfinder -d target.com | httpx | nexa scan

# Scan a list of targets
cat targets.txt | nexa scan

# or with --list flag
nexa scan --list targets.txt

# Filter CRITICAL findings with jq
subfinder -d target.com | httpx | nexa scan --format jsonl \
  | jq 'select(.severity == "CRITICAL")'

# Extract values only
nexa scan target.com --format jsonl \
  | jq -r 'select(.severity == "CRITICAL") | "\(.title): \(.value)"'
```

---

## Options

| Option | Default | Description |
|--------|---------|-------------|
| `--depth` | `2` | Crawl depth |
| `--max-pages` | `50` | Max pages to crawl |
| `--concurrency` | `10` | Concurrent requests |
| `--timeout` | `20` | Request timeout in seconds |
| `--rate-limit` | `5.0` | Requests per second |
| `--min-severity` | `INFO` | Minimum severity to show (`INFO/LOW/MEDIUM/HIGH/CRITICAL`) |
| `--format / -f` | `text` | Output format: `text` / `json` / `jsonl` |
| `--output-dir` | auto | Directory to save JSON/Markdown reports |
| `--export-csv` | off | Also export findings as CSV |
| `--list / -l` | — | File with one target per line |
| `--url` | — | Extra URL to include in scan (repeatable) |
| `--no-subdomain` | off | Skip subdomain discovery |
| `--no-www` | off | Skip www. variant crawl |
| `--crawl-subdomains` | off | Also crawl discovered subdomains |
| `--historical-urls` | off | Fetch URLs from Wayback Machine CDX |
| `--waf-bypass` | off | Enable WAF bypass mode |
| `--waf-strategy` | `rotate` | `rotate` / `random` / `aggressive` |
| `--quiet / -q` | off | Suppress progress output |
| `--verbose` | off | Debug logging |

---

## Detection Coverage

| Category | Examples | Severity |
|----------|----------|----------|
| AWS | Access Key ID (`AKIA…`), Secret Access Key | CRITICAL |
| Stripe | Secret key (`sk_live_…`), Publishable key (`pk_…`) | CRITICAL / MEDIUM |
| GitHub | PAT (`ghp_…`), Fine-grained PAT (`github_pat_…`) | CRITICAL |
| Google | API Key (`AIza…`), OAuth Client ID, reCAPTCHA | HIGH / MEDIUM |
| Slack | Bot token (`xoxb-…`), Incoming webhook URL | HIGH |
| Twilio | Account SID, Auth Token | HIGH / CRITICAL |
| SendGrid | API key (`SG.…`) | CRITICAL |
| Sentry | DSN URL | MEDIUM |
| Mapbox | Access token (`pk.eyJ1…`) | HIGH |
| JWT | `eyJ…eyJ…` tokens | HIGH |
| Credentials | Hardcoded password, secret, auth header | HIGH |
| PII | Email addresses, phone numbers, SSN | LOW |
| Internal Endpoints | Private IPs, admin paths, internal API routes | MEDIUM / LOW |
| Source Maps | Publicly accessible `.map` files | MEDIUM |
| Env Config | `NEXT_PUBLIC_`, `VITE_`, `REACT_APP_` vars | INFO |
| High Entropy | Unknown secrets detected by entropy scoring | LOW |

---

## Output Formats

| Format | Description |
|--------|-------------|
| `text` (default) | Rich color table in terminal |
| `jsonl` | One JSON object per finding — best for piping |
| `json` | Full scan result as a single JSON object |

Reports (JSON + Markdown) are saved automatically to `./nexa-output/<target>/`.

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Scan complete, no CRITICAL findings |
| `1` | Error |
| `2` | CRITICAL findings detected |
| `130` | Interrupted (Ctrl+C) |

---

## Development

```bash
make dev    # set up local .venv
make test   # run test suite
make smoke  # quick smoke test against a live target
```

---

## Disclaimer

NEXA is intended for **authorized security assessments only**. Only scan targets you have explicit permission to test. The authors are not responsible for misuse.
