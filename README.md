<div align="center">
  
# NEXA
<p>Credential & Secret Scanner</p>

<a href="https://github.com/dalpan/nexa/releases/latest"><img src="https://img.shields.io/github/v/release/dalpan/nexa?color=58a6ff&label=version&style=flat-square" alt="version"/></a>
<img src="https://img.shields.io/badge/python-3.11+-58a6ff?style=flat-square" alt="python"/>
<img src="https://img.shields.io/badge/license-MIT-3fb950?style=flat-square" alt="license"/>
<img src="https://img.shields.io/badge/for-bug%20bounty-f85149?style=flat-square" alt="bug bounty"/>

<br/>

<p>
  <a href="#install">Install</a> •
  <a href="#usage">Usage</a> •
  <a href="#pipe-mode">Pipe Mode</a> •
  <a href="#options">Options</a> •
  <a href="#detection-coverage">Detection Coverage</a>
</p>

</div>

---

NEXA is a fast, passive credential and secret scanner for frontend web applications. It crawls target sites and hunts for exposed API keys, hardcoded credentials, auth tokens, and secrets buried inside JavaScript bundles, source maps, HTML, and server-side rendered framework state payloads.

Built for bug bounty hunters and pentesters. Works standalone or chained with `subfinder`, `httpx`, and `jq`.

---

## Features

- **Credential pair detection** — captures both username/keyId and password/secret fields together (e.g. `wsApiKeyId: xxxxxxx` + `wsApiKeyPassword: uuid`)
- **All major JS frameworks** — extracts and scans `__NEXT_DATA__`, `__NUXT__`, `__remixContext`, `__GATSBY__`, `ng-state`, `__INITIAL_STATE__`, SvelteKit, Astro, and generic `application/json` script tags
- **26 targeted patterns** — AWS, Google, GitHub, Stripe, Slack, SendGrid, Twilio, Sentry, JWT, Basic Auth, hardcoded passwords, and more
- **High-entropy string detection** — catches unknown secrets via Shannon entropy scoring with credential keyword context
- **Source map discovery** — publicly accessible `.map` files that leak original source code
- **Framework fingerprinting** — Next.js, Nuxt, React, Vue, Angular, Vite, Svelte, Astro
- **Subdomain discovery** — passive enumeration via crt.sh + HackerTarget
- **WAF detection + bypass mode** — UA rotation, jitter, cookie persistence, Sec-Fetch headers
- **CORS misconfiguration** — detects reflected origins with credentials
- **Pipe-friendly** — progress to stderr, findings to stdout, JSONL for chaining
- **Passive only** — no state-changing requests

---

## Install

**Requirements:** Python 3.11+ and [pipx](https://pipx.pypa.io/stable/) (`brew install pipx` on macOS)

```bash
pipx install git+https://github.com/dalpan/nexa.git
```

Or clone and install locally:

```bash
git clone https://github.com/dalpan/nexa
cd nexa
make install
```

`nexa` will be available system-wide — no venv needed.

### Update

```bash
nexa upgrade
```

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

# Skip subdomain discovery for faster scans
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

NEXA reads targets from stdin when no target argument is given — progress to stderr, findings to stdout.

```bash
# subfinder → httpx → nexa
subfinder -d target.com | httpx | nexa scan

# Scan from a list file
nexa scan --list targets.txt

# Filter CRITICAL findings with jq
subfinder -d target.com | httpx | nexa scan --format jsonl \
  | jq 'select(.severity == "CRITICAL")'

# Extract values only
nexa scan target.com --format jsonl \
  | jq -r 'select(.severity == "HIGH" or .severity == "CRITICAL") | "\(.title): \(.value)"'
```

---

## Options

| Option | Default | Description |
|--------|---------|-------------|
| `--depth` | `2` | Crawl depth |
| `--max-pages` | `50` | Max pages to crawl |
| `--concurrency` | `10` | Concurrent requests |
| `--timeout` | `15` | Request timeout in seconds |
| `--rate-limit` | `5.0` | Requests per second |
| `--min-severity` | `INFO` | Minimum severity (`INFO/LOW/MEDIUM/HIGH/CRITICAL`) |
| `--format / -f` | `text` | Output format: `text` / `json` / `jsonl` |
| `--output-dir` | auto | Directory to save JSON + Markdown reports |
| `--export-csv` | off | Also export findings as CSV |
| `--list / -l` | — | File with one target per line |
| `--url` | — | Extra URL to include in scan (repeatable) |
| `--no-subdomain` | off | Skip subdomain discovery |
| `--no-www` | off | Skip www. variant crawl |
| `--crawl-subdomains` | off | Also crawl discovered subdomains |
| `--historical-urls` | off | Fetch URLs from Wayback Machine CDX |
| `--no-sourcemaps` | off | Skip source map fetching |
| `--waf-bypass` | off | Enable WAF bypass mode |
| `--waf-strategy` | `rotate` | `rotate` / `random` / `aggressive` |
| `--quiet / -q` | off | Suppress progress output |
| `--verbose` | off | Debug logging |

---

## Detection Coverage

| Category | Examples | Severity |
|----------|----------|----------|
| AWS | Access Key ID (`AKIA…`), Secret Access Key | CRITICAL |
| GitHub | PAT (`ghp_…`), Fine-grained PAT (`github_pat_…`) | CRITICAL |
| Stripe | Secret key (`sk_live_…`), Publishable key (`pk_…`) | CRITICAL / INFO |
| Google | API Key (`AIza…`) | HIGH |
| Slack | Bot token (`xoxb-…`), Webhook URL | HIGH |
| SendGrid | API key (`SG.…`) | CRITICAL |
| Twilio | Auth Token (`SK…`) | CRITICAL |
| Sentry | DSN URL | MEDIUM |
| JWT | `eyJ…eyJ…` Bearer tokens | HIGH |
| Private Key | `-----BEGIN PRIVATE KEY-----` | CRITICAL |
| Basic Auth | `Basic <base64>` in field or header, auto-decoded | CRITICAL |
| Credential Pair | `apiKeyId` + `apiKeyPassword` in JSON payloads | HIGH |
| Hardcoded Password | `password`, `passwd`, `secret` in JS/JSON | HIGH |
| API Key in Requests | Key passed to `fetch()` / `axios()` headers | HIGH |
| Source Maps | Publicly accessible `.map` files | MEDIUM |
| Internal URLs | Private IP ranges in JS (`192.168.x.x`, `10.x.x.x`) | MEDIUM |
| CORS | Reflected origin with `credentials: true` | HIGH |
| High Entropy | Unknown secrets detected by entropy scoring | LOW |

### Framework State Extraction

NEXA automatically extracts and scans embedded JSON payloads from all major SSR frameworks — the most common place credentials accidentally get exposed on the frontend:

| Framework | Payload |
|-----------|---------|
| Next.js | `<script id="__NEXT_DATA__">` |
| Nuxt | `window.__NUXT__`, `<script id="__NUXT_DATA__">` |
| Remix | `window.__remixContext` |
| Gatsby | `window.__GATSBY*`, `window.pageData` |
| SvelteKit | `<script id="svelte-data">` |
| Angular | `<script id="ng-state">` |
| Vue SSR | `window.__VUE_SSR_CONTEXT__`, `window.__INITIAL_STATE__` |
| Generic | `window.__REDUX_STATE__`, `window.__APP_STATE__`, `application/json` script tags |

---

## Output Formats

| Format | Description |
|--------|-------------|
| `text` (default) | Rich color table in terminal |
| `jsonl` | One JSON object per finding — best for piping |
| `json` | Full scan result as a single JSON object |

Reports (JSON + Markdown) are saved automatically to `./nexa-output/<target>_<timestamp>/`.

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
```

---

## Disclaimer

NEXA is intended for **authorized security assessments only**. Only scan targets you have explicit permission to test. The authors are not responsible for misuse.
