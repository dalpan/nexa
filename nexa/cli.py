"""NEXA CLI entrypoint."""

from __future__ import annotations

import asyncio
import json
import re
import sys
import time
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import typer
from rich.console import Console

from nexa import __version__

app = typer.Typer(
    name="nexa",
    help=(
        "Frontend Exposure & Secret Detection\n\n"
        "Examples:\n"
        "  nexa scan target.com\n"
        "  nexa scan target.com --depth 3 --waf-bypass\n"
        "  subfinder -d target.com | httpx | nexa scan\n"
        "  cat targets.txt | nexa scan --format jsonl | jq 'select(.severity==\"HIGH\")'"
    ),
    no_args_is_help=True,
    add_completion=False,
)

# Progress/status always goes to stderr so stdout stays clean for piped findings
console = Console(stderr=True)
out_console = Console(stderr=False)  # for findings table / non-pipe text output


# ── ANSI / httpx output cleaner ────────────────────────────────────────────────

_ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')
_HTTPX_STATUS_RE = re.compile(r'\s+\[\d{3}\]\s*$')  # trailing [200]


def _parse_stdin_line(line: str) -> Optional[str]:
    """Parse one line from stdin (subfinder/httpx output) into a URL."""
    line = _ANSI_RE.sub('', line).strip()
    if not line or line.startswith('#'):
        return None
    # Strip httpx trailing status: "https://example.com [200]"
    line = _HTTPX_STATUS_RE.sub('', line).strip()
    # Strip httpx extra fields (space-separated): take first token
    line = line.split()[0] if line else line
    if not line:
        return None
    # Add scheme if missing
    if not line.startswith(('http://', 'https://')):
        line = 'https://' + line
    # Basic sanity: must have a host
    try:
        p = urlparse(line)
        if p.scheme and p.netloc:
            return line
    except Exception:
        pass
    return None


def _read_targets_stdin() -> list[str]:
    """Read target URLs from stdin (pipe mode)."""
    targets: list[str] = []
    for line in sys.stdin:
        url = _parse_stdin_line(line)
        if url and url not in targets:
            targets.append(url)
    return targets


def _ensure_scheme(url: str) -> str:
    if not url.startswith(('http://', 'https://')):
        return 'https://' + url
    return url


# ── Shared scan engine ─────────────────────────────────────────────────────────

async def _run_scan(
    target: str,
    *,
    depth: int,
    max_pages: int,
    concurrency: int,
    timeout: int,
    rate_limit: float,
    user_agent: Optional[str],
    no_sourcemaps: bool,
    no_subdomain: bool,
    no_www: bool,
    crawl_subdomains: bool,
    historical_urls: bool,
    passive_validate: bool,
    waf_bypass: bool,
    waf_strategy: str,
    extra_urls: list[str],
) -> "ScanResult":  # noqa: F821
    """Core async scan — returns a ScanResult."""
    from nexa.core.http import HttpClient
    from nexa.core.crawler import crawl_site, discover_subdomains, fetch_historical_urls
    from nexa.core.fingerprint import fingerprint
    from nexa.core.js_collector import collect_js_files
    from nexa.core.sourcemap import process_source_maps
    from nexa.core.extractors import run_all_extractors
    from nexa.core.detectors import deduplicate_findings, run_detection
    from nexa.core.validators import validate_findings
    from nexa.core.waf_bypass import WAFBypassConfig
    from nexa.models import Category, Finding, Severity, ScanResult

    import re as _re

    start = time.monotonic()
    parsed = urlparse(target)
    domain = parsed.netloc
    hostname = parsed.hostname or domain

    result = ScanResult(target=target)

    ua = user_agent or f"nexa/{__version__} (+https://github.com/security-tools/nexa)"
    waf_cfg = WAFBypassConfig(enabled=waf_bypass, strategy=waf_strategy)

    async with HttpClient(
        timeout=float(timeout),
        retries=3,
        rate_limit=rate_limit,
        user_agent=ua,
        waf_bypass=waf_cfg,
    ) as client:

        # 1. Crawl
        console.print("[bold cyan]»[/bold cyan] Crawling target...")
        crawl_targets = [target]
        if not no_www and not hostname.startswith("www."):
            crawl_targets.append(f"{parsed.scheme}://www.{hostname}")
        for extra in extra_urls:
            u = _ensure_scheme(extra)
            if u not in crawl_targets:
                crawl_targets.append(u)

        crawl_results, crawl_warnings = await crawl_site(
            client, crawl_targets, max_depth=depth, max_pages=max_pages
        )
        result.pages_crawled = len(crawl_results)
        result.hosts = list(dict.fromkeys([parsed.netloc, f"www.{hostname}"]))
        result.scan_warnings.extend(crawl_warnings)

        all_html = "\n".join(r.raw_html for r in crawl_results)
        all_headers = crawl_results[0].headers if crawl_results else {}

        # Always report detected WAF as INFO finding
        if client.detected_waf:
            result.findings.append(Finding(
                category=Category.INTERNAL_ENDPOINT,
                severity=Severity.INFO,
                confidence=80,
                title=f"WAF Detected: {client.detected_waf}",
                value=client.detected_waf,
                context=f"WAF fingerprinted during scan of {target}",
                source_url=target,
                host=domain,
            ))

        # 2. Fingerprint
        console.print("[bold cyan]»[/bold cyan] Fingerprinting frameworks...")
        fw_result = fingerprint(html=all_html, headers=all_headers)
        result.frameworks_detected = fw_result.detected
        if fw_result.detected:
            console.print(f"  Detected: [cyan]{', '.join(fw_result.detected)}[/cyan]")

        # 3. Subdomain discovery
        if not no_subdomain:
            console.print("[bold cyan]»[/bold cyan] Discovering subdomains...")
            subdomains = await discover_subdomains(client, hostname)
            result.subdomains_found = subdomains
            if subdomains:
                console.print(f"  Found {len(subdomains)} subdomains")
                if crawl_subdomains:
                    console.print("  Crawling subdomains (max 5)...")
                    for sub in subdomains[:5]:
                        for scheme in ("https", "http"):
                            sub_cr, sub_warnings = await crawl_site(
                                client, f"{scheme}://{sub}", max_depth=1, max_pages=10
                            )
                            result.scan_warnings.extend(sub_warnings)
                            if sub_cr:
                                crawl_results.extend(sub_cr)
                                result.hosts.append(sub)
                                all_html += "\n".join(r.raw_html for r in sub_cr)
                                break
                    console.print(f"  Total pages crawled: {len(crawl_results)}")

        # 4. Historical URLs
        hist_urls: list[str] = []
        if historical_urls:
            console.print("[bold cyan]»[/bold cyan] Fetching historical URLs from Wayback Machine...")
            hist_urls = await fetch_historical_urls(client, hostname)
            console.print(f"  Found {len(hist_urls)} historical URLs")

        # 5. Collect JS files
        console.print("[bold cyan]»[/bold cyan] Collecting JavaScript files...")
        all_base_urls = list(dict.fromkeys(r.url for r in crawl_results if r.url))
        js_files = await collect_js_files(
            client,
            crawl_results,
            all_base_urls[0] if all_base_urls else target,
            fw_result.detected,
            historical_urls=hist_urls,
            concurrency=concurrency,
        )
        result.js_files = js_files
        console.print(f"  Fetched {len(js_files)} JS files")

        # 6. Source maps
        if not no_sourcemaps:
            console.print("[bold cyan]»[/bold cyan] Detecting source maps...")
            source_maps = await process_source_maps(client, js_files)
            result.source_maps = source_maps
            if source_maps:
                console.print(f"  Found {len(source_maps)} source maps")
                for sm in source_maps:
                    result.findings.append(Finding(
                        category=Category.SOURCE_MAP,
                        severity=Severity.MEDIUM,
                        confidence=95,
                        title="Source Map Publicly Accessible",
                        value=sm.url,
                        context=f"Sources: {', '.join(sm.sources[:3])}",
                        source_url=sm.url,
                        host=domain,
                        framework=", ".join(fw_result.detected),
                    ))

        # 7. Run detectors
        console.print("[bold cyan]»[/bold cyan] Running secret detectors...")
        framework_str = ", ".join(fw_result.detected)
        _NEXT_DATA_RE = _re.compile(
            r'<script[^>]*id=["\']__NEXT_DATA__["\'][^>]*>(.*?)</script>',
            _re.DOTALL | _re.IGNORECASE,
        )

        for cr in crawl_results:
            result.findings.extend(run_detection(cr.raw_html, cr.url, domain, framework_str))
            for m in _NEXT_DATA_RE.finditer(cr.raw_html):
                result.findings.extend(run_detection(m.group(1), cr.url, domain, framework_str))
            for script in cr.inline_scripts:
                result.findings.extend(run_detection(script, cr.url, domain, framework_str))
            for comment in cr.html_comments:
                result.findings.extend(run_detection(comment, cr.url, domain, framework_str))

        for js_file in js_files:
            result.findings.extend(run_detection(js_file.content, js_file.url, domain, framework_str))

        for sm in result.source_maps:
            for src_content in sm.sources_content:
                if src_content:
                    result.findings.extend(run_detection(src_content, sm.url, domain, framework_str))

        # 8. Extractors
        all_js_content = "\n".join(jf.content for jf in js_files)
        extracted = run_all_extractors(all_html, all_js_content, fw_result.detected, result.source_maps)

        for key, value in extracted.env_vars.items():
            if not value:
                continue
            result.findings.extend(
                run_detection(f'{key} = "{value}"', target, domain, framework_str)
            )

        for snippet in extracted.raw_snippets:
            result.findings.extend(run_detection(snippet, target, domain, framework_str))

        for internal_url in extracted.internal_urls:
            if internal_url:
                result.findings.append(Finding(
                    category=Category.INTERNAL_ENDPOINT,
                    severity=Severity.MEDIUM,
                    confidence=80,
                    title="Internal Network URL",
                    value=internal_url,
                    context="Extracted from JS content",
                    source_url=target,
                    host=domain,
                    framework=framework_str,
                ))

        # 9. Deduplicate + validate
        result.findings = deduplicate_findings(result.findings)
        console.print(f"  Found {len(result.findings)} unique findings")

        if passive_validate:
            console.print("[bold cyan]»[/bold cyan] Running passive validators...")
            result.findings = validate_findings(result.findings)

    result.scan_duration = time.monotonic() - start
    return result


# ── scan command ───────────────────────────────────────────────────────────────

@app.command(context_settings={"allow_extra_args": True, "ignore_unknown_options": True})
def scan(
    target: Optional[str] = typer.Argument(
        None,
        help="Target URL. Omit to read from stdin (pipe mode): subfinder -d x.com | httpx | nexa scan",
    ),
    list_file: Optional[Path] = typer.Option(None, "--list", "-l", help="File with one target per line"),
    output_dir: Path = typer.Option(Path("./nexa-output"), "--output-dir", "-o", help="Output directory"),
    depth: int = typer.Option(2, "--depth", min=0, max=5, help="Crawl depth"),
    max_pages: int = typer.Option(50, "--max-pages", min=1, max=500, help="Max pages to crawl"),
    concurrency: int = typer.Option(10, "--concurrency", min=1, max=50, help="Concurrent requests"),
    timeout: int = typer.Option(15, "--timeout", min=5, max=120, help="Request timeout (seconds)"),
    rate_limit: float = typer.Option(5.0, "--rate-limit", min=0.1, max=50.0, help="Requests per second"),
    user_agent: Optional[str] = typer.Option(None, "--user-agent", help="Custom User-Agent string"),
    no_sourcemaps: bool = typer.Option(False, "--no-sourcemaps", help="Skip source map fetching"),
    no_subdomain: bool = typer.Option(False, "--no-subdomain", help="Skip subdomain discovery"),
    no_www: bool = typer.Option(False, "--no-www", help="Skip auto-crawl of www. variant"),
    crawl_subdomains: bool = typer.Option(False, "--crawl-subdomains", help="Also crawl discovered subdomains"),
    historical_urls: bool = typer.Option(False, "--historical-urls", help="Fetch historical URLs from Wayback Machine"),
    passive_validate: bool = typer.Option(False, "--passive-validate", help="Run passive validators on findings"),
    min_severity: str = typer.Option("INFO", "--min-severity", help="Minimum severity [CRITICAL|HIGH|MEDIUM|LOW|INFO]"),
    export_csv: bool = typer.Option(False, "--export-csv", help="Export findings to CSV"),
    fmt: str = typer.Option("text", "--format", "-f", help="Output format [text|json|jsonl]"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress progress output (implied by --format jsonl)"),
    verbose: bool = typer.Option(False, "--verbose/--no-verbose", "-v/ ", help="Verbose logging"),
    waf_bypass: bool = typer.Option(False, "--waf-bypass", help="Enable WAF bypass mode"),
    waf_strategy: str = typer.Option("rotate", "--waf-strategy", help="WAF bypass strategy [rotate|random|aggressive]"),
    url: Optional[list[str]] = typer.Option(None, "--url", help="Additional URL(s) to include (repeatable)"),
) -> None:
    """Scan targets for frontend exposure and secret leaks.

    \b
    Pipe examples:
      subfinder -d target.com | httpx | nexa scan
      cat urls.txt | nexa scan --format jsonl | jq 'select(.severity=="HIGH")'
      echo "target.com" | nexa scan --no-subdomain
    """
    from nexa.utils import setup_logging, slugify
    from nexa.models import Severity
    from nexa.core.reporting import print_banner, print_scan_start, print_summary, save_all_reports

    setup_logging(verbose)

    # Validate format
    fmt = fmt.lower()
    if fmt not in ("text", "json", "jsonl"):
        console.print(f"[red]Invalid format: {fmt}. Use text, json, or jsonl[/red]")
        raise typer.Exit(1)

    # jsonl implies quiet (progress on stderr, findings on stdout)
    is_pipe_mode = fmt in ("json", "jsonl")
    suppress_progress = quiet or is_pipe_mode

    # Validate min_severity
    try:
        min_sev = Severity(min_severity.upper())
    except ValueError:
        console.print(f"[red]Invalid severity: {min_severity}[/red]")
        raise typer.Exit(1)

    # ── Collect targets ────────────────────────────────────────────────────────
    targets: list[str] = []

    if target and target != "-":
        targets.append(_ensure_scheme(target))
    elif list_file:
        pass  # handled below
    elif not sys.stdin.isatty():
        # Pipe mode: read from stdin
        targets = _read_targets_stdin()
        if not targets:
            console.print("[red]No valid URLs found in stdin[/red]")
            raise typer.Exit(1)
    else:
        console.print("[red]No target specified. Provide a target URL or pipe URLs via stdin.[/red]")
        console.print("[dim]Example: nexa scan example.com[/dim]")
        console.print("[dim]Example: subfinder -d example.com | httpx | nexa scan[/dim]")
        raise typer.Exit(1)

    # --list file
    if list_file:
        if not list_file.exists():
            console.print(f"[red]List file not found: {list_file}[/red]")
            raise typer.Exit(1)
        for line in list_file.read_text().splitlines():
            u = _parse_stdin_line(line)
            if u and u not in targets:
                targets.append(u)

    if not targets:
        console.print("[red]No targets to scan.[/red]")
        raise typer.Exit(1)

    # ── Banner + run ───────────────────────────────────────────────────────────
    if not suppress_progress:
        print_banner()

    scan_kwargs = dict(
        depth=depth,
        max_pages=max_pages,
        concurrency=concurrency,
        timeout=timeout,
        rate_limit=rate_limit,
        user_agent=user_agent,
        no_sourcemaps=no_sourcemaps,
        no_subdomain=no_subdomain,
        no_www=no_www,
        crawl_subdomains=crawl_subdomains,
        historical_urls=historical_urls,
        passive_validate=passive_validate,
        waf_bypass=waf_bypass,
        waf_strategy=waf_strategy,
        extra_urls=url or [],
    )

    all_results = []
    exit_code = 0

    for t in targets:
        if not suppress_progress:
            print_scan_start(t, {
                "Depth": depth, "Max Pages": max_pages, "Concurrency": concurrency,
                "Timeout": f"{timeout}s", "Rate Limit": f"{rate_limit} req/s",
                "Source Maps": "disabled" if no_sourcemaps else "enabled",
                "Subdomain Discovery": "disabled" if no_subdomain else "enabled",
                "Historical URLs": "enabled" if historical_urls else "disabled",
                "WAF Bypass": f"enabled ({waf_strategy})" if waf_bypass else "disabled",
                "Format": fmt,
            })
        elif len(targets) > 1:
            console.print(f"[bold cyan]»[/bold cyan] Scanning [cyan]{t}[/cyan]")

        try:
            scan_result = asyncio.run(_run_scan(t, **scan_kwargs))
        except KeyboardInterrupt:
            console.print("\n[yellow]Scan interrupted.[/yellow]")
            raise typer.Exit(130)
        except Exception as e:
            console.print(f"[red]Scan failed for {t}: {e}[/red]")
            if verbose:
                import traceback as _tb
                console.print(_tb.format_exc())
            continue

        all_results.append(scan_result)

        # ── Output ─────────────────────────────────────────────────────────────
        filtered = [f for f in scan_result.findings if f.severity >= min_sev]

        if fmt == "jsonl":
            for f in filtered:
                d = f.to_dict()
                d["target"] = t
                print(json.dumps(d, default=str))

        elif fmt == "json":
            print(json.dumps(scan_result.to_dict(), indent=2, default=str))

        else:  # text
            print_summary(scan_result, min_sev)

            # Save reports
            parsed = urlparse(t)
            ts = time.strftime("%Y%m%d_%H%M%S")
            resolved_output = output_dir / f"{slugify(parsed.netloc)}_{ts}"
            resolved_output.mkdir(parents=True, exist_ok=True)
            saved = save_all_reports(scan_result, resolved_output, export_csv=export_csv)
            out_console.print()
            out_console.print("[bold]Reports saved:[/bold]")
            for fmt_name, path in saved.items():
                out_console.print(f"  [{fmt_name.upper()}] {path}")

        # Track exit code — exit 2 if any CRITICAL
        from nexa.models import Severity as _Sev
        if any(f.severity == _Sev.CRITICAL for f in scan_result.findings):
            exit_code = 2

    if exit_code:
        raise typer.Exit(exit_code)


# ── version command ────────────────────────────────────────────────────────────

@app.command()
def version() -> None:
    """Show NEXA version."""
    out_console.print(f"nexa v{__version__}")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
