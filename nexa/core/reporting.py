"""Reporting: terminal summary, JSON, Markdown, and CSV output."""

from __future__ import annotations

import csv
import json
import logging
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.text import Text

from nexa.models import Category, Finding, ScanResult, Severity

logger = logging.getLogger(__name__)

console = Console(stderr=False)
err_console = Console(stderr=True)

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH:     "red",
    Severity.MEDIUM:   "yellow",
    Severity.LOW:      "cyan",
    Severity.INFO:     "dim white",
}

CATEGORY_SHORT = {
    "API_KEY":           "API KEY",
    "AUTH_TOKEN":        "AUTH",
    "CREDENTIAL":        "CRED",
    "PII":               "PII",
    "INTERNAL_ENDPOINT": "INTERNAL",
    "ENV_CONFIG":        "ENV",
    "SOURCE_MAP":        "SOURCEMAP",
    "FRAMEWORK_INFO":    "FRAMEWORK",
    "SECURITY_HEADER":   "SEC HEADER",
    "EXPOSED_FILE":      "EXPOSED",
    "CORS":              "CORS",
    "JS_VULN":           "JS VULN",
}


def _sev_text(sev: Severity) -> Text:
    t = Text(f"  {sev.value:<8}", style=SEVERITY_COLORS.get(sev, "white"))
    return t


def print_banner() -> None:
    from nexa import __version__
    banner = rf"""
[bold cyan]  _  _ _______  ___   [/bold cyan]
[bold cyan] | \| | ____\ \/ / \  [/bold cyan]
[bold cyan] | .` |  _|  >  < / _ [/bold cyan]
[bold cyan] |_|\_|___| /_/\_/_/ \_[/bold cyan]  [dim]v{__version__}[/dim]
[dim]  Frontend Exposure & Secret Detection[/dim]
[dim]  For authorized security assessments only[/dim]
"""
    console.print(banner)


def print_scan_start(target: str, options: dict) -> None:
    table = Table(box=box.SIMPLE, show_header=False)
    table.add_column("Key", style="dim")
    table.add_column("Value", style="cyan")
    table.add_row("Target", target)
    for k, v in options.items():
        table.add_row(k, str(v))
    console.print(Panel(table, title="[bold]Scan Configuration[/bold]", border_style="dim blue"))


def print_summary(result: ScanResult, min_severity: Severity = Severity.INFO) -> None:
    console.print()
    console.print(Panel(
        f"[bold]Scan complete[/bold] — {result.target}\n"
        f"Duration: [cyan]{result.scan_duration:.1f}s[/cyan]  |  "
        f"Pages: [cyan]{result.pages_crawled}[/cyan]  |  "
        f"JS files: [cyan]{len(result.js_files)}[/cyan]  |  "
        f"Source maps: [cyan]{len(result.source_maps)}[/cyan]",
        title="[bold green]Scan Complete[/bold green]",
        border_style="green",
    ))

    # Scan warnings (WAF blocks, ISP blocks, etc.)
    for w in (result.scan_warnings or []):
        console.print(f"[bold yellow]⚠  {w}[/bold yellow]")

    if result.frameworks_detected:
        console.print(f"[dim]Frameworks detected:[/dim] [cyan]{', '.join(result.frameworks_detected)}[/cyan]")
    if result.subdomains_found:
        console.print(f"[dim]Subdomains found:[/dim] [cyan]{', '.join(result.subdomains_found[:10])}[/cyan]")

    # Severity count table
    counts: dict[Severity, int] = {sev: 0 for sev in Severity}
    for f in result.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    sev_table = Table(title="[bold]Findings by Severity[/bold]", box=box.ROUNDED)
    sev_table.add_column("Severity", justify="center", min_width=10)
    sev_table.add_column("Count",    justify="center", min_width=6)
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        n = counts.get(sev, 0)
        color = SEVERITY_COLORS[sev]
        sev_table.add_row(
            Text(sev.value, style=color),
            Text(str(n), style=color if n > 0 else "dim"),
        )
    console.print(sev_table)
    console.print()

    # Findings detail table
    filtered = [f for f in result.findings if f.severity >= min_severity]
    if not filtered:
        console.print("[dim]No findings at or above the minimum severity threshold.[/dim]")
        return

    findings_table = Table(
        title=f"[bold]Findings[/bold] ({len(filtered)} shown)",
        box=box.SIMPLE_HEAVY,
        show_lines=False,
        expand=True,
    )
    findings_table.add_column("Severity",  min_width=10, no_wrap=True)
    findings_table.add_column("Cat",       min_width=10, no_wrap=True)
    findings_table.add_column("Title",     min_width=26, no_wrap=False)
    findings_table.add_column("Value",     min_width=38, no_wrap=False)
    findings_table.add_column("Source",    min_width=30, no_wrap=False)

    for f in sorted(filtered, key=lambda x: (x.severity, -x.confidence), reverse=True):
        color = SEVERITY_COLORS[f.severity]
        cat_short = CATEGORY_SHORT.get(f.category.value, f.category.value)

        # Truncate value for terminal readability — full value is in JSON report
        val_display = f.value if len(f.value) <= 60 else f.value[:57] + "..."
        src_display = f.source_url if len(f.source_url) <= 55 else "..." + f.source_url[-52:]

        findings_table.add_row(
            Text(f.severity.value, style=color),
            Text(cat_short, style="bold"),
            f.title,
            Text(val_display, style="green"),
            Text(src_display, style="dim"),
        )

    console.print(findings_table)


def save_json(result: ScanResult, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "findings.json"
    with path.open("w", encoding="utf-8") as f:
        json.dump(result.to_dict(), f, indent=2, default=str)
    logger.info("JSON report saved: %s", path)
    return path


def save_csv(result: ScanResult, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "findings.csv"
    fieldnames = [
        "id", "severity", "confidence", "category", "title",
        "value", "source_url", "host", "framework", "line_number", "timestamp",
    ]
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for finding in result.findings:
            writer.writerow({
                "id":          finding.id,
                "severity":    finding.severity.value,
                "confidence":  finding.confidence,
                "category":    finding.category.value,
                "title":       finding.title,
                "value":       finding.value,
                "source_url":  finding.source_url,
                "host":        finding.host,
                "framework":   finding.framework,
                "line_number": finding.line_number or "",
                "timestamp":   finding.timestamp.isoformat(),
            })
    logger.info("CSV report saved: %s", path)
    return path


def save_markdown(result: ScanResult, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "report.md"

    counts = {sev: sum(1 for f in result.findings if f.severity == sev) for sev in Severity}
    total = len(result.findings)

    lines: list[str] = [
        "# NEXA Security Report",
        "",
        f"**Target:** `{result.target}`  ",
        f"**Scan Date:** {result.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
        f"**Duration:** {result.scan_duration:.1f}s  ",
        f"**Pages Crawled:** {result.pages_crawled}  ",
        f"**JS Files Fetched:** {len(result.js_files)}  ",
        f"**Source Maps:** {len(result.source_maps)}  ",
        f"**Tool:** NEXA v1.0.0  ",
        "",
        "> **Disclaimer:** This report was generated for an authorized security assessment only.",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        f"Frontend security scan of `{result.target}` found **{total} findings** across "
        f"{result.pages_crawled} pages and {len(result.js_files)} JavaScript files.",
        "",
        "| Severity | Count |",
        "|----------|------:|",
    ]
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        lines.append(f"| {sev.value} | {counts.get(sev, 0)} |")

    if result.frameworks_detected:
        lines += ["", "### Frameworks Detected", ""]
        for fw in result.frameworks_detected:
            lines.append(f"- {fw}")

    if result.subdomains_found:
        lines += ["", "### Subdomains Found", ""]
        for sub in result.subdomains_found:
            lines.append(f"- `{sub}`")

    # Findings grouped by host
    hosts_order = list(dict.fromkeys(f.host for f in result.findings))
    lines += ["", "---", "", "## Findings", ""]

    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        sev_findings = [f for f in result.findings if f.severity == sev]
        if not sev_findings:
            continue
        lines += [f"### {sev.value} ({len(sev_findings)})", ""]
        for f in sev_findings:
            lines += [
                f"#### {f.title}",
                "",
                f"| Field | Value |",
                f"|-------|-------|",
                f"| **ID** | `{f.id}` |",
                f"| **Category** | {f.category.value} |",
                f"| **Confidence** | {f.confidence}% |",
                f"| **Source** | `{f.source_url}` |",
                f"| **Host** | `{f.host}` |",
            ]
            if f.framework:
                lines.append(f"| **Framework** | {f.framework} |")
            lines += [
                "",
                "**Value:**",
                "```",
                f.value,
                "```",
            ]
            if f.context:
                ctx = f.context[:300].replace("`", "'")
                lines += [
                    "",
                    "**Context:**",
                    "```",
                    ctx,
                    "```",
                ]
            if f.validator_result:
                vr = f.validator_result
                lines += [
                    "",
                    f"**Validation:** {vr.provider} — format_valid=`{vr.format_valid}`, "
                    f"likely_test=`{vr.likely_test}`",
                ]
                for note in (vr.notes or []):
                    lines.append(f"  - {note}")
            lines += ["", _get_recommendation(f), "", "---", ""]

    if result.source_maps:
        lines += ["## Source Maps Found", ""]
        for sm in result.source_maps:
            lines += [
                f"### `{sm.url}`",
                "",
                f"- **Sources:** {len(sm.sources)}",
                f"- **Publicly accessible:** {sm.publicly_accessible}",
                "",
                "**Source file paths:**",
                "```",
            ]
            for src in sm.sources[:20]:
                lines.append(src)
            if len(sm.sources) > 20:
                lines.append(f"... and {len(sm.sources) - 20} more")
            lines += ["```", ""]

    with path.open("w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    logger.info("Markdown report saved: %s", path)
    return path


def _get_recommendation(finding: Finding) -> str:
    recs = {
        Category.API_KEY: (
            "**Recommendation:** Remove this key from frontend code immediately. "
            "Rotate the key and proxy API calls server-side."
        ),
        Category.AUTH_TOKEN: (
            "**Recommendation:** Never hardcode tokens in client-side code. "
            "Use short-lived tokens, HttpOnly cookies, or session auth."
        ),
        Category.CREDENTIAL: (
            "**Recommendation:** Remove hardcoded credentials. "
            "Use a secrets manager and inject credentials server-side only."
        ),
        Category.PII: (
            "**Recommendation:** Ensure PII is not embedded in frontend assets. "
            "Review GDPR/CCPA compliance."
        ),
        Category.INTERNAL_ENDPOINT: (
            "**Recommendation:** Internal endpoints should not appear in public JavaScript. "
            "Review API gateway and network segmentation."
        ),
        Category.ENV_CONFIG: (
            "**Recommendation:** Only use public env prefixes (NEXT_PUBLIC_, VITE_, REACT_APP_) "
            "for values safe to expose. Never prefix secrets."
        ),
        Category.SOURCE_MAP: (
            "**Recommendation:** Disable source map generation for production "
            "or restrict access to internal networks."
        ),
        Category.FRAMEWORK_INFO: (
            "**Recommendation:** Consider hiding framework version information."
        ),
    }
    return recs.get(finding.category, "**Recommendation:** Review and remediate this finding.")


def save_all_reports(
    result: ScanResult,
    output_dir: Path,
    export_csv: bool = False,
) -> dict[str, Path]:
    saved: dict[str, Path] = {}
    saved["json"] = save_json(result, output_dir)
    saved["markdown"] = save_markdown(result, output_dir)
    if export_csv:
        saved["csv"] = save_csv(result, output_dir)
    return saved
