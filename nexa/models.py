"""Data models for NEXA."""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    def __lt__(self, other: "Severity") -> bool:
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self) < order.index(other)

    def __le__(self, other: "Severity") -> bool:
        return self == other or self < other

    def __gt__(self, other: "Severity") -> bool:
        return not self <= other

    def __ge__(self, other: "Severity") -> bool:
        return not self < other


class Category(str, Enum):
    API_KEY = "API_KEY"
    AUTH_TOKEN = "AUTH_TOKEN"
    CREDENTIAL = "CREDENTIAL"
    PII = "PII"
    INTERNAL_ENDPOINT = "INTERNAL_ENDPOINT"
    ENV_CONFIG = "ENV_CONFIG"
    SOURCE_MAP = "SOURCE_MAP"
    FRAMEWORK_INFO = "FRAMEWORK_INFO"
    SECURITY_HEADER = "SECURITY_HEADER"
    EXPOSED_FILE = "EXPOSED_FILE"
    CORS = "CORS"
    JS_VULN = "JS_VULN"


@dataclass
class ValidationResult:
    provider: str
    format_valid: bool
    likely_test: bool
    metadata: dict[str, Any] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)


@dataclass
class Finding:
    category: Category
    severity: Severity
    confidence: int  # 0-100
    title: str
    value: str
    source_url: str
    host: str
    context: str = ""
    framework: str = ""
    line_number: Optional[int] = None
    validator_result: Optional[ValidationResult] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)
    id: str = field(init=False)

    def __post_init__(self) -> None:
        # Deterministic ID based on value hash so duplicates collapse
        value_hash = hashlib.sha256(self.value.encode()).hexdigest()[:16]
        self.id = value_hash

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "id": self.id,
            "category": self.category.value,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "title": self.title,
            "value": self.value,
            "context": self.context,
            "source_url": self.source_url,
            "host": self.host,
            "framework": self.framework,
            "line_number": self.line_number,
            "timestamp": self.timestamp.isoformat(),
        }
        if self.validator_result:
            d["validator_result"] = {
                "provider": self.validator_result.provider,
                "format_valid": self.validator_result.format_valid,
                "likely_test": self.validator_result.likely_test,
                "metadata": self.validator_result.metadata,
                "notes": self.validator_result.notes,
            }
        return d


@dataclass
class JSFile:
    url: str
    content: str
    size: int
    source_map_url: Optional[str] = None
    framework_hints: list[str] = field(default_factory=list)
    status_code: int = 200
    final_url: str = ""

    def __post_init__(self) -> None:
        if not self.final_url:
            self.final_url = self.url


@dataclass
class SourceMap:
    url: str
    sources: list[str] = field(default_factory=list)
    sources_content: list[Optional[str]] = field(default_factory=list)
    mappings_present: bool = False
    publicly_accessible: bool = True
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "sources": self.sources,
            "sources_count": len(self.sources),
            "has_content": any(c is not None for c in self.sources_content),
            "mappings_present": self.mappings_present,
            "publicly_accessible": self.publicly_accessible,
        }


@dataclass
class CrawlResult:
    url: str
    script_urls: list[str] = field(default_factory=list)
    inline_scripts: list[str] = field(default_factory=list)
    preload_urls: list[str] = field(default_factory=list)
    manifest_urls: list[str] = field(default_factory=list)
    page_links: list[str] = field(default_factory=list)
    html_comments: list[str] = field(default_factory=list)
    meta_tags: dict[str, str] = field(default_factory=dict)
    sourcemap_hints: list[str] = field(default_factory=list)
    raw_html: str = ""
    status_code: int = 200
    headers: dict[str, str] = field(default_factory=dict)
    is_blocked: bool = False
    block_reason: str = ""


@dataclass
class FrameworkResult:
    detected: list[str] = field(default_factory=list)
    confidence: dict[str, int] = field(default_factory=dict)  # framework -> 0-100
    evidence: dict[str, list[str]] = field(default_factory=dict)  # framework -> evidence list


@dataclass
class ScanResult:
    target: str
    hosts: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    js_files: list[JSFile] = field(default_factory=list)
    source_maps: list[SourceMap] = field(default_factory=list)
    frameworks_detected: list[str] = field(default_factory=list)
    scan_duration: float = 0.0
    timestamp: datetime = field(default_factory=datetime.utcnow)
    pages_crawled: int = 0
    subdomains_found: list[str] = field(default_factory=list)
    scan_warnings: list[str] = field(default_factory=list)  # non-fatal issues

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "hosts": self.hosts,
            "findings": [f.to_dict() for f in self.findings],
            "js_files": [{"url": j.url, "size": j.size, "source_map_url": j.source_map_url} for j in self.js_files],
            "source_maps": [s.to_dict() for s in self.source_maps],
            "frameworks_detected": self.frameworks_detected,
            "scan_duration": self.scan_duration,
            "timestamp": self.timestamp.isoformat(),
            "pages_crawled": self.pages_crawled,
            "subdomains_found": self.subdomains_found,
            "summary": {
                "total_findings": len(self.findings),
                "critical": sum(1 for f in self.findings if f.severity == Severity.CRITICAL),
                "high": sum(1 for f in self.findings if f.severity == Severity.HIGH),
                "medium": sum(1 for f in self.findings if f.severity == Severity.MEDIUM),
                "low": sum(1 for f in self.findings if f.severity == Severity.LOW),
                "info": sum(1 for f in self.findings if f.severity == Severity.INFO),
            },
        }
