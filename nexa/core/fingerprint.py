"""Framework fingerprinting from HTML, headers, and JS content."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Optional

from nexa.models import FrameworkResult

logger = logging.getLogger(__name__)


@dataclass
class FrameworkSignature:
    name: str
    patterns: list[str]  # regex patterns
    header_patterns: dict[str, str] = field(default_factory=dict)  # header_name -> pattern
    weight: int = 10  # confidence contribution per match


FRAMEWORKS: list[FrameworkSignature] = [
    FrameworkSignature(
        name="Next.js",
        patterns=[
            r"__NEXT_DATA__",
            r"/_next/static",
            r"__nextjs",
            r"next/dist",
            r"/_next/",
            r"NEXT_PUBLIC_",
            r'"buildId"\s*:',
            r"_next/static/chunks",
            r"__NEXT_LOADED_PAGES__",
            r"next\.config\.js",
        ],
        weight=15,
    ),
    FrameworkSignature(
        name="Nuxt",
        patterns=[
            r"__NUXT__",
            r"/_nuxt/",
            r"window\.__nuxt",
            r"nuxt\.config",
            r"NUXT_PUBLIC_",
            r"window\.__NUXT__",
            r"_nuxt/entry\.",
        ],
        weight=15,
    ),
    FrameworkSignature(
        name="React",
        patterns=[
            r"data-reactroot",
            r"data-reactid",
            r"React\.createElement",
            r"__react",
            r"_reactFiber",
            r"ReactDOM\.render",
            r"_reactRootContainer",
            r"__reactFiber",
        ],
        weight=10,
    ),
    FrameworkSignature(
        name="Vue",
        patterns=[
            r"__vue_app__",
            r"data-v-[0-9a-f]+",
            r"Vue\.config",
            r"createApp\(",
            r"defineComponent\(",
            r"vue\.runtime",
            r"__VUE__",
        ],
        weight=10,
    ),
    FrameworkSignature(
        name="Angular",
        patterns=[
            r"ng-version",
            r"ng-app",
            r"angular\.json",
            r"ng-reflect",
            r"__ng_",
            r"platformBrowserDynamic",
            r"@angular/core",
            r"ng\.probe",
            r"angular\.min\.js",
        ],
        header_patterns={"x-powered-by": r"Angular"},
        weight=10,
    ),
    FrameworkSignature(
        name="Svelte",
        patterns=[
            r"__svelte",
            r'class="svelte-',
            r"SvelteKit",
            r"_app/immutable/",
            r"svelte-",
            r"@sveltejs",
            r"svelte\.js",
        ],
        weight=10,
    ),
    FrameworkSignature(
        name="Vite",
        patterns=[
            r"/@vite/client",
            r"vite/preload-helper",
            r"import\.meta\.env",
            r"vite\.config",
            r"__vite__",
            r"@vite-plugin",
        ],
        weight=12,
    ),
    FrameworkSignature(
        name="Webpack",
        patterns=[
            r"webpackJsonp",
            r"webpackChunk",
            r"__webpack_require__",
            r"__webpack_modules__",
            r"__webpack_exports__",
            r"webpack/bootstrap",
            r'webpack:///\.',
        ],
        weight=10,
    ),
    FrameworkSignature(
        name="Astro",
        patterns=[
            r"astro-island",
            r"@astrojs",
            r"/_astro/",
            r"astro:page-load",
            r"astro:after-swap",
        ],
        weight=15,
    ),
    FrameworkSignature(
        name="Gatsby",
        patterns=[
            r"___gatsby",
            r"gatsby-",
            r"__GATSBY",
            r"gatsby-runtime",
            r"page-data\.json",
            r"/static/gatsby",
        ],
        weight=12,
    ),
    FrameworkSignature(
        name="Remix",
        patterns=[
            r"__remix",
            r"@remix-run",
            r"window\.__remixContext",
            r"_data\?",
            r"remix-",
        ],
        weight=12,
    ),
    FrameworkSignature(
        name="Create React App",
        patterns=[
            r"REACT_APP_",
            r"/static/js/main\.",
            r"/static/js/bundle\.js",
        ],
        weight=10,
    ),
]


def fingerprint(
    html: str = "",
    js_content: str = "",
    headers: Optional[dict[str, str]] = None,
) -> FrameworkResult:
    """Detect frameworks from HTML, JS, and HTTP headers."""
    result = FrameworkResult()
    combined = html + "\n" + js_content
    headers = headers or {}
    lowered_headers = {k.lower(): v for k, v in headers.items()}

    for fw in FRAMEWORKS:
        score = 0
        evidence: list[str] = []

        # Check header patterns
        for header_name, pattern in fw.header_patterns.items():
            header_val = lowered_headers.get(header_name, "")
            if header_val and re.search(pattern, header_val, re.IGNORECASE):
                score += fw.weight
                evidence.append(f"header:{header_name}={header_val[:50]}")

        # Check content patterns
        for pattern in fw.patterns:
            try:
                if re.search(pattern, combined, re.IGNORECASE):
                    score += fw.weight
                    # Find the actual snippet
                    m = re.search(pattern, combined, re.IGNORECASE)
                    if m:
                        start = max(0, m.start() - 10)
                        snippet = combined[start : m.end() + 10].strip()[:60]
                        evidence.append(f"pattern:{snippet}")
            except re.error:
                pass

        if score > 0:
            confidence = min(100, score)
            result.confidence[fw.name] = confidence
            result.evidence[fw.name] = evidence[:5]  # cap evidence list
            if confidence >= 10:
                result.detected.append(fw.name)

    # Sort detected by confidence
    result.detected.sort(key=lambda fw_name: result.confidence.get(fw_name, 0), reverse=True)
    if result.detected:
        logger.debug("Detected frameworks: %s", result.detected)
    return result
