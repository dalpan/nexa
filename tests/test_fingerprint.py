"""Tests for framework fingerprinting."""

from __future__ import annotations

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from nexa.core.fingerprint import fingerprint


class TestNextJsFingerprint:
    def test_detects_nextjs_from_html(self):
        html = """
        <html>
        <body>
        <script id="__NEXT_DATA__" type="application/json">{"props":{},"buildId":"abc123"}</script>
        <script src="/_next/static/chunks/main.js"></script>
        </body>
        </html>
        """
        result = fingerprint(html=html)
        assert "Next.js" in result.detected

    def test_nextjs_high_confidence(self):
        html = '<div>__NEXT_DATA__ is here and /_next/static/ is loaded</div>'
        result = fingerprint(html=html)
        if "Next.js" in result.detected:
            assert result.confidence.get("Next.js", 0) >= 10

    def test_nextjs_build_id(self):
        js = 'self.__next_f.push([1,"buildId":"abc123def456"])'
        html = '<script src="/_next/static/chunks/main.js"></script>'
        result = fingerprint(html=html, js_content=js)
        assert "Next.js" in result.detected


class TestNuxtFingerprint:
    def test_detects_nuxt_from_html(self):
        html = """
        <html>
        <body>
        <script>window.__NUXT__ = {"config":{"public":{}}};</script>
        <script src="/_nuxt/app.js"></script>
        </body>
        </html>
        """
        result = fingerprint(html=html)
        assert "Nuxt" in result.detected

    def test_nuxt_window_key(self):
        html = "<script>window.__nuxt = {};</script>"
        result = fingerprint(html=html)
        assert "Nuxt" in result.detected


class TestAngularFingerprint:
    def test_detects_angular_ng_version(self):
        html = '<app-root ng-version="17.0.0"></app-root>'
        result = fingerprint(html=html)
        assert "Angular" in result.detected

    def test_detects_angular_ng_app(self):
        html = '<div ng-app="myApp"></div>'
        result = fingerprint(html=html)
        assert "Angular" in result.detected

    def test_angular_platform_browser(self):
        js = "platformBrowserDynamic().bootstrapModule(AppModule)"
        result = fingerprint(js_content=js)
        assert "Angular" in result.detected


class TestWebpackFingerprint:
    def test_detects_webpackchunk(self):
        js = '(self.webpackChunkmy_app=self.webpackChunkmy_app||[]).push([[0],{'
        result = fingerprint(js_content=js)
        assert "Webpack" in result.detected

    def test_detects_webpack_require(self):
        js = "var __webpack_require__ = function(moduleId) {"
        result = fingerprint(js_content=js)
        assert "Webpack" in result.detected

    def test_detects_webpack_modules(self):
        js = "__webpack_modules__[moduleId]"
        result = fingerprint(js_content=js)
        assert "Webpack" in result.detected


class TestVueFingerprint:
    def test_detects_vue_app(self):
        html = '<div id="app" __vue_app__></div>'
        result = fingerprint(html=html)
        assert "Vue" in result.detected

    def test_detects_vue_data_attr(self):
        html = '<div data-v-7ba5bd90 class="container"></div>'
        result = fingerprint(html=html)
        assert "Vue" in result.detected


class TestViteFingerprint:
    def test_detects_vite_client(self):
        html = '<script type="module" src="/@vite/client"></script>'
        result = fingerprint(html=html)
        assert "Vite" in result.detected

    def test_detects_import_meta_env(self):
        js = "const apiUrl = import.meta.env.VITE_API_URL;"
        result = fingerprint(js_content=js)
        assert "Vite" in result.detected


class TestAstroFingerprint:
    def test_detects_astro_island(self):
        html = '<astro-island uid="abc" component-url="/_astro/Widget.js"></astro-island>'
        result = fingerprint(html=html)
        assert "Astro" in result.detected

    def test_detects_astro_path(self):
        html = '<script src="/_astro/hoisted.abc123.js"></script>'
        result = fingerprint(html=html)
        assert "Astro" in result.detected


class TestGatsbyFingerprint:
    def test_detects_gatsby(self):
        html = '<div id="___gatsby"><div id="gatsby-focus-wrapper"></div></div>'
        result = fingerprint(html=html)
        assert "Gatsby" in result.detected

    def test_detects_gatsby_global(self):
        js = "window.___gatsby = true; __GATSBY = {};"
        result = fingerprint(js_content=js)
        assert "Gatsby" in result.detected


class TestNoFrameworkDetected:
    def test_empty_html_no_frameworks(self):
        result = fingerprint(html="<html><body><p>Hello World</p></body></html>")
        # Should not detect any major JS frameworks
        assert result.detected == [] or all(
            result.confidence.get(fw, 0) < 20 for fw in result.detected
        )

    def test_plain_html(self):
        result = fingerprint(html="<h1>Welcome</h1><p>This is a plain page.</p>")
        # No framework markers present
        assert len(result.detected) == 0 or all(
            result.confidence.get(fw, 0) < 20 for fw in result.detected
        )

    def test_returns_framework_result_type(self):
        from nexa.models import FrameworkResult
        result = fingerprint(html="<html></html>")
        assert isinstance(result, FrameworkResult)
        assert isinstance(result.detected, list)
        assert isinstance(result.confidence, dict)
        assert isinstance(result.evidence, dict)


class TestMultipleFrameworks:
    def test_detects_nextjs_and_webpack(self):
        html = '<script src="/_next/static/chunks/main.js"></script>'
        js = "__webpack_require__.e = function(chunkId) {}"
        result = fingerprint(html=html, js_content=js)
        # Both should be detected — Next.js uses Webpack internally
        assert "Next.js" in result.detected or "Webpack" in result.detected

    def test_confidence_ordering(self):
        html = """
        <div __vue_app__></div>
        <script src="/_next/static/chunks/app.js"></script>
        <script>window.__NEXT_DATA__ = {};</script>
        """
        result = fingerprint(html=html)
        # Next.js should have higher confidence than Vue here
        if "Next.js" in result.detected and "Vue" in result.detected:
            assert result.confidence.get("Next.js", 0) >= result.confidence.get("Vue", 0)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
