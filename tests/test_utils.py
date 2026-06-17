"""Tests for utility functions."""

from __future__ import annotations

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from nexa.utils import (
    deduplicate_urls,
    extract_domain,
    is_same_domain,
    normalize_url,
    shannon_entropy,
    slugify,
    is_placeholder,
    redact_value,
    get_context_window,
    truncate_value,
)


class TestShannonEntropy:
    def test_empty_string_is_zero(self):
        assert shannon_entropy("") == 0.0

    def test_uniform_string_is_zero(self):
        assert shannon_entropy("aaaaaaa") == 0.0

    def test_binary_string_is_one(self):
        result = shannon_entropy("abababab")
        assert abs(result - 1.0) < 0.01

    def test_high_entropy(self):
        # A string with many different characters has high entropy
        s = "aAbBcCdDeEfFgGhH1234567890!@#$"
        result = shannon_entropy(s)
        assert result > 4.0

    def test_base64_like_string(self):
        s = "SG9sYXMgbXVuZG8gbWkgbm9tYnJl"
        result = shannon_entropy(s)
        assert result > 3.5

    def test_returns_float(self):
        assert isinstance(shannon_entropy("hello world"), float)

    def test_single_character(self):
        assert shannon_entropy("z") == 0.0


class TestNormalizeUrl:
    def test_resolves_relative_url(self):
        result = normalize_url("/path/to/file.js", "https://example.com")
        assert result == "https://example.com/path/to/file.js"

    def test_strips_fragment(self):
        result = normalize_url("https://example.com/page#section")
        assert "#" not in result
        assert result == "https://example.com/page"

    def test_lowercases_host(self):
        result = normalize_url("https://EXAMPLE.COM/path")
        assert "example.com" in result

    def test_removes_default_http_port(self):
        result = normalize_url("http://example.com:80/path")
        assert ":80" not in result

    def test_removes_default_https_port(self):
        result = normalize_url("https://example.com:443/path")
        assert ":443" not in result

    def test_rejects_non_http_schemes(self):
        result = normalize_url("ftp://example.com/file")
        assert result == ""

    def test_empty_url_returns_empty(self):
        result = normalize_url("")
        assert result == ""

    def test_absolute_url_unchanged_scheme(self):
        result = normalize_url("https://example.com/api/v1")
        assert result.startswith("https://")

    def test_relative_path_with_base(self):
        result = normalize_url("../other.js", "https://example.com/app/main.js")
        assert "example.com" in result

    def test_query_string_preserved(self):
        result = normalize_url("https://example.com/script.js?v=123")
        assert "v=123" in result


class TestIsSameDomain:
    def test_same_domain(self):
        assert is_same_domain("https://example.com/page", "example.com")

    def test_subdomain_is_same(self):
        assert is_same_domain("https://app.example.com/page", "example.com")

    def test_different_domain_false(self):
        assert not is_same_domain("https://other.com/page", "example.com")

    def test_similar_but_different(self):
        assert not is_same_domain("https://notexample.com/page", "example.com")

    def test_empty_url(self):
        assert not is_same_domain("", "example.com")

    def test_empty_domain(self):
        assert not is_same_domain("https://example.com", "")

    def test_with_port(self):
        assert is_same_domain("https://example.com:8080/api", "example.com")

    def test_deep_subdomain(self):
        assert is_same_domain("https://api.v2.app.example.com/resource", "example.com")


class TestDeduplicateUrls:
    def test_removes_duplicates(self):
        urls = [
            "https://example.com/a",
            "https://example.com/b",
            "https://example.com/a",
        ]
        result = deduplicate_urls(urls)
        assert len(result) == 2

    def test_preserves_order(self):
        urls = ["https://example.com/c", "https://example.com/a", "https://example.com/b"]
        result = deduplicate_urls(urls)
        assert result[0].endswith("/c")

    def test_empty_list(self):
        assert deduplicate_urls([]) == []

    def test_single_url(self):
        result = deduplicate_urls(["https://example.com/page"])
        assert len(result) == 1

    def test_case_insensitive_dedup(self):
        urls = ["https://Example.COM/path", "https://example.com/path"]
        result = deduplicate_urls(urls)
        assert len(result) == 1

    def test_trailing_slash_dedup(self):
        urls = ["https://example.com/path", "https://example.com/path/"]
        result = deduplicate_urls(urls)
        assert len(result) == 1


class TestExtractDomain:
    def test_simple_domain(self):
        assert extract_domain("https://example.com/path") == "example.com"

    def test_with_port(self):
        assert extract_domain("http://example.com:8080/api") == "example.com:8080"

    def test_subdomain(self):
        assert extract_domain("https://api.example.com/v1") == "api.example.com"

    def test_empty_url(self):
        assert extract_domain("") == ""

    def test_invalid_url(self):
        # Should not raise, return empty or netloc
        result = extract_domain("not-a-url")
        assert isinstance(result, str)


class TestSlugify:
    def test_basic(self):
        assert slugify("Hello World") == "hello-world"

    def test_special_chars_removed(self):
        result = slugify("example.com/path?q=1")
        assert "/" not in result
        assert "?" not in result

    def test_unicode_normalized(self):
        result = slugify("café résumé")
        assert isinstance(result, str)
        assert result  # not empty

    def test_max_length(self):
        long_str = "a" * 200
        result = slugify(long_str)
        assert len(result) <= 64


class TestIsPlaceholder:
    def test_your_api_key(self):
        assert is_placeholder("your-api-key")

    def test_replace_me(self):
        assert is_placeholder("REPLACE_ME")

    def test_placeholder_literal(self):
        assert is_placeholder("placeholder")

    def test_example_in_value(self):
        assert is_placeholder("example-token-here")

    def test_xxx_pattern(self):
        assert is_placeholder("xxxxxxxxxxxxxxxx")

    def test_real_key_not_placeholder(self):
        # AKIAIOSFODNN7EXAMPLE starts with AKIA — real-secret prefix prevents placeholder flagging
        assert not is_placeholder("AKIAIOSFODNN7EXAMPLE")
        # Stripe live secret key — starts with sk_live_
        _sk = "sk" + "_live_" + "4eC39HqLyjWDarjtT1zdp7dc"
        assert not is_placeholder(_sk)

    def test_empty_string(self):
        # Empty string is considered a placeholder (no value)
        assert is_placeholder("")

    def test_null_literal(self):
        assert is_placeholder("null")

    def test_undefined_literal(self):
        assert is_placeholder("undefined")


class TestRedactValue:
    def test_short_value_fully_redacted(self):
        result = redact_value("abc")
        assert result == "***"

    def test_long_value_partially_shown(self):
        value = "sk" + "_live_" + "4eC39HqLyjWDarjtT1zdp7dc"
        result = redact_value(value)
        assert "*" in result
        # Should show some prefix and suffix
        assert len(result) > 0

    def test_preserves_length_info(self):
        value = "A" * 40
        result = redact_value(value)
        assert len(result) == len(value)


class TestGetContextWindow:
    def test_extracts_context(self):
        text = "abc " + "secret_key=hello123 " + "xyz"
        start = text.index("secret_key")
        end = start + len("secret_key=hello123")
        ctx = get_context_window(text, start, end, window=10)
        assert "secret" in ctx.lower() or "hello" in ctx.lower()

    def test_handles_start_of_text(self):
        text = "key=value rest of text"
        ctx = get_context_window(text, 0, 9, window=100)
        assert "key" in ctx.lower()

    def test_handles_end_of_text(self):
        text = "some prefix and key=value"
        ctx = get_context_window(text, len(text) - 9, len(text), window=100)
        assert ctx  # should not crash


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
