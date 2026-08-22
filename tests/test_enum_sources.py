"""Tests for the Wayback/OTX enumeration sources and wildcard-DNS filtering."""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

import scanner  # noqa: E402


WAYBACK_CDX = json.dumps([
    ["original"],
    ["https://app.example.com/", "200"],
    ["http://old.example.com/blog/page1", "200"],
    ["https://other.domain.net/", "200"],        # out of scope — must drop
    ["ftp://files.example.com/pub", "200"],
])

OTX_JSON = json.dumps({"passive_dns": [
    {"hostname": "api.example.com"},
    {"hostname": "api.example.com"},               # dedup via set
    {"hostname": "www.otherdomain.org"},           # out of scope — must drop
    {"hostname": ""},
]})


def test_wayback_source_extracts_in_domain_hostnames(monkeypatch):
    seen_urls = []

    def fake_curl(url, timeout=20):
        seen_urls.append(url)
        return WAYBACK_CDX if "web.archive.org" in url else ""

    monkeypatch.setattr(scanner, "_curl", fake_curl)
    names = scanner._subdomains_wayback("example.com")
    assert names == {"app.example.com", "old.example.com", "files.example.com"}
    assert "collapse=urlkey" in seen_urls[0] and "output=json" in seen_urls[0]


def test_otx_source_extracts_in_domain_hostnames(monkeypatch):
    monkeypatch.setattr(scanner, "_curl",
                        lambda url, timeout=20:
                        OTX_JSON if "otx.alienvault.com" in url else "")
    names = scanner._subdomains_otx("example.com")
    assert names == {"api.example.com"}


def test_enum_sources_degrade_on_bad_json(monkeypatch):
    monkeypatch.setattr(scanner, "_curl",
                        lambda url, timeout=20: "{not json")
    assert scanner._subdomains_wayback("example.com") == set()
    assert scanner._subdomains_otx("example.com") == set()


def test_enumerate_subdomains_unions_new_sources(monkeypatch):
    calls = []

    def fake_curl(url, timeout=20):
        if "web.archive.org" in url:
            return WAYBACK_CDX
        if "otx.alienvault.com" in url:
            return OTX_JSON
        return ""

    monkeypatch.setattr(scanner, "_curl", fake_curl)
    monkeypatch.setattr(scanner, "ENUM_RETRIES", 0)
    orig = scanner._with_retries

    def no_retry(fn, source, domain, attempts=0):
        return orig(fn, source, domain, attempts=0)

    monkeypatch.setattr(scanner, "_with_retries", no_retry)
    # silence the 4 legacy CT sources so the union is fully deterministic
    monkeypatch.setattr(scanner, "_subdomains_crtsh", lambda d: set())
    monkeypatch.setattr(scanner, "_subdomains_certspotter", lambda d: set())
    monkeypatch.setattr(scanner, "_subdomains_hackertarget", lambda d: set())
    monkeypatch.setattr(scanner, "_subdomains_crtname", lambda d: set())
    del calls
    subs = scanner.enumerate_subdomains(["example.com"])
    assert {"app.example.com", "old.example.com", "api.example.com"} <= subs


def test_detect_wildcard_resolves_random_label(monkeypatch):
    monkeypatch.setattr(scanner, "_wildcard_cache", {})
    monkeypatch.setattr(scanner, "_resolve",
                        lambda host, timeout=10: ["203.0.113.9"]
                        if host.endswith(".example.com") else [])
    assert scanner._detect_wildcard("example.com") == {"203.0.113.9"}
    # cached — second call must not re-resolve
    monkeypatch.setattr(scanner, "_resolve", lambda host, timeout=10: [])
    assert scanner._detect_wildcard("example.com") == {"203.0.113.9"}


def test_filter_wildcard_hosts_drops_only_pure_echoes(monkeypatch):
    monkeypatch.setattr(scanner, "_wildcard_cache", {})
    monkeypatch.setattr(scanner, "_resolve", lambda host, timeout=10: [])
    monkeypatch.setattr(scanner, "WILDCARD_FILTER", True)
    wildcard = {"example.com": {"203.0.113.9"}}
    hosts = {
        "example.com": ["192.0.2.1"],                       # apex stays
        "phantom1.example.com": ["203.0.113.9"],            # pure echo — drop
        "phantom2.example.com": ["203.0.113.9"],            # pure echo — drop
        "real.example.com": ["203.0.113.9", "198.51.100.7"],  # own IP — stay
    }
    monkeypatch.setattr(scanner, "_detect_wildcard", lambda d: wildcard.get(d, set()))
    out, dropped = scanner._filter_wildcard_hosts(hosts, ["example.com"])
    assert dropped == 2
    assert set(out) == {"example.com", "real.example.com"}
    assert out["real.example.com"] == ["203.0.113.9", "198.51.100.7"]


def test_filter_disabled_returns_unchanged(monkeypatch):
    monkeypatch.setattr(scanner, "WILDCARD_FILTER", False)
    hosts = {"phantom.example.com": ["203.0.113.9"]}
    out, dropped = scanner._filter_wildcard_hosts(hosts, ["example.com"])
    assert out is hosts and dropped == 0
