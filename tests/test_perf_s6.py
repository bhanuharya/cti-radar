"""Tests for S6 performance work: shared resolver pool, InternetDB cache,
per-stage scan stats."""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

import scanner  # noqa: E402
import cti_correlation as cc  # noqa: E402


def test_dns_pool_shared_and_reused():
    scanner._dns_pool_inst = None
    p1 = scanner._dns_pool()
    p2 = scanner._dns_pool()
    assert p1 is p2
    assert p1._max_workers == scanner.DNS_POOL_SIZE
    scanner._dns_pool_inst = None  # do not leak the executor into other tests


def test_resolve_rejects_private_answers(monkeypatch):
    """Rebinding guard intact on the shared-pool implementation."""
    monkeypatch.setattr(scanner.socket, "getaddrinfo",
                        lambda host, port: [(0, 0, 0, "", ("10.0.0.5", 0))])
    assert scanner._resolve("internal.example.com") == []
    monkeypatch.setattr(scanner.socket, "getaddrinfo",
                        lambda host, port: [(0, 0, 0, "", ("93.184.216.34", 0))])
    assert scanner._resolve("ok.example.com") == ["93.184.216.34"]


def test_resolve_deadline_returns_empty(monkeypatch):
    import concurrent.futures as cf

    def hang(host, port):
        import time as _t
        _t.sleep(3)
        return [(0, 0, 0, "", ("93.184.216.34", 0))]
    monkeypatch.setattr(scanner.socket, "getaddrinfo", hang)
    out = scanner._resolve("slow.example.com", timeout=0.2)
    assert out == []
    # pool must still be usable after a timed-out lookup
    monkeypatch.setattr(scanner.socket, "getaddrinfo",
                        lambda host, port: [(0, 0, 0, "", ("104.16.132.229", 0))])
    assert scanner._resolve("after.example.com") == ["104.16.132.229"]


def test_internetdb_cached_per_ip(monkeypatch):
    monkeypatch.setattr(scanner, "_idb_cache", {})
    calls = []

    def fake_curl(url, timeout=20):
        calls.append(url)
        return json.dumps({"ports": [{"port": 443}], "cpes": [], "vulns": []})
    monkeypatch.setattr(scanner, "_curl", fake_curl)
    d1 = scanner._internetdb("203.0.113.77")
    d2 = scanner._internetdb("203.0.113.77")
    assert d1 == d2 and d1["ports"][0]["port"] == 443
    assert len(calls) == 1                      # second call served from cache
    # a different IP is a new lookup
    scanner._internetdb("198.51.100.9")
    assert len(calls) == 2


def test_internetdb_negative_cached_safely(monkeypatch):
    monkeypatch.setattr(scanner, "_idb_cache", {})
    calls = []
    monkeypatch.setattr(scanner, "_curl", lambda url, timeout=20: calls.append(url) or "")
    assert scanner._internetdb("203.0.113.1", retries=0) is None
    assert scanner._internetdb("203.0.113.1", retries=0) is None
    assert len(calls) == 1


ORG = {"slug": "sample", "domains": ["example.com"]}


def test_scan_stats_recorded(tmp_path, monkeypatch):
    org_dir = tmp_path / "orgs" / "sample"
    org_dir.mkdir(parents=True)
    (org_dir / "findings.json").write_text(json.dumps({"findings": []}))
    monkeypatch.setattr(scanner, "ORG_ROOT", str(tmp_path / "orgs"))
    monkeypatch.setattr(scanner, "enumerate_subdomains",
                        lambda domains, on_progress=None: {"app.example.com"})
    monkeypatch.setattr(scanner, "_resolve",
                        lambda h: ["93.184.216.34"] if h == "app.example.com" else [])
    monkeypatch.setattr(scanner, "_fetch_fingerprint",
                        lambda h, timeout, ips: (None, None))
    monkeypatch.setattr(scanner, "_tcp_reachable",
                        lambda ip, port, timeout: "closed")
    monkeypatch.setattr(scanner, "_grab_banner", lambda *a, **k: None)
    monkeypatch.setattr(scanner, "_tls_cert", lambda *a, **k: None)
    monkeypatch.setattr(scanner, "_wildcard_cache", {})
    monkeypatch.setattr(cc, "org_findings_path",
                        lambda org: str(tmp_path / "orgs" / org / "findings.json"))

    result = scanner.generate_org(dict(ORG), mode="fast")
    assert "error" not in result
    d = json.loads((org_dir / "findings.json").read_text())
    stats = d["meta"]["scan_stats"]
    for key in ("enum", "resolve", "probe", "services", "tls", "nvd", "total"):
        assert key in stats, stats
        assert stats[key] >= 0
