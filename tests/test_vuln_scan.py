"""Tests for host-based vuln lookup: scope safety, passive match, active gate."""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

import vuln_scan as vs  # noqa: E402
import cti_correlation as cc  # noqa: E402


@pytest.fixture(autouse=True)
def _restore_registry():
    snap = dict(cc.REGISTRY)
    yield
    cc.REGISTRY.clear()
    cc.REGISTRY.update(snap)


def _seed_org(tmp_path, monkeypatch):
    import scanner as _scanner  # noqa: E402
    d = tmp_path / "vdata"
    (d / "orgs" / "acme").mkdir(parents=True)
    monkeypatch.setenv("CTI_DATA_DIR", str(d))
    monkeypatch.setattr(cc, "DATA_ROOT", str(d))
    monkeypatch.setattr(cc, "_REGISTRY_FILE", str(d / "orgs.json"))
    monkeypatch.setattr(_scanner, "DATA_ROOT", str(d))
    monkeypatch.setattr(_scanner, "ORG_ROOT", str(d / "orgs"))
    store = {
        "findings": [],
        "meta": {"fingerprints": {
            "app.example.com": {"url": "https://app.example.com", "code": "200",
                                "server": "nginx/1.18.0",
                                "versions": [{"product": "nginx", "version": "1.18.0"}]},
            "clean.example.com": {"url": "https://clean.example.com", "code": "200",
                                  "server": "nginx", "title": "ok"},
        }},
    }
    (d / "orgs" / "acme" / "findings.json").write_text(json.dumps(store))
    (d / "orgs" / "acme" / "baseline.txt").write_text("app.example.com\nclean.example.com\n")
    (d / "orgs.json").write_text(json.dumps({"acme": {"name": "Acme", "domains": ["example.com"],
                                                      "findings": "data/orgs/acme/findings.json",
                                                      "baseline": "data/orgs/acme/baseline.txt"}}))
    cc._reload_registry()
    # vuln_scan resolves org via cc.org_get -> registry; scanner fingerprint refresh
    # is disabled in these tests via refresh=False
    return d


def test_rejects_out_of_scope(tmp_path, monkeypatch):
    _seed_org(tmp_path, monkeypatch)
    r = vs.vuln_scan_org("acme", targets=["evil.com"], refresh=False)
    assert "error" in r and "scope" in r["error"]
    r = vs.vuln_scan_org("acme", targets=["not a host!!"], refresh=False)
    assert "error" in r


def test_passive_cve_match_persists_once(tmp_path, monkeypatch):
    _seed_org(tmp_path, monkeypatch)
    r1 = vs.vuln_scan_org("acme", targets=["app.example.com"], checks=["cve"], refresh=False)
    assert r1.get("error", "") == "" or "error" not in r1
    assert r1["candidates"] >= 1
    assert r1["new_findings"] >= 1
    persisted = json.loads(open(cc.org_findings_path("acme")).read())["findings"]
    assert any(f.get("source") == "vuln-scan" for f in persisted)
    r2 = vs.vuln_scan_org("acme", targets=["app.example.com"], checks=["cve"], refresh=False)
    assert r2["new_findings"] == 0  # dedup, no duplicates


def test_clean_host_no_candidates(tmp_path, monkeypatch):
    _seed_org(tmp_path, monkeypatch)
    r = vs.vuln_scan_org("acme", targets=["clean.example.com"], checks=["cve"], refresh=False)
    assert r["new_findings"] == 0 and r["candidates"] == 0


def test_active_denied_by_default(tmp_path, monkeypatch):
    _seed_org(tmp_path, monkeypatch)
    monkeypatch.delenv("CTI_VULN_ACTIVE", raising=False)
    r = vs.vuln_scan_org("acme", targets=["app.example.com"], active=True, refresh=False)
    assert "error" in r and "denied" in r["error"]
    gate = vs._vuln_active_authorization_error({"domains": ["example.com"]})
    assert gate  # fail-closed without env


def test_nuclei_uses_canonical_scoped_target_not_stored_url(tmp_path, monkeypatch):
    """A stale/poisoned fingerprint URL must never influence active Nuclei egress."""
    _seed_org(tmp_path, monkeypatch)
    store_path = cc.org_findings_path("acme")
    store = json.loads(open(store_path).read())
    store["meta"]["fingerprints"]["app.example.com"]["url"] = "https://evil.example/not-in-scope"
    open(store_path, "w").write(json.dumps(store))

    monkeypatch.setenv("CTI_VULN_ACTIVE", "1")
    monkeypatch.setenv("CTI_VULN_ISOLATED", "1")
    monkeypatch.setenv("CTI_VULN_ALLOWED_DOMAINS", "example.com")
    monkeypatch.setenv("CTI_VULN_ROE_EXPIRES", "2999-01-01T00:00:00Z")
    import nuclei_scan as nuc
    monkeypatch.setattr(nuc, "engine_status", lambda: {"available": True, "reason": ""})
    captured = {}

    def fake_run(target_urls, severity, tags, timeout_s, on_progress=None):
        captured["targets"] = target_urls
        return "", None, "simulated no-network run"

    monkeypatch.setattr(nuc, "run_scan", fake_run)
    result = vs.vuln_scan_org("acme", targets=["app.example.com"], engine="nuclei", refresh=False)
    assert result["engine"] == "nuclei"
    assert captured["targets"] == ["https://app.example.com"]


def test_nuclei_rejects_known_host_outside_registered_org_domains(tmp_path, monkeypatch):
    """Known-host state alone must not enlarge active Nuclei scope."""
    _seed_org(tmp_path, monkeypatch)
    store_path = cc.org_findings_path("acme")
    store = json.loads(open(store_path).read())
    store["meta"]["fingerprints"]["evil.example"] = {"url": "https://evil.example", "code": "200"}
    open(store_path, "w").write(json.dumps(store))

    monkeypatch.setenv("CTI_VULN_ACTIVE", "1")
    monkeypatch.setenv("CTI_VULN_ISOLATED", "1")
    monkeypatch.setenv("CTI_VULN_ALLOWED_DOMAINS", "example.com")
    monkeypatch.setenv("CTI_VULN_ROE_EXPIRES", "2999-01-01T00:00:00Z")
    import nuclei_scan as nuc
    monkeypatch.setattr(nuc, "engine_status", lambda: {"available": True, "reason": ""})
    called = {"run": False}

    def fake_run(*args, **kwargs):
        called["run"] = True
        return "", None, "simulated no-network run"

    monkeypatch.setattr(nuc, "run_scan", fake_run)
    result = vs.vuln_scan_org("acme", targets=["evil.example"], engine="nuclei", refresh=False)
    assert "error" in result and "outside registered org domain" in result["error"]
    assert not called["run"]


def test_canonical_nuclei_url_preserves_only_same_host_scheme_and_port():
    assert vs._canonical_nuclei_url("app.example.com", {"url": "http://app.example.com:8080/path?q=1"}) == "http://app.example.com:8080"
    assert vs._canonical_nuclei_url("app.example.com", {"url": "https://user@evil.example/x"}) == "https://app.example.com"
