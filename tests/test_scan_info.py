"""Tests for scan observability surfacing (scan_info in the aggregate payload)."""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

os.environ.setdefault("CTI_SCAN_TOKEN", "test-tok")
os.environ.setdefault("CTI_USER", "testuser")
os.environ.setdefault("CTI_PASSWORD", "testpass")

import cti_correlation as cc  # noqa: E402
import main  # noqa: E402


def _setup_org(tmp_path, monkeypatch, meta):
    data_root = tmp_path / "cti"
    org_dir = data_root / "orgs" / "obs"
    org_dir.mkdir(parents=True)
    (org_dir / "findings.json").write_text(json.dumps({
        "meta": meta,
        "findings": [{"id": "F-1", "title": "T", "severity": "LOW",
                      "target": "a.example.com", "category": "x",
                      "status": "OPEN"}],
    }))
    (org_dir / "baseline.txt").write_text("a.example.com\n")
    (data_root / "orgs.json").write_text(json.dumps({
        "obs": {"name": "obs", "domains": ["example.com", "example.org"],
                "findings": "data/orgs/obs/findings.json",
                "baseline": "data/orgs/obs/baseline.txt"},
    }))
    monkeypatch.setattr(cc, "DATA_ROOT", str(data_root))
    monkeypatch.setattr(cc, "_REGISTRY_FILE", str(data_root / "orgs.json"))
    cc._reload_registry()
    cc.invalidate_org_cache("obs")


META = {
    "date": "2026-08-22", "subdomains": 38, "reachable": 21,
    "reconcile": {"observed": 17},
    "scan_stats": {"enum": 12.4, "resolve": 3.1, "probe": 41.0,
                   "services": 19.5, "tls": 2.2, "nvd": 0.0,
                   "total": 78.2, "last": 0.0},
}


def test_scan_info_in_dashboard_payload(tmp_path, monkeypatch):
    _setup_org(tmp_path, monkeypatch, META)
    payload = main._build_dashboard_payload("obs")
    si = payload.get("scan_info")
    assert si is not None
    assert si["date"] == "2026-08-22"
    assert si["subdomains"] == 38 and si["reachable"] == 21
    assert si["domains"] == 2
    assert si["reconcile"] == 17
    assert si["stages"]["enum"] == 12.4
    assert si["stages"]["nvd"] == 0.0            # present-but-zero is kept
    assert si["stages"]["total"] == 78.2
    assert "last" not in si["stages"]            # internal checkpoint marker hidden


def test_scan_info_absent_without_stats(tmp_path, monkeypatch):
    _setup_org(tmp_path, monkeypatch, {"date": "2026-08-22"})
    payload = main._build_dashboard_payload("obs")
    assert payload.get("scan_info") is None
    # other payload keys unaffected
    assert payload["org"] == "obs"
    assert payload["findings"]["findings_total"] == 1
