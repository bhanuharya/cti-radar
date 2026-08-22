"""Focused regression / performance tests for the aggregate dashboard plan.

- Deep-compare aggregate fields with legacy endpoint responses
- Verify thresholded gzip (JSON only, >1KB gzipped, small not)
- Verify legacy routes retained and fallback shapes stable
- Verify single findings load per aggregate request (read-through cache)
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

# Tests must not inherit live service credentials from the invoking shell.
os.environ["CTI_SCAN_TOKEN"] = "test-tok"
os.environ["CTI_USER"] = "testuser"
os.environ["CTI_PASSWORD"] = "testpass"

import cti_correlation as cc
import scanner  # noqa: F401
import main
from fastapi.testclient import TestClient


def _ensure_sample_data():
    # ensure orgs.json has sample + beta registered (under redirected root)
    orgs_json = os.path.join(cc.DATA_ROOT, "orgs.json")
    reg = {}
    if os.path.exists(orgs_json):
        try:
            with open(orgs_json) as f:
                reg = json.load(f)
        except Exception:
            reg = {}
    org_root = os.path.join(cc.DATA_ROOT, "orgs")
    for slug in ("sample", "beta"):
        od = os.path.join(org_root, slug)
        os.makedirs(od, exist_ok=True)
        if slug not in reg:
            reg[slug] = {
                "name": slug,
                "domains": ["example.com"],
                "findings": f"data/orgs/{slug}/findings.json",
                "baseline": f"data/orgs/{slug}/baseline.txt",
            }
        fp = os.path.join(od, "findings.json")
        bp = os.path.join(od, "baseline.txt")
        hp = os.path.join(od, "history.json")
        with open(fp, "w") as f:
            json.dump({"meta": {"date": "2026-01-15"}, "findings": [
                {"id": "F-001", "title": "T", "severity": "CRITICAL", "target": "a.example.com", "ip": "1.2.3.4", "category": "XSS", "status": "OPEN", "related_cves": ["CVE-2023-1234"]},
                {"id": "F-002", "title": "U", "severity": "HIGH", "target": "b.example.com", "ip": "1.2.3.4", "category": "XSS", "status": "OPEN", "related_cves": ["CVE-2023-1234"]},
            ]}, f, indent=2)
        with open(bp, "w") as f:
            f.write("a.example.com\n1.2.3.4\n")
        with open(hp, "w") as f:
            json.dump([{"ts": "2026-01-10T00:00:00", "kind": "scan", "mode": "fast", "summary": {"found": 2}}], f)
    with open(orgs_json, "w") as f:
        json.dump(reg, f, indent=2)
    cc._reload_registry()


_ensure_sample_data()
client = TestClient(main.app)

_AUTH = {"X-CTI-Token": os.environ["CTI_SCAN_TOKEN"]}


def _get(path):
    return client.get(path, headers=_AUTH)


def test_aggregate_matches_legacy():
    for org in ("sample", "beta"):
        s_sum = _get(f"/api/summary?org={org}").json()
        s_graph = _get(f"/api/graph?org={org}").json()
        s_fleet = _get(f"/api/fleet?org={org}").json()
        s_ips = _get(f"/api/ips?org={org}").json()
        s_find = _get(f"/api/findings?org={org}&sort=severity&status=all").json()
        s_hist = _get(f"/api/orgs/{org}/history").json()
        agg = _get(f"/api/dashboard?org={org}&sort=severity&status=all").json()
        assert agg["summary"] == s_sum
        assert agg["graph"] == s_graph
        assert agg["fleet"] == s_fleet
        assert agg["ips"] == s_ips
        assert agg["findings"]["findings_total"] == s_find["findings_total"]
        assert [f["id"] for f in agg["findings"]["findings"]] == [
            f["id"] for f in s_find["findings"]
        ]
        # Aggregate lists stay lightweight; the legacy endpoint remains full.
        if agg["findings"]["findings"]:
            light = agg["findings"]["findings"][0]
            full = s_find["findings"][0]
            assert "status_history" not in light
            assert "status_history" in full
        assert agg["history"] == s_hist
        # also /api/orgs/{slug}/dashboard
        agg2 = _get(f"/api/orgs/{org}/dashboard?sort=severity&status=all").json()
        assert agg2["summary"] == s_sum


def test_legacy_routes_retained():
    for path in ["/api/summary?org=sample", "/api/graph?org=sample", "/api/fleet?org=sample", "/api/ips?org=sample", "/api/findings?org=sample"]:
        r = _get(path)
        assert r.status_code == 200, path


def test_thresholded_gzip():
    # small JSON (<1KB) should NOT be gzipped
    r_small = _get("/api/summary?org=sample", )
    assert r_small.headers.get("content-encoding") is None
    # large aggregate should be gzipped when Accept-Encoding includes gzip
    r_large = client.get("/api/dashboard?org=sample&sort=severity&status=all",
                         headers={**_AUTH, "Accept-Encoding": "gzip"})
    assert r_large.headers.get("content-encoding") == "gzip"
    # decoded payload still correct (TestClient auto-decompresses)
    r_plain = client.get("/api/dashboard?org=sample&sort=severity&status=all",
                         headers={**_AUTH, "Accept-Encoding": "identity"})
    assert r_large.json() == r_plain.json()


def test_single_findings_load_per_aggregate():
    import builtins
    orig = builtins.open
    cnt = {"n": 0}

    def counting_open(*a, **kw):
        if a and "findings.json" in str(a[0]):
            cnt["n"] += 1
        return orig(*a, **kw)

    builtins.open = counting_open
    try:
        # cold read-through cache: aggregate reads findings.json exactly once
        cc.invalidate_org_cache("sample")
        cc.invalidate_org_cache("beta")
        cnt["n"] = 0
        _get("/api/dashboard?org=sample&sort=severity&status=all")
        assert cnt["n"] == 1, f"aggregate should open findings.json once, got {cnt['n']}"
        # warm cache: a second identical request avoids the disk read entirely
        cnt["n"] = 0
        _get("/api/dashboard?org=sample&sort=severity&status=all")
        assert cnt["n"] == 0, f"cached aggregate should not re-open findings.json, got {cnt['n']}"
        # each legacy endpoint performs its own read when cache is invalidated
        cnt["n"] = 0
        for p in ["/api/summary?org=sample", "/api/graph?org=sample", "/api/fleet?org=sample", "/api/ips?org=sample", "/api/findings?org=sample&sort=severity&status=all"]:
            cc.invalidate_org_cache("sample")
            _get(p)
        assert cnt["n"] >= 5
    finally:
        builtins.open = orig
        cc.invalidate_org_cache("sample")
        cc.invalidate_org_cache("beta")


def test_pii_masking_preserved():
    # finding with PII-like content should be masked via normalize_finding
    f = {"id": "X", "target": "h.example.com", "severity": "HIGH", "status": "OPEN", "description": "contact admin@example.com phone 081234567890", "related_cves": []}
    nf = cc.normalize_finding(f, "sample", meta_date="2026-01-15")
    # email should be masked (first char + ***)
    assert "admin@example.com" not in str(nf.get("description", ""))
    assert "***@" in str(nf.get("description", ""))


def test_from_data_helpers_equivalent():
    fs, baseline = cc.load_data("sample")
    # direct vs from_data
    assert cc.summary("sample") == cc.summary_from_data(fs, baseline)
    assert cc.fleet_spread("sample") == cc.fleet_spread_from_data(fs)
    assert cc.ip_sharing("sample") == cc.ip_sharing_from_data(fs)
    domains = (cc.REGISTRY.get("sample") or {}).get("domains") or []
    assert cc.build_graph("sample") == cc.build_graph_from_data(fs, baseline, domains)
