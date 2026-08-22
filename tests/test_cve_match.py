"""Tests for the offline version→CVE matching (cve_match + scanner wiring)."""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

import cve_match  # noqa: E402
import scanner  # noqa: E402
import cti_correlation as cc  # noqa: E402


# ---------------------------------------------------------------- comparator

def test_vkey_numeric_prefix_only():
    assert cve_match._vkey("1.18.0") == (1, 18, 0)
    assert cve_match._vkey("7.1p2") == (7, 1)
    assert cve_match._vkey("2.4.49-1ubuntu2") == (2, 4, 49)
    assert cve_match._vkey("2") == (2,)
    assert cve_match._vkey("") == ()


def test_version_satisfies_operators():
    assert cve_match.version_satisfies("1.18.0", ">=0.6.18,<1.20.1")
    assert cve_match.version_satisfies("1.20.0", ">=0.6.18,<1.20.1")
    assert not cve_match.version_satisfies("1.20.1", ">=0.6.18,<1.20.1")
    assert not cve_match.version_satisfies("0.6.17", ">=0.6.18,<1.20.1")
    assert cve_match.version_satisfies("2.4.49", "=2.4.49")
    assert not cve_match.version_satisfies("2.4.50", "=2.4.49")
    assert cve_match.version_satisfies("7.0", "<7.0.100")
    # truncated version 1.18 pads as 1.18.0 — range still applies
    assert cve_match.version_satisfies("1.18", ">=1.18.0,<1.20.1")
    # distro suffix ignored
    assert cve_match.version_satisfies("8.5p1-0ubuntu1", ">=8.5,<=9.7")


def test_normalize_product_aliases():
    assert cve_match.normalize_product("nginx") == "nginx"
    assert cve_match.normalize_product("Nginx") == "nginx"
    assert cve_match.normalize_product("Apache-Coyote") == "tomcat"
    assert cve_match.normalize_product("Apache-Coyote/1.1") == "tomcat"
    assert cve_match.normalize_product("Apache") == "apache"
    assert cve_match.normalize_product("OpenSSH") == "openssh"
    assert cve_match.normalize_product("MariaDB") == "mysql"
    assert cve_match.normalize_product("Apache Tomcat") == "tomcat"  # vendor-prefix drop
    assert cve_match.normalize_product("definitely-not-a-product") is None


# ------------------------------------------------------------------ map data

def test_map_loads_and_is_wellformed():
    products = cve_match.load_map()
    assert len(products) >= 18
    for key, entry in products.items():
        assert entry.get("aliases"), key
        for c in entry["cves"]:
            assert c["severity"] in ("CRITICAL", "HIGH")
            assert isinstance(c["cvss"], (int, float)) and c["cvss"] >= 7.0
            assert c["ranges"], c["cve"]
            assert c["summary"]
    # load_map re-raises on a malformed map (validation runs at load)
    bad = {"products": {"x": {"aliases": ["x"], "cves": [
        {"cve": "NOT-A-CVE", "severity": "HIGH", "ranges": ["<1"]}]}}}
    import unittest.mock as mock
    cve_match.reset_cache()
    try:
        with mock.patch("builtins.open",
                        mock.mock_open(read_data=json.dumps(bad))):
            try:
                cve_match.load_map()
                raised = False
            except ValueError:
                raised = True
            assert raised
    finally:
        cve_match.reset_cache()


# ------------------------------------------------------------------- matches

def test_match_cves_nginx_high_impact():
    matches = cve_match.match_cves([{"product": "nginx", "version": "1.18.0"}])
    cves = {m["cve"] for m in matches}
    assert "CVE-2021-23017" in cves
    m = next(m for m in matches if m["cve"] == "CVE-2021-23017")
    assert m["confidence"] == "medium"          # two numeric components
    assert m["fix_version"] == "1.20.1"


def test_match_cves_single_component_low_confidence():
    matches = cve_match.match_cves([{"product": "Apache", "version": "2"}])
    assert any(m["cve"] == "CVE-2019-0211" and m["confidence"] == "low"
               for m in matches)


def test_match_cves_patch_levels_exclude_fixed():
    assert cve_match.match_cves([{"product": "nginx", "version": "1.24.0"}]) == []
    # below/above the regreSSHion window (8.5–9.7); 38408 (5.5–9.3) also misses both
    assert cve_match.match_cves([{"product": "openssh", "version": "5.4p1"}]) == []
    assert cve_match.match_cves([{"product": "openssh", "version": "9.8p1"}]) == []


def test_match_cves_dedup_and_severity_order():
    matches = cve_match.match_cves([
        {"product": "Apache-Struts", "version": "2.5.10"},
    ])
    cves = [m["cve"] for m in matches]
    assert cves.count("CVE-2017-5638") == 1
    assert matches[0]["severity"] == "CRITICAL"


# ------------------------------------------------------------- scanner wiring

ORG = {"slug": "sample", "domains": ["example.com"]}


def _patch_scan(monkeypatch, tmp_path, fp_map, resolve_map):
    monkeypatch.setattr(scanner, "ORG_ROOT", str(tmp_path / "orgs"))
    monkeypatch.setattr(scanner, "enumerate_subdomains",
                        lambda domains, on_progress=None: set(fp_map))
    monkeypatch.setattr(scanner, "_resolve", lambda h: resolve_map.get(h, []))

    def fp(h, timeout, ips):
        return ("x", fp_map[h]) if h in fp_map else (None, None)
    monkeypatch.setattr(scanner, "_fetch_fingerprint", fp)
    monkeypatch.setattr(scanner, "_tcp_reachable", lambda ip, port, timeout: "closed")
    monkeypatch.setattr(scanner, "_grab_banner", lambda *a, **k: None)
    monkeypatch.setattr(scanner, "_tls_cert", lambda *a, **k: None)
    monkeypatch.setattr(scanner, "_wildcard_cache", {})
    monkeypatch.setattr(cc, "org_findings_path",
                        lambda org: str(tmp_path / "orgs" / org / "findings.json"))


def test_scan_emits_cve_finding(tmp_path, monkeypatch):
    org_dir = tmp_path / "orgs" / "sample"
    org_dir.mkdir(parents=True)
    (org_dir / "findings.json").write_text(json.dumps({"findings": []}))
    _patch_scan(monkeypatch, tmp_path,
                {"app.example.com": {"url": "https://app.example.com", "code": "200",
                                     "server": "nginx/1.18.0",
                                     "versions": [{"product": "nginx",
                                                   "version": "1.18.0"}]}},
                {"app.example.com": ["5.6.7.8"]})

    result = scanner.generate_org(dict(ORG), mode="fast")
    assert "error" not in result
    d = json.loads((org_dir / "findings.json").read_text())
    cvefs = [f for f in d["findings"] if f.get("source") == "scan-cve"]
    assert len(cvefs) == 1
    f = cvefs[0]
    assert "CVE-2021-23017" in f["related_cves"]
    assert "CORRELATED" in f["status_detail"]
    assert f["severity"] == "HIGH"
    assert f["provenance"]["confidence"] == "medium"
    assert f["port"] == 443
    # identity_key assigned from the scan-cve branch
    assert f["identity_key"].startswith("cve|app.example.com|")

    # light normalization: tier CORRELATED + confidence surface
    light = cc.normalize_finding_light(f)
    assert light["tier"] == "CORRELATED"
    assert light["confidence"] == "medium"
    assert any("nvd.nist.gov" in u for u in light["cve_links"])

    # second scan must not duplicate the finding
    scanner.generate_org(dict(ORG), mode="fast")
    d2 = json.loads((org_dir / "findings.json").read_text())
    assert len([x for x in d2["findings"] if x.get("source") == "scan-cve"]) == 1


def test_scan_cve_does_not_seed_correlation(tmp_path, monkeypatch):
    """A scan-cve finding must not generate cve-share/ip correlation records."""
    org_dir = tmp_path / "orgs" / "sample"
    org_dir.mkdir(parents=True)
    seed = {
        "id": "CVM-1", "target": "app.example.com", "ip": "5.6.7.8",
        "severity": "HIGH", "status": "OPEN",
        "status_detail": "CORRELATED (version-based match)",
        "category": "cve version match", "source": "scan-cve",
        "related_cves": ["CVE-2021-23017"],
    }
    other = {
        "id": "F-2", "target": "web.example.com", "ip": "5.6.7.8",
        "severity": "HIGH", "status": "OPEN",
        "status_detail": "CONFIRMED via scan", "category": "reachable",
        "source": "scan-surface", "related_cves": ["CVE-2021-23017"],
    }
    (org_dir / "findings.json").write_text(
        json.dumps({"findings": [seed, other], "meta": {}}))
    (org_dir / "baseline.txt").write_text("app.example.com\n")

    monkeypatch.setattr(scanner, "ORG_ROOT", str(tmp_path / "orgs"))
    monkeypatch.setattr(scanner, "_resolve", lambda h: ["5.6.7.8"])
    monkeypatch.setattr(scanner, "_internetdb",
                        lambda ip, retries=1: {"ports": [{"port": 443}],
                                               "cpes": [], "vulns": []})
    monkeypatch.setattr(cc, "org_findings_path",
                        lambda org: str(tmp_path / "orgs" / org / "findings.json"))
    monkeypatch.setattr(cc, "invalidate_org_cache", lambda slug: None)
    monkeypatch.setattr(scanner, "_history_path",
                        lambda slug: str(tmp_path / "orgs" / slug / "history.json"))
    scanner.correlate_org(dict(ORG))

    d = json.loads((org_dir / "findings.json").read_text())
    # no derived finding may cite the scan-cve record as its source host
    derived = [f for f in d["findings"] if f.get("source") in
               ("cve-share", "ip-co-residency", "internetdb")]
    assert all(not str(x.get("status_detail", "")).find("app.example.com") >= 0
               or x.get("evidence", {}).get("source_host") != "app.example.com"
               for x in derived)
    seeds = {x.get("evidence", {}).get("source_host") for x in derived}
    assert "app.example.com" not in seeds


def test_banner_versions_reach_cve_matching(tmp_path, monkeypatch):
    org_dir = tmp_path / "orgs" / "sample"
    org_dir.mkdir(parents=True)
    (org_dir / "findings.json").write_text(json.dumps({"findings": []}))
    monkeypatch.setattr(scanner, "ORG_ROOT", str(tmp_path / "orgs"))
    monkeypatch.setattr(scanner, "enumerate_subdomains",
                        lambda domains, on_progress=None: {"ssh.example.com"})
    # resolve ONLY the real host — an unconditional lambda would also answer
    # the wildcard probe and every name would be filtered as a phantom
    monkeypatch.setattr(scanner, "_resolve",
                        lambda h: ["5.6.7.8"] if h == "ssh.example.com" else [])
    monkeypatch.setattr(scanner, "_fetch_fingerprint",
                        lambda h, timeout, ips: (None, None))
    monkeypatch.setattr(scanner, "_tcp_reachable",
                        lambda ip, port, timeout:
                        "reachable" if str(port) == "22" else "closed")
    monkeypatch.setattr(scanner, "_grab_banner",
                        lambda ip, port, name, h, timeout:
                        "SSH-2.0-OpenSSH_9.6p1 Ubuntu" if str(port) == "22" else None)
    monkeypatch.setattr(scanner, "_tls_cert", lambda *a, **k: None)
    monkeypatch.setattr(scanner, "_wildcard_cache", {})
    monkeypatch.setattr(cc, "org_findings_path",
                        lambda org: str(tmp_path / "orgs" / org / "findings.json"))

    result = scanner.generate_org(dict(ORG), mode="fast")
    assert "error" not in result
    d = json.loads((org_dir / "findings.json").read_text())
    cvefs = [f for f in d["findings"] if f.get("source") == "scan-cve"]
    assert len(cvefs) == 1
    assert "CVE-2024-6387" in cvefs[0]["related_cves"]   # regreSSHion 8.5–9.7
    # version disclosure finding also synthesized from the banner
    ver = [f for f in d["findings"] if f.get("source") == "scan-version"]
    assert len(ver) == 1


# ------------------------------------------------------------- NVD enrichment

def _nvd_response(score=7.7):
    return {"vulnerabilities": [{"cve": {
        "cvssMetricV31": [{"cvssData": {"baseScore": score,
                                        "vectorString": "CVSS:3.1/AV:N/AC:L"}}],
        "descriptions": [{"lang": "en", "value": "resolver one-byte write"}]}}]}


def test_nvd_enrichment_attaches_to_finding(tmp_path, monkeypatch):
    org_dir = tmp_path / "orgs" / "sample"
    org_dir.mkdir(parents=True)
    (org_dir / "findings.json").write_text(json.dumps({"findings": []}))
    monkeypatch.setenv("CTI_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("CTI_NVD_ENRICH", "1")
    calls = []

    def fake_http(url, timeout=15, headers=()):
        calls.append(url)
        return _nvd_response()
    monkeypatch.setattr(cve_match, "_http_get_json", fake_http)
    monkeypatch.setattr(cve_match.time, "sleep", lambda s: None)
    _patch_scan(monkeypatch, tmp_path,
                {"app.example.com": {"url": "https://app.example.com", "code": "200",
                                     "server": "nginx/1.18.0",
                                     "versions": [{"product": "nginx",
                                                   "version": "1.18.0"}]}},
                {"app.example.com": ["5.6.7.8"]})

    result = scanner.generate_org(dict(ORG), mode="fast")
    assert "error" not in result
    assert len(calls) == 1                       # one CVE matched -> one lookup
    d = json.loads((org_dir / "findings.json").read_text())
    f = next(x for x in d["findings"] if x.get("source") == "scan-cve")
    m = f["evidence"]["matched"][0]
    assert m["cve"] == "CVE-2021-23017"
    assert m["nvd"]["cvss"] == 7.7
    assert m["nvd"]["vector"].startswith("CVSS:3.1")

    # second scan: disk cache answers, no further network call
    scanner.generate_org(dict(ORG), mode="fast")
    assert len(calls) == 1


def test_nvd_enrichment_fails_open(tmp_path, monkeypatch):
    org_dir = tmp_path / "orgs" / "sample"
    org_dir.mkdir(parents=True)
    (org_dir / "findings.json").write_text(json.dumps({"findings": []}))
    monkeypatch.setenv("CTI_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("CTI_NVD_ENRICH", "1")
    monkeypatch.setattr(cve_match, "_http_get_json", lambda *a, **k: {})
    monkeypatch.setattr(cve_match.time, "sleep", lambda s: None)
    _patch_scan(monkeypatch, tmp_path,
                {"app.example.com": {"url": "https://app.example.com", "code": "200",
                                     "server": "nginx/1.18.0",
                                     "versions": [{"product": "nginx",
                                                   "version": "1.18.0"}]}},
                {"app.example.com": ["5.6.7.8"]})

    result = scanner.generate_org(dict(ORG), mode="fast")
    assert "error" not in result                 # scan never fails on NVD errors
    d = json.loads((org_dir / "findings.json").read_text())
    f = next(x for x in d["findings"] if x.get("source") == "scan-cve")
    assert f["evidence"]["matched"][0]["cve"] == "CVE-2021-23017"
    assert "nvd" not in f["evidence"]["matched"][0]


def test_nvd_disabled_by_default(tmp_path, monkeypatch):
    assert not cve_match.nvd_enabled()
    monkeypatch.delenv("CTI_NVD_ENRICH", raising=False)
    calls = []
    monkeypatch.setattr(cve_match, "_http_get_json",
                        lambda *a, **k: calls.append(1) or {})
    cve_match.nvd_enrich_hosts({}, cap=5)
    assert calls == []
