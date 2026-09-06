"""Tests for the nuclei provider: parser, scope, severity cap, argv safety."""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

import nuclei_scan as nuc  # noqa: E402

DOMAINS = ["example.com"]


@pytest.fixture(autouse=True)
def _restore_registry():
    import cti_correlation as _cc
    snap = dict(_cc.REGISTRY)
    yield
    _cc.REGISTRY.clear()
    _cc.REGISTRY.update(snap)


def _event(**kw):
    base = {"template-id": "CVE-2021-41733",
            "matched-at": "https://app.example.com/cgi-bin/.%2e/%2e%2e/etc/passwd",
            "matcher-name": "path",
            "info": {"name": "Apache Path Traversal", "severity": "critical",
                     "tags": ["cve", "apache"],
                     "classification": {"cve-id": ["CVE-2021-41733"]},
                     "reference": ["https://example.com/ref"]}}
    base.update(kw)
    return base


def test_map_event_ok_and_capped_severity():
    rec = nuc.map_event("acme", _event(), DOMAINS)
    assert rec is not None
    assert rec["severity"] == "HIGH"  # critical capped by policy
    assert rec["source"] == "nuclei"
    assert rec["related_cves"] == ["CVE-2021-41733"]
    assert rec["identity_key"] == "nuclei|app.example.com|cve-2021-41733|/cgi-bin/.%2e/%2e%2e/etc/passwd"
    assert rec["status_detail"].startswith("NUCLEI-MATCHED")


def test_map_event_drops_out_of_scope():
    assert nuc.map_event("acme", _event(**{"matched-at": "https://evil.com/x"}), DOMAINS) is None
    assert nuc.map_event("acme", _event(**{"matched-at": "http://1.2.3.4/x"}), DOMAINS) is None
    assert nuc.map_event("acme", _event(**{"matched-at": "ftp://app.example.com/x"}), DOMAINS) is None
    assert nuc.map_event("acme", _event(**{"template-id": "bad id!!"}), DOMAINS) is None
    assert nuc.map_event("acme", "not-a-dict", DOMAINS) is None


def test_map_event_invalid_cve_filtered():
    ev = _event()
    ev["info"] = dict(ev["info"])
    ev["info"]["classification"] = {"cve-id": ["CVE-99", "CVE-2021-41733"]}
    rec = nuc.map_event("acme", ev, DOMAINS)
    assert rec["related_cves"] == ["CVE-2021-41733"]


def test_severity_map_covers_all():
    for raw, want in (("critical", "HIGH"), ("high", "HIGH"), ("medium", "MEDIUM"),
                      ("low", "LOW"), ("info", "INFO"), ("unknown", "INFO"), ("bogus", "INFO")):
        rec = nuc.map_event("acme", _event(info={"name": "T", "severity": raw}), DOMAINS)
        assert rec["severity"] == want, raw


def test_parse_output_file_bounds_and_skips_bad(tmp_path):
    p = tmp_path / "out.jsonl"
    lines = [json.dumps(_event()),
             json.dumps(_event(**{"matched-at": "https://evil.com/"})),
             "not json at all",
             json.dumps(_event(**{"template-id": "xss", "matched-at": "https://sub.example.com/a",
                                  "info": {"name": "X", "severity": "low"}}))]
    p.write_text("\n".join(lines) + "\n")
    recs = nuc.parse_output_file(str(p), "acme", DOMAINS)
    assert len(recs) == 2
    assert {r["target"] for r in recs} == {"app.example.com", "sub.example.com"}


def test_normalize_options_rejects_garbage():
    sev, tags, err = nuc.normalize_options(["critical", "bogus!"], None)
    assert err == "" and sev == ["critical"]
    sev, tags, err = nuc.normalize_options(["bogus"], None)
    assert err  # nothing valid left
    sev, tags, err = nuc.normalize_options(None, ["cve", "bad tag!!"])
    assert err


def test_exclude_tags_always_force_dos_fuzz(monkeypatch):
    monkeypatch.setenv("CTI_NUCLEI_EXCLUDE_TAGS", "intrusive")
    assert "dos" in nuc.exclude_tags() and "fuzz" in nuc.exclude_tags()
    monkeypatch.setenv("CTI_NUCLEI_EXCLUDE_TAGS", "")
    assert "dos" in nuc.exclude_tags() and "fuzz" in nuc.exclude_tags()


def test_build_argv_no_shell_no_raw(monkeypatch, tmp_path):
    monkeypatch.setenv("CTI_NUCLEI_BIN", "/bin/false")
    monkeypatch.setenv("CTI_NUCLEI_TEMPLATES", str(tmp_path))
    argv = nuc.build_argv("t.txt", "o.jsonl", ["high"], [])
    assert isinstance(argv, list) and all(isinstance(a, str) for a in argv)
    assert "-or" in argv and "-ni" in argv and "-duc" in argv
    assert "-store-resp" not in " ".join(argv)
    joined = " ".join(argv)
    assert "dos" in joined and "fuzz" in joined  # forced excludes present


def test_vuln_scan_rejects_bad_engine(tmp_path, monkeypatch):
    import cti_correlation as cc
    import scanner as _scanner
    import vuln_scan as vs
    d = tmp_path / "vdata"
    (d / "orgs" / "acme").mkdir(parents=True)
    monkeypatch.setattr(cc, "DATA_ROOT", str(d))
    monkeypatch.setattr(cc, "_REGISTRY_FILE", str(d / "orgs.json"))
    monkeypatch.setattr(_scanner, "DATA_ROOT", str(d))
    monkeypatch.setattr(_scanner, "ORG_ROOT", str(d / "orgs"))
    store = {"findings": [], "meta": {"fingerprints": {
        "app.example.com": {"url": "https://app.example.com", "code": "200"}}}}
    (d / "orgs" / "acme" / "findings.json").write_text(json.dumps(store))
    (d / "orgs.json").write_text(json.dumps({"acme": {"name": "A", "domains": ["example.com"],
                                                      "findings": "data/orgs/acme/findings.json",
                                                      "baseline": "data/orgs/acme/baseline.txt"}}))
    cc._reload_registry()
    r = vs.vuln_scan_org("acme", engine="bogus", refresh=False)
    assert "error" in r and "engine" in r["error"]
    # nuclei without gate -> denied, no subprocess
    r = vs.vuln_scan_org("acme", engine="nuclei", refresh=False)
    assert "error" in r and "denied" in r["error"]
