"""Slice 4 regression tests: correlation engine canonical semantics.

- IP co-residency seeds from CONFIRMED sources recognized through the
  canonical lifecycle view (status OR status_detail/tier text), so migrated
  legacy records still qualify and correlated/AI sources never seed;
- correlated findings are born canonical: status OPEN, descriptive CORRELATED
  text in status_detail, full lifecycle fields + correlate history entry,
  stable identity assigned at merge.
"""
import json
import os
import sys
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

import cti_correlation as cc  # noqa: E402
import scanner  # noqa: E402


def _correlate_env(monkeypatch, tmp_path, findings, baseline):
    od = tmp_path / "orgs" / "sample"
    od.mkdir(parents=True)
    fp = od / "findings.json"
    fp.write_text(json.dumps({"meta": {}, "findings": findings}))
    hp = tmp_path / "history.json"
    monkeypatch.setattr(cc, "org_findings_path", lambda s: str(fp))
    monkeypatch.setattr(cc, "_org_lock", lambda s: threading.Lock())
    monkeypatch.setattr(cc, "load_data", lambda s: ([json.loads(json.dumps(f)) for f in findings], list(baseline)))
    monkeypatch.setattr(scanner, "_resolve",
                        lambda h: ["7.7.7.7"] if h.startswith("b.") else [])
    monkeypatch.setattr(scanner, "_internetdb", lambda ip: {})
    monkeypatch.setattr(scanner, "_history_path", lambda slug: str(hp))
    return fp


BASELINE = ["a.example.com", "b.example.com"]

MIGRATED_CONFIRMED = {
    "id": "F1", "target": "a.example.com", "ip": "7.7.7.7",
    "title": "Legacy confirmed finding", "severity": "HIGH",
    # migrated shape: descriptive CONFIRMED text moved out of `status`
    "status": "OPEN", "status_detail": "VERSION-CONFIRMED (manual)",
    "source": "scan-surface", "related_cves": [], "evidence": {},
}


def test_coresidency_from_migrated_confirmed_and_canonical_birth(monkeypatch, tmp_path):
    fp = _correlate_env(monkeypatch, tmp_path, [MIGRATED_CONFIRMED], BASELINE)
    res = scanner.correlate_org({"slug": "sample", "domains": ["example.com"]})
    assert "error" not in res
    d = json.loads(fp.read_text())
    core = [f for f in d["findings"] if f.get("source") == "ip-co-residency"]
    assert len(core) == 1, [f["id"] for f in d["findings"]]
    rec = core[0]
    assert rec["target"] == "b.example.com"
    assert rec["status"] == "OPEN"                      # canonical at birth
    assert rec["status_detail"].startswith("CORRELATED")
    assert rec["first_seen"] and rec["last_seen"] and rec["found_date"]
    assert any(e.get("by") == "correlate" for e in rec["status_history"])
    assert rec.get("identity_key", "").startswith("corr|ip-co-residency|")


def test_ai_source_never_seeds_coresidency(monkeypatch, tmp_path):
    ai_src = dict(MIGRATED_CONFIRMED, id="AI-9", source="ai-assess")
    fp = _correlate_env(monkeypatch, tmp_path, [ai_src], BASELINE)
    res = scanner.correlate_org({"slug": "sample", "domains": ["example.com"]})
    assert "error" not in res
    d = json.loads(fp.read_text())
    assert not [f for f in d["findings"] if f.get("source") == "ip-co-residency"]


def test_cve_share_born_canonical(monkeypatch, tmp_path):
    src = {"id": "V1", "target": "a.example.com", "ip": "7.7.7.7",
           "title": "vuln", "severity": "CRITICAL", "status": "OPEN",
           "source": "scan-surface", "evidence": {},
           "related_cves": ["CVE-2025-9999"]}
    fp = _correlate_env(monkeypatch, tmp_path, [src], BASELINE)
    # InternetDB reports the same CVE for the shared IP -> b inherits it,
    # giving rule 1 a second host that shares a known CVE
    monkeypatch.setattr(scanner, "_internetdb",
                        lambda ip: {"vulns": ["CVE-2025-9999"], "ports": [443]}
                        if ip == "7.7.7.7" else {})
    res = scanner.correlate_org({"slug": "sample", "domains": ["example.com"]})
    assert "error" not in res
    d = json.loads(fp.read_text())
    cve = [f for f in d["findings"] if f.get("source") == "cve-share"]
    assert len(cve) == 1
    rec = cve[0]
    assert rec["target"] == "b.example.com"
    assert rec["status"] == "OPEN"
    assert rec["first_seen"] == rec["last_seen"]
    assert rec.get("identity_key") == "corr|cve-share|b.example.com|CVE-2025-9999"
