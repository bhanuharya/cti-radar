"""Regression tests for Stage-B AI grading (judgment-only re-severity/impact).

Detection stays deterministic: the model may only re-grade existing OPEN
findings by finding ID, clamped to +/-1 severity step of the baseline, and
findings are never mutated on provider/parse failure.
"""
import json
import os
import sys
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

import scanner  # noqa: E402
import cti_correlation as cc  # noqa: E402


FINDINGS = {"findings": [
    {"id": "F-1", "target": "a.example.com", "title": "Exposed database/service",
     "severity": "MEDIUM", "status": "OPEN", "category": "Exposed database/service",
     "description": "mysql open on 3306", "evidence": {"services": {"3306": "mysql"}},
     "last_seen": "2026-08-10"},
    {"id": "F-2", "target": "b.example.com", "title": "Reachable service (passively fingerprinted)",
     "severity": "INFO", "status": "OPEN", "category": "Internet-facing service",
     "description": "public site", "evidence": {"code": "200"},
     "last_seen": "2026-08-10"},
    {"id": "F-3", "target": "c.example.com", "title": "Mitigated thing",
     "severity": "HIGH", "status": "MITIGATED", "description": "done",
     "evidence": {}, "last_seen": "2026-08-01"},
]}


def _setup(tmp_path, monkeypatch, call_ai=None):
    fp = tmp_path / "findings.json"
    hp = tmp_path / "history.json"
    fp.write_text(json.dumps(FINDINGS))
    monkeypatch.setattr(scanner, "_history_path", lambda slug: str(hp))
    monkeypatch.setattr(cc, "org_findings_path", lambda org: str(fp))
    monkeypatch.setattr(cc, "_org_lock", lambda slug: threading.Lock())
    monkeypatch.setattr(cc, "load_data", lambda slug: (FINDINGS["findings"], []))
    monkeypatch.setattr(scanner.ai_providers, "resolve_profile_for_org",
                        lambda slug, override=None: "test")
    monkeypatch.setattr(scanner.ai_providers, "load_profiles",
                        lambda: ({"test": {"max_hosts": 10}}, "test"))
    if call_ai is not None:
        monkeypatch.setattr(scanner.ai_providers, "call_ai", call_ai)
    return fp, hp


def test_select_grading_candidates_skips_non_open_and_caps(monkeypatch):
    monkeypatch.setattr(cc, "load_data", lambda slug: (FINDINGS["findings"], []))
    picks = scanner._select_grading_candidates("sample")
    # MITIGATED finding excluded, capped at default max
    ids = [c["id"] for c in picks]
    assert "F-3" not in ids
    assert set(ids) == {"F-1", "F-2"}
    assert all(c["severity"] in ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL") for c in picks)


def test_parse_ai_grading_whitelist_and_shapes():
    raw = json.dumps({"results": [
        {"id": "F-1", "severity": "high", "impact": "Direct DB exposure"},
        {"id": "F-9", "severity": "CRITICAL", "impact": "invented id"},
        {"id": "F-2", "severity": "NOT-A-SEVERITY", "impact": "bad"},
        {"id": "F-2", "severity": "LOW", "impact": "ok"},
    ]})
    out = scanner.parse_ai_grading(raw, {"F-1", "F-2"})
    assert out is not None
    assert set(out) == {"F-1", "F-2"}
    assert out["F-1"]["severity"] == "HIGH"
    assert out["F-2"]["severity"] == "LOW"
    assert scanner.parse_ai_grading("not json at all", {"F-1"}) is None
    assert scanner.parse_ai_grading("", {"F-1"}) is None


def test_ai_grade_org_applies_and_clamps(tmp_path, monkeypatch):
    def fake(prompt, profile_name=None):
        return (json.dumps({"results": [
            {"id": "F-1", "severity": "HIGH", "impact": "Direct database exposure"},
            {"id": "F-2", "severity": "CRITICAL", "impact": "wild swing"}]}),
                {"model": "test", "profile": "test"})

    fp, hp = _setup(tmp_path, monkeypatch, call_ai=fake)
    result = scanner.ai_grade_org("sample")
    assert result == "done"
    d = json.loads(fp.read_text())
    f1 = next(f for f in d["findings"] if f["id"] == "F-1")
    f2 = next(f for f in d["findings"] if f["id"] == "F-2")
    # +1 step applied with provenance + impact
    assert f1["severity"] == "HIGH"
    assert f1["ai_grading"]["severity_baseline"] == "MEDIUM"
    assert f1["ai_impact"] == "Direct database exposure"
    assert any(str(e.get("note", "")).startswith("AI-GRADED") for e in f1["status_history"])
    # INFO->CRITICAL is 3 steps -> dropped, finding untouched
    assert f2["severity"] == "INFO"
    assert "ai_grading" not in f2
    # history event recorded
    hist = json.loads(hp.read_text())
    assert any(e["kind"] == "ai_grade" and e["summary"].get("graded") == 1
               and e["summary"].get("clamped") == 1 for e in hist)


def test_ai_grade_org_no_ratchet_on_regrade(tmp_path, monkeypatch):
    """Repeated grading must clamp vs the stored deterministic baseline, not the
    AI-adjusted current severity (MEDIUM->HIGH then HIGH->CRITICAL would otherwise
    ratchet around the +/-1 guard)."""
    state = {"n": 0}

    def fake(prompt, profile_name=None):
        state["n"] += 1
        sev = "HIGH" if state["n"] == 1 else "CRITICAL"
        return (json.dumps({"results": [
            {"id": "F-1", "severity": sev, "impact": "attempt %d" % state["n"]}]}),
                {"model": "test", "profile": "test"})

    fp, hp = _setup(tmp_path, monkeypatch, call_ai=fake)
    assert scanner.ai_grade_org("sample") == "done"   # MEDIUM -> HIGH applied
    # second pass: F-1 now has ai_grading, CRITICAL is 2 steps from MEDIUM -> dropped
    assert scanner.ai_grade_org("sample") == "done"
    d = json.loads(fp.read_text())
    f1 = next(f for f in d["findings"] if f["id"] == "F-1")
    assert f1["severity"] == "HIGH"          # unchanged — no ratchet
    assert f1["ai_grading"]["severity_baseline"] == "MEDIUM"
    assert f1["ai_impact"] == "attempt 1"    # grade not re-applied


def test_parse_ai_grading_ignores_prompt_schema_echo():
    # a model echoing the documented schema (with the literal placeholder shape)
    # must not be parsed as a result
    echo = ('The schema is {"results":[{"id":"<finding id>",'
            '"severity":"INFO|LOW|MEDIUM|HIGH|CRITICAL","impact":"<one sentence>"}]} '
            "so please use that.")
    assert scanner.parse_ai_grading(echo, {"F-1"}) is None


def test_ai_grade_org_failure_leaves_findings_untouched(tmp_path, monkeypatch):
    calls = []

    def fake(prompt, profile_name=None):
        calls.append(prompt)
        return "this is not json", {"model": "test"}

    fp, hp = _setup(tmp_path, monkeypatch, call_ai=fake)
    before = fp.read_text()
    result = scanner.ai_grade_org("sample")
    assert result == "failed"
    assert len(calls) == 2  # one self-repair retry
    assert fp.read_text() == before  # findings byte-identical
    hist = json.loads(hp.read_text())
    assert any(e["kind"] == "ai_grade" and "failed" in e["note"].lower() for e in hist)


def test_ai_grade_org_skips_without_open_findings(tmp_path, monkeypatch):
    called = []

    def fake(prompt, profile_name=None):
        called.append(prompt)
        return "{}", {"model": "test"}

    _setup(tmp_path, monkeypatch, call_ai=fake)
    monkeypatch.setattr(cc, "load_data",
                        lambda slug: ([{"id": "F-3", "status": "MITIGATED"}], []))
    result = scanner.ai_grade_org("sample")
    assert result == "skipped"
    assert not called  # provider never called


def _setup_api(tmp_path, monkeypatch, call_ai=None):
    """Full-app smoke setup: isolated data dirs + registered org + test client."""
    os.environ.setdefault("CTI_SCAN_TOKEN", "test-tok")
    os.environ.setdefault("CTI_USER", "testuser")
    os.environ.setdefault("CTI_PASSWORD", "testpass")
    org_root = tmp_path / "data" / "orgs"
    od = org_root / "sample"
    od.mkdir(parents=True, exist_ok=True)
    (od / "findings.json").write_text(json.dumps(FINDINGS))
    (od / "history.json").write_text("[]")
    (od / "baseline.txt").write_text("a.example.com\n")
    reg = {"sample": {"name": "sample", "domains": ["example.com"],
                      "findings": "data/orgs/sample/findings.json",
                      "baseline": "data/orgs/sample/baseline.txt"}}
    orgs_json = tmp_path / "data" / "orgs.json"
    orgs_json.write_text(json.dumps(reg))
    tp = str(tmp_path)
    monkeypatch.setattr("main.ORGS_JSON", str(orgs_json))
    monkeypatch.setattr("main.DATA_ORG_DIR", str(org_root))
    monkeypatch.setattr("cti_correlation._REGISTRY_FILE", str(orgs_json))
    monkeypatch.setattr("cti_correlation.DATA_ROOT", str(tmp_path / "data"))
    monkeypatch.setattr("cti_correlation.BASE", tp)
    monkeypatch.setattr("cti_correlation.ORG_ROOT", str(org_root))
    monkeypatch.setattr("scanner.DATA_ROOT", str(tmp_path / "data"))
    monkeypatch.setattr("scanner.BASE", tp)
    monkeypatch.setattr("scanner.ORG_ROOT", str(org_root))
    import cti_correlation as _cc
    _cc._reload_registry()
    import main
    if call_ai is not None:
        monkeypatch.setattr(main.scanner.ai_providers, "call_ai", call_ai)
        monkeypatch.setattr(main.scanner.ai_providers, "resolve_profile_for_org",
                            lambda slug, override=None: "test")
        monkeypatch.setattr(main.scanner.ai_providers, "load_profiles",
                            lambda: ({"test": {"max_hosts": 10}}, "test"))
    else:
        monkeypatch.setattr(main.scanner.ai_providers, "resolve_profile_for_org",
                            lambda slug, override=None: "nop")
        monkeypatch.setattr(main.scanner.ai_providers, "load_profiles",
                            lambda: ({}, None))
    from fastapi.testclient import TestClient
    return TestClient(main.app), od


def test_ai_grade_endpoint_queued_and_applies(tmp_path, monkeypatch):
    def fake(prompt, profile_name=None):
        return (json.dumps({"results": [
            {"id": "F-1", "severity": "HIGH", "impact": "DB exposed"}]}),
                {"model": "test", "profile": "test"})

    client, od = _setup_api(tmp_path, monkeypatch, call_ai=fake)
    auth = {"X-CTI-Token": os.environ["CTI_SCAN_TOKEN"]}
    # unauthenticated -> 401
    assert client.post("/api/orgs/sample/ai-grade", json={}).status_code == 401
    r = client.post("/api/orgs/sample/ai-grade", headers=auth, json={})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["queued"] is True and body["job_id"]
    # let the executor finish (small bounded work)
    import time as _time
    for _ in range(50):
        s = client.get("/api/orgs/sample/ai-grade/" + body["job_id"], headers=auth).json()
        if s.get("status") in ("done", "failed"):
            break
        _time.sleep(0.1)
    assert s.get("status") == "done", s
    d = json.loads((od / "findings.json").read_text())
    f1 = next(f for f in d["findings"] if f["id"] == "F-1")
    assert f1["severity"] == "HIGH"
    assert f1["ai_grading"]["severity_baseline"] == "MEDIUM"
    import main as _main
    _main._jobs.clear()
