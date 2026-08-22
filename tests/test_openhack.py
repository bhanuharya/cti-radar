"""Slice 2.5 regression tests: OpenHack ingestion source.

Covers mapper trust rules (validated vs candidate severity cap), URL-based
identity stability, the fake-binary runner e2e, per-family streak lifecycle
(add -> refresh -> miss -> auto-resolve -> recurrence reopen), per-kind
stale-job deadline extension, and endpoint auth/opt-in gating.
"""
import json
import os
import stat
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

os.environ.setdefault("CTI_SCAN_TOKEN", "test-tok")
os.environ.setdefault("CTI_USER", "testuser")
os.environ.setdefault("CTI_PASSWORD", "testpass")

import cti_correlation as cc  # noqa: E402
import openhack_source as oh  # noqa: E402


VALIDATED = {
    "title": "SQL injection in login",
    "description": "Unsanitized input reaches query builder",
    "category": "sql-injection",
    "severity": "critical",
    "cvssScore": 9.8,
    "validated": True,
    "verificationSource": "sandbox",
    "filePath": "https://api.example.com/login?id=1",
    "lineNumber": None,
    "relevantCode": "SELECT * FROM users WHERE id=" + "x" * 5000,
    "poc": "curl 'https://api.example.com/login?id=1%27--",
    "recommendation": "Use parameterized queries.",
}

CANDIDATE = {
    "title": "Possible reflected XSS",
    "category": "xss",
    "severity": "CRITICAL",          # must be capped: not verified
    "cvssScore": 9.1,
    "validated": False,
    "filePath": "https://www.example.com/search?q=x/",
}

REPORT = {"target_dir": "/scratch", "status": "completed",
          "findings": [VALIDATED, CANDIDATE]}


def test_mapper_trust_rules_and_identity():
    out = oh.map_report_findings("sample", REPORT, ["example.com"])
    assert len(out) == 2
    ver = next(f for f in out if f["status_detail"] == "OHACK-VERIFIED")
    cand = next(f for f in out if f["status_detail"] == "OHACK-CANDIDATE")
    # verified: full severity from CVSS band
    assert ver["severity"] == "CRITICAL" and ver["provenance"]["confidence"] == "verified"
    assert ver["identity_key"] == "ohack|api.example.com|/login|sql-injection"
    assert len(ver["evidence"]["relevant_code"]) <= 2048
    assert any(p.startswith("poc:") for p in ver["proof_chain"])
    # unvalidated candidate capped at HIGH regardless of reported/CVSS
    assert cand["severity"] == "HIGH"
    assert cand["identity_key"] == "ohack|www.example.com|/search|xss"


def test_mapper_rejects_non_url_path():
    rep = {"findings": [{**VALIDATED, "filePath": "src/app/db.py"}]}
    out = oh.map_report_findings("sample", rep, ["example.com"])
    assert out == []


def test_mapper_rejects_out_of_scope_and_unsafe_urls():
    bad = [
        "https://evil-example.com/a",
        "https://example.com.evil.test/a",
        "https://user:pass@api.example.com/a",
        "https://203.0.113.10/a",
        "file:///etc/passwd",
    ]
    for value in bad:
        rep = {"findings": [{**VALIDATED, "filePath": value}]}
        assert oh.map_report_findings("sample", rep, ["example.com"]) == []
    good = {"findings": [{**VALIDATED, "filePath": "https://api.example.com/a"}]}
    assert len(oh.map_report_findings("sample", good, ["example.com"])) == 1


def test_runner_e2e_with_fake_binary(monkeypatch, tmp_path):
    scans = tmp_path / "scans"
    scans.mkdir()
    fake_bin = tmp_path / "fake-openhack.sh"
    fake_bin.write_text(
        "#!/usr/bin/env bash\n"
        'scratch="$3"\n'   # argv: --hack <objective> <scratch>
        'export CTI_OPENHACK_SCANS_DIR="%s"\n'
        'python3 -c \'import json,sys,os,time; d={"target_dir":sys.argv[1],'
        '"findings":[{"title":"T","category":"c","severity":"HIGH","cvssScore":7.5,'
        '"validated":True,"filePath":"https://h.example.com/"}]};'
        'open(os.path.join(os.environ["CTI_OPENHACK_SCANS_DIR"],'
        'str(time.time())+".json"),"w").write(json.dumps(d))\' "$scratch"\n'
        % scans)
    os.chmod(fake_bin, os.stat(fake_bin).st_mode | stat.S_IEXEC)
    monkeypatch.setenv("CTI_OPENHACK_BIN", str(fake_bin))
    monkeypatch.setenv("CTI_OPENHACK_SCANS_DIR", str(scans))

    od = tmp_path / "orgs" / "sample"
    od.mkdir(parents=True)
    (od / "findings.json").write_text(json.dumps({"findings": []}))
    monkeypatch.setattr(cc, "org_findings_path", lambda s: str(od / "findings.json"))
    monkeypatch.setattr(cc, "_org_lock", lambda s: __import__("threading").Lock())

    scratch = tmp_path / "scratch"
    res = oh.run_and_ingest("sample", ["example.com"])
    assert res["status"] == "done", res
    assert res["added"] == 1
    d = json.loads((od / "findings.json").read_text())
    oh_f = [f for f in d["findings"] if f.get("source") == "openhack"]
    assert len(oh_f) == 1
    assert oh_f[0]["identity_key"] == "ohack|h.example.com|/|c"


def _ingest_env(monkeypatch, tmp_path):
    od = tmp_path / "orgs" / "sample"
    od.mkdir(parents=True)
    fp = od / "findings.json"
    fp.write_text(json.dumps({"findings": []}))
    monkeypatch.setattr(cc, "org_findings_path", lambda s: str(fp))
    import threading
    monkeypatch.setattr(cc, "_org_lock", lambda s: threading.Lock())
    return fp


FULL = {"findings": [dict(VALIDATED)]}
EMPTY = {"findings": []}


def test_streak_lifecycle_resolve_then_recur(monkeypatch, tmp_path):
    fp = _ingest_env(monkeypatch, tmp_path)
    s1 = oh.ingest_report("sample", FULL)
    assert s1["added"] == 1 and s1["error" if False else "updated"] == 0
    # still present: refreshed, no dup
    s2 = oh.ingest_report("sample", FULL)
    assert s2["added"] == 0 and s2["updated"] == 1
    # three consecutive absences -> auto-resolve (LOW/INFO/MEDIUM only;
    # this finding is CRITICAL+verified so it must be PROPOSE-only instead)
    r3 = oh.ingest_report("sample", EMPTY)
    r4 = oh.ingest_report("sample", EMPTY)
    r5 = oh.ingest_report("sample", EMPTY)
    d = json.loads(fp.read_text())
    f = d["findings"][0]
    assert f["missing_streak"] == 3
    assert f["status"] == "OPEN", "verified CRITICAL must be propose-only"
    assert r5["proposed"] == 1
    # downgrade scenario: LOW candidate resolves after 3 misses
    low_rep = {"findings": [dict(CANDIDATE,
                                 title="Low thing", category="info",
                                 severity="LOW", cvssScore=1.0,
                                 validated=False,
                                 filePath="https://low.example.com/x")]}

    def _norm(rep):
        return {"findings": [dict(x) for x in rep["findings"]]}

    oh.ingest_report("sample", FULL)          # re-present critical (reopen n/a)
    oh.ingest_report("sample", _norm(low_rep))
    oh.ingest_report("sample", EMPTY)
    oh.ingest_report("sample", EMPTY)
    oh.ingest_report("sample", EMPTY)
    d = json.loads(fp.read_text())
    lowf = next(f for f in d["findings"]
                if f["identity_key"] == "ohack|low.example.com|/x|info")
    assert lowf["status"] == "RESOLVED"
    # recurrence: full report containing LOW again reopens it
    low_back = {"findings": [_norm(low_rep)["findings"][0]]}
    oh.ingest_report("sample", low_back)
    d = json.loads(fp.read_text())
    lowf = next(f for f in d["findings"]
                if f["identity_key"] == "ohack|low.example.com|/x|info")
    assert lowf["status"] == "OPEN"
    assert any(e.get("by") == "openhack" and "recurrence" in e.get("note", "")
               for e in lowf["status_history"])


def test_surface_scans_never_touch_ohack_streaks(monkeypatch):
    import scanner
    fs = [{"id": "OH-x", "source": "openhack",
           "identity_key": "ohack|h.example.com|/|c",
           "severity": "LOW", "status": "OPEN", "positive": False,
           "evidence": {}}]
    counts = scanner._reconcile_findings(fs, {}, {}, [], {})
    # explicit contract: reconcile SKIPS the ohack family entirely —
    # no streak bookkeeping, no missing count, no status mutation
    assert fs[0].get("missing_streak") is None
    assert fs[0]["status"] == "OPEN"
    assert counts["missing"] == 0 and counts["observed"] == 0


# ------------------------------------------------------------- endpoints --

def _client(monkeypatch, tmp_path, enabled=False):
    from fastapi.testclient import TestClient
    import main as m
    org_root = tmp_path / "data" / "orgs"
    org_root.mkdir(parents=True, exist_ok=True)
    reg = {"sample": {"name": "sample", "domains": ["example.com"],
                      "findings": "d", "baseline": "b"}}
    if enabled:
        reg["sample"]["openhack_enabled"] = True
        # Active-assessment endpoint tests opt into the server gate explicitly.
        monkeypatch.setenv("CTI_OPENHACK_ACTIVE", "1")
        monkeypatch.setenv("CTI_OPENHACK_ISOLATED", "1")
        monkeypatch.setenv("CTI_OPENHACK_ALLOWED_DOMAINS", "example.com")
        monkeypatch.setenv("CTI_OPENHACK_BIN", "/bin/true")
        monkeypatch.setenv("CTI_OPENHACK_ROE_EXPIRES", "2999-01-01T00:00:00Z")
    (tmp_path / "data" / "orgs.json").write_text(json.dumps(reg))
    od = org_root / "sample"
    od.mkdir(exist_ok=True)
    (od / "findings.json").write_text(json.dumps({"findings": []}))
    monkeypatch.setattr(m, "ORGS_JSON", str(tmp_path / "data" / "orgs.json"))
    monkeypatch.setattr(m, "DATA_ORG_DIR", str(org_root))
    monkeypatch.setattr(m.cc, "_REGISTRY_FILE", str(tmp_path / "data" / "orgs.json"))
    # hermetic registry view: org_get serves ONLY the tmp registry; the
    # config endpoint's reload becomes a no-op so global cache stays intact
    monkeypatch.setattr(m.cc, "org_get",
                        lambda s: json.loads(json.dumps(reg[s])) if s in reg else None)
    monkeypatch.setattr(m.cc, "_reload_registry", lambda: None)
    m._jobs.clear()
    client = TestClient(m.app)
    H = {"X-CTI-Token": "test-tok"}
    return m, client, H


def test_endpoint_auth_and_optin_gate(monkeypatch, tmp_path):
    m, client, H = _client(monkeypatch, tmp_path, enabled=False)
    assert client.post("/api/orgs/sample/openhack-scan").status_code == 401
    r = client.post("/api/orgs/sample/openhack-scan", headers=H)
    assert r.status_code == 403 and "not enabled" in r.json()["error"]

    # opt-in writes the registry flag
    r = client.post("/api/orgs/sample/openhack-config", headers=H,
                    json={"enabled": True})
    assert r.status_code == 200 and r.json()["openhack_enabled"] is True
    reg = json.loads((tmp_path / "data" / "orgs.json").read_text())
    assert reg["sample"]["openhack_enabled"] is True

    # disabled again removes the flag
    client.post("/api/orgs/sample/openhack-config", headers=H,
                json={"enabled": False})
    reg = json.loads((tmp_path / "data" / "orgs.json").read_text())
    assert "openhack_enabled" not in reg["sample"]


def test_active_gate_denies_disabled_and_missing_allowlist(monkeypatch, tmp_path):
    m, client, H = _client(monkeypatch, tmp_path, enabled=True)
    monkeypatch.delenv("CTI_OPENHACK_ACTIVE")
    assert client.post("/api/orgs/sample/openhack-scan", headers=H).status_code == 403
    monkeypatch.setenv("CTI_OPENHACK_ACTIVE", "1")
    monkeypatch.setenv("CTI_OPENHACK_ISOLATED", "1")
    monkeypatch.delenv("CTI_OPENHACK_ALLOWED_DOMAINS")
    r = client.post("/api/orgs/sample/openhack-scan", headers=H)
    assert r.status_code == 403 and "allow" in r.json()["error"].lower()


def test_active_gate_scope_expiry_and_valid_authorization(monkeypatch, tmp_path):
    m, client, H = _client(monkeypatch, tmp_path, enabled=True)
    monkeypatch.setattr(oh, "openhack_bin", lambda: "/bin/true")
    monkeypatch.setattr(oh, "run_and_ingest", lambda *a, **k: {"status": "done"})
    for expiry in ("not-a-time", "2030-01-01T00:00:00", "2000-01-01T00:00:00Z"):
        monkeypatch.setenv("CTI_OPENHACK_ROE_EXPIRES", expiry)
        assert client.post("/api/orgs/sample/openhack-scan", headers=H).status_code == 403
    monkeypatch.setenv("CTI_OPENHACK_ROE_EXPIRES", "2999-01-01T00:00:00Z")
    monkeypatch.setenv("CTI_OPENHACK_ALLOWED_DOMAINS", "other.example")
    assert client.post("/api/orgs/sample/openhack-scan", headers=H).status_code == 403
    monkeypatch.setenv("CTI_OPENHACK_ALLOWED_DOMAINS", "EXAMPLE.COM.")
    r = client.post("/api/orgs/sample/openhack-scan", headers=H)
    assert r.status_code == 200 and r.json()["queued"] is True


def test_endpoint_missing_binary_503(monkeypatch, tmp_path):
    m, client, H = _client(monkeypatch, tmp_path, enabled=True)
    monkeypatch.setattr(oh, "openhack_bin", lambda: None)
    r = client.post("/api/orgs/sample/openhack-scan", headers=H)
    assert r.status_code == 503


def test_endpoint_queued_and_status(monkeypatch, tmp_path):
    m, client, H = _client(monkeypatch, tmp_path, enabled=True)
    monkeypatch.setattr(oh, "openhack_bin", lambda: "/bin/true")

    def fake_run(slug, domains, on_progress=None, mode="deep", model=None):
        return {"status": "done", "added": 0, "updated": 0, "resolved": 0,
                "reopened": 0, "proposed": 0, "missed": 0, "graded": 0, "clamped": 0}
    monkeypatch.setattr(oh, "run_and_ingest", fake_run)
    r = client.post("/api/orgs/sample/openhack-scan", headers=H)
    assert r.status_code == 200 and r.json()["queued"] is True
    jid = r.json()["job_id"]
    dead = time.time() + 5
    st = None
    while time.time() < dead:
        sr = client.get(f"/api/orgs/sample/openhack-scan/{jid}", headers=H)
        if sr.status_code == 200:
            st = sr.json().get("status")
            if st in ("done", "failed"):
                break
        time.sleep(0.05)
    assert st == "done"

    # while-running duplicate gets 409
    slow_started = {}

    def slow_run(slug, domains, on_progress=None, mode="deep", model=None):
        slow_started["t"] = True
        time.sleep(0.6)
        return {"status": "done", "added": 0, "updated": 0, "resolved": 0,
                "reopened": 0, "proposed": 0, "missed": 0}
    monkeypatch.setattr(oh, "run_and_ingest", slow_run)
    r1 = client.post("/api/orgs/sample/openhack-scan", headers=H)
    assert r1.status_code == 200
    r2 = client.post("/api/orgs/sample/openhack-scan", headers=H)
    assert r2.status_code == 409
    time.sleep(0.9)


def test_ohack_kind_gets_extended_stale_deadline():
    import main as m
    m._jobs.clear()
    original_default = m._JOB_STALE_SECS
    try:
        ok, jid = m._try_acquire_job("slowoh", "ohack", stale_after=99999)
        assert ok
        key = m._job_key("slowoh", "ohack")
        with m._jobs_lock:
            m._jobs[key]["started"] -= 2000   # far past the 1800s default
        ok2, jid2 = m._try_acquire_job("slowoh", "scan")
        assert not ok2, "extended-deadline job was reclaimed too early"
    finally:
        m._JOB_STALE_SECS = original_default
        m._jobs.clear()
