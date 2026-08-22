"""Slice 6 regression tests: OpenHack quick-pass (budgeted enrich+grade).

- graceful SIGINT runner: budget expires -> CLI persists partial report ->
  ingest grades ref-matched findings and creates candidates,
- grading authority rules: verified full range / unverified ±1 clamp,
  anchored to the FIRST grade's baseline (no ratchet),
- ref-to-unknown-id falls back to candidate creation,
- manifest sanitization + ordering + eligibility filters,
- API mode validation and per-mode stale deadline wiring.
"""
import json
import os
import stat
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

os.environ.setdefault("CTI_SCAN_TOKEN", "test-tok")
os.environ.setdefault("CTI_USER", "testuser")
os.environ.setdefault("CTI_PASSWORD", "testpass")

import cti_correlation as cc  # noqa: E402
import openhack_source as oh  # noqa: E402


def _org_env(monkeypatch, tmp_path, findings):
    od = tmp_path / "orgs" / "sample"
    od.mkdir(parents=True, exist_ok=True)
    fp = od / "findings.json"
    fp.write_text(json.dumps({"meta": {}, "findings": findings}))
    monkeypatch.setattr(cc, "org_findings_path", lambda s: str(fp))
    monkeypatch.setattr(cc, "_org_lock", lambda s: threading.Lock())
    return fp


BASE_FINDING = {
    "id": "R-1", "target": "api.example.com", "port": 443,
    "severity": "MEDIUM", "status": "OPEN", "positive": False,
    "source": "scan-surface",
    "identity_key": "surface-web|api.example.com|443",
    "evidence": {"url": "https://api.example.com", "code": "200"},
    "status_history": [],
}

QUICK_REPORT = {
    "findings": [
        {   # unverified CRITICAL proposal against MEDIUM baseline -> clamped HIGH
            "ref": "R-1",
            "title": "Login endpoint weaknesses confirmed",
            "description": "probed and enriched",
            "category": "weak-login",
            "severity": "CRITICAL",
            "cvssScore": 9.1,
            "validated": False,
            "filePath": "https://api.example.com/login",
            "relevantCode": "POST /login",
            "poc": "curl -X POST .../login -d 'x'",
        },
        {   # new discovery, no ref
            "title": "Exposed .git directory",
            "category": "source-exposure",
            "severity": "HIGH",
            "cvssScore": 7.5,
            "validated": True,
            "filePath": "https://old.example.com/.git/HEAD",
        },
    ]
}


FAKE_SIGINT_BIN = r"""#!/usr/bin/env bash
scratch="$3"
export CTI_OPENHACK_SCANS_DIR="%SCANS%"
write_report() {
python3 - "$scratch" <<'PY'
import json, sys, os, time
rep = {"target_dir": sys.argv[1], "status": "cancelled", "findings": [
  {"ref": "R-1", "title": "Login endpoint weaknesses", "category": "weak-login",
   "severity": "CRITICAL", "cvssScore": 9.1, "validated": False,
   "filePath": "https://api.example.com/login", "poc": "curl poc"},
  {"title": "Exposed .git directory", "category": "source-exposure",
   "severity": "HIGH", "cvssScore": 7.5, "validated": True,
   "filePath": "https://old.example.com/.git/HEAD"},
]}
d = os.environ["CTI_OPENHACK_SCANS_DIR"]
open(os.path.join(d, str(time.time()) + ".json"), "w").write(json.dumps(rep))
PY
exit 0
}
trap write_report INT
sleep 25 &
wait $!
"""


def test_quick_pass_sigint_graceful_e2e(monkeypatch, tmp_path):
    scans = tmp_path / "scans"
    scans.mkdir()
    fake_bin = tmp_path / "fake-openhack-slow.sh"
    fake_bin.write_text(FAKE_SIGINT_BIN.replace("%SCANS%", str(scans)))
    os.chmod(fake_bin, os.stat(fake_bin).st_mode | stat.S_IEXEC)
    monkeypatch.setenv("CTI_OPENHACK_BIN", str(fake_bin))
    monkeypatch.setenv("CTI_OPENHACK_SCANS_DIR", str(scans))
    monkeypatch.setattr(oh, "quick_budget", lambda: 2)   # tiny test budget

    fp = _org_env(monkeypatch, tmp_path, [dict(BASE_FINDING)])
    t0 = time.time()
    res = oh.run_and_ingest("sample", ["example.com"], mode="quick")
    elapsed = time.time() - t0

    assert res["status"] == "done", res
    assert res["graded"] == 1 and res["clamped"] == 1 and res["added"] == 1
    assert elapsed < 15, f"budget stop took too long: {elapsed:.1f}s"
    d = json.loads(fp.read_text())
    r1 = next(f for f in d["findings"] if f["id"] == "R-1")
    assert r1["severity"] == "HIGH"                       # clamped from CRITICAL
    g = r1["ohack_grading"]
    assert g["severity_baseline"] == "MEDIUM" and g["verified"] is False
    assert r1["evidence"]["openhack"]["cvss_score"] == 9.1
    assert r1["evidence"]["openhack"]["poc"].startswith("curl")
    assert any(e.get("by") == "openhack" and "clamped" in e.get("note", "")
               for e in r1["status_history"])
    cand = [f for f in d["findings"] if f.get("source") == "openhack"]
    assert len(cand) == 1 and cand[0]["target"] == "old.example.com"
    meta = d["meta"]["openhack_last_ingest"]
    assert meta["mode"] == "quick" and meta["graded"] == 1


def test_process_group_cleanup_kills_descendants(tmp_path):
    script = tmp_path / "spawn-child.sh"
    child_file = tmp_path / "child.pid"
    script.write_text(
        "#!/usr/bin/env bash\n"
        "trap 'exit 0' INT\n"
        "sleep 1000 &\n"
        f"echo $! > {child_file}\n"
        "wait\n")
    os.chmod(script, os.stat(script).st_mode | stat.S_IEXEC)
    proc = __import__("subprocess").Popen(
        [str(script)], start_new_session=True,
        stdout=__import__("subprocess").DEVNULL,
        stderr=__import__("subprocess").DEVNULL)
    deadline = time.time() + 3
    while not child_file.exists() and time.time() < deadline:
        time.sleep(0.02)
    child = int(child_file.read_text().strip())
    oh._terminate_process_group(proc, graceful=True, grace=0.2)
    deadline = time.time() + 3
    while os.path.exists(f"/proc/{child}") and time.time() < deadline:
        time.sleep(0.02)
    assert not os.path.exists(f"/proc/{child}")


def test_grade_clamp_rules():
    f = dict(BASE_FINDING)
    m = {"severity": "CRITICAL",
         "evidence": {"validated": False}, "proof_chain": []}
    g, c = oh._grade_and_enrich(f, m, "2026-08-22", "run1")
    assert (g, c) == (1, 1) and f["severity"] == "HIGH"

    # verified: full range allowed
    f2 = dict(BASE_FINDING)
    m_v = {"severity": "CRITICAL", "evidence": {"validated": True},
           "proof_chain": []}
    g2, c2 = oh._grade_and_enrich(f2, m_v, "2026-08-22", "run2")
    assert (g2, c2) == (1, 0) and f2["severity"] == "CRITICAL"

    # within ±1 unverified: no clamp flag
    f3 = dict(BASE_FINDING)
    m_l = {"severity": "LOW", "evidence": {"validated": False},
           "proof_chain": []}
    g3, c3 = oh._grade_and_enrich(f3, m_l, "2026-08-22", "run3")
    assert (g3, c3) == (1, 0) and f3["severity"] == "LOW"

    # anchor does NOT ratchet: baseline stays MEDIUM across passes
    f4 = dict(BASE_FINDING)
    oh._grade_and_enrich(f4, {"severity": "HIGH",
                              "evidence": {"validated": False},
                              "proof_chain": []}, "2026-08-22", "a")
    oh._grade_and_enrich(f4, {"severity": "INFO",
                              "evidence": {"validated": False},
                              "proof_chain": []}, "2026-08-22", "b")
    assert f4["ohack_grading"]["severity_baseline"] == "MEDIUM"
    assert f4["severity"] == "LOW"


def test_ref_unknown_id_falls_back_to_candidate(monkeypatch, tmp_path):
    fp = _org_env(monkeypatch, tmp_path, [dict(BASE_FINDING)])
    rep = {"findings": [{"ref": "NOPE-404", "title": "orphan",
                         "category": "misc", "severity": "HIGH",
                         "cvssScore": 7.4, "validated": False,
                         "filePath": "https://x.example.com/a"}]}
    res = oh.ingest_report("sample", rep, mode="quick")
    assert res["graded"] == 0 and res["added"] == 1
    d = json.loads(fp.read_text())
    orphan = next(f for f in d["findings"] if f["target"] == "x.example.com")
    assert "ref" not in orphan                     # never persisted on records
    assert orphan["status_detail"] == "OHACK-CANDIDATE"


def test_quick_report_does_not_age_unobserved_openhack_findings(monkeypatch, tmp_path):
    existing = {
        "id": "OH-1", "target": "old.example.com", "severity": "LOW",
        "status": "OPEN", "source": "openhack",
        "identity_key": "ohack|old.example.com|/admin|exposure",
        "missing_streak": 0, "status_history": [],
    }
    fp = _org_env(monkeypatch, tmp_path, [existing])
    oh.ingest_report("sample", {"status": "cancelled", "findings": []}, mode="quick")
    after_quick = json.loads(fp.read_text())["findings"][0]
    assert after_quick["missing_streak"] == 0
    oh.ingest_report("sample", {"status": "completed", "findings": []}, mode="deep")
    after_deep = json.loads(fp.read_text())["findings"][0]
    assert after_deep["missing_streak"] == 1


def test_manifest_sanitized_filtered_ordered(monkeypatch):
    fs = [
        {"id": "Z-9", "target": "z.example.com", "severity": "LOW",
         "status": "OPEN", "source": "scan-services", "port": 22,
         "positive": False, "evidence": {}},
        {"id": "A-1", "target": "evil\nDROP TABLE example.com",
         "severity": "CRITICAL", "status": "OPEN", "source": "scan-surface",
         "port": 443, "positive": False,
         "evidence": {"server": "nginx | x\nnew", "title": "ok"}},
        {"id": "S-1", "target": "skip.example.com", "severity": "HIGH",
         "status": "RESOLVED", "source": "scan-surface", "positive": False,
         "evidence": {}},
        {"id": "O-1", "target": "oh.example.com", "severity": "HIGH",
         "status": "OPEN", "source": "openhack", "positive": False,
         "evidence": {}},
        {"id": "P-1", "target": "pos.example.com", "severity": "HIGH",
         "status": "OPEN", "source": "scan-surface", "positive": True,
         "evidence": {}},
    ]
    orig = cc.load_data
    try:
        cc.load_data = lambda slug: (fs, [])
        lines = oh.build_manifest("sample")
    finally:
        cc.load_data = orig
    assert len(lines) == 2, lines                    # only A-1 (critical first) + Z-9
    assert lines[0].startswith("ref=A-1 ")
    # sanitizer neutralizes newlines + pipes (format injection); keyword text
    # itself legitimately remains as inert words
    assert "\n" not in lines[0]
    assert "nginx | x" not in lines[0]
    assert "nginx / x new ok" in lines[0]
    assert any(l.startswith("ref=Z-9 ") for l in lines)


def _client_enabled(monkeypatch, tmp_path, **kw):
    from test_openhack import _client
    return _client(monkeypatch, tmp_path, enabled=True, **kw)


def test_api_mode_validation_and_deadline(monkeypatch, tmp_path):
    m, client, H = _client_enabled(monkeypatch, tmp_path)
    monkeypatch.setattr(oh, "openhack_bin", lambda: "/bin/true")

    def fake_run(slug, domains, on_progress=None, mode="deep"):
        return {"status": "done", "added": 0, "updated": 0, "resolved": 0,
                "reopened": 0, "proposed": 0, "missed": 0,
                "graded": 0, "clamped": 0}
    monkeypatch.setattr(oh, "run_and_ingest", fake_run)

    bad = client.post("/api/orgs/sample/openhack-scan", headers=H,
                      json={"mode": "bogus"})
    assert bad.status_code == 400

    r = client.post("/api/orgs/sample/openhack-scan", headers=H,
                    json={"mode": "quick"})
    assert r.status_code == 200 and r.json()["mode"] == "quick"
    jid = r.json()["job_id"]
    key = m._job_key("sample", "ohack")
    with m._jobs_lock:
        entry = m._jobs[key]
        assert entry["stale_after"] == oh.quick_budget() + 600
    # deep mode uses the long timeout
    r2 = client.post("/api/orgs/sample/openhack-scan", headers=H,
                     json={"mode": "deep"})
    assert r2.status_code == 200
    time.sleep(0.3)


# ------------------------------------------------------- model selection --

def test_spawn_argv_model_override(monkeypatch):
    import openhack_source as oh
    monkeypatch.setattr(oh, "openhack_bin", lambda: "/opt/openhack-wrapper")
    monkeypatch.setattr(oh, "_venv_python", lambda binp=None: "/opt/openhack-python")
    a = oh._spawn_argv("obj", "/scratch", None)
    assert "--hack" in a and "run_task" not in " ".join(a)
    b = oh._spawn_argv("obj", "/scratch", "zai/glm-5.2")
    joined = " ".join(b)
    assert "-c" in b and "run_task" in joined
    # shim argv order: objective, scratch, model
    i = b.index("-c")
    assert b[i + 2] == "obj" and b[i + 3] == "/scratch" \
        and b[i + 4] == "zai/glm-5.2"


def test_models_endpoint_auth_and_payload(monkeypatch, tmp_path):
    m, client, H = _client_enabled(monkeypatch, tmp_path)
    monkeypatch.setattr(oh, "openhack_bin", lambda: "/bin/true")
    monkeypatch.setattr(oh, "list_models",
                        lambda force=False: {"models": [
                            {"id": "ox-alpha", "label": "OX Alpha"},
                            {"id": "zai/glm-5.2", "label": "GLM 5.2"}],
                            "default": "ox-alpha"})
    assert client.get("/api/openhack/models").status_code == 401
    r = client.get("/api/openhack/models", headers=H)
    d = r.json()
    assert r.status_code == 200 and d["default"] == "ox-alpha"
    assert {m["id"] for m in d["models"]} == {"ox-alpha", "zai/glm-5.2"}


def test_config_persists_and_resets_model(monkeypatch, tmp_path):
    m, client, H = _client_enabled(monkeypatch, tmp_path)
    r = client.post("/api/orgs/sample/openhack-config", headers=H,
                    json={"model": "zai/glm-5.2"})
    print("RESP:", r.status_code, r.text[:200])
    assert r.json()["openhack_model"] == "zai/glm-5.2"
    reg = json.loads((tmp_path / "data" / "orgs.json").read_text())
    assert reg["sample"]["openhack_model"] == "zai/glm-5.2"
    # invalid id rejected
    bad = client.post("/api/orgs/sample/openhack-config", headers=H,
                      json={"model": "bad model; rm -rf"})
    assert bad.status_code == 400
    # empty string resets to server default
    rs = client.post("/api/orgs/sample/openhack-config", headers=H,
                     json={"model": ""})
    assert rs.json()["openhack_model"] == ""
    reg = json.loads((tmp_path / "data" / "orgs.json").read_text())
    assert "openhack_model" not in reg["sample"]
    # enable stays independent of model toggles
    client.post("/api/orgs/sample/openhack-config", headers=H,
                json={"enabled": True})
    reg = json.loads((tmp_path / "data" / "orgs.json").read_text())
    assert reg["sample"]["openhack_enabled"] is True


def test_scan_endpoint_passes_org_model(monkeypatch, tmp_path):
    m, client, H = _client_enabled(monkeypatch, tmp_path)
    captured = {}
    monkeypatch.setattr(oh, "openhack_bin", lambda: "/bin/true")

    def fake_run(slug, domains, on_progress=None, mode="deep", model=None):
        captured["model"] = model
        return {"status": "done", "added": 0, "updated": 0, "resolved": 0,
                "reopened": 0, "proposed": 0, "missed": 0,
                "graded": 0, "clamped": 0}
    monkeypatch.setattr(oh, "run_and_ingest", fake_run)
    # org registry carries a pinned model via patched org_get
    real = m.cc.org_get
    monkeypatch.setattr(m.cc, "org_get",
                        lambda s: {**(real(s) or {}), "openhack_model":
                                   "zai/glm-5.2"} if s == "sample" else real(s))
    r = client.post("/api/orgs/sample/openhack-scan", headers=H, json={})
    assert r.status_code == 200
    dead = time.time() + 5
    while time.time() < dead:
        st = client.get(f"/api/orgs/sample/openhack-scan/{r.json()['job_id']}",
                        headers=H).json().get("status")
        if st in ("done", "failed"):
            break
        time.sleep(0.05)
    assert captured["model"] == "zai/glm-5.2"

    # no org pin -> falls back to the preferred runnable default (ox-alpha),
    # NOT the hosted catalog's nominal default
    monkeypatch.setattr(m.cc, "org_get",
                        lambda s: {**(real(s) or {})} if s == "sample" else real(s))
    r2 = client.post("/api/orgs/sample/openhack-scan", headers=H, json={})
    assert r2.status_code == 200
    dead = time.time() + 5
    while time.time() < dead:
        st = client.get(f"/api/orgs/sample/openhack-scan/{r2.json()['job_id']}",
                        headers=H).json().get("status")
        if st in ("done", "failed"):
            break
        time.sleep(0.05)
    assert captured["model"] == "ox-alpha", captured
