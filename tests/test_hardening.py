"""Regression tests for the security-correctness hardening slice.

Covers:
  S1.1 TLS inspection keyed off TCP 443/8443 reachability (not HTTPS
      fingerprint success), real port propagated into cert findings,
  S1.2 job failure propagation for scan/correlate error dicts and grade
      "failed" return,
  S1.3 grading provenance: AI-generated findings are never graded;
      CTI_AI_GRADE_MAX clamped to a safe range,
  S1.4 constant-time token compare, atomic 0600 writes, permission migration,
  S1.5 stale-running job reclaim, global active-job cap, legacy full-finding
      AI fallback removed.
"""
import importlib
import json
import os
import stat
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

# Tests must not inherit live service credentials from the invoking shell.
os.environ.setdefault("CTI_SCAN_TOKEN", "test-tok")
os.environ.setdefault("CTI_USER", "testuser")
os.environ.setdefault("CTI_PASSWORD", "testpass")

import cti_correlation as cc  # noqa: E402
import scanner  # noqa: E402


ORG = {"slug": "sample", "domains": ["example.com"]}


def _patch_offline_scan(monkeypatch, tmp_path, subs, resolve_map,
                        fingerprint=None, open_ports=(), banner=None,
                        tls_cert=None):
    """Make generate_org run fully offline against tmp ORG_ROOT."""
    monkeypatch.setattr(scanner, "ORG_ROOT", str(tmp_path / "orgs"))
    monkeypatch.setattr(scanner, "enumerate_subdomains",
                        lambda domains, on_progress=None: set(subs))
    monkeypatch.setattr(scanner, "_resolve", lambda h: resolve_map.get(h, []))
    if fingerprint is None:
        monkeypatch.setattr(scanner, "_fetch_fingerprint",
                            lambda h, timeout, ips: (None, None))
    else:
        monkeypatch.setattr(scanner, "_fetch_fingerprint",
                            lambda h, timeout, ips: fingerprint(h))
    monkeypatch.setattr(scanner, "_tcp_reachable",
                        lambda ip, port, timeout: "reachable" if str(port) in open_ports else "closed")
    monkeypatch.setattr(scanner, "_grab_banner",
                        lambda ip, port, name, h, timeout: banner)
    tls_calls = []

    def fake_tls(host, ip=None, port=443, timeout=6):
        tls_calls.append((host, port))
        return dict(tls_cert) if tls_cert else None

    monkeypatch.setattr(scanner, "_tls_cert", fake_tls)
    monkeypatch.setattr(cc, "org_findings_path",
                        lambda org: str(tmp_path / "orgs" / org / "findings.json"))
    return tls_calls


EXPIRED_CERT = {"not_after": "2020-01-01", "days_left": -2400, "expired": True,
                "self_signed": False, "issuer_cn": "Old CA"}


def test_tls_inspected_when_https_fingerprint_fails(tmp_path, monkeypatch):
    """The original bug: curl without --insecure fails the HTTPS fetch exactly
    when a cert is invalid, so snippet-gating skipped those certs forever."""
    org_dir = tmp_path / "orgs" / "sample"
    org_dir.mkdir(parents=True)
    (org_dir / "findings.json").write_text(json.dumps({"findings": []}))

    # HTTP fingerprint FAILS entirely; only TCP knows 443 is open
    tls_calls = _patch_offline_scan(
        monkeypatch, tmp_path, ["bad.example.com"], {"bad.example.com": ["5.6.7.8"]},
        fingerprint=None, open_ports=("443",), tls_cert=EXPIRED_CERT)

    scanner.generate_org(dict(ORG), mode="fast")
    assert tls_calls == [("bad.example.com", 443)], "cert not inspected despite TCP 443 reachability"
    d = json.loads((org_dir / "findings.json").read_text())
    tls = [f for f in d["findings"] if f.get("source") == "scan-tls"]
    assert len(tls) == 1, "expired-cert finding missing though cert was inspected"
    assert tls[0]["severity"] == "MEDIUM"
    assert tls[0]["port"] == 443


def test_tls_inspected_on_8443_and_port_propagated(tmp_path, monkeypatch):
    org_dir = tmp_path / "orgs" / "sample"
    org_dir.mkdir(parents=True)
    (org_dir / "findings.json").write_text(json.dumps({"findings": []}))

    tls_calls = _patch_offline_scan(
        monkeypatch, tmp_path, ["alt.example.com"], {"alt.example.com": ["5.6.7.8"]},
        open_ports=("8443",), tls_cert=dict(EXPIRED_CERT))

    scanner.generate_org(dict(ORG), mode="fast")
    assert tls_calls == [("alt.example.com", 8443)]
    d = json.loads((org_dir / "findings.json").read_text())
    tls = [f for f in d["findings"] if f.get("source") == "scan-tls"]
    assert len(tls) == 1
    assert tls[0]["port"] == 8443
    assert tls[0]["evidence"]["port"] == 8443


def test_clean_cert_produces_no_finding(tmp_path, monkeypatch):
    org_dir = tmp_path / "orgs" / "sample"
    org_dir.mkdir(parents=True)
    (org_dir / "findings.json").write_text(json.dumps({"findings": []}))
    clean = {"not_after": "2027-01-01", "days_left": 100, "expired": False,
             "self_signed": False, "issuer_cn": "Real CA"}
    _patch_offline_scan(monkeypatch, tmp_path, ["ok.example.com"],
                        {"ok.example.com": ["5.6.7.8"]},
                        open_ports=("443",), tls_cert=clean)
    scanner.generate_org(dict(ORG), mode="fast")
    d = json.loads((org_dir / "findings.json").read_text())
    assert not [f for f in d["findings"] if f.get("source") == "scan-tls"]


def test_synthesize_cert_findings_dedups_by_target_category(tmp_path, monkeypatch):
    fp = tmp_path / "findings.json"
    fp.write_text(json.dumps({"findings": [
        {"id": "TLS-old", "target": "dup.example.com", "category": "tls certificate",
         "status": "OPEN"}]}))
    monkeypatch.setattr(cc, "org_findings_path", lambda org: str(fp))
    out = scanner.synthesize_cert_findings("sample", {
        "dup.example.com": dict(EXPIRED_CERT, port=443),
        "new.example.com": dict(EXPIRED_CERT, port=8443)})
    ids = [f["target"] for f in out]
    assert ids == ["new.example.com"]
    assert out[0]["port"] == 8443


# ---------------------------------------------------------------- S1.2 ----

def _client_with_patched_registry(monkeypatch, tmp_path):
    os.environ["CTI_SCAN_TOKEN"] = "test-tok"
    org_root = tmp_path / "data" / "orgs"
    org_root.mkdir(parents=True, exist_ok=True)
    reg = {"sample": {"name": "sample", "domains": ["example.com"],
                      "findings": "data/orgs/sample/findings.json",
                      "baseline": "data/orgs/sample/baseline.txt"}}
    (tmp_path / "data" / "orgs.json").write_text(json.dumps(reg))
    od = org_root / "sample"
    od.mkdir(exist_ok=True)
    (od / "findings.json").write_text(json.dumps({"findings": []}))
    (od / "baseline.txt").write_text("")
    import main as m
    monkeypatch.setattr(m, "ORGS_JSON", str(tmp_path / "data" / "orgs.json"))
    monkeypatch.setattr(m, "DATA_ORG_DIR", str(org_root))
    monkeypatch.setattr(cc, "_REGISTRY_FILE", str(tmp_path / "data" / "orgs.json"))
    m._jobs.clear()
    return m


def _wait_job(client, base, jid, timeout=10.0):
    dead = time.time() + timeout
    while time.time() < dead:
        r = client.get(f"{base}/{jid}", headers={"X-CTI-Token": "test-tok"})
        if r.status_code == 200:
            st = r.json().get("status")
            if st in ("done", "failed"):
                return r.json()
        time.sleep(0.05)
    raise AssertionError("job did not reach terminal state in time")


def test_scan_error_result_marks_job_failed(monkeypatch, tmp_path):
    m = _client_with_patched_registry(monkeypatch, tmp_path)
    from fastapi.testclient import TestClient
    client = TestClient(m.app)
    monkeypatch.setattr(scanner, "generate_org",
                        lambda org, mode="fast", ai_profile=None, on_progress=None:
                        {"slug": "sample", "error": "corrupted findings.json"})
    r = client.post("/api/orgs/sample/scan", headers={"X-CTI-Token": "test-tok"},
                    json={"mode": "fast"})
    assert r.status_code == 200
    st = _wait_job(client, "/api/orgs/sample/scan", r.json()["job_id"])
    assert st["status"] == "failed"
    assert "corrupted" in (st.get("error") or "")


def test_scan_success_still_done(monkeypatch, tmp_path):
    m = _client_with_patched_registry(monkeypatch, tmp_path)
    from fastapi.testclient import TestClient
    client = TestClient(m.app)
    monkeypatch.setattr(scanner, "generate_org",
                        lambda org, mode="fast", ai_profile=None, on_progress=None:
                        {"slug": "sample", "subdomains": 1})
    r = client.post("/api/orgs/sample/scan", headers={"X-CTI-Token": "test-tok"},
                    json={"mode": "fast"})
    st = _wait_job(client, "/api/orgs/sample/scan", r.json()["job_id"])
    assert st["status"] == "done"


def test_correlate_error_result_marks_job_failed(monkeypatch, tmp_path):
    m = _client_with_patched_registry(monkeypatch, tmp_path)
    from fastapi.testclient import TestClient
    client = TestClient(m.app)
    monkeypatch.setattr(scanner, "correlate_org",
                        lambda org, on_progress=None:
                        {"slug": "sample", "error": "corrupted"})
    r = client.post("/api/orgs/sample/correlate", headers={"X-CTI-Token": "test-tok"})
    st = _wait_job(client, "/api/orgs/sample/correlate", r.json()["job_id"])
    assert st["status"] == "failed"


def test_grade_failed_return_marks_job_failed(monkeypatch, tmp_path):
    m = _client_with_patched_registry(monkeypatch, tmp_path)
    from fastapi.testclient import TestClient
    client = TestClient(m.app)
    monkeypatch.setattr(scanner, "ai_grade_org",
                        lambda slug, profile_name=None, on_progress=None: "failed")
    r = client.post("/api/orgs/sample/ai-grade", headers={"X-CTI-Token": "test-tok"},
                    json={})
    st = _wait_job(client, "/api/orgs/sample/ai-grade", r.json()["job_id"])
    assert st["status"] == "failed"
    assert "failed" in (st.get("error") or "").lower()


def test_grade_skipped_stays_done(monkeypatch, tmp_path):
    m = _client_with_patched_registry(monkeypatch, tmp_path)
    from fastapi.testclient import TestClient
    client = TestClient(m.app)
    monkeypatch.setattr(scanner, "ai_grade_org",
                        lambda slug, profile_name=None, on_progress=None: "skipped")
    r = client.post("/api/orgs/sample/ai-grade", headers={"X-CTI-Token": "test-tok"},
                    json={})
    st = _wait_job(client, "/api/orgs/sample/ai-grade", r.json()["job_id"])
    assert st["status"] == "done"


# ---------------------------------------------------------------- S1.3 ----

def test_grading_candidates_exclude_ai_generated():
    fs = [
        {"id": "D-1", "target": "a.example.com", "title": "t", "severity": "MEDIUM",
         "status": "OPEN", "evidence": {}, "last_seen": "2026-08-10"},
        {"id": "AI-1", "target": "b.example.com", "title": "AI-flagged HIGH exposure",
         "severity": "HIGH", "status": "OPEN", "source": "ai-assess", "evidence": {},
         "last_seen": "2026-08-11"},
        {"id": "AI-2", "target": "c.example.com", "title": "AI-flagged MEDIUM exposure",
         "severity": "MEDIUM", "status": "OPEN",
         "status_detail": "AI-ASSESSED", "evidence": {}},
    ]
    picks = scanner._select_grading_candidates.__globals__  # module ref sanity
    monkey_out = None
    # direct call with patched loader
    orig = cc.load_data
    try:
        cc.load_data = lambda slug: (fs, [])
        out = scanner._select_grading_candidates("sample")
    finally:
        cc.load_data = orig
    ids = {c["id"] for c in out}
    assert ids == {"D-1"}, ids


def test_is_ai_generated_helper():
    assert scanner._is_ai_generated({"source": "ai-assess"})
    assert scanner._is_ai_generated({"status_detail": "AI-ASSESSED"})
    assert not scanner._is_ai_generated({"source": "scan-surface"})
    assert not scanner._is_ai_generated({})


def test_ai_grade_max_clamped_subprocess():
    code = (
        "import sys, os; sys.path.insert(0, 'app');"
        "os.environ['CTI_AI_GRADE_MAX']='9999';"
        "import scanner; print(scanner.AI_GRADE_MAX)")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True,
                         text=True, timeout=60)
    assert out.returncode == 0, out.stderr[-500:]
    val = int(out.stdout.strip().splitlines()[-1])
    assert 1 <= val <= 50, val


# ---------------------------------------------------------------- S1.4 ----

def test_atomic_write_json_sets_0600_and_roundtrips(tmp_path):
    p = tmp_path / "nested" / "findings.json"
    cc._atomic_write_json(str(p), {"findings": [{"id": "x"}]})
    assert json.loads(p.read_text())["findings"][0]["id"] == "x"
    assert stat.S_IMODE(p.stat().st_mode) == 0o600
    assert stat.S_IMODE((tmp_path / "nested").stat().st_mode) == 0o700
    # no temp leftovers
    leftovers = [f.name for f in p.parent.iterdir() if f.name != "findings.json"]
    assert not leftovers, leftovers


def test_atomic_write_text_sets_0600(tmp_path):
    p = tmp_path / "baseline.txt"
    cc._atomic_write_text(str(p), "# hi\nhost\n")
    assert p.read_text() == "# hi\nhost\n"
    assert stat.S_IMODE(p.stat().st_mode) == 0o600


def test_migrate_data_permissions(monkeypatch, tmp_path):
    root = tmp_path / "droot"
    org = root / "orgs" / "acme"
    org.mkdir(parents=True)
    f = org / "findings.json"
    f.write_text("{}")
    os.chmod(f, 0o644)
    os.chmod(org, 0o755)
    reg = root / "orgs.json"
    reg.write_text("{}")
    os.chmod(reg, 0o644)
    monkeypatch.setattr(cc, "DATA_ROOT", str(root))
    changed = cc.migrate_data_permissions()
    assert changed >= 3
    assert stat.S_IMODE(f.stat().st_mode) == 0o600
    assert stat.S_IMODE(org.stat().st_mode) == 0o700
    assert stat.S_IMODE(reg.stat().st_mode) == 0o600


def test_token_compare_correctness(monkeypatch, tmp_path):
    m = _client_with_patched_registry(monkeypatch, tmp_path)
    from fastapi.testclient import TestClient
    client = TestClient(m.app)
    ok = client.get("/api/orgs", headers={"X-CTI-Token": "test-tok"})
    bad = client.get("/api/orgs", headers={"X-CTI-Token": "test-toke"})
    empty = client.get("/api/orgs", headers={"X-CTI-Token": ""})
    none = client.get("/api/orgs")
    assert ok.status_code == 200
    for r in (bad, empty, none):
        assert r.status_code == 401


# ---------------------------------------------------------------- S1.5 ----

def test_stale_running_job_remains_serialization_fence():
    import main as m
    m._jobs.clear()
    key = m._job_key("sloworg", "scan")
    with m._jobs_lock:
        m._jobs[key] = {"id": "sloworg-scan-dead", "started": time.time() - 99999,
                        "kind": "scan", "status": "running", "stage": "x",
                        "progress": "", "error": None}
    ok, jid = m._try_acquire_job("sloworg", "scan")
    # Age alone cannot prove a worker is dead; do not allow overlapping writers.
    assert not ok and jid == "sloworg-scan-dead"
    with m._jobs_lock:
        cur = m._jobs[key]
        assert cur["id"] == "sloworg-scan-dead" and cur["status"] == "running"
    m._jobs.clear()


def test_global_active_job_cap():
    import main as m
    m._jobs.clear()
    original = m._MAX_ACTIVE_JOBS
    try:
        m._MAX_ACTIVE_JOBS = 1
        ok1, _ = m._try_acquire_job("orga", "scan")
        ok2, jid2 = m._try_acquire_job("orgb", "scan")
        assert ok1 and not ok2 and jid2 is None
    finally:
        m._MAX_ACTIVE_JOBS = original
        m._jobs.clear()


def test_legacy_full_finding_parse_removed(monkeypatch):
    """Model echoing full findings must NOT be accepted anymore."""
    legacy_payload = json.dumps([
        {"target": "h1.example.com", "title": "Some invented title",
         "severity": "HIGH", "description": "prose", "impact": "prose"}])

    def must_not_be_called(*a, **k):
        raise AssertionError("legacy parse_ai_response fallback was invoked")

    monkeypatch.setattr(scanner.ai_providers, "parse_ai_response", must_not_be_called)
    monkeypatch.setattr(scanner.ai_providers, "call_ai",
                        lambda prompt, profile_name=None: (legacy_payload, {}))

    hosts = {"h1.example.com": {"code": 200, "server": "nginx"}}
    arr, prov = scanner.ai_assess_finding(hosts, ["h1.example.com"],
                                          profile_name="p", services={}, feedback=None)
    assert arr is None or all("title" not in x for x in arr), \
        "legacy full-finding output leaked through"


def test_classifier_schema_still_accepted(monkeypatch):
    good = json.dumps({"results": [
        {"target": "h1.example.com", "verdict": "confirm", "severity": "HIGH",
         "reason": "db exposed", "response": ""}]})
    monkeypatch.setattr(scanner.ai_providers, "call_ai",
                        lambda prompt, profile_name=None: (good, {}))
    hosts = {"h1.example.com": {"code": 200, "server": "nginx/1.18"},
             }
    svc = {"h1.example.com": {"ip": "5.6.7.8", "open": {"3306": "mysql"}, "banners": {}}}
    arr, prov = scanner.ai_assess_finding(hosts, ["h1.example.com"],
                                          profile_name="p", services=svc, feedback=None)
    assert isinstance(arr, list) and len(arr) == 1
    assert arr[0]["target"] == "h1.example.com"
    assert "title" in arr[0]  # template-expanded finding shape
