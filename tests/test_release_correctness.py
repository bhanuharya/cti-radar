"""Focused regression tests for release-blocking correctness fixes."""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))
import cti_correlation as cc
import main
from fastapi.testclient import TestClient


def test_cache_returns_deep_copies(tmp_path, monkeypatch):
    monkeypatch.setenv("CTI_DATA_DIR", str(tmp_path))
    findings = tmp_path / "findings.json"
    findings.write_text(json.dumps({"findings": [{"id": "f1", "evidence": {"commands": ["safe"]}}]}))
    monkeypatch.setattr(cc, "_org_paths", lambda org: (str(findings), None))
    cc._DATA_CACHE.clear()

    first, _ = cc.load_data("isolated")
    first[0]["evidence"]["commands"].append("mutated")
    second, _ = cc.load_data("isolated")
    assert second[0]["evidence"]["commands"] == ["safe"]


def test_job_status_binds_kind_and_uses_finished_elapsed(tmp_path, monkeypatch):
    monkeypatch.setenv("CTI_DATA_DIR", str(tmp_path))
    with main._jobs_lock:
        main._jobs.clear()
    ok, jid = main._try_acquire_job("isolated", "scan")
    assert ok
    with main._jobs_lock:
        main._jobs["isolated:scan"]["started"] = 100.0
    main._release_job("isolated", "scan", jid)
    with main._jobs_lock:
        main._jobs["isolated:scan"]["finished"] = 105.0
    result = main._job_status("isolated", "scan", jid)
    assert result["status"] == "done"
    assert result["elapsed"] == 5.0
    wrong_kind = main._job_status("isolated", "correlate", jid)
    assert wrong_kind.status_code == 404


def test_old_running_job_blocks_and_late_callbacks_are_fenced():
    with main._jobs_lock:
        main._jobs.clear()
    ok, jid_a = main._try_acquire_job("race", "scan")
    assert ok
    with main._jobs_lock:
        main._jobs["race:scan"]["started"] = 0
    ok, jid_b = main._try_acquire_job("race", "scan")
    assert not ok and jid_b == jid_a
    # Simulate a restart/replacement in the table: A must not touch B.
    with main._jobs_lock:
        main._jobs["race:scan"] = {"id": "race-scan-B", "status": "running", "stage": "b"}
    main._job_progress("race", "scan", jid_a, "late", "late A")
    main._release_job("race", "scan", jid_a)
    with main._jobs_lock:
        assert main._jobs["race:scan"] == {"id": "race-scan-B", "status": "running", "stage": "b"}


def test_structured_scanner_failures_are_detected():
    assert main._structured_job_failure({"error": "bad file"}) == "bad file"
    assert main._structured_job_failure({"status": "failed"}) == "failed"
    assert main._structured_job_failure({"report": {"error": "bad file"}}) == "bad file"
    assert main._structured_job_failure({"status": "ok", "success": True}) is None


def test_registry_absolute_paths_stay_under_data_root(tmp_path, monkeypatch):
    monkeypatch.setattr(cc, "DATA_ROOT", str(tmp_path))
    inside = tmp_path / "orgs" / "sample" / "findings.json"
    assert cc._resolve_registry_path(str(inside)) == str(inside)
    assert cc._resolve_registry_path(str(tmp_path.parent / "outside.json")) is None
    outside = tmp_path.parent / "secret.json"
    outside.write_text("secret")
    link = tmp_path / "link.json"
    link.symlink_to(outside)
    assert cc._resolve_registry_path(str(link)) is None


def test_login_failure_throttle_and_success_reset(monkeypatch):
    monkeypatch.setenv("CTI_LOGIN_FAIL_THRESHOLD", "3")
    monkeypatch.setenv("CTI_LOGIN_FAIL_WINDOW", "300")
    monkeypatch.setenv("CTI_LOGIN_RETRY_AFTER", "17")
    monkeypatch.setenv("CTI_USER", "testuser")
    monkeypatch.setenv("CTI_PASSWORD", "testpass")
    main._LOGIN_FAILS.clear()
    client = TestClient(main.app)
    # A success before threshold resets accumulated failures.
    for _ in range(2):
        assert client.post("/api/login", auth=("testuser", "wrong")).status_code == 401
    assert client.post("/api/login", auth=("testuser", "testpass")).status_code == 200
    assert not main._LOGIN_FAILS
    # Threshold blocks further attempts and returns bounded retry guidance.
    for _ in range(3):
        assert client.post("/api/login", auth=("testuser", "wrong")).status_code == 401
    limited = client.post("/api/login", auth=("testuser", "wrong"))
    assert limited.status_code == 429
    assert limited.headers["retry-after"] == "17"
    main._LOGIN_FAILS.clear()
