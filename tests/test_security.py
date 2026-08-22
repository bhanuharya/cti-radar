"""Security regression tests for the final audit hardening.

Tests cover:
- Tenant authentication on all org-scoped reads
- Unknown org rejection (no legacy fallback)
- Graph XSS prevention (escaped node labels/titles)
- PDF report PII masking
- Job state retention and failure reporting
- Provider URL validation (SSRF, DNS rebinding)
- Session cookie Secure flag
- CSP does not trust unpkg.com
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

# Tests must not inherit live service credentials from the invoking shell.
os.environ["CTI_SCAN_TOKEN"] = "test-tok"
os.environ["CTI_USER"] = "testuser"
os.environ["CTI_PASSWORD"] = "testpass"


def _patch_data_paths(monkeypatch, tmp_path):
    """Create isolated orgs.json + per-org data dirs under tmp_path and
    patch all module-level path variables so the app writes/reads from there."""
    org_root = tmp_path / "data" / "orgs"
    org_root.mkdir(parents=True, exist_ok=True)
    orgs_json = tmp_path / "data" / "orgs.json"

    for slug in ("sample", "beta"):
        od = org_root / slug
        od.mkdir(parents=True, exist_ok=True)
        fp = od / "findings.json"
        if not fp.exists():
            fp.write_text(json.dumps({"meta": {"date": "2026-01-15"}, "findings": [
                {"id": "F-001", "title": "T", "severity": "CRITICAL",
                 "target": "a.example.com", "ip": "1.2.3.4",
                 "category": "XSS", "status": "OPEN",
                 "related_cves": ["CVE-2023-1234"]},
            ]}, indent=2))
        bp = od / "baseline.txt"
        if not bp.exists():
            bp.write_text("a.example.com\n1.2.3.4\n")
        hp = od / "history.json"
        if not hp.exists():
            hp.write_text("[]")

    reg = {}
    for slug in ("sample", "beta"):
        reg[slug] = {
            "name": slug, "domains": ["example.com"],
            "findings": f"data/orgs/{slug}/findings.json",
            "baseline": f"data/orgs/{slug}/baseline.txt",
        }
    orgs_json.write_text(json.dumps(reg, indent=2))

    # patch all path variables so all modules resolve to tmp_path
    tp = str(tmp_path)
    monkeypatch.setattr("main.ORGS_JSON", str(orgs_json))
    monkeypatch.setattr("main.DATA_ORG_DIR", str(org_root))
    monkeypatch.setattr("cti_correlation._REGISTRY_FILE", str(orgs_json))
    monkeypatch.setattr("cti_correlation.BASE", tp)
    monkeypatch.setattr("cti_correlation.ORG_ROOT", str(org_root))
    monkeypatch.setattr("scanner.BASE", tp)
    monkeypatch.setattr("scanner.ORG_ROOT", str(org_root))

    import cti_correlation as cc
    cc._reload_registry()
    return orgs_json


def test_unauthenticated_reads_rejected(tmp_path, monkeypatch):
    _patch_data_paths(monkeypatch, tmp_path)
    import main
    from fastapi.testclient import TestClient
    client = TestClient(main.app)
    for path in [
        "/api/summary?org=sample",
        "/api/graph?org=sample",
        "/api/fleet?org=sample",
        "/api/ips?org=sample",
        "/api/findings?org=sample",
        "/api/dashboard?org=sample",
        "/api/orgs",
        "/api/orgs/sample",
        "/api/orgs/sample/history",
        "/api/orgs/sample/ai_profile",
        "/api/ai/capabilities",
        "/api/orgs/sample/report.pdf",
    ]:
        r = client.get(path)
        assert r.status_code == 401, f"{path} returned {r.status_code}, expected 401"


def test_authenticated_reads_accepted(tmp_path, monkeypatch):
    _patch_data_paths(monkeypatch, tmp_path)
    import main
    from fastapi.testclient import TestClient
    client = TestClient(main.app)
    auth = {"X-CTI-Token": os.environ["CTI_SCAN_TOKEN"]}
    for path in [
        "/api/summary?org=sample",
        "/api/graph?org=sample",
        "/api/fleet?org=sample",
        "/api/ips?org=sample",
        "/api/findings?org=sample",
        "/api/dashboard?org=sample",
        "/api/orgs",
        "/api/orgs/sample",
        "/api/orgs/sample/history",
        "/api/orgs/sample/ai_profile",
        "/api/ai/capabilities",
    ]:
        r = client.get(path, headers=auth)
        assert r.status_code == 200, f"{path} returned {r.status_code}: {r.text[:200]}"


def test_unknown_org_rejected(tmp_path, monkeypatch):
    _patch_data_paths(monkeypatch, tmp_path)
    import main
    from fastapi.testclient import TestClient
    client = TestClient(main.app)
    auth = {"X-CTI-Token": os.environ["CTI_SCAN_TOKEN"]}
    for path in [
        "/api/summary?org=nonexistent",
        "/api/graph?org=nonexistent",
        "/api/findings?org=nonexistent",
        "/api/dashboard?org=nonexistent",
    ]:
        r = client.get(path, headers=auth)
        assert r.status_code == 404, f"{path} returned {r.status_code}, expected 404"


def test_invalid_slug_rejected(tmp_path, monkeypatch):
    _patch_data_paths(monkeypatch, tmp_path)
    import main
    from fastapi.testclient import TestClient
    client = TestClient(main.app)
    auth = {"X-CTI-Token": os.environ["CTI_SCAN_TOKEN"]}
    for path in [
        "/api/summary?org=..%2Fetc",
        "/api/findings?org=BAD_SLUG",
    ]:
        r = client.get(path, headers=auth)
        assert r.status_code in (400, 404), f"{path} returned {r.status_code}"


def test_graph_xss_escaped():
    import cti_correlation as cc
    fs = [
        {"id": "X1", "target": "evil.com", "severity": "HIGH",
         "category": "<script>alert(1)</script>", "status": "OPEN",
         "ip": "1.2.3.4", "related_cves": []},
        {"id": "X2", "target": "<img onerror=alert(1)>", "severity": "CRITICAL",
         "category": "XSS", "status": "OPEN", "ip": "5.6.7.8",
         "related_cves": []},
    ]
    g = cc.build_graph_from_data(fs, [], ["example.com"])
    for node in g["nodes"]:
        label = node.get("label", "")
        title = node.get("title", "")
        assert "<script>" not in label, f"unescaped script in label: {label}"
        assert "<script>" not in title, f"unescaped script in title: {title}"
        assert "<img onerror" not in label, f"unescaped img in label: {label}"
        assert "<img onerror" not in title, f"unescaped img in title: {title}"
        assert "onerror" not in label or "<" not in label, f"unescaped onerror in label: {label}"


def test_report_uses_normalized_findings():
    import main
    fs = [
        {"id": "F-1", "title": "Test", "severity": "HIGH",
         "target": "host.example.com", "ip": "1.2.3.4",
         "description": "contact admin@example.com",
         "status": "OPEN", "related_cves": []},
    ]
    html = main._build_report_html("sample", {"name": "Test"}, fs, ["example.com"])
    assert "admin@example.com" not in html, "raw email leaked in report HTML"
    assert "***@" in html or "a***@" in html, f"email not masked in report: {html[:500]}"


def test_job_failure_retained_and_reported():
    import main as m
    m._jobs.clear()
    _, jid = m._try_acquire_job("testorg", "scan")
    m._release_job("testorg", "scan", jid, error=ValueError("test failure"))
    key = m._job_key("testorg", "scan")
    with m._jobs_lock:
        entry = m._jobs.get(key)
        assert entry is not None, "job entry should be retained"
        assert entry.get("status") == "failed"
        assert "test failure" in entry.get("error", "")
    m._jobs.clear()


def test_job_success_status():
    import main as m
    m._jobs.clear()
    ok, jid = m._try_acquire_job("testorg2", "scan")
    assert ok
    m._release_job("testorg2", "scan", jid)
    key = m._job_key("testorg2", "scan")
    with m._jobs_lock:
        entry = m._jobs.get(key)
        assert entry is not None
        assert entry.get("status") == "done"
    m._jobs.clear()


def test_provider_url_validation():
    import ai_providers
    assert ai_providers._validate_base_url("https://api.openai.com/v1", "openai-compatible", "OPENAI_API_KEY")
    assert ai_providers._validate_base_url("http://127.0.0.1:11434", "ollama", None)
    assert ai_providers._validate_base_url("http://localhost:11434", "ollama", None)
    assert not ai_providers._validate_base_url("http://api.openai.com/v1", "openai-compatible", "OPENAI_API_KEY")
    assert not ai_providers._validate_base_url("https://192.168.1.1/v1", "openai-compatible", None)
    assert not ai_providers._validate_base_url("https://10.0.0.1/v1", "openai-compatible", None)
    assert not ai_providers._validate_base_url("https://169.254.169.254/v1", "openai-compatible", None)
    assert not ai_providers._validate_base_url("https://user:pass@api.openai.com/v1", "openai-compatible", None)
    assert not ai_providers._validate_base_url("ftp://api.openai.com/v1", "openai-compatible", None)


def test_provider_api_key_env_allowed():
    import ai_providers
    assert ai_providers._ALLOWED_API_KEY_RE.match("OPENAI_API_KEY")
    assert ai_providers._ALLOWED_API_KEY_RE.match("CTI_AI_CUSTOM_KEY")
    assert ai_providers._ALLOWED_API_KEY_RE.match("OPENCODE_GO_B_API_KEY")
    assert ai_providers._ALLOWED_API_KEY_RE.match("OPENROUTER_API_KEY")
    assert ai_providers._ALLOWED_API_KEY_RE.match("VLLM_API_KEY")
    assert not ai_providers._ALLOWED_API_KEY_RE.match("PATH")
    assert not ai_providers._ALLOWED_API_KEY_RE.match("HOME")


def test_session_cookie_secure_behind_https(tmp_path, monkeypatch):
    _patch_data_paths(monkeypatch, tmp_path)
    import main
    from fastapi.testclient import TestClient
    client = TestClient(main.app)
    cred = __import__("base64").b64encode(b"testuser:testpass").decode()
    r = client.post("/api/login", headers={
        "Content-Type": "application/json",
        "Authorization": "Basic " + cred,
        "X-Forwarded-Proto": "https",
    }, json={})
    assert r.status_code == 200
    set_cookie = r.headers.get("set-cookie", "")
    assert "Secure" in set_cookie, f"cookie not secure behind HTTPS: {set_cookie}"


def test_session_cookie_not_secure_over_http(tmp_path, monkeypatch):
    _patch_data_paths(monkeypatch, tmp_path)
    import main
    from fastapi.testclient import TestClient
    client = TestClient(main.app)
    cred = __import__("base64").b64encode(b"testuser:testpass").decode()
    r = client.post("/api/login", headers={
        "Content-Type": "application/json",
        "Authorization": "Basic " + cred,
    }, json={})
    assert r.status_code == 200
    set_cookie = r.headers.get("set-cookie", "")
    assert "Secure" not in set_cookie, f"cookie secure over HTTP: {set_cookie}"


def test_csp_does_not_trust_unpkg(tmp_path, monkeypatch):
    _patch_data_paths(monkeypatch, tmp_path)
    import main
    from fastapi.testclient import TestClient
    client = TestClient(main.app)
    auth = {"X-CTI-Token": os.environ["CTI_SCAN_TOKEN"]}
    r = client.get("/", headers=auth)
    csp = r.headers.get("content-security-policy", "")
    assert "unpkg.com" not in csp, f"CSP still trusts unpkg.com: {csp}"


def test_csp_headers_present(tmp_path, monkeypatch):
    _patch_data_paths(monkeypatch, tmp_path)
    import main
    from fastapi.testclient import TestClient
    client = TestClient(main.app)
    auth = {"X-CTI-Token": os.environ["CTI_SCAN_TOKEN"]}
    r = client.get("/api/summary?org=sample", headers=auth)
    assert r.headers.get("x-content-type-options") == "nosniff"
    assert r.headers.get("x-frame-options") == "DENY"
    assert "frame-ancestors" in r.headers.get("content-security-policy", "")


def test_register_rejects_too_many_domains(tmp_path, monkeypatch):
    _patch_data_paths(monkeypatch, tmp_path)
    import main
    from fastapi.testclient import TestClient
    client = TestClient(main.app)
    auth = {"X-CTI-Token": os.environ["CTI_SCAN_TOKEN"]}
    domains = [f"d{i}.example.com" for i in range(25)]
    r = client.post("/api/orgs/register", headers=auth, json={
        "slug": "toomany", "name": "Too Many", "domains": domains
    })
    assert r.status_code == 400
    assert "too many" in r.json().get("error", "").lower()


def test_register_rejects_long_name(tmp_path, monkeypatch):
    _patch_data_paths(monkeypatch, tmp_path)
    import main
    from fastapi.testclient import TestClient
    client = TestClient(main.app)
    auth = {"X-CTI-Token": os.environ["CTI_SCAN_TOKEN"]}
    r = client.post("/api/orgs/register", headers=auth, json={
        "slug": "longname", "name": "x" * 300, "domains": ["example.com"]
    })
    assert r.status_code == 400


def test_add_remove_domains_endpoint(tmp_path, monkeypatch):
    _patch_data_paths(monkeypatch, tmp_path)
    import main
    from fastapi.testclient import TestClient
    client = TestClient(main.app)
    auth = {"X-CTI-Token": os.environ["CTI_SCAN_TOKEN"]}
    # add (merges + dedups + drops invalid)
    r = client.post("/api/orgs/sample/domains", headers=auth, json={
        "domains": ["new.example.com", "example.com", "not a domain!!"],
        "action": "add",
    })
    assert r.status_code == 200, r.text
    assert set(r.json()["domains"]) == {"example.com", "new.example.com"}
    # remove
    r = client.post("/api/orgs/sample/domains", headers=auth, json={
        "domains": ["example.com"], "action": "remove",
    })
    assert r.status_code == 200, r.text
    assert "example.com" not in r.json()["domains"]
    # invalid action
    r = client.post("/api/orgs/sample/domains", headers=auth, json={
        "domains": ["example.com"], "action": "wipe",
    })
    assert r.status_code == 400


def test_extract_openai_reasoning_and_cline_wrapper():
    import ai_providers
    # standard openai shape with separate reasoning field
    content, reasoning = ai_providers._extract_openai_content_reasoning({
        "choices": [{"message": {"content": "OK", "reasoning": "step by step"}}]
    })
    assert content == "OK"
    assert reasoning == "step by step"
    # cline.bot wrapper `{"data": {"choices": [...]}}` with reasoning_details
    content, reasoning = ai_providers._extract_openai_content_reasoning({
        "data": {"choices": [{"message": {
            "content": "OK",
            "reasoning_details": [{"index": 0, "text": "think1"}, {"index": 1, "text": "think2"}],
        }}]}
    })
    assert content == "OK"
    assert reasoning == "think1\nthink2"
