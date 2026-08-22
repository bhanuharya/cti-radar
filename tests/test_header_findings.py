"""Tests for security-header findings (scan-headers)."""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

import scanner  # noqa: E402
import cti_correlation as cc  # noqa: E402


def _snip(**kw):
    base = {"url": "https://app.example.com", "code": "200", "title": "App"}
    base.update(kw)
    return base


def test_https_missing_all_headers_flagged(tmp_path, monkeypatch):
    fp = tmp_path / "findings.json"
    fp.write_text(json.dumps({"findings": []}))
    monkeypatch.setattr(cc, "org_findings_path", lambda slug: str(fp))
    out = scanner.synthesize_header_findings(
        "sample", {"app.example.com": _snip()})
    assert len(out) == 1
    f = out[0]
    assert f["source"] == "scan-headers"
    assert f["severity"] == "LOW"
    assert set(f["evidence"]["missing_headers"]) == {
        "strict-transport-security", "content-security-policy",
        "x-frame-options", "x-content-type-options"}
    assert f["port"] == 443


def test_partial_headers_report_only_missing(tmp_path, monkeypatch):
    fp = tmp_path / "findings.json"
    fp.write_text(json.dumps({"findings": []}))
    monkeypatch.setattr(cc, "org_findings_path", lambda slug: str(fp))
    out = scanner.synthesize_header_findings(
        "sample",
        {"app.example.com": _snip(**{"strict-transport-security": "max-age=63072000",
                                     "content-security-policy": "default-src 'self'"})})
    assert len(out) == 1
    assert set(out[0]["evidence"]["missing_headers"]) == {
        "x-frame-options", "x-content-type-options"}
    assert out[0]["evidence"]["present_headers"]["strict-transport-security"] \
        == "max-age=63072000"


def test_all_headers_present_no_finding(tmp_path, monkeypatch):
    fp = tmp_path / "findings.json"
    fp.write_text(json.dumps({"findings": []}))
    monkeypatch.setattr(cc, "org_findings_path", lambda slug: str(fp))
    full = _snip(**{"strict-transport-security": "max-age=63072000",
                    "content-security-policy": "default-src 'self'",
                    "x-frame-options": "DENY",
                    "x-content-type-options": "nosniff"})
    assert scanner.synthesize_header_findings("sample", {"app.example.com": full}) == []


def test_http_host_never_flagged_for_hsts_or_csp(tmp_path, monkeypatch):
    fp = tmp_path / "findings.json"
    fp.write_text(json.dumps({"findings": []}))
    monkeypatch.setattr(cc, "org_findings_path", lambda slug: str(fp))
    out = scanner.synthesize_header_findings(
        "sample", {"old.example.com": _snip(url="http://old.example.com")})
    assert len(out) == 1
    assert "strict-transport-security" not in out[0]["evidence"]["missing_headers"]
    assert "content-security-policy" not in out[0]["evidence"]["missing_headers"]
    assert out[0]["port"] == 80


def test_auth_surface_bumps_severity(tmp_path, monkeypatch):
    fp = tmp_path / "findings.json"
    fp.write_text(json.dumps({"findings": []}))
    monkeypatch.setattr(cc, "org_findings_path", lambda slug: str(fp))
    out = scanner.synthesize_header_findings(
        "sample", {"vpn.example.com": _snip(code="401", login_form=True)})
    assert out[0]["severity"] == "MEDIUM"


def test_error_pages_and_bannerless_skipped(tmp_path, monkeypatch):
    fp = tmp_path / "findings.json"
    fp.write_text(json.dumps({"findings": []}))
    monkeypatch.setattr(cc, "org_findings_path", lambda slug: str(fp))
    out = scanner.synthesize_header_findings("sample", {
        "err.example.com": _snip(code="503"),
        "bare.example.com": {"url": "https://bare.example.com", "code": "200"},
        "none.example.com": {"url": "https://none.example.com"},
    })
    # 503 and no-code skipped; bare (no title/server, nothing present) skipped
    assert out == []


def test_dedup_across_scans_and_identity(tmp_path, monkeypatch):
    fp = tmp_path / "findings.json"
    fp.write_text(json.dumps({"findings": []}))
    monkeypatch.setattr(cc, "org_findings_path", lambda slug: str(fp))
    snips = {"app.example.com": _snip()}
    out = scanner.synthesize_header_findings("sample", snips)
    assert len(out) == 1
    # identity assigned at creation (headers|target|)
    assert out[0]["identity_key"] == "headers|app.example.com|"
    # persist and re-run -> deduped by (target, category)
    fp.write_text(json.dumps({"findings": out}))
    assert scanner.synthesize_header_findings("sample", snips) == []
    # identity_key branch shape
    ik = cc.identity_key(out[0])
    assert ik == "headers|app.example.com|"
