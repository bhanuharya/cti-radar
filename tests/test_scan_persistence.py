"""Regression tests for scan persistence guarantees in generate_org.

Covers:
  - corrupted findings.json aborts the scan BEFORE baseline.txt is rewritten
    (a new baseline must never be paired with stale/unreadable findings),
  - last_seen is refreshed for service-only hosts (open TCP port, no HTTP).
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

import scanner  # noqa: E402
import cti_correlation as cc  # noqa: E402


def _patch_offline_scan(monkeypatch, tmp_path, subs, resolve_map,
                        fingerprint=None, open_ports=(), banner=None):
    """Make _generate_org_inner run fully offline against tmp ORG_ROOT."""
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
    monkeypatch.setattr(cc, "org_findings_path", lambda org: str(tmp_path / "orgs" / org / "findings.json"))


ORG = {"slug": "sample", "domains": ["example.com"]}


def test_corrupted_findings_aborts_before_baseline_write(tmp_path, monkeypatch):
    org_dir = tmp_path / "orgs" / "sample"
    org_dir.mkdir(parents=True)
    (org_dir / "findings.json").write_text("{corrupted json")
    old_baseline = "# old baseline\nold.example.com\n"
    (org_dir / "baseline.txt").write_text(old_baseline)

    _patch_offline_scan(monkeypatch, tmp_path, ["db.example.com"],
                        {"db.example.com": ["5.6.7.8"]}, open_ports=("3306",))

    result = scanner.generate_org(dict(ORG), mode="fast")
    assert "corrupted findings.json" in result.get("error", "")
    # baseline must be untouched — never pair a new baseline with stale findings
    assert (org_dir / "baseline.txt").read_text() == old_baseline
    # corrupted findings.json itself untouched
    assert (org_dir / "findings.json").read_text() == "{corrupted json"


def test_last_seen_refreshed_for_service_only_host(tmp_path, monkeypatch):
    org_dir = tmp_path / "orgs" / "sample"
    org_dir.mkdir(parents=True)
    findings = {"findings": [{
        "id": "F-1", "target": "db.example.com", "title": "Exposed database/service",
        "severity": "HIGH", "status": "OPEN",
        "last_seen": "2000-01-01",
    }]}
    (org_dir / "findings.json").write_text(json.dumps(findings))

    _patch_offline_scan(monkeypatch, tmp_path, ["db.example.com"],
                        {"db.example.com": ["5.6.7.8"]}, open_ports=("3306",))

    result = scanner.generate_org(dict(ORG), mode="fast")
    assert "error" not in result
    d = json.loads((org_dir / "findings.json").read_text())
    f1 = next(f for f in d["findings"] if f["id"] == "F-1")
    today = scanner.time.strftime("%Y-%m-%d")
    assert f1["last_seen"] == today


def test_scan_refreshes_stale_evidence_and_adds_login_version_findings(tmp_path, monkeypatch):
    """End-to-end offline scan: existing finding's probe evidence is refreshed
    from this scan's capture, and login/version findings are synthesized."""
    org_dir = tmp_path / "orgs" / "sample"
    org_dir.mkdir(parents=True)
    findings = {"findings": [{
        "id": "F-1", "target": "app.example.com", "title": "Reachable service",
        "severity": "INFO", "status": "OPEN",
        "evidence": {"code": "200", "server": "OLD/1.0"},  # stale capture
        "last_seen": "2000-01-01",
    }]}
    (org_dir / "findings.json").write_text(json.dumps(findings))

    fp_map = {
        "app.example.com": {"url": "https://app.example.com", "code": "200",
                            "server": "nginx/1.25.3",
                            "versions": [{"product": "nginx", "version": "1.25.3"}]},
        "vpn.example.com": {"url": "https://vpn.example.com", "code": "200",
                            "title": "SSL VPN", "login_form": True},
    }

    def fp(h):
        return (f"https://{h} -> 200", fp_map.get(h))

    _patch_offline_scan(monkeypatch, tmp_path,
                        ["app.example.com", "vpn.example.com"],
                        {"app.example.com": ["5.6.7.8"], "vpn.example.com": ["9.9.9.9"]},
                        fingerprint=fp)

    result = scanner.generate_org(dict(ORG), mode="fast")
    assert "error" not in result
    d = json.loads((org_dir / "findings.json").read_text())
    f1 = next(f for f in d["findings"] if f["id"] == "F-1")
    # evidence refreshed from this scan — no more OLD/1.0
    assert f1["evidence"]["server"] == "nginx/1.25.3"
    assert f1["evidence"]["versions"][0]["version"] == "1.25.3"
    cats = {f.get("category"): f for f in d["findings"] if f.get("category")}
    assert "software version disclosure" in cats          # app host
    assert "login portal exposed" in cats                  # vpn host
    assert cats["login portal exposed"]["target"] == "vpn.example.com"
    # meta carries fresh fingerprints for AI grading's still_open basis
    assert d["meta"]["fingerprints"]["vpn.example.com"]["login_form"] is True


def test_finding_port_uses_evidence_services():
    # single open service port -> recheck that port (AI finding, no HTTP)
    f = {"target": "db.example.com", "title": "AI-flagged HIGH exposure",
         "category": "Exposed database/service",
         "evidence": {"services": {"3306": "mysql"}}}
    assert scanner._finding_port(f) == 3306

    # multiple ports -> match the service name/aliases against the category
    f2 = {"target": "vpn.example.com", "title": "Exposed remote/admin service",
          "category": "Exposed remote/admin service",
          "evidence": {"services": {"443": "https", "22": "ssh"}}}
    assert scanner._finding_port(f2) == 22

    # explicit port field still wins
    f3 = {"port": 8080, "evidence": {"services": {"3306": "mysql"}}}
    assert scanner._finding_port(f3) == 8080

    # no service evidence -> default
    assert scanner._finding_port({"title": "something"}) == 443


def test_cert_findings_expired_and_self_signed(tmp_path, monkeypatch):
    fp = tmp_path / "findings.json"
    fp.write_text(json.dumps({"findings": []}))
    monkeypatch.setattr(cc, "org_findings_path", lambda slug: str(fp))
    certs = {
        "a.example.com": {"not_after": "Aug 1 00:00:00 2020 GMT", "days_left": -100,
                          "expired": True, "self_signed": False, "issuer_cn": "Let's Encrypt",
                          "san_count": 1},
        "b.example.com": {"not_after": "Aug 1 00:00:00 2030 GMT", "days_left": 300,
                          "expired": False, "self_signed": True, "issuer_cn": "b.example.com",
                          "san_count": 0},
        "c.example.com": {"not_after": "Aug 1 00:00:00 2030 GMT", "days_left": 300,
                          "expired": False, "self_signed": False, "issuer_cn": "CA",
                          "san_count": 2},
    }
    out = scanner.synthesize_cert_findings("sample", certs)
    by_target = {r["target"]: r for r in out}
    assert set(by_target) == {"a.example.com", "b.example.com"}  # healthy cert skipped
    assert by_target["a.example.com"]["severity"] == "MEDIUM"
    assert by_target["b.example.com"]["severity"] == "LOW"
    assert by_target["a.example.com"]["evidence"]["port"] == 443
    # re-run with existing findings -> deduped by (target, category)
    fp.write_text(json.dumps({"findings": out}))
    assert scanner.synthesize_cert_findings("sample", certs) == []


def test_generate_org_persists_cert_finding(tmp_path, monkeypatch):
    org_dir = tmp_path / "orgs" / "sample"
    org_dir.mkdir(parents=True)
    (org_dir / "findings.json").write_text(json.dumps({"findings": []}))
    monkeypatch.setattr(scanner, "ORG_ROOT", str(tmp_path / "orgs"))
    monkeypatch.setattr(scanner, "enumerate_subdomains",
                        lambda domains, on_progress=None: {"a.example.com"})
    monkeypatch.setattr(scanner, "_resolve", lambda h: ["1.2.3.4"])
    monkeypatch.setattr(scanner, "_fetch_fingerprint",
                        lambda h, timeout, ips: ({"ip": "1.2.3.4"},
                                                 {"url": "https://a.example.com", "code": "200",
                                                  "title": "A"}))
    monkeypatch.setattr(scanner, "_tls_cert", lambda host, ip=None, port=443, timeout=6:
                        {"not_after": "Aug 1 00:00:00 2020 GMT", "days_left": -5, "expired": True,
                         "self_signed": False, "issuer_cn": "CA", "san_count": 1})
    monkeypatch.setattr(scanner, "_tcp_reachable", lambda ip, port, timeout: "closed")
    monkeypatch.setattr(scanner, "_grab_banner", lambda *a, **k: None)
    monkeypatch.setattr(cc, "org_findings_path", lambda org: str(tmp_path / "orgs" / org / "findings.json"))

    result = scanner.generate_org(dict(ORG), mode="fast")
    assert "error" not in result
    d = json.loads((org_dir / "findings.json").read_text())
    tls = [f for f in d["findings"] if f["source"] == "scan-tls"]
    assert len(tls) == 1
    assert tls[0]["target"] == "a.example.com"
    assert tls[0]["severity"] == "MEDIUM"
    # and it is not duplicated on the next scan
    scanner.generate_org(dict(ORG), mode="fast")
    d2 = json.loads((org_dir / "findings.json").read_text())
    assert len([f for f in d2["findings"] if f["source"] == "scan-tls"]) == 1
