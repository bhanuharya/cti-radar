"""Slice 2 regression tests: stable identity, per-host/port split + migration,
and the reconciliation lifecycle (tiered auto-resolve, propose-only HIGH,
recurrence reopen, raw-IP join via service IPs, TLS renewal resolve).
Also covers the correlate pass emitting its own snapshot/history event.
"""
import json
import os
import sys
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

import cti_correlation as cc  # noqa: E402
import scanner  # noqa: E402


def _patch_org_paths(monkeypatch, tmp_path, findings, meta=None):
    od = tmp_path / "orgs" / "sample"
    od.mkdir(parents=True, exist_ok=True)
    fp = od / "findings.json"
    fp.write_text(json.dumps({"meta": meta or {}, "findings": findings}))
    hp = tmp_path / "history.json"
    monkeypatch.setattr(cc, "org_findings_path", lambda org: str(fp))
    monkeypatch.setattr(scanner, "_history_path", lambda slug: str(hp))
    monkeypatch.setattr(cc, "_org_lock", lambda slug: threading.Lock())
    return fp, hp


# ------------------------------------------------------------- migration --

def test_migration_splits_combined_service_findings():
    legacy = [{
        "id": "SRV-old-1", "target": "ssh.example.com", "ip": "1.2.3.4",
        "source": "scan-services", "severity": "MEDIUM", "status": "OPEN",
        "title": "Exposed service (TCP connect probe)",
        "evidence": {"ip": "1.2.3.4", "services": {"22": "ssh", "3306": "mysql"},
                     "banners": {"22": "SSH-2.0-OpenSSH"}},
        "status_history": [{"at": "2026-08-01", "from": "", "to": "OPEN", "by": "scan"}],
    }]
    out, changed = scanner._migrate_legacy_surface_findings(legacy)
    assert changed == 1 and len(out) == 2
    ids = {f["identity_key"] for f in out}
    assert "surface-tcp|ssh.example.com|22" in ids
    assert "surface-tcp|ssh.example.com|3306" in ids
    ssh = next(f for f in out if f.get("port") == 22)
    mysql = next(f for f in out if f.get("port") == 3306)
    assert ssh["id"] == "SRV-old-1"                      # first child keeps id
    assert ssh["evidence"]["banners"] == {"22": "SSH-2.0-OpenSSH"}
    assert "3306" not in json.dumps(ssh["evidence"])      # scoped to own port
    assert mysql["id"].endswith("-P3306")
    assert any(e.get("by") == "reconcile" and "split" in e.get("note", "")
               for e in mysql["status_history"])
    # idempotent: second pass is a no-op
    out2, changed2 = scanner._migrate_legacy_surface_findings(out)
    assert changed2 == 0 and len(out2) == 2


def test_migration_resources_enum_and_sets_web_port():
    legacy = [
        {"id": "E-1", "target": "vpn.example.com", "source": "scan-surface",
         "severity": "LOW", "status": "OPEN",
         "evidence": {"host": "vpn.example.com", "classification": "VPN / remote access"}},
        {"id": "W-1", "target": "www.example.com", "source": "scan-surface",
         "severity": "INFO", "status": "OPEN",
         "evidence": {"url": "https://www.example.com", "code": 200}},
    ]
    out, changed = scanner._migrate_legacy_surface_findings(legacy)
    vpn = next(f for f in out if f["target"] == "vpn.example.com")
    web = next(f for f in out if f["target"] == "www.example.com")
    assert vpn["source"] == "scan-enum"
    assert vpn["identity_key"] == "surface-enum|vpn.example.com|"
    assert web["port"] == 443
    assert web["identity_key"] == "surface-web|www.example.com|443"
    assert changed >= 1


# ------------------------------------------------------------- synthesis --

FP_EMPTY = {"findings": []}


def test_synthesis_per_port_split_and_dedup(monkeypatch, tmp_path):
    fp, _ = _patch_org_paths(monkeypatch, tmp_path, [])
    snippets = {"api.example.com": {"url": "https://api.example.com", "code": 200,
                                    "server": "nginx/1.24"}}
    services = {"api.example.com": {"ip": "5.5.5.5",
                                    "open": {"443": "https", "22": "ssh"},
                                    "banners": {"22": "SSH-2.0"}},
                "db.example.com": {"ip": "5.5.5.6",
                                   "open": {"3306": "mysql"}, "banners": {}}}
    out = scanner.synthesize_surface_findings("sample", snippets, [], services)
    web = [f for f in out if f["source"] == "scan-surface"]
    tcp = [f for f in out if f["source"] == "scan-services"]
    assert len(web) == 1 and web[0]["port"] == 443
    assert web[0]["identity_key"] == "surface-web|api.example.com|443"
    ports = sorted(f["port"] for f in tcp)
    assert ports == [22, 3306], "expected per-port findings for ssh + mysql"
    byp = {f["port"]: f for f in tcp}
    assert byp[22]["identity_key"] == "surface-tcp|api.example.com|22"
    assert byp[22]["evidence"]["banners"] == {"22": "SSH-2.0"}
    assert byp[3306]["identity_key"] == "surface-tcp|db.example.com|3306"
    # dedup on second run against the persisted first-run identities
    fp.write_text(json.dumps({"findings": out}))
    again = scanner.synthesize_surface_findings("sample", snippets, [], services)
    assert again == [], [f["id"] for f in again]


# --------------------------------------------------------- reconciliation --

def _f(fid, ik, sev="LOW", status="OPEN", target="h.example.com", **kw):
    f = {"id": fid, "identity_key": ik, "severity": sev, "status": status,
         "target": target, "positive": False, "evidence": {"x": fid},
         "status_history": []}
    f.update(kw)
    return f


def test_reconcile_observed_refresh_and_hash():
    fs = [_f("F1", "surface-web|h.example.com|443")]
    counts = scanner._reconcile_findings(
        fs, {"h.example.com": {"url": "https://h.example.com", "code": 200}},
        {}, [], {})
    assert counts["observed"] == 1 and fs[0]["missing_streak"] == 0
    assert fs[0]["last_seen"] and fs[0]["evidence_hash"]


def test_reconcile_tiered_resolution():
    # missing_streak=1 pre-seeded: this is the second consecutive miss
    low = _f("L", "surface-tcp|l.example.com|3306", sev="MEDIUM", missing_streak=1)
    high = _f("H", "surface-tcp|h.example.com|3389", sev="HIGH", missing_streak=1)
    prog = _f("P", "surface-tcp|p.example.com|22", sev="CRITICAL",
              status="IN_PROGRESS", missing_streak=1)
    pos = _f("N", "surface-web|n.example.com|80", positive=True, missing_streak=1)
    fs = [low, high, prog, pos]
    counts = scanner._reconcile_findings(fs, {}, {}, [], {}, resolve_after=2)
    assert counts["missing"] == 4
    assert low["status"] == "RESOLVED" and low["missing_streak"] == 2
    assert high["status"] == "OPEN" and counts["proposed"] == 1
    assert any("propose RESOLVED" in e.get("note", "") for e in high["status_history"])
    assert prog["status"] == "IN_PROGRESS"          # analyst-owned untouched
    assert pos["status"] == "OPEN"                  # positive never auto-changed


def test_reconcile_recurrence_reopens():
    f = _f("R", "surface-web|r.example.com|443", status="RESOLVED",
           missing_streak=3)
    counts = scanner._reconcile_findings(
        f and [f], {"r.example.com": {"url": "https://r.example.com", "code": 200}},
        {}, [], {})
    assert counts["reopened"] == 1
    assert f["status"] == "OPEN" and f["missing_streak"] == 0
    assert any(e.get("to") == "OPEN" and "recurrence" in e.get("note", "")
               for e in f["status_history"])


def test_reconcile_raw_ip_observed_via_service_ip():
    f = _f("IP1", "surface-tcp|9.9.9.9|22", target="9.9.9.9")
    counts = scanner._reconcile_findings(
        [f], {},
        {"box.example.com": {"ip": "9.9.9.9", "open": {"22": "ssh"}}}, [], {})
    assert counts["observed"] == 1 and f["missing_streak"] == 0


def test_reconcile_cert_renewal_immediate_resolve():
    f = _f("T1", "tls|old.example.com|443", sev="MEDIUM")
    certs = {"old.example.com": {"port": 443, "expired": False,
                                 "self_signed": False, "days_left": 90}}
    counts = scanner._reconcile_findings([f], {}, {}, [], certs)
    assert f["status"] == "RESOLVED" and counts["resolved"] == 1
    assert any("valid certificate" in e.get("note", "") for e in f["status_history"])


def test_reconcile_expired_cert_stays_open_but_observed():
    f = _f("T2", "tls|bad.example.com|443", sev="MEDIUM")
    certs = {"bad.example.com": {"port": 443, "expired": True}}
    scanner._reconcile_findings([f], {}, {}, [], certs)
    assert f["status"] == "OPEN" and f["missing_streak"] == 0


# ------------------------------------------------------------ correlate ----

def test_correlate_updates_snapshot_and_appends_history(monkeypatch, tmp_path):
    finding = {"id": "C-1", "target": "a.example.com", "ip": "4.4.4.4",
               "title": "t", "severity": "HIGH", "status": "OPEN",
               "related_cves": ["CVE-2024-1234"], "category": "c",
               "source": "scan-surface", "evidence": {}}
    fp, hp = _patch_org_paths(monkeypatch, tmp_path, [finding])
    monkeypatch.setattr(cc, "load_data",
                        lambda slug: ([finding], ["a.example.com"]))
    monkeypatch.setattr(scanner, "_resolve", lambda h: ["4.4.4.4"])
    monkeypatch.setattr(scanner, "_internetdb", lambda ip: {})
    res = scanner.correlate_org({"slug": "sample", "domains": ["example.com"]})
    assert "error" not in res
    d = json.loads(fp.read_text())
    snap = d.get("meta", {}).get("last_snapshot")
    assert snap and "C-1" in snap, "correlate must refresh meta.last_snapshot"
    events = json.loads(hp.read_text())
    corr = [e for e in events if e.get("kind") == "correlate"]
    assert corr and "added" in corr[-1]["summary"]


def test_summary_live_semantics_exclude_resolved():
    fs = [
        {"id": "1", "severity": "HIGH", "status": "OPEN"},
        {"id": "2", "severity": "MEDIUM", "status": "RESOLVED",
         "status_history": []},
        {"id": "3", "severity": "LOW", "status": "MITIGATED"},  # analyst-closed: stays live
    ]
    s = cc.summary_from_data(fs, ["a.example.com"])
    assert s["findings_total"] == 2
    assert s["resolved_total"] == 1
    assert s["severity"] == {"HIGH": 1, "LOW": 1}
    assert s["baseline"] == 1
