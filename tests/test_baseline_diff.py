"""Tests for baseline-diff new-exposure findings."""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

import scanner  # noqa: E402
import cti_correlation as cc  # noqa: E402

ORG = {"slug": "sample", "domains": ["example.com"]}


def _patch(monkeypatch, tmp_path, subs, resolve_map, open_by_ip):
    monkeypatch.setattr(scanner, "ORG_ROOT", str(tmp_path / "orgs"))
    monkeypatch.setattr(scanner, "enumerate_subdomains",
                        lambda domains, on_progress=None: set(subs))
    monkeypatch.setattr(scanner, "_resolve",
                        lambda h: resolve_map.get(h, []))
    monkeypatch.setattr(scanner, "_fetch_fingerprint",
                        lambda h, timeout, ips: (None, None))
    monkeypatch.setattr(scanner, "_tcp_reachable",
                        lambda ip, port, timeout:
                        "reachable" if str(port) in open_by_ip.get(ip, ())
                        else "closed")
    monkeypatch.setattr(scanner, "_grab_banner", lambda *a, **k: None)
    monkeypatch.setattr(scanner, "_tls_cert", lambda *a, **k: None)
    monkeypatch.setattr(scanner, "_wildcard_cache", {})
    monkeypatch.setattr(cc, "org_findings_path",
                        lambda org: str(tmp_path / "orgs" / org / "findings.json"))


def _run(monkeypatch, tmp_path, subs, resolve_map, open_by_ip):
    _patch(monkeypatch, tmp_path, subs, resolve_map, open_by_ip)
    return scanner.generate_org(dict(ORG), mode="fast")


def test_three_scan_exposure_sequence(tmp_path, monkeypatch):
    org_dir = tmp_path / "orgs" / "sample"
    org_dir.mkdir(parents=True)
    (org_dir / "findings.json").write_text(json.dumps({"findings": []}))

    # scan 1: app + db hosts, no open ports -> no diff findings (first scan)
    r1 = _run(monkeypatch, tmp_path, ["app.example.com", "db.example.com"],
              {"app.example.com": ["5.6.7.8"], "db.example.com": ["5.6.7.9"]}, {})
    assert "error" not in r1
    assert r1["new_exposure"] == 0
    d1 = json.loads((org_dir / "findings.json").read_text())
    assert [f for f in d1["findings"] if f.get("source") == "baseline-diff"] == []

    # scan 2: new host appears + new port opens on the KNOWN db host
    r2 = _run(monkeypatch, tmp_path,
              ["app.example.com", "db.example.com", "new.example.com"],
              {"app.example.com": ["5.6.7.8"], "db.example.com": ["5.6.7.9"],
               "new.example.com": ["5.6.7.10"]},
              {"5.6.7.9": ("3306",)})  # mysql only on db.example.com
    assert "error" not in r2
    d2 = json.loads((org_dir / "findings.json").read_text())
    diffs = [f for f in d2["findings"] if f.get("source") == "baseline-diff"]
    assert r2["new_exposure"] == len(diffs) == 2
    by_target = {f["target"]: f for f in diffs}
    # new host -> LOW + CONFIRMED
    nh = by_target["new.example.com"]
    assert nh["severity"] == "LOW"
    assert "CONFIRMED" in nh["status_detail"]
    assert nh["identity_key"] == "diff|new.example.com|host"
    # new port on known host -> MEDIUM with explicit port
    np_ = by_target["db.example.com"]
    assert np_["severity"] == "MEDIUM"
    assert np_["port"] == 3306
    assert np_["identity_key"] == "diff|db.example.com|3306"
    light = cc.normalize_finding_light(nh)
    assert light["tier"] == "CONFIRMED"

    # scan 3: identical state -> no repeats
    r3 = _run(monkeypatch, tmp_path,
              ["app.example.com", "db.example.com", "new.example.com"],
              {"app.example.com": ["5.6.7.8"], "db.example.com": ["5.6.7.9"],
               "new.example.com": ["5.6.7.10"]},
              {"5.6.7.9": ("3306",)})
    d3 = json.loads((org_dir / "findings.json").read_text())
    diffs3 = [f for f in d3["findings"] if f.get("source") == "baseline-diff"]
    assert len(diffs3) == 2 and r3["new_exposure"] == 0


def test_new_host_with_sensitive_port_is_medium(tmp_path, monkeypatch):
    org_dir = tmp_path / "orgs" / "sample"
    org_dir.mkdir(parents=True)
    (org_dir / "findings.json").write_text(json.dumps({"findings": []}))
    _run(monkeypatch, tmp_path, ["app.example.com"],
         {"app.example.com": ["5.6.7.8"]}, ())
    r2 = _run(monkeypatch, tmp_path,
              ["app.example.com", "panel.example.com"],
              {"app.example.com": ["5.6.7.8"], "panel.example.com": ["5.6.7.11"]},
              {"5.6.7.11": ("3389",)})  # rdp only on panel (new host)
    d = json.loads((org_dir / "findings.json").read_text())
    diffs = [f for f in d["findings"] if f.get("source") == "baseline-diff"]
    assert len(diffs) == 1
    assert diffs[0]["target"] == "panel.example.com"
    assert diffs[0]["severity"] == "MEDIUM"       # non-web open port
    assert "3389" in diffs[0]["description"] or \
        diffs[0]["evidence"]["open_ports"] == ["3389"]


def test_first_scan_never_emits_diff_findings(tmp_path, monkeypatch):
    org_dir = tmp_path / "orgs" / "sample"
    org_dir.mkdir(parents=True)
    (org_dir / "findings.json").write_text(json.dumps({"findings": []}))
    _run(monkeypatch, tmp_path, ["app.example.com"],
         {"app.example.com": ["5.6.7.8"]}, {"5.6.7.8": ("22",)})
    d = json.loads((org_dir / "findings.json").read_text())
    assert [f for f in d["findings"] if f.get("source") == "baseline-diff"] == []
