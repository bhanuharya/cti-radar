"""Regression tests for the cheap-model AI triage flow.

Covers the deterministic pre-filter, compact classifier prompt, classifier
JSON parsing (whitelist + verdict normalization), template expansion, and the
single self-repair retry on malformed JSON.
"""
import json
import os
import sys
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

import scanner  # noqa: E402


HOSTS = {
    "vpn.example.com": {"url": "https://vpn.example.com", "code": "200",
                        "server": "nginx/1.18.0", "title": "Citrix Gateway"},
    "db.example.com": {"url": "https://db.example.com", "code": "200",
                       "server": "Apache", "title": "Welcome"},
    "www.example.com": {"url": "https://www.example.com", "code": "200",
                        "server": "nginx", "title": "Example Home"},
}
SERVICES = {
    "vpn.example.com": {"ip": "1.2.3.4", "open": {"443": "https", "22": "ssh"}},
    "db.example.com": {"ip": "5.6.7.8", "open": {"3306": "mysql"}},
    "www.example.com": {"ip": "9.9.9.9", "open": {"443": "https"}},
}


def test_select_ai_hosts_prioritizes_interesting():
    sel = scanner._select_ai_hosts(HOSTS, SERVICES, max_hosts=10)
    assert "vpn.example.com" in sel
    assert "db.example.com" in sel
    assert "www.example.com" not in sel  # plain site -> score 0 -> skipped


def test_build_prompt_is_compact_and_includes_ports():
    prompt = scanner._build_ai_prompt(HOSTS, ["vpn.example.com"], services=SERVICES)
    assert prompt is not None
    assert "22/ssh, 443/https" in prompt
    assert "Citrix Gateway" in prompt
    assert '"results"' in prompt


def test_parse_and_expand_classification():
    raw = json.dumps({"results": [
        {"target": "vpn.example.com", "verdict": "confirm", "severity": "HIGH", "reason": "citrix + ssh"},
        {"target": "db.example.com", "verdict": "dismiss", "severity": "INFO", "reason": "fine"},
        # not whitelisted -> must be dropped even though verdict=confirm
        {"target": "evil.example.com", "verdict": "confirm", "severity": "CRITICAL", "reason": "x"},
    ]})
    items = scanner.parse_ai_classification(raw, {"vpn.example.com", "db.example.com"})
    assert items is not None
    assert len(items) == 2  # evil.example.com dropped by whitelist
    confirms = [i for i in items if i["verdict"] == "confirm"]
    assert len(confirms) == 1
    rec = scanner._expand_ai_classification(confirms[0], HOSTS, SERVICES)
    assert rec["target"] == "vpn.example.com"
    assert rec["severity"] == "HIGH"
    assert rec["category"] == "Exposed remote/admin service"
    assert rec["related_cves"] == []
    assert "22/ssh" in rec["description"]


def test_ai_assess_finding_expands_classifier(monkeypatch):
    calls = []

    def fake_call(prompt, profile_name=None):
        calls.append(prompt)
        return (json.dumps({"results": [{"target": "vpn.example.com", "verdict": "confirm",
                                          "severity": "MEDIUM", "reason": "citrix exposed"}]}),
                {"model": "test", "profile": "test"})

    monkeypatch.setattr(scanner.ai_providers, "call_ai", fake_call)
    out, prov = scanner.ai_assess_finding(HOSTS, ["vpn.example.com"],
                                          profile_name="test", services=SERVICES)
    assert prov == {"model": "test", "profile": "test"}
    assert out is not None and len(out) == 1
    assert out[0]["severity"] == "MEDIUM"
    assert out[0]["title"] == "AI-flagged MEDIUM exposure"


def test_ai_assess_finding_self_repair_retry(monkeypatch):
    calls = []

    def fake_call(prompt, profile_name=None):
        calls.append(prompt)
        if len(calls) == 1:
            return "{not valid json", {"model": "test"}
        return (json.dumps({"results": [{"target": "vpn.example.com", "verdict": "confirm",
                                          "severity": "LOW", "reason": "ssh open"}]}),
                {"model": "test"})

    monkeypatch.setattr(scanner.ai_providers, "call_ai", fake_call)
    out, _ = scanner.ai_assess_finding(HOSTS, ["vpn.example.com"],
                                       profile_name="test", services=SERVICES)
    assert len(calls) == 2  # one repair retry
    assert out is not None and out[0]["severity"] == "LOW"


def test_collect_host_feedback(monkeypatch):
    fs = [
        {"target": "vpn.example.com", "feedback": [
            {"at": "t1", "by": "analyst", "note": "false positive"},
            {"at": "t2", "by": "analyst", "note": "confirm real"}]},
        {"target": "www.example.com", "feedback": []},
    ]
    monkeypatch.setattr(scanner.cc, "load_data", lambda slug: (fs, []))
    fb = scanner._collect_host_feedback("sample")
    assert fb == {"vpn.example.com": ["false positive", "confirm real"]}


def test_add_finding_comment_and_feedback_prompt(monkeypatch, tmp_path):
    fp = tmp_path / "findings.json"
    fp.write_text(json.dumps({"findings": [{"id": "F-1", "target": "vpn.example.com",
                                            "severity": "INFO", "status": "OPEN"}]}))
    hp = tmp_path / "history.json"
    monkeypatch.setattr(scanner.cc, "org_findings_path", lambda slug: str(fp))
    monkeypatch.setattr(scanner.cc, "history_path", lambda slug: str(hp))
    monkeypatch.setattr(scanner.cc, "_org_lock", lambda slug: threading.Lock())
    monkeypatch.setattr(scanner.cc, "load_meta_date", lambda org: "2026-01-15")

    f, err = scanner.cc.add_finding_comment("sample", "F-1", "false positive", by="analyst")
    assert err is None
    assert f["feedback"][0]["note"] == "false positive"
    # persisted to disk
    data = json.loads(fp.read_text())
    assert data["findings"][0]["feedback"][0]["note"] == "false positive"

    prompt = scanner._build_ai_prompt(
        HOSTS, ["vpn.example.com"], services=SERVICES,
        feedback={"vpn.example.com": ["false positive"]})
    assert "analyst_feedback" in prompt
    assert "false positive" in prompt


def test_classify_infra():
    assert scanner._classify_infra("vpn.acme.example") == ("VPN / remote access", "MEDIUM")
    assert scanner._classify_infra("cloud.acme.example") == ("Cloud / console", "MEDIUM")
    assert scanner._classify_infra("gitlab.acme.example") == ("Code / CI-CD", "MEDIUM")
    assert scanner._classify_infra("mail.acme.example") == ("Mail / collaboration", "MEDIUM")
    assert scanner._classify_infra("dashboard.acme.example") == ("Admin / management", "LOW")
    assert scanner._classify_infra("www.acme.example") == ("News / public web", "INFO")
    assert scanner._classify_infra("digital.acme.example") == (None, None)  # no 'git' substring FP
    assert scanner._classify_infra("random.acme.example") == (None, None)


def test_surface_finds_enumerated_critical_infra(tmp_path, monkeypatch):
    fp = tmp_path / "findings.json"
    fp.write_text(json.dumps({"findings": []}))
    monkeypatch.setattr(scanner.cc, "org_findings_path", lambda slug: str(fp))
    out = scanner.synthesize_surface_findings(
        "sample", {}, [], {}, enumerated=["vpn.acme.example", "www.acme.example", "random.acme.example"])
    targets = {r["target"] for r in out}
    assert "vpn.acme.example" in targets
    assert "www.acme.example" in targets
    assert "random.acme.example" not in targets  # unknown + unreachable -> skipped
    vpn = next(r for r in out if r["target"] == "vpn.acme.example")
    assert vpn["severity"] == "MEDIUM"
    assert vpn["status_detail"] == "ENUMERATED (no reachable service)"


def test_parse_response_field_and_expand(monkeypatch):
    host = {"vpn.acme.example": {"code": "200", "server": "FortiGate", "title": "FortiClient"}}
    svc = {"vpn.acme.example": {"ip": "1.2.3.4", "open": {"443": "https"}}}
    raw = json.dumps({"results": [{"target": "vpn.acme.example", "verdict": "confirm",
                                    "severity": "MEDIUM", "reason": "exposed portal",
                                    "response": "Thanks for flagging FortiClient — checked banner/title."}]})
    items = scanner.parse_ai_classification(raw, {"vpn.acme.example"})
    assert items[0]["response"] == "Thanks for flagging FortiClient — checked banner/title."
    rec = scanner._expand_ai_classification(items[0], host, svc)
    assert rec["evidence"]["analyst_response"] == "Thanks for flagging FortiClient — checked banner/title."
    assert "Analyst comment" not in rec["description"]  # response appended to description as Agent reply
    assert "Agent reply" in rec["description"]


def test_ai_assess_finding_captures_dismiss_reply(monkeypatch):
    host = {"vpn.acme.example": {"code": "200", "server": "-", "title": "-", "url": "https://vpn.acme.example"}}
    svc = {"vpn.acme.example": {"ip": "1.2.3.4", "open": {}}}
    feedback = {"vpn.acme.example": ["false positive"]}

    def fake(prompt, profile_name=None):
        return (json.dumps({"results": [{"target": "vpn.acme.example", "verdict": "dismiss",
                                          "severity": "INFO", "reason": "internal",
                                          "response": "Ack: looks internal, dismissing."}]}),
                {"model": "test"})

    monkeypatch.setattr(scanner.ai_providers, "call_ai", fake)
    arr, prov = scanner.ai_assess_finding(host, ["vpn.acme.example"], profile_name="test", services=svc, feedback=feedback)
    assert arr == []  # dismiss -> no new finding
    assert prov.get("replies", {}).get("vpn.acme.example") == "Ack: looks internal, dismissing."


def test_ai_assess_org_includes_service_only_hosts(monkeypatch, tmp_path):
    """A host with an open DB port but no HTTP fingerprint must still reach AI triage."""
    fp = tmp_path / "findings.json"
    fp.write_text(json.dumps({"findings": []}))
    monkeypatch.setattr(scanner.cc, "org_findings_path", lambda slug: str(fp))
    monkeypatch.setattr(scanner, "_history_path", lambda slug: str(tmp_path / "history.json"))
    monkeypatch.setattr(scanner.cc, "_org_lock", lambda slug: threading.Lock())
    monkeypatch.setattr(scanner.ai_providers, "resolve_profile_for_org",
                        lambda slug, override=None: "test")
    monkeypatch.setattr(scanner.ai_providers, "load_profiles",
                        lambda: ({"test": {"max_hosts": 10}}, "test"))
    monkeypatch.setattr(scanner, "_collect_host_feedback", lambda slug: {})
    seen = {}

    def fake_assess(host_dict, selected, profile_name=None, services=None, feedback=None):
        seen["selected"] = list(selected)
        seen["host_dict"] = dict(host_dict)
        return [], {"model": "test"}

    monkeypatch.setattr(scanner, "ai_assess_finding", fake_assess)
    svc_only = {"db.internal.example.com": {"ip": "5.6.7.8", "open": {"3306": "mysql"}}}
    result = scanner.ai_assess_org("sample", {}, profile_name="test", services=svc_only)
    assert result == "done"
    assert seen["selected"] == ["db.internal.example.com"]
    assert seen["host_dict"]["db.internal.example.com"] == {}


def test_ai_assess_org_skips_when_no_hosts_or_services(monkeypatch, tmp_path):
    monkeypatch.setattr(scanner, "_history_path", lambda slug: str(tmp_path / "history.json"))
    monkeypatch.setattr(scanner.cc, "_org_lock", lambda slug: threading.Lock())
    called = []

    def fake_assess(*a, **k):
        called.append(a)
        return [], None

    monkeypatch.setattr(scanner, "ai_assess_finding", fake_assess)
    result = scanner.ai_assess_org("sample", {}, profile_name="test", services={})
    assert result == "skipped"
    assert not called