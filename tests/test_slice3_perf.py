"""Slice 3 regression tests: pipeline performance changes preserve semantics.

- recheck probes now run in a bounded pool: same results/apply-by-id as the
  old sequential loop, measurably concurrent execution,
- InternetDB enrichment pool (covered indirectly by the correlate lifecycle
  test in test_reconcile.py which patches _internetdb).
"""
import json
import os
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

import cti_correlation as cc  # noqa: E402
import scanner  # noqa: E402


def test_recheck_probes_run_concurrently(monkeypatch, tmp_path):
    findings = {"findings": [
        {"id": f"R-{i}", "target": f"h{i}.example.com", "ip": "5.6.7.8",
         "severity": "MEDIUM", "status": "OPEN", "positive": False,
         "port": 8080 + i, "title": "t"} for i in range(6)]}
    fp = tmp_path / "findings.json"
    fp.write_text(json.dumps(findings))
    monkeypatch.setattr(cc, "org_findings_path", lambda s: str(fp))
    monkeypatch.setattr(cc, "_org_lock", lambda s: threading.Lock())
    monkeypatch.setattr(cc, "single_public_ip",
                        lambda ip: "5.6.7.8" if ip else None)
    # make every finding's port resolve deterministically
    monkeypatch.setattr(scanner, "_finding_port", lambda f, default=443: f["port"])

    peak = {"cur": 0, "max": 0}
    lock = threading.Lock()

    def fake_tcp(ip, port, timeout=3):
        with lock:
            peak["cur"] += 1
            peak["max"] = max(peak["max"], peak["cur"])
        time.sleep(0.12)
        with lock:
            peak["cur"] -= 1
        return "closed"

    monkeypatch.setattr(scanner, "_tcp_reachable", fake_tcp)

    t0 = time.time()
    changed = scanner.recheck_findings("sample", max_probe=6, timeout=1)
    elapsed = time.time() - t0

    # first-ever observation (prev unknown -> closed) is NOT a transition
    assert changed == 0
    assert peak["max"] >= 4, f"probes appear sequential (peak concurrency {peak['max']})"
    # 6 probes x 0.12s serial would be >=0.72s; pooled should be well under
    assert elapsed < 0.6, elapsed
    d = json.loads(fp.read_text())
    assert all(f["_reachable"] == "no" for f in d["findings"])
    assert all(int(f["_unreach_streak"]) == 1 for f in d["findings"])
