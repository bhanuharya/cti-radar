"""Session-wide guardrails for the test suite.

The repo ships a tracked, sample-only data/orgs.json. Historical sessions
leaked test writes into it (a stray "beta" entry). Nothing in the current
suite does — this fixture makes that invariant enforced rather than assumed:
if any test dirties the tracked registry file during a run, its original
bytes are restored at session end and the session FAILS naming the file.
"""
import json
import os
import shutil
import tempfile

import pytest

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_GUARDED = (os.path.join(_REPO_ROOT, "data", "orgs.json"),)

# Establish an isolated runtime root before pytest imports any test module (and
# therefore before app modules freeze CTI_DATA_DIR into module constants).
_TEST_DATA_ROOT = tempfile.mkdtemp(prefix="cti-radar-pytest-")
_TEST_STATE_ROOT = tempfile.mkdtemp(prefix="cti-radar-state-pytest-")
os.environ["CTI_DATA_DIR"] = _TEST_DATA_ROOT
os.environ["CTI_STATE_DIR"] = _TEST_STATE_ROOT
os.environ["CTI_SCAN_TOKEN"] = "test-tok"
os.environ["CTI_USER"] = "testuser"
os.environ["CTI_PASSWORD"] = "testpass"

_sample_dir = os.path.join(_TEST_DATA_ROOT, "orgs", "sample")
os.makedirs(_sample_dir, exist_ok=True)
with open(os.path.join(_TEST_DATA_ROOT, "orgs.json"), "w") as f:
    json.dump({"sample": {
        "name": "Sample Org (demo)", "domains": ["example.com"],
        "findings": "data/orgs/sample/findings.json",
        "baseline": "data/orgs/sample/baseline.txt",
    }}, f)
with open(os.path.join(_sample_dir, "findings.json"), "w") as f:
    json.dump({"findings": []}, f)
with open(os.path.join(_sample_dir, "baseline.txt"), "w") as f:
    f.write("example.com\n")


def _read(p):
    try:
        with open(p, "rb") as f:
            return f.read()
    except OSError:
        return None


@pytest.fixture(scope="session", autouse=True)
def guard_tracked_runtime_files():
    snapshot = {p: _read(p) for p in _GUARDED}
    yield
    dirty = []
    for p, original in snapshot.items():
        if _read(p) != original:
            dirty.append(p)
            if original is not None:
                with open(p, "wb") as f:
                    f.write(original)
    try:
        assert not dirty, (
            "tests modified tracked runtime file(s) "
            f"{dirty} — original bytes restored. Fix the offending test to patch "
            "ORGS_JSON / cc._REGISTRY_FILE onto tmp_path instead.")
    finally:
        shutil.rmtree(_TEST_DATA_ROOT, ignore_errors=True)
        shutil.rmtree(_TEST_STATE_ROOT, ignore_errors=True)
