import json
import os
import subprocess
import sys
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]


def _probe_imports(data_dir: Path) -> dict:
    code = r'''
import json, sys
sys.path.insert(0, "app")
import cti_correlation as cc
import scanner, main, ai_providers
print(json.dumps({
    "cc_data": cc.DATA_ROOT,
    "cc_registry": cc._REGISTRY_FILE,
    "scanner_orgs": scanner.ORG_ROOT,
    "main_data": main.DATA_ROOT,
    "main_registry": main.ORGS_JSON,
    "ai_data": ai_providers.DATA_ROOT,
    "ai_config": ai_providers.DEFAULT_CONFIG_PATH,
    "ai_profiles": ai_providers.ORG_PROFILES_PATH,
}))
'''
    env = os.environ.copy()
    env["CTI_DATA_DIR"] = str(data_dir)
    proc = subprocess.run(
        [sys.executable, "-c", code],
        cwd=REPO,
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(proc.stdout.strip())


def test_cti_data_dir_applies_to_all_runtime_modules(tmp_path):
    data_dir = tmp_path / "runtime-data"
    data_dir.mkdir()
    values = _probe_imports(data_dir)
    root = str(data_dir.resolve())
    assert values["cc_data"] == root
    assert values["cc_registry"] == str(data_dir / "orgs.json")
    assert values["scanner_orgs"] == str(data_dir / "orgs")
    assert values["main_data"] == root
    assert values["main_registry"] == str(data_dir / "orgs.json")
    assert values["ai_data"] == root
    assert values["ai_config"] == str(data_dir / "ai_config.json")
    assert values["ai_profiles"] == str(data_dir / "ai_org_profiles.json")


def test_registry_legacy_data_prefix_resolves_under_runtime_root(tmp_path, monkeypatch):
    sys.path.insert(0, str(REPO / "app"))
    import cti_correlation as cc

    root = tmp_path / "private-data"
    monkeypatch.setattr(cc, "DATA_ROOT", str(root))
    assert cc._resolve_registry_path("data/orgs/beta/findings.json") == str(
        root / "orgs" / "beta" / "findings.json"
    )
    assert cc._resolve_registry_path("orgs/beta/baseline.txt") == str(
        root / "orgs" / "beta" / "baseline.txt"
    )


def test_registry_relative_path_cannot_escape_runtime_root(tmp_path, monkeypatch):
    sys.path.insert(0, str(REPO / "app"))
    import cti_correlation as cc

    monkeypatch.setattr(cc, "DATA_ROOT", str(tmp_path / "private-data"))
    assert cc._resolve_registry_path("../outside.json") is None
