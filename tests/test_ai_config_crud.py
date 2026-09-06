"""Tests for generic AI model config (no presets): validate + merge-save + env-single."""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

import ai_providers as ap  # noqa: E402


def _isolate(tmp_path, monkeypatch):
    d = tmp_path / "aidata"
    d.mkdir()
    monkeypatch.setenv("CTI_DATA_DIR", str(d))
    monkeypatch.delenv("CTI_AI_CONFIG", raising=False)
    monkeypatch.delenv("CTI_AI_CONFIG_FILE", raising=False)
    for k in ("CTI_AI_BASE_URL", "CTI_AI_MODEL", "CTI_AI_PROFILE_NAME",
              "CTI_AI_PROVIDER", "CTI_AI_API_KEY", "CTI_AI_API_KEY_ENV"):
        monkeypatch.delenv(k, raising=False)
    # rebind module constants that froze at import
    monkeypatch.setattr(ap, "DATA_ROOT", str(d))
    monkeypatch.setattr(ap, "DEFAULT_CONFIG_PATH", str(d / "ai_config.json"))
    monkeypatch.setattr(ap, "ORG_PROFILES_PATH", str(d / "ai_org_profiles.json"))
    return d


def test_golden_cline_shape_validates():
    golden = {"provider": "openai-compatible",
              "base_url": "https://api.cline.bot/api/v1",
              "model": "cline-pass/mimo-v2.5-pro",
              "api_key_env": "HERMES_CUSTOM_API_CLINE_BOT_API_KEY",
              "timeout": 90, "max_hosts": 10, "max_tokens": 3072}
    ok, reason, fd = ap.validate_profile_fields("cline", golden)
    assert ok, reason
    assert fd["model"] == "cline-pass/mimo-v2.5-pro"


def test_validate_rejects_with_reason():
    ok, reason, _ = ap.validate_profile_fields("bad name!", {})
    assert not ok and "name" in reason
    ok, reason, _ = ap.validate_profile_fields("x", {"provider": "nope"})
    assert not ok and "provider" in reason
    ok, reason, _ = ap.validate_profile_fields(
        "x", {"provider": "openai-compatible", "base_url": "http://evil.example.com", "model": "m"})
    assert not ok and "base_url" in reason
    ok, reason, _ = ap.validate_profile_fields(
        "x", {"provider": "openai-compatible", "base_url": "https://ok.example.com",
              "model": "m", "api_key_env": "lowercase-bad"})
    assert not ok and "api_key_env" in reason


def test_save_merge_preserves_existing(tmp_path, monkeypatch):
    d = _isolate(tmp_path, monkeypatch)
    seed = {"default_profile": "cline",
            "profiles": {"cline": {"provider": "openai-compatible",
                                   "base_url": "https://api.cline.bot/api/v1",
                                   "model": "cline-pass/mimo-v2.5-pro",
                                   "api_key_env": "HERMES_CUSTOM_API_CLINE_BOT_API_KEY"}}}
    (d / "ai_config.json").write_text(json.dumps(seed))
    ok, info = ap.save_profile("second", {"provider": "ollama",
                                          "base_url": "http://127.0.0.1:11434",
                                          "model": "somemodel"})
    assert ok, info
    data = json.loads((d / "ai_config.json").read_text())
    assert set(data["profiles"]) == {"cline", "second"}  # additive
    assert data["default_profile"] == "cline"  # default preserved
    assert data["profiles"]["cline"]["model"] == "cline-pass/mimo-v2.5-pro"  # untouched
    assert oct((d / "ai_config.json").stat().st_mode & 0o777) == "0o600"


def test_save_blocked_on_env_override(tmp_path, monkeypatch):
    _isolate(tmp_path, monkeypatch)
    monkeypatch.setenv("CTI_AI_CONFIG", json.dumps({"profiles": {"a": {}}}))
    ok, info = ap.save_profile("b", {"provider": "ollama",
                                     "base_url": "http://127.0.0.1:11434", "model": "m"})
    assert not ok and "CTI_AI_CONFIG" in str(info)


def test_delete_keeps_default_valid(tmp_path, monkeypatch):
    d = _isolate(tmp_path, monkeypatch)
    seed = {"default_profile": "cline",
            "profiles": {"cline": {"provider": "ollama", "base_url": "http://127.0.0.1:11434",
                                   "model": "a"},
                         "extra": {"provider": "ollama", "base_url": "http://127.0.0.1:11434",
                                   "model": "b"}}}
    (d / "ai_config.json").write_text(json.dumps(seed))
    ok, info = ap.delete_profile("extra")
    assert ok, info
    data = json.loads((d / "ai_config.json").read_text())
    assert set(data["profiles"]) == {"cline"}
    ok, info = ap.delete_profile("cline")
    assert not ok  # last profile protected


def test_env_single_additive_and_file_wins(tmp_path, monkeypatch):
    d = _isolate(tmp_path, monkeypatch)
    seed = {"default_profile": "cline",
            "profiles": {"cline": {"provider": "openai-compatible",
                                   "base_url": "https://api.cline.bot/api/v1",
                                   "model": "cline-pass/mimo-v2.5-pro"}}}
    (d / "ai_config.json").write_text(json.dumps(seed))
    # loopback ollama avoids DNS-dependent URL validation in sandboxes
    monkeypatch.setenv("CTI_AI_PROVIDER", "ollama")
    monkeypatch.setenv("CTI_AI_BASE_URL", "http://127.0.0.1:11434")
    monkeypatch.setenv("CTI_AI_MODEL", "env-model")
    monkeypatch.setenv("CTI_AI_PROFILE_NAME", "envprof")
    profiles, default = ap.load_profiles()
    assert "cline" in profiles and "envprof" in profiles
    assert default == "cline"  # file default wins
    # file wins on name clash
    monkeypatch.setenv("CTI_AI_PROFILE_NAME", "cline")
    profiles2, _ = ap.load_profiles()
    assert profiles2["cline"]["model"] == "cline-pass/mimo-v2.5-pro"


def test_capabilities_reason_present(monkeypatch):
    monkeypatch.delenv("HERMES_CUSTOM_API_CLINE_BOT_API_KEY", raising=False)
    caps = ap.get_capabilities()
    assert "profiles" in caps
