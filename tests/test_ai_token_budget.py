"""Tests for per-profile token budgets, cap-exhaustion retry, and partial-batch salvage."""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

import ai_providers  # noqa: E402
import scanner  # noqa: E402


# ------------------------------------------------------- profile normalization

def test_profile_max_tokens_parsed_and_clamped(monkeypatch):
    raw = {"default_profile": "p1", "profiles": {
        "p1": {"provider": "openai-compatible", "base_url": "https://api.example.com/v1",
               "model": "m", "api_key_env": "TEST_API_KEY", "max_tokens": 3072},
        "p2": {"provider": "openai-compatible", "base_url": "https://api.example.com/v1",
               "model": "m", "api_key_env": "TEST_API_KEY", "max_tokens": 99999},
        "p3": {"provider": "openai-compatible", "base_url": "https://api.example.com/v1",
               "model": "m", "api_key_env": "TEST_API_KEY", "max_tokens": 10},
    }}
    monkeypatch.setenv("CTI_AI_CONFIG", json.dumps(raw))
    monkeypatch.setenv("TEST_API_KEY", "x")
    # skip URL/DNS validation (fake hostnames) — normalization is under test
    monkeypatch.setattr(ai_providers, "_validate_base_url",
                        lambda url, provider, key_env: True)
    profiles, _ = ai_providers.load_profiles()
    assert profiles["p1"]["max_tokens"] == 3072
    assert profiles["p2"]["max_tokens"] == 8192   # clamped high
    assert profiles["p3"]["max_tokens"] == 64     # clamped low


def test_ollama_num_predict_maps_to_options(monkeypatch):
    raw = {"default_profile": "o1", "profiles": {
        "o1": {"provider": "ollama", "base_url": "http://127.0.0.1:11434",
               "model": "m", "num_predict": 2048},
    }}
    monkeypatch.setenv("CTI_AI_CONFIG", json.dumps(raw))
    profiles, _ = ai_providers.load_profiles()
    assert profiles["o1"]["options"]["num_predict"] == 2048


# ------------------------------------------------------ cap exhaustion + retry

class _FakeResp:
    def __init__(self, body):
        self._body = body.encode()
        self.status = 200
        self.headers = {"Content-Length": str(len(self._body))}

    def read(self, n=-1):
        return self._body[:n] if n > 0 else self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _empty_content_body(cap, finish=None, comp=None):
    return json.dumps({
        "choices": [{"index": 0, "message": {"role": "assistant"},
                     "finish_reason": finish}],
        "usage": {"prompt_tokens": 900,
                  "completion_tokens": cap if comp is None else comp},
    })


def _ok_body(content):
    return json.dumps({
        "choices": [{"index": 0, "finish_reason": "stop",
                     "message": {"role": "assistant", "content": content}}],
        "usage": {"prompt_tokens": 900, "completion_tokens": 50},
    })


def test_cap_exhaustion_detected_and_retried_with_doubled_cap(monkeypatch):
    posts = []

    def fake_urlopen(req, timeout=30):
        body = json.loads(req.data.decode())
        posts.append(body)
        if len(posts) == 1:
            return _FakeResp(_empty_content_body(1024, finish=None))
        return _FakeResp(_ok_body('{"results":[]}'))

    monkeypatch.setattr(ai_providers, "_urlopen_no_redirect", fake_urlopen)
    content, reasoning, diag = ai_providers._call_openai_compatible(
        "https://api.example.com/v1", "muse", "prompt", 30, None, max_tokens=1024)
    assert content == '{"results":[]}'
    assert [p["max_tokens"] for p in posts] == [1024, 2048]
    assert diag["retried_with_cap"] == 2048
    # the retry keeps structured output when the endpoint accepted it
    assert all(p.get("response_format") == {"type": "json_object"} for p in posts)


def test_cap_at_ceiling_not_retried_no_double_spend(monkeypatch):
    """A profile already at the 8192 ceiling must not re-send a duplicate."""
    posts = []

    def fake_urlopen(req, timeout=30):
        posts.append(json.loads(req.data.decode()))
        return _FakeResp(_empty_content_body(8192, finish=None))

    monkeypatch.setattr(ai_providers, "_urlopen_no_redirect", fake_urlopen)
    content, _, diag = ai_providers._call_openai_compatible(
        "https://api.example.com/v1", "muse", "prompt", 30, None, max_tokens=8192)
    assert content is None
    assert len(posts) == 1                        # no duplicate request
    assert diag["reason"] == "token_cap_exhausted"


def test_cap_retry_opt_out(monkeypatch):
    posts = []

    def fake_urlopen(req, timeout=30):
        posts.append(json.loads(req.data.decode()))
        return _FakeResp(_empty_content_body(1024, finish=None))

    monkeypatch.setattr(ai_providers, "_urlopen_no_redirect", fake_urlopen)
    content, _, diag = ai_providers._call_openai_compatible(
        "https://api.example.com/v1", "muse", "prompt", 30, None,
        max_tokens=1024, cap_retry=False)
    assert content is None
    assert len(posts) == 1
    assert diag["reason"] == "token_cap_exhausted"


def test_profile_cap_retry_flag_parsed(monkeypatch):
    raw = {"default_profile": "p1", "profiles": {
        "p1": {"provider": "openai-compatible", "base_url": "https://api.example.com/v1",
               "model": "m", "api_key_env": "TEST_API_KEY", "cap_retry": False},
    }}
    monkeypatch.setenv("CTI_AI_CONFIG", json.dumps(raw))
    monkeypatch.setenv("TEST_API_KEY", "x")
    monkeypatch.setattr(ai_providers, "_validate_base_url",
                        lambda url, provider, key_env: True)
    profiles, _ = ai_providers.load_profiles()
    assert profiles["p1"]["cap_retry"] is False


def test_cap_exhaustion_retry_also_failing_reports_reason(monkeypatch):
    def fake_urlopen(req, timeout=30):
        cap = json.loads(req.data.decode())["max_tokens"]
        return _FakeResp(_empty_content_body(cap, finish="length"))

    monkeypatch.setattr(ai_providers, "_urlopen_no_redirect", fake_urlopen)
    content, _, diag = ai_providers._call_openai_compatible(
        "https://api.example.com/v1", "muse", "prompt", 30, None, max_tokens=1024)
    assert content is None
    assert diag["reason"] == "token_cap_exhausted"
    assert diag["retried_with_cap"] == 2048


def test_empty_content_without_cap_signature_not_retried(monkeypatch):
    posts = []

    def fake_urlopen(req, timeout=30):
        posts.append(1)
        # empty content but completion tokens well below cap -> not exhaustion
        return _FakeResp(_empty_content_body(1024, finish="stop", comp=12))

    monkeypatch.setattr(ai_providers, "_urlopen_no_redirect", fake_urlopen)
    content, _, diag = ai_providers._call_openai_compatible(
        "https://api.example.com/v1", "m", "prompt", 30, None, max_tokens=1024)
    assert content is None
    assert diag.get("reason") is None            # generic no-content, no retry
    assert len(posts) == 1


# ------------------------------------------------------------------- salvage

def test_salvage_result_objects_from_truncated_json():
    raw = ('{"results":[{"target":"a.example.com","verdict":"confirm",'
           '"severity":"HIGH","reason":"x"},{"target":"b.example.com","ver')
    objs = ai_providers.salvage_result_objects(raw)
    assert len(objs) == 1                        # second object is truncated
    assert objs[0]["target"] == "a.example.com"


def test_classification_parser_salvages_truncated_batch():
    raw = ('Here are the verdicts:\n{"results":['
           '{"target":"vpn.example.com","verdict":"confirm","severity":"HIGH","reason":"rdp"},'
           '{"target":"www.example.com","verdict":"d')
    out = scanner.parse_ai_classification(raw, {"vpn.example.com", "www.example.com"})
    assert out is not None and len(out) == 1
    assert out[0]["target"] == "vpn.example.com"
    assert out[0]["verdict"] == "confirm"


def test_classification_salvage_still_enforces_target_whitelist():
    raw = '{"results":[{"target":"evil.example.net","verdict":"confirm","severity":"HIGH"}]}'
    # contract: empty list (falsy) when every item is filtered out
    assert not scanner.parse_ai_classification(raw, {"good.example.com"})


def test_grading_parser_salvages_truncated_batch():
    raw = ('{"results":['
           '{"id":"F-1","still_open":"yes","severity":"HIGH","impact":"exposed rdp"},'
           '{"id":"F-2","still_op')
    out = scanner.parse_ai_grading(raw, {"F-1", "F-2"})
    assert out == {"F-1": {"severity": "HIGH", "impact": "exposed rdp",
                           "still_open": "yes"}}


def test_grading_salvage_rejects_unknown_ids():
    raw = '{"results":[{"id":"F-999","severity":"HIGH","impact":"x"}]}'
    assert not scanner.parse_ai_grading(raw, {"F-1"})
