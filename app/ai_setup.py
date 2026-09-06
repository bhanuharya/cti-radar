"""ai_setup.py — generic CLI for AI model config (no presets).

Usage:
  python -m app.ai_setup --list
  python -m app.ai_setup --wizard
  python -m app.ai_setup --check --name my-model
  python -m app.ai_setup --test --name my-model

Generic only: every field is prompted raw with no suggested URLs/models.
Existing profiles in the config file are never modified unless you save.
Secrets are never written to disk — only the env var NAME is stored.
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ai_providers as ap


def cmd_list():
    data = ap.get_profiles_for_edit()
    print(f"source: {data.get('source')}  default: {data.get('default_profile')}")
    if data.get("env_override"):
        print("NOTE: CTI_AI_CONFIG env override is active — file edits are disabled until unset.")
    for p in data.get("profiles", []):
        state = "ready" if p.get("ready") else "NOT READY"
        extra = f" — {p['reason']}" if p.get("reason") else ""
        dflt = " [default]" if p.get("default") else ""
        print(f"- {p['name']} | {p['provider']} | {p['model']} | {p.get('base_url','')}"
              f" | key={p.get('api_key_env') or '(none)'} | {state}{extra}{dflt}")


def prompt(msg, default=""):
    try:
        raw = input(f"{msg}" + (f" [{default}]" if default else "") + ": ").strip()
    except EOFError:
        return default
    return raw or default


def cmd_wizard(args):
    if ap._env_json_override_active():
        print("REFUSED: CTI_AI_CONFIG env override is active — unset it to manage file profiles.",
              file=sys.stderr)
        return 2
    print("Generic model setup (no presets). Existing profiles are preserved.")
    print(f"File: {ap.config_write_path()}")
    name = prompt("name (a-z 0-9 -, max 32)").strip().lower()
    provider = prompt("provider (ollama|openai-compatible)", "openai-compatible").strip().lower()
    base_url = prompt("base_url (https required for remote; http only for 127.0.0.1)").strip()
    model = prompt("model").strip()
    api_key_env = prompt("api_key_env (optional, e.g. MY_API_KEY)").strip()
    timeout = prompt("timeout secs (10-300)", "90")
    max_hosts = prompt("max_hosts (1-50)", "10")
    max_tokens = prompt("max_tokens (64-8192)", "1024")
    try:
        fields = {"provider": provider, "base_url": base_url, "model": model,
                  "timeout": int(timeout or 90), "max_hosts": int(max_hosts or 10),
                  "max_tokens": int(max_tokens or 1024)}
    except ValueError:
        print("REFUSED: timeout/max_hosts/max_tokens must be integers.", file=sys.stderr)
        return 2
    if api_key_env:
        fields["api_key_env"] = api_key_env
    ok, reason, _fd = ap.validate_profile_fields(name, fields)
    if not ok:
        print(f"INVALID: {reason}", file=sys.stderr)
        return 2
    if args.check:
        print(f"CHECK OK: {name} validates. (dry-run, nothing written)")
        return 0
    confirm = prompt(f"Save '{name}' (merge only, others preserved)? [y/N]", "N")
    if confirm.strip().lower() not in ("y", "yes"):
        print("Aborted (nothing written).")
        return 1
    good, info = ap.save_profile(name, fields)
    if not good:
        print(f"SAVE FAILED: {info}", file=sys.stderr)
        return 2
    print(f"Saved '{name}'. Backup written alongside config (*.bak-*).")
    if api_key_env and not os.environ.get(api_key_env, "").strip():
        print(f"NOTE: {api_key_env} is not set in this shell — export it and restart the server.")
    if args.test:
        ok_t, detail = ap.test_profile(name)
        print(json.dumps(detail, indent=2)[:2000])
        return 0 if ok_t else 3
    return 0


def cmd_check(args):
    data = ap.get_profiles_for_edit()
    names = {p["name"] for p in data.get("profiles", [])}
    if args.name and args.name not in names:
        print(f"UNKNOWN PROFILE: {args.name} (known: {sorted(names)})", file=sys.stderr)
        return 2
    print(json.dumps(data, indent=2)[:4000])
    return 0


def cmd_test(args):
    ok_t, detail = ap.test_profile(args.name or None)
    print(json.dumps(detail, indent=2)[:4000])
    return 0 if ok_t else 3


def main(argv=None):
    pr = argparse.ArgumentParser(description="Generic AI model config (no presets)")
    pr.add_argument("--list", action="store_true")
    pr.add_argument("--wizard", action="store_true")
    pr.add_argument("--check", action="store_true")
    pr.add_argument("--test", action="store_true")
    pr.add_argument("--name", default="")
    args = pr.parse_args(argv)
    if args.list or (not args.wizard and not args.check and not args.test):
        cmd_list()
        return 0
    if args.wizard:
        return cmd_wizard(args)
    if args.check:
        return cmd_check(args)
    if args.test:
        return cmd_test(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
