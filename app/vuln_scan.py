"""vuln_scan.py — host-based vulnerability lookup (passive default, active gated).

C1 (passive CVE map): match stored/fresh fingerprints' {product, version}
  against the vendored cve_data.json map via cve_match (offline, $0).
C2 (passive config audit): version disclosure, missing security headers,
  TLS cert issues — all from already-captured or freshly fingerprinted data.
C3 (active, fail-closed): light banner re-grab on a finding's own IP/port
  only when explicitly requested AND CTI_VULN_* gates pass. No exploits.

Scope safety: targets must already belong to the org (stored fingerprints /
findings targets, or subdomains of registered org domains). Out-of-scope
targets are rejected before any network. New findings persist only when
genuinely new (same dedup as scans); a full report is always returned.
"""
import concurrent.futures as _cf
import json
import os
import re
import time
from urllib.parse import urlsplit

import cve_match
import scanner
import cti_correlation as cc

_SLUG_RE = re.compile(r"^[a-z0-9-]{1,32}$")
MAX_TARGETS = 20
VALID_CHECKS = ("cve", "version", "headers", "tls", "login")
DEFAULT_CHECKS = ("cve", "version", "headers", "tls")


def _emit(cb, stage, msg):
    try:
        if cb:
            cb(stage, msg)
    except Exception:
        pass


def _log(level, message):
    try:
        scanner._log(level, message)
    except Exception:
        pass


def _vuln_active_authorization_error(org):
    """Fail-closed gate for C3 active re-checks (mirrors OpenHack pattern)."""
    if os.environ.get("CTI_VULN_ACTIVE") != "1":
        return "CTI_VULN_ACTIVE must equal 1"
    if os.environ.get("CTI_VULN_ISOLATED") != "1":
        return "CTI_VULN_ISOLATED must equal 1"
    raw = os.environ.get("CTI_VULN_ALLOWED_DOMAINS")
    if raw is None or not raw.strip():
        return "CTI_VULN_ALLOWED_DOMAINS is missing or empty"
    allowed = set()
    for item in raw.split(","):
        d = str(item or "").strip().lower().rstrip(".")
        if not d or not scanner._is_valid_domain(d):
            return "CTI_VULN_ALLOWED_DOMAINS contains an invalid domain"
        allowed.add(d)
    targets = org.get("domains") if isinstance(org, dict) else None
    if not isinstance(targets, list) or not targets:
        return "the organization has no registered target domains"
    for target in targets:
        d = str(target or "").strip().lower().rstrip(".")
        if not scanner._is_valid_domain(d):
            return "the organization has an invalid registered target domain"
        if d not in allowed:
            return "registered target domain outside CTI_VULN_ALLOWED_DOMAINS"
    from datetime import datetime, timezone
    raw_expiry = os.environ.get("CTI_VULN_ROE_EXPIRES", "")
    try:
        stamp = str(raw_expiry or "").strip()
        if stamp.endswith(("Z", "z")):
            stamp = stamp[:-1] + "+00:00"
        expires = datetime.fromisoformat(stamp)
        if expires.tzinfo is None or expires.utcoffset() is None:
            return "CTI_VULN_ROE_EXPIRES must be timezone-aware RFC3339/ISO-8601"
        if expires.astimezone(timezone.utc) <= datetime.now(timezone.utc):
            return "CTI_VULN_ROE_EXPIRES is expired"
    except (TypeError, ValueError, OverflowError):
        return "CTI_VULN_ROE_EXPIRES is not a valid RFC3339/ISO-8601 timestamp"
    return None


def _load_store(slug):
    fp = cc.org_findings_path(slug)
    try:
        with open(fp) as f:
            d = json.load(f)
    except Exception as e:
        return None, f"findings store unreadable: {type(e).__name__}"
    if not isinstance(d, dict):
        return None, "findings store corrupted"
    meta = d.get("meta") if isinstance(d.get("meta"), dict) else {}
    snippets = meta.get("fingerprints") if isinstance(meta.get("fingerprints"), dict) else {}
    services = meta.get("services") if isinstance(meta.get("services"), dict) else {}
    findings = d.get("findings") if isinstance(d.get("findings"), list) else []
    return {"raw": d, "meta": meta, "snippets": snippets,
            "services": services, "findings": findings, "path": fp}, ""


def _known_hosts(store):
    known = set()
    for h in (store["snippets"] or {}):
        known.add(str(h).strip().lower())
    for f in (store["findings"] or []):
        try:
            t = str((f or {}).get("target", "")).strip().lower()
            if t:
                known.add(t)
        except Exception:
            continue
    return known


def _in_scope(target, org_domains, known):
    t = str(target or "").strip().lower()
    if not t or not scanner._is_valid_domain(t):
        return False
    if t in known:
        return True
    for d in org_domains or []:
        dd = str(d or "").strip().lower().rstrip(".")
        if t == dd or t.endswith("." + dd):
            return True
    return False


def _registered_org_domain(target, org_domains):
    """Strict active-scan scope: cached state never expands registered scope."""
    t = str(target or "").strip().lower().rstrip(".")
    for domain in org_domains or []:
        d = str(domain or "").strip().lower().rstrip(".")
        if d and (t == d or t.endswith("." + d)):
            return True
    return False


def _canonical_nuclei_url(host, snippet):
    """Build a safe Nuclei input from an exact scoped hostname.

    Stored fingerprint URLs are evidence, not egress authority. Preserve a
    scheme and non-default port only when their parsed host exactly matches the
    approved hostname; discard userinfo, path, query, and fragments.
    """
    host = str(host or "").strip().lower().rstrip(".")
    scheme, port = "https", None
    raw = str((snippet or {}).get("url") or "").strip()
    try:
        parsed = urlsplit(raw)
        parsed_host = (parsed.hostname or "").strip().lower().rstrip(".")
        parsed_scheme = parsed.scheme.lower()
        if (parsed_scheme in ("http", "https") and parsed_host == host
                and not parsed.username and not parsed.password):
            scheme = parsed_scheme
            candidate_port = parsed.port
            if candidate_port and candidate_port != (443 if scheme == "https" else 80):
                port = candidate_port
    except (TypeError, ValueError, AttributeError):
        pass
    authority = host if port is None else f"{host}:{port}"
    return f"{scheme}://{authority}"


def vuln_scan_org(slug, targets=None, checks=None, refresh=True,
                  include_nvd=False, active=False, on_progress=None,
                  engine="passive", nuclei_severity=None, nuclei_tags=None):
    """Run a host-scoped vuln lookup. Returns a stats dict (never raises fatally)."""
    slug = str(slug or "").strip()
    if not _SLUG_RE.match(slug):
        return {"slug": slug, "error": "invalid slug"}
    org = cc.org_get(slug)
    if org is None:
        return {"slug": slug, "error": "org not found"}
    org_domains = [str(d).strip().lower() for d in (org.get("domains") or [])]

    store, err = _load_store(slug)
    if store is None:
        return {"slug": slug, "error": err}

    # normalize checks
    if checks is None:
        checks = list(DEFAULT_CHECKS)
    norm_checks = []
    for c in checks or []:
        cc_ = str(c or "").strip().lower()
        if cc_ in VALID_CHECKS and cc_ not in norm_checks:
            norm_checks.append(cc_)
    if not norm_checks:
        norm_checks = list(DEFAULT_CHECKS)

    # normalize targets
    known = _known_hosts(store)
    if targets:
        scope = []
        for t in targets:
            tt = str(t or "").strip().lower().rstrip(".")
            if not tt or tt in scope:
                continue
            if not scanner._is_valid_domain(tt):
                return {"slug": slug, "error": f"invalid target: {t}"}
            if not _in_scope(tt, org_domains, known):
                return {"slug": slug, "error": f"target out of scope for org: {tt}"}
            scope.append(tt)
        scope = scope[:MAX_TARGETS]
        if not scope:
            return {"slug": slug, "error": "no valid targets"}
    else:
        scope = sorted(known)[:MAX_TARGETS]
        if not scope:
            return {"slug": slug, "error": "no fingerprinted hosts yet — run Scan (full) first",
                    "targets": [], "checks": norm_checks, "new_findings": 0}

    if active:
        gate = _vuln_active_authorization_error(dict(org, slug=slug))
        if gate:
            return {"slug": slug, "error": "active assessment denied: " + gate,
                    "targets": scope, "checks": norm_checks}

    # engine selection: nuclei is active probing -> same fail-closed gate
    engine = str(engine or "passive").strip().lower()
    if engine not in ("passive", "nuclei"):
        return {"slug": slug, "error": "invalid engine (passive|nuclei)",
                "targets": scope, "checks": norm_checks}
    import nuclei_scan as _nuc
    nuc_sev, nuc_tags, nuc_err = [], [], ""
    if engine == "nuclei":
        gate = _vuln_active_authorization_error(dict(org, slug=slug))
        if gate:
            return {"slug": slug, "error": "nuclei engine denied: " + gate,
                    "targets": scope, "checks": norm_checks, "engine": engine}
        outside_registered = [h for h in scope if not _registered_org_domain(h, org_domains)]
        if outside_registered:
            return {"slug": slug,
                    "error": "nuclei target outside registered org domain: " + outside_registered[0],
                    "targets": scope, "checks": norm_checks, "engine": engine}
        nuc_sev, nuc_tags, nuc_err = _nuc.normalize_options(nuclei_severity, nuclei_tags)
        if nuc_err:
            return {"slug": slug, "error": nuc_err,
                    "targets": scope, "checks": norm_checks, "engine": engine}
        st = _nuc.engine_status()
        if not st["available"]:
            return {"slug": slug, "error": "nuclei engine unavailable: " + st["reason"],
                    "targets": scope, "checks": norm_checks, "engine": engine}

    snippets = dict(store["snippets"] or {})
    refreshed = []
    # passive refresh: re-fingerprint explicitly requested hosts that lack data
    if refresh and scope:
        need = [h for h in scope
                if h not in snippets or not isinstance(snippets[h], dict)
                or (not snippets[h].get("versions") and not snippets[h].get("server")
                    and not snippets[h].get("code"))]
        if need:
            _emit(on_progress, "fingerprint", f"refreshing {len(need)} host(s)")
            try:
                with _cf.ThreadPoolExecutor(max_workers=min(8, len(need))) as ex:
                    futs = {ex.submit(scanner._fetch_fingerprint, h, 8, None): h for h in need}
                    for fut in _cf.as_completed(futs):
                        h = futs[fut]
                        try:
                            _probe, snippet = fut.result()
                        except Exception:
                            _probe, snippet = None, None
                        if snippet:
                            snippets[h] = snippet
                            refreshed.append(h)
            except Exception as e:
                _log("warn", f"vuln fingerprint refresh failed for {slug}: {e}")

    # C3 active: light banner re-grab on finding's own IP/port only (no exploits)
    active_evidence = {}
    if active and scope:
        _emit(on_progress, "active", f"light banner re-check on {len(scope)} host(s)")
        by_target = {}
        for f in (store["findings"] or []):
            try:
                t = str((f or {}).get("target", "")).strip().lower()
                if t in scope and t not in by_target:
                    by_target[t] = f
            except Exception:
                continue
        for h in scope:
            f = by_target.get(h) or {}
            ip = f.get("ip")
            try:
                port = int(f.get("port") or 0)
            except Exception:
                port = 0
            if not ip or not port or not (1 <= port <= 65535):
                continue
            try:
                banner = scanner._grab_banner(ip, port, "", h, timeout=4)
                if banner:
                    active_evidence[h] = banner[:500]
            except Exception:
                continue

    filt = {h: snippets[h] for h in scope if h in snippets and isinstance(snippets[h], dict)}
    if not filt:
        return {"slug": slug, "targets": scope, "checks": norm_checks,
                "engine": engine,
                "new_findings": 0, "total_findings": len(store["findings"] or []),
                "refreshed": refreshed,
                "note": "no fingerprint data for targets — run Scan (full) first"}

    new_all = []
    # optional NVD context for CVE matches (fail-open, capped)
    nvd_extra = {}
    if include_nvd and "cve" in norm_checks and filt:
        _emit(on_progress, "nvd", "enriching matched CVEs")
        try:
            cap = max(1, min(20, int(os.environ.get("CTI_NVD_MAX_LOOKUPS", 20) or 20)))
        except Exception:
            cap = 20
        try:
            nvd_extra = cve_match.nvd_enrich_hosts(filt, cap, on_progress=None) or {}
        except Exception as e:
            _log("warn", f"vuln NVD enrich failed for {slug}: {e}")
            nvd_extra = {}

    # certs for TLS check (stdlib handshake, same as scans)
    certs = {}
    if "tls" in norm_checks and filt:
        _emit(on_progress, "tls", f"inspecting TLS on {len(filt)} host(s)")
        targets_tls = [h for h, s in filt.items()
                       if str(s.get("url") or "").startswith("https://")]
        try:
            with _cf.ThreadPoolExecutor(max_workers=min(8, max(1, len(targets_tls)))) as ex:
                futs = {ex.submit(scanner._tls_cert, h, None, 443, 6): h for h in targets_tls}
                for fut in _cf.as_completed(futs):
                    h = futs[fut]
                    try:
                        c = fut.result()
                    except Exception:
                        c = None
                    if c:
                        c["port"] = 443
                        certs[h] = c
        except Exception as e:
            _log("warn", f"vuln TLS inspect failed for {slug}: {e}")

    _emit(on_progress, "match", f"matching {len(filt)} host(s): {','.join(norm_checks)}")
    builders = []
    if "cve" in norm_checks:
        builders.append(("cve", lambda: scanner.synthesize_cve_findings(slug, filt, nvd=nvd_extra)))
    if "version" in norm_checks:
        builders.append(("version", lambda: scanner.synthesize_version_findings(slug, filt)))
    if "headers" in norm_checks:
        builders.append(("headers", lambda: scanner.synthesize_header_findings(slug, filt)))
    if "login" in norm_checks:
        builders.append(("login", lambda: scanner.synthesize_login_findings(slug, filt)))
    if "tls" in norm_checks:
        builders.append(("tls", lambda: scanner.synthesize_cert_findings(slug, certs)))
    for _cname, fn in builders:
        try:
            extra = fn() or []
            if extra:
                new_all.extend(extra)
        except Exception as e:
            _log("warn", f"vuln {_cname} synthesis failed for {slug}: {type(e).__name__}: {e}")

    # retag provenance to vuln-scan + attach active evidence (no dupes).
    # nuclei findings keep their own source/identity (set by the mapper).
    for f in new_all:
        try:
            if str(f.get("source", "")).startswith("scan-"):
                f["source"] = "vuln-scan"
            if active_evidence.get(f.get("target", "").strip().lower()):
                ev = f.get("evidence")
                if isinstance(ev, dict):
                    ev["active_banner"] = active_evidence[f["target"].strip().lower()]
                pc = f.get("proof_chain") or []
                pc.append("vuln-scan active banner re-check (own IP/port only)")
                f["proof_chain"] = pc
            if not f.get("identity_key"):
                f["identity_key"] = cc.identity_key(f)
        except Exception:
            continue

    # nuclei phase (active, gated above): template probes over in-scope URLs
    nuc_summary = {}
    if engine == "nuclei" and filt:
        import shutil
        urls = []
        for h in scope:
            s = filt.get(h) or {}
            urls.append(_canonical_nuclei_url(h, s))
        urls = urls[:MAX_TARGETS]
        _emit(on_progress, "nuclei", f"probing {len(urls)} target(s) with nuclei templates")
        workdir, ofile, run_err = _nuc.run_scan(urls, nuc_sev, nuc_tags,
                                                _nuc.run_timeout(),
                                                on_progress=on_progress)
        try:
            if run_err:
                nuc_summary = {"error": run_err}
                _log("warn", f"nuclei run failed for {slug}: {run_err}")
            elif ofile:
                mapped = _nuc.parse_output_file(ofile, slug, org_domains)
                nuc_summary = {"matched": len(mapped)}
                if mapped:
                    new_all.extend(mapped)
        finally:
            try:
                if workdir:
                    shutil.rmtree(workdir, ignore_errors=True)
            except Exception:
                pass

    # persist genuinely new findings + refreshed fingerprints atomically
    persisted = 0
    if new_all or refreshed:
        try:
            with open(store["path"]) as fh:
                current = json.load(fh)
            if not isinstance(current, dict):
                raise ValueError("corrupted findings store")
            cur_list = current.get("findings") if isinstance(current.get("findings"), list) else []
            seen = set()
            for x in cur_list:
                try:
                    ik = (x or {}).get("identity_key") or cc.identity_key(x)
                    seen.add(ik)
                    seen.add((str((x or {}).get("target", "")).strip().lower(),
                              str((x or {}).get("category", "")).strip().lower()))
                except Exception:
                    continue
            fresh = []
            for f in new_all:
                try:
                    ik = f.get("identity_key") or cc.identity_key(f)
                    tk = (str(f.get("target", "")).strip().lower(),
                          str(f.get("category", "")).strip().lower())
                    if ik in seen or tk in seen:
                        continue
                    seen.add(ik)
                    seen.add(tk)
                    fresh.append(f)
                except Exception:
                    continue
            if fresh:
                current["findings"] = cur_list + fresh
                persisted = len(fresh)
            meta = current.get("meta") if isinstance(current.get("meta"), dict) else {}
            fps = meta.get("fingerprints") if isinstance(meta.get("fingerprints"), dict) else {}
            for h in refreshed:
                if h in snippets:
                    fps[h] = snippets[h]
            meta["fingerprints"] = fps
            meta["vuln_scan"] = {"date": time.strftime("%Y-%m-%d"),
                                 "targets": scope, "checks": norm_checks,
                                 "engine": engine,
                                 "new": persisted, "refreshed": refreshed,
                                 "nvd_enriched": len(nvd_extra),
                                 "nuclei": nuc_summary}
            current["meta"] = meta
            cc._atomic_write_json(store["path"], current)
            cc.invalidate_org_cache(slug)
        except Exception as e:
            return {"slug": slug, "targets": scope, "checks": norm_checks,
                    "error": f"persist failed: {type(e).__name__}: {e}",
                    "candidates": len(new_all), "refreshed": refreshed,
                    "engine": engine}
        try:
            scanner.append_history(slug, {"kind": "vuln-scan",
                                          "summary": {"targets": len(scope), "new": persisted,
                                                      "checks": norm_checks, "engine": engine,
                                                      "nuclei": nuc_summary},
                                          "note": f"vuln lookup on {len(scope)} host(s) [{engine}]"})
        except Exception:
            pass

    return {"slug": slug, "targets": scope, "checks": norm_checks,
            "engine": engine,
            "new_findings": persisted, "candidates": len(new_all),
            "total_findings": len(store["findings"] or []) + persisted,
            "refreshed": refreshed, "nvd_enriched": len(nvd_extra),
            "nuclei": nuc_summary,
            "active": bool(active)}
