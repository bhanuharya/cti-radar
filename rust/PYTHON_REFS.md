# Python reference excerpts (app/main.py, feat/rust-rewrite)

## routes mount + static (66-68)
```python
60:    if _migrated:
61:        print(f"[cti] tightened permissions on {_migrated} data path(s)", file=sys.stderr)
62:except Exception as _perm_err:  # pragma: no cover
63:    print(f"[cti] permission migration skipped: {_perm_err}", file=sys.stderr)
64:
65:# serve vendored static assets (vis-network) from app/static/
66:_STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
67:if os.path.isdir(_STATIC_DIR):
68:    app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")
69:
70:# thresholded gzip for sufficiently large responses — stdlib only, no extra dep
71:app.add_middleware(GZipMiddleware, minimum_size=1024)
72:
73:# bounded executor + per-org job deduplication (P0: serialize mutations)
74:import uuid as _uuid
75:from concurrent.futures import ThreadPoolExecutor as _ThreadPoolExecutor
```

## busy cap 429 (130-136)
```python
120:        jid = f"{slug}-{kind}-{_uuid.uuid4().hex[:8]}"
121:        entry = {"id": jid, "started": time.time(), "kind": kind,
122:                 "status": "running", "stage": "queued", "progress": "",
123:                 "error": None}
124:        if stale_after:
125:            entry["stale_after"] = int(stale_after)
126:        _jobs[key] = entry
127:        return True, jid
128:
129:
130:def _job_busy_response(slug, kind, jid):
131:    """409 when this org has a running job; 429 when the global cap is hit."""
132:    if jid:
133:        return JSONResponse({"error": f"{kind} already running", "slug": slug,
134:                             "job_id": jid}, status_code=409)
135:    return JSONResponse({"error": f"{kind} rejected: server busy (max {_MAX_ACTIVE_JOBS} active jobs)",
136:                         "slug": slug, "job_id": None}, status_code=429)
137:
138:
139:def _release_job(slug, kind, jid, error=None, result=None):
140:    key = _job_key(slug, kind)
```

## unknown job 404 (273-275)
```python
265:    if isinstance(report, dict) and report.get("error"):
266:        return str(report["error"])
267:    return None
268:
269:
270:def _job_status(slug, kind, job_id, running=None):
271:    """Return status only for this exact org, kind, and job id."""
272:    job = _get_job(slug, kind, job_id)
273:    if job is None:
274:        return JSONResponse({"error": "unknown job", "job_id": job_id,
275:                             "slug": slug, "kind": kind}, status_code=404)
276:    payload = {"status": job.get("status", "failed"), "job_id": job_id}
277:    for key in ("stage", "progress", "error", "started", "finished"):
278:        if job.get(key) is not None:
279:            payload[key] = job[key]
280:    if isinstance(job.get("result"), dict):
```

## auth/session (364,389,490-516)
```python
355:        exp = _SESSIONS.get(sid)
356:        if exp and _t.time() <= exp:
357:            return True
358:        if exp:
359:            _SESSIONS.pop(sid, None)
360:    # (2) static API token for scripted/CI scans (constant-time compare)
361:    import secrets as _s
362:    tok = os.environ.get("CTI_SCAN_TOKEN", "")
363:    supplied = req.headers.get("X-CTI-Token") or ""
364:    if tok and supplied and _s.compare_digest(tok, supplied):
365:        return True
366:    return False
367:
368:
369:def _login_ok(body_or_req):
370:    """Validate username/password; on success issue a session id (stored in
371:    _SESSIONS) which the login handler sets as an HttpOnly cookie."""
372:    import base64
373:    import secrets as _secrets
374:    import time as _t
375:    u = os.environ.get("CTI_USER", "")
376:    p = os.environ.get("CTI_PASSWORD", "")
377:    if not u or not p:
378:        return None
379:    auth = getattr(body_or_req, "headers", {}).get("Authorization", "") if hasattr(body_or_req, "headers") else ""
380:    if not auth.startswith("Basic "):
381:        return None
382:    try:
383:        raw = base64.b64decode(auth[6:].strip()).decode("utf-8", "replace")
384:    except Exception:
385:        return None
386:    if ":" not in raw:
387:        return None
388:    gu, gp = raw.split(":", 1)
389:    if not (_secrets.compare_digest(gu, u) and _secrets.compare_digest(gp, p)):
390:        return None
391:    sid = _secrets.token_urlsafe(32)
392:    _SESSIONS[sid] = _t.time() + _SESSION_TTL
393:    return sid
394:
395:
```

## findings envelope (584)
```python
575:        nf = [f for f in nf if str(f.get("status", "OPEN")).upper() == status.upper()]
576:    if sort == "severity":
577:        nf.sort(key=lambda f: _SEV_ORDER.get(
578:            str(f.get("severity", "INFO")).upper(), 99))
579:    elif sort in ("newest", "oldest"):
580:        dated = [f for f in nf if f.get("found_date")]
581:        undated = [f for f in nf if not f.get("found_date")]
582:        dated.sort(key=lambda f: f.get("found_date"), reverse=(sort == "newest"))
583:        nf = dated + undated
584:    return {"findings_total": len(nf), "findings": nf}
585:
586:
587:def _build_dashboard_payload(org: str, sort: str = None, status: str = "all"):
588:    """Aggregate dashboard payload reusing ONE findings/correlation load per request.
589:
590:    Returns shapes identical to /api/summary, /api/graph, /api/fleet, /api/ips,
591:    /api/findings (filtered/sorted), and /api/orgs/{slug}/history. Uses the
592:    read-through cache in cti_correlation so repeated views avoid disk reads.
593:    """
594:    fs, baseline = cc.load_data(org)
595:    meta_date = cc.load_meta_date(org)
```

## dashboard envelope (637-646)
```python
625:        scan_info = {
626:            "date": meta.get("date"),
627:            "domains": len((cc.REGISTRY.get(org) or {}).get("domains") or []),
628:            "subdomains": meta.get("subdomains"),
629:            "reachable": meta.get("reachable"),
630:            "reconcile": (meta.get("reconcile") or {}).get("observed")
631:            if isinstance(meta.get("reconcile"), dict) else None,
632:            "stages": {k: scan_stats.get(k) for k in
633:                       ("enum", "resolve", "probe", "services", "tls", "nvd", "total")
634:                       if scan_stats.get(k) is not None},
635:        }
636:
637:    return {
638:        "org": org,
639:        "summary": cc.summary_from_data(fs, baseline),
640:        "graph": cc.build_graph_from_data(fs, baseline, domains),
641:        "fleet": cc.fleet_spread_from_data(fs),
642:        "ips": cc.ip_sharing_from_data(fs),
643:        "findings": {"findings_total": len(nf), "findings": nf},
644:        "history": history,
645:        "scan_info": scan_info,
646:    }
647:
648:
649:@app.get("/api/dashboard")
650:def api_dashboard(org: str = _DEFAULT_ORG, sort: str = None, status: str = "all", req: Request = None):
```

## finding detail (674)
```python
665:@app.get("/api/findings/{id_}")
666:def api_finding_detail(id_: str, org: str = _DEFAULT_ORG, req: Request = None):
667:    err = _read_auth(req, org)
668:    if err:
669:        return err
670:    f = cc.find_finding(org, id_)
671:    if f is None:
672:        return JSONResponse({"error": "finding not found", "id": id_, "org": org},
673:                            status_code=404)
674:    return {"org": org, "finding": cc.normalize_finding(f, org)}
675:
676:
677:@app.get("/api/orgs")
678:def api_orgs(req: Request = None):
679:    if not _auth_ok(req):
680:        return JSONResponse({"error": "unauthorized"}, status_code=401)
```

## orgs envelope (681) + admin logs (684-694)
```python
680:        return JSONResponse({"error": "unauthorized"}, status_code=401)
681:    return {"orgs": cc.org_list()}
682:
683:
684:@app.get("/api/admin/logs")
685:def api_admin_logs(org: str = None, limit: int = 200, req: Request = None):
686:    """Recent runtime logs (scan/recheck/correlate/AI attempts + failures)."""
687:    if not _auth_ok(req):
688:        return JSONResponse({"error": "unauthorized"}, status_code=401)
689:    lim = max(1, min(int(limit or 200), 1000))
690:    with _JOB_LOG_LOCK:
691:        logs = list(_JOB_LOGS[-lim:])
692:    if org:
693:        logs = [l for l in logs if l.get("org") == org][-lim:]
694:    return {"logs": logs[::-1], "total": len(logs)}
695:
696:
697:@app.get("/api/orgs/{slug}")
698:def api_org_get(slug: str, req: Request = None):
699:    err, org = _require_org(slug, req)
700:    if err:
```

## openhack gates (817-831,837,865,878)
```python
810:        return JSONResponse({"error": "invalid model id"}, status_code=400)
811:    model = (model
812:             or (cc.org_get(slug) or {}).get("openhack_model")
813:             or oh.OHACK_PREFERRED_MODEL)   # ox-alpha: proven runnable default
814:    org = cc.org_get(slug)
815:    if org is None:
816:        return _org_not_found(slug)
817:    if not org.get("openhack_enabled"):
818:        return JSONResponse(
819:            {"error": ("openhack source not enabled for this org — "
820:                       "POST /api/orgs/%s/openhack-config {\"enabled\": true}" % slug)},
821:            status_code=403)
822:    # This is immediately before acquisition: no binary lookup or worker can
823:    # occur until the operator gate, exact target scope, and live ROE pass.
824:    gate_error = _openhack_authorization_error(org)
825:    if gate_error:
826:        return JSONResponse(
827:            {"error": "OpenHack active assessment authorization denied: " + gate_error},
828:            status_code=403)
829:    if not oh.openhack_bin():
830:        return JSONResponse({"error": "openhack binary not available "
831:                                      "(set explicit absolute CTI_OPENHACK_BIN)"}, status_code=503)
832:    if mode == "quick":
833:        stale_after = oh.quick_budget() + 600
834:    else:
835:        stale_after = int(oh._env_float("CTI_OHACK_TIMEOUT", 1800, lo=60,
836:                                        hi=7200)) + 600
837:    ok, jid = _try_acquire_job(slug, "ohack", stale_after=stale_after)
838:    if not ok:
839:        return _job_busy_response(slug, "openhack-scan", jid)
840:    domains = list(org.get("domains") or [])
841:    _log_event("info", "openhack", slug,
842:               f"openHack {mode} queued ({len(domains)} domain(s))", job_id=jid)
843:
844:    def _on_progress(stage, message):
845:        _job_progress(slug, "ohack", jid, stage, message)
846:
847:    def _oh_wrap():
848:        try:
849:            result = oh.run_and_ingest(slug, domains, on_progress=_on_progress,
850:                                       mode=mode, model=model or None)
851:            err = result.get("error") if isinstance(result, dict) else None
852:            if err:
853:                _release_job(slug, "ohack", jid, error=err)
854:                _log_event("error", "openhack", slug, f"openHack failed: {err}", job_id=jid)
855:            else:
856:                _release_job(slug, "ohack", jid)
857:                _log_event("info", "openhack", slug,
858:                           f"openHack {mode} done (+{result.get('added', 0)} new,"
859:                           f" {result.get('graded', 0)} graded)", job_id=jid)
860:        except Exception as e:
861:            _release_job(slug, "ohack", jid, error=e)
862:            _log_event("error", "openhack", slug, f"openHack failed: {e}", job_id=jid)
863:
864:    _executor.submit(_oh_wrap)
865:    return {"queued": True, "slug": slug, "mode": mode, "job_id": jid}
866:
867:
868:@app.get("/api/orgs/{slug}/openhack-scan/{job_id}")
869:def api_openhack_status(slug: str, job_id: str, req: Request = None):
870:    err, _ = _require_org(slug, req)
871:    if err:
872:        return err
873:    running = False
874:    key = _job_key(slug, "ohack")
875:    with _jobs_lock:
876:        v = _jobs.get(key)
877:        running = bool(v and v.get("status") == "running" and v.get("id") == job_id)
878:    return _job_status(slug, "ohack", job_id, running)
879:
880:
```

## register/orgs path (984-992)
```python
975:        corrupted = False
976:        if os.path.exists(ORGS_JSON):
977:            try:
978:                with open(ORGS_JSON) as f:
979:                    registry = json.load(f)
980:                if not isinstance(registry, dict):
981:                    corrupted = True
982:            except Exception:
983:                corrupted = True
984:        if corrupted:
985:            return JSONResponse({"error": "registry corrupted, aborting"}, status_code=500)
986:        if slug in registry:
987:            return JSONResponse({"error": "org already registered", "slug": slug}, status_code=409)
988:        registry[slug] = {
989:            "name": name,
990:            "domains": domains,
991:            "findings": f"data/orgs/{slug}/findings.json",
992:            "baseline": f"data/orgs/{slug}/baseline.txt",
993:        }
994:        cc._atomic_write_json(ORGS_JSON, registry)
995:    cc._reload_registry()
996:
997:    # filesystem creation after successful registry commit (with cleanup on failure)
998:    try:
999:        org_dir = os.path.join(DATA_ORG_DIR, slug)
1000:        os.makedirs(org_dir, mode=0o700, exist_ok=True)
```

## history order (1209)
```python
1200:def api_org_history(slug: str, req: Request = None):
1201:    err, _ = _require_org(slug, req)
1202:    if err:
1203:        return err
1204:    events = scanner.read_history(slug)
1205:    by_kind = {}
1206:    for e in events:
1207:        k = e.get("kind", "?")
1208:        by_kind[k] = by_kind.get(k, 0) + 1
1209:    return {"org": slug, "events": events[::-1][:100],
1210:            "summary": {"total": len(events), "by_kind": by_kind}}
1211:
1212:
1213:class StatusBody(BaseModel):
1214:    status: str
1215:    note: str = ""
```

## status/comment full finding (1237,1265)
```python
1230:                            status_code=400)
1231:    finding, err = cc.set_finding_status(slug, id_, status, note=(body.note or "").strip())
1232:    if err:
1233:        if err == "not found":
1234:            return JSONResponse({"error": "finding not found", "id": id_}, status_code=404)
1235:        return JSONResponse({"error": err}, status_code=400)
1236:    _log_event("info", "status", slug, f"finding {id_} status -> {status}")
1237:    return {"org": slug, "finding": cc.normalize_finding(finding, slug)}
1238:
1239:
1240:class CommentBody(BaseModel):
1241:    note: str
1242:    by: str = ""
1243:
1244:
1245:@app.post("/api/orgs/{slug}/findings/{id_}/comment")
1246:def api_finding_comment(slug: str, id_: str, body: CommentBody, req: Request):
1247:    """Append an analyst comment to a finding; this feedback is weighed by the
1248:    AI triage pass on the next `mode=ai` scan of the org."""
1249:    if not _auth_ok(req):
1250:        return JSONResponse({"error": "unauthorized: missing or bad credentials (username/password)"},
1251:                            status_code=401)
1252:    if not _valid_slug(slug):
1253:        return JSONResponse({"error": "invalid slug"}, status_code=400)
1254:    if cc.org_get(slug) is None:
1255:        return _org_not_found(slug)
1256:    note = (body.note or "").strip()
1257:    if not note:
1258:        return JSONResponse({"error": "note is required"}, status_code=400)
1259:    finding, err = cc.add_finding_comment(slug, id_, note, by=(body.by or "").strip())
1260:    if err:
1261:        if err == "not found":
1262:            return JSONResponse({"error": "finding not found", "id": id_}, status_code=404)
1263:        return JSONResponse({"error": err}, status_code=400)
1264:    _log_event("info", "comment", slug, f"finding {id_} commented (analyst feedback)")
1265:    return {"org": slug, "finding": cc.normalize_finding(finding, slug)}
1266:
1267:
1268:@app.post("/api/orgs/{slug}/correlate")
1269:def api_org_correlate(slug: str, req: Request):
1270:    if not _auth_ok(req):
```

## report caps (1487-1498)
```python
1480:
1481:@app.get("/api/orgs/{slug}/report.pdf")
1482:def api_org_report_pdf(slug: str, req: Request = None):
1483:    err, org = _require_org(slug, req)
1484:    if err:
1485:        return err
1486:    fs, _ = cc.load_data(slug)
1487:    if len(fs) > _MAX_PDF_FINDINGS:
1488:        return JSONResponse({"error": "too many findings for PDF", "max": _MAX_PDF_FINDINGS,
1489:                             "count": len(fs)}, status_code=413)
1490:    domains = org.get("domains") or []
1491:    report_html = _build_report_html(slug, org, fs, domains)
1492:    if len(report_html) > _MAX_PDF_HTML_SIZE:
1493:        return JSONResponse({"error": "report too large", "max": _MAX_PDF_HTML_SIZE}, status_code=413)
1494:    if not _CHROMIUM:
1495:        return JSONResponse(
1496:            {"error": "Chromium not found; set CTI_CHROMIUM_PATH"}, status_code=503)
1497:    if not _PDF_SEMAPHORE.acquire(blocking=False):
1498:        return JSONResponse({"error": "PDF generation busy, try again"}, status_code=503)
1499:
1500:    fd, html_path = tempfile.mkstemp(suffix=".html", prefix="cti-report-")
```
