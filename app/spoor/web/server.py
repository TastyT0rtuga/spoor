"""Local dashboard: a small HTTP server bound to 127.0.0.1 only.

Security for a single-user evidence workstation: the server listens on loopback only, requires
a per-launch token (set as an HttpOnly SameSite=Strict cookie by the link the launcher opens),
checks the Host header (DNS-rebinding) and the Origin of every POST (cross-site requests)."""
from __future__ import annotations

import json
import mimetypes
import os
import re
import secrets
import socket
import string
import threading
import time
import traceback
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from .. import __version__
from .. import db as dbm
from ..case import Case, create_case, get_case, list_cases, register_path, source_rows
from ..config import DEFAULT_PARAMS, load_settings, merged_params, save_settings
from ..util import IS_WINDOWS, open_in_file_manager, utc_now_str

STATIC = Path(__file__).resolve().parent / "static"
TOKEN = secrets.token_urlsafe(24)
PORT = 8765
_LLM_CACHE = {"t": 0.0, "v": None}


class ApiError(Exception):
    def __init__(self, msg, code=400):
        super().__init__(msg)
        self.code = code


ROUTES: list = []


def route(method: str, pattern: str):
    rx = re.compile("^" + pattern + "$")

    def deco(fn):
        ROUTES.append((method, rx, fn))
        return fn
    return deco


def _case(slug: str) -> Case:
    try:
        return get_case(unquote(slug))
    except FileNotFoundError as e:
        raise ApiError(str(e), 404) from e


def _llm_status(force: bool = False) -> dict:
    if force or time.time() - _LLM_CACHE["t"] > 30:
        from ..llm import LLM
        _LLM_CACHE["v"] = LLM(load_settings()["llm"]).status()
        _LLM_CACHE["t"] = time.time()
    return _LLM_CACHE["v"]


# ---------------------------------------------------------------- API: global

@route("GET", r"/api/state")
def api_state(h, q, body):
    s = load_settings()
    return {"version": __version__, "cases": list_cases(s), "settings": {"display_tz": s.get("display_tz"), "llm": s["llm"],
                                                                         "cases_dir": s["cases_dir"]},
            "llm": _llm_status(), "now": utc_now_str(), "params_default": DEFAULT_PARAMS}


@route("POST", r"/api/settings")
def api_settings(h, q, body):
    s = load_settings()
    if "display_tz" in body:
        s["display_tz"] = body["display_tz"]
    for k, v in (body.get("llm") or {}).items():
        if k in s["llm"]:
            s["llm"][k] = v
    save_settings(s)
    _LLM_CACHE["t"] = 0
    return {"ok": True, "llm": _llm_status(True)}


@route("GET", r"/api/llm")
def api_llm(h, q, body):
    return _llm_status(True)


@route("POST", r"/api/cases")
def api_new_case(h, q, body):
    name = (body.get("name") or "").strip()
    if not name:
        raise ApiError("Give the case a name.")
    c = create_case(name, body.get("examiner", ""), body.get("description", ""), body.get("display_tz", ""))
    return {"slug": c.slug, "name": c.name}


@route("POST", r"/api/demo")
def api_demo(h, q, body):
    from ..selftest import make_demo_case
    try:
        c = make_demo_case(run=True)
    except FileNotFoundError as e:
        raise ApiError(str(e)) from e
    return {"slug": c.slug}


@route("GET", r"/api/fs")
def api_fs(h, q, body):
    p = (q.get("path") or [""])[0]
    if not p:
        if IS_WINDOWS:
            drives = [f"{d}:\\" for d in string.ascii_uppercase if os.path.exists(f"{d}:\\")]
            return {"path": "", "parent": None, "dirs": drives, "files": []}
        p = str(Path.home())
    path = Path(p)
    if not path.exists():
        raise ApiError(f"Not found: {p}", 404)
    if path.is_file():
        path = path.parent
    dirs, files = [], []
    try:
        for e in sorted(path.iterdir(), key=lambda x: x.name.lower()):
            if e.name.startswith(".") or e.name.startswith("$"):
                continue
            try:
                if e.is_dir():
                    dirs.append(e.name)
                else:
                    files.append({"name": e.name, "size": e.stat().st_size})
            except OSError:
                continue
    except PermissionError as ex:
        raise ApiError(f"No permission to read {path}") from ex
    parent = str(path.parent) if path.parent != path else ""
    return {"path": str(path), "parent": parent, "dirs": dirs, "files": files[:500]}


# ---------------------------------------------------------------- API: case

@route("GET", r"/api/case/([^/]+)")
def api_case(h, q, body, slug):
    c = _case(slug)
    con = c.db(readonly=True)
    try:
        from ..jobs import job_rows, status_text
        counts = {
            "sources": dbm.one(con, "SELECT COUNT(*) FROM sources WHERE status != 'container'"),
            "ingested": dbm.one(con, "SELECT COUNT(*) FROM sources WHERE status='ingested'"),
            "pending": dbm.one(con, "SELECT COUNT(*) FROM sources WHERE status IN ('new','scanned','ingesting') OR "
                                    "(status='ingested' AND ingested_rev != config_rev)"),
            "events": dbm.one(con, "SELECT COUNT(*) FROM events"),
            "findings": dbm.one(con, "SELECT COUNT(*) FROM findings WHERE fid IS NOT NULL"),
            "p1": dbm.one(con, "SELECT COUNT(*) FROM findings WHERE fid IS NOT NULL AND priority=1"),
            "asks": dbm.one(con, "SELECT COUNT(*) FROM asks"),
            "returns": dbm.one(con, "SELECT COUNT(*) FROM returns WHERE state='active'"),
            "returns_all": dbm.one(con, "SELECT COUNT(*) FROM returns WHERE state != 'removed'"),
        }
        span = con.execute("SELECT MIN(ts_utc), MAX(ts_utc) FROM events WHERE ts_epoch IS NOT NULL AND "
                           "(ts_flag IS NULL OR ts_flag NOT LIKE '%implausible_year%')").fetchone()
        key = dbm.rows(con, "SELECT fid, category, title, statement FROM findings WHERE fid IS NOT NULL AND priority=1 ORDER BY fid LIMIT 40")
        jobs = job_rows(con, 10)
        return {"slug": c.slug, "info": c.info, "params": c.params, "counts": counts, "span": list(span) if span else None,
                "key_findings": key, "jobs": jobs, "status_text": status_text(c, con, False),
                "citation_check": dbm.get_meta(con, "citation_check"), "narrative": dbm.get_meta(con, "narrative"),
                "returns_changed": dbm.get_meta(con, "returns_changed"),
                "analysis_errors": dbm.analysis_errors(con),
                "report_ready": (c.report_dir / "REPORT.md").exists(), "case_dir": str(c.dir), "report_dir": str(c.report_dir)}
    finally:
        con.close()


@route("POST", r"/api/case/([^/]+)/settings")
def api_case_settings(h, q, body, slug):
    c = _case(slug)
    for k in ("examiner", "description", "display_tz", "name"):
        if k in body:
            c.info[k] = body[k]
    if "params" in body:
        cur = dict(c.info.get("params") or {})
        for k, v in body["params"].items():
            if k in DEFAULT_PARAMS:
                cur[k] = v
        c.info["params"] = cur
        merged_params(cur)  # validates types
    c.save()
    con = c.db()
    c.audit(con, "case_settings_changed", body)
    con.close()
    return {"ok": True, "params": c.params}


@route("GET", r"/api/case/([^/]+)/returns")
def api_returns(h, q, body, slug):
    from .. import returns as rets
    from ..jobs import active_job
    c = _case(slug)
    con = c.db(readonly=True)
    try:
        rows = rets.return_rows(con)
        for r in rows:
            r["files"] = [{"label": f["label"], "name": f["member"] or Path(f["path"]).name, "status": f["status"], "rows": f["rows"], "kind": f["kind"]}
                          for f in r["files"]]
        return {"returns": rows, "changed": dbm.get_meta(con, "returns_changed"),
                "running": bool(active_job(con, "run"))}
    finally:
        con.close()


@route("POST", r"/api/case/([^/]+)/returns")
def api_returns_change(h, q, body, slug):
    """action: exclude | include | remove | restore | rename | move  (see returns.py). Takes effect on the next run."""
    from .. import returns as rets
    from ..jobs import active_job
    c = _case(slug)
    con = c.db()
    try:
        if active_job(con, "run"):
            raise ApiError("An analysis is running for this case. Stop it, or wait until it finishes, before changing the returns.", 409)
        act = body.get("action")
        try:
            if act in ("exclude", "include", "remove", "restore"):
                st = {"exclude": "excluded", "include": "active", "restore": "active", "remove": "removed"}[act]
                for ref in (body.get("refs") or [body.get("ref")]):
                    rets.set_state(con, c, ref, st, (body.get("reason") or "").strip())
            elif act == "rename":
                rets.rename(con, c, body.get("ref"), body.get("name"), body.get("note"))
            elif act == "move":
                rets.move_source(con, c, body.get("source"), body.get("to") or None, body.get("name") or "")
            else:
                raise ApiError("unknown action")
        except ValueError as e:
            raise ApiError(str(e)) from e
        return {"ok": True, "changed": dbm.get_meta(con, "returns_changed"),
                "note": "Saved. Run the analysis again for the change to take effect; nothing in the current report has changed yet."}
    finally:
        con.close()


@route("GET", r"/api/case/([^/]+)/sources")
def api_sources(h, q, body, slug):
    c = _case(slug)
    con = c.db(readonly=True)
    try:
        out = []
        rmap = {r[0]: r[1] for r in con.execute("SELECT id, label FROM returns")}
        for s in source_rows(con):
            cfg = s["config"] or {}
            st = s["stats"] or {}
            s["ret"] = rmap.get(s.get("return_id"))
            out.append({"label": s["label"], "name": s["name"], "display": s["display"], "kind": s["kind"], "size": s["size"],
                        "status": s["status"], "rows": s["rows"], "error": s["error"], "sha256": s["sha256"],
                        "tz": cfg.get("tz"), "tz_assumed": cfg.get("tz_assumed"), "default_account": cfg.get("default_account"),
                        "skip": cfg.get("skip"), "ts_failed": st.get("ts_failed", 0),
                        "flags": st.get("flags") or {}, "changed": s["status"] == "ingested" and s["ingested_rev"] != s["config_rev"],
                        "parent": s["parent_id"], "ret": s["ret"]})
        return {"sources": out}
    finally:
        con.close()


@route("POST", r"/api/case/([^/]+)/sources")
def api_add_sources(h, q, body, slug):
    c = _case(slug)
    con = c.db()
    try:
        path = (body.get("path") or "").strip().strip('"')
        if not path:
            raise ApiError("Enter the path of a file or folder.")
        try:
            r = register_path(c, con, path, bool(body.get("recursive", True)), body.get("zip_password") or "")
        except (FileNotFoundError, ValueError) as e:
            raise ApiError(str(e)) from e
        return r
    finally:
        con.close()


@route("GET", r"/api/case/([^/]+)/source/([^/]+)")
def api_source(h, q, body, slug, label):
    c = _case(slug)
    con = c.db(readonly=True)
    try:
        s = [x for x in source_rows(con) if x["label"] == label]
        if not s:
            raise ApiError("no such source", 404)
        s = s[0]
        scan = s.get("scan") or {}
        samples = {t["name"]: {"headers": t.get("headers"), "samples": (t.get("samples") or [])[:12]} for t in scan.get("tables", [])}
        return {"source": {k: v for k, v in s.items() if k not in ("scan",)}, "samples": samples, "notes": scan.get("notes", []),
                "preamble": scan.get("preamble", [])[:30]}
    finally:
        con.close()


@route("POST", r"/api/case/([^/]+)/source/([^/]+)/config")
def api_source_config(h, q, body, slug, label):
    c = _case(slug)
    con = c.db()
    try:
        r = dbm.rows(con, "SELECT * FROM sources WHERE label=?", (label,))
        if not r:
            raise ApiError("no such source", 404)
        r = r[0]
        old = json.loads(r["config"]) if r["config"] else {}
        new = body.get("config") or {}
        if "zip_password" in old:
            new["zip_password"] = old["zip_password"]
        from ..timeparse import TzSpec
        try:
            TzSpec(new.get("tz") or "UTC")
        except ValueError as e:
            raise ApiError(f"Unknown timezone '{new.get('tz')}'. Use an IANA name like America/New_York, or UTC, or an offset like UTC-05:00.") from e
        if new.get("tz") != old.get("tz") or new.get("tz_assumed") != old.get("tz_assumed"):
            if not new.get("tz_assumed"):
                new["tz_basis"] = f"set by the analyst on {utc_now_str()}" + (f" (detected: {old.get('tz')} - {old.get('tz_basis')})" if old.get("tz") else "")
        if new.get("default_account") != old.get("default_account"):
            new["default_account_basis"] = f"set by the analyst on {utc_now_str()}" if new.get("default_account") else ""
        for t_new in new.get("tables", []):
            t_old = next((t for t in old.get("tables", []) if t.get("name") == t_new.get("name")), {})
            if t_new.get("mapping") != t_old.get("mapping"):
                t_new["mapping_notes"] = (t_old.get("mapping_notes") or []) + [f"mapping changed by the analyst on {utc_now_str()}"]
            if t_new.get("default_category") != t_old.get("default_category"):
                t_new["default_category_basis"] = f"set by the analyst on {utc_now_str()}" if t_new.get("default_category") else ""
            if t_new.get("date_order") != t_old.get("date_order"):
                t_new["date_order_note"] = f"set by the analyst on {utc_now_str()}"
        status = r["status"]
        if status in ("ingested", "skipped", "ingesting"):
            status = "scanned"
        con.execute("UPDATE sources SET config=?, config_rev=config_rev+1, status=?, checkpoint=NULL WHERE id=?",
                    (json.dumps(new), "skipped" if new.get("skip") else status, r["id"]))
        if new.get("skip"):
            from ..ingest import _delete_source_rows
            _delete_source_rows(con, r["id"])
            con.execute("UPDATE sources SET rows=0 WHERE id=?", (r["id"],))
        con.commit()
        diff = {k: [old.get(k), new.get(k)] for k in set(old) | set(new) if old.get(k) != new.get(k) and k != "zip_password"}
        c.audit(con, "source_config_changed", {"source": label, "changes": diff})
        return {"ok": True, "note": "Saved. The file will be re-read on the next run."}
    finally:
        con.close()


@route("POST", r"/api/case/([^/]+)/source/([^/]+)/preview")
def api_source_preview(h, q, body, slug, label):
    c = _case(slug)
    con = c.db()
    try:
        r = dbm.rows(con, "SELECT * FROM sources WHERE label=?", (label,))
        if not r:
            raise ApiError("no such source", 404)
        from ..ingest import preview
        cfg = body.get("config") or json.loads(r[0]["config"] or "{}")
        try:
            return {"rows": preview(c, r[0], cfg, 25)}
        except ValueError as e:
            raise ApiError(str(e)) from e
    finally:
        con.close()


@route("POST", r"/api/case/([^/]+)/run")
def api_run(h, q, body, slug):
    c = _case(slug)
    con = c.db()
    try:
        from ..jobs import start_job
        params = {"llm": bool(body.get("llm", True))}
        if body.get("figures") is not None:
            params["figures"] = bool(body["figures"])
        if body.get("accounts") is not None:
            params["accounts"] = int(body["accounts"])
        try:
            jid = start_job(c, con, "run", params)
        except RuntimeError as e:
            raise ApiError(str(e), 409) from e
        return {"job": jid}
    finally:
        con.close()


@route("POST", r"/api/case/([^/]+)/cancel")
def api_cancel(h, q, body, slug):
    c = _case(slug)
    con = c.db()
    try:
        from ..jobs import active_job, cancel_job
        j = active_job(con)
        if not j:
            raise ApiError("Nothing is running.")
        cancel_job(c, con, j["id"])
        return {"ok": True}
    finally:
        con.close()


@route("GET", r"/api/case/([^/]+)/jobs")
def api_jobs(h, q, body, slug):
    c = _case(slug)
    con = c.db(readonly=True)
    try:
        from ..jobs import job_rows, status_text
        return {"jobs": job_rows(con, 10), "status_text": status_text(c, con, False)}
    finally:
        con.close()


@route("GET", r"/api/case/([^/]+)/log")
def api_log(h, q, body, slug):
    c = _case(slug)
    n = int((q.get("n") or ["200"])[0])
    p = c.logs_dir / "run.log"
    lines = p.read_text(encoding="utf-8", errors="replace").splitlines()[-n:] if p.exists() else []
    return {"lines": lines}


@route("GET", r"/api/case/([^/]+)/findings")
def api_findings(h, q, body, slug):
    c = _case(slug)
    con = c.db(readonly=True)
    try:
        where, args = ["fid IS NOT NULL"], []
        cat = (q.get("category") or [""])[0]
        if cat:
            where.append("category=?")
            args.append(cat)
        pr = (q.get("priority") or [""])[0]
        if pr:
            where.append("priority<=?")
            args.append(int(pr))
        text = (q.get("q") or [""])[0]
        if text:
            where.append("(statement LIKE ? OR title LIKE ? OR fid=?)")
            args += [f"%{text}%", f"%{text}%", text.upper()]
        rows = dbm.rows(con, f"SELECT fid, category, kind, priority, title, statement, evidence_count FROM findings WHERE "
                             f"{' AND '.join(where)} ORDER BY fid", tuple(args))
        cats = [r[0] for r in con.execute("SELECT DISTINCT category FROM findings WHERE fid IS NOT NULL")]
        return {"findings": rows, "categories": cats}
    finally:
        con.close()


@route("GET", r"/api/case/([^/]+)/finding/([^/]+)")
def api_finding(h, q, body, slug, fid):
    c = _case(slug)
    con = c.db(readonly=True)
    try:
        f = dbm.rows(con, "SELECT * FROM findings WHERE fid=?", (fid.upper(),))
        if not f:
            raise ApiError("no such finding", 404)
        f = f[0]
        f["facts"] = json.loads(f["facts"]) if f["facts"] else {}
        f["evidence"] = dbm.rows(con, "SELECT fe.role, s.label || ':' || e.loc AS cite, e.ts_utc, e.ts_raw, e.tz_basis, e.ts_flag, e.ip, "
                                      "e.account, e.category, e.action, e.raw FROM finding_evidence fe JOIN events e ON e.id=fe.event_id "
                                      "JOIN sources s ON s.id=e.source_id WHERE fe.finding_id=? ORDER BY e.ts_epoch IS NULL, e.ts_epoch",
                                 (f["id"],))
        f["cites"] = dbm.rows(con, "SELECT cite, text FROM finding_cites WHERE finding_id=?", (f["id"],))
        f["checks"] = dbm.rows(con, "SELECT cite, status, detail FROM citation_checks WHERE event_id IN "
                                    "(SELECT event_id FROM finding_evidence WHERE finding_id=?)", (f["id"],))
        f["sql_failure"] = next((x[1] for x in (dbm.get_meta(con, "sql_failures") or []) if x[0] == f["fid"]), None)
        return f
    finally:
        con.close()


@route("GET", r"/api/case/([^/]+)/lookup")
def api_lookup(h, q, body, slug):
    from ..lookup import lookup
    c = _case(slug)
    g = lambda k: (q.get(k) or [""])[0] or None  # noqa: E731
    try:
        return lookup(c, g("kind") or "text", g("q") or "", g("from"), g("to"), int(g("limit") or 500))
    except ValueError as e:
        raise ApiError(str(e)) from e


@route("POST", r"/api/case/([^/]+)/lookup/save")
def api_lookup_save(h, q, body, slug):
    from ..lookup import lookup, save_lookup_md
    c = _case(slug)
    res = lookup(c, body.get("kind") or "text", body.get("q") or "", body.get("from") or None, body.get("to") or None, 5000)
    p = save_lookup_md(c, res)
    return {"file": str(p.relative_to(c.report_dir).as_posix())}


@route("GET", r"/api/case/([^/]+)/context")
def api_context(h, q, body, slug):
    from ..lookup import source_context
    c = _case(slug)
    cite = (q.get("cite") or [""])[0]
    m = re.match(r"^(S\d+):(.+)$", cite)
    if not m:
        raise ApiError("not a citation")
    loc = m.group(2).split("+")[0]
    try:
        return source_context(c, m.group(1), loc)
    except (ValueError, OSError) as e:
        raise ApiError(str(e)) from e


@route("POST", r"/api/case/([^/]+)/ask")
def api_ask(h, q, body, slug):
    c = _case(slug)
    con = c.db()
    try:
        qs = (body.get("question") or "").strip()
        if not qs:
            raise ApiError("Type a question.")
        cur = con.execute("INSERT INTO asks(question, status, created_at) VALUES (?,?,?)", (qs, "queued", utc_now_str()))
        con.commit()
        from ..jobs import start_job
        jid = start_job(c, con, "ask", {"ask_id": cur.lastrowid})
        con.execute("UPDATE asks SET job_id=? WHERE id=?", (jid, cur.lastrowid))
        con.commit()
        return {"ask": cur.lastrowid, "job": jid}
    finally:
        con.close()


@route("GET", r"/api/case/([^/]+)/asks")
def api_asks(h, q, body, slug):
    c = _case(slug)
    con = c.db(readonly=True)
    try:
        return {"asks": dbm.rows(con, "SELECT id, question, status, row_count, created_at, finished_at, error FROM asks ORDER BY id DESC LIMIT 100")}
    finally:
        con.close()


@route("GET", r"/api/case/([^/]+)/ask/(\d+)")
def api_ask_get(h, q, body, slug, aid):
    c = _case(slug)
    con = c.db(readonly=True)
    try:
        a = dbm.rows(con, "SELECT * FROM asks WHERE id=?", (int(aid),))
        if not a:
            raise ApiError("no such question", 404)
        a = a[0]
        for k in ("columns", "rows", "summary"):
            a[k] = json.loads(a[k]) if a.get(k) else []
        if a.get("job_id"):
            j = dbm.rows(con, "SELECT status, message FROM jobs WHERE id=?", (a["job_id"],))
            a["job"] = j[0] if j else None
        return a
    finally:
        con.close()


@route("GET", r"/api/case/([^/]+)/reports")
def api_reports(h, q, body, slug):
    c = _case(slug)
    order = ["REPORT.md", "CROSSREF.md", "FIGURES.md", "REVIEW.md", "FINDINGS.md", "EVIDENCE.md", "SOURCES.md", "TIMELINE.md", "METHODS.md", "CITATION_CHECK.md"]
    files = []
    if c.report_dir.exists():
        for p in sorted(c.report_dir.rglob("*.md")):
            rel = p.relative_to(c.report_dir).as_posix()
            files.append({"file": rel, "size": p.stat().st_size, "modified": time.strftime("%Y-%m-%d %H:%M", time.localtime(p.stat().st_mtime))})
    files.sort(key=lambda f: (order.index(f["file"]) if f["file"] in order else 99, f["file"]))
    exports = sorted(p.relative_to(c.report_dir).as_posix() for p in (c.report_dir / "exports").glob("*") if p.suffix.lower() in (".csv", ".kml", ".geojson")) if (c.report_dir / "exports").exists() else []
    return {"files": files, "exports": exports, "progress_md": (c.dir / "PROGRESS.md").exists()}


@route("GET", r"/api/case/([^/]+)/map")
def api_map(h, q, body, slug):
    from ..mapdata import map_data
    c = _case(slug)
    con = c.db(readonly=True)
    try:
        return map_data(con, c.params)
    finally:
        con.close()


@route("GET", r"/api/case/([^/]+)/links")
def api_links_choices(h, q, body, slug):
    from ..contactgraph import Graph
    c = _case(slug)
    con = c.db(readonly=True)
    try:
        if not (dbm.one(con, "SELECT COUNT(*) FROM tel") or 0):
            return {"telecom": False}
        g = Graph(con, c.params, dumps=True)
        return {"telecom": True, **g.choices(), "sets": c.params.get("tel_link_sets") or [], "max_hops": c.params.get("tel_path_max_hops", 6)}
    finally:
        con.close()


@route("POST", r"/api/case/([^/]+)/links")
def api_links(h, q, body, slug):
    """{seeds: [number | dump:... | imei:...], max_hops, slack, devices} -> chains between every pair, with citations."""
    from ..contactgraph import Graph
    c = _case(slug)
    con = c.db(readonly=True)
    try:
        g = Graph(con, c.params, dumps=True, devices=bool(body.get("devices")))
        asked = [str(x) for x in (body.get("seeds") or [])][:40]
        seeds, missing = [], []
        for x in asked:
            n = g.find(x)
            (seeds.append(n) if n else missing.append(x))
        seeds = list(dict.fromkeys(seeds))
        if len(seeds) < 2:
            raise ApiError("Choose at least two numbers or tower dumps that are in the records." + (f" Not found: {', '.join(missing)}." if missing else ""), 400)
        hops = max(1, min(10, int(body.get("max_hops") or 6)))
        slack = max(0, min(2, int(body.get("slack") or 0)))
        res = g.result_json(g.connect(seeds, hops, slack, int(body.get("max_paths") or 25)))
        res["missing"] = missing
        res["hub_max"] = g.hub_max
        return res
    finally:
        con.close()


@route("POST", r"/api/case/([^/]+)/links/save")
def api_links_save(h, q, body, slug):
    """Save (or with delete=true, remove) a named link group; it is reported on the next run."""
    c = _case(slug)
    name = str(body.get("name") or "").strip()[:80]
    if not name:
        raise ApiError("Give the group a name.", 400)
    cur = dict(c.info.get("params") or {})
    sets = [s for s in (cur.get("tel_link_sets") or []) if s.get("name") != name]
    if not body.get("delete"):
        members = [str(m) for m in (body.get("members") or [])][:40]
        if len(members) < 2:
            raise ApiError("A link group needs at least two members.", 400)
        sets.append({"name": name, "members": members, "max_hops": int(body.get("max_hops") or 6), "slack": int(body.get("slack") or 0)})
    cur["tel_link_sets"] = sets
    c.info["params"] = cur
    c.save()
    con = c.db()
    c.audit(con, "link_group_" + ("deleted" if body.get("delete") else "saved"), {"name": name, "members": body.get("members")})
    con.close()
    return {"ok": True, "sets": sets}


@route("GET", r"/api/case/([^/]+)/report")
def api_report(h, q, body, slug):
    from ..markdown import render
    c = _case(slug)
    f = (q.get("file") or ["REPORT.md"])[0]
    p = (c.dir / f) if f == "PROGRESS.md" else (c.report_dir / f)
    if not _inside(p, c.dir) or not p.exists() or p.suffix.lower() != ".md":
        raise ApiError("no such report file", 404)
    md = p.read_text(encoding="utf-8", errors="replace")
    big = len(md) > 3_000_000
    return {"file": f, "html": render(md[:3_000_000]) + ("<p><em>(truncated in the viewer - open the file for the rest)</em></p>" if big else ""),
            "path": str(p)}


@route("POST", r"/api/case/([^/]+)/open-folder")
def api_open_folder(h, q, body, slug):
    c = _case(slug)
    which = body.get("which", "report")
    p = c.report_dir if which == "report" else c.dir
    p.mkdir(parents=True, exist_ok=True)
    try:
        open_in_file_manager(p)
    except Exception as e:  # noqa: BLE001
        raise ApiError(f"Could not open the folder: {e}. It is at {p}") from e
    return {"ok": True, "path": str(p)}


@route("POST", r"/api/case/([^/]+)/report")
def api_rewrite_report(h, q, body, slug):
    c = _case(slug)
    con = c.db()
    try:
        from ..jobs import start_job
        return {"job": start_job(c, con, "report", {})}
    finally:
        con.close()


def _inside(p: Path, root: Path) -> bool:
    try:
        p.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------- HTTP handler

class Handler(BaseHTTPRequestHandler):
    server_version = f"Spoor/{__version__}"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def _host_ok(self) -> bool:
        host = (self.headers.get("Host") or "").lower()
        return host in (f"127.0.0.1:{PORT}", f"localhost:{PORT}")

    def _authed(self) -> bool:
        cookie = self.headers.get("Cookie") or ""
        return f"spoor_t={TOKEN}" in [c.strip() for c in cookie.split(";")]

    def _send(self, code: int, body: bytes, ctype: str = "application/json; charset=utf-8", extra: dict | None = None):
        if code in (401, 403, 413):
            self.close_connection = True
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
                                                    "font-src 'self' data:; script-src 'self'; connect-src 'self'; frame-ancestors 'none'")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj, default=str, ensure_ascii=False).encode("utf-8"))

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def _dispatch(self, method: str):
        raw = b""
        if method == "POST":
            n = int(self.headers.get("Content-Length") or 0)
            if n > 5_000_000:
                self.close_connection = True
                self._json({"error": "request too large"}, 413)
                return
            raw = self.rfile.read(n) if n else b""   # always drain the body so the connection stays in sync
        if not self._host_ok():
            self._send(403, b"Forbidden host", "text/plain")
            return
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if method == "GET" and "t" in q:
            if secrets.compare_digest(q["t"][0], TOKEN):
                self._send(302, b"", "text/plain", {"Location": "/", "Set-Cookie": f"spoor_t={TOKEN}; HttpOnly; SameSite=Strict; Path=/"})
            else:
                self._send(403, b"This link is from an earlier session. Use the link printed in the Spoor window.", "text/plain; charset=utf-8")
            return
        if method == "GET" and (u.path == "/style.css" or u.path.startswith("/fonts/")):
            f = STATIC / u.path.lstrip("/")
            if _inside(f, STATIC) and f.is_file():
                self._send(200, f.read_bytes(), "text/css; charset=utf-8" if f.suffix == ".css" else "font/woff2")
                return
        if not self._authed():
            self._send(401, (STATIC / "locked.html").read_bytes(), "text/html; charset=utf-8")
            return
        if method == "POST":
            origin = self.headers.get("Origin")
            if origin and origin.lower() not in (f"http://127.0.0.1:{PORT}", f"http://localhost:{PORT}"):
                self._send(403, b"Cross-site request refused", "text/plain")
                return
        path = u.path
        if path.startswith("/api/"):
            body = {}
            if method == "POST":
                try:
                    body = json.loads(raw or b"{}")
                except ValueError:
                    self._json({"error": "bad JSON"}, 400)
                    return
            for m, rx, fn in ROUTES:
                if m != method:
                    continue
                mt = rx.match(path)
                if mt:
                    try:
                        self._json(fn(self, q, body, *mt.groups()))
                    except ApiError as e:
                        self._json({"error": str(e)}, e.code)
                    except Exception as e:  # noqa: BLE001
                        traceback.print_exc()
                        self._json({"error": f"{type(e).__name__}: {e}"}, 500)
                    return
            self._json({"error": "not found"}, 404)
            return
        m = re.match(r"^/case/([^/]+)/file/(.+)$", path)
        if m and method == "GET":
            try:
                c = _case(m.group(1))
            except ApiError:
                self._send(404, b"not found", "text/plain")
                return
            p = c.report_dir / unquote(m.group(2))
            if not _inside(p, c.report_dir) or not p.is_file():
                self._send(404, b"not found", "text/plain")
                return
            ctype = mimetypes.guess_type(p.name)[0] or "application/octet-stream"
            if p.suffix.lower() in (".md", ".csv", ".sha256", ".txt"):
                ctype = "text/plain; charset=utf-8"
            elif p.suffix.lower() == ".svg":          # the Windows registry may not know .svg
                ctype = "image/svg+xml"
            extra = {"Content-Disposition": f'attachment; filename="{p.name}"'} if p.suffix.lower() == ".csv" else None
            self._send(200, p.read_bytes(), ctype, extra)
            return
        if path in ("/", "/index.html"):
            path = "/index.html"
        f = STATIC / path.lstrip("/")
        if _inside(f, STATIC) and f.is_file():
            ctype = mimetypes.guess_type(f.name)[0] or "application/octet-stream"
            if f.suffix == ".js":
                ctype = "text/javascript; charset=utf-8"
            self._send(200, f.read_bytes(), ctype)
            return
        self._send(404, b"not found", "text/plain")


class _Server(ThreadingHTTPServer):
    """On Windows SO_REUSEADDR lets a second program bind a port that is already listening, so two Spoor windows (or
    an old and a new version) could share 8765 and the browser would reach the wrong one ('This link is from an
    earlier session'). Ask for the port exclusively instead."""
    allow_reuse_address = not IS_WINDOWS

    def server_bind(self):
        if IS_WINDOWS and hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


def _port_in_use(p: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", p), timeout=0.3):
            return True
    except OSError:
        return False


def serve(port: int | None = None, open_browser: bool = True) -> None:
    global PORT
    s = load_settings()
    PORT = int(port or s.get("port") or 8765)
    srv = None
    busy = []
    for p in range(PORT, PORT + 20):
        if _port_in_use(p):          # another Spoor (any version) or another program is already answering there
            busy.append(p)
            continue
        try:
            srv = _Server(("127.0.0.1", p), Handler)
            PORT = p
            break
        except OSError:
            busy.append(p)
            continue
    if srv is None:
        raise SystemExit("No free port between %d and %d" % (PORT, PORT + 19))
    srv.daemon_threads = True
    url = f"http://127.0.0.1:{PORT}/?t={TOKEN}"
    bar = "=" * 72
    print(f"\n{bar}\n  Spoor {__version__} - offline subpoena-return analysis\n{bar}")
    print(f"  Dashboard:  {url}")
    print(f"  Cases:      {s['cases_dir']}")
    if busy:
        print(f"  Port {busy[0]} is already in use (another Spoor window, possibly an older version?) - this one is on {PORT}.")
        print("  Use the link above; links printed by other windows belong to those windows.")
    print("  Keep this window open while you use the dashboard. Closing it does NOT")
    print("  stop analyses that are running - they continue in the background.")
    print(f"{bar}\n")
    if open_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("stopped")
