"""Background jobs: a detached worker process runs the pipeline and reports progress to the case
database (read by the dashboard and `spoor status`) and to PROGRESS.md in the case folder.

Every stage is safe to re-run: starting the same job again after a crash, reboot or cancel
continues where it stopped (ingest resumes from per-file checkpoints, AI sections already
written are kept while the findings are unchanged)."""
from __future__ import annotations

import hashlib
import json
import os
import sys
import threading
import time
import traceback
from pathlib import Path
from typing import Optional

from . import __version__
from . import db as dbm
from .util import fmt_duration, fmt_int, get_logger, keep_awake, pid_alive, spawn_detached, utc_now_str

RUN_STAGES = [
    ("prepare", "Register, extract and hash files"),
    ("scan", "Detect formats and map columns"),
    ("ingest", "Read records"),
    ("index", "Index, enrich and summarise"),
    ("analyze", "Run analyses"),
    ("report1", "Write report (deterministic findings)"),
    ("figures", "Draw figures (deterministic SVG)"),
    ("verify", "Re-check citations and source hashes"),
    ("narrative", "AI-drafted summary (local model, verified)"),
    ("report2", "Write final report"),
]
STALE_SECONDS = 180


class Cancelled(Exception):
    pass


class Progress:
    def __init__(self, case, con, job_id: int, stages: list[tuple[str, str]]):
        self.case = case
        self.con = con
        self.job_id = job_id
        self.stages = stages
        self.stage_no = 0
        self.done = 0.0
        self.total = 0.0
        self.unit = ""
        self.msg = ""
        self.rate = None
        self._t_stage = time.time()
        self._last_db = 0.0
        self._last_md = 0.0
        self._last_cancel = 0.0
        self._samples: list[tuple[float, float]] = []
        self.started = time.time()

    # stage control
    def stage(self, key: str) -> None:
        keys = [k for k, _ in self.stages]
        if key not in keys:          # a job created by an older version lacks a newer stage
            self.stages = list(self.stages) + [(key, key)]
            keys.append(key)
        idx = keys.index(key)
        self.stage_no = idx + 1
        self.done, self.total, self.unit, self.rate = 0.0, 0.0, "", None
        self._samples = []
        self._t_stage = time.time()
        self.msg = self.stages[idx][1]
        self.flush(force=True)

    def set_total(self, total, unit: str = "") -> None:
        self.total = float(total or 0)
        self.unit = unit
        self.done = 0.0
        self._samples = []
        self.flush(force=True)

    def update(self, done) -> None:
        self.done = float(done)
        now = time.time()
        self._samples.append((now, self.done))
        self._samples = [s for s in self._samples if now - s[0] <= 120]
        if len(self._samples) >= 2 and self._samples[-1][0] > self._samples[0][0]:
            self.rate = (self._samples[-1][1] - self._samples[0][1]) / (self._samples[-1][0] - self._samples[0][0])
        self.flush()

    def message(self, msg: str) -> None:
        self.msg = msg
        self.flush()

    def eta(self) -> Optional[float]:
        if self.total and self.rate and self.rate > 0:
            return max(0.0, (self.total - self.done) / self.rate)
        return None

    def check_cancel(self) -> None:
        now = time.time()
        if now - self._last_cancel < 2:
            return
        self._last_cancel = now
        r = self.con.execute("SELECT cancel FROM jobs WHERE id=?", (self.job_id,)).fetchone()
        if r and r[0]:
            raise Cancelled()

    def flush(self, force: bool = False) -> None:
        now = time.time()
        if not force and now - self._last_db < 1.5:
            return
        self._last_db = now
        self.con.execute("UPDATE jobs SET heartbeat=?, stage=?, stage_no=?, stage_total=?, done=?, total=?, unit=?, rate=?, eta_s=?, "
                         "message=? WHERE id=?",
                         (now, self.stages[self.stage_no - 1][0] if self.stage_no else "", self.stage_no, len(self.stages),
                          self.done, self.total, self.unit, self.rate, self.eta(), self.msg[:500], self.job_id))
        self.con.commit()
        if force or now - self._last_md > 15:
            self._last_md = now
            try:
                write_progress_md(self.case, self.con)
            except Exception:  # noqa: BLE001
                pass


# ---------------------------------------------------------------- job table helpers

def job_rows(con, limit: int = 20, case_dir=None) -> list[dict]:
    if case_dir is None:
        try:
            dbfile = con.execute("PRAGMA database_list").fetchone()[2]
            case_dir = Path(dbfile).parent if dbfile else None
        except Exception:  # noqa: BLE001
            case_dir = None
    ALIVE_DIR["dir"] = case_dir
    rows = dbm.rows(con, "SELECT * FROM jobs ORDER BY id DESC LIMIT ?", (limit,))
    for r in rows:
        r["params"] = json.loads(r["params"]) if r.get("params") else {}
        r["stages"] = json.loads(r["stages"]) if r.get("stages") else []
        r["stages_done"] = json.loads(r["stages_done"]) if r.get("stages_done") else []
        r["result"] = json.loads(r["result"]) if r.get("result") else None
        if r["status"] in ("running", "starting") and _stale(r):
            r["status"] = "interrupted"
    return rows


ALIVE_DIR: dict = {}


def _alive_file(case_dir, job_id) -> Path:
    return Path(case_dir) / "logs" / f"job-{job_id}.alive"


def _stale(r: dict) -> bool:
    """A job is stale when its process is gone or its heartbeat file stopped updating.

    The heartbeat file is written by a background thread, so long model calls or long
    database statements (index builds) never make a healthy job look stale."""
    if r.get("pid") and not pid_alive(r["pid"]):
        return True
    d = ALIVE_DIR.get("dir")
    f = _alive_file(d, r["id"]) if d else None
    if f is not None and f.exists():
        return time.time() - f.stat().st_mtime > STALE_SECONDS
    hb = r.get("heartbeat") or 0
    return bool(hb) and time.time() - hb > STALE_SECONDS * 10


def active_job(con, kind: Optional[str] = None) -> Optional[dict]:
    for r in job_rows(con, 50):
        if r["status"] in ("running", "starting", "queued") and (kind is None or r["kind"] == kind):
            return r
    return None


def start_job(case, con, kind: str, params: Optional[dict] = None, wait: bool = False) -> int:
    if kind == "run":
        a = active_job(con, "run")
        if a:
            raise RuntimeError(f"Job #{a['id']} is already running for this case.")
    # mark stale jobs as interrupted so the history is honest
    for r in job_rows(con, 50):
        if r["status"] == "interrupted":
            con.execute("UPDATE jobs SET status='interrupted' WHERE id=? AND status IN ('running','starting')", (r["id"],))
    stages = RUN_STAGES if kind == "run" else [(kind, kind)]
    cur = con.execute("INSERT INTO jobs(kind, params, status, created_at, stages, stages_done, heartbeat) VALUES (?,?,?,?,?,?,?)",
                      (kind, json.dumps(params or {}), "starting", utc_now_str(), json.dumps(stages), "[]", time.time()))
    con.commit()
    jid = cur.lastrowid
    case.audit(con, "job_started", {"job": jid, "kind": kind, "params": params or {}})
    # the worker runs with the same isolation as this process (-S: no system site-packages)
    args = [sys.executable] + (["-S"] if sys.flags.no_site else []) + ["-m", "spoor", "worker", "--case-dir", str(case.dir), "--job", str(jid)]
    if wait:
        run_worker(case.dir, jid)
        return jid
    pid = spawn_detached(args, case.logs_dir / f"worker-{jid}.log", low_priority=True)
    con.execute("UPDATE jobs SET pid=? WHERE id=?", (pid, jid))
    con.commit()
    return jid


def cancel_job(case, con, job_id: int) -> None:
    con.execute("UPDATE jobs SET cancel=1 WHERE id=?", (job_id,))
    con.commit()
    case.audit(con, "job_cancel_requested", {"job": job_id})


# ---------------------------------------------------------------- worker

def run_worker(case_dir, job_id: int) -> None:
    from .case import Case
    case = Case(Path(case_dir))
    log = get_logger(case.dir, f"spoor.job{job_id}")
    con = case.db()
    job = dbm.rows(con, "SELECT * FROM jobs WHERE id=?", (job_id,))[0]
    params = json.loads(job["params"]) if job.get("params") else {}
    stages = [tuple(s) for s in json.loads(job["stages"])]
    con.execute("UPDATE jobs SET status='running', pid=?, started_at=?, heartbeat=? WHERE id=?",
                (os.getpid(), utc_now_str(), time.time(), job_id))
    con.commit()
    if hasattr(os, "nice"):
        try:
            os.nice(5)
        except OSError:
            pass
    keep_awake(True)
    alive = _alive_file(case.dir, job_id)
    stop_beat = threading.Event()

    def beat():
        while not stop_beat.is_set():
            try:
                alive.write_text(str(time.time()), encoding="ascii")
            except OSError:
                pass
            stop_beat.wait(20)
    threading.Thread(target=beat, daemon=True).start()
    prog = Progress(case, con, job_id, stages)
    log.info("job %s (%s) started, pid %s, Spoor %s", job_id, job["kind"], os.getpid(), __version__)
    try:
        if job["kind"] == "run":
            result = run_pipeline(case, con, prog, params, log)
        elif job["kind"] == "ask":
            from .ask import run_ask
            prog.stage("ask")
            result = run_ask(case, con, int(params["ask_id"]), prog, log)
        elif job["kind"] == "report":
            from .report import write_reports
            prog.stage("report")
            write_reports(case, con, prog)
            result = {"ok": True}
        else:
            raise ValueError(f"unknown job kind {job['kind']}")
        con.execute("UPDATE jobs SET status='done', finished_at=?, heartbeat=?, result=?, message=? WHERE id=?",
                    (utc_now_str(), time.time(), json.dumps(result, default=str), "Finished", job_id))
        con.commit()
        case.audit(con, "job_finished", {"job": job_id, "result": result})
        log.info("job %s finished", job_id)
    except Cancelled:
        con.execute("UPDATE jobs SET status='cancelled', finished_at=?, message=? WHERE id=?",
                    (utc_now_str(), "Cancelled - run again to continue where it stopped", job_id))
        con.commit()
        case.audit(con, "job_cancelled", {"job": job_id})
        log.info("job %s cancelled", job_id)
    except Exception as e:  # noqa: BLE001
        tb = traceback.format_exc()
        log.error("job %s failed: %s\n%s", job_id, e, tb)
        con.execute("UPDATE jobs SET status='error', finished_at=?, error=?, message=? WHERE id=?",
                    (utc_now_str(), f"{type(e).__name__}: {e}", "Failed - see the log", job_id))
        con.commit()
        case.audit(con, "job_failed", {"job": job_id, "error": f"{type(e).__name__}: {e}"})
    finally:
        stop_beat.set()
        keep_awake(False)
        try:
            alive.unlink()
        except OSError:
            pass
        try:
            write_progress_md(case, con)
        except Exception:  # noqa: BLE001
            pass
        con.close()


def findings_fingerprint(con) -> str:
    h = hashlib.sha256()
    for r in con.execute("SELECT fid, statement FROM findings WHERE fid IS NOT NULL ORDER BY fid"):
        h.update(f"{r[0]}\x00{r[1]}\x01".encode("utf-8"))
    return h.hexdigest()


def run_pipeline(case, con, prog: Progress, params: dict, log) -> dict:
    from . import derive, ingest
    from .analyses import MODULES
    from .citecheck import Checker, recheck_hashes
    from .findings import number_findings
    from .report import write_reports
    p = case.params
    done = []
    timings: dict = {}

    def mark(key):
        done.append(key)
        took = time.time() - prog._t_stage
        timings[key] = round(took, 1)
        log.info("stage %s finished in %s", key, fmt_duration(took))
        con.execute("UPDATE jobs SET stages_done=? WHERE id=?", (json.dumps(done), prog.job_id))
        con.commit()

    prog.stage("prepare")
    ingest.prepare_sources(case, con, prog, log)
    mark("prepare")

    prog.stage("scan")
    ingest.scan_sources(case, con, prog, log, rescan_ids=params.get("rescan"))
    mark("scan")

    prog.stage("ingest")
    todo = ingest.sources_to_ingest(con)
    total = sum(s["size"] or 0 for s in todo) or 1
    prog.set_total(total, "bytes")
    base = 0
    stats = {}
    for s in todo:
        prog.message(f"Reading {s['label']} {Path(s['path']).name}")
        size = s["size"] or 0

        def frac(f, _b=base, _s=size):
            prog.update(_b + f * _s)
        try:
            st = ingest.ingest_source(case, con, s, prog, log, on_fraction=frac)
            stats[s["label"]] = {"rows": st["rows"], "ts_failed": st["ts_failed"]}
        except Cancelled:
            raise
        except Exception as e:  # noqa: BLE001
            if type(e).__name__ == "Cancelled":
                raise
            log.exception("ingest %s", s["label"])
            con.execute("UPDATE sources SET status='error', error=? WHERE id=?", (f"read failed: {type(e).__name__}: {e}", s["id"]))
            con.commit()
        base += size
        prog.update(base)
    mark("ingest")

    prog.stage("index")
    derive.build_indexes(con, prog)
    prog.message("Looking up networks (offline ASN/country data)")
    derive.enrich_ips(con, prog)
    prog.stage("index")
    derive.build_summaries(con, prog)
    fts = derive.build_fts(con, bool(p.get("fts", True)), prog)
    dbm.set_meta(con, "fts", fts)
    con.commit()
    mark("index")

    prog.stage("analyze")
    prog.set_total(len(MODULES), "analyses")
    for i, M in enumerate(MODULES):
        prog.message(M.category if hasattr(M, "category") else M.__name__)
        prog.check_cancel()
        try:
            M(case, con, p, log, prog).run()
        except Cancelled:
            raise
        except Exception as e:  # noqa: BLE001
            if type(e).__name__ == "Cancelled":
                raise
            log.exception("analysis %s", M.__name__)
            dbm.set_meta(con, f"analysis_error_{M.__name__}", f"{type(e).__name__}: {e}")
        con.commit()
        prog.update(i + 1)
    n = number_findings(con)
    from .figures import invalidate as invalidate_figures
    invalidate_figures(case, con)     # figures are redrawn from the new findings in the Figures stage
    fp = findings_fingerprint(con)
    old_fp = dbm.get_meta(con, "findings_fingerprint")
    if old_fp != fp:
        con.execute("DELETE FROM narrative")
        con.execute("DELETE FROM narrative_sections")
        dbm.set_meta(con, "narrative", None)
    dbm.set_meta(con, "findings_fingerprint", fp)
    _validate_sql(con, log)
    con.commit()
    mark("analyze")

    prog.stage("report1")
    write_reports(case, con, prog)
    mark("report1")

    prog.stage("figures")
    figs = None
    if params.get("figures", p.get("figures", True)):
        figs = draw_figures(case, con, prog, log)
    else:
        from .figures import invalidate as invalidate_figures
        invalidate_figures(case, con)
        dbm.set_meta(con, "figures", {"off": True})
        con.commit()
        prog.message("Figures not requested")
    mark("figures")

    prog.stage("verify")
    mode = params.get("citation_check") or p.get("citation_check", "all")
    cc = {}
    if mode != "off":
        cc = Checker(case, con, prog).run(mode)
    if p.get("verify_hashes_at_end", True):
        recheck_hashes(case, con, prog)
    mark("verify")

    prog.stage("narrative")
    nar = None
    if params.get("llm", p.get("llm_narrative", True)):
        from .narrative import run_narrative
        try:
            nar = run_narrative(case, con, prog, log, accounts=int(params.get("accounts", p.get("llm_account_profiles", 10))))
        except Cancelled:
            raise
        except Exception as e:  # noqa: BLE001
            if type(e).__name__ == "Cancelled":
                raise
            log.exception("narrative")
            nar = {"error": f"{type(e).__name__}: {e}"}
            prog.message(f"AI summary skipped: {e}")
    else:
        prog.message("AI summary not requested")
    mark("narrative")

    prog.stage("report2")
    write_reports(case, con, prog)
    mark("report2")
    return {"findings": n, "ingest": stats, "citation_check": cc, "figures": figs, "narrative": nar, "stage_seconds": timings}


def draw_figures(case, con, prog=None, log=None) -> dict:
    """Draw every figure, then rewrite the report files that show or list them. Never raises for a figure."""
    from .figures import run_figures
    from .report import Report
    try:
        figs = run_figures(case, con, prog, log)
    except Exception as e:  # noqa: BLE001
        if type(e).__name__ == "Cancelled":
            raise
        if log:
            log.exception("figures")
        figs = {"error": f"{type(e).__name__}: {e}"}
        dbm.set_meta(con, "figures", figs)
        con.commit()
    Report(case, con, prog).write_after_figures()
    return figs


def _validate_sql(con, log) -> None:
    """Every finding's reproduce-SQL must run; a broken one is removed rather than shown."""
    for r in dbm.rows(con, "SELECT id, fid, sql FROM findings WHERE sql IS NOT NULL"):
        try:
            con.execute(f"SELECT * FROM ({r['sql']}) LIMIT 1").fetchall()
        except Exception as e:  # noqa: BLE001
            log.warning("finding %s: reproduce SQL failed (%s); removed", r["fid"], e)
            con.execute("UPDATE findings SET sql=NULL WHERE id=?", (r["id"],))


# ---------------------------------------------------------------- PROGRESS.md / status

def status_text(case, con, markdown: bool = True) -> str:
    jobs = job_rows(con, 5)
    lines = []
    h = "# " if markdown else ""
    lines.append(f"{h}Progress - {case.name}")
    lines.append(f"Updated {utc_now_str()}" + (" (rewritten every 15 s while a job runs)" if markdown else ""))
    lines.append("")
    if not jobs:
        lines.append("No jobs have run yet.")
        return "\n".join(lines) + "\n"
    j = jobs[0]
    stages = j["stages"] or []
    elapsed = None
    if j.get("heartbeat") and j.get("started_at"):
        try:
            import datetime as dt
            st = dt.datetime.strptime(j["started_at"], "%Y-%m-%d %H:%M:%S UTC").replace(tzinfo=dt.timezone.utc)
            end = j["heartbeat"] if j["status"] in ("running", "starting") else j["heartbeat"]
            elapsed = end - st.timestamp()
        except ValueError:
            pass
    lines.append(f"Job #{j['id']} ({j['kind']}): **{j['status'].upper()}**" if markdown else f"Job #{j['id']} ({j['kind']}): {j['status'].upper()}")
    if j.get("started_at"):
        lines.append(f"Started {j['started_at']}" + (f", running for {fmt_duration(elapsed)}" if elapsed and j["status"] == "running" else
                                                      (f", took {fmt_duration(elapsed)}" if elapsed else "")))
    if j["status"] in ("running", "starting") and j.get("stage_no"):
        pct = (100 * j["done"] / j["total"]) if j.get("total") else None
        unit = j.get("unit") or ""
        if unit == "bytes":
            from .util import fmt_bytes
            amt = f"{fmt_bytes(j['done'])} of {fmt_bytes(j['total'])}"
            rate = f", {fmt_bytes(j['rate'])}/s" if j.get("rate") else ""
        else:
            amt = f"{fmt_int(j['done'])} of {fmt_int(j['total'])} {unit}" if j.get("total") else ""
            rate = f", {j['rate']:.1f} {unit}/s" if j.get("rate") else ""
        lines.append(f"Stage {j['stage_no']}/{j['stage_total']}: {stages[j['stage_no'] - 1][1] if stages else j['stage']}"
                     + (f" - {pct:.1f}%" if pct is not None else "") + (f" ({amt}{rate})" if amt else "")
                     + (f", about {fmt_duration(j['eta_s'])} left in this stage" if j.get("eta_s") else ""))
        if j.get("message"):
            lines.append(f"Now: {j['message']}")
    if j["status"] == "error":
        lines.append(f"Error: {j.get('error')}")
    if j["status"] in ("interrupted", "cancelled"):
        lines.append("Start the analysis again to continue where it stopped.")
    lines.append("")
    if stages:
        for i, (k, label) in enumerate(stages, 1):
            mark = "x" if k in (j["stages_done"] or []) else (">" if j["status"] == "running" and i == j.get("stage_no") else " ")
            lines.append(f"- [{mark}] {label}")
        lines.append("")
    log = case.logs_dir / "run.log"
    if log.exists():
        tail = log.read_text(encoding="utf-8", errors="replace").splitlines()[-12:]
        lines.append("Recent log:" if not markdown else "Recent log lines:")
        lines.append("```" if markdown else "")
        lines += tail
        lines.append("```" if markdown else "")
    return "\n".join(lines) + "\n"


def write_progress_md(case, con) -> None:
    (case.dir / "PROGRESS.md").write_text(status_text(case, con, True), encoding="utf-8")
