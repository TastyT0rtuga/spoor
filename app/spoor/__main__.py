"""Command line. Most people use `spoor serve` (the dashboard); everything is also scriptable."""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from . import __version__


def _case(name):
    from .case import get_case, list_cases
    try:
        return get_case(name)
    except FileNotFoundError:
        for c in list_cases():
            if c["name"].lower() == name.lower():
                return get_case(c["slug"])
        raise SystemExit(f"No case '{name}'. Cases: {', '.join(c['slug'] for c in list_cases()) or 'none'}")


def _utf8_streams() -> None:
    """Console and redirected logs in UTF-8, so Cyrillic or other non-Latin text never breaks output."""
    for st in (sys.stdout, sys.stderr):
        try:
            st.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def main(argv=None):
    _utf8_streams()
    ap = argparse.ArgumentParser(prog="spoor", description=f"Spoor {__version__} - offline subpoena-return analysis")
    sub = ap.add_subparsers(dest="cmd")
    s = sub.add_parser("serve", help="start the local dashboard (default)")
    s.add_argument("--port", type=int)
    s.add_argument("--no-browser", action="store_true")
    s = sub.add_parser("new", help="create a case")
    s.add_argument("name")
    s.add_argument("--examiner", default="")
    s.add_argument("--tz", default="", help="local timezone for display, e.g. America/New_York")
    sub.add_parser("cases", help="list cases")
    s = sub.add_parser("add", help="add files or a folder of returns to a case")
    s.add_argument("case")
    s.add_argument("path")
    s.add_argument("--no-recursive", action="store_true")
    s.add_argument("--zip-password", default="")
    s = sub.add_parser("run", help="run (or resume) the full analysis in the background")
    s.add_argument("case")
    s.add_argument("--no-llm", action="store_true", help="skip the AI-drafted summary")
    s.add_argument("--accounts", type=int, default=None, help="AI profiles for the N busiest accounts")
    s.add_argument("--wait", action="store_true", help="run in this window instead of in the background")
    s = sub.add_parser("status", help="show progress")
    s.add_argument("case")
    s.add_argument("--watch", action="store_true", help="refresh every 10 seconds")
    s = sub.add_parser("cancel", help="stop the running job (it can be resumed)")
    s.add_argument("case")
    s = sub.add_parser("report", help="rewrite the Markdown report from the current results")
    s.add_argument("case")
    s = sub.add_parser("ask", help="ask a question (local model writes read-only SQL)")
    s.add_argument("case")
    s.add_argument("question")
    s = sub.add_parser("lookup", help="look up an IP, account, identifier or text (no AI)")
    s.add_argument("case")
    g = s.add_mutually_exclusive_group(required=True)
    g.add_argument("--ip")
    g.add_argument("--account")
    g.add_argument("--id", dest="ident")
    g.add_argument("--text")
    s.add_argument("--from", dest="t_from")
    s.add_argument("--to", dest="t_to")
    s.add_argument("--limit", type=int, default=200)
    s = sub.add_parser("worker", help=argparse.SUPPRESS)
    s.add_argument("--case-dir", required=True)
    s.add_argument("--job", type=int, required=True)
    sub.add_parser("llm", help="check the local model server")
    sub.add_parser("selftest", help="run the built-in end-to-end test on fictional data")
    s = sub.add_parser("demo", help="create a case from the bundled fictional demo returns")
    s.add_argument("--run", action="store_true")
    a = ap.parse_args(argv)
    cmd = a.cmd or "serve"

    if cmd == "serve":
        from .web.server import serve
        serve(port=getattr(a, "port", None), open_browser=not getattr(a, "no_browser", False))
    elif cmd == "worker":
        from .jobs import run_worker
        run_worker(Path(a.case_dir), a.job)
    elif cmd == "new":
        from .case import create_case
        c = create_case(a.name, a.examiner, "", a.tz)
        print(f"created case '{c.name}' in {c.dir}")
    elif cmd == "cases":
        from .case import list_cases
        for c in list_cases():
            print(f"{c['slug']:30} {c['name']:30} {c['created']}")
    elif cmd == "add":
        from .case import register_path
        c = _case(a.case)
        con = c.db()
        r = register_path(c, con, a.path, not a.no_recursive, a.zip_password)
        for x in r["added"]:
            print(f"{x['label']}  {x['kind']:8} {x['path']}")
        for p, why in r["skipped"]:
            print(f"skipped {p}: {why}")
    elif cmd == "run":
        from .jobs import start_job
        c = _case(a.case)
        con = c.db()
        params = {"llm": not a.no_llm}
        if a.accounts is not None:
            params["accounts"] = a.accounts
        jid = start_job(c, con, "run", params, wait=a.wait)
        print(f"job #{jid} started" + ("" if a.wait else " in the background - check with: spoor status \"" + c.slug + "\""))
        if a.wait:
            from .jobs import status_text
            print(status_text(c, c.db(), markdown=False))
    elif cmd == "status":
        from .jobs import status_text
        c = _case(a.case)
        while True:
            con = c.db(readonly=True)
            txt = status_text(c, con, markdown=False)
            con.close()
            if a.watch:
                print("\033[2J\033[H", end="")
            print(txt)
            if not a.watch:
                break
            time.sleep(10)
    elif cmd == "cancel":
        from .jobs import active_job, cancel_job
        c = _case(a.case)
        con = c.db()
        j = active_job(con)
        if not j:
            print("nothing is running")
        else:
            cancel_job(c, con, j["id"])
            print(f"cancel requested for job #{j['id']}; it stops at the next checkpoint")
    elif cmd == "report":
        from .report import write_reports
        c = _case(a.case)
        files = write_reports(c, c.db())
        print(f"wrote {len(files)} files to {c.report_dir}")
    elif cmd == "ask":
        from .jobs import start_job
        from .util import utc_now_str
        c = _case(a.case)
        con = c.db()
        cur = con.execute("INSERT INTO asks(question, status, created_at) VALUES (?,?,?)", (a.question, "queued", utc_now_str()))
        con.commit()
        start_job(c, con, "ask", {"ask_id": cur.lastrowid}, wait=True)
        r = con.execute("SELECT * FROM asks WHERE id=?", (cur.lastrowid,)).fetchone()
        print(f"status: {r['status']} {r['error'] or ''}\nSQL: {r['sql']}\nrows: {r['row_count']}")
        print(f"written to {c.report_dir / 'questions' / ('Q%03d.md' % cur.lastrowid)}")
    elif cmd == "lookup":
        from .lookup import lookup
        c = _case(a.case)
        kind, q = (("ip", a.ip) if a.ip else ("account", a.account) if a.account else ("identifier", a.ident) if a.ident else ("text", a.text))
        res = lookup(c, kind, q, a.t_from, a.t_to, a.limit)
        print(res["summary"])
        for r in res["rows"]:
            print(f"{r['cite']:24} {r['ts_utc'] or '':20} {r['account'] or '':28} {r['category'] or '':14} {r['ip'] or '':16} {r['action'] or ''}")
    elif cmd == "llm":
        from .config import load_settings
        from .llm import LLM
        print(json.dumps(LLM(load_settings()["llm"]).status(), indent=2))
    elif cmd == "selftest":
        from .selftest import selftest
        sys.exit(0 if selftest() else 1)
    elif cmd == "demo":
        from .selftest import make_demo_case
        c = make_demo_case(run=a.run)
        print(f"demo case ready: {c.dir}")
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
