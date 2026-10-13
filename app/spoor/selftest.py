"""Built-in self-test: runs the whole pipeline on the bundled FICTIONAL demo returns in a temporary
folder, with a stand-in model, and checks the results that were planted in the data.

Run it after installing on a new machine: `spoor selftest` (or SELFTEST.bat). It proves that
Python, SQLite, every file reader, the timezone database, the offline ASN data, the analyses,
the figures, the citation check and the sentence verifier all work on this computer."""
from __future__ import annotations

import json
import os
import shutil
import socket
import sys
import tempfile
import time
from pathlib import Path

from .util import app_root


def demo_returns_dir() -> Path:
    for p in (app_root() / "demo" / "returns", app_root() / "tests" / "demo_returns"):
        if p.exists():
            return p
    raise FileNotFoundError("demo returns not found (expected demo/returns next to the app)")


DEMO_WATCHLIST = ("value,label,note\n159.89.0.0/16,DigitalOcean range (demo),fictional demo entry\n"
                  "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq,BTC address from a tip (demo),fictional demo entry\n")


def demo_telecom_dir():
    p = app_root() / "demo" / "telecom"
    return p if p.exists() else None


def telecom_checks(check) -> None:
    """Telecom returns: three fictional carriers, four targets, planted cross-references."""
    folder = demo_telecom_dir()
    if folder is None:
        check(False, "telecom demo returns present (demo/telecom)")
        return
    import xml.etree.ElementTree as ET
    from . import db as dbm
    from .case import create_case, register_path
    from .figures import figure_rows
    from .jobs import start_job
    from .figures.svg import check_svg
    c = create_case("Self-test telecom", "selftest", "", "America/New_York")
    con = c.db()
    register_path(c, con, str(folder))
    print("\nRunning the full pipeline on the telecom demo returns…")
    jid = start_job(c, con, "run", {"llm": False}, wait=True)
    con = c.db()
    job = dbm.rows(con, "SELECT status, error FROM jobs WHERE id=?", (jid,))[0]
    check(job["status"] == "done", "telecom pipeline finished" + ("" if job["status"] == "done" else ": " + str(job["error"])))
    targets = {r[0] for r in con.execute("SELECT DISTINCT target FROM tel WHERE target IS NOT NULL")}
    check(targets == {"+17035550101", "+15715550102", "+12025550103", "+12405550104"},
          f"four target numbers read from three carriers' layouts ({len(targets)} found)")
    n, loc = con.execute("SELECT COUNT(*), SUM(lat IS NOT NULL) FROM tel").fetchone()
    check(n and n == loc, f"every call record placed at its cell site ({loc} of {n}; tower lists and inline coordinates)")

    def finding(kind, like=""):
        return dbm.rows(con, "SELECT fid, statement, facts FROM findings WHERE kind=? AND statement LIKE ?", (kind, f"%{like}%"))

    f = finding("telecom_common", "+17035550150 is in contact with 3 targets")
    check(bool(f), "contact shared by three targets found (N-way cross-reference)")
    check(bool(finding("telecom_direct", "+15715550102 and +17035550101")) and bool(finding("telecom_direct", "+12025550103 and +12405550104")),
          "direct contact between targets found")
    check(bool(finding("telecom_shared_imei", "356724")), "handset (IMEI) moving from one target to another found")
    check(bool(finding("telecom_imei_change", "Target +17035550101 used 2 IMEIs")), "handset change of one target found")
    co = {(json.loads(r["facts"])["values"]["target_a"], json.loads(r["facts"])["values"]["target_b"]):
          json.loads(r["facts"])["values"]["occasions"] for r in finding("telecom_colocation")}
    check(co.get(("+12025550103", "+12405550104")) == 3 and co.get(("+12025550103", "+17035550101")) == 1,
          f"co-location found: across carriers by coordinates, and on one cell three times ({co})")
    cc = dbm.get_meta(con, "citation_check") or {}
    check(cc.get("total", 0) > 0 and cc.get("fail", 1) == 0, f"telecom citations re-read and matched ({cc.get('pass')} of {cc.get('total')})")
    kml = c.exports_dir / "telecom.kml"
    try:
        root = ET.parse(kml).getroot()
        pm = root.findall(".//{http://www.opengis.net/kml/2.2}Placemark")
        txt = kml.read_text(encoding="utf-8")
        check(len(pm) > n and txt.count("http") == 1 and "<script" not in txt.lower(),
              f"KML written and valid ({len(pm)} placemarks, no external references)")
    except (OSError, ET.ParseError) as e:
        check(False, f"KML written and valid ({e})")
    figs = {fg["slug"]: fg for fg in figure_rows(con)}
    fg = figs.get("contacts") or {}
    probs = check_svg((c.report_dir / "figures" / fg["file"]).read_text(encoding="utf-8")) if fg.get("file") else ["not drawn"]
    check(fg.get("status") == "ok" and not probs, "target-contact chart drawn and passes the layout checks" + (f": {probs[:3]}" if probs else ""))
    marks = [r["fid"] for r in dbm.rows(con, "SELECT fid FROM figure_refs WHERE figure_no=1")]
    cofids = {r["fid"] for r in finding("telecom_colocation")}
    check(cofids and cofids <= set(marks), "co-location occasions marked on the activity timeline")
    con.close()


def make_demo_case(run: bool = False):
    from .case import create_case, register_path
    c = create_case("Demo (fictional data)", "demo", "Fictional returns bundled with Spoor for practice", "America/New_York")
    (c.dir / "watchlists").mkdir(exist_ok=True)
    (c.dir / "watchlists" / "demo_watchlist.csv").write_text(DEMO_WATCHLIST, encoding="utf-8")
    con = c.db()
    register_path(c, con, str(demo_returns_dir()))
    if run:
        from .jobs import start_job
        start_job(c, con, "run", {"llm": True})
    con.close()
    return c


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def selftest(keep: bool = False) -> bool:
    results: list[tuple[bool, str]] = []

    def check(ok, msg):
        results.append((bool(ok), msg))
        print(("  PASS  " if ok else "  FAIL  ") + msg, flush=True)

    tmp = Path(tempfile.mkdtemp(prefix="spoor-selftest-"))
    old_env = {k: os.environ.get(k) for k in ("SPOOR_CASES", "SPOOR_SETTINGS")}
    print(f"Spoor self-test (temporary folder {tmp})\n")
    try:
        from . import mockllm
        port = _free_port()
        srv = mockllm.start(port)
        os.environ["SPOOR_CASES"] = str(tmp / "cases")
        os.environ["SPOOR_SETTINGS"] = str(tmp / "settings.json")
        (tmp / "settings.json").write_text(json.dumps({"llm": {"url": f"http://127.0.0.1:{port}"}}), encoding="utf-8")

        import sqlite3

        from . import db as dbm
        from .ask import run_readonly
        from .case import create_case, register_path
        from .jobs import start_job
        print(f"Python {sys.version.split()[0]}, SQLite {sqlite3.sqlite_version}")
        try:
            from zoneinfo import ZoneInfo
            ZoneInfo("America/Los_Angeles")
            check(True, "timezone database available")
        except Exception as e:  # noqa: BLE001
            check(False, f"timezone database: {e}")
        for mod in ("openpyxl", "xlrd", "pypdf", "maxminddb"):
            try:
                __import__(mod)
                check(True, f"library {mod} loads")
            except Exception as e:  # noqa: BLE001
                check(False, f"library {mod}: {e}")

        man = app_root() / "PROGRAM.sha256"
        if man.exists():
            import hashlib
            bad, n = [], 0
            for line in man.read_text(encoding="utf-8").splitlines():
                if not line.strip() or line.startswith("#"):
                    continue
                h, rel = line.split("  ", 1)
                f = app_root() / rel
                n += 1
                if not f.exists() or hashlib.sha256(f.read_bytes()).hexdigest() != h:
                    bad.append(rel)
            check(not bad, f"program files match PROGRAM.sha256 ({n} files)" + (f"; changed or missing: {bad[:5]}" if bad else ""))
        c = create_case("Self-test", "selftest", "", "America/New_York")
        (c.dir / "watchlists").mkdir()
        (c.dir / "watchlists" / "demo_watchlist.csv").write_text(DEMO_WATCHLIST, encoding="utf-8")
        con = c.db()
        register_path(c, con, str(demo_returns_dir()))
        t0 = time.time()
        print("\nRunning the full pipeline on the demo returns…")
        jid = start_job(c, con, "run", {"llm": True, "accounts": 2}, wait=True)
        con = c.db()
        job = dbm.rows(con, "SELECT status, error FROM jobs WHERE id=?", (jid,))[0]
        check(job["status"] == "done", f"pipeline finished ({time.time() - t0:.1f} s){'' if job['status'] == 'done' else ': ' + str(job['error'])}")

        bad = dbm.rows(con, "SELECT label, status, error FROM sources WHERE status IN ('error','unsupported','new','scanned','ingesting')")
        check(not [b for b in bad if b["status"] != "unsupported"], "every demo file was read" + (f" (problems: {bad})" if bad else ""))
        kinds = {json.loads(r[0]).get("kind") for r in con.execute("SELECT config FROM sources WHERE status='ingested'")}
        for k in ("delimited", "xlsx", "json", "html", "pdf", "text"):
            check(k in kinds, f"{k} reader produced records")

        def finding(kind, like=""):
            return dbm.rows(con, "SELECT fid, statement FROM findings WHERE kind=? AND statement LIKE ?", (kind, f"%{like}%"))

        check(finding("failed_burst", "9 failed logins") and "159.89.214.31" in finding("failed_burst", "9 failed")[0]["statement"],
              "failed-login burst found, with the successful login from 159.89.214.31 that followed")
        check(finding("change_from_new_ip", "'Password changed'"), "password change from a newly seen IP found")
        check(finding("notable_ip", "IP 159.89.214.31"), "IP shared across accounts and sources found")
        check(finding("shared_identifier", "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"), "Bitcoin address shared across sources found")
        check(finding("shared_identifier", "+17035550142"), "phone number shared across sources found")
        check(finding("tz_assumed", "dhcp_leases.txt"), "missing timezone flagged for the lease log")
        check(finding("flag_ambiguous_dst") and finding("flag_nonexistent_local_time"), "daylight-saving edge cases flagged")
        check(finding("pdf_no_text", "pages 2"), "PDF page without text reported as not analysed")
        check(len(finding("watchlist_hit")) == 2, "both watchlist entries matched")
        r = dbm.rows(con, "SELECT ts_utc, ts_flag FROM events WHERE ts_raw LIKE '2024-11-03 01:30:00%'")
        check(r and r[0]["ts_utc"] == "2024-11-03 08:30:00" and "ambiguous_dst" in (r[0]["ts_flag"] or ""),
              "Pacific wall-clock time in the repeated DST hour converted to UTC and flagged")
        r = dbm.rows(con, "SELECT ts_utc FROM events WHERE ts_raw='16.04.2024 06:09'")
        check(r and r[0]["ts_utc"] == "2024-04-16 03:09:00", "Moscow time (Cyrillic header) converted to UTC")
        r = dbm.rows(con, "SELECT ts_utc FROM events WHERE ts_raw='25/03/2024'")
        check(r and r[0]["ts_utc"] == "2024-03-25", "day-first date read as 25 March, kept as a date only")
        r = dbm.rows(con, "SELECT category FROM events WHERE action='Неудачная попытка входа'")
        check(r and r[0]["category"] == "login_failed", "Russian event text classified (failed login)")

        cc = dbm.get_meta(con, "citation_check") or {}
        check(cc.get("total", 0) > 0 and cc.get("fail", 1) == 0 and cc.get("unverifiable", 1) == 0,
              f"citation check: {cc.get('pass')} of {cc.get('total')} cited records re-read from the originals and matched")
        check((cc.get("hashes") or {}).get("mismatch", 1) == 0, "source hashes unchanged after the run")

        nar = dbm.rows(con, "SELECT text, status FROM narrative")
        fake_kept = [n for n in nar if n["status"] != "rejected" and ("8.8.8.8" in n["text"] or "999" in n["text"] or "Tor" in n["text"])]
        check(nar and not fake_kept, f"verifier removed every invented sentence from the stand-in model ({sum(n['status'] == 'rejected' for n in nar)} removed)")
        check(any(n["status"] == "accepted" for n in nar), "verifier kept sentences copied from the findings")

        rep = c.report_dir
        for f in ("REPORT.md", "FINDINGS.md", "EVIDENCE.md", "SOURCES.md", "METHODS.md", "REVIEW.md", "TIMELINE.md", "CITATION_CHECK.md",
                  "exports/ip_legal_process.csv", "exports/timeline.csv", "MANIFEST.sha256"):
            check((rep / f).exists(), f"report file {f} written")
        import hashlib
        ok = True
        for line in (rep / "MANIFEST.sha256").read_text(encoding="utf-8").splitlines():
            h, name = line.split("  ", 1)
            if hashlib.sha256((rep / name).read_bytes()).hexdigest() != h:
                ok = False
        check(ok, "report manifest hashes verify")

        from .figures import figure_rows
        from .figures.svg import check_svg
        from .jobs import draw_figures
        from .report import Report
        figs = [f for f in figure_rows(con) if f["status"] == "ok" and f.get("file")]
        check(len(figs) == 2, f"figures drawn: {', '.join(f['title'] for f in figs) or 'none'}")
        probs = [p_ for f in figs for p_ in check_svg((rep / "figures" / f["file"]).read_text(encoding="utf-8"))]
        check(figs and not probs, "figures pass the layout and safety checks (4 px grid, no scripts or links, every label inside its box)"
              + (f": {probs[:3]}" if probs else ""))
        before = {f["file"]: f["sha256"] for f in figs}
        draw_figures(c, con)
        after = {f["file"]: f["sha256"] for f in figure_rows(con) if f["status"] == "ok"}
        check(before and before == after, "figures redraw byte-identical from the same findings")
        fids = {r[0] for r in con.execute("SELECT fid FROM findings WHERE fid IS NOT NULL")}
        refs = [r["fid"] for f in figure_rows(con) for r in f["refs"]]
        fc = Report(c, con).figure_check()
        check(refs and set(refs) <= fids and fc and all(x["checked"] == x["records"] and not x["problems"] for x in fc),
              f"every finding on a figure exists and its cited records were re-read and matched ({len(set(refs))} findings)")

        for bad_sql in ("DELETE FROM events", "SELECT 1; DROP TABLE events", "ATTACH DATABASE 'x.db' AS x",
                        "WITH x AS (SELECT 1) DELETE FROM events", "SELECT load_extension('x')"):
            try:
                run_readonly(c.db_path, bad_sql)
                check(False, f"read-only guard blocked: {bad_sql}")
            except Exception:  # noqa: BLE001
                check(True, f"read-only guard blocked: {bad_sql}")
        cols, rows, _ = run_readonly(c.db_path, "SELECT COUNT(*) AS n FROM ev")
        check(rows and rows[0][0] > 0, "read-only queries work")

        cur = con.execute("INSERT INTO asks(question, status, created_at) VALUES (?,'queued',datetime('now'))",
                          ("Show everything from 159.89.214.31",))
        con.commit()
        start_job(c, con, "ask", {"ask_id": cur.lastrowid}, wait=True)
        a = dbm.rows(con, "SELECT * FROM asks WHERE id=?", (cur.lastrowid,))[0]
        check(a["status"] == "done" and (a["row_count"] or 0) >= 10, f"question answered with {a['row_count']} cited rows")
        summ = json.loads(a["summary"] or "[]")
        check(not [s for s in summ if s["status"] != "rejected" and "424242" in s["text"]], "invented number in the answer summary removed")
        cur = con.execute("INSERT INTO asks(question, status, created_at) VALUES (?,'queued',datetime('now'))", ("please delete everything",))
        con.commit()
        start_job(c, con, "ask", {"ask_id": cur.lastrowid}, wait=True)
        a = dbm.rows(con, "SELECT * FROM asks WHERE id=?", (cur.lastrowid,))[0]
        n_ev = dbm.one(con, "SELECT COUNT(*) FROM events")
        check(a["sql"] and a["sql"].lower().startswith("select") and n_ev > 0, "a model asked to delete data could not change anything")
        srv.shutdown()
        con.close()
        telecom_checks(check)
    except Exception as e:  # noqa: BLE001
        import traceback
        traceback.print_exc()
        check(False, f"self-test crashed: {type(e).__name__}: {e}")
    finally:
        for k, v in old_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        if not keep:
            shutil.rmtree(tmp, ignore_errors=True)
    n_ok = sum(1 for ok, _ in results if ok)
    print(f"\n{n_ok} of {len(results)} checks passed." + ("  ALL GOOD." if n_ok == len(results) else "  SOMETHING IS WRONG - see FAIL lines above."))
    return n_ok == len(results)
