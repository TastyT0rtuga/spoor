"""Developer tests: units (time parsing, identifiers, verifier, Markdown safety), the built-in
self-test, and a dashboard/API smoke test including the security checks.

usage:  python tests/run_tests.py      (from the Spoor folder; uses app/ and vendor/)"""
from __future__ import annotations

import http.client
import json
import os
import re
import shutil
import sys
import tempfile
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT / "app"), str(ROOT / "vendor")]

FAILS: list[str] = []


def ok(cond, msg):
    print(("  ok    " if cond else "  FAIL  ") + msg)
    if not cond:
        FAILS.append(msg)


def unit_time():
    from spoor.timeparse import TsParser, TzSpec, fmt_utc
    utc = TsParser(TzSpec("UTC"))
    pt = TsParser(TzSpec("America/Los_Angeles", assumed=False))
    dmy = TsParser(TzSpec("Europe/Moscow", assumed=False), date_order="DMY")
    cases = [
        (utc, "2024-03-05T14:22:10Z", "2024-03-05 14:22:10", ""),
        (utc, "Mar 5, 2024, 2:22:10 PM PST", "2024-03-05 22:22:10", ""),
        (utc, "Jul 5, 2024, 2:22:10 PM PST", "2024-07-05 22:22:10", "abbr_dst_mismatch"),
        (utc, "Tue, 05 Mar 2024 14:22:10 -0800", "2024-03-05 22:22:10", ""),
        (utc, "05/Mar/2024:14:22:10 -0800", "2024-03-05 22:22:10", ""),
        (utc, "1709648530123", "2024-03-05 14:22:10.123", ""),
        (pt, "2024-03-10 02:30:00", "2024-03-10 10:30:00", "nonexistent_local_time"),
        (pt, "2024-11-03 01:30:00", "2024-11-03 08:30:00", "ambiguous_dst"),
        (dmy, "16.04.2024 06:09", "2024-04-16 03:09:00", ""),
        (utc, "05 марта 2024 14:22", "2024-03-05 14:22:00", ""),
    ]
    for p, v, want, flag in cases:
        r = p.parse(v)
        ok(r is not None and fmt_utc(r.utc) == want and (flag in r.flags if flag else not r.flags),
           f"time {v!r} -> {want} {flag}".strip())
    ok(utc.parse("25/03/2024 10:00") is None, "impossible MM/DD date is refused, not guessed")
    ok(not utc.find_all("from 10.12.20.4 today"), "an IP address is not mistaken for a date")


def unit_identifiers():
    from spoor.identifiers import extract, keccak256
    ok(keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470", "keccak-256 test vector")
    got = {(k, n, v) for k, _r, n, v in extract(
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed "
        "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb (703) 555-0142 IMEI 490154203237518")}
    ok(("btc", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "checksum") in got, "Base58Check Bitcoin address verified")
    ok(("btc", "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", "checksum") in got, "Bech32 address verified")
    ok(("eth", "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed", "checksum") in got, "EIP-55 address verified")
    ok(("trx", "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", "checksum") in got, "TRON address verified")
    ok(not any(n.endswith("fNb") for _k, n, _v in got), "address with a bad checksum ignored")
    ok(("phone", "+17035550142", "format") in got and ("imei", "490154203237518", "checksum") in got, "phone and IMEI")


def unit_verify():
    from spoor.verify import FactBase, check_sentence
    fb = FactBase([{"id": "F001", "title": "x", "statement": "IP 203.0.113.5 appears in 698 events between 2024-01-03 08:11:02 UTC "
                    "and 2024-03-05 14:22:10 UTC; 76.2% from US; account jd@example.com.", "values": {}}])
    table = [("IP 203.0.113.5 appears in 698 events.", "accepted"), ("IP 203.0.113.5 appears in 700 events.", "rejected"),
             ("IP 203.0.113.5 appears in about 700 events.", "accepted"), ("IP 198.51.100.1 appears in 698 events.", "rejected"),
             ("The first event was on January 3, 2024 at 08:11 UTC.", "accepted"), ("The first event was on January 4, 2024.", "rejected"),
             ("About 80% of events came from the US.", "rejected"), ("Account jd@example.com likely used a VPN at 08:11.", "flagged"),
             ("Activity was heavy.", "rejected"), ("Account jd@example.com used Tor.", "rejected")]
    for t, want in table:
        st, *_ = check_sentence(t, ["F001"], fb)
        ok(st == want, f"verifier {want}: {t}")
    st, *_ = check_sentence("IP 203.0.113.5 appears in 698 events.", ["F002"], fb)
    ok(st == "rejected", "verifier rejects a citation to a finding that does not exist")


def unit_markdown():
    from spoor.markdown import render
    h = render("<script>alert(1)</script>\n\n[x](javascript:alert(1)) `S03:L12` | a |")
    ok("<script>" not in h and "javascript:" not in h, "Markdown viewer escapes HTML and script links")
    ok('data-cite="S03:L12"' in h, "citations become clickable in the viewer")


def _figure_case(root: Path, name: str, folder: Path, tz: str = "America/New_York", params=None, interrupt=None,
                 case_params=None):
    """Create a case in its own folder and run it (optionally interrupted once, then resumed)."""
    root.mkdir(parents=True, exist_ok=True)
    os.environ["SPOOR_CASES"] = str(root / "cases")
    os.environ["SPOOR_SETTINGS"] = str(root / "settings.json")
    (root / "settings.json").write_text(json.dumps({"llm": {"enabled": False, "url": "http://127.0.0.1:9"}}))
    from spoor.case import create_case, register_path
    from spoor.jobs import start_job
    c = create_case(name, "t", "", tz)
    if case_params:
        c.info["params"] = dict(c.info.get("params") or {}, **case_params)
        c.save()
    con = c.db()
    register_path(c, con, str(folder))
    restore = None
    if interrupt:
        restore = interrupt()
    start_job(c, con, "run", dict({"llm": False}, **(params or {})), wait=True)
    if restore:
        restore()
        st = con.execute("SELECT status FROM jobs ORDER BY id DESC LIMIT 1").fetchone()[0]
        ok(st == "cancelled", f"{name}: run interrupted as planned ({st})")
        start_job(c, con, "run", dict({"llm": False}, **(params or {})), wait=True)
    st = con.execute("SELECT status FROM jobs ORDER BY id DESC LIMIT 1").fetchone()[0]
    ok(st == "done", f"{name}: run finished ({st})")
    return c, c.db()


def _cancel_once(module, attr):
    """Make module.attr raise Cancelled the first time it is called (a crash or cancel at that point)."""
    import importlib
    mod = importlib.import_module(module)
    orig = getattr(mod, attr)
    state = {"done": False}
    from spoor.jobs import Cancelled

    def wrapper(*a, **k):
        if not state["done"]:
            state["done"] = True
            raise Cancelled()
        return orig(*a, **k)

    def install():
        setattr(mod, attr, wrapper)
        return lambda: setattr(mod, attr, orig)
    return install


def figures_tests():
    import hashlib
    from spoor.figures import figure_rows
    from spoor.figures.svg import check_svg, svg_texts
    from spoor.jobs import draw_figures
    from spoor.selftest import demo_returns_dir
    tmp = Path(tempfile.mkdtemp(prefix="spoor-fig-"))
    old_env = {k: os.environ.get(k) for k in ("SPOOR_CASES", "SPOOR_SETTINGS")}
    try:
        def hashes(c):
            return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((c.report_dir / "figures").glob("*.svg"))}

        a, con = _figure_case(tmp / "a", "Figure test", demo_returns_dir())
        figs = figure_rows(con)
        ha = hashes(a)
        ok([f["status"] for f in figs] == ["ok", "ok"] and len(ha) == 2, f"demo: both figures drawn ({sorted(ha)})")
        for name in sorted(ha):
            svg = (a.report_dir / "figures" / name).read_text(encoding="utf-8")
            probs = check_svg(svg)
            ok(not probs, f"{name}: grid, safety and layout checks pass" + (f" - {probs[:3]}" if probs else ""))
            ok("@font-face" in svg and "font/woff2;base64," in svg, f"{name}: fonts embedded, nothing loaded from outside")
        # determinism and resume
        draw_figures(a, con)
        ok(hashes(a) == ha, "redrawing from the same findings gives byte-identical SVG")
        b, _ = _figure_case(tmp / "b", "Figure test", demo_returns_dir(), interrupt=_cancel_once("spoor.figures.timeline", "build"))
        ok(hashes(b) == ha, "a run interrupted while drawing figures, then resumed, gives identical figures")
        c3, _ = _figure_case(tmp / "c", "Figure test", demo_returns_dir(), interrupt=_cancel_once("spoor.derive", "build_indexes"))
        ok(hashes(c3) == ha, "a run interrupted after reading the files, then resumed, gives identical figures")
        # coverage: every finding on a figure exists; every figure has a sources table
        fids = {r[0] for r in con.execute("SELECT fid FROM findings WHERE fid IS NOT NULL")}
        refs = [r for f in figs for r in f["refs"]]
        ok(refs and all(r["fid"] in fids for r in refs), f"every finding ID on a figure exists in FINDINGS ({len(refs)} references)")
        texts = " ".join(t for name in ha for t in svg_texts((a.report_dir / "figures" / name).read_text(encoding="utf-8")))
        shown = set(re.findall(r"\bF\d{3,}\b", texts))
        ok(shown and shown <= fids, f"every finding ID printed on a figure exists ({len(shown)} shown)")
        fm = (a.report_dir / "FIGURES.md").read_text(encoding="utf-8")
        ok(fm.count("**Figure sources**") == 2 and "## Figure 1" in fm and "## Figure 2" in fm, "FIGURES.md has a sources table per figure")
        rep = (a.report_dir / "REPORT.md").read_text(encoding="utf-8")
        ok("figures/FIG01-timeline.svg" in rep and "figures/FIG02-links.svg" in rep, "REPORT.md embeds both figures")
        man = (a.report_dir / "MANIFEST.sha256").read_text(encoding="utf-8")
        ok(all(ha[n] + "  figures/" + n in man for n in ha), "MANIFEST.sha256 covers the figures")
        ok("Every finding referenced by a figure passed the re-read check" in (a.report_dir / "CITATION_CHECK.md").read_text(encoding="utf-8"),
           "CITATION_CHECK.md confirms the findings shown in figures")
        rv = (a.report_dir / "REVIEW.md").read_text(encoding="utf-8")
        ok("- [ ] Figure 1 (" in rv and "- [ ] Figure 2 (" in rv, "REVIEW.md has a tick-box per figure")
        ok("## Figures" in (a.report_dir / "METHODS.md").read_text(encoding="utf-8"), "METHODS.md describes the figures")
        # the queries in FIGURES.md return exactly what is drawn
        tl = figs[0]
        got: dict = {}
        for acc, b_, n in con.execute(tl["data_sql"][0][1]):
            got.setdefault("(no account)" if acc is None else acc, {})[b_] = n
        ok(got == tl["meta"]["bins"], "timeline: the data query returns exactly the bars drawn")
        lk = figs[1]
        for (what, sql), pnl in zip(lk["data_sql"], lk["meta"]["panels"]):
            rows = sorted([r[0], r[1], r[2]] for r in con.execute(sql))
            ok(rows == pnl["edges"], f"link chart {what}: the data query returns exactly the lines drawn")
        # the checker catches what it should
        good = (a.report_dir / "figures" / "FIG02-links.svg").read_text(encoding="utf-8")
        for bad, what in ((good.replace("</svg>", "<script>alert(1)</script></svg>"), "a script"),
                          (good.replace("<rect ", '<rect onclick="x()" ', 1), "an event handler"),
                          (good.replace("</svg>", '<a href="http://example.com"><text x="0" y="0">x</text></a></svg>'), "an external link"),
                          (re.sub(r'<rect x="(\d+)"', lambda m: f'<rect x="{int(m.group(1)) + 2}"', good, count=3), "off-grid coordinates"),
                          (good.replace("</svg>", '<text x="24" y="36" font-family="' + "'Atkinson Next', 'Segoe UI', 'DejaVu Sans', Arial, sans-serif"
                                        + '" font-size="20" font-weight="700" fill="#000">Overlapping title</text></svg>'), "overlapping text")):
            ok(check_svg(bad), f"layout checker flags {what}")
        # stress: long and Cyrillic names, 260 shared IPs, many bursts, a long silence; and a one-day return
        sys.path.insert(0, str(ROOT / "tests"))
        import make_stress_data
        make_stress_data.main(str(tmp / "stress"))
        s1, con1 = _figure_case(tmp / "s1", "Stress", tmp / "stress" / "long")
        s2, con2 = _figure_case(tmp / "s2", "One day", tmp / "stress" / "short", tz="Europe/Moscow")
        for cc, cn, label in ((s1, con1, "stress"), (s2, con2, "one-day")):
            fr = figure_rows(cn)
            ok([f["status"] for f in fr] == ["ok", "ok"], f"{label}: both figures drawn")
            for f in [f for f in fr if f.get("file")]:
                svg = (cc.report_dir / "figures" / f["file"]).read_text(encoding="utf-8")
                probs = check_svg(svg)
                ok(not probs, f"{label} {f['file']}: no text outside its box or the canvas, no overlaps" + (f" - {probs[:3]}" if probs else ""))
        fr1 = figure_rows(con1)
        ok(any(n.startswith("Showing 12 of 30 accounts") for n in fr1[0]["notes"]), "stress: the timeline prints its account cap")
        ok(any("showing 12 of 30 accounts and 16 of" in n for n in fr1[1]["notes"]), "stress: the link chart prints its caps")
        txt = " ".join(svg_texts((s1.report_dir / "figures" / fr1[0]["file"]).read_text(encoding="utf-8")))
        ok("Showing 12 of 30 accounts" in txt and "\u2026" in txt, "stress: caps and shortened labels are printed on the figure")
        ok(len(fr1[0]["meta"]["segments"]) == 2, "stress: the six-month silence is cut from the axis")
        u = figure_rows(con2)[0]["meta"]["unit"]
        ok(u in ("minute", "5 minutes", "15 minutes", "hour", "3 hours", "6 hours"), f"one-day: bins finer than a day ({u})")
        # switched off
        d, cond = _figure_case(tmp / "d", "No figures", demo_returns_dir(), params={"figures": False})
        ok(not (d.report_dir / "figures").exists() or not list((d.report_dir / "figures").glob("*.svg")), "--no-figures: no figures drawn")
        ok("switched off" in (d.report_dir / "REVIEW.md").read_text(encoding="utf-8"), "--no-figures: REVIEW.md says so")
    finally:
        for k, v in old_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        shutil.rmtree(tmp, ignore_errors=True)


def unit_telecom():
    from spoor.mapping import propose_mapping
    from spoor.telecom import km, norm_cell, norm_dir, norm_kind, norm_number, parse_duration
    ok(norm_number("(703) 555-0101") == "+17035550101" and norm_number("17035550101") == "+17035550101"
       and norm_number("72345") == "72345" and norm_number("+44 20 7946 0958") == "+442079460958" and norm_number("000") is None,
       "numbers normalised (NANP to E.164, short codes and foreign numbers kept)")
    ok(norm_cell("NL-1021-02") == norm_cell("nl 1021 2") == "NL-1021-2" and norm_cell("N/A") is None, "cell IDs compared without case, separators or leading zeros")
    ok(parse_duration("00:06:46") == 406 and parse_duration("6:46") == 406 and parse_duration("95") == 95
       and parse_duration("2.5", "Duration (min)") == 150 and parse_duration("12 sec") == 12, "durations read (HH:MM:SS, MM:SS, seconds, minutes header)")
    ok(norm_dir("Outgoing", "") == "out" and norm_dir("", "MTC") == "in" and norm_dir("", "SMS-MO") == "out" and norm_dir("", "Voice") == ""
       and norm_dir("MF", "") == "fwd" and norm_dir("M0", "") == "out", "direction from direction column or call type (MF forwarded, M0 typo)")
    ok(norm_kind("SMS-MT") == "sms" and norm_kind("MOC") == "voice" and norm_kind("GPRS") == "data" and norm_kind("Text") == "sms"
       and norm_kind("SMSC") == "sms" and norm_kind("RCS-IMCHAT") == "rcs" and norm_kind("mSTerminatingSMSinMSC") == "sms"
       and norm_kind("AUDIO CALL") == "voice" and norm_kind("NULL") == "", "call / text / chat / data kinds")
    from spoor.telecom import parse_eci, parse_cell_location, norm_imei
    ok(parse_eci("12344578")[0] == 12344578 and parse_eci("311480-0c82216")[0] == 51234 * 256 + 22
       and parse_eci("311580-123456-1")[0] == 123456 * 256 + 1 and parse_eci("310260-0012345-005")[0] == 12345 * 256 + 5
       and parse_eci("310260012344578")[0] == 12344578 and parse_eci("12344578:12344579")[0] == 12344578
       and parse_eci("N/A")[0] is None, "cell identity: decimal, hex ECGI, MCC-MNC-eNB-cell, 15-digit ECGI, first:last")
    cl = parse_cell_location("[12344578:48221:-77.30020:38.80010:110:-1.0:200;12344579:48221:-77.3:38.8:230:-1.0:200]")
    ok(cl["eci"] == 12344578 and cl["lat"] == 38.8001 and cl["lon"] == -77.3002 and cl["azimuth"] == 110 and cl["cells_listed"] == 2
       and "lat" not in parse_cell_location("[000000020:0:0.0:0.0:-1:-1.0:]"), "AT&T CellLocation: longitude first, 0,0 = unknown")
    ok(norm_imei("350000000012340")[0] == norm_imei("3500000000123401")[0] == "35000000001234" and norm_imei("3.50000E+14") == (None, "sci"),
       "IMEIs compared on 14 digits; scientific notation rejected")
    ok(abs(km(38.7521, -77.4739, 38.75228, -77.47371) * 1000 - 26) < 3, "site distance (haversine)")
    m, _ = propose_mapping(["Name", "Cell", "Email"], {"Cell": ["(703) 555-0142"], "Name": ["J"], "Email": ["a@b.com"]})
    ok("cell" not in m, "a 'Cell' column holding phone numbers is not read as a cell site")
    m, _ = propose_mapping(["Date", "Called Number", "Duration"], {"Date": ["2024-04-01 10:00"], "Called Number": ["7035550101"], "Duration": ["12"]})
    ok(m.get("counterparty") == "Called Number" and "term" not in m, "a lone called-number column is the other party")
    m, _ = propose_mapping(["Cell ID", "Latitude", "Longitude", "Azimuth"],
                           {"Cell ID": ["123"], "Latitude": ["38.1"], "Longitude": ["-77.2"], "Azimuth": ["120"]})
    ok(m.get("cell") == "Cell ID" and m.get("lat") == "Latitude" and m.get("lon") == "Longitude" and m.get("azimuth") == "Azimuth",
       "tower-list columns recognised")


def telecom_isolation():
    """Returns that are not telecom returns are read exactly as before telecom support existed."""
    from spoor.mapping import categorize, default_account_from, propose_mapping
    m, _ = propose_mapping(["Timestamp (UTC)", "User", "IP Address", "Event", "IMEI", "Session Duration", "Latitude", "Longitude"],
                           {"Timestamp (UTC)": ["2024-04-01 10:00:00"], "User": ["a@b.com"], "IP Address": ["203.0.113.5"],
                            "Event": ["Login"], "IMEI": ["353911104143632"], "Session Duration": ["00:12:00"],
                            "Latitude": ["38.75"], "Longitude": ["-77.47"]})
    ok(m.get("device") == "IMEI" and not any(k in m for k in ("imei", "duration", "lat", "lon")),
       "a login log with IMEI, duration and coordinate columns is not read as telecom (IMEI stays the device)")
    ok(default_account_from([("L2", "Account Number: 12345678")])[0] is None, "'Account Number:' in a bank preamble is not a default account")
    ok(categorize("Sent text", "", None) == "transaction" and categorize("Sent text", "", None, telecom=True) == "communication",
       "call-record wording only applies to telecom tables")
    from spoor.readers.delimited import scan as _scan
    from spoor.selftest import demo_returns_dir
    split = [p.name for p in demo_returns_dir().rglob("*") if p.suffix in (".csv", ".txt", ".log", ".tsv")
             and len(_scan(p, p.name)["tables"]) != 1]
    ok(not split, "ordinary single-table files are never split into several tables" + (f": {split}" if split else ""))
    tmp = Path(tempfile.mkdtemp(prefix="spoor-iso-"))
    old_env = {k: os.environ.get(k) for k in ("SPOOR_CASES", "SPOOR_SETTINGS")}
    try:
        _c, con = _figure_case(tmp, "Isolation", demo_returns_dir())
        n_tel = con.execute("SELECT COUNT(*) FROM tel").fetchone()[0]
        n_f = con.execute("SELECT COUNT(*) FROM findings WHERE module='telecom'").fetchone()[0]
        n_fig = con.execute("SELECT COUNT(*) FROM figures WHERE slug='contacts'").fetchone()[0]
        ok(n_tel == 0 and n_f == 0 and n_fig == 0 and not (_c.exports_dir / "telecom.kml").exists(),
           "the non-telecom demo produces no telecom records, findings, figure or KML")
        rows = {r[0]: r[1] for r in con.execute("SELECT display, rows FROM sources")}
        st = [v for k, v in rows.items() if k.endswith("statement_transactions.csv")]
        ok(st == [6], f"the bank statement keeps all 6 rows ({st})")
    finally:
        for k, v_ in old_env.items():
            if v_ is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v_
        shutil.rmtree(tmp, ignore_errors=True)


def carrier_layout_tests():
    """Carrier layouts (fictional values): every quirk the format readers handle, one case per layout."""
    import json as _json
    sys.path.insert(0, str(ROOT / "tests"))
    import make_carrier_layouts as mcl
    tmp = Path(tempfile.mkdtemp(prefix="spoor-cl-"))
    old_env = {k: os.environ.get(k) for k in ("SPOOR_CASES", "SPOOR_SETTINGS")}
    try:
        mcl._USED.clear()
        mcl.R.seed(20240521)
        mcl.main(str(tmp / "gen"))
        bundled = ROOT / "demo" / "carrier_layouts"
        same = all((tmp / "gen" / p.relative_to(bundled)).read_bytes() == p.read_bytes()
                   for p in bundled.rglob("*") if p.is_file() and p.suffix in (".csv", ".txt"))
        ok(same, "carrier-layout generator reproduces the bundled text/CSV demo files")
        cases = {}
        for name in ("mediation", "volte", "report", "hda", "dumps"):
            shutil.copytree(bundled / name, tmp / "in" / name)
        for f in (bundled / "location").iterdir():
            shutil.copy(f, tmp / "in" / "mediation" / f.name)
        for name in ("mediation", "volte", "report", "hda", "dumps"):
            c, con = _figure_case(tmp / name, f"Layout {name}", tmp / "in" / name, params={"figures": False})
            cases[name] = (c, con)

        def q(name, sql, args=()):
            return cases[name][1].execute(sql, args).fetchall()

        def facts(name, kind):
            return [_json.loads(f)["values"] for (f,) in q(name, "SELECT facts FROM findings WHERE kind=? ORDER BY fid", (kind,))]

        E = mcl.EXPECT
        # mediation spreadsheet: target only in the file name; eNodeB + sector -> ECI -> tower list; texts carry no cell
        tq = facts("mediation", "telecom_quality")[0]
        ok(E["mediation_target"] in tq["targets"] and list(tq["filename_targets"].values())[0]["target"] == E["mediation_target"],
           "mediation layout: target taken from the file name (and listed for review)")
        n_eci = q("mediation", "SELECT COUNT(*) FROM tel WHERE loc_basis LIKE 'tower list in the same folder (by ECI)%'")[0][0]
        ok(n_eci > 0, f"mediation layout: voice records without coordinates located by eNodeB + sector -> ECI ({n_eci})")
        tl = tuple(q("mediation", "SELECT COUNT(*), SUM(ts_utc IS NOT NULL) FROM events e JOIN sources s ON s.id=e.source_id "
                                  "WHERE s.display LIKE '%Tower_List%'")[0])
        ok(tl[0] == 24 and not tl[1], "a tower list's ListDate column is not read as event times")
        ok(not q("mediation", "SELECT 1 FROM tel WHERE target=?", (E["ta_imsi"],)) and
           q("mediation", "SELECT COUNT(*) FROM tel WHERE src_kind='ta' AND target=?", (E["mediation_target"],))[0][0] == 30,
           "timing-advance report named by IMSI filed under the number whose CDR shows that IMSI")
        ok(q("mediation", "SELECT COUNT(*) FROM tel WHERE src_kind='ping' AND target=? AND dev_lat IS NOT NULL AND lat IS NULL",
             (E["mediation_target"],))[0][0] == 12, "pings read as device location estimates, not cell sites")
        prof = facts("mediation", "telecom_target")[0]
        ok(prof["data_sessions"] == 0 and prof["timing_advance_estimates"] == 30 and prof["ping_estimates"] == 12,
           "location estimates are not counted as data usage in the target profile")
        # VoLTE: local and GMT times, MF legs, Cell Face + eNB -> hex ECGI
        m = _json.loads(q("volte", "SELECT config FROM sources WHERE display LIKE '%VoLTE%'")[0][0])["tables"][0]["mapping"]
        ok(m.get("ts") == "Record Open Dt/Tm(GMT)" and m.get("orig") == "CPN" and m.get("term") == "Called #",
           "VoLTE layout: the GMT column is the time; CPN / Called # are the two parties")
        ok(tuple(q("volte", "SELECT COUNT(*), SUM(lat IS NOT NULL) FROM tel")[0]) == (35, 35), "VoLTE layout: every record located via hex ECGI")
        ok(q("volte", "SELECT COUNT(*) FROM tel WHERE dir='fwd'")[0][0] == 5 and facts("volte", "telecom_target")[0]["records"] == 30,
           "VoLTE layout: forwarded (MF) legs kept but not counted")
        ok(not q("volte", "SELECT 1 FROM tel WHERE other = target"), "VoLTE layout: the other party is never the target itself")
        # report text: two tables, CellLocation longitude-first, damaged IMEI
        sc = _json.loads(q("report", "SELECT config FROM sources")[0][0])
        ok([t["name"] for t in sc["tables"]] == ["Voice Usage For: (703)555-0133", "Data Usage For: (703)555-0133"],
           "report layout: two tables in one text file, named by their labels")
        pr = facts("report", "telecom_target")[0]
        ok(pr["target"] == E["report_target"] and pr["calls"] == 8 and pr["data_sessions"] == 4,
           "report layout: target from 'Voice Usage For'; table label gives the record kind")
        loc = q("report", "SELECT lat, lon FROM tel WHERE lat IS NOT NULL LIMIT 1")[0]
        ok(38 < loc[0] < 39 and -78 < loc[1] < -77, "report layout: CellLocation read longitude-first")
        rq = facts("report", "telecom_quality")[0]
        ok(rq["imei_sci"] == 1, "report layout: IMEI in scientific notation flagged and not used")
        # HDA: preamble target, date + separate time column
        ok(facts("hda", "telecom_target")[0]["target"] == E["hda_target"], "HDA layout: target from 'o Target MSISDN :'")
        ok(len({r[0] for r in q("hda", "SELECT ts_utc FROM tel")}) == 20, "HDA layout: date and time columns combined (20 distinct times)")
        # tower dumps across carriers and scenes
        ok(len(facts("dumps", "telecom_dump_scene")) == 2, "tower dumps grouped into 2 scenes across carriers")
        ok([f["phone"] for f in facts("dumps", "telecom_dump_multi")] == [E["both_scenes"]],
           "tower dumps: exactly the phone planted at both scenes")
        tw = facts("dumps", "telecom_dump_imei")
        ok(len(tw) == 1 and set(tw[0]["phones"]) == E["twin_numbers"], "tower dumps: one handset under two numbers at both scenes")
        ok(not facts("dumps", "telecom_target"), "tower-dump phones are not reported as targets")
    finally:
        for k, v_ in old_env.items():
            if v_ is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v_
        shutil.rmtree(tmp, ignore_errors=True)


def telecom_tests():
    import hashlib
    import xml.etree.ElementTree as ET
    from spoor.figures import figure_rows
    from spoor.figures.svg import check_svg
    sys.path.insert(0, str(ROOT / "tests"))
    import make_telecom_demo
    tmp = Path(tempfile.mkdtemp(prefix="spoor-tel-"))
    old_env = {k: os.environ.get(k) for k in ("SPOOR_CASES", "SPOOR_SETTINGS")}
    try:
        make_telecom_demo.main(str(tmp / "returns"))
        same = all((tmp / "returns" / p.relative_to(ROOT / "demo" / "telecom")).read_bytes() == p.read_bytes()
                   for p in (ROOT / "demo" / "telecom").rglob("*") if p.is_file() and p.suffix != ".xlsx")
        ok(same, "telecom demo generator reproduces the bundled demo files")

        def outputs(c):
            out = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((c.report_dir / "figures").glob("*.svg"))}
            for n in ("telecom.kml", "colocation.csv", "common_contacts.csv", "target_overlap.csv", "telecom_records.csv"):
                out[n] = hashlib.sha256((c.exports_dir / n).read_bytes()).hexdigest()
            return out

        a, con = _figure_case(tmp / "a", "Telecom", tmp / "returns")
        ha = outputs(a)
        pl = make_telecom_demo.PLANTED
        rows = con.execute("SELECT kind, facts FROM findings WHERE module='telecom'").fetchall()
        facts = [(k, json.loads(f)["values"]) for k, f in rows]
        com = [x for k, x in facts if k == "telecom_common" and x["other"] == pl["common_contact_3"][0]]
        ok(com and set(com[0]["targets"]) == pl["common_contact_3"][1], "telecom: the 3-target common contact found with the right targets")
        com2 = [x for k, x in facts if k == "telecom_common" and x["other"] == pl["common_contact_2"][0]]
        ok(com2 and set(com2[0]["targets"]) == pl["common_contact_2"][1], "telecom: the 2-target common contact found")
        dirs = {tuple(sorted((x["target_a"], x["target_b"]))) for k, x in facts if k == "telecom_direct"}
        ok(dirs == {tuple(sorted(d)) for d in pl["direct"]}, f"telecom: exactly the planted direct contacts ({dirs})")
        sh = [x for k, x in facts if k == "telecom_shared_imei"]
        ok(len(sh) == 1 and sh[0]["imei"] == pl["shared_imei"][0][:14] and set(sh[0]["targets"]) == pl["shared_imei"][1],
           "telecom: shared IMEI (compared on its first 14 digits)")
        ch = [x for k, x in facts if k == "telecom_imei_change" and x["target"] == pl["imei_change"][0]]
        ok(ch and ch[0]["imeis"] == [pl["imei_change"][1][:14], pl["imei_change"][2][:14]], "telecom: handset change in time order")
        co = {tuple(sorted((x["target_a"], x["target_b"]))) for k, x in facts if k == "telecom_colocation"}
        ok(co == {tuple(sorted(c)) for c in pl["colocation"]}, f"telecom: exactly the planted co-locations ({co})")
        cross = [x for k, x in facts if k == "telecom_colocation" and "+17035550101" in (x["target_a"], x["target_b"])]
        ok(cross and 0 < cross[0]["closest_distance_m"] <= 100, "telecom: cross-carrier co-location by coordinates (sites ~26 m apart)")
        mx = [x for k, x in facts if k == "telecom_overlap"]
        ok(mx and mx[0]["most_shared"] == pl["common_contact_3"][0], "telecom: overlap table across all targets")
        q = con.execute("SELECT COUNT(*) FROM findings WHERE module IN ('links','counterparties','idents') AND "
                        "kind IN ('shared_identifier','counterparties','account_contacts')").fetchone()[0]
        ok(q == 0, "telecom: no duplicate shared-identifier / counterparty findings for call records")
        root = ET.parse(a.exports_dir / "telecom.kml").getroot()
        ns = "{http://www.opengis.net/kml/2.2}"
        folders = [f.find(ns + "name").text for f in root.iter(ns + "Folder")]
        ok(folders[0].startswith("Cell sites used") and folders[-1] == "Co-location occasions" and len(folders) == 6,
           f"KML: cell sites, one folder per target, co-location ({len(folders)} folders)")
        stamps = [w.text for w in root.iter(ns + "when")]
        ok(stamps and all(re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", t) for t in stamps), "KML: every record time-stamped in UTC")
        txt = (a.exports_dir / "telecom.kml").read_text(encoding="utf-8")
        ok(txt.count("http") == 1 and "href" not in txt, "KML: no external references (icons, links)")
        ok(re.search(r"Record: S\d+:L\d+", txt) and re.search(r"Site location: tower list in the same folder \(by cell label\) S\d+:L\d+", txt),
           "KML: each point cites its call record and the tower-list row of its location")
        figs = {f["slug"]: f for f in figure_rows(con)}
        f3 = figs["contacts"]
        ok(f3["status"] == "ok" and not check_svg((a.report_dir / "figures" / f3["file"]).read_text(encoding="utf-8")),
           "target-contact chart drawn, layout checks pass")
        drawn = {(t, k, n) for t, k, n in f3["meta"]["edges"] if "|" not in k}
        got = {(r[0], r[1], r[2]) for r in con.execute(f3["data_sql"][0][1])}
        ok(drawn and drawn <= got, "target-contact chart: the data query returns the lines drawn")
        marks = {r["fid"] for r in figs["timeline"]["refs"]}
        cofid = {r[0] for r in con.execute("SELECT fid FROM findings WHERE kind='telecom_colocation'")}
        ok(cofid <= marks, "co-location marked on the activity timeline")
        rv = (a.report_dir / "REVIEW.md").read_text(encoding="utf-8")
        ok("read as telecom records - check the columns" in rv, "REVIEW.md asks to confirm the telecom column mapping")
        mt = (a.report_dir / "METHODS.md").read_text(encoding="utf-8")
        ok("### Telecom returns" in mt and "not that the users were together" in mt, "METHODS.md describes telecom reading and its limits")
        cc = json.loads(con.execute("SELECT value FROM meta WHERE key='citation_check'").fetchone()[0])
        ok(cc["fail"] == 0 and cc["total"] > 0, f"telecom: every cited record re-read and matched ({cc['pass']})")
        # determinism and resume
        b, _ = _figure_case(tmp / "b", "Telecom", tmp / "returns", interrupt=_cancel_once("spoor.telecom", "build"))
        ok(outputs(b) == ha, "telecom: a run interrupted in the telecom stage, then resumed, gives identical figures, KML and exports")
        # a CDR with no target named anywhere: the target is inferred and flagged
        (tmp / "inf").mkdir()
        lines = ["Date (UTC),Calling Number,Called Number,Duration"]
        for i in range(30):
            o, t = ("2025550177", f"30155501{i % 10:02d}") if i % 2 else (f"30155501{i % 10:02d}", "2025550177")
            lines.append(f"2024-05-{1 + i % 20:02d} 1{i % 10}:00:00,{o},{t},{30 + i}")
        (tmp / "inf" / "carrier_cdr.csv").write_text("\n".join(lines) + "\n", encoding="utf-8")
        d, cond = _figure_case(tmp / "d", "Inferred", tmp / "inf")
        tq = [json.loads(f)["values"] for (f,) in cond.execute("SELECT facts FROM findings WHERE kind='telecom_quality'")]
        inf = (tq[0]["inferred_targets"] if tq else {})
        ok(inf and list(inf.values())[0]["target"] == "+12025550177", f"target inferred from a CDR that names none ({inf})")
        pr = cond.execute("SELECT priority FROM findings WHERE kind='telecom_quality'").fetchone()[0]
        ok(pr == 1 and "inferred from the data" in (d.report_dir / "REVIEW.md").read_text(encoding="utf-8"),
           "the inferred target is a priority-1 assumption in REVIEW.md")
        dirs = dict(cond.execute("SELECT dir, COUNT(*) FROM tel GROUP BY dir").fetchall())
        ok(dirs.get("out") == 15 and dirs.get("in") == 15, f"directions from the inferred target's side ({dirs})")
    finally:
        for k, v_ in old_env.items():
            if v_ is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v_
        shutil.rmtree(tmp, ignore_errors=True)


def cellref_tests():
    """Reference cell-site library (fictional lists): indexing, carrier choice, ECI collisions between carriers."""
    from spoor import cellref
    tmp = Path(tempfile.mkdtemp(prefix="spoor-cellref-"))
    old = {k: os.environ.get(k) for k in ("SPOOR_CASES", "SPOOR_SETTINGS", "SPOOR_CELLSITES")}
    try:
        lib = tmp / "cellsites"
        (lib / "Verizon_Test").mkdir(parents=True)
        (lib / "TMOB_Test").mkdir(parents=True)
        # ECI 1000001 is in both carriers' lists at different places; 2000002 only Verizon; 3000003 both, same place
        (lib / "Verizon_Test" / "Region_CALEA.V0.csv").write_text(
            "SITE NUMBER,LATITUDE,LONGITUDE,SECTOR,AZIMUTH (DEG),ANTENNA H-BW (DEG),ENODEB ID,ECGI\n"
            f"0101,40.100000,-75.100000,1,30,65,{1000001 // 256},311480-{1000001:07X}\n"
            f"0102,40.200000,-75.200000,2,150,65,{2000002 // 256},311480-{2000002:07X}\n"
            f"0103,40.300000,-75.300000,3,270,65,{3000003 // 256},311480-{3000003:07X}\n"
            "0104,40.400000,-75.400000,1,90,65,,\n", encoding="utf-8")
        (lib / "TMOB_Test" / "TEST-2025-01.csv").write_text(
            "Market_Name,Cell_ID,NodeB_ID,CGI,Azimuth,Site_Latitude,Site_Longitude,Horizontal_BW,List_Date\n"
            f"TEST,{1000001 % 256},{1000001 // 256},1000001,NULL,41.500000,-76.500000,NULL,1/1/2025 12:00:00 AM\n"
            f"TEST,{3000003 % 256},{3000003 // 256},3000003,270,40.300100,-75.300100,60,1/1/2025 12:00:00 AM\n",
            encoding="utf-8")
        (lib / "Verizon_Test.zip").write_bytes(b"PK\x05\x06" + b"\x00" * 18)     # extracted copy beside it: skipped
        logs = []
        r = cellref.index(lib, log=logs.append)
        ok(r["carriers"].get("Verizon", {}).get("cells") == 3 and r["carriers"].get("T-Mobile", {}).get("cells") == 2,
           f"library index: 3 Verizon + 2 T-Mobile LTE cells (non-LTE row skipped) ({r['carriers']})")
        ok(any("already extracted" in x for x in logs), "library index: a ZIP with its extracted folder beside it is skipped")
        r2 = cellref.index(lib, log=lambda *a: None)
        ok(r2["new"] == 0, "library index: unchanged lists are not re-read")
        L = cellref.Library(lib)
        ok(sorted(c["carrier"] for c in L.by_eci(1000001)) == ["T-Mobile", "Verizon"], "library lookup by ECI returns every carrier")
        L.close()
        ok(cellref.carrier_hint("D:/x/CellSites-CDR_Test_15555550100.csv")[0] == "Verizon"
           and cellref.carrier_hint("C:/r/CDR_Mediations_15555550100.xlsx")[0] == "T-Mobile"
           and cellref.carrier_hint("C:/r/ReportAU_1.txt")[0] == "AT&T"
           and cellref.carrier_hint("C:/r/calls.csv")[0] == "", "carrier hints from return file names")

        ret = tmp / "returns"
        ret.mkdir()
        hdr = "Calling Number,Called Number,Start Time (UTC),Duration (sec),ECI\n"
        rows = "".join(f"5555550{100 + i},5555550{150 + i},2025-03-0{1 + i} 1{i}:00:00,60,{e}\n"
                       for i, e in enumerate((1000001, 2000002, 3000003, 4000004)))
        (ret / "CellSites-CDR_TEST_5555550100.csv").write_text(hdr + rows, encoding="utf-8")
        (ret / "calls_export_5555550200.csv").write_text(hdr + rows.replace("5555550", "5555551"), encoding="utf-8")
        os.environ["SPOOR_CELLSITES"] = str(lib)
        c, con = _figure_case(tmp / "c1", "Library", ret, params={"figures": False})

        def loc(name, eci):
            return con.execute("SELECT t.lat, t.lon, t.loc_basis, c.loc_cite FROM tel t JOIN sources s ON s.id=t.source_id "
                               "JOIN calls c ON c.id=t.event_id WHERE s.display LIKE ? AND t.eci=?", (f"%{name}%", eci)).fetchone()
        v = loc("CellSites-CDR", 1000001)
        ok(v and abs(v[0] - 40.1) < 1e-6 and "Verizon" in v[2] and "cellsites/Verizon_Test/Region_CALEA.V0.csv" in (v[3] or ""),
           f"Verizon-named return: colliding ECI placed from the Verizon list, citing file and row ({v})")
        g = loc("calls_export", 1000001)
        ok(g and g[0] is None, "return with no carrier: ECI named by two carriers at different places is left unlocated")
        g2, g3 = loc("calls_export", 2000002), loc("calls_export", 3000003)
        ok(g2 and g2[0] is not None and g3 and g3[0] is not None,
           "return with no carrier: ECI in one list, or in lists that agree, is placed")
        q = json.loads(con.execute("SELECT facts FROM findings WHERE kind='telecom_quality'").fetchone()[0])["values"]
        reasons = q["unlocated_reasons"]
        ok(any("several carriers" in k for k in reasons) and q["library"]["matched"] == 5,
           f"quality finding counts library matches and the carrier collision ({q['library']['matched']}, {reasons})")
        rv = (c.report_dir / "REVIEW.md").read_text("utf-8")
        ok("Reference cell-site list used" in rv and "Verizon_Test/Region_CALEA.V0.csv" in rv, "REVIEW lists the library files used")
        mt = (c.report_dir / "METHODS.md").read_text("utf-8")
        ok("Reference cell-site library" in mt, "METHODS describes the library")

        c2, con2 = _figure_case(tmp / "c2", "Library forced", ret, params={"figures": False},
                                case_params={"tel_carrier": "T-Mobile"})
        r = con2.execute("SELECT t.lat FROM tel t JOIN sources s ON s.id=t.source_id WHERE s.display LIKE '%calls_export%' "
                         "AND t.eci=1000001").fetchone()
        ok(r and abs(r[0] - 41.5) < 1e-6, "case setting tel_carrier picks that carrier's list")

        os.environ["SPOOR_CELLSITES"] = str(tmp / "none")
        c3, con3 = _figure_case(tmp / "c3", "No library", ret, params={"figures": False})
        ok(not con3.execute("SELECT COUNT(*) FROM tel WHERE lat IS NOT NULL").fetchone()[0],
           "without a library nothing is placed (bring-your-own lists only)")
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        shutil.rmtree(tmp, ignore_errors=True)


def report_tests():
    """Returns lifecycle, cross-return page, negative results, BLUF-first report, references, telecom map files."""
    from spoor import db as dbm
    from spoor import returns as rets
    from spoor.jobs import start_job
    from spoor.selftest import demo_returns_dir
    root = Path(tempfile.mkdtemp(prefix="spoor-report-"))
    c, con = _figure_case(root, "Report-demo", demo_returns_dir())
    ok(not [r[0] for r in con.execute("SELECT key FROM meta WHERE key LIKE 'analysis_error%'")], "no analysis module failed")
    ok(rets.multi(con) and len(rets.active_returns(con)) >= 6, "demo folder grouped into returns (R01...)")
    rp = c.report_dir
    for fn in ("REPORT.md", "REPORT-FULL.md", "CROSSREF.md"):
        ok((rp / fn).exists(), f"{fn} written")
    txt = (rp / "REPORT.md").read_text(encoding="utf-8")
    pos = [txt.find(h) for h in ("## BLUF", "## Figures", "## What the records show", "## References", "## Appendix A")]
    ok(all(x >= 0 for x in pos) and pos == sorted(pos), "REPORT.md order: BLUF, figures, narrative, references, appendix A")
    a = txt.find("## Appendix A")
    ok("No IP address was the source of failed logins" not in txt[:a] and "No IP address was the source of failed logins" in txt[a:],
       "negative results appear only in Appendix A")
    cited = set(re.findall(r"\(#ref-(\d+)\)", txt))
    anchors = set(re.findall(r'<a id="ref-(\d+)"></a>', txt))
    ok(cited and cited <= anchors, f"every reference number cited has a bibliography entry ({len(anchors)} entries)")
    ok(re.search(r"\*\*\[1\]\*\* .*S\d+ \(R\d+ ", txt) is not None, "bibliography names source, return and file")
    xr = (rp / "CROSSREF.md").read_text(encoding="utf-8")
    ok("+17035550142" in xr and "R01" in xr, "CROSSREF.md lists the shared phone number with the returns it is in")
    ok("**Map:**" not in txt and not (rp / "exports" / "telecom.geojson").exists(), "no map line or GeoJSON when there are no telecom records")
    # leave a return out, run again, put it back
    n_all = con.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    rets.set_state(con, c, "R05", "excluded", "test")
    start_job(c, con, "run", {"llm": False}, wait=True)
    con = c.db()
    txt2 = (rp / "REPORT.md").read_text(encoding="utf-8")
    ok("Left out by the analyst: R05" in txt2, "report names the return that was left out")
    ok("R05" not in (rp / "CROSSREF.md").read_text(encoding="utf-8").split("Left out by the analyst")[0].split("## Items present")[-1],
       "excluded return takes no part in the cross-return items")
    rets.set_state(con, c, "R05", "active")
    start_job(c, con, "run", {"llm": False}, wait=True)
    con = c.db()
    ok(con.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == n_all, "including the return again restores the same findings")
    # telecom: map files and map line
    tc, tcon = _figure_case(Path(tempfile.mkdtemp(prefix="spoor-tel-report-")), "Tel-report", ROOT / "demo" / "telecom")
    t = (tc.report_dir / "REPORT.md").read_text(encoding="utf-8")
    ok("**Map:**" in t and (tc.report_dir / "exports" / "telecom.geojson").exists() and (tc.report_dir / "exports" / "telecom.kml").exists(),
       "telecom case: report names the KML and GeoJSON, both written")
    from spoor.mapdata import map_data
    d = map_data(tcon, tc.params)
    ok(d["status"]["map"] and d["sites"] and d["targets"], "map data has cell sites and located records per target")
    ok(not [r[0] for r in tcon.execute("SELECT key FROM meta WHERE key LIKE 'analysis_error%'")], "telecom case: no analysis module failed")


def web_smoke():
    tmp = Path(tempfile.mkdtemp(prefix="spoor-web-"))
    os.environ["SPOOR_CASES"] = str(tmp / "cases")
    os.environ["SPOOR_SETTINGS"] = str(tmp / "settings.json")
    (tmp / "settings.json").write_text(json.dumps({"llm": {"enabled": False, "url": "http://127.0.0.1:9"}}))
    try:
        from spoor.case import create_case, register_path
        from spoor.jobs import start_job
        from spoor.selftest import demo_returns_dir
        from spoor.web import server
        c = create_case("Web test", "t")
        con = c.db()
        register_path(c, con, str(demo_returns_dir()))
        start_job(c, con, "run", {"llm": False}, wait=True)
        from http.server import ThreadingHTTPServer
        srv = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        server.PORT = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        port = server.PORT

        def req(method, path, body=None, headers=None, cookie=True):
            hc = http.client.HTTPConnection("127.0.0.1", port, timeout=60)
            hd = {"Host": f"127.0.0.1:{port}"}
            if cookie:
                hd["Cookie"] = f"spoor_t={server.TOKEN}"
            hd.update(headers or {})
            hc.request(method, path, body=json.dumps(body) if body is not None else None, headers=hd)
            r = hc.getresponse()
            data = r.read()
            return r.status, data
        ok(req("GET", "/api/state", cookie=False)[0] == 401, "no token: refused")
        ok(req("GET", f"/?t={server.TOKEN}", cookie=False)[0] == 302, "token link sets the session cookie")
        ok(req("GET", "/api/state", headers={"Host": "evil.example:80"})[0] == 403, "wrong Host header refused (DNS rebinding)")
        ok(req("POST", "/api/cases", {"name": "x"}, headers={"Origin": "http://evil.example"})[0] == 403, "cross-site POST refused")
        ok(req("GET", "/case/Web-test/file/../case.db")[0] == 404, "report file route cannot leave the report folder")
        slug = c.slug
        for path in ("/api/state", f"/api/case/{slug}", f"/api/case/{slug}/sources", f"/api/case/{slug}/findings",
                     f"/api/case/{slug}/finding/F001", f"/api/case/{slug}/lookup?kind=ip&q=159.89.214.31",
                     f"/api/case/{slug}/lookup?kind=text&q=Password", f"/api/case/{slug}/context?cite=S10:L5",
                     f"/api/case/{slug}/reports", f"/api/case/{slug}/report?file=REPORT.md", f"/api/case/{slug}/jobs",
                     f"/api/case/{slug}/source/S05", "/", "/app.js", "/style.css"):
            st, data = req("GET", path)
            ok(st == 200, f"GET {path} -> {st}")
        st, data = req("GET", f"/api/case/{slug}/lookup?kind=ip&q=159.89.214.31")
        ok(json.loads(data)["count"] >= 10, "lookup returns cited rows")
        st, data = req("POST", f"/api/case/{slug}/source/S05/preview", {})
        ok(st == 200 and json.loads(data)["rows"], "mapping preview works")
        srv.shutdown()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    os.environ["SPOOR_CELLSITES"] = tempfile.mkdtemp(prefix="spoor-no-cellsites-")   # results must not depend on a library
    for name, fn in (("time parsing", unit_time), ("identifiers", unit_identifiers), ("verifier", unit_verify),
                     ("markdown", unit_markdown), ("telecom units", unit_telecom)):
        print(f"\n[{name}]")
        fn()
    print("\n[figures]")
    figures_tests()
    print("\n[telecom]")
    telecom_isolation()
    telecom_tests()
    print("\n[carrier layouts]")
    carrier_layout_tests()
    print("\n[returns, cross-reference, report]")
    report_tests()
    print("\n[reference cell-site library]")
    cellref_tests()
    print("\n[self-test]")
    from spoor.selftest import selftest
    ok(selftest(), "built-in self-test")
    print("\n[dashboard]")
    web_smoke()
    print(f"\n{'ALL TESTS PASSED' if not FAILS else str(len(FAILS)) + ' FAILED: ' + '; '.join(FAILS)}")
    sys.exit(1 if FAILS else 0)


if __name__ == "__main__":
    main()
