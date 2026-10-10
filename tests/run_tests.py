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


def _figure_case(root: Path, name: str, folder: Path, tz: str = "America/New_York", params=None, interrupt=None):
    """Create a case in its own folder and run it (optionally interrupted once, then resumed)."""
    root.mkdir(parents=True, exist_ok=True)
    os.environ["SPOOR_CASES"] = str(root / "cases")
    os.environ["SPOOR_SETTINGS"] = str(root / "settings.json")
    (root / "settings.json").write_text(json.dumps({"llm": {"enabled": False, "url": "http://127.0.0.1:9"}}))
    from spoor.case import create_case, register_path
    from spoor.jobs import start_job
    c = create_case(name, "t", "", tz)
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
            for f in fr:
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
    for name, fn in (("time parsing", unit_time), ("identifiers", unit_identifiers), ("verifier", unit_verify),
                     ("markdown", unit_markdown)):
        print(f"\n[{name}]")
        fn()
    print("\n[figures]")
    figures_tests()
    print("\n[self-test]")
    from spoor.selftest import selftest
    ok(selftest(), "built-in self-test")
    print("\n[dashboard]")
    web_smoke()
    print(f"\n{'ALL TESTS PASSED' if not FAILS else str(len(FAILS)) + ' FAILED: ' + '; '.join(FAILS)}")
    sys.exit(1 if FAILS else 0)


if __name__ == "__main__":
    main()
