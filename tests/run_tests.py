"""Developer tests: units (time parsing, identifiers, verifier, Markdown safety), the built-in
self-test, and a dashboard/API smoke test including the security checks.

usage:  python tests/run_tests.py      (from the Spoor folder; uses app/ and vendor/)"""
from __future__ import annotations

import http.client
import json
import os
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
    print("\n[self-test]")
    from spoor.selftest import selftest
    ok(selftest(), "built-in self-test")
    print("\n[dashboard]")
    web_smoke()
    print(f"\n{'ALL TESTS PASSED' if not FAILS else str(len(FAILS)) + ' FAILED: ' + '; '.join(FAILS)}")
    sys.exit(1 if FAILS else 0)


if __name__ == "__main__":
    main()
