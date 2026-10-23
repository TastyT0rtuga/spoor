"""Citation self-check: re-read every cited record from the original file and compare.

Independent of the ingest path wherever possible: text files are re-read by byte offset, HTML
by source line, PDF by page; workbooks and JSON are re-opened and the cited row/path is located
again. Each record's stored timestamp text, IP, account (when read from a column), other party, and for call records
the cell, IMEI and IMSI, must also appear literally in what was re-read. The check proves the record exists and says what
was stored; it does not prove the timezone, the day/month order, the column mapping or a finding's conclusion."""
from __future__ import annotations

import html as htmlmod
import json
import re
from pathlib import Path

from . import db as dbm
from .util import sha256_file, utc_now_str

_TAG = re.compile(r"<[^>]+>")
_WS = re.compile(r"\s+")


def _norm(s: str) -> str:
    return _WS.sub(" ", (s or "")).strip()


def _check_values(ev: dict, text: str) -> list[str]:
    problems = []
    t = _norm(text)
    for col in ("ip_raw", "ts_raw"):
        v = ev.get(col)
        if v and _norm(str(v)) not in t:
            # a time built from separate date and time (and zone) columns is stored joined by spaces:
            # each part must then appear literally
            parts = _norm(str(v)).split(" ")
            if col == "ts_raw" and len(parts) > 1 and all(p in t for p in parts):
                continue
            problems.append(f"{col} '{v}' not found in the re-read text")
    # who and what the record was credited to, not only when and from where (reviews #1 F-12, #2 Q8, #3 SR-14)
    digits_t = re.sub(r"\D", "", text)
    acct, basis = ev.get("account"), ev.get("account_basis") or ""
    if acct and "source default" not in basis:
        if "E.164" in basis:
            d = re.sub(r"\D", "", acct)
            if d and d not in digits_t and d[-10:] not in digits_t:
                problems.append(f"account '{acct}' (from a column) not found in the re-read text")
        elif _norm(str(acct)).lower() not in t.lower():
            problems.append(f"account '{acct}' (from a column) not found in the re-read text")
    cp = ev.get("counterparty")
    if cp:
        d = re.sub(r"\D", "", str(cp))
        if _norm(str(cp)).lower() not in t.lower() and not (len(d) >= 7 and d[-10:] in digits_t):
            problems.append(f"counterparty '{cp}' not found in the re-read text")
    try:
        tel = (json.loads(ev.get("extra") or "{}") or {}).get("_tel") or {}
    except (TypeError, ValueError):
        tel = {}
    for k in ("cell", "cell_last", "imei", "imsi", "eci", "other", "target"):
        v = tel.get(k)
        if v and _norm(str(v)).lower() not in t.lower():
            d = re.sub(r"\D", "", str(v))
            if not (len(d) >= 5 and d in digits_t):
                problems.append(f"telecom {k} '{v}' not found in the re-read text")
    return problems


class Checker:
    def __init__(self, case, con, prog=None):
        self.case = case
        self.con = con
        self.prog = prog
        self.results: list[tuple] = []

    def record(self, cite, source_id, event_id, status, detail=""):
        self.results.append((utc_now_str(), cite, source_id, event_id, status, detail[:500]))

    # ------------------------------------------------------------------
    def run(self, mode: str = "all") -> dict:
        con = self.con
        con.execute("DELETE FROM citation_checks")
        ids = [r[0] for r in con.execute("SELECT DISTINCT event_id FROM finding_evidence ORDER BY event_id")]
        if mode == "sample" and len(ids) > 3000:
            step = len(ids) / 3000
            ids = [ids[int(i * step)] for i in range(3000)]
        by_src: dict = {}
        for chunk in range(0, len(ids), 900):
            part = ids[chunk: chunk + 900]
            for e in dbm.rows(con, f"SELECT e.*, s.label FROM events e JOIN sources s ON s.id=e.source_id WHERE e.id IN "
                                   f"({','.join('?' * len(part))})", part):
                by_src.setdefault(e["source_id"], []).append(e)
        cites = dbm.rows(con, "SELECT * FROM finding_cites")
        total = len(ids) + len(cites)
        if self.prog:
            self.prog.set_total(max(1, total), "citations")
        done = 0
        for sid, evs in sorted(by_src.items()):
            src = dbm.rows(con, "SELECT * FROM sources WHERE id=?", (sid,))[0]
            cfg = json.loads(src["config"]) if src.get("config") else {}
            if self.prog:
                self.prog.message(f"Citation check: {src['label']} ({len(evs)} records)")
                self.prog.check_cancel()
            p = Path(src["path"])
            if not p.exists():
                for e in evs:
                    self.record(f"{e['label']}:{e['loc']}", sid, e["id"], "unverifiable", f"file not found: {p}")
            else:
                try:
                    self._check_source(src, cfg, p, evs)
                except Exception as ex:  # noqa: BLE001
                    for e in evs:
                        self.record(f"{e['label']}:{e['loc']}", sid, e["id"], "unverifiable", f"{type(ex).__name__}: {ex}")
            done += len(evs)
            if self.prog:
                self.prog.update(done)
        for c in cites:
            self._check_other(c)
        con.executemany("INSERT INTO citation_checks(run_at, cite, source_id, event_id, status, detail) VALUES (?,?,?,?,?,?)",
                        self.results)
        summary = {"run_at": utc_now_str(), "total": len(self.results),
                   "pass": sum(1 for r in self.results if r[4] == "pass"),
                   "fail": sum(1 for r in self.results if r[4] == "fail"),
                   "unverifiable": sum(1 for r in self.results if r[4] == "unverifiable"), "mode": mode}
        dbm.set_meta(con, "citation_check", summary)
        con.commit()
        return summary

    # ------------------------------------------------------------------
    def _compare(self, e, text: str, exact_raw: bool = True):
        cite = f"{e['label']}:{e['loc']}"
        stored = e["raw"] or ""
        extra = json.loads(e["extra"]) if e.get("extra") else {}
        if extra.get("_raw_truncated_from"):
            ok = _norm(text).startswith(_norm(stored)) if exact_raw else _norm(stored) in _norm(text)
        else:
            ok = (_norm(text) == _norm(stored)) if exact_raw else (_norm(stored) in _norm(text))
        probs = [] if ok else ["text at the cited place differs from the text stored at ingest"]
        probs += _check_values(e, text)
        self.record(cite, e["source_id"], e["id"], "pass" if not probs else "fail", "; ".join(probs))

    def _check_source(self, src, cfg, p: Path, evs: list[dict]):
        kind = cfg.get("kind")
        enc = cfg.get("encoding") or "utf-8"
        if kind in ("delimited", "text", "jsonl") or (kind == "json" and evs and evs[0]["loc"].startswith("L")):
            from .readers.delimited import read_lines_at
            items = []
            for e in evs:
                extra = json.loads(e["extra"]) if e.get("extra") else {}
                if extra.get("_lines"):
                    for loc, line, off, ln in extra["_lines"]:
                        items.append((line, off, ln))
                elif e["line"] is not None:
                    items.append((e["line"], e["byte_offset"], e["byte_len"]))
            got = read_lines_at(p, enc, sorted(set(items), key=lambda t: t[0]))
            for e in evs:
                extra = json.loads(e["extra"]) if e.get("extra") else {}
                if extra.get("_lines"):
                    text = "\n".join(got.get(l[1], "").rstrip("\r\n") for l in extra["_lines"])
                elif e["byte_len"] and e["byte_offset"] is not None:
                    text = got.get(e["line"], "")
                    if e["loc"].count("-") and e["loc"].startswith("L"):
                        pass  # multi-line record: read_lines_at returned the whole byte span
                else:
                    text = got.get(e["line"], "")
                self._compare(e, text.rstrip("\r\n"))
            return
        if kind in ("xlsx", "xls"):
            from .readers import excel
            want: dict = {}
            for e in evs:
                sheet, _, r = e["loc"].rpartition("!R")
                want.setdefault(sheet, {})[int(r)] = e
            tables = {t["name"]: t for t in cfg.get("tables", [])}
            if kind == "xlsx":
                wb = excel._open_xlsx(p)
                try:
                    for sheet, rows in want.items():
                        ncols = tables.get(sheet, {}).get("ncols")
                        ws = wb[sheet]
                        hi = max(rows)
                        for ridx, r in enumerate(ws.iter_rows(values_only=True, min_row=min(rows), max_row=hi), start=min(rows)):
                            if ridx in rows:
                                vals = list(r[:ncols]) + [None] * max(0, (ncols or 0) - len(r))
                                self._compare(rows[ridx], " | ".join(excel._cell_text(v) for v in vals))
                finally:
                    wb.close()
            else:
                import xlrd
                book = xlrd.open_workbook(p, on_demand=True)
                try:
                    for sheet, rows in want.items():
                        ncols = tables.get(sheet, {}).get("ncols")
                        sh = book.sheet_by_name(sheet)
                        for ridx, r in excel._xls_rows(sh, book):
                            if ridx in rows:
                                vals = list(r[:ncols]) + [None] * max(0, (ncols or 0) - len(r))
                                self._compare(rows[ridx], " | ".join(excel._cell_text(v) for v in vals))
                finally:
                    book.release_resources()
            return
        if kind == "json":
            from .readers.jsonr import _s, resolve
            with open(p, "r", encoding="utf-8" if enc in ("utf-8", "utf-8-sig") else enc, errors="replace") as f:
                doc = json.load(f)
            for e in evs:
                vals = list(resolve(doc, e["loc"]))
                if not vals:
                    self.record(f"{e['label']}:{e['loc']}", e["source_id"], e["id"], "fail", "JSON path not found")
                    continue
                v = vals[0][1]
                if isinstance(v, (dict, list)):
                    self._compare(e, json.dumps(v, ensure_ascii=False))
                else:
                    key = e["loc"].rsplit(".", 1)[-1]
                    self._compare(e, f"{key}: {_s(v)}")
            return
        if kind == "html":
            with open(p, "r", encoding="utf-8" if enc == "utf-8-sig" else enc, errors="replace", newline="") as f:
                lines = f.read().splitlines()
            for e in evs:
                extra = json.loads(e["extra"]) if e.get("extra") else {}
                parts = extra.get("_lines") or [[e["loc"], e["line"], None, None]]
                stored_parts = (e["raw"] or "").split("\n") if extra.get("_lines") else [e["raw"] or ""]
                probs = []
                for (loc, line, _o, _l), want_txt in zip(parts, stored_parts):
                    m = re.match(r"L(\d+)(?::C(\d+))?", loc)
                    ln = int(m.group(1))
                    col = int(m.group(2) or 1) - 1
                    window = "\n".join(lines[ln - 1: ln + 40])
                    window = window[col:] if col and ln - 1 < len(lines) else window
                    txt = _norm(htmlmod.unescape(_TAG.sub(" ", window)))
                    cells = [c for c in (want_txt.split(" | ") if " | " in want_txt else [want_txt]) if c.strip()]
                    for c in cells:
                        if _norm(c) not in txt:
                            probs.append(f"'{c[:60]}' not found at {loc}")
                            break
                full = _norm(htmlmod.unescape(_TAG.sub(" ", "\n".join(lines[max(0, (e["line"] or 1) - 1): (e["line"] or 1) + 60]))))
                probs += _check_values(e, full)
                self.record(f"{e['label']}:{e['loc']}", e["source_id"], e["id"], "pass" if not probs else "fail", "; ".join(probs))
            return
        if kind == "pdf":
            from .readers.pdfr import read_page_lines
            pages = set()
            for e in evs:
                for loc in e["loc"].split("+"):
                    m = re.match(r"p(\d+):L(\d+)", loc)
                    if m:
                        pages.add(int(m.group(1)))
            got = read_page_lines(p, pages)
            for e in evs:
                texts = []
                for loc in e["loc"].split("+"):
                    m = re.match(r"p(\d+):L(\d+)", loc)
                    pg, ln = int(m.group(1)), int(m.group(2))
                    pl = got.get(pg, [])
                    texts.append(pl[ln - 1] if 0 < ln <= len(pl) else "")
                self._compare(e, "\n".join(texts))
            return
        for e in evs:
            self.record(f"{e['label']}:{e['loc']}", e["source_id"], e["id"], "unverifiable", f"no checker for kind {kind}")

    def _check_other(self, c: dict):
        cite = c["cite"]
        expect = c.get("expect") or c.get("text") or ""
        try:
            if c.get("source_id"):
                src = dbm.rows(self.con, "SELECT * FROM sources WHERE id=?", (c["source_id"],))[0]
                cfg = json.loads(src["config"]) if src.get("config") else {}
                text = _locate_text(Path(src["path"]), cfg, c["loc"])
            else:
                path = None
                if "watchlist" in cite.lower() or c.get("loc", "").startswith("L"):
                    from .analyses.watchlist import load_watchlists
                    fname = cite.rsplit(":L", 1)[0]
                    for w in load_watchlists(self.case):
                        if w["file"] == fname:
                            path = Path(w["path"])
                            break
                if path is None:
                    self.record(cite, None, None, "unverifiable", "no file for this citation")
                    return
                ln = int(c["loc"][1:])
                text = path.read_text(encoding="utf-8-sig", errors="replace").splitlines()[ln - 1]
            ok = _norm(expect) in _norm(text)
            self.record(cite, c.get("source_id"), None, "pass" if ok else "fail",
                        "" if ok else f"expected text '{expect[:80]}' not found; line reads '{text[:120]}'")
        except Exception as ex:  # noqa: BLE001
            self.record(cite, c.get("source_id"), None, "unverifiable", f"{type(ex).__name__}: {ex}")


def _locate_text(path: Path, cfg: dict, loc: str) -> str:
    kind = cfg.get("kind")
    enc = cfg.get("encoding") or "utf-8"
    if "!R" in loc:
        from .readers import excel
        sheet, _, r = loc.rpartition("!R")
        r = int(r)
        if kind == "xlsx":
            wb = excel._open_xlsx(path)
            try:
                for row in wb[sheet].iter_rows(values_only=True, min_row=r, max_row=r):
                    return " | ".join(excel._cell_text(v) for v in row)
            finally:
                wb.close()
        import xlrd
        book = xlrd.open_workbook(path, on_demand=True)
        try:
            for ridx, row in excel._xls_rows(book.sheet_by_name(sheet), book):
                if ridx == r:
                    return " | ".join(excel._cell_text(v) for v in row)
        finally:
            book.release_resources()
        return ""
    m = re.match(r"p(\d+):L(\d+)", loc)
    if m:
        from .readers.pdfr import read_page_lines
        pl = read_page_lines(path, {int(m.group(1))}).get(int(m.group(1)), [])
        n = int(m.group(2))
        return pl[n - 1] if 0 < n <= len(pl) else ""
    if loc.startswith("$"):
        from .readers.jsonr import _s, resolve
        with open(path, "r", encoding="utf-8" if enc in ("utf-8", "utf-8-sig") else enc, errors="replace") as f:
            doc = json.load(f)
        vals = list(resolve(doc, loc))
        if not vals:
            return ""
        v = vals[0][1]
        return json.dumps(v, ensure_ascii=False) if isinstance(v, (dict, list)) else f"{loc.rsplit('.', 1)[-1]}: {_s(v)}"
    m = re.match(r"L(\d+)", loc)
    if m:
        from .readers.delimited import read_lines_at
        n = int(m.group(1))
        txt = read_lines_at(path, enc, [(n, None, None)]).get(n, "")
        if kind == "html":
            txt = htmlmod.unescape(_TAG.sub(" ", txt))
        return txt
    return ""


def recheck_hashes(case, con, prog=None) -> dict:
    srcs = dbm.rows(con, "SELECT id, label, path, size, sha256 FROM sources WHERE status IN ('ingested','container','duplicate') ORDER BY id")
    out = {"match": 0, "mismatch": 0, "missing": 0}
    total = sum(s["size"] or 0 for s in srcs) or 1
    done = 0
    if prog:
        prog.set_total(total, "bytes")
    for s in srcs:
        if prog:
            prog.message(f"Re-hashing {s['label']}")
            prog.check_cancel()
        try:
            def cb(n):
                nonlocal done
                done += n
                if prog:
                    prog.update(done)
            h = sha256_file(s["path"], cb)
        except OSError:
            out["missing"] += 1
            con.execute("UPDATE sources SET recheck_sha256='(missing)', rechecked_at=? WHERE id=?", (utc_now_str(), s["id"]))
            continue
        out["match" if h == s["sha256"] else "mismatch"] += 1
        con.execute("UPDATE sources SET recheck_sha256=?, rechecked_at=? WHERE id=?", (h, utc_now_str(), s["id"]))
    con.commit()
    meta = dbm.get_meta(con, "citation_check") or {}
    meta["hashes"] = out
    dbm.set_meta(con, "citation_check", meta)
    con.commit()
    return out
