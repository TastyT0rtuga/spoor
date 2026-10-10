"""Deterministic lookups (no AI): everything about an IP/range, account, identifier or text string."""
from __future__ import annotations

import ipaddress
import re
from pathlib import Path

from . import db as dbm
from .identifiers import phone_from_cell
from .ipaddr import normalize_ip
from .util import md_code, md_escape, slug, utc_now_str

COLS = ["cite", "ts_utc", "ts_raw", "account", "category", "action", "status", "ip", "port", "ip_class", "network", "country",
        "user_agent", "counterparty", "amount", "currency", "raw"]
BASE = ("SELECT e.id, s.label || ':' || e.loc AS cite, e.ts_utc, e.ts_raw, e.account, e.category, e.action, e.status, e.ip, e.port, "
        "e.ip_class, x.as_org AS network, x.country, e.user_agent, e.counterparty, e.amount, e.currency, substr(e.raw, 1, 400) AS raw "
        "FROM events e JOIN sources s ON s.id = e.source_id LEFT JOIN ip_enrich x ON x.ip = e.ip")


def _q(v: str) -> str:
    return "'" + str(v).replace("'", "''") + "'"


def lookup(case, kind: str, q: str, t_from: str | None = None, t_to: str | None = None, limit: int = 500) -> dict:
    con = case.db(readonly=True)
    try:
        q = (q or "").strip()
        where, args, shown = [], [], []
        if kind == "ip":
            if "/" in q:
                net = ipaddress.ip_network(q, strict=False)
                ips = [r[0] for r in con.execute("SELECT ip FROM ip_summary") if ipaddress.ip_address(r[0]) in net]
                if not ips:
                    ips = ["__none__"]
                where.append(f"e.ip IN ({','.join('?' * len(ips))})")
                args += ips
                shown.append(f"e.ip IN ({', '.join(_q(i) for i in ips[:50])}{', ...' if len(ips) > 50 else ''})")
            else:
                n = normalize_ip(q)
                ip = n[0] if n else q
                where.append("e.ip = ?")
                args.append(ip)
                shown.append(f"e.ip = {_q(ip)}")
        elif kind == "account":
            if any(c in q for c in "%*"):
                pat = q.replace("*", "%").lower()
                where.append("lower(e.account) LIKE ?")
                args.append(pat)
                shown.append(f"lower(e.account) LIKE {_q(pat)}")
            else:
                where.append("lower(e.account) = ?")
                args.append(q.lower())
                shown.append(f"lower(e.account) = {_q(q.lower())}")
        elif kind == "identifier":
            cands = {q, q.lower()}
            ph = phone_from_cell(q)
            if ph:
                cands.add(ph)
            cands = sorted(cands)
            ph_s = ",".join("?" * len(cands))
            n = normalize_ip(q)
            ipc = [n[0]] if n else []
            ip_s = " OR e.ip = ?" if ipc else ""
            where.append(f"(e.id IN (SELECT event_id FROM identifiers WHERE norm IN ({ph_s})) OR lower(e.account) IN ({ph_s}){ip_s})")
            args += cands + [c.lower() for c in cands] + ipc
            lst = ", ".join(_q(c) for c in cands)
            shown.append(f"(e.id IN (SELECT event_id FROM identifiers WHERE norm IN ({lst})) OR lower(e.account) IN ({lst.lower()})"
                         + (f" OR e.ip = {_q(ipc[0])}" if ipc else "") + ")")
        elif kind == "text":
            fts = dbm.get_meta(con, "fts")
            if fts and q:
                phrase = '"' + q.replace('"', '""') + '"'
                where.append("e.id IN (SELECT rowid FROM events_fts WHERE events_fts MATCH ?)")
                args.append(phrase)
                shown.append(f"e.id IN (SELECT rowid FROM events_fts WHERE events_fts MATCH {_q(phrase)})")
            else:
                where.append("e.raw LIKE ?")
                args.append(f"%{q}%")
                shown.append(f"e.raw LIKE {_q('%' + q + '%')}")
        elif kind != "time":
            raise ValueError(f"unknown lookup kind {kind}")
        if t_from:
            where.append("e.ts_utc >= ?")
            args.append(t_from)
            shown.append(f"e.ts_utc >= {_q(t_from)}")
        if t_to:
            to = t_to if len(t_to) > 10 else t_to + " 23:59:59.999999"
            where.append("e.ts_utc <= ?")
            args.append(to)
            shown.append(f"e.ts_utc <= {_q(to)}")
        if not where:
            raise ValueError("enter something to look up")
        w = " AND ".join(where)
        total = dbm.one(con, f"SELECT COUNT(*) FROM events e WHERE {w}", tuple(args)) or 0
        rows = dbm.rows(con, f"{BASE} WHERE {w} ORDER BY e.ts_epoch IS NULL, e.ts_epoch, e.id LIMIT ?", tuple(args) + (limit,))
        agg = con.execute(f"SELECT MIN(e.ts_utc), MAX(e.ts_utc), COUNT(DISTINCT e.account), COUNT(DISTINCT e.source_id), "
                          f"COUNT(DISTINCT e.ip) FROM events e WHERE {w}", tuple(args)).fetchone()
        accts = [r[0] for r in con.execute(f"SELECT e.account, COUNT(*) n FROM events e WHERE {w} AND e.account IS NOT NULL "
                                           f"GROUP BY e.account ORDER BY n DESC LIMIT 8", tuple(args))]
        summary = (f"{total:,} record(s)" + (f" between {agg[0]} and {agg[1]} UTC" if agg[0] else "")
                   + f"; {agg[2]} account(s){': ' + ', '.join(accts) if accts else ''}; {agg[3]} source(s); {agg[4]} IP(s)."
                   + (f" Showing the first {limit:,}." if total > limit else ""))
        sql = f"{BASE} WHERE {' AND '.join(shown)} ORDER BY e.ts_epoch IS NULL, e.ts_epoch, e.id"
        return {"kind": kind, "query": q, "from": t_from, "to": t_to, "count": total, "summary": summary, "columns": COLS,
                "rows": rows, "sql": sql}
    finally:
        con.close()


def save_lookup_md(case, res: dict) -> Path:
    d = case.report_dir / "lookups"
    d.mkdir(parents=True, exist_ok=True)
    n = len(list(d.glob("*.md"))) + 1
    name = f"L{n:03d}_{res['kind']}_{slug(res['query'] or 'range', 40)}.md"
    L = [f"# Lookup: {res['kind']} {md_escape(res['query'])}", "", f"Run {utc_now_str()} (deterministic; no AI).", "",
         res["summary"], "", "Reproduce:", "", "```sql", res["sql"], "```", "",
         "| Citation | UTC | As written | Account | Type | Event | IP | Network | Verbatim record |",
         "|---|---|---|---|---|---|---|---|---|"]
    for r in res["rows"]:
        L.append(f"| {md_code(r['cite'])} | {md_escape(r['ts_utc'])} | {md_escape(r['ts_raw'])} | {md_escape(r['account'])} | "
                 f"{md_escape(r['category'])} | {md_escape(r['action'])} | {md_escape(r['ip'])} | {md_escape(r['network'])} | {md_code(r['raw'], 200)} |")
    p = d / name
    p.write_text("\n".join(L) + "\n", encoding="utf-8")
    return p


def source_context(case, label: str, loc: str, around: int = 4) -> dict:
    """The lines around a citation, read straight from the original file (for the 'view source' panel)."""
    con = case.db(readonly=True)
    try:
        s = dbm.rows(con, "SELECT * FROM sources WHERE label=?", (label,))
        if not s:
            raise ValueError(f"no source {label}")
        s = s[0]
        import json as _json
        cfg = _json.loads(s["config"]) if s.get("config") else {}
        ev = dbm.rows(con, "SELECT * FROM events WHERE source_id=? AND loc=? LIMIT 1", (s["id"], loc))
    finally:
        con.close()
    path = Path(s["path"])
    kind = cfg.get("kind")
    out = {"source": label, "file": s["display"], "path": s["path"], "loc": loc, "sha256": s["sha256"], "lines": [],
           "record": ev[0]["raw"] if ev else None}
    m = re.match(r"L(\d+)", loc)
    if m and kind in ("delimited", "text", "jsonl", "html", "json"):
        want = int(m.group(1))
        last = want
        m2 = re.match(r"L\d+-(\d+)", loc)
        if m2:
            last = int(m2.group(1))
        lo, hi = max(1, want - around), last + around
        enc = cfg.get("encoding") or "utf-8"
        with open(path, "r", encoding="utf-8" if enc == "utf-8-sig" else enc, errors="replace", newline="") as f:
            for i, line in enumerate(f, 1):
                if i > hi:
                    break
                if i >= lo:
                    out["lines"].append({"n": i, "text": line.rstrip("\r\n")[:2000], "hit": want <= i <= last})
        return out
    m = re.match(r"p(\d+):L(\d+)", loc)
    if m and kind == "pdf":
        from .readers.pdfr import read_page_lines
        pg, ln = int(m.group(1)), int(m.group(2))
        lines = read_page_lines(path, {pg}).get(pg, [])
        for i in range(max(1, ln - around), min(len(lines), ln + around) + 1):
            out["lines"].append({"n": f"p{pg}:L{i}", "text": lines[i - 1], "hit": i == ln})
        return out
    if "!R" in loc and kind in ("xlsx", "xls"):
        from .citecheck import _locate_text
        sheet, _, r = loc.rpartition("!R")
        r = int(r)
        for i in range(max(1, r - 2), r + 3):
            try:
                txt = _locate_text(path, cfg, f"{sheet}!R{i}")
            except Exception:  # noqa: BLE001
                txt = ""
            out["lines"].append({"n": f"{sheet}!R{i}", "text": txt, "hit": i == r})
        return out
    if loc.startswith("$"):
        from .citecheck import _locate_text
        out["lines"].append({"n": loc, "text": _locate_text(path, cfg, loc), "hit": True})
        return out
    out["lines"].append({"n": loc, "text": out["record"] or "", "hit": True})
    return out
