"""Findings: deterministic statements built from SQL results, each tied to the events behind it.

facts = {"values": {name: value}, "columns": [...], "rows": [[...]], "total_rows": n, "params": {...}}
Every number or identifier in a statement is also present in facts, which is what the LLM is
allowed to use and what the verifier checks its sentences against."""
from __future__ import annotations

import json
from typing import Iterable, Optional

from . import db as dbm
from .util import fmt_int, utc_now_str

CATEGORY_ORDER = [
    "Sources & data quality",
    "IP addresses",
    "Logins & account security",
    "Timing & activity patterns",
    "Links & cross-source",
    "Identifiers",
    "Counterparties & transactions",
    "Watchlist hits",
]
CATEGORY_SLUG = {
    "Sources & data quality": "quality", "IP addresses": "ip", "Logins & account security": "logins",
    "Timing & activity patterns": "temporal", "Links & cross-source": "links", "Identifiers": "identifiers",
    "Counterparties & transactions": "counterparties", "Watchlist hits": "watchlist",
}


def ts_label(ts: Optional[str]) -> str:
    return f"{ts} UTC" if ts else "(no time)"


def plural(n: int, word: str, plural_word: Optional[str] = None) -> str:
    return f"{fmt_int(n)} {word if n == 1 else (plural_word or word + 's')}"


class FindingWriter:
    def __init__(self, con, module: str):
        self.con = con
        self.module = module
        self.count = 0
        con.execute("DELETE FROM finding_evidence WHERE finding_id IN (SELECT id FROM findings WHERE module=?)", (module,))
        con.execute("DELETE FROM finding_cites WHERE finding_id IN (SELECT id FROM findings WHERE module=?)", (module,))
        con.execute("DELETE FROM findings WHERE module=?", (module,))

    def add(self, category: str, kind: str, title: str, statement: str, facts: dict, sql: Optional[str] = None,
            evidence: Iterable = (), priority: int = 2, sort_key: str = "", export: Optional[str] = None,
            cites: Iterable = ()) -> int:
        ev = list(dict.fromkeys((int(e[0]), e[1]) for e in evidence if e and e[0] is not None))
        cur = self.con.execute(
            "INSERT INTO findings(module, category, kind, title, statement, priority, sort_key, facts, sql, export,"
            " evidence_count, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (self.module, category, kind, title, statement, priority, sort_key,
             json.dumps(facts, default=str, ensure_ascii=False), sql, export, len(ev), utc_now_str()))
        fid = cur.lastrowid
        seen = set()
        rows = []
        for eid, role in ev:
            if eid in seen:
                continue
            seen.add(eid)
            rows.append((fid, eid, role))
        self.con.executemany("INSERT OR IGNORE INTO finding_evidence(finding_id, event_id, role) VALUES (?,?,?)", rows)
        for c in cites:
            self.con.execute("INSERT INTO finding_cites(finding_id, cite, source_id, loc, text, expect) VALUES (?,?,?,?,?,?)",
                             (fid, c["cite"], c.get("source_id"), c.get("loc"), c.get("text"), c.get("expect")))
        self.count += 1
        return fid


def number_findings(con) -> int:
    """Assign stable IDs F001.. in report order: category, priority, sort key."""
    order = {c: i for i, c in enumerate(CATEGORY_ORDER)}
    rows = dbm.rows(con, "SELECT id, category, priority, sort_key FROM findings")
    rows.sort(key=lambda r: (order.get(r["category"], 99), r["priority"] or 9, r["sort_key"] or "", r["id"]))
    con.execute("UPDATE findings SET fid=NULL")
    width = max(3, len(str(len(rows))))
    for i, r in enumerate(rows, 1):
        con.execute("UPDATE findings SET fid=? WHERE id=?", (f"F{i:0{width}d}", r["id"]))
    con.commit()
    return len(rows)


def evidence_sample(con, where: str, args: tuple = (), n: int = 12) -> list[tuple[int, str]]:
    """First, last and evenly spaced events (by time) for a condition on the events table."""
    total = dbm.one(con, f"SELECT COUNT(*) FROM events WHERE {where}", args) or 0
    if not total:
        return []
    order = "ORDER BY ts_epoch IS NULL, ts_epoch, id"
    out = []
    first = dbm.one(con, f"SELECT id FROM events WHERE {where} {order} LIMIT 1", args)
    last = dbm.one(con, f"SELECT id FROM events WHERE {where} ORDER BY ts_epoch IS NULL, ts_epoch DESC, id DESC LIMIT 1", args)
    out.append((first, "first"))
    if total <= n:
        for (eid,) in con.execute(f"SELECT id FROM events WHERE {where} {order}", args).fetchall():
            out.append((eid, "sample"))
    else:
        step = total / (n - 1)
        for k in range(1, n - 1):
            eid = dbm.one(con, f"SELECT id FROM events WHERE {where} {order} LIMIT 1 OFFSET ?", args + (int(k * step),))
            out.append((eid, "sample"))
    if last != first:
        out.append((last, "last"))
    seen, res = set(), []
    for eid, role in out:
        if eid not in seen:
            seen.add(eid)
            res.append((eid, role))
    return res


def cite_of(con, event_id: int) -> str:
    r = con.execute("SELECT s.label || ':' || e.loc FROM events e JOIN sources s ON s.id=e.source_id WHERE e.id=?",
                    (event_id,)).fetchone()
    return r[0] if r else "?"


def labels_for(con, source_ids: Iterable[int]) -> str:
    ids = sorted(set(int(i) for i in source_ids))
    if not ids:
        return ""
    m = {r[0]: r[1] for r in con.execute(f"SELECT id, label FROM sources WHERE id IN ({','.join('?' * len(ids))})", ids)}
    return ", ".join(m.get(i, str(i)) for i in ids)
