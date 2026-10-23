"""Shared helpers for analysis modules."""
from __future__ import annotations

import json
from typing import Optional

from .. import db as dbm
from ..config import HOSTING_KEYWORDS
from ..findings import FindingWriter, cite_of, evidence_sample, labels_for  # noqa: F401
from ..provenance import Provenance

ATTRIBUTABLE = ("public", "documentation")
ATTR_SQL = "('public','documentation')"
# events whose instant is known: not an implausible year, and not a day/month order that the data could not prove
TIMED = ("ts_epoch IS NOT NULL AND (ts_flag IS NULL OR (ts_flag NOT LIKE '%implausible_year%' "
         "AND ts_flag NOT LIKE '%date_order_assumed%'))")
# ... and a time of day (bursts, co-use, switches, anything measured in minutes)
TIMED_HOURS = TIMED + " AND (ts_flag IS NULL OR ts_flag NOT LIKE '%date_only%')"
EXACT = TIMED_HOURS


class Analysis:
    module = "base"
    category = ""

    def __init__(self, case, con, params: dict, log=None, prog=None):
        self.case = case
        self.con = con
        self.p = params
        self.log = log
        self.prog = prog
        self.fw = FindingWriter(con, self.module)
        self.max = int(params.get("max_findings_per_kind", 150))
        self.nsamp = int(params.get("evidence_samples", 12))
        self.trows = int(params.get("table_rows", 25))
        self.geo = dbm.get_meta(con, "geoip", {}) or {}
        has_doc = dbm.one(con, "SELECT 1 FROM ip_summary WHERE ip_class='documentation' LIMIT 1")
        self.pub = "public or documentation-range" if has_doc else "public"
        self.prov = Provenance(con)
        self.multi = self.prov.multi            # two or more returns: statements and tables name the return behind each source

    # ------------------------------------------------------------ sql helpers
    def q(self, sql: str, args=()) -> list[dict]:
        return dbm.rows(self.con, sql, args)

    def one(self, sql: str, args=()):
        return dbm.one(self.con, sql, args)

    def sample(self, where: str, args=(), n: Optional[int] = None):
        return evidence_sample(self.con, where, tuple(args), n or self.nsamp)

    def cite(self, eid: int) -> str:
        return cite_of(self.con, eid)

    def labels(self, ids) -> str:
        """Source labels (S03, S05). With several returns each is followed by its return: S03 (R02)."""
        return labels_for(self.con, ids, with_returns=self.multi)

    def add(self, kind, title, statement, facts, sql=None, evidence=(), priority=2, sort_key="", export=None, cites=()):
        return self.fw.add(self.category, kind, title, statement, facts, sql, evidence, priority, sort_key, export, cites)

    def run(self):  # pragma: no cover - implemented by subclasses
        raise NotImplementedError

    def msg(self, m: str):
        if self.prog:
            self.prog.message(f"{self.category}: {m}")

    # ------------------------------------------------------------ formatting
    def net_label(self, ip: str) -> str:
        r = self.con.execute("SELECT ip_class, asn, as_org, country FROM ip_summary WHERE ip=?", (ip,)).fetchone()
        if not r:
            return ""
        bits = [r["ip_class"]]
        if r["asn"]:
            bits.append(f"AS{r['asn']} {r['as_org'] or ''}".strip())
        if r["country"]:
            bits.append(r["country"])
        return "; ".join(b for b in bits if b)


def hosting_match(org: Optional[str]) -> Optional[str]:
    if not org:
        return None
    o = org.lower()
    for k in HOSTING_KEYWORDS:
        if k in o:
            return k
    return None


ACTIVITY_CATS = ("login", "login_failed", "logout", "account_change", "registration", "transaction", "communication")


def closest_couse(con, ip: str, accounts: Optional[set] = None):
    """Smallest time gap between records of two different accounts on one IP.

    Activity records (logins, changes, transactions, messages) are preferred over attribute
    records such as ISP lease lines; falls back to any timed record. Date-only records are ignored.
    Streams the rows, so IPs with millions of records cost no memory.
    Returns (seconds, event_id_a, account_a, ts_a, event_id_b, account_b, ts_b, activity) or None."""
    acts = ",".join(f"'{c}'" for c in ACTIVITY_CATS)
    base = ("SELECT id, account, ts_epoch, ts_utc FROM events WHERE ip=? AND account IS NOT NULL AND " + EXACT + " "
            "AND (ts_flag IS NULL OR ts_flag NOT LIKE '%date_only%')")
    for activity, extra in ((True, f" AND category IN ({acts})"), (False, "")):
        best = None
        prev = None
        for r in con.execute(base + extra + " ORDER BY ts_epoch, id", (ip,)):
            if accounts is not None and r[1] not in accounts:
                continue
            if prev is not None and prev[1] != r[1]:
                d = r[2] - prev[2]
                if best is None or d < best[0]:
                    best = (d, prev[0], prev[1], prev[3], r[0], r[1], r[3], activity)
            prev = r
        if best is not None:
            return best
    return None


def T(ts) -> str:
    """Timestamp for a statement: 'YYYY-MM-DD HH:MM:SS UTC', or 'YYYY-MM-DD (date only)'."""
    if not ts:
        return "(no time)"
    ts = str(ts)
    return f"{ts} (date only)" if len(ts) == 10 else f"{ts} UTC"


def human_delta(seconds: float) -> str:
    s = int(round(abs(seconds)))
    if s < 60:
        return f"{s} second{'s' if s != 1 else ''}"
    m = s // 60
    if m < 120:
        return f"{m} minute{'s' if m != 1 else ''}"
    h = m // 60
    if h < 72:
        return f"{h} hour{'s' if h != 1 else ''}"
    d = h // 24
    return f"{d} day{'s' if d != 1 else ''}"


def sq(v) -> str:
    """Quote a value for display inside a reproducible SQL string."""
    return "'" + str(v).replace("'", "''") + "'"


def jl(v) -> str:
    return json.dumps(v, ensure_ascii=False, default=str)
