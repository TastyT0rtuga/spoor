"""What every figure builder receives (Ctx) and returns (Figure)."""
from __future__ import annotations

import datetime as dt
import json
from dataclasses import dataclass, field
from typing import Optional

from .. import db as dbm

UTC = dt.timezone.utc


@dataclass
class Ref:
    """One entry of a figure's sources table: a visible marker and the finding it stands for."""
    marker: str            # as printed on the figure: "1", "lane 2", "panel 1"
    fid: str
    shows: str             # what the marked element shows, in words
    cite: Optional[str] = None   # the record the marker is anchored on (opened by the dashboard)


@dataclass
class Figure:
    no: int
    slug: str
    title: str
    svg: Optional[str] = None
    status: str = "ok"                 # ok | skipped (nothing to draw) | failed
    reason: str = ""
    caption: str = ""
    refs: list = field(default_factory=list)
    notes: list = field(default_factory=list)      # caps and anything not shown, as printed on the figure
    data_sql: list = field(default_factory=list)   # [(what, sql)] reproducing what is drawn
    caps: dict = field(default_factory=dict)       # parameter -> value used
    meta: dict = field(default_factory=dict)       # what was drawn, for tests and METHODS.md

    @property
    def file(self) -> str:
        return f"FIG{self.no:02d}-{self.slug}.svg"


class Ctx:
    def __init__(self, case, con):
        self.case = case
        self.con = con
        self.p = case.params
        self.findings = dbm.rows(con, "SELECT * FROM findings WHERE fid IS NOT NULL ORDER BY fid")
        for f in self.findings:
            f["facts"] = json.loads(f["facts"]) if f["facts"] else {}
            f["values"] = f["facts"].get("values") or {}
        self.by_fid = {f["fid"]: f for f in self.findings}
        self.by_id = {f["id"]: f for f in self.findings}
        try:
            from zoneinfo import ZoneInfo
            self.tzname = case.display_tz or "UTC"
            self.tz = ZoneInfo(self.tzname)
        except Exception:  # noqa: BLE001
            self.tzname, self.tz = "UTC", UTC

    def of_kind(self, kind: str) -> list[dict]:
        return [f for f in self.findings if f["kind"] == kind]

    def evidence(self, finding_id: int) -> list[dict]:
        return dbm.rows(self.con, "SELECT fe.role, e.id, e.account, e.ts_utc, e.ts_epoch, e.ts_flag, e.category, s.label || ':' || e.loc AS cite "
                                  "FROM finding_evidence fe JOIN events e ON e.id = fe.event_id JOIN sources s ON s.id = e.source_id "
                                  "WHERE fe.finding_id = ? ORDER BY e.ts_epoch IS NULL, e.ts_epoch, e.id", (finding_id,))

    def cite(self, event_id: Optional[int]) -> Optional[str]:
        if not event_id:
            return None
        r = self.con.execute("SELECT s.label || ':' || e.loc FROM events e JOIN sources s ON s.id = e.source_id WHERE e.id = ?",
                             (event_id,)).fetchone()
        return r[0] if r else None


def fmt_n(n: int) -> str:
    return f"{n:,}"
