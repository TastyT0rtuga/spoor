"""Which return does an identifier come from? Answers for IPs, accounts, identifiers (emails, phone numbers, crypto addresses,
MACs, IMEIs...), counterparties and telecom numbers, from the records themselves (never from a model).

In a case with a single return every record has the same origin and nothing is added to the text; with two or more, statements
and tables name the returns (R01 ...) and how many records each contributed."""
from __future__ import annotations

from . import db as dbm
from . import returns as rets

_J = "JOIN sources s ON s.id=e.source_id JOIN returns r ON r.id=s.return_id"


class Provenance:
    def __init__(self, con):
        self.con = con
        self.names = {r[0]: r[1] for r in con.execute("SELECT label, name FROM returns")}
        self.multi = rets.multi(con)

    # ---- raw lookups: [(return label, records, first_utc, last_utc)] ordered by return label
    def _q(self, sql: str, args=()) -> list[tuple]:
        return [tuple(r) for r in self.con.execute(sql, args)]

    def of_ip(self, ip: str):
        return self._q(f"SELECT r.label, COUNT(*), MIN(e.ts_utc), MAX(e.ts_utc) FROM events e {_J} WHERE e.ip=? GROUP BY r.label ORDER BY r.label", (ip,))

    def of_account(self, account: str):
        return self._q(f"SELECT r.label, COUNT(*), MIN(e.ts_utc), MAX(e.ts_utc) FROM events e {_J} WHERE e.account=? GROUP BY r.label ORDER BY r.label", (account,))

    def of_ident(self, kind: str, norm: str):
        return self._q(f"SELECT r.label, COUNT(*), MIN(e.ts_utc), MAX(e.ts_utc) FROM identifiers i JOIN events e ON e.id=i.event_id {_J} "
                       f"WHERE i.kind=? AND i.norm=? GROUP BY r.label ORDER BY r.label", (kind, norm))

    def of_where(self, where: str, args=()):
        """`where` is a condition on the events table with unqualified column names (as the analyses write them)."""
        return self._q(f"SELECT r.label, COUNT(*), MIN(e.ts_utc), MAX(e.ts_utc) FROM (SELECT source_id, ts_utc FROM events WHERE {where}) e {_J} "
                       f"GROUP BY r.label ORDER BY r.label", args)

    def of_sources(self, source_ids):
        ids = sorted({int(i) for i in source_ids if i is not None})
        if not ids:
            return []
        return self._q(f"SELECT r.label, SUM(s.rows), NULL, NULL FROM sources s JOIN returns r ON r.id=s.return_id WHERE s.id IN "
                       f"({','.join('?' * len(ids))}) GROUP BY r.label ORDER BY r.label", ids)

    # ---- text
    def name(self, label: str) -> str:
        return self.names.get(label, "")

    def tag(self, label: str) -> str:
        """'R03 App_Return'"""
        n = self.name(label)
        return f"{label} {n}" if n else label

    def labels(self, pairs) -> str:
        return ", ".join(p[0] for p in pairs)

    def counts(self, pairs, names: bool = True) -> str:
        """'R03 App_Return (12), R05 Exchange_Return (4)'"""
        return ", ".join(f"{self.tag(p[0]) if names else p[0]} ({p[1]:,})" for p in pairs)

    def tags(self, pairs) -> str:
        """'R03 App_Return, R05 Exchange_Return'"""
        return ", ".join(self.tag(p[0]) for p in pairs)

    def phrase(self, pairs) -> str:
        """'in 3 returns (R03 App_Return, R05 ..., R07 ...)', or '' when the case has one return."""
        if not self.multi or not pairs:
            return ""
        n = len(pairs)
        return f"{n} {'return' if n == 1 else 'returns'} ({', '.join(self.tag(p[0]) for p in pairs)})"
