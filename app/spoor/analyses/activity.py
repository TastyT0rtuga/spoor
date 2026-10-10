"""Account activity over time: one finding per account (and one for records without an account)
summarising its activity records - the TIMELINE data - so each lane of the activity-timeline figure
cites a finding with evidence and a query that reproduces the lane.

Runs after the other modules so accounts named in priority-1 findings are covered first when the
per-kind limit applies."""
from __future__ import annotations

from ..findings import plural
from .base import TIMED, T, Analysis, sq

ACTIVITY = f"category != 'other' AND {TIMED}"
CAT_WORDS = [("login", "login", "logins"), ("login_failed", "failed login", "failed logins"), ("logout", "logout", "logouts"),
             ("account_change", "account change", "account changes"), ("registration", "registration", "registrations"),
             ("transaction", "transaction", "transactions"), ("communication", "message", "messages")]


def lane_where(account) -> tuple[str, tuple]:
    return ("account IS NULL", ()) if account is None else ("account = ?", (account,))


def lane_sql(account) -> str:
    who = "account IS NULL" if account is None else f"account = {sq(account)}"
    return (f"SELECT substr(ts_utc, 1, 10) AS day_utc, COUNT(*) AS records FROM events WHERE {who} AND {ACTIVITY} "
            "GROUP BY 1 ORDER BY 1")


class Activity(Analysis):
    module = "activity"
    category = "Timing & activity patterns"

    def run(self):
        self.msg("activity over time per account")
        rows = self.q(f"SELECT account, COUNT(*) AS n, COUNT(DISTINCT substr(ts_utc, 1, 10)) AS days FROM events "
                      f"WHERE {ACTIVITY} GROUP BY account")
        if not rows:
            return
        involved = {r[0] for r in self.con.execute(
            "SELECT DISTINCT e.account FROM finding_evidence fe JOIN findings f ON f.id = fe.finding_id "
            "JOIN events e ON e.id = fe.event_id WHERE f.priority = 1 AND f.category != 'Sources & data quality' "
            "AND e.account IS NOT NULL")}
        rows.sort(key=lambda r: (r["account"] is None, r["account"] not in involved, -r["n"], r["account"] or ""))
        for rank, r in enumerate(rows[: self.max]):
            acc = r["account"]
            where, args = lane_where(acc)
            w = f"{where} AND {ACTIVITY}"
            cats = {c["category"]: c["n"] for c in self.q(f"SELECT category, COUNT(*) AS n FROM events WHERE {w} GROUP BY category", args)}
            first = self.q(f"SELECT ts_utc FROM events WHERE {w} ORDER BY ts_epoch, id LIMIT 1", args)[0]["ts_utc"]
            last = self.q(f"SELECT ts_utc FROM events WHERE {w} ORDER BY ts_epoch DESC, id DESC LIMIT 1", args)[0]["ts_utc"]
            busy = self.q(f"SELECT substr(ts_utc, 1, 10) AS d, COUNT(*) AS n FROM events WHERE {w} GROUP BY d ORDER BY n DESC, d LIMIT 1", args)[0]
            parts = [plural(cats[k], one, many) for k, one, many in CAT_WORDS if cats.get(k)]
            parts += [plural(n, k.replace("_", " ") + " record") for k, n in sorted(cats.items()) if k not in {c[0] for c in CAT_WORDS}]
            who = f"Account {acc}" if acc is not None else "Records without an account"
            stmt = (f"{who}: {plural(r['n'], 'activity record')} ({', '.join(parts)}) on {plural(r['days'], 'UTC day')}, "
                    f"from {T(first)} to {T(last)}; the busiest UTC day was {busy['d']} with {plural(busy['n'], 'record')}.")
            vals = {"account": acc, "records": r["n"], "days": r["days"], "first_utc": first, "last_utc": last,
                    "busiest_day_utc": busy["d"], "busiest_day_records": busy["n"],
                    "by_type": {k: v for k, v in sorted(cats.items())}}
            title = f"{acc}: activity over time" if acc is not None else "Records without an account: activity over time"
            self.add("account_activity", title, stmt, {"values": vals}, sql=lane_sql(acc),
                     evidence=self.sample(w, args), priority=3, sort_key=f"9{rank:06d}")
