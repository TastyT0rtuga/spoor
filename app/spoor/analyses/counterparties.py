"""Counterparties and transactions: who each account dealt with most, and the largest amounts."""
from __future__ import annotations

from ..findings import plural
from ..util import fmt_num
from .base import T, Analysis, sq


class Counterparties(Analysis):
    module = "counterparties"
    category = "Counterparties & transactions"

    def run(self):
        # call/text records are covered by 'Calls, texts & cell sites'
        self.nt = "id NOT IN (SELECT event_id FROM tel)"
        n_cp = self.one(f"SELECT COUNT(*) FROM events WHERE counterparty IS NOT NULL AND {self.nt}") or 0
        n_amt = self.one("SELECT COUNT(*) FROM events WHERE amount IS NOT NULL") or 0
        if not n_cp and not n_amt:
            return
        if n_cp:
            accts = self.q("SELECT COALESCE(account, '(no account)') AS acc, COUNT(*) AS n, COUNT(DISTINCT counterparty) AS cps "
                           f"FROM events WHERE counterparty IS NOT NULL AND {self.nt} GROUP BY acc ORDER BY n DESC, acc")
            for a in accts[: self.max]:
                acc = a["acc"]
                cond = "account IS NULL" if acc == "(no account)" else "account=?"
                args = () if acc == "(no account)" else (acc,)
                top = self.q(f"SELECT counterparty, COUNT(*) AS n, CASE WHEN COUNT(DISTINCT currency) <= 1 THEN SUM(amount) END AS amt, "
                             f"MIN(ts_utc) AS f, MAX(ts_utc) AS l, "
                             f"GROUP_CONCAT(DISTINCT direction) AS dirs, GROUP_CONCAT(DISTINCT currency) AS cur FROM events "
                             f"WHERE counterparty IS NOT NULL AND {cond} AND {self.nt} GROUP BY counterparty ORDER BY n DESC, counterparty LIMIT ?",
                             args + (self.trows,))
                ex = "; ".join(f"{t['counterparty']} ({plural(t['n'], 'record')}" + (f", total {fmt_num(t['amt'])}{(' ' + t['cur']) if t['cur'] else ''}" if t["amt"] is not None else "") + ")"
                               for t in top[:5])
                stmt = (f"{'Account ' + acc if acc != '(no account)' else 'Records without an account'}: {plural(a['n'], 'record')} with "
                        f"{plural(a['cps'], 'distinct counterparty', 'distinct counterparties')}. Most frequent: {ex}.")
                ev = []
                for t in top[:5]:
                    ev += self.sample(f"counterparty=? AND {cond} AND {self.nt}", (t["counterparty"],) + args, 2)
                self.add("counterparties", f"{acc if acc != '(no account)' else 'Records without an account'}: counterparties", stmt,
                         {"values": {"account": acc, "records": a["n"], "counterparties": a["cps"]},
                          "tables": [{"title": "Counterparties", "columns": ["counterparty", "records", "amount_total", "first_utc", "last_utc", "direction", "currency"],
                                      "rows": [[t["counterparty"], t["n"], t["amt"], t["f"], t["l"], t["dirs"], t["cur"]] for t in top],
                                      "total_rows": a["cps"]}]},
                         sql=("SELECT counterparty, COUNT(*), SUM(amount) FROM ev WHERE id NOT IN (SELECT id FROM calls) AND " +
                              (f"account={sq(acc)}" if acc != "(no account)" else "account IS NULL") + " GROUP BY 1 ORDER BY 2 DESC"),
                         evidence=ev, priority=2, sort_key=f"2{10**9 - a['n']:010d}{acc}", export="exports/counterparties.csv")
        if n_amt:
            big = self.q("SELECT id, ts_utc, account, counterparty, amount, currency, action FROM events WHERE amount IS NOT NULL "
                         "ORDER BY ABS(amount) DESC, id LIMIT ?", (self.trows,))
            stmt = (f"{plural(n_amt, 'record')} carry an amount. Largest by absolute value: "
                    + "; ".join(f"{fmt_num(b['amount'])}{(' ' + b['currency']) if b['currency'] else ''} on {T(b['ts_utc'])}"
                                + (f" (account {b['account'] or 'none'}, counterparty {b['counterparty'] or 'none'})" if b["account"] or b["counterparty"] else "")
                                for b in big[:5]) + ".")
            self.add("largest_amounts", "Largest amounts", stmt,
                     {"values": {"records_with_amount": n_amt},
                      "tables": [{"title": "Largest amounts", "columns": ["cite", "ts_utc", "account", "counterparty", "amount", "currency", "action"],
                                  "rows": [[self.cite(b["id"]), b["ts_utc"], b["account"], b["counterparty"], b["amount"], b["currency"], b["action"]] for b in big]}]},
                     sql="SELECT cite, ts_utc, account, counterparty, amount, currency FROM ev WHERE amount IS NOT NULL ORDER BY ABS(amount) DESC",
                     evidence=[(b["id"], "amount") for b in big[: self.nsamp]], priority=2, sort_key="1")
