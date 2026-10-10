"""Identifier inventory: every email, phone, crypto address, MAC, IMEI and URL found, with validation."""
from __future__ import annotations

from ..findings import plural
from ..identifiers import KIND_LABELS
from ..util import fmt_int
from .base import Analysis, sq


class Identifiers(Analysis):
    module = "idents"
    category = "Identifiers"

    def run(self):
        kinds = self.q("SELECT kind, COUNT(*) AS distinct_values, SUM(events) AS occurrences, SUM(validity='checksum') AS verified "
                       "FROM ident_summary WHERE kind NOT IN ('ipv4','ipv6') GROUP BY kind ORDER BY occurrences DESC")
        if not kinds:
            self.add("no_identifiers", "No other identifiers found",
                     "No email address, phone number, cryptocurrency address, MAC, IMEI or URL was found in the records.",
                     {"values": {"identifiers": 0}}, priority=3)
            return
        parts = []
        tables = []
        for k in kinds:
            label = KIND_LABELS.get(k["kind"], k["kind"])
            parts.append(f"{label}: {fmt_int(k['distinct_values'])} distinct ({plural(k['occurrences'], 'record')})")
            top = self.q("SELECT norm, validity, events, sources, accounts, first_utc, last_utc FROM ident_summary WHERE kind=? "
                         "ORDER BY events DESC, norm LIMIT ?", (k["kind"], min(self.trows, 15)))
            tables.append({"title": f"{label} (top {len(top)})",
                           "columns": ["value", "validated", "records", "sources", "accounts", "first_utc", "last_utc"],
                           "rows": [[t["norm"], t["validity"], t["events"], t["sources"], t["accounts"], t["first_utc"], t["last_utc"]]
                                    for t in top], "total_rows": k["distinct_values"]})
        stmt = "Identifiers found in the records - " + "; ".join(parts) + ". Cryptocurrency addresses, IMEIs and checksummed formats were kept only when their checksum verified."
        self.add("identifier_inventory", "Identifier inventory", stmt,
                 {"values": {k["kind"]: k["distinct_values"] for k in kinds}, "tables": tables},
                 sql="SELECT kind, value, COUNT(*) FROM ids GROUP BY 1,2 ORDER BY 3 DESC", priority=3, sort_key="9",
                 export="exports/identifiers.csv")
        bad = self.q("SELECT norm, events, first_utc FROM ident_summary WHERE validity='bad_checksum' ORDER BY events DESC")
        if bad:
            ev = []
            for b in bad[:6]:
                eid = self.one("SELECT event_id FROM identifiers WHERE norm=? AND validity='bad_checksum' LIMIT 1", (b["norm"],))
                if eid:
                    ev.append((eid, "occurrence"))
            self.add("eth_bad_checksum", "Ethereum-format addresses failing their checksum",
                     f"{plural(len(bad), 'Ethereum-format address', 'Ethereum-format addresses')} use mixed case that fails the EIP-55 checksum - possible transcription errors: "
                     + ", ".join(b["norm"] for b in bad[:6]) + ".",
                     {"values": {"count": len(bad)}, "tables": [{"title": "Addresses", "columns": ["address (lower-case)", "records", "first_utc"],
                                                                "rows": [[b["norm"], b["events"], b["first_utc"]] for b in bad]}]},
                     sql="SELECT value, cite FROM ids WHERE validity='bad_checksum'", evidence=ev, priority=2, sort_key="5")
        # accounts named in the data that are themselves identifiers of other kinds (e.g. recovery emails)
        rec = self.q("SELECT e.account AS account, i.kind, i.norm, COUNT(*) AS n FROM identifiers i JOIN events e ON e.id=i.event_id "
                     "WHERE i.kind IN ('email','phone') AND e.account IS NOT NULL AND i.norm != lower(e.account) "
                     "GROUP BY e.account, i.kind, i.norm ORDER BY e.account, n DESC LIMIT 5000")
        by: dict = {}
        for r in rec:
            by.setdefault(r["account"], []).append(r)
        for acc, lst in sorted(by.items())[: self.max]:
            emails = [r["norm"] for r in lst if r["kind"] == "email"][:10]
            phones = [r["norm"] for r in lst if r["kind"] == "phone"][:10]
            if not emails and not phones:
                continue
            stmt = (f"Records of account {acc} also contain "
                    + "; ".join(x for x in [
                        (f"{plural(len(emails), 'other email address', 'other email addresses')}: {', '.join(emails)}" if emails else ""),
                        (f"{plural(len(phones), 'phone number')}: {', '.join(phones)}" if phones else "")] if x) + ".")
            ev = []
            for r in lst[:8]:
                eid = self.one("SELECT i.event_id FROM identifiers i JOIN events e ON e.id=i.event_id WHERE e.account=? AND i.norm=? "
                               "ORDER BY e.ts_epoch IS NULL, e.ts_epoch LIMIT 1", (acc, r["norm"]))
                if eid:
                    ev.append((eid, "occurrence"))
            self.add("account_contacts", f"{acc}: other emails and phones in its records", stmt,
                     {"values": {"account": acc, "emails": emails, "phones": phones},
                      "tables": [{"title": "Identifiers", "columns": ["kind", "value", "records"],
                                  "rows": [[r["kind"], r["norm"], r["n"]] for r in lst[: self.trows]]}]},
                     sql=f"SELECT kind, value, cite FROM ids WHERE account={sq(acc)} AND kind IN ('email','phone')",
                     evidence=ev, priority=2, sort_key=f"3{acc}")
