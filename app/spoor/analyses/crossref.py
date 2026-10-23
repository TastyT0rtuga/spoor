"""Cross-return overlap: anything that appears in the records of TWO OR MORE returns - an IP address, an account name, an
identifier (email, phone number, cryptocurrency address, MAC, IMEI ...) or a counterparty.

Only positive overlaps become findings, one per item, each citing records from every return it appears in. What does not
overlap is reported as a single count in the summary (and in the negative-results appendix), never item by item.
The telecom cross-reference (shared handsets, common contacts, co-location) is in 'Calls, texts & cell sites'; the
CROSSREF.md page lists those findings next to these."""
from __future__ import annotations

import csv
import re
import itertools

from ..findings import plural
from ..identifiers import KIND_LABELS
from .base import ATTR_SQL, T, Analysis, sq

# which kinds are listed first (stronger evidence of a common actor) - a listing order, not a judgement
KIND_ORDER = {"account": 0, "username": 6, "email": 1, "phone": 2, "btc": 3, "eth": 3, "ltc": 3, "trx": 3, "xmr": 3, "doge": 3, "imei": 4, "imsi": 4,
              "mac": 5, "ip": 6, "counterparty": 7, "url": 9}
# account / counterparty strings that are a provider's filler, not an identity - never matched across returns
PLACEHOLDERS = {"", "-", "--", "0", "unknown", "n/a", "na", "none", "null", "nil", "guest", "user", "admin", "administrator", "default",
                "system", "anonymous", "test", "redacted", "not available", "not provided", "undefined"}
_PH_SQL = "(" + ", ".join("'" + x.replace("'", "''") + "'" for x in sorted(PLACEHOLDERS)) + ")"


def _placeholder(v) -> bool:
    v = (v or "").strip().lower()
    return v in PLACEHOLDERS or bool(re.fullmatch(r"\d{1,6}", v)) or not re.search(r"[a-z0-9]", v)


J = "JOIN sources s ON s.id=e.source_id JOIN returns r ON r.id=s.return_id"
# reproduces the list of overlapping items from the read-only views (ev, ids carry the return label in `ret`)
ALL_SQL = ("SELECT 'ip' AS kind, ip AS value, COUNT(DISTINCT ret) AS returns, GROUP_CONCAT(DISTINCT ret) AS return_labels FROM ev "
           "WHERE ip IS NOT NULL AND ip_class IN ('public','documentation') GROUP BY ip HAVING COUNT(DISTINCT ret) >= 2 "
           "UNION ALL SELECT 'account', lower(account), COUNT(DISTINCT ret), GROUP_CONCAT(DISTINCT ret) FROM ev "
           "WHERE account IS NOT NULL AND lower(trim(account)) NOT IN " + _PH_SQL + " GROUP BY lower(account) HAVING COUNT(DISTINCT ret) >= 2 "
           "UNION ALL SELECT kind, value, COUNT(DISTINCT ret), GROUP_CONCAT(DISTINCT ret) FROM ids "
           "WHERE kind NOT IN ('ipv4','ipv6') GROUP BY kind, value HAVING COUNT(DISTINCT ret) >= 2 "
           "UNION ALL SELECT 'counterparty', lower(counterparty), COUNT(DISTINCT ret), GROUP_CONCAT(DISTINCT ret) FROM ev "
           "WHERE counterparty IS NOT NULL AND lower(trim(counterparty)) NOT IN " + _PH_SQL + " GROUP BY lower(counterparty) HAVING COUNT(DISTINCT ret) >= 2 ORDER BY 3 DESC, 1, 2")


class CrossRef(Analysis):
    module = "crossref"
    category = "Cross-return overlap"

    def run(self):
        self.rows = []       # every overlapping item (all of them go to the CSV)
        self.placeholders = set()
        if not self.multi:
            return
        self.msg("items present in more than one return")
        self.collect()
        self.write_csv()
        self.findings()

    # ------------------------------------------------------------ collecting
    def collect(self):
        # IPs (public and documentation ranges; private / CGNAT / link-local addresses repeat across providers by design)
        for (v,) in self.con.execute(f"SELECT e.ip FROM events e {J} WHERE e.ip IS NOT NULL AND e.ip_class IN {ATTR_SQL} "
                                     f"GROUP BY e.ip HAVING COUNT(DISTINCT s.return_id) >= 2"):
            self.rows.append(self.entity("ip", v, v, "e.ip=?", (v,), f"SELECT ret, cite, ts_utc, account, category, action FROM ev WHERE ip={sq(v)} ORDER BY ts_utc"))
        self.nonattr = self.one(f"SELECT COUNT(*) FROM (SELECT e.ip FROM events e {J} WHERE e.ip IS NOT NULL AND e.ip_class NOT IN {ATTR_SQL} "
                                f"GROUP BY e.ip HAVING COUNT(DISTINCT s.return_id) >= 2)") or 0
        # accounts (case-insensitive). Placeholders never match; an email address or phone number is an account identity,
        # a bare username is only the same string - reported as such (reviews #1 F-09, #2 G-F9, #3 SR-10)
        for (v,) in self.con.execute(f"SELECT lower(e.account) FROM events e {J} WHERE e.account IS NOT NULL "
                                     f"GROUP BY lower(e.account) HAVING COUNT(DISTINCT s.return_id) >= 2"):
            if _placeholder(v):
                self.placeholders.add(v)
                continue
            shown = self.one("SELECT account FROM events WHERE lower(account)=? ORDER BY ts_epoch IS NULL, ts_epoch, id LIMIT 1", (v,)) or v
            strong = bool(re.fullmatch(r"[^@\s]+@[^@\s]+\.[a-z]{2,}", v) or re.fullmatch(r"\+\d{10,15}", v))
            self.rows.append(self.entity("account" if strong else "username", v, shown, "lower(e.account)=?", (v,),
                                         f"SELECT ret, cite, ts_utc, account, category, action FROM ev WHERE lower(account)={sq(v)} ORDER BY ts_utc"))
        # identifiers other than IPs
        for kind, norm in self.con.execute("SELECT i.kind, i.norm FROM identifiers i JOIN sources s ON s.id=i.source_id "
                                           "WHERE i.kind NOT IN ('ipv4','ipv6') AND i.validity != 'bad_checksum' "
                                           "GROUP BY i.kind, i.norm HAVING COUNT(DISTINCT s.return_id) >= 2").fetchall():
            self.rows.append(self.entity(kind, norm, norm, "e.id IN (SELECT event_id FROM identifiers WHERE kind=? AND norm=?)", (kind, norm),
                                         f"SELECT ret, value, cite, ts_utc, account FROM ids WHERE kind={sq(kind)} AND value={sq(norm)} ORDER BY ts_utc"))
        # counterparties named in transactions / messages
        for (v,) in self.con.execute(f"SELECT lower(e.counterparty) FROM events e {J} WHERE e.counterparty IS NOT NULL "
                                     f"GROUP BY lower(e.counterparty) HAVING COUNT(DISTINCT s.return_id) >= 2"):
            if _placeholder(v):
                self.placeholders.add(v)
                continue
            shown = self.one("SELECT counterparty FROM events WHERE lower(counterparty)=? ORDER BY ts_epoch IS NULL, ts_epoch, id LIMIT 1", (v,)) or v
            self.rows.append(self.entity("counterparty", v, shown, "lower(e.counterparty)=?", (v,),
                                         f"SELECT ret, cite, ts_utc, account, category, counterparty, amount, currency FROM ev WHERE lower(counterparty)={sq(v)} ORDER BY ts_utc"))
        self.rows = [r for r in self.rows if r]
        self.rows.sort(key=lambda r: (-len(r["per"]), KIND_ORDER.get(r["kind"], 8), -r["records"], r["kind"], r["shown"].lower()))

    def entity(self, kind, key, shown, where, args, sql):
        per = self.q(f"SELECT r.label AS ret, r.name AS name, COUNT(*) AS n, MIN(e.ts_utc) AS f, MAX(e.ts_utc) AS l, "
                     f"COUNT(DISTINCT e.account) AS accounts FROM events e {J} WHERE {where} GROUP BY r.label ORDER BY r.label", args)
        if len(per) < 2:
            return None
        accs = [r[0] for r in self.con.execute(f"SELECT DISTINCT e.account FROM events e {J} WHERE {where} AND e.account IS NOT NULL "
                                               f"ORDER BY e.account LIMIT 12", args)]
        return {"kind": kind, "key": key, "shown": str(shown), "where": where, "args": args, "per": per, "sql": sql, "accounts": accs,
                "records": sum(p["n"] for p in per), "first": min((p["f"] for p in per if p["f"]), default=None),
                "last": max((p["l"] for p in per if p["l"]), default=None)}

    def label(self, kind: str) -> str:
        return ({"ip": "IP address", "account": "account", "username": "username string", "counterparty": "counterparty"}.get(kind)
                or KIND_LABELS.get(kind, kind))

    def n_kind(self, n: int, kind: str) -> str:
        w = self.label(kind)
        pl = {"ip": "IP addresses", "counterparty": "counterparties", "email": "email addresses", "mac": "MAC addresses"}.get(kind)
        if pl is None:
            pl = w + ("es" if w.endswith(("s", "x")) else "s")
        return f"{n:,} {w if n == 1 else pl}"

    # ------------------------------------------------------------ outputs
    def write_csv(self):
        out = self.case.exports_dir
        out.mkdir(parents=True, exist_ok=True)
        with open(out / "crossref.csv", "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["kind", "value", "returns", "return_labels", "records_by_return", "records", "first_utc", "last_utc", "accounts"])
            for r in self.rows:
                w.writerow([r["kind"], r["shown"], len(r["per"]), " ".join(p["ret"] for p in r["per"]),
                            " ".join(f"{p['ret']}:{p['n']}" for p in r["per"]), r["records"], r["first"], r["last"], "; ".join(r["accounts"])])

    def findings(self):
        cap = int(self.p.get("crossref_max_findings", 40))
        rets = self.q("SELECT r.label, r.name, COUNT(DISTINCT s.id) AS files, SUM(s.rows) AS records FROM returns r JOIN sources s ON s.return_id=r.id "
                      "WHERE r.state='active' AND s.status='ingested' AND s.rows > 0 GROUP BY r.id ORDER BY r.label")
        labels = [r["label"] for r in rets]
        # pairwise matrix (kinds counted separately); only pairs that share something are listed
        pairs = {}
        for r in self.rows:
            for a, b in itertools.combinations([p["ret"] for p in r["per"]], 2):
                d = pairs.setdefault((a, b), {})
                d[r["kind"]] = d.get(r["kind"], 0) + 1
        none_pairs = [f"{a}-{b}" for a, b in itertools.combinations(labels, 2) if (a, b) not in pairs]

        def grp(d, kinds):
            return sum(v for k, v in d.items() if k in kinds)

        idk = set(KIND_LABELS) - {"ipv4", "ipv6"}
        mrows = [[a, self.prov.name(a), b, self.prov.name(b), grp(d, {"ip"}), grp(d, {"account", "username"}), grp(d, idk), grp(d, {"counterparty"}), sum(d.values())]
                 for (a, b), d in sorted(pairs.items(), key=lambda kv: (-sum(kv[1].values()), kv[0]))]
        by_kind: dict = {}
        for r in self.rows:
            by_kind[r["kind"]] = by_kind.get(r["kind"], 0) + 1
        n_pairs = len(labels) * (len(labels) - 1) // 2
        vals = {"returns": labels, "return_count": len(labels), "items": len(self.rows), "by_kind": by_kind,
                "pairs_compared": n_pairs, "pairs_with_overlap": len(pairs), "pairs_without_overlap": none_pairs,
                "nonattributable_ips_in_several_returns": self.nonattr, "individual_findings": min(cap, len(self.rows)), "cap": cap}
        if not self.rows:
            self.add("crossref_none", "No item appears in more than one return",
                     f"No public IP address, account name, identifier (email, phone number, cryptocurrency address, MAC, IMEI) or counterparty "
                     f"appears in the records of more than one of the {len(labels)} returns ({', '.join(labels)}). "
                     + (f"{plural(self.nonattr, 'private, shared or reserved IP address', 'private, shared or reserved IP addresses')} appear in several returns "
                        f"and were not counted." if self.nonattr else ""),
                     {"values": vals}, sql=ALL_SQL, priority=3, sort_key="9")
            return
        ph = sorted(self.placeholders)
        vals["placeholders_not_matched"] = ph
        kinds_txt = ", ".join(self.n_kind(n, k) for k, n in sorted(by_kind.items(), key=lambda kv: (KIND_ORDER.get(kv[0], 8), kv[0])))
        stmt = (f"{plural(len(self.rows), 'item')} appear in the records of two or more of the {len(labels)} returns: {kinds_txt}. "
                f"{len(pairs)} of {n_pairs} {'pair' if n_pairs == 1 else 'pairs'} of returns share at least one item"
                + (f"; the strongest pair is {mrows[0][0]} and {mrows[0][2]} with {mrows[0][8]} shared items" if mrows else "") + ".")
        if self.nonattr:
            stmt += (f" {plural(self.nonattr, 'private, shared or reserved IP address', 'private, shared or reserved IP addresses')} "
                     f"{'appears' if self.nonattr == 1 else 'appear'} in several returns; such addresses say nothing about a common user and were not counted.")
        if ph:
            stmt += (f" Placeholder values that appear in several returns were not treated as matches: {', '.join(repr(x) for x in ph[:8])}"
                     f"{' and more' if len(ph) > 8 else ''}.")
        if by_kind.get("username"):
            stmt += (" A username matched across returns is only the same name string; different services can have different people "
                     "behind the same name.")
        self.add("crossref_summary", "Items present in more than one return", stmt,
                 {"values": vals, "tables": [{"title": "Pairs of returns that share items", "columns": ["return A", "name A", "return B", "name B", "IPs", "accounts", "identifiers", "counterparties", "total"],
                                              "rows": mrows[:60], "total_rows": len(mrows)}]},
                 sql=ALL_SQL, priority=1, sort_key="0", export="exports/crossref.csv")
        for r in self.rows[:cap]:
            per = r["per"]
            ev = []
            for p in per:
                where, args = r["where"], tuple(r["args"])
                ids = [x[0] for x in self.con.execute(
                    f"SELECT e.id FROM events e {J} WHERE {where} AND r.label=? ORDER BY e.ts_epoch IS NULL, e.ts_epoch, e.id", args + (p["ret"],))]
                if ids:
                    ev.append((ids[0], "first in " + p["ret"]))
                    if len(ids) > 1:
                        ev.append((ids[-1], "last in " + p["ret"]))
            what = self.label(r["kind"])
            tags = ", ".join(f"{self.prov.tag(p['ret'])} ({p['n']:,})" for p in per)
            stmt = (f"{what[0].upper() + what[1:]} {r['shown']} appears in {len(per)} returns: {tags}" +
                    (f"; {T(r['first'])} to {T(r['last'])}" if r["first"] else "") + "."
                    + (f" Accounts in those records: {', '.join(r['accounts'][:8])}{' and more' if len(r['accounts']) > 8 else ''}." if r["accounts"] and r["kind"] != "account" else ""))
            if r["kind"] == "username":
                variants = [x[0] for x in self.con.execute(
                    f"SELECT DISTINCT e.account FROM events e {J} WHERE lower(e.account)=? ORDER BY 1", (r["key"],))]
                stmt += (" This is the same name string only, not a confirmed common account: verify it is the same person "
                         "(subscriber details, shared IPs or identifiers).")
                if len(variants) > 1:
                    stmt += f" The letter case differs between records: {', '.join(variants[:6])}."
            prio = 1 if r["kind"] not in ("ip", "username") or len(per) >= 3 else 2
            if r["kind"] == "username":
                prio = 2
            self.add("crossref_item", f"{what} {r['shown']}: {len(per)} returns", stmt,
                     {"values": {"kind": r["kind"], "value": r["shown"], "returns": ", ".join(p["ret"] for p in per), "return_count": len(per),
                                 "records": r["records"], "first_utc": r["first"], "last_utc": r["last"], "accounts": r["accounts"]},
                      "tables": [{"title": "Records by return", "columns": ["return", "name", "records", "first_utc", "last_utc", "accounts"],
                                  "rows": [[p["ret"], p["name"], p["n"], p["f"], p["l"], p["accounts"]] for p in per]}]},
                     sql=r["sql"], evidence=ev, priority=prio,
                     sort_key=f"{9 - min(len(per), 9)}{KIND_ORDER.get(r['kind'], 8)}{10**9 - min(r['records'], 10**9 - 1):010d}{r['shown'].lower()}")
        if len(self.rows) > cap:
            rest = self.rows[cap:]
            self.add("crossref_more", f"{len(rest)} more items in several returns",
                     f"{plural(len(rest), 'more item')} appear in two or more returns; they are all listed in exports/crossref.csv.",
                     {"values": {"count": len(rest)}, "tables": [{"title": "Not shown individually", "columns": ["kind", "value", "returns", "records"],
                                                                "rows": [[x["kind"], x["shown"], " ".join(p["ret"] for p in x["per"]), x["records"]] for x in rest[: self.trows]],
                                                                "total_rows": len(rest)}]},
                     sql=ALL_SQL, priority=3, sort_key="8", export="exports/crossref.csv")
