"""Links: accounts connected through shared IPs (with the closest co-use as evidence) and
identifiers (emails, phones, crypto addresses, devices) shared across accounts or sources."""
from __future__ import annotations

import csv

from ..findings import plural
from ..identifiers import KIND_LABELS
from .base import T, ATTR_SQL, Analysis, closest_couse, human_delta, sq


class Links(Analysis):
    module = "links"
    category = "Links & cross-source"

    def run(self):
        self.msg("accounts linked by shared IPs")
        self.ip_links()
        self.msg("shared identifiers")
        self.shared_identifiers()
        self.msg("link-chart export")
        self.export_edges()

    def ip_links(self):
        maxacc = int(self.p.get("shared_ip_max_accounts", 25))
        classes = "('public','documentation','private','cgnat')" if self.p.get("link_include_nonpublic") else ATTR_SQL
        ips = self.q(f"SELECT ip FROM ip_summary WHERE ip_class IN {classes} AND accounts BETWEEN 2 AND ?", (maxacc,))
        parent: dict = {}

        def find(x):
            while parent.setdefault(x, x) != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        pair_ips: dict = {}
        for r in ips:
            accs = [a["account"] for a in self.q("SELECT account FROM ip_accounts WHERE ip=? ORDER BY account", (r["ip"],))]
            for i, a in enumerate(accs):
                find(a)
                for b in accs[i + 1:]:
                    parent[find(a)] = find(b)
                    pair_ips.setdefault((a, b), []).append(r["ip"])
        comps: dict = {}
        for a in list(parent):
            comps.setdefault(find(a), set()).add(a)
        comps_l = sorted((sorted(c) for c in comps.values() if len(c) >= 2), key=lambda c: (-len(c), c[0]))
        for comp in comps_l[: self.max]:
            cs = set(comp)
            pairs = [(k, v) for k, v in pair_ips.items() if k[0] in cs]
            rows, ev, best = [], [], None
            for (a, b), ipl in sorted(pairs, key=lambda kv: (-len(kv[1]), kv[0])):
                closest = None
                for ip in ipl:
                    c = closest_couse(self.con, ip, {a, b})
                    if c and (closest is None or (c[7], -c[0]) > (closest[7], -closest[0])):
                        closest = c + (ip,)
                rows.append([a, b, len(ipl), ", ".join(ipl[:8]) + (" ..." if len(ipl) > 8 else ""),
                             human_delta(closest[0]) if closest else "", closest[8] if closest else "",
                             ("activity" if closest[7] else "other records") if closest else ""])
                if closest:
                    ev += [(closest[1], "co-use"), (closest[4], "co-use")]
                    # prefer co-use seen in activity records; among equals the smaller gap
                    if best is None or (closest[7], -closest[0]) > (best[7], -best[0]):
                        best = closest
            n_ips = len({ip for _, v in pairs for ip in v})
            stmt = (f"{plural(len(comp), 'account')} are connected through {plural(n_ips, 'shared IP')}: {', '.join(comp[:12])}"
                    + (" ..." if len(comp) > 12 else "") + ".")
            vals = {"accounts": comp[:50], "account_count": len(comp), "shared_ips": n_ips}
            if best:
                d, ea, aa, ta, eb, ab, tb, act, ip = best
                kind_txt = "activity records" if act else "records (no activity records overlap)"
                stmt += (f" Closest {kind_txt} of two of these accounts on one IP: {aa} at {T(ta)} and {ab} at {T(tb)} on IP {ip} "
                         f"({human_delta(d)} apart).")
                vals.update({"closest_ip": ip, "closest": human_delta(d), "closest_seconds": round(d), "closest_a": aa,
                             "closest_ts_a": ta, "closest_b": ab, "closest_ts_b": tb, "closest_activity_records": act})
            mer = self._mermaid(comp, pairs)
            self.add("account_cluster", f"{len(comp)} accounts linked by shared IPs", stmt,
                     {"values": vals, "mermaid": mer,
                      "tables": [{"title": "Account pairs", "columns": ["account_a", "account_b", "shared_ips", "ips", "closest_co_use", "on_ip", "co_use_records"],
                                  "rows": rows[: self.trows], "total_rows": len(rows)}]},
                     sql="SELECT a.ip, a.account, b.account FROM ip_accounts a JOIN ip_accounts b ON a.ip=b.ip AND a.account<b.account "
                         f"WHERE a.account IN ({', '.join(sq(x) for x in comp[:30])})",
                     evidence=ev[: self.nsamp * 2], priority=1, sort_key=f"1{999 - len(comp):03d}{comp[0]}")

    @staticmethod
    def _mermaid(comp, pairs) -> str:
        if len(comp) > 15:
            return ""
        ids = {a: f"A{i}" for i, a in enumerate(comp)}
        lines = ["graph LR"]
        for a, i in ids.items():
            lines.append(f'  {i}["{a.replace(chr(34), "")}"]')
        ipn: dict = {}
        for (a, b), ipl in pairs:
            for ip in ipl[:6]:
                if ip not in ipn:
                    ipn[ip] = f"I{len(ipn)}"
                    lines.append(f'  {ipn[ip]}(("{ip}"))')
        seen = set()
        for (a, b), ipl in pairs:
            for ip in ipl[:6]:
                for acc in (a, b):
                    k = (acc, ip)
                    if k not in seen:
                        seen.add(k)
                        lines.append(f"  {ids[acc]} --- {ipn[ip]}")
        return "\n".join(lines) if len(lines) < 120 else ""

    def shared_identifiers(self):
        rows = self.q("SELECT * FROM ident_summary WHERE kind NOT IN ('ipv4','ipv6','url') AND validity != 'bad_checksum' "
                      "AND (accounts >= 2 OR sources >= 2) ORDER BY accounts DESC, sources DESC, events DESC, norm")
        for r in rows[: self.max]:
            per = self.q("SELECT e.account, i.source_id, COUNT(*) AS n, MIN(e.ts_utc) AS f, MAX(e.ts_utc) AS l "
                         "FROM identifiers i JOIN events e ON e.id=i.event_id WHERE i.kind=? AND i.norm=? "
                         "GROUP BY e.account, i.source_id ORDER BY i.source_id, e.account", (r["kind"], r["norm"]))
            srcs = self.labels({p["source_id"] for p in per})
            accs = sorted({p["account"] for p in per if p["account"]})
            label = KIND_LABELS.get(r["kind"], r["kind"])
            stmt = (f"{label[0].upper() + label[1:]} {r['norm']} appears in {plural(r['events'], 'record')} across {plural(r['sources'], 'source')} ({srcs})"
                    + (f" and in records of {plural(len(accs), 'account')}: {', '.join(accs[:10])}" if accs else "")
                    + (f"; {T(r['first_utc'])} to {T(r['last_utc'])}" if r["first_utc"] else "") + ".")
            ev = []
            for p in per[:10]:
                eid = self.one("SELECT i.event_id FROM identifiers i JOIN events e ON e.id=i.event_id WHERE i.kind=? AND i.norm=? "
                               "AND i.source_id=? AND (e.account IS ? OR e.account=?) ORDER BY e.ts_epoch IS NULL, e.ts_epoch, e.id LIMIT 1",
                               (r["kind"], r["norm"], p["source_id"], p["account"], p["account"]))
                if eid:
                    ev.append((eid, "occurrence"))
            prio = 1 if (len(accs) >= 2 or r["kind"] in ("btc", "eth", "ltc", "trx", "xmr", "doge", "phone", "email")) else 2
            self.add("shared_identifier", f"{label} {r['norm']}: {plural(r['sources'], 'source')}, {plural(len(accs), 'account')}", stmt,
                     {"values": {"kind": r["kind"], "value": r["norm"], "validity": r["validity"], "records": r["events"],
                                 "sources": r["sources"], "source_labels": srcs, "accounts": accs[:20], "account_count": len(accs),
                                 "first_utc": r["first_utc"], "last_utc": r["last_utc"]},
                      "tables": [{"title": "Occurrences by source and account", "columns": ["source", "account", "records", "first_utc", "last_utc"],
                                  "rows": [[self.labels([p["source_id"]]), p["account"], p["n"], p["f"], p["l"]] for p in per[: self.trows]],
                                  "total_rows": len(per)}]},
                     sql=f"SELECT kind, value, cite, ts_utc, account FROM ids WHERE kind='{r['kind']}' AND value={sq(r['norm'])} ORDER BY ts_utc",
                     evidence=ev, priority=prio, sort_key=f"2{9 - min(len(accs), 9)}{9 - min(r['sources'], 9)}{r['norm']}")

    def export_edges(self):
        out = self.case.exports_dir
        out.mkdir(parents=True, exist_ok=True)
        with open(out / "link_edges.csv", "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["source_node", "source_type", "target_node", "target_type", "relationship", "events", "first_utc", "last_utc"])
            for r in self.con.execute("SELECT account, ip, events, first_utc, last_utc FROM ip_accounts ORDER BY account, ip"):
                w.writerow([r["account"], "account", r["ip"], "ip", "used IP", r["events"], r["first_utc"], r["last_utc"]])
            for r in self.con.execute("SELECT e.account, i.kind, i.norm, COUNT(*) AS n, MIN(e.ts_utc), MAX(e.ts_utc) FROM identifiers i "
                                      "JOIN events e ON e.id=i.event_id WHERE e.account IS NOT NULL AND i.kind NOT IN ('ipv4','ipv6','url') "
                                      "AND i.norm != e.account GROUP BY e.account, i.kind, i.norm ORDER BY e.account"):
                w.writerow([r[0], "account", r[2], r[1], "appears with", r[3], r[4], r[5]])
        with open(out / "link_nodes.csv", "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["node", "type", "events", "first_utc", "last_utc", "detail"])
            for r in self.con.execute("SELECT account, events, first_utc, last_utc, ips FROM account_summary ORDER BY account"):
                w.writerow([r[0], "account", r[1], r[2], r[3], f"{r[4]} IPs"])
            for r in self.con.execute("SELECT ip, events, first_utc, last_utc, ip_class, as_org, country FROM ip_summary ORDER BY ip"):
                w.writerow([r[0], "ip", r[1], r[2], r[3], " / ".join(str(x) for x in r[4:] if x)])
            for r in self.con.execute("SELECT norm, kind, events, first_utc, last_utc FROM ident_summary WHERE kind NOT IN ('ipv4','ipv6','url')"):
                w.writerow([r[0], r[1], r[2], r[3], r[4], ""])
