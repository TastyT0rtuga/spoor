"""IP address analysis: inventory, IPs shared across sources/accounts, address types, ports,
networks (offline ASN/country), subnet clusters, and the IP/timestamp list for follow-on process."""
from __future__ import annotations

import csv

from ..findings import plural
from ..ipaddr import CLASS_NOTES
from ..util import fmt_int
from .base import T, ATTR_SQL, Analysis, closest_couse, hosting_match, human_delta


class IPs(Analysis):
    module = "ips"
    category = "IP addresses"

    def run(self):
        n_ip_ev = self.one("SELECT COUNT(*) FROM events WHERE ip IS NOT NULL") or 0
        if not n_ip_ev:
            self.add("no_ips", "No IP addresses in the data",
                     "No record in the ingested sources carries an IP address in a mapped IP column or in free text.",
                     {"values": {"events_with_ip": 0}}, priority=2)
            return
        self.msg("inventory")
        self.inventory(n_ip_ev)
        self.msg("IPs shared across sources and accounts")
        self.notable()
        self.msg("address types")
        self.nonpublic()
        self.ports()
        self.msg("networks")
        self.networks()
        self.subnets()
        self.msg("IP/timestamp list for legal process")
        self.legal_process()

    # ------------------------------------------------------------------
    def inventory(self, n_ip_ev):
        by = self.q("SELECT ip_ver, ip_class, COUNT(*) AS n, SUM(events) AS ev FROM ip_summary GROUP BY 1, 2")
        distinct = sum(r["n"] for r in by)
        v4 = sum(r["n"] for r in by if r["ip_ver"] == 4)
        v6 = sum(r["n"] for r in by if r["ip_ver"] == 6)
        classes: dict = {}
        for r in by:
            classes[r["ip_class"]] = classes.get(r["ip_class"], 0) + r["n"]
        top = self.q("SELECT * FROM ip_summary ORDER BY events DESC, ip LIMIT ?", (self.trows,))
        cls_txt = ", ".join(f"{c} {fmt_int(n)}" for c, n in sorted(classes.items(), key=lambda t: -t[1]))
        stmt = (f"{plural(distinct, 'distinct IP address', 'distinct IP addresses')} appear in {plural(n_ip_ev, 'event')} "
                f"({fmt_int(v4)} IPv4, {fmt_int(v6)} IPv6). By address type: {cls_txt}.")
        vals = {"distinct_ips": distinct, "events_with_ip": n_ip_ev, "ipv4": v4, "ipv6": v6}
        vals.update({f"class_{k}": v for k, v in classes.items()})
        ev = []
        for r in top[:5]:
            ev += self.sample("ip=?", (r["ip"],), 2)
        self.add("ip_inventory", "IP address inventory", stmt,
                 {"values": vals, "tables": [{"title": f"Top {len(top)} IPs by number of events",
                                              "columns": ["ip", "class", "events", "accounts", "sources", "first_utc", "last_utc", "asn", "network", "country"],
                                              "rows": [[r["ip"], r["ip_class"], r["events"], r["accounts"], r["sources"], r["first_utc"],
                                                        r["last_utc"], r["asn"], r["as_org"], r["country"]] for r in top],
                                              "total_rows": distinct}]},
                 sql="SELECT * FROM ip_summary ORDER BY events DESC", evidence=ev, priority=3, sort_key="9",
                 export="exports/ip_inventory.csv")

    # ------------------------------------------------------------------
    def notable(self):
        maxacc = int(self.p.get("shared_ip_max_accounts", 25))
        win = int(self.p.get("coincidence_window_min", 60)) * 60
        rows = self.q(f"SELECT * FROM ip_summary WHERE ip_class IN {ATTR_SQL} AND (sources >= 2 OR accounts >= 2) "
                      "ORDER BY accounts DESC, sources DESC, events DESC, ip")
        infra = [r for r in rows if r["accounts"] > maxacc]
        rows = [r for r in rows if r["accounts"] <= maxacc]
        for r in rows[: self.max]:
            ip = r["ip"]
            accts = self.q("SELECT account, events, first_utc, last_utc FROM ip_accounts WHERE ip=? ORDER BY events DESC, account", (ip,))
            srcs = self.q("SELECT source_id, COUNT(*) AS n, MIN(ts_utc) AS f, MAX(ts_utc) AS l FROM events WHERE ip=? "
                          "GROUP BY source_id ORDER BY source_id", (ip,))
            net = self.net_label(ip)
            src_lab = self.labels([s["source_id"] for s in srcs])
            parts = [f"IP {ip} ({net}) appears in {plural(r['events'], 'event')}"]
            if r["sources"] >= 2:
                parts.append(f"across {plural(r['sources'], 'source')} ({src_lab})")
            else:
                parts.append(f"in {src_lab}")
            stmt = " ".join(parts)
            if r["first_utc"]:
                stmt += f" between {T(r['first_utc'])} and {T(r['last_utc'])}"
            stmt += "."
            vals = {"ip": ip, "network": net, "events": r["events"], "sources": r["sources"], "source_labels": src_lab,
                    "accounts": r["accounts"], "first_utc": r["first_utc"], "last_utc": r["last_utc"],
                    "asn": r["asn"], "as_org": r["as_org"], "country": r["country"], "ip_class": r["ip_class"]}
            ev = []
            if accts:
                shown = accts[:5]
                desc = "; ".join(f"{a['account']} ({plural(a['events'], 'event')}, {T(a['first_utc'])} to {T(a['last_utc'])})"
                                 if a["first_utc"] else f"{a['account']} ({plural(a['events'], 'event')})" for a in shown)
                more = f" and {len(accts) - 5} more" if len(accts) > 5 else ""
                stmt += f" Accounts using it: {desc}{more}."
            couse = closest_couse(self.con, ip) if r["accounts"] >= 2 else None
            prio = 1
            if couse:
                d, ea, aa, ta, eb, ab, tb, act = couse
                vals.update({"closest_couse_seconds": round(d), "closest_couse": human_delta(d), "couse_account_a": aa,
                             "couse_ts_a": ta, "couse_account_b": ab, "couse_ts_b": tb, "couse_activity_records": act})
                kind_txt = "activity records (logins, changes, transactions or messages)" if act else "records"
                stmt += (f" Closest {kind_txt} of two different accounts on this IP: {aa} at {T(ta)} and {ab} at {T(tb)} "
                         f"({human_delta(d)} apart).")
                ev += [(ea, "co-use"), (eb, "co-use")]
                if d > win:
                    prio = 2
            for s in srcs:
                ev += self.sample("ip=? AND source_id=?", (ip, s["source_id"]), 2)
            ev += self.sample("ip=?", (ip,), 4)
            tables = [{"title": "Accounts", "columns": ["account", "events", "first_utc", "last_utc"],
                       "rows": [[a["account"], a["events"], a["first_utc"], a["last_utc"]] for a in accts[: self.trows]],
                       "total_rows": len(accts)},
                      {"title": "Sources", "columns": ["source", "events", "first_utc", "last_utc"],
                       "rows": [[self.labels([s["source_id"]]), s["n"], s["f"], s["l"]] for s in srcs]}]
            key = f"{999 - min(r['accounts'], 999):03d}{99 - min(r['sources'], 99):02d}{10**9 - min(r['events'], 10**9 - 1):010d}{ip}"
            self.add("notable_ip", f"IP {ip}: {plural(r['sources'], 'source')}, {plural(r['accounts'], 'account')}", stmt,
                     {"values": vals, "tables": tables},
                     sql=f"SELECT cite, ts_utc, account, category, action, port FROM ev WHERE ip='{ip}' ORDER BY ts_utc",
                     evidence=ev, priority=prio, sort_key=key)
        if len(rows) > self.max:
            rest = rows[self.max:]
            self.add("notable_ip_more", f"{len(rest)} more IPs in several sources or accounts",
                     f"{plural(len(rest), 'more IP address', 'more IP addresses')} appear in more than one source or account; they are listed in exports/ip_inventory.csv (sources >= 2 or accounts >= 2).",
                     {"values": {"count": len(rest)}, "tables": [{"title": "Not shown individually", "columns": ["ip", "sources", "accounts", "events"],
                                                                "rows": [[x["ip"], x["sources"], x["accounts"], x["events"]] for x in rest[: self.trows]],
                                                                "total_rows": len(rest)}]},
                     sql=f"SELECT * FROM ip_summary WHERE ip_class IN {ATTR_SQL} AND (sources>=2 OR accounts>=2)",
                     priority=2, sort_key="zzz")
        if infra:
            self.add("shared_infrastructure", f"{len(infra)} IPs used by more than {maxacc} accounts",
                     f"{plural(len(infra), 'IP address', 'IP addresses')} are each linked to more than {maxacc} accounts and are treated as shared infrastructure (not used to link accounts): "
                     + ", ".join(f"{x['ip']} ({x['accounts']} accounts)" for x in infra[:10]) + ".",
                     {"values": {"count": len(infra), "threshold": maxacc},
                      "tables": [{"title": "IPs", "columns": ["ip", "accounts", "events", "network"],
                                  "rows": [[x["ip"], x["accounts"], x["events"], x["as_org"]] for x in infra[: self.trows]],
                                  "total_rows": len(infra)}]},
                     sql=f"SELECT * FROM ip_summary WHERE accounts > {maxacc}", priority=2, sort_key="zz")

    # ------------------------------------------------------------------
    def nonpublic(self):
        for cls in ("cgnat", "private", "loopback", "link-local", "multicast", "reserved", "nat64"):
            r = self.q("SELECT COUNT(*) AS ips, SUM(events) AS ev FROM ip_summary WHERE ip_class=?", (cls,))[0]
            if not r["ips"]:
                continue
            top = self.q("SELECT ip, events, accounts, first_utc, last_utc FROM ip_summary WHERE ip_class=? ORDER BY events DESC, ip LIMIT ?",
                         (cls, self.trows))
            ex = ", ".join(f"{t['ip']} ({plural(t['events'], 'event')})" for t in top[:5])
            stmt = (f"{plural(r['ev'], 'event')} carry {plural(r['ips'], 'distinct IP')} in {CLASS_NOTES[cls]}: {ex}"
                    + (" ..." if r["ips"] > 5 else "") + ".")
            ev = []
            for t in top[:3]:
                ev += self.sample("ip=?", (t["ip"],), 2)
            self.add(f"class_{cls}", f"{cls} addresses", stmt,
                     {"values": {"class": cls, "ips": r["ips"], "events": r["ev"], "note": CLASS_NOTES[cls]},
                      "tables": [{"title": "Addresses", "columns": ["ip", "events", "accounts", "first_utc", "last_utc"],
                                  "rows": [[t["ip"], t["events"], t["accounts"], t["first_utc"], t["last_utc"]] for t in top],
                                  "total_rows": r["ips"]}]},
                     sql=f"SELECT * FROM ip_summary WHERE ip_class='{cls}'", evidence=ev,
                     priority=2 if cls in ("cgnat", "private") else 3, sort_key=f"5{cls}")

    def ports(self):
        rows = self.q(f"SELECT source_id, COUNT(*) AS n, SUM(port IS NOT NULL) AS wp FROM events WHERE ip_ver=4 AND "
                      f"ip_class IN {ATTR_SQL} GROUP BY source_id ORDER BY source_id")
        if not rows:
            return
        parts, trs = [], []
        for r in rows:
            lab = self.labels([r["source_id"]])
            trs.append([lab, r["n"], r["wp"]])
            parts.append(f"{lab}: {fmt_int(r['wp'])} of {fmt_int(r['n'])}")
        total = sum(r["n"] for r in rows)
        withp = sum(r["wp"] for r in rows)
        stmt = (f"{fmt_int(withp)} of {plural(total, self.pub + ' IPv4 event')} include a source port ({'; '.join(parts)}). "
                f"Events without a port may not be attributable to one subscriber where the ISP uses address sharing (CGNAT).")
        self.add("source_ports", f"Source ports for {self.pub} IPv4 events", stmt,
                 {"values": {"public_ipv4_events": total, "with_port": withp},
                  "tables": [{"title": "By source", "columns": ["source", "public_ipv4_events", "with_port"], "rows": trs}]},
                 sql=f"SELECT source, COUNT(*), SUM(port IS NOT NULL) FROM ev WHERE ip LIKE '%.%' AND ip_class IN {ATTR_SQL} GROUP BY source",
                 priority=2 if withp < total else 3, sort_key="6ports")

    # ------------------------------------------------------------------
    def networks(self):
        asn_meta = (self.geo or {}).get("asn")
        geo_meta = (self.geo or {}).get("geo")
        if asn_meta:
            dbl = f"{asn_meta['file']} (built {asn_meta['built']})"
            nets = self.q("SELECT asn, as_org, COUNT(*) AS ips, SUM(events) AS ev, SUM(accounts) AS acc, MIN(first_utc) AS f, "
                          "MAX(last_utc) AS l FROM ip_summary WHERE asn IS NOT NULL GROUP BY asn, as_org ORDER BY ev DESC, asn")
            unk = self.one("SELECT COUNT(*) FROM ip_summary WHERE ip_class='public' AND asn IS NULL") or 0
            if nets:
                top = nets[:5]
                stmt = (f"Public IPs map to {plural(len(nets), 'network')} (autonomous systems) in the offline database {dbl}. "
                        "Most events: " + "; ".join(f"AS{n['asn']} {n['as_org']} ({plural(n['ev'], 'event')}, {plural(n['ips'], 'IP')})" for n in top) + "."
                        + (f" {plural(unk, 'public IP')} had no ASN entry." if unk else "")
                        + " Registrations reflect the database date, not necessarily the date of each event.")
                self.add("networks", "Networks (ASNs) behind the public IPs", stmt,
                         {"values": {"networks": len(nets), "database": dbl, "no_asn": unk},
                          "tables": [{"title": "Networks", "columns": ["asn", "network", "ips", "events", "first_utc", "last_utc"],
                                      "rows": [[n["asn"], n["as_org"], n["ips"], n["ev"], n["f"], n["l"]] for n in nets[: self.trows]],
                                      "total_rows": len(nets)}]},
                         sql="SELECT asn, as_org, COUNT(*) ips, SUM(events) FROM ip_summary WHERE asn IS NOT NULL GROUP BY 1,2 ORDER BY 4 DESC",
                         priority=2, sort_key="7net", export="exports/ip_inventory.csv")
                hits = [(n, hosting_match(n["as_org"])) for n in nets]
                hits = [(n, k) for n, k in hits if k]
                if hits:
                    ev = []
                    for n, _k in hits[:8]:
                        ev += self.sample("ip IN (SELECT ip FROM ip_summary WHERE asn=?)", (n["asn"],), 2)
                    tot_ev = sum(n["ev"] for n, _ in hits)
                    tot_ip = sum(n["ips"] for n, _ in hits)
                    stmt = (f"{plural(tot_ev, 'event')} from {plural(tot_ip, 'IP')} belong to {plural(len(hits), 'network')} whose registered name "
                            f"matches the hosting/VPN keyword list: " + "; ".join(
                                f"AS{n['asn']} {n['as_org']} (keyword '{k}'; {plural(n['ev'], 'event')}, {plural(n['ips'], 'IP')})" for n, k in hits[:8])
                            + (" ..." if len(hits) > 8 else "") + f". Source: {dbl}. A keyword match is a lead, not proof of VPN or hosting use.")
                    self.add("hosting_networks", "IPs on hosting / VPN-named networks", stmt,
                             {"values": {"events": tot_ev, "ips": tot_ip, "networks": len(hits), "database": dbl},
                              "tables": [{"title": "Matched networks", "columns": ["asn", "network", "keyword", "ips", "events", "first_utc", "last_utc"],
                                          "rows": [[n["asn"], n["as_org"], k, n["ips"], n["ev"], n["f"], n["l"]] for n, k in hits]}]},
                             sql="SELECT ip, asn, as_org, events, first_utc, last_utc FROM ip_summary WHERE asn IN (" +
                                 ",".join(str(n["asn"]) for n, _ in hits) + ")",
                             evidence=ev, priority=1, sort_key="2host")
        if geo_meta:
            dbl = f"{geo_meta['file']} (built {geo_meta['built']})"
            cs = self.q("SELECT country, COUNT(*) AS ips, SUM(events) AS ev FROM ip_summary WHERE country IS NOT NULL GROUP BY country ORDER BY ev DESC")
            if cs:
                tot = sum(c["ev"] for c in cs) or 1
                stmt = (f"Public IPs geolocate (country level only) to {plural(len(cs), 'country', 'countries')} in {dbl}: "
                        + "; ".join(f"{c['country']} {plural(c['ev'], 'event')} ({100 * c['ev'] / tot:.1f}%)" for c in cs[:8])
                        + ". Geolocation is approximate and reflects the database date.")
                rows = [[c["country"], c["ips"], c["ev"], round(100 * c["ev"] / tot, 1)] for c in cs]
                self.add("countries", "Country geolocation of public IPs", stmt,
                         {"values": {"countries": len(cs), "database": dbl},
                          "tables": [{"title": "Countries", "columns": ["country", "ips", "events", "pct"], "rows": rows}]},
                         sql="SELECT country, COUNT(*), SUM(events) FROM ip_summary WHERE country IS NOT NULL GROUP BY 1 ORDER BY 3 DESC",
                         priority=2, sort_key="7geo")

    def subnets(self):
        mn = int(self.p.get("subnet_min_ips", 3))
        rows = self.q(f"SELECT subnet, COUNT(*) AS ips, SUM(events) AS ev, MIN(first_utc) AS f, MAX(last_utc) AS l, "
                      f"MAX(as_org) AS org FROM ip_summary WHERE ip_class IN {ATTR_SQL} GROUP BY subnet HAVING ips >= ? "
                      f"ORDER BY ips DESC, ev DESC, subnet", (mn,))
        if not rows:
            return
        trs = []
        for r in rows[: self.trows]:
            acc = self.one("SELECT COUNT(DISTINCT account) FROM events WHERE subnet=?", (r["subnet"],))
            trs.append([r["subnet"], r["ips"], r["ev"], acc, r["org"], r["f"], r["l"]])
        stmt = (f"{plural(len(rows), 'subnet')} (/24 for IPv4, /64 for IPv6) contain at least {mn} distinct IPs from the data; largest: "
                + "; ".join(f"{t[0]} ({plural(t[1], 'IP')}, {plural(t[2], 'event')})" for t in trs[:5]) + ".")
        self.add("subnets", "Subnet clusters", stmt,
                 {"values": {"subnets": len(rows), "min_ips": mn},
                  "tables": [{"title": "Subnets", "columns": ["subnet", "ips", "events", "accounts", "network", "first_utc", "last_utc"],
                              "rows": trs, "total_rows": len(rows)}]},
                 sql=f"SELECT subnet, COUNT(*), SUM(events) FROM ip_summary WHERE ip_class IN {ATTR_SQL} GROUP BY subnet HAVING COUNT(*)>={mn}",
                 priority=3, sort_key="8sub")

    def legal_process(self):
        path = self.case.exports_dir / "ip_legal_process.csv"
        path.parent.mkdir(parents=True, exist_ok=True)
        n = wp = 0
        ips, asns = set(), set()
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["ip", "timestamp_utc", "source_port", "account", "citation", "original_timestamp", "timezone_basis",
                        "timestamp_flags", "asn", "network", "country"])
            for r in self.con.execute(
                    f"SELECT e.ip, e.ts_utc, e.port, e.account, s.label || ':' || e.loc AS cite, e.ts_raw, e.tz_basis, e.ts_flag, "
                    f"x.asn, x.as_org, x.country FROM events e JOIN sources s ON s.id=e.source_id LEFT JOIN ip_enrich x ON x.ip=e.ip "
                    f"WHERE e.ip_class IN {ATTR_SQL} AND e.ts_utc IS NOT NULL ORDER BY x.as_org, e.ip, e.ts_epoch, e.id"):
                w.writerow(list(r))
                n += 1
                wp += r["port"] is not None
                ips.add(r["ip"])
                if r["asn"]:
                    asns.add(r["asn"])
        if not n:
            return
        stmt = (f"{plural(n, self.pub + ' IP/timestamp pair')} ({plural(len(ips), 'distinct IP')}"
                + (f", {plural(len(asns), 'network')}" if asns else "") + f") are listed in exports/ip_legal_process.csv, sorted by network, IP and time; "
                f"{fmt_int(wp)} include a source port. Each row carries its citation and the original timestamp text.")
        self.add("legal_process_list", "IP/timestamp list for follow-on legal process", stmt,
                 {"values": {"pairs": n, "ips": len(ips), "networks": len(asns), "with_port": wp}},
                 sql=f"SELECT ip, ts_utc, port, account, cite FROM ev WHERE ip_class IN {ATTR_SQL} AND ts_utc IS NOT NULL ORDER BY ip, ts_utc",
                 priority=2, sort_key="6legal", export="exports/ip_legal_process.csv")
