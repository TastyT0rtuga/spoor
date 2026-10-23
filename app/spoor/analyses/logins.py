"""Login and account-security analysis: per-account summaries, failed-login bursts (and what
followed them), password-spray patterns, and security changes made from newly seen IPs."""
from __future__ import annotations

from ..findings import plural
from ..util import fmt_int
from .base import EXACT, T, Analysis, human_delta, sq

LOGIN_CATS = "('login','login_failed','logout','account_change','registration')"


class Logins(Analysis):
    module = "logins"
    category = "Logins & account security"

    def run(self):
        n = self.one(f"SELECT COUNT(*) FROM events WHERE category IN {LOGIN_CATS}") or 0
        if not n:
            self.add("no_logins", "No login or account-security events",
                     "No record was classified as a login, failed login, logout, registration or account change "
                     "(event types are read from the mapped event/activity column, or from the source's default type).",
                     {"values": {"events": 0}}, priority=3)
            return
        self.msg("per-account summaries")
        self.accounts()
        self.msg("failed-login bursts")
        self.bursts()
        self.spray()
        self.msg("security changes")
        self.changes()

    def accounts(self):
        accts = self.q(f"SELECT account, SUM(category='login') AS li, SUM(category='login_failed') AS lf, SUM(category='logout') AS lo, "
                       f"SUM(category='account_change') AS ch, SUM(category='registration') AS rg, COUNT(DISTINCT ip) AS ips, "
                       f"COUNT(DISTINCT CASE WHEN ip_class='public' THEN ip END) AS pub, "
                       f"COUNT(DISTINCT CASE WHEN ip_class='documentation' THEN ip END) AS doc, COUNT(DISTINCT user_agent) AS uas, "
                       f"MIN(ts_utc) AS f, MAX(ts_utc) AS l, COUNT(DISTINCT source_id) AS srcs "
                       f"FROM events WHERE category IN {LOGIN_CATS} AND account IS NOT NULL GROUP BY account "
                       f"ORDER BY li + lf DESC, account")
        for a in accts[: self.max]:
            acc = a["account"]
            top_ips = self.q(f"SELECT e.ip, COUNT(*) AS n, MIN(e.ts_utc) AS f, MAX(e.ts_utc) AS l, x.as_org, x.country FROM events e "
                             f"LEFT JOIN ip_enrich x ON x.ip=e.ip WHERE e.account=? AND e.category IN {LOGIN_CATS} AND e.ip IS NOT NULL "
                             f"GROUP BY e.ip ORDER BY n DESC, e.ip LIMIT ?", (acc, self.trows))
            uas = self.q(f"SELECT user_agent, COUNT(*) AS n, MIN(ts_utc) AS f, MAX(ts_utc) AS l FROM events WHERE account=? AND "
                         f"category IN {LOGIN_CATS} AND user_agent IS NOT NULL GROUP BY user_agent ORDER BY n DESC LIMIT 10", (acc,))
            bits = [f"{fmt_int(a['li'])} successful logins", f"{fmt_int(a['lf'])} failed", f"{fmt_int(a['lo'])} logouts",
                    f"{fmt_int(a['ch'])} account changes"]
            if a["rg"]:
                bits.append(f"{fmt_int(a['rg'])} registration events")
            stmt = (f"Account {acc}: " + ", ".join(bits) + f", from {plural(a['ips'], 'distinct IP')} ({fmt_int(a['pub'])} public"
                    + (f", {fmt_int(a['doc'])} in documentation ranges" if a["doc"] else "") + ")"
                    + (f" and {plural(a['uas'], 'user agent')}" if a["uas"] else "")
                    + (f", {T(a['f'])} to {T(a['l'])}" if a["f"] else "")
                    + (f" (returns: {self.prov.tags(self.prov.of_account(acc))})." if self.multi else f" (sources: {plural(a['srcs'], 'source')})."))
            ev = self.sample(f"account=? AND category IN {LOGIN_CATS}", (acc,), self.nsamp)
            tables = [{"title": "Most-used IPs", "columns": ["ip", "events", "first_utc", "last_utc", "network", "country"],
                       "rows": [[t["ip"], t["n"], t["f"], t["l"], t["as_org"], t["country"]] for t in top_ips]}]
            if uas:
                tables.append({"title": "User agents", "columns": ["user_agent", "events", "first_utc", "last_utc"],
                               "rows": [[u["user_agent"], u["n"], u["f"], u["l"]] for u in uas]})
            self.add("account_logins", f"Account {acc}: login activity", stmt,
                     {"values": {"account": acc, "logins": a["li"], "failed": a["lf"], "logouts": a["lo"], "changes": a["ch"],
                                 "registrations": a["rg"], "ips": a["ips"], "public_ips": a["pub"], "documentation_ips": a["doc"], "user_agents": a["uas"],
                                 "first_utc": a["f"], "last_utc": a["l"], "sources": a["srcs"],
                                 "returns": self.prov.labels(self.prov.of_account(acc))}, "tables": tables},
                     sql=f"SELECT cite, ts_utc, category, action, ip, user_agent FROM ev WHERE account={sq(acc)} AND category IN {LOGIN_CATS} ORDER BY ts_utc",
                     evidence=ev, priority=2, sort_key=f"5{10**9 - (a['li'] + a['lf']):010d}{acc}")

    def bursts(self):
        k = int(self.p.get("burst_failures", 5))
        w = int(self.p.get("burst_window_min", 10)) * 60
        fu = int(self.p.get("burst_followup_min", 30)) * 60
        accts = [r["account"] for r in self.q("SELECT account FROM events WHERE category='login_failed' AND account IS NOT NULL "
                                               f"AND {EXACT} GROUP BY account HAVING COUNT(*) >= ?", (k,))]
        from collections import deque
        found = []
        for acc in accts:
            cluster = None
            window: deque = deque()

            def close(cl):
                if cl and cl["max_in_window"] >= k:
                    found.append((acc, cl))
            for r in self.con.execute("SELECT id, ts_epoch, ts_utc, ip FROM events WHERE account=? AND category='login_failed' "
                                      f"AND {EXACT} ORDER BY ts_epoch, id", (acc,)):
                f = {"id": r[0], "ts_epoch": r[1], "ts_utc": r[2], "ip": r[3]}
                if cluster is None or f["ts_epoch"] - cluster["last"]["ts_epoch"] > w:
                    close(cluster)
                    cluster = {"first": f, "last": f, "n": 0, "ips": set(), "samples": [], "max_in_window": 0}
                    window.clear()
                cluster["last"] = f
                cluster["n"] += 1
                if f["ip"] and len(cluster["ips"]) < 50:
                    cluster["ips"].add(f["ip"])
                if len(cluster["samples"]) < 8:
                    cluster["samples"].append(f)
                window.append(f["ts_epoch"])
                while window and f["ts_epoch"] - window[0] > w:
                    window.popleft()
                cluster["max_in_window"] = max(cluster["max_in_window"], len(window))
            close(cluster)
        found.sort(key=lambda t: (-t[1]["n"], t[0], t[1]["first"]["ts_epoch"]))
        for acc, cl in found[: self.max]:
            start, end, n_fail = cl["first"], cl["last"], cl["n"]
            ips = sorted(cl["ips"])
            succ = self.q("SELECT id, ts_utc, ts_epoch, ip FROM events WHERE account=? AND category='login' AND ts_epoch > ? AND ts_epoch <= ? "
                          "ORDER BY ts_epoch, id LIMIT 1", (acc, end["ts_epoch"], end["ts_epoch"] + fu))
            dur = end["ts_epoch"] - start["ts_epoch"]
            stmt = (f"Account {acc}: {plural(n_fail, 'failed login')} between {T(start['ts_utc'])} and {T(end['ts_utc'])} "
                    f"({human_delta(dur)}) from {plural(len(ips), 'IP')}" + (f" ({', '.join(ips[:6])}{' ...' if len(ips) > 6 else ''})" if ips else "") + ".")
            vals = {"account": acc, "failures": n_fail, "start_utc": start["ts_utc"], "end_utc": end["ts_utc"],
                    "duration": human_delta(dur), "duration_seconds": round(dur), "ips": ips[:20], "ip_count": len(ips),
                    "threshold": int(self.p.get("burst_failures", 5)), "window_minutes": int(self.p.get("burst_window_min", 10)),
                    "followup_minutes": int(self.p.get("burst_followup_min", 30))}
            ev = [(start["id"], "first failure"), (end["id"], "last failure")] + [(f["id"], "failure") for f in cl["samples"][1:7]]
            prio = 2
            if succ:
                s = succ[0]
                gap = s["ts_epoch"] - end["ts_epoch"]
                same = s["ip"] in ips if s["ip"] else False
                stmt += (f" A successful login followed at {T(s['ts_utc'])} ({human_delta(gap)} after the last failure) from IP {s['ip'] or '(no IP)'}, "
                         + ("one of the failing IPs." if same else "an IP not used in the failures."))
                vals.update({"success_utc": s["ts_utc"], "success_ip": s["ip"], "success_after": human_delta(gap),
                             "success_ip_in_failures": same})
                ev.append((s["id"], "success after burst"))
                prio = 1
            else:
                stmt += f" No successful login for the account within {int(self.p.get('burst_followup_min', 30))} minutes after the last failure."
            self.add("failed_burst", f"{acc}: burst of {n_fail} failed logins", stmt, {"values": vals},
                     sql=f"SELECT cite, ts_utc, ip, action FROM ev WHERE account={sq(acc)} AND category IN ('login_failed','login') "
                         f"AND ts_utc BETWEEN '{start['ts_utc']}' AND datetime('{end['ts_utc']}', '+{int(fu // 60)} minutes') ORDER BY ts_utc",
                     evidence=ev, priority=prio, sort_key=f"2{start['ts_utc']}{acc}")

    def spray(self):
        rows = self.q("SELECT ip, COUNT(DISTINCT account) AS accts, COUNT(*) AS n, MIN(ts_utc) AS f, MAX(ts_utc) AS l FROM events "
                      "WHERE category='login_failed' AND ip IS NOT NULL AND account IS NOT NULL GROUP BY ip HAVING accts >= 3 "
                      "ORDER BY accts DESC, n DESC, ip")
        for r in rows[: self.max]:
            accs = [x["account"] for x in self.q("SELECT account, COUNT(*) AS n FROM events WHERE ip=? AND category='login_failed' "
                                                  "GROUP BY account ORDER BY n DESC, account LIMIT 10", (r["ip"],))]
            stmt = (f"IP {r['ip']} ({self.net_label(r['ip'])}) has {plural(r['n'], 'failed login')} against {plural(r['accts'], 'different account')} "
                    f"between {T(r['f'])} and {T(r['l'])}: {', '.join(accs)}{' ...' if r['accts'] > 10 else ''}.")
            self.add("multi_account_failures", f"IP {r['ip']}: failed logins on {r['accts']} accounts", stmt,
                     {"values": {"ip": r["ip"], "accounts": r["accts"], "failures": r["n"], "first_utc": r["f"], "last_utc": r["l"],
                                 "account_list": accs}},
                     sql=f"SELECT cite, ts_utc, account, action FROM ev WHERE ip='{r['ip']}' AND category='login_failed' ORDER BY ts_utc",
                     evidence=self.sample("ip=? AND category='login_failed'", (r["ip"],), 8), priority=1, sort_key=f"1{r['ip']}")

    def changes(self):
        hours = int(self.p.get("change_new_ip_hours", 24))
        rows = self.q("SELECT id, account, ts_utc, ts_epoch, ip, action, status FROM events WHERE category='account_change' AND "
                      "account IS NOT NULL ORDER BY ts_epoch IS NULL, ts_epoch, id")
        if not rows:
            return
        newip, other = [], []
        for r in rows:
            if r["ip"] and r["ts_epoch"] is not None:
                first = self.q("SELECT id, ts_utc, ts_epoch FROM events WHERE account=? AND ip=? AND ts_epoch IS NOT NULL "
                               "ORDER BY ts_epoch, id LIMIT 1", (r["account"], r["ip"]))
                f = first[0] if first else None
                if f and f["ts_epoch"] >= r["ts_epoch"] - hours * 3600:
                    newip.append((r, f))
                    continue
            other.append(r)
        for r, f in newip[: self.max]:
            delta = r["ts_epoch"] - f["ts_epoch"]
            when = "with this event" if f["id"] == r["id"] or delta == 0 else f"at {T(f['ts_utc'])} ({human_delta(delta)} earlier)"
            stmt = (f"Account {r['account']}: '{r['action']}' at {T(r['ts_utc'])} from IP {r['ip']} ({self.net_label(r['ip'])}). "
                    f"The account's records show this IP for the first time {when}.")
            ev = [(r["id"], "account change")]
            if f["id"] != r["id"]:
                ev.append((f["id"], "first use of IP"))
            self.add("change_from_new_ip", f"{r['account']}: change from a newly seen IP", stmt,
                     {"values": {"account": r["account"], "action": r["action"], "ts_utc": r["ts_utc"], "ip": r["ip"],
                                 "ip_first_seen_utc": f["ts_utc"], "minutes_since_first_seen": round(delta / 60),
                                 "window_hours": hours}},
                     sql=f"SELECT cite, ts_utc, category, action, ip FROM ev WHERE account={sq(r['account'])} AND ip='{r['ip']}' ORDER BY ts_utc",
                     evidence=ev, priority=1, sort_key=f"3{r['ts_utc']}")
        if other:
            trs = [[self.cite(r["id"]), r["account"], r["ts_utc"], r["action"], r["ip"]] for r in other[: self.trows * 4]]
            stmt = (f"{plural(len(other), 'other account-change event')} came from IPs the account had used before (or carry no IP/time); "
                    "they are listed in the table and in exports/timeline.csv.")
            self.add("changes_other", "Other account changes", stmt,
                     {"values": {"count": len(other)},
                      "tables": [{"title": "Account changes", "columns": ["cite", "account", "ts_utc", "action", "ip"], "rows": trs,
                                  "total_rows": len(other)}]},
                     sql="SELECT cite, account, ts_utc, action, ip FROM ev WHERE category='account_change' ORDER BY ts_utc",
                     evidence=[(r["id"], "account change") for r in other[: self.nsamp]], priority=3, sort_key="9chg")
