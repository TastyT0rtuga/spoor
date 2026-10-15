"""Timing and activity patterns: hour-of-day and weekday profiles (UTC and the case's local zone),
daily volume spikes, inactivity gaps, and rapid switches between networks."""
from __future__ import annotations

import datetime as dt
import statistics
from array import array

from ..findings import plural
from ..util import fmt_int
from .base import ACTIVITY_CATS, ATTR_SQL, TIMED, TIMED_HOURS, Analysis, T, human_delta, sq

try:
    from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover
    ZoneInfo = None  # type: ignore

UTC = dt.timezone.utc
DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]


def quiet_window(h: list[int], k: int) -> tuple[int, int]:
    best = None
    for s in range(24):
        tot = sum(h[(s + i) % 24] for i in range(k))
        if best is None or tot < best[1]:
            best = (s, tot)
    return best  # type: ignore[return-value]


def hh(h: int) -> str:
    return f"{h % 24:02d}:00"


def hh_end(h: int) -> str:
    return f"{(h - 1) % 24:02d}:59"


class Temporal(Analysis):
    module = "temporal"
    category = "Timing & activity patterns"

    def run(self):
        n = self.one(f"SELECT COUNT(*) FROM events WHERE {TIMED}") or 0
        if not n:
            self.add("no_times", "No usable timestamps", "No record carries a usable timestamp, so no timing analysis was possible.",
                     {"values": {"timed_events": 0}}, priority=2)
            return
        try:
            self.tz = ZoneInfo(self.case.display_tz) if ZoneInfo else None
        except Exception:  # noqa: BLE001
            self.tz = None
        self.msg("hour-of-day profile")
        self.profile(None)
        tops = self.q(f"SELECT account, COUNT(*) AS n FROM events WHERE account IS NOT NULL AND {TIMED_HOURS} GROUP BY account "
                      f"HAVING n >= 50 ORDER BY n DESC, account LIMIT 5")
        for t in tops:
            self.profile(t["account"])
        self.msg("daily volume")
        self.daily()
        self.msg("inactivity gaps")
        self.gaps()
        self.msg("network switches")
        self.switches()

    # ------------------------------------------------------------------
    def profile(self, account):
        where = TIMED_HOURS + (" AND account=?" if account else "")
        args = (account,) if account else ()
        uh, lh, wd = [0] * 24, [0] * 24, [0] * 7
        total = 0
        for (ep,) in self.con.execute(f"SELECT ts_epoch FROM events WHERE {where}", args):
            d = dt.datetime.fromtimestamp(ep, UTC)
            uh[d.hour] += 1
            wd[d.weekday()] += 1
            if self.tz is not None:
                lh[d.astimezone(self.tz).hour] += 1
            total += 1
        if total < 10:
            return
        k = int(self.p.get("quiet_window_hours", 6))
        qs, qn = quiet_window(uh, k)
        bh = max(range(24), key=lambda i: (uh[i], -i))
        who = f"Account {account}" if account else "All sources"
        stmt = (f"{who}: of {plural(total, 'event')} with a time of day, the quietest {k}-hour window is "
                f"{hh(qs)}-{hh_end(qs + k)} UTC ({plural(qn, 'event')}, {100 * qn / total:.1f}%); the busiest hour is "
                f"{hh(bh)}-{hh_end(bh + 1)} UTC ({plural(uh[bh], 'event')}, {100 * uh[bh] / total:.1f}%).")
        vals = {"account": account, "events": total, "quiet_window_hours": k, "quiet_start_utc": hh(qs),
                "quiet_end_utc": hh_end(qs + k), "quiet_events": qn, "quiet_pct": round(100 * qn / total, 1),
                "busiest_hour_utc": hh(bh), "busiest_events": uh[bh], "busiest_pct": round(100 * uh[bh] / total, 1)}
        cols = ["hour", "events_utc"]
        if self.tz is not None:
            lqs, lqn = quiet_window(lh, k)
            stmt += (f" In {self.case.display_tz} local time the quietest {k}-hour window is {hh(lqs)}-{hh_end(lqs + k)} "
                     f"({plural(lqn, 'event')}).")
            vals.update({"local_zone": self.case.display_tz, "quiet_start_local": hh(lqs), "quiet_end_local": hh_end(lqs + k),
                         "quiet_events_local": lqn})
            cols.append(f"events_{self.case.display_tz}")
        bd = max(range(7), key=lambda i: (wd[i], -i))
        qd = min(range(7), key=lambda i: (wd[i], i))
        stmt += (f" Busiest weekday (UTC): {DAYS[bd]} ({plural(wd[bd], 'event')}); quietest: {DAYS[qd]} ({plural(wd[qd], 'event')}).")
        vals.update({"busiest_weekday": DAYS[bd], "busiest_weekday_events": wd[bd], "quietest_weekday": DAYS[qd],
                     "quietest_weekday_events": wd[qd]})
        rows = [[hh(i), uh[i]] + ([lh[i]] if self.tz is not None else []) for i in range(24)]
        self.add("hour_profile" if not account else "hour_profile_account",
                 f"{who}: hour-of-day profile", stmt,
                 {"values": vals, "chart": "hourly", "tables": [
                     {"title": "Events by hour", "columns": cols, "rows": rows},
                     {"title": "Events by weekday (UTC)", "columns": ["weekday", "events"], "rows": [[DAYS[i], wd[i]] for i in range(7)]}]},
                 sql=("SELECT strftime('%H', ts_utc) AS hour_utc, COUNT(*) FROM ev " +
                      (f"WHERE account={sq(account)} " if account else "") + "GROUP BY 1 ORDER BY 1"),
                 priority=2 if not account else 3, sort_key=("1" if not account else "2") + (account or ""))

    def daily(self):
        rows = self.q(f"SELECT substr(ts_utc, 1, 10) AS day, COUNT(*) AS n FROM events WHERE {TIMED} GROUP BY day ORDER BY day")
        if len(rows) < 3:
            return
        counts = [r["n"] for r in rows]
        med = statistics.median(counts)
        thr = max(10, 5 * med)
        spikes = sorted([r for r in rows if r["n"] >= thr], key=lambda r: (-r["n"], r["day"]))
        first, last = rows[0]["day"], rows[-1]["day"]
        span = (dt.date.fromisoformat(last) - dt.date.fromisoformat(first)).days + 1
        stmt = (f"Events fall on {plural(len(rows), 'distinct UTC day')} between {first} and {last} ({plural(span, 'calendar day')}); "
                f"median {fmt_int(med)} events per active day.")
        if spikes:
            stmt += (f" {plural(len(spikes), 'day')} {'has' if len(spikes) == 1 else 'have'} at least {fmt_int(thr)} events (5 times the median, minimum 10): "
                     + "; ".join(f"{r['day']} ({plural(r['n'], 'event')})" for r in spikes[:8]) + (" ..." if len(spikes) > 8 else "") + ".")
        ev = []
        for r in spikes[:5]:
            ev += self.sample("substr(ts_utc,1,10)=?", (r["day"],), 2)
        self.add("daily_volume", "Daily activity volume", stmt,
                 {"values": {"active_days": len(rows), "first_day": first, "last_day": last, "calendar_days": span,
                             "median_per_day": med, "spike_threshold": thr, "spike_days": len(spikes)},
                  "chart": "daily",
                  "tables": [{"title": "Busiest days", "columns": ["day_utc", "events"],
                              "rows": [[r["day"], r["n"]] for r in sorted(rows, key=lambda r: (-r["n"], r["day"]))[: self.trows]],
                              "total_rows": len(rows)}]},
                 sql="SELECT substr(ts_utc,1,10) AS day, COUNT(*) FROM ev WHERE ts_utc IS NOT NULL GROUP BY 1 ORDER BY 2 DESC",
                 evidence=ev, priority=2, sort_key="3", export="exports/daily.csv")

    def gaps(self):
        """Inactivity gaps in activity records (logins, changes, transactions, messages), per account
        within each source and per source. Attribute records (creation dates, lease lines) are not activity.

        Measured within a source so that sparse records from other sources (e.g. an account's
        creation date in subscriber information) do not produce meaningless multi-year gaps."""
        min_days = float(self.p.get("gap_min_days", 7))
        factor = float(self.p.get("gap_factor", 10))
        found, seen = [], set()
        act = "category IN (" + ",".join(f"'{c}'" for c in ACTIVITY_CATS) + ") AND " + TIMED
        groups = [("account", (r["account"], r["source_id"])) for r in self.q(
            f"SELECT account, source_id FROM events WHERE account IS NOT NULL AND {act} GROUP BY account, source_id HAVING COUNT(*) >= 10")]
        groups += [("source", (None, r["source_id"])) for r in self.q(
            f"SELECT source_id FROM events WHERE {act} GROUP BY source_id HAVING COUNT(*) >= 20")]
        for kind, (acc, sid) in groups:
            if kind == "account":
                sql, args = f"SELECT id, ts_epoch, ts_utc FROM events WHERE account=? AND source_id=? AND {act} ORDER BY ts_epoch, id", (acc, sid)
            else:
                sql, args = f"SELECT id, ts_epoch, ts_utc FROM events WHERE source_id=? AND {act} ORDER BY ts_epoch, id", (sid,)
            ints = array("d")
            prev = None
            for r in self.con.execute(sql, args):          # pass 1: intervals (8 bytes each)
                if prev is not None and r[1] - prev > 0:
                    ints.append(r[1] - prev)
                prev = r[1]
            if not ints:
                continue
            med = statistics.median(ints)
            del ints
            thr = max(min_days * 86400, factor * med)
            prev = None
            for r in self.con.execute(sql, args):          # pass 2: the gaps themselves
                if prev is not None and r[1] - prev[1] >= thr:
                    key = (sid, prev[0], r[0])
                    if key not in seen:
                        seen.add(key)
                        found.append((kind, acc, sid, {"id": prev[0], "ts_utc": prev[2]}, {"id": r[0], "ts_utc": r[2]},
                                      r[1] - prev[1], med))
                prev = r
        found.sort(key=lambda t: -t[5])
        for kind, acc, sid, a, b, d, med in found[: self.max]:
            lab = self.labels([sid])
            who = f"Account {acc} in {lab}" if kind == "account" else f"Source {lab}"
            stmt = (f"{who} has no records between {T(a['ts_utc'])} and {T(b['ts_utc'])} ({human_delta(d)}); "
                    f"the median interval between its consecutive records is {human_delta(med)}.")
            self.add("gap", f"{who}: {human_delta(d)} without records", stmt,
                     {"values": {"account": acc, "source": lab, "kind": kind, "gap_start_utc": a["ts_utc"],
                                 "gap_end_utc": b["ts_utc"], "gap": human_delta(d), "gap_days": round(d / 86400, 1),
                                 "median_interval": human_delta(med), "min_days": min_days, "factor": factor}},
                     sql=(f"SELECT cite, ts_utc FROM ev WHERE source='{lab}'" + (f" AND account={sq(acc)}" if acc else "") +
                          f" AND ts_utc BETWEEN '{a['ts_utc']}' AND '{b['ts_utc']}' ORDER BY ts_utc"),
                     evidence=[(a["id"], "last record before gap"), (b["id"], "first record after gap")],
                     priority=2, sort_key=f"5{10**12 - int(d):013d}")

    def switches(self):
        win = int(self.p.get("concurrent_window_min", 10)) * 60
        accts = [r["account"] for r in self.q(
            f"SELECT account FROM events WHERE account IS NOT NULL AND ip_class IN {ATTR_SQL} AND ts_epoch IS NOT NULL "
            f"GROUP BY account HAVING COUNT(DISTINCT ip) >= 2")]
        results = []
        cols = ("id", "ts_epoch", "ts_utc", "ip", "ip_ver", "asn", "as_org", "country")
        for acc in accts:
            pairs, total = [], 0
            prev = None
            for row in self.con.execute(
                    f"SELECT e.id, e.ts_epoch, e.ts_utc, e.ip, e.ip_ver, x.asn, x.as_org, x.country FROM events e "
                    f"LEFT JOIN ip_enrich x ON x.ip=e.ip WHERE e.account=? AND e.ip_class IN {ATTR_SQL} AND {TIMED.replace('ts_', 'e.ts_')} "
                    f"ORDER BY e.ts_epoch, e.id", (acc,)):
                b = dict(zip(cols, row))
                a = prev
                prev = b
                if a is None:
                    continue
                d = b["ts_epoch"] - a["ts_epoch"]
                if d > win or a["ip"] == b["ip"]:
                    continue
                if a["asn"] and b["asn"]:
                    differ, how = a["asn"] != b["asn"], "different ASN"
                elif a["ip_ver"] == b["ip_ver"]:
                    differ = _wide_net(a["ip"], a["ip_ver"]) != _wide_net(b["ip"], b["ip_ver"])
                    how = "different /16 prefix" if a["ip_ver"] == 4 else "different /32 prefix"
                else:
                    differ = False   # IPv4 <-> IPv6 on the same connection is normal dual-stack behaviour
                if differ:
                    total += 1
                    cc = a["country"] and b["country"] and a["country"] != b["country"]
                    if len(pairs) < 500 or cc:
                        pairs.append((a, b, d, how))
            if pairs:
                results.append((acc, pairs, total))
        results.sort(key=lambda t: (-t[2], t[0]))
        for acc, pairs, total in results[: self.max]:
            cc = [p for p in pairs if p[0]["country"] and p[1]["country"] and p[0]["country"] != p[1]["country"]]
            hows = sorted({p[3] for p in pairs})
            show = (cc or pairs)[:5]
            ex = "; ".join(f"{a['ip']} ({_net(a)}) at {T(a['ts_utc'])} then {b['ip']} ({_net(b)}) at {T(b['ts_utc'])}, {human_delta(d)} apart"
                           for a, b, d, _h in show[:3])
            stmt = (f"Account {acc}: {plural(total, 'time')} consecutive events came from different networks ({' or '.join(hows)}) within "
                    f"{int(win // 60)} minutes" + (f", {plural(len(cc), 'time')} with a change of country" if cc else "") + f". Examples: {ex}.")
            ev = []
            for a, b, _d, _h in show:
                ev += [(a["id"], "before switch"), (b["id"], "after switch")]
            ordered = cc + [p for p in pairs if p not in cc]
            self.add("network_switch", f"{acc}: rapid network switches", stmt,
                     {"values": {"account": acc, "switches": total, "country_changes": len(cc), "window_minutes": int(win // 60),
                                 "basis": " or ".join(hows)},
                      "tables": [{"title": "Switches", "columns": ["from_ip", "from_network", "from_utc", "to_ip", "to_network", "to_utc", "gap", "basis"],
                                  "rows": [[a["ip"], _net(a), a["ts_utc"], b["ip"], _net(b), b["ts_utc"], human_delta(d), h]
                                           for a, b, d, h in ordered[: self.trows]],
                                  "total_rows": total}]},
                     sql=f"SELECT cite, ts_utc, ip, category FROM ev WHERE account={sq(acc)} AND ip IS NOT NULL ORDER BY ts_utc",
                     evidence=ev, priority=1 if cc else 2, sort_key=f"4{10**6 - min(total, 10**6 - 1):07d}{acc}")


def _wide_net(ip: str, ver: int) -> str:
    if ver == 4:
        return ".".join(ip.split(".")[:2])
    return ":".join(ip.split(":")[:2])


def _net(e) -> str:
    bits = []
    if e["asn"]:
        bits.append(f"AS{e['asn']}")
    if e["country"]:
        bits.append(e["country"])
    return " ".join(bits) or "no ASN data"
