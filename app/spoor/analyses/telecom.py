"""Calls, texts & cell sites: per-target profiles, and cross-references across ANY number of
telecom returns - direct contact between targets, common contacts, shared handsets/SIMs,
handset changes, and co-location (two targets served by co-located cell sites close in time).

Co-location is stated for what it is: both phones used cell sites at (almost) the same place
within a time window. Sector direction, coverage area and timing accuracy are not modelled."""
from __future__ import annotations

import collections
import csv
import math
import os

from ..findings import plural
from ..telecom import km
from ..util import fmt_num
from .base import T, Analysis, human_delta, sq


def _minutes(sec) -> str:
    return f"{round((sec or 0) / 60, 1):,.1f}"


class Telecom(Analysis):
    module = "telecom"
    category = "Calls, texts & cell sites"

    def run(self):
        if not (self.one("SELECT COUNT(*) FROM tel") or 0):
            return
        self.targets = [r["target"] for r in self.q(
            "SELECT target, COUNT(*) AS n FROM tcore WHERE target IS NOT NULL GROUP BY target ORDER BY n DESC, target")]
        self.tset = set(self.targets)
        self.msg("data quality")
        self.quality()
        self.msg("target profiles")
        self.profiles()
        self.msg("direct contact between targets")
        self.direct()
        self.msg("common contacts")
        self.common()
        self.msg("shared and changed handsets / SIMs")
        self.devices()
        self.msg("co-location")
        self.colocation()
        self.msg("tower dumps")
        self.dumps()
        self.msg("contact chains")
        self.paths()
        self.msg("telecom exports and KML")
        self.exports()

    # ------------------------------------------------------------ helpers
    def tcount(self, where: str, args=()) -> int:
        return self.one(f"SELECT COUNT(*) FROM tcore WHERE {where}", args) or 0

    def first_last(self, where: str, args=()):
        f = self.one(f"SELECT event_id FROM tcore WHERE {where} ORDER BY ts_epoch IS NULL, ts_epoch, event_id LIMIT 1", args)
        l = self.one(f"SELECT event_id FROM tcore WHERE {where} ORDER BY ts_epoch IS NULL, ts_epoch DESC, event_id DESC LIMIT 1", args)
        return f, l

    def tel_sample(self, where: str, args=(), n=None):
        ids = [r[0] for r in self.con.execute(f"SELECT event_id FROM tcore WHERE {where} ORDER BY ts_epoch IS NULL, ts_epoch, event_id", args)]
        n = n or self.nsamp
        if len(ids) <= n:
            pick = ids
        else:
            step = (len(ids) - 1) / (n - 1)
            pick = [ids[round(k * step)] for k in range(n)]
        return [(e, "sample") for e in dict.fromkeys(pick)]

    # ------------------------------------------------------------ data quality
    def quality(self):
        st = self.case_meta("telecom") or {}
        n = st.get("records", 0)
        loc = st.get("located", 0)
        unl = st.get("unlocated", 0)
        reasons = st.get("unlocated_reasons") or {}
        inferred = st.get("inferred_targets") or {}
        bits = [f"{plural(n, 'telecom record')} read" + (
            f" for {plural(len(self.targets), 'target')} ({', '.join(self.targets[:12])}{' ...' if len(self.targets) > 12 else ''})."
            if self.targets else " (tower dumps only - no target numbers).")]
        bits.append(f"{plural(loc, 'record')} have cell-site coordinates" + (f"; {plural(unl, 'record')} do not ("
                    + "; ".join(f"{k}: {fmt_num(v)}" for k, v in sorted(reasons.items(), key=lambda kv: -kv[1])) + ")" if unl else "") + ".")
        if st.get("tower_rows"):
            bits.append(f"{plural(st['tower_rows'], 'cell-site row')} read from tower lists.")
        if st.get("cross_folder_matches"):
            bits.append(f"{plural(st['cross_folder_matches'], 'record')} were located from a tower list in a different folder "
                        f"(cell ID match only).")
        lib = st.get("library") or {}
        if lib.get("matched"):
            bits.append(f"{plural(lib['matched'], 'record')} were located from the reference cell-site library ("
                        + ", ".join(f"{k}: {fmt_num(v)}" for k, v in sorted(lib.get("by_carrier", {}).items()))
                        + f"; {plural(len(lib.get('files_used') or []), 'list')}): these lists did not come with the return - "
                        f"check that the list's date covers the record dates and that the carrier is right"
                        + (f"; {fmt_num(lib['no_carrier_agreed'])} of them had no known carrier and were placed only because "
                           f"every library list naming the cell agrees" if lib.get("no_carrier_agreed") else "") + ".")
        if st.get("conflicts"):
            bits.append(f"{plural(len(st['conflicts']), 'cell ID')} have different coordinates in different tower lists and were not located.")
        for lab, v in sorted(inferred.items()):
            bits.append(f"Source {lab}: target {v['target']} was inferred from the data (it is on one end of nearly every record) - verify.")
        if st.get("no_target"):
            bits.append(f"{plural(st['no_target'], 'record')} have no target number; set the account or default account for that source.")
        if st.get("neither_end_target"):
            bits.append(f"{plural(st['neither_end_target'], 'record')} of a target's line name two other numbers (typically a "
                        f"call forwarded by the target's line, e.g. to voicemail); they are kept without a direction.")
        fn = st.get("filename_targets") or {}
        for lab, v in sorted(fn.items()):
            bits.append(f"Source {lab}: target {v['target']} taken from the file name (carriers name call-record files after "
                        f"the target) - verify against the return.")
        for imsi, v in sorted((st.get("imsi_targets") or {}).items()):
            if v.get("number"):
                bits.append(f"Records requested by IMSI {imsi} are filed under {v['number']}: that IMSI appears in "
                            f"{plural(v['records'], 'call record')} of {v['number']} ({self.cite(v['event_id'])}).")
            else:
                bits.append(f"IMSI {imsi} appears with several numbers ({', '.join(v.get('candidates') or [])}); its records "
                            f"are kept under the IMSI.")
        if st.get("imei_sci") or st.get("imsi_sci"):
            bits.append(f"{plural(st.get('imei_sci', 0) + st.get('imsi_sci', 0), 'IMEI/IMSI value')} are in scientific notation "
                        f"(e.g. 3.5E+14): a spreadsheet damaged them before they reached Spoor, so they are not used - "
                        f"use the carrier's original file.")
        if st.get("fwd_legs"):
            bits.append(f"{plural(st['fwd_legs'], 'forwarded-call leg')} (e.g. Verizon 'MF') duplicate another record of the "
                        f"same call; they are in the export but not counted as contacts.")
        if st.get("multi_cell"):
            bits.append(f"{plural(st['multi_cell'], 'record')} list several cells (AT&T CellLocation); the first listed is used.")
        sk = st.get("src_kinds") or {}
        if sk.get("ta") or sk.get("ping"):
            bits.append(f"{plural(sk.get('ta', 0) + sk.get('ping', 0), 'location estimate')} (timing advance: "
                        f"{fmt_num(sk.get('ta', 0))}, pings: {fmt_num(sk.get('ping', 0))}) carry the carrier's estimate of "
                        f"the device position; they are drawn separately from cell sites.")
        dsrc = st.get("dump_sources") or {}
        if dsrc:
            bits.append(f"{plural(sk.get('dump', 0), 'record')} come from tower dumps ({', '.join(sorted(dsrc))}): they are about "
                        f"every phone on the dumped towers and are reported in the tower-dump findings, not as targets.")
        prio = 1 if (inferred or st.get("conflicts") or st.get("no_target") or fn or st.get("imei_sci")
                     or lib.get("matched")) else 2
        self.add("telecom_quality", "Telecom records: how they were read", " ".join(bits),
                 {"values": {"records": n, "targets": self.targets[:50], "target_count": len(self.targets), "located": loc,
                             "unlocated": unl, "unlocated_reasons": reasons, "tower_rows": st.get("tower_rows", 0),
                             "cross_folder_matches": st.get("cross_folder_matches", 0),
                             "inferred_targets": inferred, "no_target": st.get("no_target", 0),
                             "neither_end_target": st.get("neither_end_target", 0), "filename_targets": fn,
                             "imsi_targets": st.get("imsi_targets") or {}, "imei_sci": st.get("imei_sci", 0),
                             "fwd_legs": st.get("fwd_legs", 0), "src_kinds": sk, "dump_sources": dsrc,
                             "eci_forms": st.get("eci_forms") or {}, "library": lib},
                  "tables": [{"title": "Cell IDs with conflicting coordinates", "columns": ["cell", "coordinates"],
                              "rows": [[c["cell"], "; ".join(c["coordinates"])] for c in st.get("conflicts", [])[: self.trows]],
                              "total_rows": len(st.get("conflicts", []))}] if st.get("conflicts") else []},
                 sql="SELECT source, target, COUNT(*) AS records, SUM(lat IS NOT NULL) AS located, loc_basis FROM calls "
                     "GROUP BY source, target, loc_basis ORDER BY source, target",
                 evidence=[], priority=prio, sort_key="0")

    def case_meta(self, key):
        from .. import db as dbm
        return dbm.get_meta(self.con, key)

    # ------------------------------------------------------------ per target
    def profiles(self):
        ntop = int(self.p.get("tel_top_contacts", 10))
        for t in self.targets[: self.max]:
            # usage counts come from call/text/data records; timing-advance and ping reports are location estimates
            agg = self.q("SELECT COUNT(*) AS n, SUM(kind='voice') AS v, SUM(kind IN ('sms','mms','rcs')) AS s, SUM(kind='data') AS d, "
                         "SUM(dir='out') AS o, SUM(dir='in') AS i, COUNT(DISTINCT other) AS c, MIN(ts_utc) AS f, MAX(ts_utc) AS l, "
                         "SUM(CASE WHEN kind='voice' THEN duration_s END) AS secs, COUNT(DISTINCT cell) AS cells, "
                         "COUNT(DISTINCT source_id) AS srcs FROM tcore WHERE target=? AND src_kind='cdr'", (t,))[0]
            est = {k: n for k, n in self.con.execute("SELECT src_kind, COUNT(*) FROM tcore WHERE target=? AND src_kind IN ('ta','ping') "
                                                     "GROUP BY src_kind", (t,))}
            top = self.q("SELECT other, COUNT(*) AS n, SUM(kind='voice') AS v, SUM(kind IN ('sms','mms','rcs')) AS s, "
                         "SUM(CASE WHEN kind='voice' THEN duration_s END) AS secs, SUM(dir='out') AS o, SUM(dir='in') AS i, "
                         "MIN(ts_utc) AS f, MAX(ts_utc) AS l FROM tcore WHERE target=? AND other IS NOT NULL "
                         "GROUP BY other ORDER BY n DESC, other LIMIT ?", (t, max(ntop, self.trows)))
            imeis = [r[0] for r in self.con.execute("SELECT DISTINCT imei FROM tcore WHERE target=? AND imei IS NOT NULL ORDER BY 1", (t,))]
            imsis = [r[0] for r in self.con.execute("SELECT DISTINCT imsi FROM tcore WHERE target=? AND imsi IS NOT NULL ORDER BY 1", (t,))]
            srcs = self.labels(r[0] for r in self.con.execute("SELECT DISTINCT source_id FROM tcore WHERE target=?", (t,)))
            stmt = (f"Target {t} ({srcs}): {plural(agg['n'], 'record')} from {T(agg['f'])} to {T(agg['l'])} - "
                    f"{plural(agg['v'] or 0, 'call')} ({_minutes(agg['secs'])} minutes), {plural(agg['s'] or 0, 'text')}, "
                    f"{plural(agg['d'] or 0, 'data session')}; {fmt_num(agg['o'] or 0)} outgoing and {fmt_num(agg['i'] or 0)} incoming; "
                    f"{plural(agg['c'], 'distinct other number')} and {plural(agg['cells'], 'distinct cell')}.")
            if est:
                stmt += (" Also " + " and ".join(f"{plural(n, 'timing-advance location estimate' if k == 'ta' else 'ping location estimate')}"
                                                 for k, n in sorted(est.items())) + ".")
            if top:
                stmt += " Most frequent: " + "; ".join(f"{x['other']} ({plural(x['n'], 'record')})" for x in top[:5]) + "."
            if imeis:
                stmt += f" {plural(len(imeis), 'IMEI')}: {', '.join(imeis[:6])}."
            ev = []
            f, l = self.first_last("target=?", (t,))
            ev += [(f, "first"), (l, "last")]
            for x in top[:5]:
                e = self.one("SELECT event_id FROM tcore WHERE target=? AND other=? ORDER BY ts_epoch IS NULL, ts_epoch, event_id LIMIT 1",
                             (t, x["other"]))
                ev.append((e, "contact"))
            self.add("telecom_target", f"Target {t}: calls, texts and contacts", stmt,
                     {"values": {"target": t, "records": agg["n"], "calls": agg["v"] or 0, "texts": agg["s"] or 0,
                                 "data_sessions": agg["d"] or 0, "outgoing": agg["o"] or 0, "incoming": agg["i"] or 0,
                                 "call_minutes": round((agg["secs"] or 0) / 60, 1), "contacts": agg["c"], "cells": agg["cells"],
                                 "first_utc": agg["f"], "last_utc": agg["l"], "sources": srcs, "imeis": imeis[:20], "imsis": imsis[:20],
                                 "timing_advance_estimates": est.get("ta", 0), "ping_estimates": est.get("ping", 0),
                                 "top": [[x["other"], x["n"]] for x in top[:ntop]]},
                      "tables": [{"title": "Most frequent other numbers",
                                  "columns": ["other", "records", "calls", "texts", "call_minutes", "outgoing", "incoming", "first_utc", "last_utc"],
                                  "rows": [[x["other"], x["n"], x["v"], x["s"], round((x["secs"] or 0) / 60, 1), x["o"], x["i"], x["f"], x["l"]]
                                           for x in top[: max(ntop, self.trows)]], "total_rows": agg["c"]}]},
                     sql=(f"SELECT other, COUNT(*) AS records, SUM(kind='voice') AS calls, SUM(kind IN ('sms','mms','rcs')) AS texts, "
                          f"MIN(ts_utc), MAX(ts_utc) FROM ccore WHERE target={sq(t)} AND other IS NOT NULL GROUP BY other ORDER BY records DESC"
                          if top else f"SELECT cite, ts_utc, src_kind, kind, cell FROM ccore WHERE target={sq(t)} ORDER BY ts_utc"),
                     evidence=ev, priority=2, sort_key=f"5{10**9 - agg['n']:010d}{t}", export="exports/telecom_contacts.csv")

    # ------------------------------------------------------------ target <-> target
    def direct(self):
        if len(self.targets) < 2:
            return
        ph = ",".join("?" * len(self.targets))
        pairs = self.q(f"SELECT target, other, COUNT(*) AS n, SUM(kind='voice') AS v, SUM(kind IN ('sms','mms','rcs')) AS s, "
                       f"MIN(ts_utc) AS f, MAX(ts_utc) AS l FROM tcore WHERE other IN ({ph}) AND target IN ({ph}) AND other != target "
                       f"GROUP BY target, other", tuple(self.targets) * 2)
        merged: dict = {}
        for p in pairs:
            k = tuple(sorted((p["target"], p["other"])))
            m = merged.setdefault(k, {"n": 0, "v": 0, "s": 0, "f": None, "l": None, "seen_in": []})
            m["n"] += p["n"]
            m["v"] += p["v"] or 0
            m["s"] += p["s"] or 0
            m["f"] = min(x for x in (m["f"], p["f"]) if x) if (m["f"] or p["f"]) else None
            m["l"] = max(x for x in (m["l"], p["l"]) if x) if (m["l"] or p["l"]) else None
            m["seen_in"].append(f"{p['target']}'s records ({plural(p['n'], 'record')})")
        for (a, b), m in sorted(merged.items(), key=lambda kv: (-kv[1]["n"], kv[0])):
            where = "((target=? AND other=?) OR (target=? AND other=?))"
            args = (a, b, b, a)
            stmt = (f"Targets {a} and {b} were in direct contact: {plural(m['n'], 'record')} "
                    f"({plural(m['v'], 'call')}, {plural(m['s'], 'text')}) from {T(m['f'])} to {T(m['l'])}, "
                    f"seen in {' and '.join(m['seen_in'])}.")
            rows = self.q(f"SELECT event_id, ts_utc, target, other, dir, kind, duration_s, cell FROM tcore WHERE {where} "
                          f"ORDER BY ts_epoch, event_id LIMIT ?", args + (self.trows,))
            self.add("telecom_direct", f"Direct contact: {a} and {b}", stmt,
                     {"values": {"target_a": a, "target_b": b, "records": m["n"], "calls": m["v"], "texts": m["s"],
                                 "first_utc": m["f"], "last_utc": m["l"]},
                      "tables": [{"title": "Records", "columns": ["cite", "ts_utc", "target", "other", "direction", "kind", "seconds", "cell"],
                                  "rows": [[self.cite(r["event_id"]), r["ts_utc"], r["target"], r["other"], r["dir"], r["kind"], r["duration_s"], r["cell"]]
                                           for r in rows], "total_rows": m["n"]}]},
                     sql=f"SELECT cite, ts_utc, target, other, dir, kind, duration_s FROM ccore WHERE (target={sq(a)} AND other={sq(b)}) "
                         f"OR (target={sq(b)} AND other={sq(a)}) ORDER BY ts_utc",
                     evidence=self.tel_sample(where, args), priority=1, sort_key=f"1{10**9 - m['n']:010d}{a}{b}")

    def common(self):
        mint = max(2, int(self.p.get("tel_common_min_targets", 2)))
        if len(self.targets) < mint:
            return
        rows = self.q("SELECT other, target, COUNT(*) AS n, SUM(kind='voice') AS v, SUM(kind IN ('sms','mms','rcs')) AS s, "
                      "MIN(ts_utc) AS f, MAX(ts_utc) AS l, MIN(source_id) AS sid FROM tcore "
                      "WHERE other IS NOT NULL AND target IS NOT NULL GROUP BY other, target ORDER BY other, target")
        by: dict = collections.defaultdict(list)
        for r in rows:
            by[r["other"]].append(r)
        from ..contactgraph import digits
        commons = [(o, rs) for o, rs in by.items() if len(rs) >= mint and o not in self.tset and digits(o) >= 7]   # not 611, *86 ...
        commons.sort(key=lambda kv: (-len(kv[1]), -sum(r["n"] for r in kv[1]), kv[0]))
        self.common_rows = commons
        # overlap matrix across ALL targets (any number of returns at once)
        contacts = {t: set() for t in self.targets}
        for o, rs in by.items():
            if o in self.tset or digits(o) < 7:
                continue
            for r in rs:
                contacts[r["target"]].add(o)
        self.matrix = [[t] + [len(contacts[t] & contacts[u]) if t != u else len(contacts[t]) for u in self.targets] for t in self.targets]
        tmax = self.targets[:40]
        self.add("telecom_overlap", f"Shared contacts between {plural(len(self.targets), 'target')}",
                 f"{plural(len(commons), 'other number')} {'is' if len(commons) == 1 else 'are'} in contact with at least {mint} of the "
                 f"{plural(len(self.targets), 'target')}"
                 + (f"; the most widely shared is {commons[0][0]} ({plural(len(commons[0][1]), 'target')})" if commons else "")
                 + ". The table counts the other numbers each pair of targets has in common (the diagonal is each target's own count).",
                 {"values": {"targets": tmax, "common_contacts": len(commons), "min_targets": mint,
                             "most_shared": commons[0][0] if commons else None,
                             "most_shared_targets": len(commons[0][1]) if commons else 0},
                  "tables": [{"title": "Contacts in common (rows x columns)", "columns": ["target"] + tmax,
                              "rows": [r[: len(tmax) + 1] for r in self.matrix[:40]], "total_rows": len(self.matrix)}]},
                 sql="SELECT a.target AS target_a, b.target AS target_b, COUNT(DISTINCT a.other) AS shared_contacts FROM tcore a "
                     "JOIN tcore b ON a.other = b.other AND a.target < b.target WHERE a.other NOT IN (SELECT DISTINCT target FROM tcore "
                     "WHERE target IS NOT NULL) GROUP BY 1, 2 ORDER BY 3 DESC",
                 evidence=[], priority=1 if commons else 2, sort_key="2", export="exports/target_overlap.csv")
        for o, rs in commons[: self.max]:
            tl = [r["target"] for r in rs]
            stmt = (f"{o} is in contact with {plural(len(rs), 'target')}: "
                    + "; ".join(f"{r['target']} - {plural(r['n'], 'record')}, {T(r['f'])} to {T(r['l'])}" for r in rs[:12])
                    + (" ..." if len(rs) > 12 else "") + ".")
            ev = []
            for r in rs[:12]:
                f, l = self.first_last("other=? AND target=?", (o, r["target"]))
                ev += [(f, "first"), (l, "last")]
            self.add("telecom_common", f"Common contact {o}: {plural(len(rs), 'target')}", stmt,
                     {"values": {"other": o, "target_count": len(rs), "targets": tl[:50],
                                 "records": {r["target"]: r["n"] for r in rs[:50]},
                                 "first": {r["target"]: r["f"] for r in rs[:50]}, "last": {r["target"]: r["l"] for r in rs[:50]}},
                      "tables": [{"title": "By target", "columns": ["target", "records", "calls", "texts", "first_utc", "last_utc", "source"],
                                  "rows": [[r["target"], r["n"], r["v"], r["s"], r["f"], r["l"], self.labels([r["sid"]])] for r in rs[: self.trows]],
                                  "total_rows": len(rs)}]},
                     sql=f"SELECT target, COUNT(*) AS records, MIN(ts_utc), MAX(ts_utc) FROM ccore WHERE other={sq(o)} GROUP BY target ORDER BY target",
                     evidence=ev, priority=1 if len(rs) >= 3 else 2,
                     sort_key=f"3{999 - min(len(rs), 999):03d}{10**9 - sum(r['n'] for r in rs):010d}{o}",
                     export="exports/common_contacts.csv")

    # ------------------------------------------------------------ handsets and SIMs
    def devices(self):
        for col, label in (("imei", "IMEI"), ("imsi", "IMSI")):
            word = "handset" if col == "imei" else "SIM"
            shared = self.q(f"SELECT {col} AS v, COUNT(DISTINCT target) AS nt FROM tcore WHERE {col} IS NOT NULL AND target IS NOT NULL "
                            f"GROUP BY {col} HAVING nt >= 2 ORDER BY nt DESC, v")
            for s in shared[: self.max]:
                per = self.q(f"SELECT target, COUNT(*) AS n, MIN(ts_utc) AS f, MAX(ts_utc) AS l, MIN(ts_epoch) AS fe FROM tcore "
                             f"WHERE {col}=? GROUP BY target ORDER BY fe, target", (s["v"],))
                stmt = (f"{label} {s['v']} appears on {plural(len(per), 'target')}: "
                        + "; ".join(f"{p['target']} from {T(p['f'])} to {T(p['l'])} ({plural(p['n'], 'record')})" for p in per[:10]) + ".")
                if len(per) >= 2 and per[0]["l"] and per[1]["f"] and per[0]["l"] < per[1]["f"]:
                    stmt += f" The periods do not overlap: the {word} was last seen with {per[0]['target']} before it was first seen with {per[1]['target']}."
                ev = []
                for p in per[:10]:
                    f, l = self.first_last(f"{col}=? AND target=?", (s["v"], p["target"]))
                    ev += [(f, "first"), (l, "last")]
                self.add(f"telecom_shared_{col}", f"{label} {s['v']} used by {plural(len(per), 'target')}", stmt,
                         {"values": {col: s["v"], "targets": [p["target"] for p in per], "target_count": len(per),
                                     "periods": [[p["target"], p["f"], p["l"], p["n"]] for p in per]},
                          "tables": [{"title": "By target", "columns": ["target", "records", "first_utc", "last_utc"],
                                      "rows": [[p["target"], p["n"], p["f"], p["l"]] for p in per]}]},
                         sql=f"SELECT target, COUNT(*), MIN(ts_utc), MAX(ts_utc) FROM ccore WHERE {col}={sq(s['v'])} GROUP BY target",
                         evidence=ev, priority=1, sort_key=f"4{9 - min(len(per), 9)}{s['v']}")
            for t in self.targets:
                per = self.q(f"SELECT {col} AS v, COUNT(*) AS n, MIN(ts_utc) AS f, MAX(ts_utc) AS l, MIN(ts_epoch) AS fe FROM tcore "
                             f"WHERE target=? AND {col} IS NOT NULL GROUP BY {col} ORDER BY fe, v", (t,))
                if len(per) < 2:
                    continue
                seq = []
                for a, b in zip(per, per[1:]):
                    if a["l"] and b["f"] and a["l"] < b["f"]:
                        seq.append(f"{a['v']} last seen {T(a['l'])}, {b['v']} first seen {T(b['f'])}")
                    else:
                        seq.append(f"{a['v']} and {b['v']} used in overlapping periods")
                stmt = (f"Target {t} used {plural(len(per), label)}: "
                        + "; ".join(f"{p['v']} ({plural(p['n'], 'record')}, {T(p['f'])} to {T(p['l'])})" for p in per[:10]) + ". "
                        + "Changes: " + "; ".join(seq[:9]) + ".")
                ev = []
                for p in per[:10]:
                    f, l = self.first_last(f"target=? AND {col}=?", (t, p["v"]))
                    ev += [(f, "first"), (l, "last")]
                self.add(f"telecom_{col}_change", f"Target {t}: {plural(len(per), label)} ({word} change)", stmt,
                         {"values": {"target": t, label.lower() + "s": [p["v"] for p in per],
                                     "periods": [[p["v"], p["f"], p["l"], p["n"]] for p in per]},
                          "tables": [{"title": f"{label}s in time order", "columns": [col, "records", "first_utc", "last_utc"],
                                      "rows": [[p["v"], p["n"], p["f"], p["l"]] for p in per]}]},
                         sql=f"SELECT {col}, COUNT(*), MIN(ts_utc), MAX(ts_utc) FROM ccore WHERE target={sq(t)} GROUP BY {col} ORDER BY 3",
                         evidence=ev, priority=2, sort_key=f"6{t}{col}")

    # ------------------------------------------------------------ co-location
    def colocation(self):
        if len(self.targets) < 2:
            return
        win = float(self.p.get("tel_coloc_window_min", 15)) * 60
        dmax = float(self.p.get("tel_same_site_km", 0.1))
        rows = self.con.execute(
            "SELECT t.event_id, t.target, t.ts_epoch, t.ts_utc, t.lat, t.lon, t.cell, t.azimuth, t.site_name, s.path "
            "FROM tcore t JOIN sources s ON s.id = t.source_id WHERE t.target IS NOT NULL AND t.ts_epoch IS NOT NULL "
            "AND t.event_id NOT IN (SELECT id FROM events WHERE ts_flag LIKE '%date_order_assumed%') "
            "AND length(t.ts_utc) > 10 AND (t.lat IS NOT NULL OR t.cell IS NOT NULL) ORDER BY t.ts_epoch, t.event_id")
        recent = collections.deque()
        # occasions are built as matches arrive (in time order), so two phones that are together for weeks
        # cost one entry per occasion, not one per pair of records
        episodes: dict = collections.defaultdict(list)
        label_eps: dict = collections.defaultdict(list)   # same cell label, no coordinates: NOT co-location
        for r in rows:
            while recent and r["ts_epoch"] - recent[0]["ts_epoch"] > win:
                recent.popleft()
            rd = dict(r)
            for q in recent:
                if q["target"] == rd["target"]:
                    continue
                if q["lat"] is not None and rd["lat"] is not None:
                    d = km(q["lat"], q["lon"], rd["lat"], rd["lon"])
                    if d > dmax:
                        continue
                elif q["lat"] is None and rd["lat"] is None and q["cell"] and q["cell"] == rd["cell"] \
                        and os.path.dirname(str(q["path"])) == os.path.dirname(str(rd["path"])):
                    d = None              # same cell ID in the same carrier's folder, no coordinates
                else:
                    continue
                a, b = (q, rd) if q["target"] < rd["target"] else (rd, q)
                m = (q["ts_epoch"], rd["ts_epoch"] - q["ts_epoch"], d, a, b)
                eps = (episodes if d is not None else label_eps)[(a["target"], b["target"])]
                if eps and m[0] - eps[-1]["end"] <= win:
                    e = eps[-1]
                    e["end"] = max(e["end"], m[0] + m[1])
                    e["n"] += 1
                    if m[1] < e["best"][1]:
                        e["best"] = m
                else:
                    eps.append({"start": m[0], "end": m[0] + m[1], "n": 1, "best": m})
            recent.append(rd)
        self.coloc = sorted(((ta, tb, eps) for (ta, tb), eps in episodes.items()), key=lambda x: (-len(x[2]), x[0], x[1]))
        for ta, tb, eps in self.coloc[: self.max]:
            best = min(eps, key=lambda e: e["best"][1])["best"]
            _s, gap, d, a, b = best
            dist = "at the same coordinates" if round(d * 1000) == 0 else f"{int(round(d * 1000))} m apart"
            first, last = eps[0]["best"], eps[-1]["best"]
            t_first = min(first[3]["ts_utc"], first[4]["ts_utc"])
            t_last = min(last[3]["ts_utc"], last[4]["ts_utc"])
            stmt = (f"Targets {ta} and {tb} used cell sites at the same location (within {int(dmax * 1000)} m) within "
                    f"{int(win // 60)} minutes of each other on {plural(len(eps), 'occasion')}"
                    + (f", first {T(t_first)}, last {T(t_last)}" if len(eps) > 1 else f", {T(t_first)}") + f". Closest in time: {a['target']} at {T(a['ts_utc'])} on cell {a['cell']} and "
                    f"{b['target']} at {T(b['ts_utc'])} on cell {b['cell']}, {human_delta(gap)} apart, sites {dist}. "
                    f"This shows both phones were served by co-located cell sites; it does not show the users were together.")
            table = []
            ev = [(a["event_id"], "closest co-location"), (b["event_id"], "closest co-location")]
            occ_ids = []
            for e in eps[: self.trows]:
                _s2, g2, d2, a2, b2 = e["best"]
                sect = ""
                if a2["azimuth"] is not None and b2["azimuth"] is not None:
                    diff = abs((a2["azimuth"] - b2["azimuth"] + 180) % 360 - 180)
                    sect = "same azimuth" if diff < 1 else f"azimuths {fmt_num(a2['azimuth'])} / {fmt_num(b2['azimuth'])}"
                table.append([a2["ts_utc"], self.cite(a2["event_id"]), a2["cell"], b2["ts_utc"], self.cite(b2["event_id"]), b2["cell"],
                              human_delta(g2), "" if d2 is None else int(round(d2 * 1000)), a2["site_name"] or b2["site_name"] or "",
                              sect, e["n"]])
                occ_ids.append([a2["event_id"], b2["event_id"]])
                if len(ev) < self.nsamp * 2:
                    ev += [(a2["event_id"], "co-location"), (b2["event_id"], "co-location")]
            self.add("telecom_colocation", f"Co-location: {ta} and {tb} ({plural(len(eps), 'occasion')})", stmt,
                     {"values": {"target_a": ta, "target_b": tb, "occasions": len(eps), "window_min": int(win // 60),
                                 "distance_m": int(dmax * 1000), "closest": human_delta(gap), "closest_seconds": round(gap),
                                 "closest_a": a["target"], "closest_ts_a": a["ts_utc"], "closest_cell_a": a["cell"],
                                 "closest_b": b["target"], "closest_ts_b": b["ts_utc"], "closest_cell_b": b["cell"],
                                 "closest_distance_m": None if d is None else int(round(d * 1000)),
                                 "first_utc": t_first, "last_utc": t_last},
                      "tables": [{"title": "Occasions (closest pair of records in each)",
                                  "columns": ["ts_a", "cite_a", "cell_a", "ts_b", "cite_b", "cell_b", "apart", "site_distance_m", "site",
                                              "sectors", "record_pairs"],
                                  "rows": table, "total_rows": len(eps)}], "occasion_ids": occ_ids},
                     # reproduce-SQL: a lat/lon box slightly larger than the distance limit (the table above is exact)
                     sql=(f"SELECT ea.cite AS cite_a, a.ts_utc AS ts_a, a.cell AS cell_a, eb.cite AS cite_b, b.ts_utc AS ts_b, b.cell AS cell_b "
                          f"FROM tcore a JOIN tcore b ON b.target={sq(tb)} AND b.ts_epoch BETWEEN a.ts_epoch - {int(win)} AND a.ts_epoch + {int(win)} "
                          f"AND ((a.lat IS NOT NULL AND b.lat IS NOT NULL AND ABS(a.lat - b.lat) <= {dmax / 111.0:.5f} "
                          f"AND ABS(a.lon - b.lon) <= {dmax / (111.0 * math.cos(math.radians(min(abs(a['lat'] or 0), 80)))):.5f})) "
                          f"JOIN ev ea ON ea.id = a.event_id "
                          f"JOIN ev eb ON eb.id = b.event_id WHERE a.target={sq(ta)} AND length(a.ts_utc) > 10 ORDER BY a.ts_epoch, b.ts_epoch"),
                     evidence=ev, priority=1, sort_key=f"0{999 - min(len(eps), 999):03d}{ta}{tb}", export="exports/colocation.csv")
        # the same cell label without coordinates: reported apart, as a weaker note, never as co-location
        for (ta, tb), eps in sorted(label_eps.items(), key=lambda kv: (-len(kv[1]), kv[0]))[: self.max]:
            best = min(eps, key=lambda e: e["best"][1])["best"]
            _s, gap, _d, a, b = best
            cells = sorted({e["best"][3]["cell"] for e in eps})
            t_first = min(eps[0]["best"][3]["ts_utc"], eps[0]["best"][4]["ts_utc"])
            stmt = (f"Targets {ta} and {tb} both appear on cell label{'s' if len(cells) > 1 else ''} {', '.join(cells[:6])} within "
                    f"{int(win // 60)} minutes of each other on {plural(len(eps), 'occasion')} (first {T(t_first)}; closest {human_delta(gap)} apart), "
                    f"in records of the same carrier folder that carry no coordinates. A cell label alone does not say where the cell is - "
                    f"carriers reuse labels across markets - so this is NOT co-location; add the carrier's tower list to place the cells.")
            self.add("telecom_same_cell", f"Same cell label, no coordinates: {ta} and {tb}", stmt,
                     {"values": {"target_a": ta, "target_b": tb, "occasions": len(eps), "cells": cells[:20], "window_min": int(win // 60),
                                 "closest": human_delta(gap), "first_utc": t_first}},
                     sql=(f"SELECT ea.cite AS cite_a, a.ts_utc AS ts_a, a.cell, eb.cite AS cite_b, b.ts_utc AS ts_b FROM tcore a JOIN tcore b "
                          f"ON b.target={sq(tb)} AND b.cell = a.cell AND b.lat IS NULL AND b.ts_epoch BETWEEN a.ts_epoch - {int(win)} AND a.ts_epoch + {int(win)} "
                          f"JOIN ev ea ON ea.id = a.event_id JOIN ev eb ON eb.id = b.event_id "
                          f"WHERE a.target={sq(ta)} AND a.lat IS NULL AND length(a.ts_utc) > 10 ORDER BY a.ts_epoch"),
                     evidence=[(a["event_id"], "same cell label"), (b["event_id"], "same cell label")], priority=2,
                     sort_key=f"0z{ta}{tb}")

    # ------------------------------------------------------------ tower dumps
    def dumps(self):
        """Tower dumps from any number of carriers and places: records are grouped into scenes by time (a gap of
        more than tel_scene_gap_hours starts a new scene), then phones and handsets seen at 2+ scenes are listed,
        and dump phones that are targets or contacts of targets in the call-record returns."""
        rows = self.q("SELECT t.event_id, t.target, t.ts_epoch, t.ts_utc, t.source_id, COALESCE(t.section,'') AS section, t.imei, "
                      "t.lat IS NOT NULL AS loc FROM tel t WHERE t.src_kind='dump' AND t.ts_epoch IS NOT NULL AND length(t.ts_utc) > 10 "
                      "AND t.target IS NOT NULL ORDER BY t.ts_epoch, t.event_id")
        if not rows:
            return
        gap = float(self.p.get("tel_scene_gap_hours", 3)) * 3600
        scenes: list = []
        for r in rows:
            if not scenes or r["ts_epoch"] - scenes[-1]["end"] > gap:
                scenes.append({"start": r["ts_epoch"], "end": r["ts_epoch"], "first": r["ts_utc"], "rows": []})
            sc = scenes[-1]
            sc["end"], sc["last"] = r["ts_epoch"], r["ts_utc"]
            sc["rows"].append(r)
        disp = {x["id"]: (x["label"], x["display"].replace("\\", "/").split("/")[-1]) for x in self.q("SELECT id, label, display FROM sources")}
        for k, sc in enumerate(scenes, 1):
            srcs = collections.OrderedDict()
            for r in sc["rows"]:
                lab, fn = disp.get(r["source_id"], ("?", "?"))
                key = f"{lab} {fn}" + (f" ({r['section'][:90]})" if r["section"] else "")
                srcs[key] = srcs.get(key, 0) + 1
            sc["no"], sc["sources"] = k, srcs
            sc["phones"] = {r["target"] for r in sc["rows"]}
            stmt = (f"Tower-dump scene {k}: {plural(len(sc['rows']), 'record')} from {T(sc['first'])} to {T(sc['last'])}, "
                    f"{plural(len(sc['phones']), 'different phone')}, from {plural(len(srcs), 'dump')}: "
                    + "; ".join(f"{n} ({fmt_num(c)})" for n, c in list(srcs.items())[:8]) + ".")
            self.add("telecom_dump_scene", f"Tower-dump scene {k}: {plural(len(sc['phones']), 'phone')}", stmt,
                     {"values": {"scene": k, "records": len(sc["rows"]), "phones": len(sc["phones"]), "first_utc": sc["first"],
                                 "last_utc": sc["last"], "dumps": list(srcs)[:20]},
                      "tables": [{"title": "Dumps in this scene", "columns": ["dump", "records"],
                                  "rows": [[n, c] for n, c in srcs.items()]}]},
                     sql=f"SELECT cite, ts_utc, target AS phone, other, kind, cell, source, section FROM calls WHERE src_kind='dump' "
                         f"AND ts_utc BETWEEN '{sc['first']}' AND '{sc['last']}' ORDER BY ts_utc",
                     evidence=[(sc["rows"][0]["event_id"], "first"), (sc["rows"][-1]["event_id"], "last")],
                     priority=2, sort_key=f"8{k:03d}")
        # phones and handsets at 2+ scenes
        by_phone: dict = collections.defaultdict(lambda: collections.defaultdict(list))
        by_imei: dict = collections.defaultdict(lambda: collections.defaultdict(list))
        for sc in scenes:
            for r in sc["rows"]:
                by_phone[r["target"]][sc["no"]].append(r)
                if r["imei"]:
                    by_imei[r["imei"]][sc["no"]].append(r)
        multi = sorted(((ph, scs) for ph, scs in by_phone.items() if len(scs) >= 2), key=lambda x: (-len(x[1]), x[0]))
        self.dump_multi = multi
        for ph, scs in multi[: self.max]:
            parts, ev, table = [], [], []
            for no, rs in sorted(scs.items()):
                srcset = sorted({disp.get(r["source_id"], ("?", "?"))[0] for r in rs})
                parts.append(f"scene {no}: {plural(len(rs), 'record')} {T(rs[0]['ts_utc'])} to {T(rs[-1]['ts_utc'])} ({', '.join(srcset)})")
                ev += [(rs[0]["event_id"], f"scene {no} first"), (rs[-1]["event_id"], f"scene {no} last")]
                table.append([no, len(rs), rs[0]["ts_utc"], rs[-1]["ts_utc"], ", ".join(srcset), self.cite(rs[0]["event_id"])])
            imeis = sorted({r["imei"] for rs in scs.values() for r in rs if r["imei"]})
            stmt = (f"Phone {ph} is in the tower dumps of {plural(len(scs), 'scene')}: " + "; ".join(parts) + "."
                    + (f" IMEI (first 14 digits): {', '.join(imeis[:4])}." if imeis else "")
                    + " A tower-dump record shows the phone used one of the dumped cells in that window; it does not place "
                      "the phone at a particular address.")
            self.add("telecom_dump_multi", f"{ph}: in tower dumps at {plural(len(scs), 'scene')}", stmt,
                     {"values": {"phone": ph, "scenes": sorted(scs), "scene_count": len(scs), "imeis": imeis[:10],
                                 "records": {str(no): len(rs) for no, rs in scs.items()}},
                      "tables": [{"title": "By scene", "columns": ["scene", "records", "first_utc", "last_utc", "sources", "first_cite"],
                                  "rows": table}]},
                     sql=f"SELECT cite, ts_utc, target AS phone, other, kind, cell, imei, source, section FROM calls "
                         f"WHERE src_kind='dump' AND target={sq(ph)} ORDER BY ts_utc",
                     evidence=ev, priority=1, sort_key=f"7{999 - len(scs):03d}{ph}", export="exports/tower_dump_phones.csv")
        for imei, scs in sorted(by_imei.items()):
            phones = sorted({r["target"] for rs in scs.values() for r in rs})
            if len(scs) >= 2 and len(phones) >= 2:
                ev = [(rs[0]["event_id"], f"scene {no}") for no, rs in sorted(scs.items())]
                self.add("telecom_dump_imei", f"Handset {imei}: {plural(len(scs), 'scene')}, {plural(len(phones), 'number')}",
                         f"Handset IMEI {imei} (first 14 digits) is in the tower dumps of {plural(len(scs), 'scene')} under "
                         f"{plural(len(phones), 'different number')}: {', '.join(phones[:8])}.",
                         {"values": {"imei": imei, "scenes": sorted(scs), "phones": phones[:20]}},
                         sql=f"SELECT cite, ts_utc, target AS phone, imei, source FROM calls WHERE src_kind='dump' AND imei={sq(imei)} ORDER BY ts_utc",
                         evidence=ev, priority=1, sort_key=f"7{imei}")
        # dump phones that are targets or contacts of targets
        if self.targets:
            ph_t = sorted(set(by_phone) & self.tset)
            contacts: dict = collections.defaultdict(set)
            for r in self.q("SELECT DISTINCT other, target FROM tcore WHERE other IS NOT NULL"):
                contacts[r["other"]].add(r["target"])
            ph_c = sorted(ph for ph in by_phone if ph in contacts and ph not in self.tset)
            for ph in ph_t + ph_c:
                scs = by_phone[ph]
                rs = [r for x in scs.values() for r in x]
                who = ("is itself a target" if ph in self.tset else
                       f"is a contact of {plural(len(contacts[ph]), 'target')} ({', '.join(sorted(contacts[ph])[:6])})")
                ev = [(rs[0]["event_id"], "in dump")]
                if ph not in self.tset:
                    e2 = self.one("SELECT event_id FROM tcore WHERE other=? ORDER BY ts_epoch LIMIT 1", (ph,))
                    ev.append((e2, "contact"))
                self.add("telecom_dump_target", f"{ph}: in a tower dump and {'a target' if ph in self.tset else 'a contact of a target'}",
                         f"Phone {ph} {who} and appears in the tower dumps of {plural(len(scs), 'scene')} "
                         f"({plural(len(rs), 'record')}, first {T(rs[0]['ts_utc'])}).",
                         {"values": {"phone": ph, "is_target": ph in self.tset, "targets": sorted(contacts.get(ph, ()))[:20],
                                     "scenes": sorted(scs), "records": len(rs)}},
                         sql=f"SELECT cite, ts_utc, target, other, src_kind, source FROM calls WHERE target={sq(ph)} OR other={sq(ph)} ORDER BY ts_utc",
                         evidence=ev, priority=1, sort_key=f"7{ph}")

    # ------------------------------------------------------------ contact chains ("degrees of separation")
    def _chain_facts(self, g, res, cites):
        from ..contactgraph import node_label
        tables, ev, chains = [], [], []
        for pr in res["pairs"]:
            for i, p in enumerate(pr["paths"][: self.nsamp]):
                hops = []
                for x, y in zip(p, p[1:]):
                    e = g.edges[g._k(x, y)]
                    hops.append([node_label(x), node_label(y), e["n"], e["first"], e["last"], ", ".join(sorted(e["returns"])),
                                 cites.get(e["first_id"]), cites.get(e["last_id"])])
                    if i == 0:
                        ev.append((e["first_id"], f"{node_label(x)} - {node_label(y)}"))
                chains.append({"a": pr["a"], "b": pr["b"], "chain": [node_label(n) for n in p]})
                tables.append({"title": f"{node_label(pr['a'])} to {node_label(pr['b'])}, chain {i + 1}: " + " - ".join(node_label(n) for n in p),
                               "columns": ["from", "to", "records", "first_utc", "last_utc", "returns", "first_cite", "last_cite"], "rows": hops})
        return tables, list(dict.fromkeys(ev)), chains

    def paths(self):
        from ..contactgraph import Graph, node_label
        maxh = int(self.p.get("tel_path_max_hops", 6))
        sets = [s for s in (self.p.get("tel_link_sets") or []) if isinstance(s, dict) and len(s.get("members") or []) >= 2]
        if len(self.targets) < 2 and not sets and not self.one("SELECT COUNT(*) FROM tel WHERE src_kind='dump'"):
            return
        g = Graph(self.con, self.p, dumps=True, devices=False)
        sql_edges = ("SELECT cite, ts_utc, target, other, kind, ret, src_kind FROM calls WHERE COALESCE(dir,'') != 'fwd' "
                     "AND target IS NOT NULL AND other IS NOT NULL ORDER BY ts_utc")
        # every pair of targets: how many hops apart
        if len(self.targets) >= 2:
            res = g.connect(self.targets, maxh, 0, 10)
            matrix = []
            for pr in res["pairs"]:
                matrix.append([pr["a"], pr["b"], pr["hops"] if pr["hops"] is not None else f"not within {maxh}", len(pr["paths"]),
                               " - ".join(pr["paths"][0]) if pr["paths"] else ""])
            linked = [pr for pr in res["pairs"] if pr["hops"] is not None]
            stmt = (f"{plural(len(res['pairs']), 'pair')} of the {len(self.targets)} target numbers: in direct contact "
                    f"{sum(1 for p in linked if p['hops'] == 1)}; with a contact in common {sum(1 for p in linked if p['hops'] == 2)}; "
                    f"linked only through a longer chain of contacts {sum(1 for p in linked if p['hops'] >= 3)}; "
                    f"not linked within {maxh} hops {len(res['pairs']) - len(linked)}.")
            if res["left_out"]:
                stmt += (f" Not used as links: {', '.join(x['node'] for x in res['left_out'][:6] if not x['node'].startswith('dump:'))}"
                         f"{' ...' if len(res['left_out']) > 6 else ''} (short codes and numbers in contact with more than {g.hub_max} others).")
            self.add("telecom_degrees", f"Contact distance between {len(self.targets)} targets", stmt,
                     {"values": {"targets": self.targets, "pairs": len(res["pairs"]), "max_hops": maxh, "hub_max": g.hub_max,
                                 "direct": sum(1 for p in linked if p["hops"] == 1), "shared_contact": sum(1 for p in linked if p["hops"] == 2),
                                 "longer": sum(1 for p in linked if p["hops"] >= 3), "not_linked": len(res["pairs"]) - len(linked),
                                 "left_out": [x["node"] for x in res["left_out"] if not x["node"].startswith("dump:")][:40]},
                      "tables": [{"title": "Pairs of targets", "columns": ["target A", "target B", "hops", "shortest chains", "first chain"], "rows": matrix}]},
                     sql=sql_edges, priority=2, sort_key="1z")
            far = sorted((pr for pr in linked if pr["hops"] >= 3), key=lambda pr: (pr["hops"], pr["a"], pr["b"]))
            for pr in far[: self.max]:
                one = {"pairs": [pr], **{k: res[k] for k in ("seeds", "max_hops", "slack")}}
                ids = [x for p in pr["paths"] for u, v in zip(p, p[1:]) for x in (g.edges[g._k(u, v)]["first_id"], g.edges[g._k(u, v)]["last_id"])]
                cites = g.cites(ids)
                tables, ev, chains = self._chain_facts(g, one, cites)
                mids = sorted({n for p in pr["paths"] for n in p[1:-1]})
                first = pr["paths"][0]
                stmt = (f"Targets {pr['a']} and {pr['b']} have no direct contact and no contact in common in these records; they are linked "
                        f"in {pr['hops']} hops: " + " - ".join(first)
                        + (f" ({plural(len(pr['paths']), 'chain')} of that length{', more not listed' if pr['more'] else ''}; numbers on them: {', '.join(mids)})"
                           if len(pr["paths"]) > 1 else "")
                        + ". Each hop is a call or text between the two numbers in the records cited; the chain does not show that "
                          "anything passed from one end to the other.")
                self.add("telecom_path", f"{pr['a']} to {pr['b']}: {pr['hops']} hops", stmt,
                         {"values": {"a": pr["a"], "b": pr["b"], "hops": pr["hops"], "chains": len(pr["paths"]), "more": pr["more"],
                                     "chain": first, "through": mids, "returns": ", ".join(sorted({r for p in pr["paths"] for u, v in zip(p, p[1:])
                                                                                                    for r in g.edges[g._k(u, v)]["returns"]}))},
                          "tables": tables}, sql=sql_edges, evidence=ev, priority=1, sort_key=f"1y{pr['hops']:02d}{pr['a']}{pr['b']}")
        # tower dumps: phones on a dump linked to a target through someone else (dump - phone - contact - ... - target)
        for dn, d in sorted(g.dumps.items()):
            for t in self.targets:
                res = g.connect([dn, t], min(maxh, 5), 0, 10)
                pr = res["pairs"][0]
                if pr["hops"] is None or pr["hops"] < 3:     # 1: the target is on the dump; 2: a dump phone is its contact (other findings)
                    continue
                ids = [x for p in pr["paths"] for u, v in zip(p, p[1:]) for x in (g.edges[g._k(u, v)]["first_id"], g.edges[g._k(u, v)]["last_id"])]
                cites = g.cites(ids)
                tables, ev, chains = self._chain_facts(g, res, cites)
                phones = sorted({p[1] for p in pr["paths"]})
                stmt = (f"{plural(len(phones), 'phone')} on tower dump {d['label']} ({', '.join(phones[:6])}) "
                        f"{'is' if len(phones) == 1 else 'are'} linked to target {t} in {pr['hops'] - 1} contact hops: "
                        + " - ".join(node_label(n) for n in pr["paths"][0][1:]) + ".")
                self.add("telecom_dump_path", f"Tower dump {d['label']} to {t}: {pr['hops'] - 1} hops", stmt,
                         {"values": {"dump": d["label"], "target": t, "hops": pr["hops"] - 1, "phones": phones, "chains": len(pr["paths"]),
                                     "chain": [node_label(n) for n in pr["paths"][0]]}, "tables": tables},
                         sql=sql_edges, evidence=ev, priority=1, sort_key=f"7y{t}{dn}")
        # saved groups (Links screen / spoor links --save)
        for k, s in enumerate(sets, 1):
            members = [m for m in (g.find(x) for x in s["members"]) if m]
            missing = [x for x in s["members"] if not g.find(x)]
            name = s.get("name") or f"group {k}"
            if len(members) < 2:
                self.add("telecom_link_set", f"Link group '{name}': not enough numbers found",
                         f"Saved link group '{name}' names {', '.join(s['members'])}; {len(members)} of them {'is' if len(members) == 1 else 'are'} in the records, so there is nothing to link.",
                         {"values": {"name": name, "members": s["members"], "missing": missing}}, sql=sql_edges, priority=2, sort_key=f"1x{k:03d}")
                continue
            hops = int(s.get("max_hops") or maxh)
            res = g.connect(members, hops, int(s.get("slack") or 0), 10)
            ids = [x for pr in res["pairs"] for p in pr["paths"] for u, v in zip(p, p[1:]) for x in (g.edges[g._k(u, v)]["first_id"], g.edges[g._k(u, v)]["last_id"])]
            cites = g.cites(ids)
            tables, ev, chains = self._chain_facts(g, res, cites)
            parts = [f"{node_label(pr['a'])} and {node_label(pr['b'])}: " + (f"{pr['hops']} hop{'s' if pr['hops'] != 1 else ''}" if pr["hops"] else f"not linked within {hops}")
                     for pr in res["pairs"]]
            through = sorted(res["through"].items(), key=lambda kv: (-len(kv[1]["pairs"]), -kv[1]["paths"], kv[0]))
            stmt = (f"Link group '{name}' ({', '.join(node_label(m) for m in members)}): " + "; ".join(parts) + "."
                    + (f" Numbers on the most chains: " + ", ".join(f"{node_label(n)} ({plural(len(v['pairs']), 'pair')})" for n, v in through[:5]) + "." if through else "")
                    + (f" Not in the records: {', '.join(missing)}." if missing else ""))
            self.add("telecom_link_set", f"Link group '{name}'", stmt,
                     {"values": {"name": name, "members": members, "missing": missing, "max_hops": hops,
                                 "pairs": [[node_label(pr["a"]), node_label(pr["b"]), pr["hops"]] for pr in res["pairs"]], "through": [node_label(n) for n, _v in through[:20]]},
                      "tables": tables[:40]}, sql=sql_edges, evidence=ev[:60], priority=1, sort_key=f"1x{k:03d}")

    # ------------------------------------------------------------ CSV exports
    def exports(self):
        out = self.case.exports_dir
        out.mkdir(parents=True, exist_ok=True)
        with open(out / "telecom_records.csv", "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["cite", "ts_utc", "target", "other", "direction", "kind", "duration_s", "cell", "cell_last", "eci", "lat",
                        "lon", "azimuth", "site_name", "location_basis", "location_cite", "imei_14", "imsi", "device_lat",
                        "device_lon", "device_confidence", "record_kind", "section", "source"])
            for r in self.con.execute("SELECT cite, ts_utc, target, other, dir, kind, duration_s, cell, cell_last, eci, lat, lon, azimuth, "
                                      "site_name, loc_basis, loc_cite, imei, imsi, dev_lat, dev_lon, dev_conf, src_kind, section, source "
                                      "FROM calls ORDER BY ts_utc, id"):
                w.writerow(list(r))
        with open(out / "telecom_contacts.csv", "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["target", "other", "records", "calls", "texts", "call_minutes", "outgoing", "incoming", "first_utc", "last_utc",
                        "other_is_target"])
            for r in self.con.execute("SELECT target, other, COUNT(*), SUM(kind='voice'), SUM(kind IN ('sms','mms','rcs')), "
                                      "ROUND(SUM(CASE WHEN kind='voice' THEN duration_s END)/60.0, 1), SUM(dir='out'), SUM(dir='in'), "
                                      "MIN(ts_utc), MAX(ts_utc) FROM tcore WHERE other IS NOT NULL GROUP BY target, other ORDER BY target, 3 DESC"):
                w.writerow(list(r) + ["yes" if r[1] in self.tset else ""])
        with open(out / "common_contacts.csv", "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["other", "target_count", "target", "records", "calls", "texts", "first_utc", "last_utc"])
            for o, rs in getattr(self, "common_rows", []):
                for r in rs:
                    w.writerow([o, len(rs), r["target"], r["n"], r["v"], r["s"], r["f"], r["l"]])
        with open(out / "target_overlap.csv", "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["target"] + self.targets)
            for row in getattr(self, "matrix", []):
                w.writerow(row)
        with open(out / "tower_dump_phones.csv", "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["phone", "scene_count", "scene", "records", "first_utc", "last_utc"])
            for ph, scs in getattr(self, "dump_multi", []):
                for no, rs in sorted(scs.items()):
                    w.writerow([ph, len(scs), no, len(rs), rs[0]["ts_utc"], rs[-1]["ts_utc"]])
        with open(out / "colocation.csv", "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["target_a", "target_b", "occasion", "ts_a", "cite_a", "cell_a", "lat_a", "lon_a", "ts_b", "cite_b", "cell_b",
                        "lat_b", "lon_b", "seconds_apart", "site_distance_m", "record_pairs"])
            for ta, tb, eps in getattr(self, "coloc", []):
                for i, e in enumerate(eps, 1):
                    _s, g, d, a, b = e["best"]
                    w.writerow([ta, tb, i, a["ts_utc"], self.cite(a["event_id"]), a["cell"], a["lat"], a["lon"], b["ts_utc"],
                                self.cite(b["event_id"]), b["cell"], b["lat"], b["lon"], round(g), "" if d is None else round(d * 1000),
                                e["n"]])
