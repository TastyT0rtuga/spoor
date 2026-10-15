"""Sources & data quality: what was read, how times were interpreted, and what could not be used."""
from __future__ import annotations

import json
from pathlib import Path

from ..findings import plural
from ..util import fmt_int
from .base import T, Analysis

FLAG_TEXT = {
    "ambiguous_dst": "fall in the repeated hour when clocks go back (first occurrence assumed)",
    "nonexistent_local_time": "fall in the skipped hour when clocks go forward (do not exist on the local clock)",
    "abbr_dst_mismatch": "carry a time-zone abbreviation that does not match daylight-saving status on that date",
    "implausible_year": "have a year before 1995 or in the future (excluded from timing analysis)",
    "two_digit_year": "use two-digit years",
    "date_only": "have a date but no time of day (excluded from hour-of-day analysis)",
    "paired_by_proximity": "were assembled by pairing an IP line with a nearby timestamp line",
}
FLAG_PRIORITY = {"ambiguous_dst": 1, "nonexistent_local_time": 1, "abbr_dst_mismatch": 1, "implausible_year": 2,
                 "two_digit_year": 2, "date_only": 3, "paired_by_proximity": 1}


class Quality(Analysis):
    module = "quality"
    category = "Sources & data quality"

    def run(self):
        for r in self.q("SELECT * FROM returns WHERE state != 'active' ORDER BY id"):
            n = self.one("SELECT COUNT(*) FROM sources WHERE return_id=? AND status != 'container'", (r["id"],)) or 0
            word = "excluded from" if r["state"] == "excluded" else "removed from"
            self.add("return_excluded", f"{r['label']} {word} this analysis",
                     f"{r['label']} ({r['name']}), {plural(n, 'file')}, was {word} this analysis by the analyst on {r['state_at']}. "
                     f"None of its records are in any finding, table, figure or count in this report; the files were not changed.",
                     {"values": {"return": r["label"], "name": r["name"], "state": r["state"], "files": n, "at": r["state_at"],
                                 "reason": r["note"] or ""}}, priority=2, sort_key=f"0{r['label']}")
        srcs = self.q("SELECT * FROM sources WHERE status != 'excluded' ORDER BY id")
        for s in srcs:
            cfg = json.loads(s["config"]) if s.get("config") else {}
            st = json.loads(s["stats"]) if s.get("stats") else {}
            name = Path(s.get("member") or s["path"]).name
            lab = s["label"]
            if s["status"] in ("error", "unsupported"):
                self.add("source_not_analysed", f"{lab} not analysed",
                         f"{lab} ({name}) was not analysed: {s.get('error') or 'file type not supported (' + str(s.get('kind')) + ')'}.",
                         {"values": {"source": lab, "file": name, "status": s["status"], "reason": s.get("error") or s.get("kind")}},
                         priority=1, sort_key=f"0{lab}")
                continue
            if s["status"] == "duplicate":
                self.add("duplicate_file", f"{lab} is a duplicate file", f"{lab} ({name}) is {s.get('error')}.",
                         {"values": {"source": lab, "file": name, "note": s.get("error")}}, priority=3, sort_key=f"9{lab}")
                continue
            if s["status"] == "skipped":
                self.add("source_skipped", f"{lab} skipped by the analyst", f"{lab} ({name}) was excluded from analysis by the analyst.",
                         {"values": {"source": lab, "file": name}}, priority=2, sort_key=f"1{lab}")
                continue
            if s["status"] != "ingested":
                continue
            rng = self.con.execute("SELECT MIN(ts_utc), MAX(ts_utc), COUNT(*) FROM events WHERE source_id=? AND ts_epoch IS NOT NULL",
                                   (s["id"],)).fetchone()
            rows = s["rows"] or 0
            tsn = st.get("ts_parsed", 0)
            failed = st.get("ts_failed", 0)
            vals = {"source": lab, "file": name, "sha256": s["sha256"], "records": rows, "timestamps_parsed": tsn,
                    "timestamps_failed": failed, "no_timestamp": st.get("ts_missing", 0), "first_utc": rng[0],
                    "last_utc": rng[1], "timezone": cfg.get("tz"), "timezone_assumed": bool(cfg.get("tz_assumed")),
                    "timezone_basis": cfg.get("tz_basis"), "kind": cfg.get("kind")}
            parts = [f"{lab} ({name}): {plural(rows, 'record')}"]
            if rows:
                parts.append(f"timestamps parsed for {fmt_int(tsn)}" + (f" ({fmt_int(failed)} could not be parsed)" if failed else ""))
            if rng[0]:
                parts.append(f"time range {T(rng[0])} to {T(rng[1])}")
            if not rows:
                parts = [f"{lab} ({name}): no lines with a timestamp, IP address or identifier were found; nothing from this file enters the analysis"]
            stmt = "; ".join(parts) + "."
            tz_txt = cfg.get("tz") or "UTC"
            n_zone = self.one("SELECT COUNT(*) FROM events WHERE source_id=? AND (tz_basis LIKE 'ASSUMED%' OR tz_basis LIKE 'source tz%')",
                              (s["id"],)) or 0
            vals["timestamps_using_source_timezone"] = n_zone
            if tsn and not n_zone:
                stmt += " Every parsed timestamp carries its own UTC offset or is an epoch value, so no timezone assumption applies."
            elif n_zone and cfg.get("tz_assumed"):
                stmt += (f" {plural(n_zone, 'timestamp')} have no offset of their own and were treated as {tz_txt}: "
                         "no timezone indicator was found (ASSUMPTION - verify with the provider).")
            elif n_zone:
                stmt += f" {plural(n_zone, 'timestamp')} have no offset of their own and were read as {tz_txt} (basis: {cfg.get('tz_basis')})."
            if cfg.get("default_account"):
                vals["default_account"] = cfg["default_account"]
                vals["default_account_basis"] = cfg.get("default_account_basis")
                stmt += f" Rows without an account were attributed to {cfg['default_account']} (basis: {cfg.get('default_account_basis')})."
            for t in cfg.get("tables", []):
                dc = t.get("default_category")
                if dc and t.get("mode") != "skip" and rows:
                    used = self.one("SELECT COUNT(*) FROM events WHERE source_id=? AND (tbl=? OR ? IS NULL) AND (action IS NULL OR category=?)",
                                    (s["id"], t.get("name"), t.get("name"), dc)) or 0
                    if used:
                        vals.setdefault("default_categories", {})[str(t.get("name"))] = dc
                        stmt += (f" Rows of '{t.get('name')}' without a recognised event type were treated as '{dc}'"
                                 f" (basis: {t.get('default_category_basis')}).")
            cites = []
            basis = cfg.get("tz_basis") or ""
            if " at " in basis and not cfg.get("tz_assumed") and n_zone:
                loc = basis.rsplit(" at ", 1)[1].split(";")[0].strip()
                if loc.startswith(lab + ":"):
                    loc = loc[len(lab) + 1:]
                txt = basis.split("'")[1] if "'" in basis else ""
                if loc and ":" not in loc[:1]:
                    cites.append({"cite": f"{lab}:{loc}", "source_id": s["id"], "loc": loc, "text": txt, "expect": txt})
            tabs = [{"table": t.get("name"), "mode": t.get("mode"),
                     "mapping": "; ".join(f"{k}<-{v}" for k, v in (t.get("mapping") or {}).items()),
                     "date_order": t.get("date_order")} for t in cfg.get("tables", []) if t.get("mode") != "skip"]
            ev = self.sample("source_id=?", (s["id"],), 4)
            self.add("source_summary", f"{lab}: {name}", stmt,
                     {"values": vals, "columns": ["table", "mode", "mapping", "date_order"],
                      "rows": [[t["table"], t["mode"], t["mapping"], t["date_order"]] for t in tabs]},
                     sql=f"SELECT * FROM ev WHERE source='{lab}' ORDER BY ts_utc",
                     evidence=ev, priority=1 if ((cfg.get("tz_assumed") and n_zone) or failed) else (3 if not rows else 2),
                     sort_key=f"2{lab}", cites=cites)
            if cfg.get("tz_assumed") and tsn:
                naive = self.one("SELECT COUNT(*) FROM events WHERE source_id=? AND tz_basis LIKE 'ASSUMED%'", (s["id"],)) or 0
                if naive:
                    self.add("tz_assumed", f"{lab}: timezone assumed",
                             f"{lab} ({name}): {plural(naive, 'timestamp')} carry no timezone and none is stated in the file; they were treated as {tz_txt}. If the provider used another zone, every time from {lab} shifts.",
                             {"values": {"source": lab, "file": name, "count": naive, "assumed_tz": tz_txt}},
                             sql=f"SELECT cite, ts_raw, ts_utc FROM ev WHERE source='{lab}' AND tz_basis LIKE 'ASSUMED%'",
                             evidence=self.sample("source_id=? AND tz_basis LIKE 'ASSUMED%'", (s["id"],), 4),
                             priority=1, sort_key=f"1{lab}a")
            if cfg.get("tz_conflicts"):
                self.add("tz_conflict", f"{lab}: conflicting timezone hints",
                         f"{lab} ({name}) contains more than one timezone hint; {tz_txt} was used ({cfg.get('tz_basis')}). Other hints: {'; '.join(cfg['tz_conflicts'][:5])}.",
                         {"values": {"source": lab, "used": tz_txt, "others": cfg["tz_conflicts"][:5]}}, priority=1, sort_key=f"1{lab}b")
            for t in cfg.get("tables", []):
                if t.get("date_order_note") and t.get("mode") != "skip":
                    n_num = self.one("SELECT COUNT(*) FROM events WHERE source_id=? AND (tbl=? OR ? IS NULL) AND ts_raw GLOB '*[0-9]/[0-9]*'",
                                     (s["id"], t.get("name"), t.get("name"))) or 0
                    if n_num:
                        self.add("date_order", f"{lab}: day/month order assumed",
                                 f"{lab} ({name}), {t.get('name')}: {t['date_order_note']}. {plural(n_num, 'timestamp')} use numeric dates.",
                                 {"values": {"source": lab, "table": t.get("name"), "assumed": t.get("date_order"), "count": n_num}},
                                 evidence=self.sample("source_id=? AND ts_raw GLOB '*[0-9]/[0-9]*'", (s["id"],), 4),
                                 priority=1, sort_key=f"1{lab}c")
            for fl, n in sorted((st.get("flags") or {}).items()):
                if not n or fl not in FLAG_TEXT:
                    continue
                self.add(f"flag_{fl}", f"{lab}: {plural(n, 'timestamp')} flagged {fl}",
                         f"{lab} ({name}): {plural(n, 'record')} {FLAG_TEXT[fl]}.",
                         {"values": {"source": lab, "flag": fl, "count": n}},
                         sql=f"SELECT cite, ts_raw, ts_utc, ts_flag FROM ev WHERE source='{lab}' AND ts_flag LIKE '%{fl}%'",
                         evidence=self.sample("source_id=? AND ts_flag LIKE ?", (s["id"], f"%{fl}%"), 6),
                         priority=FLAG_PRIORITY.get(fl, 2), sort_key=f"3{lab}{fl}")
            if failed:
                ex = st.get("ts_failed_examples") or []
                self.add("ts_failed", f"{lab}: {plural(failed, 'timestamp')} not parsed",
                         f"{lab} ({name}): {plural(failed, 'timestamp value')} could not be parsed; those records have no time. Examples: "
                         + "; ".join(f"'{e[1]}' ({lab}:{e[0]})" for e in ex[:4]) + ".",
                         {"values": {"source": lab, "count": failed}, "columns": ["cite", "value"],
                          "rows": [[f"{lab}:{e[0]}", e[1]] for e in ex]},
                         cites=[{"cite": f"{lab}:{e[0]}", "source_id": s["id"], "loc": e[0], "text": e[1], "expect": e[1]} for e in ex[:8]],
                         priority=1, sort_key=f"1{lab}d")
            if st.get("ip_invalid"):
                ex = st.get("ip_invalid_examples") or []
                self.add("ip_invalid", f"{lab}: unreadable IP values",
                         f"{lab} ({name}): {plural(st['ip_invalid'], 'value')} in the IP column are not valid IP addresses. Examples: "
                         + "; ".join(f"'{e[1]}' ({lab}:{e[0]})" for e in ex[:4]) + ".",
                         {"values": {"source": lab, "count": st["ip_invalid"]}, "columns": ["cite", "value"],
                          "rows": [[f"{lab}:{e[0]}", e[1]] for e in ex]},
                         cites=[{"cite": f"{lab}:{e[0]}", "source_id": s["id"], "loc": e[0], "text": e[1], "expect": e[1]} for e in ex[:8]],
                         priority=2, sort_key=f"3{lab}e")
            if st.get("nontable"):
                self.add("nontable", f"{lab}: lines outside the table layout",
                         f"{lab} ({name}): {plural(st['nontable'], 'line')} did not match the table layout and were read as free text"
                         + (f"; {plural(st.get('skipped_lines', 0), 'other line')} held no timestamp, IP or identifier and were skipped" if st.get("skipped_lines") else "") + ".",
                         {"values": {"source": lab, "count": st["nontable"], "skipped": st.get("skipped_lines", 0)}},
                         evidence=self.sample("source_id=? AND extra LIKE '%does not match the table layout%'", (s["id"],), 4),
                         priority=3, sort_key=f"4{lab}")
            if st.get("empty_pages"):
                pages = st["empty_pages"]
                self.add("pdf_no_text", f"{lab}: {plural(len(pages), 'page')} without text",
                         f"{lab} ({name}): {plural(len(pages), 'page')} contain no extractable text (for example scanned images) and were NOT analysed: pages "
                         + ", ".join(str(p) for p in pages[:40]) + (" ..." if len(pages) > 40 else "") + ". Review them manually.",
                         {"values": {"source": lab, "pages": pages[:200], "count": len(pages)}}, priority=1, sort_key=f"0{lab}p")
        # duplicate events across sources
        dup = self.q("""SELECT COUNT(*) AS n, SUM(c) AS total FROM (
                         SELECT COUNT(DISTINCT source_id) AS c FROM events
                         WHERE ts_utc IS NOT NULL AND (ip IS NOT NULL OR account IS NOT NULL)
                         GROUP BY ts_utc, ip, account, category HAVING c > 1)""")
        if dup and dup[0]["n"]:
            n = dup[0]["n"]
            ex = self.q("""SELECT ts_utc, ip, account, category, GROUP_CONCAT(DISTINCT source_id) AS srcs FROM events
                           WHERE ts_utc IS NOT NULL AND (ip IS NOT NULL OR account IS NOT NULL)
                           GROUP BY ts_utc, ip, account, category HAVING COUNT(DISTINCT source_id) > 1 LIMIT 10""")
            self.add("cross_source_duplicates", "Same event in more than one source",
                     f"{plural(n, 'event')} (same UTC time, IP, account and event type) appear in more than one source - likely overlapping returns. Counts in other findings include each copy.",
                     {"values": {"count": n}, "columns": ["ts_utc", "ip", "account", "category", "sources"],
                      "rows": [[r["ts_utc"], r["ip"], r["account"], r["category"], self.labels(r["srcs"].split(","))] for r in ex]},
                     sql="SELECT ts_utc, ip, account, category, COUNT(DISTINCT source) FROM ev GROUP BY 1,2,3,4 HAVING COUNT(DISTINCT source)>1",
                     priority=3, sort_key="5dup")
