"""Markdown report package: REPORT.md (start here), FINDINGS.md, EVIDENCE.md, SOURCES.md,
TIMELINE.md, METHODS.md, REVIEW.md, CITATION_CHECK.md, charts/*.svg, exports/*.csv, MANIFEST.sha256."""
from __future__ import annotations

import csv
import datetime as dt
import hashlib
import json
import os
from pathlib import Path

from . import __version__
from . import db as dbm
from .charts import bar_chart, daily_chart
from .findings import CATEGORY_ORDER
from .util import fmt_bytes, fmt_int, local_now_str, md_code, md_escape, utc_now_str

try:
    from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover
    ZoneInfo = None  # type: ignore

UTC = dt.timezone.utc
DRAFT = ("> **DRAFT FOR ANALYST REVIEW.** Every statement is computed from the ingested records and cites them. "
         "Nothing here has been reviewed by a person yet. Confirm against the original returns before relying on it.")
CITE_HELP = ("**How to read citations.** *S03:L1842* means source S03 (see [SOURCES.md](SOURCES.md)), line 1842 of the original "
             "file; *S05:Logins!R220* is worksheet Logins, row 220; *S07:p2:L14* is PDF page 2, line 14 of its extracted text; "
             "*S08:L120:C17* is line 120, column 17 of an HTML file; *S03:$.login_history[17]* is a JSON path; *L120+L122* means "
             "several lines read together. *F012* is finding 12 in [FINDINGS.md](FINDINGS.md); its records are quoted verbatim "
             "in [EVIDENCE.md](EVIDENCE.md).")


def anchor(fid: str) -> str:
    return fid.lower()


def flink(fid: str, page: str = "FINDINGS.md") -> str:
    return f"[{fid}]({page}#{anchor(fid)})"


def fmt_cell(v) -> str:
    if v is None:
        return ""
    if isinstance(v, bool):
        return "yes" if v else "no"
    if isinstance(v, float):
        return f"{v:,.2f}" if not v.is_integer() else f"{int(v):,}"
    if isinstance(v, int):
        return f"{v:,}" if abs(v) >= 10000 else str(v)
    if isinstance(v, (list, tuple)):
        return md_escape(", ".join(str(x) for x in v))
    return md_escape(v)


def md_table(columns, rows, max_rows=None) -> str:
    if not columns:
        return ""
    rows = rows if max_rows is None else rows[:max_rows]
    out = ["| " + " | ".join(md_escape(c) for c in columns) + " |",
           "| " + " | ".join("---" for _ in columns) + " |"]
    for r in rows:
        out.append("| " + " | ".join(fmt_cell(v) for v in list(r) + [None] * (len(columns) - len(r))) + " |")
    return "\n".join(out)


def facts_tables(facts: dict) -> list[dict]:
    t = list(facts.get("tables") or [])
    if facts.get("columns"):
        t.insert(0, {"title": "", "columns": facts["columns"], "rows": facts.get("rows", []), "total_rows": facts.get("total_rows")})
    return t


class Report:
    def __init__(self, case, con, prog=None):
        self.case = case
        self.con = con
        self.prog = prog
        self.out = case.report_dir
        self.out.mkdir(parents=True, exist_ok=True)
        (self.out / "exports").mkdir(exist_ok=True)
        (self.out / "charts").mkdir(exist_ok=True)
        self.p = case.params
        self.findings = dbm.rows(con, "SELECT * FROM findings WHERE fid IS NOT NULL ORDER BY fid")
        for f in self.findings:
            f["facts"] = json.loads(f["facts"]) if f["facts"] else {}
        self.sources = dbm.rows(con, "SELECT * FROM sources ORDER BY id")
        self.labels = {s["id"]: s["label"] for s in self.sources}
        self.ev_cache: dict = {}
        try:
            self.tz = ZoneInfo(case.display_tz) if ZoneInfo else None
        except Exception:  # noqa: BLE001
            self.tz = None

    # ------------------------------------------------------------------ helpers
    def evidence(self, finding_id: int, limit: int | None = None) -> list[dict]:
        key = (finding_id, limit)
        if key not in self.ev_cache:
            sql = ("SELECT fe.role, e.*, s.label FROM finding_evidence fe JOIN events e ON e.id=fe.event_id "
                   "JOIN sources s ON s.id=e.source_id WHERE fe.finding_id=? ORDER BY e.ts_epoch IS NULL, e.ts_epoch, e.id")
            if limit:
                sql += f" LIMIT {int(limit)}"
            self.ev_cache[key] = dbm.rows(self.con, sql, (finding_id,))
        return self.ev_cache[key]

    def other_cites(self, finding_id: int) -> list[dict]:
        return dbm.rows(self.con, "SELECT * FROM finding_cites WHERE finding_id=?", (finding_id,))

    def cite_line(self, f: dict, n: int = 6) -> str:
        ev = self.evidence(f["id"])
        cites = [f"`{e['label']}:{e['loc']}`" + (f" ({e['role']})" if e["role"] in ("first", "last") else "") for e in ev[:n]]
        cites += [f"`{c['cite']}`" for c in self.other_cites(f["id"])][:4]
        if not cites:
            return ""
        more = f" … {len(ev) - n} more" if len(ev) > n else ""
        return "Evidence: " + ", ".join(cites) + more + f" — [verbatim records](EVIDENCE.md#{anchor(f['fid'])})"

    def local(self, ts_epoch, ts_utc) -> str:
        if ts_epoch is None or self.tz is None or (ts_utc and len(ts_utc) == 10):
            return ""
        return dt.datetime.fromtimestamp(ts_epoch, UTC).astimezone(self.tz).strftime("%Y-%m-%d %H:%M:%S %Z")

    # ------------------------------------------------------------------ main
    def write_all(self, stage: str = "final") -> list[Path]:
        files = []
        steps = [self.exports, self.charts, self.sources_md, self.findings_md, self.evidence_md, self.timeline_md,
                 self.methods_md, self.review_md, self.citation_md, self.report_md]
        if self.prog:
            self.prog.set_total(len(steps), "files")
        for i, fn in enumerate(steps):
            if self.prog:
                self.prog.message(f"Writing {fn.__name__.replace('_md', '').upper()}")
            r = fn()
            if r:
                files += r if isinstance(r, list) else [r]
            if self.prog:
                self.prog.update(i + 1)
        files.append(self.manifest())
        return files

    # ------------------------------------------------------------------ exports
    def _csv(self, name: str, header: list[str], rows) -> Path:
        p = self.out / "exports" / name
        with open(p, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(header)
            for r in rows:
                w.writerow(list(r))
        return p

    def exports(self) -> list[Path]:
        c = self.con
        out = [
            self._csv("sources.csv", ["source", "file", "path", "kind", "size_bytes", "sha256", "status", "records", "ingested_at"],
                      c.execute("SELECT label, display, path, kind, size, sha256, status, rows, ingested_at FROM sources ORDER BY id")),
            self._csv("findings.csv", ["finding", "category", "priority", "title", "statement", "evidence_records", "reproduce_sql"],
                      c.execute("SELECT fid, category, priority, title, statement, evidence_count, sql FROM findings WHERE fid IS NOT NULL ORDER BY fid")),
            self._csv("finding_evidence.csv", ["finding", "role", "citation", "ts_utc", "ts_original", "ip", "account", "category", "action", "verbatim_record"],
                      c.execute("SELECT f.fid, fe.role, s.label || ':' || e.loc, e.ts_utc, e.ts_raw, e.ip, e.account, e.category, e.action, e.raw "
                                "FROM finding_evidence fe JOIN findings f ON f.id=fe.finding_id JOIN events e ON e.id=fe.event_id "
                                "JOIN sources s ON s.id=e.source_id WHERE f.fid IS NOT NULL ORDER BY f.fid, e.ts_epoch")),
            self._csv("timeline.csv", ["citation", "ts_utc", "ts_original", "tz_basis", "ts_flags", "account", "category", "action", "status",
                                       "ip", "port", "ip_class", "asn", "network", "country", "user_agent", "device", "counterparty", "amount", "currency"],
                      c.execute("SELECT s.label || ':' || e.loc, e.ts_utc, e.ts_raw, e.tz_basis, e.ts_flag, e.account, e.category, e.action, e.status, "
                                "e.ip, e.port, e.ip_class, x.asn, x.as_org, x.country, e.user_agent, e.device, e.counterparty, e.amount, e.currency "
                                "FROM events e JOIN sources s ON s.id=e.source_id LEFT JOIN ip_enrich x ON x.ip=e.ip "
                                "ORDER BY e.ts_epoch IS NULL, e.ts_epoch, e.id")),
            self._csv("ip_inventory.csv", ["ip", "version", "class", "subnet", "events", "accounts", "sources", "first_utc", "last_utc", "ports",
                                           "asn", "network", "country"],
                      c.execute("SELECT ip, ip_ver, ip_class, subnet, events, accounts, sources, first_utc, last_utc, ports, asn, as_org, country "
                                "FROM ip_summary ORDER BY events DESC, ip")),
            self._csv("ip_accounts.csv", ["ip", "account", "events", "first_utc", "last_utc"],
                      c.execute("SELECT ip, account, events, first_utc, last_utc FROM ip_accounts ORDER BY ip, account")),
            self._csv("accounts.csv", ["account", "events", "sources", "logins", "failed_logins", "logouts", "account_changes", "ips", "public_ips",
                                       "user_agents", "first_utc", "last_utc"],
                      c.execute("SELECT * FROM account_summary ORDER BY events DESC")),
            self._csv("identifiers.csv", ["kind", "value", "validation", "records", "sources", "accounts", "first_utc", "last_utc"],
                      c.execute("SELECT kind, norm, validity, events, sources, accounts, first_utc, last_utc FROM ident_summary ORDER BY kind, events DESC")),
            self._csv("identifier_occurrences.csv", ["kind", "value", "as_written", "validation", "citation", "ts_utc", "account"],
                      c.execute("SELECT i.kind, i.norm, i.value, i.validity, s.label || ':' || e.loc, e.ts_utc, e.account FROM identifiers i "
                                "JOIN events e ON e.id=i.event_id JOIN sources s ON s.id=i.source_id ORDER BY i.kind, i.norm, e.ts_epoch")),
            self._csv("daily.csv", ["day_utc", "events"],
                      c.execute("SELECT substr(ts_utc,1,10), COUNT(*) FROM events WHERE ts_utc IS NOT NULL GROUP BY 1 ORDER BY 1")),
            self._csv("counterparties.csv", ["account", "counterparty", "records", "amount_total_single_currency", "currencies", "first_utc", "last_utc"],
                      c.execute("SELECT account, counterparty, COUNT(*), CASE WHEN COUNT(DISTINCT currency)<=1 THEN SUM(amount) END, "
                                "GROUP_CONCAT(DISTINCT currency), MIN(ts_utc), MAX(ts_utc) FROM events WHERE counterparty IS NOT NULL "
                                "GROUP BY account, counterparty ORDER BY 3 DESC")),
        ]
        return out

    def charts(self) -> list[Path]:
        out = []
        f = next((x for x in self.findings if x["kind"] == "hour_profile"), None)
        if f:
            t = facts_tables(f["facts"])[0]
            labels = [r[0][:2] for r in t["rows"]]
            series = [("UTC", [r[1] for r in t["rows"]])]
            if len(t["columns"]) > 2:
                series.append((t["columns"][2].replace("events_", ""), [r[2] for r in t["rows"]]))
            p = self.out / "charts" / "hourly.svg"
            p.write_text(bar_chart("Events by hour of day", labels, series, note="date-only and implausible timestamps excluded"),
                         encoding="utf-8")
            out.append(p)
            wd = facts_tables(f["facts"])[1]
            p = self.out / "charts" / "weekday.svg"
            p.write_text(bar_chart("Events by weekday (UTC)", [r[0][:3] for r in wd["rows"]], [("events", [r[1] for r in wd["rows"]])],
                                   width=460), encoding="utf-8")
            out.append(p)
        rows = [(r[0], r[1]) for r in self.con.execute("SELECT substr(ts_utc,1,10), COUNT(*) FROM events WHERE ts_epoch IS NOT NULL "
                                                         "AND (ts_flag IS NULL OR ts_flag NOT LIKE '%implausible_year%') GROUP BY 1 ORDER BY 1")]
        if rows:
            p = self.out / "charts" / "daily.svg"
            p.write_text(daily_chart(rows), encoding="utf-8")
            out.append(p)
        return out

    # ------------------------------------------------------------------ SOURCES.md
    def sources_md(self) -> Path:
        L = [f"# Sources — {self.case.name}", "", "Every file read for this case, its SHA-256 hash, and how it was interpreted. "
             "Citations such as `S03:L1842` refer to the labels below.", ""]
        L.append(md_table(["Label", "File", "Kind", "Size", "Status", "Records", "SHA-256"],
                          [[s["label"], s["display"], s["kind"], fmt_bytes(s["size"]), s["status"], s["rows"], s["sha256"]] for s in self.sources]))
        L.append("")
        for s in self.sources:
            cfg = json.loads(s["config"]) if s.get("config") else {}
            st = json.loads(s["stats"]) if s.get("stats") else {}
            L += [f'<a id="{s["label"].lower()}"></a>', f"## {s['label']} — {Path(s.get('member') or s['path']).name}", ""]
            rec = "matches" if s.get("recheck_sha256") and s["recheck_sha256"] == s["sha256"] else (
                "**DOES NOT MATCH — the file changed after ingest**" if s.get("recheck_sha256") else "not re-checked yet")
            rows = [["Path read", md_code(s["path"])], ["Shown as", s["display"]], ["Size", f"{fmt_bytes(s['size'])} ({fmt_int(s['size'])} bytes)"],
                    ["File modified", s["mtime"]], ["SHA-256 at ingest", md_code(s["sha256"])],
                    ["SHA-256 re-check", f"{rec}" + (f" ({s['rechecked_at']})" if s.get("rechecked_at") else "")],
                    ["Status", s["status"] + (f" — {s['error']}" if s.get("error") else "")]]
            if s.get("parent_id"):
                rows.append(["Extracted from", self.labels.get(s["parent_id"], "")])
            if cfg:
                rows += [["Format", f"{cfg.get('kind')}" + (f", encoding {cfg.get('encoding')}" if cfg.get("encoding") else "")],
                         ["Timezone for times without an offset", f"{cfg.get('tz')}" + (" — **ASSUMED**" if cfg.get("tz_assumed") else "")
                          + f" (basis: {cfg.get('tz_basis')})"]]
                if cfg.get("tz_conflicts"):
                    rows.append(["Other timezone hints", "; ".join(cfg["tz_conflicts"])])
                if cfg.get("default_account"):
                    rows.append(["Account for rows without one", f"{cfg['default_account']} (basis: {cfg.get('default_account_basis')})"])
                rows.append(["Records", f"{fmt_int(s['rows'])}; timestamps parsed {fmt_int(st.get('ts_parsed', 0))}, not parseable "
                             f"{fmt_int(st.get('ts_failed', 0))}, none present {fmt_int(st.get('ts_missing', 0))}"])
                if st.get("flags"):
                    rows.append(["Timestamp flags", ", ".join(f"{k} {v}" for k, v in st["flags"].items())])
                if st.get("basis"):
                    rows.append(["Offset basis (counts)", "; ".join(f"{k}: {v}" for k, v in sorted(st["basis"].items(), key=lambda t: -t[1])[:6])])
                if st.get("empty_pages"):
                    rows.append(["PDF pages without text (not analysed)", ", ".join(str(p) for p in st["empty_pages"][:100])])
            L.append(md_table(["Item", "Value"], rows))
            L.append("")
            for t in cfg.get("tables", []):
                mp = t.get("mapping")
                L.append(f"**{t.get('name')}** — mode `{t.get('mode')}`"
                         + (f", header at {t.get('header_cite') or t.get('header_line')}" if t.get("header_line") or t.get("header_cite") else "")
                         + (f", delimiter `{t.get('delimiter')!r}`" if t.get("delimiter") else "")
                         + (f", date order {t.get('date_order')}" if t.get("date_order") else "")
                         + (f" ({t['date_order_note']})" if t.get("date_order_note") else "")
                         + (f", proximity pairing window {t.get('pair_window')} lines" if t.get("mode") == "text" and t.get("pair_window") else "")
                         + (f", default event type '{t['default_category']}' (basis: {t.get('default_category_basis')})" if t.get("default_category") else ""))
                L.append("")
                if mp:
                    L.append(md_table(["Field", "Column"], [[k, v] for k, v in mp.items()]))
                    L.append("")
                for n in t.get("mapping_notes") or []:
                    L.append(f"- {md_escape(n)}")
                if t.get("mapping_notes"):
                    L.append("")
        p = self.out / "SOURCES.md"
        p.write_text("\n".join(L) + "\n", encoding="utf-8")
        return p

    # ------------------------------------------------------------------ FINDINGS.md
    def findings_md(self) -> Path:
        L = [f"# Findings — {self.case.name}", "", DRAFT, "", CITE_HELP, ""]
        cur = None
        for f in self.findings:
            if f["category"] != cur:
                cur = f["category"]
                L += [f"## {cur}", ""]
            L += [f'<a id="{anchor(f["fid"])}"></a>', f"### {f['fid']} — {md_escape(f['title'])}", "",
                  f"*Priority {f['priority']}*, {f['evidence_count']} cited record(s)", "", f["statement"], ""]
            cl = self.cite_line(f, 8)
            if cl:
                L += [cl, ""]
            for t in facts_tables(f["facts"]):
                if t.get("title"):
                    L.append(f"**{md_escape(t['title'])}**" + (f" (showing {len(t['rows'])} of {fmt_int(t['total_rows'])})"
                                                               if t.get("total_rows") and t["total_rows"] > len(t["rows"]) else ""))
                    L.append("")
                L += [md_table(t["columns"], t["rows"]), ""]
            if f["facts"].get("mermaid"):
                L += ["```mermaid", f["facts"]["mermaid"], "```", ""]
            if f.get("export"):
                L += [f"Full data: [{f['export']}]({f['export']})", ""]
            if f.get("sql"):
                L += ["Reproduce (read-only SQL against `case.db`):", "", "```sql", f["sql"], "```", ""]
        p = self.out / "FINDINGS.md"
        p.write_text("\n".join(L) + "\n", encoding="utf-8")
        return p

    # ------------------------------------------------------------------ EVIDENCE.md
    def evidence_md(self) -> Path:
        L = [f"# Evidence — {self.case.name}", "",
             "The records behind each finding, quoted verbatim from the original files (long records are truncated here; "
             "the full text is in the source file at the cited place and in exports/finding_evidence.csv).", "", CITE_HELP, ""]
        for f in self.findings:
            ev = self.evidence(f["id"])
            oc = self.other_cites(f["id"])
            if not ev and not oc:
                continue
            L += [f'<a id="{anchor(f["fid"])}"></a>', f"## {f['fid']} — {md_escape(f['title'])}", "", f"Back to {flink(f['fid'])}", ""]
            if ev:
                L.append(md_table(["Role", "Citation", "UTC", "As written", "IP", "Account", "Event", "Verbatim record"],
                                  [[e["role"], md_code(f"{e['label']}:{e['loc']}"), e["ts_utc"], e["ts_raw"], e["ip"], e["account"],
                                    e["action"] or e["category"], md_code(e["raw"], 300)] for e in ev]))
                L.append("")
            for c in oc:
                L.append(f"- {md_code(c['cite'])}: {md_code(c['text'])}")
            if oc:
                L.append("")
        p = self.out / "EVIDENCE.md"
        p.write_text("\n".join(L) + "\n", encoding="utf-8")
        return p

    # ------------------------------------------------------------------ TIMELINE.md
    def timeline_md(self) -> Path:
        mx = int(self.p.get("timeline_md_max", 5000))
        n = dbm.one(self.con, "SELECT COUNT(*) FROM events WHERE ts_epoch IS NOT NULL AND category != 'other'") or 0
        tzname = self.case.display_tz if self.tz else ""
        L = [f"# Timeline — {self.case.name}", "",
             f"Activity records (logins, failures, logouts, account changes, registrations, transactions, messages) in time order. "
             f"{fmt_int(n)} records" + (f"; the first {fmt_int(mx)} are listed here and all are in exports/timeline.csv" if n > mx else "") + ".", ""]
        rows = []
        for e in dbm.rows(self.con, "SELECT e.*, s.label, x.as_org, x.country FROM events e JOIN sources s ON s.id=e.source_id "
                                    "LEFT JOIN ip_enrich x ON x.ip=e.ip WHERE e.ts_epoch IS NOT NULL AND e.category != 'other' "
                                    "ORDER BY e.ts_epoch, e.id LIMIT ?", (mx,)):
            net = " ".join(x for x in [e["as_org"], e["country"]] if x)
            rows.append([e["ts_utc"], self.local(e["ts_epoch"], e["ts_utc"]), md_code(f"{e['label']}:{e['loc']}"), e["account"],
                         e["category"], e["action"], e["ip"], net, e["ts_flag"]])
        L.append(md_table(["UTC", f"Local ({tzname})" if tzname else "Local", "Citation", "Account", "Type", "Event", "IP", "Network", "Flags"], rows))
        p = self.out / "TIMELINE.md"
        p.write_text("\n".join(L) + "\n", encoding="utf-8")
        return p

    def methods_md(self) -> Path:
        from .methods import methods_text
        p = self.out / "METHODS.md"
        p.write_text(methods_text(self.case, self.con), encoding="utf-8")
        return p

    # ------------------------------------------------------------------ REVIEW.md
    def review_md(self) -> Path:
        L = [f"# Analyst review checklist — {self.case.name}", "",
             "Everything the tool assumed, could not read, or drafted with the language model and then rejected. "
             "Tick each item once checked against the original return.", ""]
        L += ["## 1. Assumptions to confirm", ""]
        assumptions = [f for f in self.findings if f["kind"] in ("tz_assumed", "tz_conflict", "date_order", "flag_ambiguous_dst",
                                                                    "flag_nonexistent_local_time", "flag_abbr_dst_mismatch",
                                                                    "flag_paired_by_proximity", "flag_two_digit_year")]
        for f in assumptions:
            L.append(f"- [ ] {flink(f['fid'])} {md_escape(f['statement'])}")
        for s in self.sources:
            cfg = json.loads(s["config"]) if s.get("config") else {}
            if cfg.get("default_account") and s["status"] == "ingested":
                L.append(f"- [ ] {s['label']}: rows without an account were attributed to **{md_escape(cfg['default_account'])}** "
                         f"(basis: {md_escape(cfg.get('default_account_basis'))}).")
            for t in cfg.get("tables", []):
                if t.get("default_category") and s["status"] == "ingested":
                    L.append(f"- [ ] {s['label']} / {md_escape(t.get('name'))}: rows without a recognised event type were treated as "
                             f"'{t['default_category']}' (basis: {md_escape(t.get('default_category_basis'))}).")
        if not assumptions:
            L.append("- No timezone, date-order or DST assumptions were needed.")
        L += ["", "## 2. Not analysed", ""]
        na = [f for f in self.findings if f["kind"] in ("pdf_no_text", "source_not_analysed", "ts_failed", "ip_invalid", "source_skipped")]
        for f in na:
            L.append(f"- [ ] {flink(f['fid'])} {md_escape(f['statement'])}")
        if not na:
            L.append("- Every file was read and every timestamp and IP value parsed.")
        L += ["", "## 3. Priority-1 findings to verify against the originals", ""]
        for f in self.findings:
            if f["priority"] == 1 and f["category"] != "Sources & data quality":
                L.append(f"- [ ] {flink(f['fid'])} {md_escape(f['title'])} — evidence in {flink(f['fid'], 'EVIDENCE.md')}")
        nar = dbm.rows(self.con, "SELECT * FROM narrative ORDER BY section, ord")
        rej = [n for n in nar if n["status"] == "rejected"]
        flg = [n for n in nar if n["status"] == "flagged"]
        L += ["", "## 4. AI-drafted sentences removed by verification", ""]
        if not nar:
            L.append("- The language-model narrative has not been generated for this report.")
        elif not rej:
            L.append("- None: every drafted sentence passed verification.")
        else:
            L.append("These sentences were written by the model but are NOT in the report because a value in them did not match the cited findings.")
            L.append("")
            L.append(md_table(["Section", "Sentence", "Cited", "Why removed"],
                              [[n["section"], n["text"], ", ".join(json.loads(n["cites"] or "[]")), "; ".join(json.loads(n["reasons"] or "[]"))] for n in rej]))
        L += ["", "## 5. AI-drafted sentences kept but flagged", ""]
        if flg:
            L.append(md_table(["Section", "Sentence", "Flag"],
                              [[n["section"], n["text"], "; ".join(json.loads(n["flags"] or "[]"))] for n in flg]))
        else:
            L.append("- None.")
        fails = dbm.rows(self.con, "SELECT * FROM citation_checks WHERE status != 'pass' ORDER BY id")
        L += ["", "## 6. Citation check problems", ""]
        if fails:
            L.append(md_table(["Citation", "Result", "Detail"], [[c["cite"], c["status"], c["detail"]] for c in fails[:500]]))
        else:
            L.append("- None recorded (see CITATION_CHECK.md for when the check last ran).")
        p = self.out / "REVIEW.md"
        p.write_text("\n".join(L) + "\n", encoding="utf-8")
        return p

    def citation_md(self) -> Path:
        meta = dbm.get_meta(self.con, "citation_check") or {}
        L = [f"# Citation check — {self.case.name}", ""]
        if not meta:
            L.append("The citation check has not run yet. It runs automatically after the analysis.")
        else:
            L += [f"Run: {meta.get('run_at')}", "",
                  "Each cited record was located again in the original file (by byte offset, worksheet row, JSON path, PDF page "
                  "or HTML line) and compared with the text stored at ingest; the IP and timestamp stored for the record were "
                  "also required to appear literally in that text.", "",
                  md_table(["Result", "Count"], [["pass", meta.get("pass", 0)], ["fail", meta.get("fail", 0)],
                                                 ["could not check", meta.get("unverifiable", 0)], ["total", meta.get("total", 0)]]), ""]
            hashes = meta.get("hashes") or {}
            if hashes:
                L += ["Source hashes re-computed at the same time:", "",
                      md_table(["Result", "Count"], [[k, v] for k, v in hashes.items()]), ""]
            fails = dbm.rows(self.con, "SELECT * FROM citation_checks WHERE status != 'pass' ORDER BY id LIMIT 2000")
            if fails:
                L += ["## Problems", "", md_table(["Citation", "Result", "Detail"], [[c["cite"], c["status"], c["detail"]] for c in fails])]
        p = self.out / "CITATION_CHECK.md"
        p.write_text("\n".join(L) + "\n", encoding="utf-8")
        return p

    # ------------------------------------------------------------------ REPORT.md
    def report_md(self) -> Path:
        c = self.con
        n_ev = dbm.one(c, "SELECT COUNT(*) FROM events") or 0
        n_id = dbm.one(c, "SELECT COUNT(*) FROM identifiers WHERE kind NOT IN ('ipv4','ipv6')") or 0
        span = c.execute("SELECT MIN(ts_utc), MAX(ts_utc) FROM events WHERE ts_epoch IS NOT NULL AND "
                         "(ts_flag IS NULL OR ts_flag NOT LIKE '%implausible_year%')").fetchone()
        ing = [s for s in self.sources if s["status"] == "ingested"]
        p1 = [f for f in self.findings if f["priority"] == 1]
        cc = dbm.get_meta(c, "citation_check") or {}
        nar_meta = dbm.get_meta(c, "narrative") or {}
        nar = dbm.rows(c, "SELECT * FROM narrative WHERE status IN ('accepted','flagged') ORDER BY ord")
        L = [f"# {self.case.name} — subpoena return analysis", "", DRAFT, ""]
        info = [["Case", self.case.name], ["Examiner", self.case.info.get("examiner") or ""],
                ["Generated", f"{utc_now_str()} ({local_now_str()})"], ["Tool", f"Spoor {__version__} (offline)"],
                ["Sources", f"{len(ing)} files analysed of {len([s for s in self.sources if s['status'] != 'container'])} — [SOURCES.md](SOURCES.md)"],
                ["Records", f"{fmt_int(n_ev)} records, {fmt_int(n_id)} identifier occurrences"],
                ["Time span (UTC)", f"{span[0]} to {span[1]}" if span and span[0] else "no timestamps"],
                ["Findings", f"{len(self.findings)} ({len(p1)} priority 1) — [FINDINGS.md](FINDINGS.md)"],
                ["Citation check", (f"{fmt_int(cc.get('pass', 0))} of {fmt_int(cc.get('total', 0))} cited records re-read from the original files "
                                    f"and matched — [CITATION_CHECK.md](CITATION_CHECK.md)") if cc else "not run yet"],
                ["AI-drafted summary", (f"{nar_meta.get('accepted', 0)} sentences kept, {nar_meta.get('rejected', 0)} removed by verification "
                                        f"(model {nar_meta.get('model')})") if nar_meta else "not generated"],
                ["Review checklist", "[REVIEW.md](REVIEW.md)"]]
        L += [md_table(["Item", "Detail"], info), "", CITE_HELP, ""]
        if nar:
            L += ["## AI-drafted summary (machine-verified)", "",
                  f"> Drafted by the local model `{nar_meta.get('model')}` from the findings only. Each sentence below was checked "
                  "automatically: every IP, timestamp, number, identifier and name in it appears in the findings it cites. "
                  "Sentences that failed were removed and are listed in [REVIEW.md](REVIEW.md). ⚑ marks sentences that use "
                  "inference or characterisation and need your judgment.", ""]
            sec = None
            for n in nar:
                if n["section"] != sec:
                    sec = n["section"]
                    L += ["", f"**{sec}**", ""]
                cites = " ".join(flink(x) for x in json.loads(n["cites"] or "[]"))
                flag = "⚑ " if n["status"] == "flagged" else ""
                L.append(f"- {flag}{n['text']} {cites}")
            L.append("")
        L += ["## Key findings (priority 1)", ""]
        if not p1:
            L.append("No priority-1 findings.")
        for f in p1[:60]:
            L.append(f"- **{flink(f['fid'])} {md_escape(f['title'])}** — {f['statement']}")
        if len(p1) > 60:
            L.append(f"- … {len(p1) - 60} more in [FINDINGS.md](FINDINGS.md)")
        L.append("")
        for cat in CATEGORY_ORDER:
            fs = [f for f in self.findings if f["category"] == cat]
            if not fs:
                continue
            L += [f"## {cat}", ""]
            if cat == "Timing & activity patterns":
                for ch, alt in (("hourly", "Events by hour of day"), ("weekday", "Events by weekday"), ("daily", "Events over time")):
                    if (self.out / "charts" / f"{ch}.svg").exists():
                        L += [f"![{alt}](charts/{ch}.svg)", ""]
            for f in fs:
                if f["priority"] <= 2:
                    L += [f"**{flink(f['fid'])} — {md_escape(f['title'])}**", "", f["statement"], ""]
                    cl = self.cite_line(f, 4)
                    if cl:
                        L += [cl, ""]
            minor = [f for f in fs if f["priority"] >= 3]
            if minor:
                L.append("Also: " + "; ".join(f"{flink(f['fid'])} {md_escape(f['title'])}" for f in minor) + ".")
                L.append("")
        L += ["## Files in this report", "",
              "- [FINDINGS.md](FINDINGS.md) — every finding with its tables, evidence citations and reproducible SQL",
              "- [EVIDENCE.md](EVIDENCE.md) — the cited records, quoted verbatim",
              "- [SOURCES.md](SOURCES.md) — files, SHA-256 hashes, timezone and mapping decisions",
              "- [TIMELINE.md](TIMELINE.md) — activity in time order (UTC and local)",
              "- [METHODS.md](METHODS.md) — how each analysis works, parameters, data sources, limitations",
              "- [REVIEW.md](REVIEW.md) — checklist of assumptions and anything not analysed",
              "- [CITATION_CHECK.md](CITATION_CHECK.md) — re-verification of every citation against the originals",
              "- `exports/` — CSV files (timeline, IP inventory, IP/timestamp list for legal process, link-chart edges, identifiers)",
              "- `MANIFEST.sha256` — SHA-256 of every file in this report folder", ""]
        p = self.out / "REPORT.md"
        p.write_text("\n".join(L) + "\n", encoding="utf-8")
        return p

    def manifest(self) -> Path:
        lines = []
        for root, _dirs, files in os.walk(self.out):
            for fn in sorted(files):
                fp = Path(root) / fn
                if fp.name == "MANIFEST.sha256":
                    continue
                h = hashlib.sha256(fp.read_bytes()).hexdigest()
                lines.append(f"{h}  {fp.relative_to(self.out).as_posix()}")
        p = self.out / "MANIFEST.sha256"
        p.write_text("\n".join(sorted(lines, key=lambda l: l.split('  ', 1)[1])) + "\n", encoding="utf-8")
        return p


def write_reports(case, con, prog=None) -> list[Path]:
    return Report(case, con, prog).write_all()
