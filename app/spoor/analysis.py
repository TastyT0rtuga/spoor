"""REPORT.md as an analysis: bottom line first, figures next, a short narrative, then the reference material.

    BLUF                      what the records show, in a handful of sentences, each followed by its reference number
    Figures                   the graphs, before any text detail
    What the records show     the narrative, by theme (account access, linked accounts, cross-return items, telecom ...)
    Returns analysed          which returns are in (and which were left out)
    References                numbered, like a bibliography: finding, returns, files and exact lines
    Appendix A                negative results - checks that found nothing - kept apart from the findings
    Appendix B                caveats about the data (timezones assumed, unreadable pages ...)

Everything is deterministic and built from the findings and their facts; the old long-form layout is still written as
REPORT-FULL.md, and every finding keeps its full statement, tables, evidence and SQL in FINDINGS.md."""
from __future__ import annotations

import json
from pathlib import Path

from . import __version__
from . import brief as B
from . import db as dbm
from . import returns as rets
from .nulls import null_results
from .util import fmt_int, local_now_str, md_code, md_escape, utc_now_str

DRAFT_SHORT = ("*Draft for analyst review.* Every sentence below is computed from the records and carries a reference number; "
               "nothing has been reviewed by a person. Confirm against the original returns before relying on it.")


class RefBook:
    """Reference numbers in order of first use."""

    def __init__(self):
        self.order: list[str] = []

    def num(self, fid: str) -> int:
        if fid not in self.order:
            self.order.append(fid)
        return self.order.index(fid) + 1

    SUP = str.maketrans("0123456789-", "⁰¹²³⁴⁵⁶⁷⁸⁹⁻")

    def cite(self, fids) -> str:
        ns = sorted({self.num(f) for f in fids})
        parts, i = [], 0
        while i < len(ns):
            j = i
            while j + 1 < len(ns) and ns[j + 1] == ns[j] + 1:
                j += 1
            parts.append((ns[i], ns[j]))
            i = j + 1
        out = []
        for a, b in parts:
            if b == a:
                txt = str(a)
            elif b == a + 1:           # two in a row: two links, so each number opens its own reference
                out.append(f"[{str(a).translate(self.SUP)}](#ref-{a}),[{str(b).translate(self.SUP)}](#ref-{b})")
                continue
            else:
                txt = f"{a}-{b}"
            out.append(f"[{txt.translate(self.SUP)}](#ref-{a})")
        return ",".join(out)


def _first_locs(locs: list[str], n: int = 8) -> str:
    shown = ", ".join(locs[:n])
    return shown + (f", ... (+{len(locs) - n} more)" if len(locs) > n else "")


def bibliography(rp, refs: RefBook, src_info: dict) -> list[str]:
    byf = {f["fid"]: f for f in rp.findings}
    L = []
    for n, fid in enumerate(refs.order, 1):
        f = byf.get(fid)
        if not f:
            continue
        ev = rp.evidence(f["id"])
        per: dict = {}
        for e in ev:
            per.setdefault(e["label"], []).append(e["loc"])
        bits = []
        for lab in sorted(per):
            si = src_info.get(lab, {})
            ret = f" ({si['ret']} {si['retname']})" if si.get("ret") and src_info.get("_multi") else ""
            bits.append(f"{lab}{ret} {md_code(si.get('file', ''))}: {md_code(_first_locs(per[lab]))}")
        extra = [c["cite"] for c in rp.other_cites(f["id"])][:4]
        if extra:
            bits.append("also " + ", ".join(md_code(c) for c in extra))
        title = md_escape(f["title"])
        L += [f'<a id="ref-{n}"></a>', ""]
        L.append(f'**[{n}]** [{f["fid"]}](FINDINGS.md#{f["fid"].lower()}) - {title}. '
                 + ("; ".join(bits) if bits else "summary of the whole data set; reproduce with the SQL in the finding")
                 + f". [Records quoted verbatim](EVIDENCE.md#{f['fid'].lower()}).")
        L.append("")
    return L


def src_info_map(rp) -> dict:
    out = {"_multi": rets.multi(rp.con)}
    rm = {r["id"]: r for r in dbm.rows(rp.con, "SELECT id, label, name FROM returns")}
    for s in rp.sources:
        r = rm.get(s.get("return_id"), {})
        out[s["label"]] = {"file": Path(s.get("member") or s["path"]).name, "ret": r.get("label"), "retname": r.get("name", "")}
    return out


# ---------------------------------------------------------------- the pieces
def scope_line(rp, multi: bool) -> str:
    con = rp.con
    rows = rets.return_rows(con, include_removed=False)
    act = [r for r in rows if r["state"] == "active" and r["records"] > 0]
    n_ev = dbm.one(con, "SELECT COUNT(*) FROM events") or 0
    span = con.execute("SELECT MIN(ts_utc), MAX(ts_utc) FROM events WHERE ts_epoch IS NOT NULL AND "
                       "(ts_flag IS NULL OR ts_flag NOT LIKE '%implausible_year%')").fetchone()
    s = f"{len(act)} return{'s' if len(act) != 1 else ''}" + (f" ({', '.join(r['label'] + ' ' + r['name'] for r in act[:8])}{' ...' if len(act) > 8 else ''})" if act else "")
    s += f", {fmt_int(n_ev)} records"
    if span and span[0]:
        s += f", {span[0][:10]} to {span[1][:10]} (UTC)"
    out = [r for r in rows if r["state"] == "excluded"]
    if out:
        s += f". Left out by the analyst: {', '.join(r['label'] + ' ' + r['name'] for r in out)}"
    return s + "."


def caveats(rp) -> list[tuple[str, list[str]]]:
    """Short phrases about the data that change how far to rely on the results: [(text, [fids])]."""
    out = []
    for m, e in dbm.analysis_errors(rp.con):
        out.append((f"ANALYSIS FAILED: the {m} module stopped with an error ({e[:100]}), so its findings are missing from this report", []))
    tz = [f for f in rp.findings if f["kind"] == "tz_assumed"]
    if tz:
        out.append((f"times in {', '.join(B._v(f)['source'] for f in tz)} had no timezone and were read as UTC", [f["fid"] for f in tz]))
    for f in rp.findings:
        k, v = f["kind"], B._v(f)
        if k == "tz_conflict":
            out.append((f"{v.get('source', 'a file')} states conflicting timezones", [f["fid"]]))
        elif k == "pdf_no_text":
            out.append((f"{B._pl(v['count'], 'PDF page')} in {v['source']} had no text and {'was' if v['count'] == 1 else 'were'} not analysed", [f["fid"]]))
        elif k == "source_not_analysed":
            out.append((f"{v.get('source')} ({v.get('file')}) was not analysed: {v.get('reason')}", [f["fid"]]))
        elif k == "return_excluded":
            out.append((f"{v['return']} {v['name']} was {v['state'] if v['state'] != 'excluded' else 'left out'} by the analyst", [f["fid"]]))
        elif k == "ts_failed":
            out.append((B.first_sentence(f["statement"], 140), [f["fid"]]))
        elif k == "telecom_quality":
            t = f.get("facts", {}).get("values", {})
            if t.get("unlocated"):
                out.append((f"{fmt_int(t['unlocated'])} telecom records have no cell-site coordinates", [f["fid"]]))
    return out


def map_note(rp) -> str | None:
    """One sentence on whether the telecom records can be mapped, and where the files are."""
    from .mapdata import status
    st = status(rp.con)
    if not st["telecom"]:
        return None
    if not st["map"]:
        return f"No map or KML was produced. {st['reason']}"
    s = (f"{fmt_int(st['located'])} of {fmt_int(st['records'])} telecom records are placed at the cell site that served them: "
         "`exports/telecom.kml` (Google Earth Pro) and `exports/telecom.geojson` (QGIS/ArcGIS); the dashboard's Map screen draws them without a basemap. "
         "A record is plotted at the tower, not at the phone.")
    if st.get("reason"):
        s += " " + st["reason"]
    return s


def bluf_items(rp, multi: bool, refs: RefBook) -> list[str]:
    leads = [f for f in rp.findings if B.role(f) == "lead"]
    by = {}
    for f in leads:
        by.setdefault(B.theme_of(f), []).append(f)
    items: list[str] = []
    changes = B.group_changes(by.get("access", []))
    used_changes = set()
    for f in by.get("access", []):
        if f["kind"] == "failed_burst":
            v = B._v(f)
            text = B.brief(f, multi)
            fids = [f["fid"]]
            for g in changes:
                if g["text"] is None and not g["fids"]:
                    continue
                gf = g["findings"][0]
                if gf["kind"] == "change_from_new_ip" and B._v(gf)["account"] == v["account"] and B._v(gf)["ip"] == v.get("success_ip"):
                    text += " " + (g["text"] or B.brief(gf, multi))
                    fids += g["fids"]
                    used_changes.update(g["fids"])
            items.append(f"{text} {refs.cite(fids)}")
    # other account changes not tied to a burst, and password-spray style findings
    for g in changes:
        if g["fids"] and not (set(g["fids"]) & used_changes) and g["findings"][0]["kind"] == "change_from_new_ip":
            items.append(f"{g['text'] or B.brief(g['findings'][0], multi)} {refs.cite(g['fids'])}")
    for f in by.get("access", []):
        if f["kind"] == "multi_account_failures":
            items.append(f"{B.brief(f, multi)} {refs.cite([f['fid']])}")
    for f in by.get("linked", [])[:3]:
        if f["kind"] == "account_cluster":
            items.append(f"{B.brief(f, multi)} {refs.cite([f['fid']])}")
    cs = [f for f in by.get("returns", []) if f["kind"] == "crossref_summary"]
    if cs:
        top = [f for f in by["returns"] if f["kind"] == "crossref_item" and B._v(f).get("kind") != "username"][:4]
        cv = B._v(cs[0])
        s = (f"{cv['items']} item{'s' if cv['items'] != 1 else ''} appear in two or more of the {cv['return_count']} returns; "
             f"{cv['pairs_with_overlap']} of {cv['pairs_compared']} pairs of returns share at least one.")
        if top:
            s += " Strongest: " + "; ".join(f"{B._v(t)['value']} ({B._v(t)['return_count']} returns)" for t in top) + "."
        items.append(f"{s} {refs.cite([cs[0]['fid']] + [t['fid'] for t in top])} See [CROSSREF.md](CROSSREF.md).")
    shown_vals = {B._v(f).get("value") for f in by.get("returns", []) if f["kind"] == "crossref_item"}
    ids = [f for f in by.get("ident", []) if f["kind"] == "shared_identifier" and B._v(f).get("value") not in shown_vals][:2]
    for f in ids:
        items.append(f"{B.brief(f, multi)} {refs.cite([f['fid']])}")
    tel = by.get("telecom", [])
    for f in tel[:3]:
        items.append(f"{B.brief(f, multi)} {refs.cite([f['fid']])}")
    wl = by.get("watch", [])
    if wl:
        vals = "; ".join(B._v(f)["value"] + (f" ('{B._v(f)['label']}')" if B._v(f).get("label") else "") for f in wl[:4])
        items.append(f"{B._pl(len(wl), 'watchlist entry', 'watchlist entries')} matched records: {vals}{' ...' if len(wl) > 4 else ''}. {refs.cite([f['fid'] for f in wl[:6]])}")
    return items[:8]


def narrative(rp, multi: bool, refs: RefBook) -> list[str]:
    L = []
    fs = [f for f in rp.findings if B.role(f) in ("lead", "pattern")]
    crossref_vals = {B._v(f).get("value") for f in fs if f["kind"] == "crossref_item"}
    for key, title, kinds in B.THEMES:
        group = [f for f in fs if f["kind"] in kinds]
        if key == "linked":     # an IP already described as present in several returns is not described twice
            group = [f for f in group if not (f["kind"] == "notable_ip" and B._v(f).get("ip") in crossref_vals)]
        if key == "ident":
            group = [f for f in group if B._v(f).get("value") not in crossref_vals]
        if key == "returns":
            group = [f for f in group if f["kind"] == "crossref_item"]
        if not group:
            continue
        if key == "access":
            items = [(g["text"] or B.brief(g["findings"][0], multi), g["fids"]) for g in B.group_changes(group)]
        else:
            items = [(B.brief(f, multi), [f["fid"]]) for f in group]
        cap = 12
        sent = [f"{t} {refs.cite(fids)}" for t, fids in items[:cap]]
        rest = items[cap:]
        L += [f"### {title}", ""]
        if key == "returns":
            L += ["The items below appear in the records of two or more returns. The full list, with the records behind each return, is in "
                  "[CROSSREF.md](CROSSREF.md).", ""]
        if len(sent) < 3:
            L += [" ".join(sent), ""]
        else:
            L += ["- " + t for t in sent] + [""]
        if rest:
            L += [f"{len(rest)} more: " + "; ".join(f"{t.rstrip('.')} {refs.cite(fids)}" for t, fids in rest[:20]) + ".", ""]
    return L


def returns_table(rp) -> list[str]:
    rows = rets.return_rows(rp.con, include_removed=False)
    if not rows:
        return []
    L = ["| Return | Name | Files | Records | Time span (UTC) | Status |", "| --- | --- | --- | --- | --- | --- |"]
    for r in rows:
        span = f"{r['first_utc'][:10]} to {r['last_utc'][:10]}" if r["first_utc"] else ""
        st = {"active": "analysed" if r["records"] else "no records", "excluded": "**left out** by the analyst" + (f" ({r['note']})" if r["note"] else "")}.get(r["state"], r["state"])
        L.append(f"| {r['label']} | {md_escape(r['name'])} | {', '.join(r['labels'][:6])}{' ...' if len(r['labels']) > 6 else ''} | "
                 f"{fmt_int(r['records']) if r['state'] == 'active' else ''} | {span} | {st} |")
    return L + [""]


def appendix_nulls(rp) -> list[str]:
    nulls = null_results(rp.case, rp.con, rp.p)
    L = ["## Appendix A - Negative results", "",
         "Checks that were run and found nothing, and checks that could not be run on this data (and why). They are kept here "
         "so the main text is only what the records show. Each entry gives the SQL that reproduces it (run it in the dashboard's "
         "Look up / Ask screens or any SQLite viewer against `case.db`).", ""]
    if not nulls:
        return L + ["- Every check that applies to this data produced a finding.", ""]
    for state, head in (("none observed", "Checked - nothing found"), ("partly testable", "Checked - nothing found, with a limit"),
                        ("not testable", "Could not be checked on this data")):
        part = [n for n in nulls if n.get("state", "none observed") == state]
        if not part:
            continue
        L += [f"### {head}", ""]
        area = None
        for n in part:
            if n["area"] != area:
                area = n["area"]
                L += ["", f"**{area}**", ""]
            L.append(f"- **{md_escape(n['title'])}.** {md_escape(n['statement'])}")
            L.append(f"  <details><summary>reproduce</summary>\n\n  ```sql\n  {n['sql']}\n  ```\n\n  </details>")
        L.append("")
    return L


def appendix_notes(rp, refs: RefBook) -> list[str]:
    cav = caveats(rp)
    L = ["## Appendix B - Data notes", "",
         "How the tool read the returns, and anything that limits what the results can support. The per-file detail is in "
         "[SOURCES.md](SOURCES.md); things to confirm against the originals are in [REVIEW.md](REVIEW.md).", ""]
    mn = map_note(rp)
    if mn:
        L += [f"- **Map.** {mn}", ""]
    if cav:
        L += ["| Note | Ref |", "| --- | --- |"] + [f"| {md_escape(t)} | {refs.cite(fids)} |" for t, fids in cav] + [""]
    else:
        L += ["- No timezone assumptions, unreadable pages or unparsed timestamps.", ""]
    return L


def write_analysis(rp) -> Path:
    con = rp.con
    multi = rets.multi(con)
    refs = RefBook()
    cc = dbm.get_meta(con, "citation_check") or {}
    nar_meta = dbm.get_meta(con, "narrative") or {}
    p1 = [f for f in rp.findings if f["priority"] == 1 and B.role(f) == "lead"]
    L = [f"# {rp.case.name} - analysis", "", DRAFT_SHORT, "",
         f"Prepared {utc_now_str()} ({local_now_str()}) by Spoor {__version__}"
         + (f" for {rp.case.info.get('examiner')}" if rp.case.info.get("examiner") else "") + ". "
         f"[Full detail](REPORT-FULL.md) · [Findings](FINDINGS.md) · [Cross-return](CROSSREF.md) · [Review checklist](REVIEW.md)", ""]
    # ---- BLUF
    L += ["## BLUF", "", f"**Scope:** {scope_line(rp, multi)}", ""]
    items = bluf_items(rp, multi, refs)
    if items:
        L += [f"- {t}" for t in items] + [""]
    else:
        L += ["- Nothing in the records met the tests for a lead (see Appendix A for what was checked).", ""]
    mn = map_note(rp)
    if mn:
        L += [f"**Map:** {mn}", ""]
    cav = caveats(rp)
    if cav:
        L += ["**Limits:** " + "; ".join(t for t, _f in cav[:4]) + (f"; {len(cav) - 4} more in Appendix B" if len(cav) > 4 else "") + ". "
              + refs.cite([x for _t, fids in cav[:4] for x in fids]), ""]
    # ---- figures
    drawn = [fig for fig in rp.figs if fig["status"] == "ok" and fig.get("file")]
    if drawn:
        L += ["## Figures", ""]
        for fig in drawn:
            L += rp.fig_embed(fig)
    # ---- narrative
    nar = narrative(rp, multi, refs)
    L += ["## What the records show", ""] + (nar if nar else ["No findings of the kinds that make up this section."]) + [""]
    # model-drafted narrative (optional, machine-verified)
    narr = dbm.rows(con, "SELECT * FROM narrative WHERE status IN ('accepted','flagged') ORDER BY ord")
    if narr:
        L += ["### Model-drafted summary (machine-verified)", "",
              f"> Drafted by the local model `{nar_meta.get('model')}` from the findings only; every IP, time, number, identifier and name was checked "
              "against the findings it cites, and sentences that failed were removed (listed in REVIEW.md). ⚑ marks inference that needs your judgment.", ""]
        sec = None
        for n in narr:
            if n["section"] != sec:
                sec = n["section"]
                L += ["", f"**{sec}**", ""]
            cites = refs.cite(json.loads(n["cites"] or "[]"))
            L.append(f"- {'⚑ ' if n['status'] == 'flagged' else ''}{n['text']} {cites}")
        L.append("")
    # ---- across returns
    if multi:
        cs = [f for f in rp.findings if f["kind"] in ("crossref_summary", "crossref_none")]
        L += ["## Across returns", ""]
        if cs:
            L += [f"{B.first_sentence(cs[0]['statement'], 600)} {refs.cite([cs[0]['fid']])} The positive overlaps, return by return, are on the dedicated page: "
                  "**[CROSSREF.md](CROSSREF.md)**.", ""]
        else:
            L += ["See [CROSSREF.md](CROSSREF.md).", ""]
    # ---- returns
    L += ["## Returns analysed", ""] + returns_table(rp)
    # ---- references
    tail = appendix_nulls(rp)
    notes = appendix_notes(rp, refs)
    L += ["## References", "",
          "Numbers in brackets point here. Each reference is a finding; the lines listed are the records it rests on, in the file shown "
          "(with the return it belongs to). [FINDINGS.md](FINDINGS.md) has the full statement, tables and SQL; "
          "[EVIDENCE.md](EVIDENCE.md) quotes the records verbatim. Citation format: *L120* line 120; *Sheet!R220* worksheet row; "
          "*p2:L14* PDF page 2 line 14; *$.path[17]* JSON path.", ""]
    L += bibliography(rp, refs, src_info_map(rp))
    L += tail + notes
    L += ["## Appendix C - Files", "",
          "- [REPORT-FULL.md](REPORT-FULL.md) - the long form: every finding with its evidence line",
          "- [CROSSREF.md](CROSSREF.md) - items present in more than one return (positive overlaps only)",
          "- [FINDINGS.md](FINDINGS.md) · [EVIDENCE.md](EVIDENCE.md) · [SOURCES.md](SOURCES.md) · [TIMELINE.md](TIMELINE.md) · [FIGURES.md](FIGURES.md) · [METHODS.md](METHODS.md) · [REVIEW.md](REVIEW.md) · [CITATION_CHECK.md](CITATION_CHECK.md)",
          "- `exports/` - CSV (and for telecom: KML, GeoJSON); `MANIFEST.sha256` - SHA-256 of every file here"
          + (f"; source text re-read: {fmt_int(cc.get('pass', 0))} of {fmt_int(cc.get('total', 0))} cited records found in the original files with the stored values "
             "(this confirms the records exist and say what was stored; it does not confirm the timezone, day/month order, column mapping or the conclusions)" if cc else ""), ""]
    p = rp.out / "REPORT.md"
    p.write_text("\n".join(L) + "\n", encoding="utf-8")
    return p


# ---------------------------------------------------------------- CROSSREF.md
def write_crossref(rp) -> Path | None:
    """One page for what the returns have in common. Pairs and items that overlap only; the null pairs are one line."""
    con = rp.con
    p = rp.out / "CROSSREF.md"
    if not rets.multi(con):
        if p.exists():
            p.unlink()
        return None
    refs = RefBook()
    rows = rets.return_rows(con, include_removed=False)
    act = [r for r in rows if r["state"] == "active" and r["records"] > 0]
    summ = next((f for f in rp.findings if f["kind"] == "crossref_summary"), None)
    none = next((f for f in rp.findings if f["kind"] == "crossref_none"), None)
    items = [f for f in rp.findings if f["kind"] == "crossref_item"]
    more = next((f for f in rp.findings if f["kind"] == "crossref_more"), None)
    tel = [f for f in rp.findings if f["kind"].startswith("telecom_") and B._v(f).get("return_count", 0) >= 2]
    L = [f"# {rp.case.name} - cross-return analysis", "", DRAFT_SHORT, "",
         f"Prepared {utc_now_str()} by Spoor {__version__}. Back to the [analysis](REPORT.md). Only overlaps are on this page; "
         "checks that found nothing are in Appendix A of the analysis.", "",
         "## Returns compared", ""]
    L += [f"- **{r['label']}** {md_escape(r['name'])} - {', '.join(r['labels'][:6])}{' ...' if len(r['labels']) > 6 else ''}; {fmt_int(r['records'])} records"
          for r in act]
    out = [r for r in rows if r["state"] == "excluded"]
    if out:
        L += ["", "Left out by the analyst (not compared): " + ", ".join(f"{r['label']} {md_escape(r['name'])}" for r in out)]
    L.append("")
    if not summ:
        L += ["## Result", "", (B.first_sentence(none["statement"], 700) + f" {refs.cite([none['fid']])}") if none else "No cross-return analysis was produced.", ""]
    else:
        v = B._v(summ)
        L += ["## Overview", "", f"{B.first_sentence(summ['statement'], 900)} {refs.cite([summ['fid']])}", ""]
        for t in (summ["facts"].get("tables") or []):
            cols, rws = t["columns"], t["rows"]
            L += [f"**{t['title']}**", "", "| " + " | ".join(cols) + " |", "| " + " | ".join("---" for _ in cols) + " |"]
            L += ["| " + " | ".join(md_escape("" if c is None else str(c)) for c in r) + " |" for r in rws]
            if t.get("total_rows", len(rws)) > len(rws):
                L.append(f"\n{t['total_rows'] - len(rws)} more pairs in exports/crossref.csv.")
            L.append("")
        npairs = v.get("pairs_without_overlap") or []
        if npairs:
            L += [f"{len(npairs)} of {v.get('pairs_compared')} pairs share nothing: {', '.join(npairs[:40])}{' ...' if len(npairs) > 40 else ''}.", ""]
        L += ["## Items present in more than one return", "", "Strongest first (most returns, then most records).", ""]
        for f in items:
            iv = B._v(f)
            L += [f"### {md_escape(f['title'])}", "", f"{B.first_sentence(f['statement'], 600)} {refs.cite([f['fid']])}", ""]
            for t in (f["facts"].get("tables") or []):
                cols, rws = t["columns"], t["rows"]
                L += ["| " + " | ".join(cols) + " |", "| " + " | ".join("---" for _ in cols) + " |"]
                L += ["| " + " | ".join(md_escape("" if c is None else str(c)) for c in r) + " |" for r in rws] + [""]
        if more:
            L += [f"### Further items", "", f"{B.first_sentence(more['statement'], 300)} {refs.cite([more['fid']])}", ""]
    if tel:
        L += ["## Calls, texts and cell sites seen in more than one return", ""]
        L += [f"- {B.brief(f, True)} {refs.cite([f['fid']])}" for f in tel] + [""]
    L += ["## References", "", "Each reference is a finding; the lines are the first and last records in each return. "
          "[EVIDENCE.md](EVIDENCE.md) quotes them verbatim.", ""]
    L += bibliography(rp, refs, src_info_map(rp))
    p.write_text("\n".join(L) + "\n", encoding="utf-8")
    return p
