"""AI-drafted summary: the local model writes sentences from the findings; every sentence is
verified (verify.py) before it may appear in the report. Sections already drafted are kept when
a run resumes, as long as the findings have not changed."""
from __future__ import annotations

import json

from . import db as dbm
from .config import load_settings
from .findings import CATEGORY_ORDER
from .llm import LLM, LLMError, parse_json
from .util import utc_now_str
from .verify import FactBase, check_sentence, items_from_findings

SCHEMA = {"type": "object", "properties": {"sentences": {"type": "array", "items": {
    "type": "object", "properties": {"text": {"type": "string"}, "cites": {"type": "array", "items": {"type": "string"}}},
    "required": ["text", "cites"]}}}, "required": ["sentences"]}

SYSTEM = """You draft part of an investigator's analysis report. You may ONLY restate facts that appear in the findings provided.
Rules:
1. Use only facts stated in the findings. Add no background, motives, identities, locations, opinions or conclusions.
2. Copy every IP address, account name, identifier, timestamp and number exactly as written in the findings. Timestamps are UTC; keep them as given. Do not convert time zones, round, add, subtract or compute new numbers or percentages.
3. Every sentence must cite the IDs of the findings it uses, e.g. "cites": ["F012"]. Cite only IDs from the list provided.
4. Each sentence must contain at least one specific value (a number, timestamp, IP, account, identifier or name) taken from the findings.
5. Do not speculate (no "likely", "suggests", "appears", "may", "indicates") and do not characterise people or events (no "attacker", "compromised", "fraud", "suspect", "takeover").
6. If you are not sure a sentence is supported word for word, leave it out. Fewer sentences are better than unsupported ones.
Reply with JSON only: {"sentences": [{"text": "...", "cites": ["F001"]}]}"""

USER = """Section: {section}
Write at most {n} short sentences covering the most important points of these findings for an investigator.

Findings (JSON):
{facts}"""

RETRY = """Some of your sentences failed automatic verification because a value in them does not appear in the findings they cite:
{fails}
Write the section again. Copy values exactly from the findings, cite the right finding IDs, and leave out anything you cannot copy exactly."""


def compact(findings: list[dict], budget: int = 12000) -> str:
    def build(rows_per_table, with_tables=True, limit=None):
        out = []
        for f in findings[:limit]:
            facts = f["facts"]
            vals = {k: v for k, v in (facts.get("values") or {}).items() if v not in (None, "", [], {})}
            item = {"id": f["fid"], "title": f["title"], "statement": f["statement"], "values": vals}
            if with_tables:
                tabs = []
                for t in list(facts.get("tables") or []) + ([{"title": "", "columns": facts["columns"], "rows": facts.get("rows", [])}]
                                                            if facts.get("columns") else []):
                    tabs.append({"title": t.get("title"), "columns": t.get("columns"), "rows": (t.get("rows") or [])[:rows_per_table]})
                if tabs:
                    item["tables"] = tabs
            out.append(item)
        return json.dumps(out, ensure_ascii=False, default=str)
    for rows, tabs, lim in ((6, True, None), (3, True, None), (0, False, None), (0, False, 25), (0, False, 12)):
        s = build(rows, tabs, lim)
        if len(s) <= budget:
            return s
    return s[:budget]


def build_sections(findings: list[dict], con, n_accounts: int) -> list[tuple[str, list[dict]]]:
    secs = []
    p1 = [f for f in findings if f["priority"] == 1][:30]
    if p1:
        secs.append(("Overview of priority findings", p1))
    for cat in CATEGORY_ORDER:
        if cat == "Sources & data quality":
            continue
        fs = [f for f in findings if f["category"] == cat and f["priority"] <= 2][:30]
        if fs:
            secs.append((cat, fs))
    if n_accounts > 0:
        accs = [r["account"] for r in dbm.rows(con, "SELECT account FROM account_summary WHERE events >= 20 ORDER BY events DESC LIMIT ?",
                                               (n_accounts,))]
        for acc in accs:
            al = acc.lower()
            fs = [f for f in findings if f["category"] != "Sources & data quality" and
                  (str((f["facts"].get("values") or {}).get("account", "")).lower() == al or al in f["statement"].lower())][:20]
            if fs:
                secs.append((f"Account profile: {acc}", fs))
    return secs


def run_narrative(case, con, prog, log, accounts: int = 10) -> dict:
    settings = load_settings()
    cfg = settings["llm"]
    if not cfg.get("enabled", True):
        prog.message("AI summary disabled in settings")
        return {"skipped": "disabled in settings"}
    llm = LLM(cfg, con, prog.job_id)
    st = llm.status()
    if not st["ok"]:
        prog.message(f"AI summary skipped: {st['error']}")
        return {"skipped": st["error"]}
    try:
        model = llm.resolve_model()
    except LLMError as e:
        prog.message(f"AI summary skipped: {e}")
        return {"skipped": str(e)}
    findings = dbm.rows(con, "SELECT * FROM findings WHERE fid IS NOT NULL ORDER BY fid")
    for f in findings:
        f["facts"] = json.loads(f["facts"]) if f["facts"] else {}
    fb = FactBase(items_from_findings(findings))
    known = {r[0] for r in con.execute("SELECT account FROM account_summary LIMIT 50000")}
    sections = build_sections(findings, con, accounts)
    done = {r["section"] for r in dbm.rows(con, "SELECT section FROM narrative_sections WHERE status='done'")}
    maxn = int(case.params.get("llm_max_sentences", 8))
    prog.set_total(len(sections), "sections")
    for i, (name, fs) in enumerate(sections):
        if name in done:
            prog.update(i + 1)
            continue
        prog.check_cancel()
        ids = {f["fid"] for f in fs}
        facts = compact(fs)
        msgs = [{"role": "system", "content": SYSTEM},
                {"role": "user", "content": USER.format(section=name, n=maxn, facts=facts)}]
        best = None
        attempts = []
        for attempt in (1, 2):
            prog.message(f"Drafting '{name}' with {model} (attempt {attempt}) - CPU models can take several minutes per section")
            try:
                reply = llm.chat(msgs, schema=SCHEMA, purpose="narrative")
                data = parse_json(reply)
                sents = [s for s in (data.get("sentences") or []) if isinstance(s, dict) and s.get("text")][:maxn]
            except LLMError as e:
                log.warning("narrative %s attempt %s: %s", name, attempt, e)
                sents = []
            results = []
            for s in sents:
                status, reasons, flags, cited = check_sentence(str(s.get("text")), s.get("cites") or [], fb, known, ids)
                results.append({"text": str(s.get("text")).strip(), "cites": cited or [str(c) for c in (s.get("cites") or [])],
                                "status": status, "reasons": reasons, "flags": flags, "attempt": attempt})
            attempts.append(results)
            ok = sum(1 for r in results if r["status"] != "rejected")
            if best is None or ok > best[0]:
                best = (ok, results)
            if attempt == 1 and results and ok < len(results):
                fails = "\n".join(f"- \"{r['text']}\" -> {'; '.join(r['reasons'])}" for r in results if r["status"] == "rejected")
                msgs = msgs + [{"role": "assistant", "content": reply}, {"role": "user", "content": RETRY.format(fails=fails)}]
                continue
            break
        results = list(best[1]) if best else []
        # the rejected sentences of the other attempt are kept too, for the review list
        for other in attempts:
            if best and other is not best[1]:
                results += [r for r in other if r["status"] == "rejected"]
        con.execute("DELETE FROM narrative WHERE section=?", (name,))
        for k, r in enumerate(results):
            con.execute("INSERT INTO narrative(section, ord, text, cites, status, reasons, flags, attempt, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                        (name, i * 100 + k, r["text"], json.dumps(r["cites"]), r["status"], json.dumps(r["reasons"]),
                         json.dumps(r["flags"]), r["attempt"], utc_now_str()))
        con.execute("INSERT OR REPLACE INTO narrative_sections(section, status, accepted, rejected, flagged, finished_at) VALUES (?,?,?,?,?,?)",
                    (name, "done", sum(r["status"] == "accepted" for r in results), sum(r["status"] == "rejected" for r in results),
                     sum(r["status"] == "flagged" for r in results), utc_now_str()))
        con.commit()
        prog.update(i + 1)
    tot = dbm.rows(con, "SELECT status, COUNT(*) AS n FROM narrative GROUP BY status")
    counts = {r["status"]: r["n"] for r in tot}
    meta = {"model": model, "digest": llm.digest(model), "generated_at": utc_now_str(),
            "accepted": counts.get("accepted", 0) + counts.get("flagged", 0), "flagged": counts.get("flagged", 0),
            "rejected": counts.get("rejected", 0), "sections": len(sections)}
    dbm.set_meta(con, "narrative", meta)
    con.commit()
    case.audit(con, "narrative_generated", meta)
    return meta
