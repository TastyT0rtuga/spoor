"""Ask a question in plain English. The local model writes ONE read-only SQL query; the answer
is the query's own result rows (with citations). Any short summary the model writes about the
rows is verified against them like the report narrative. The database is opened read-only and
an authoriser blocks everything except reading."""
from __future__ import annotations

import json
import re
import sqlite3
import time
from pathlib import Path

from . import db as dbm
from .config import load_settings
from .llm import LLM, LLMError, parse_json
from .util import md_code, md_escape, utc_now_str
from .verify import FactBase, check_sentence

SCHEMA_DOC = """SQLite database of subpoena-return records. Read-only. Tables and views:
ev(id, cite, source, ts_utc, ts_raw, tz_basis, ts_flag, ip, ip_class, port, account, category, action, status, user_agent, device, location, counterparty, direction, amount, currency, raw)
  - one row per record. cite = citation like 'S03:L1842'. ts_utc = 'YYYY-MM-DD HH:MM:SS' in UTC (date-only values are 'YYYY-MM-DD').
  - category is one of: login, login_failed, logout, account_change, registration, communication, transaction, other.
  - ip_class is one of: public, private, cgnat, loopback, link-local, multicast, documentation, reserved, nat64.
  - action = the provider's own event text; raw = the verbatim record text.
ids(kind, value, validity, cite, source, ts_utc, account)
  - identifiers found in records. kind: email, phone (E.164 like +17035550142), btc, eth (lower-case), ltc, trx, doge, xmr, mac, imei, imsi, url, ipv4, ipv6.
ip_summary(ip, ip_ver, ip_class, subnet, events, accounts, sources, first_utc, last_utc, ports, asn, as_org, country)
ip_accounts(ip, account, events, first_utc, last_utc)
account_summary(account, events, sources, logins, failures, logouts, changes, ips, public_ips, user_agents, first_utc, last_utc)
src(source, file, kind, sha256, rows)
fnd(fid, category, title, statement)   -- the report's findings
calls(id, cite, source, ts_utc, target, other, dir, kind, duration_s, cell, cell_last, lat, lon, azimuth, site_name, loc_basis, loc_cite, imei, imsi, raw)
  - one row per call / text / data session from telecom returns (call detail records). target and other are phone numbers in
    E.164 (+17035550101) when they are North American or written with '+', otherwise digits. dir is 'out' or 'in' (from the
    target's side); kind is voice, sms, mms, data or other; duration_s in seconds; cell = first cell/sector ID;
    lat/lon = that cell site's coordinates and loc_cite the tower-list row they came from.
"""

RULES = """Write ONE SQLite SELECT statement that answers the question.
- Only SELECT (or WITH ... SELECT). Never modify anything.
- When returning individual records, include the cite column and ts_utc, and ORDER BY ts_utc.
- When aggregating, include MIN(cite) AS example_cite, and MIN(ts_utc)/MAX(ts_utc) where useful.
- Match accounts, emails and actions case-insensitively (LIKE or lower()). Compare times as text: ts_utc >= '2024-03-01' AND ts_utc < '2024-04-01'.
- Times in questions are UTC unless stated; if a timezone is stated, convert it to UTC in your WHERE clause and say so in "explanation".
- Return at most 500 rows (use LIMIT).
Reply with JSON only: {"sql": "...", "explanation": "one sentence on what the query does"}"""

EXAMPLES = [
    ("Which IPs did jdoe log in from in March 2024?",
     "SELECT ip, COUNT(*) AS logins, MIN(ts_utc) AS first_utc, MAX(ts_utc) AS last_utc, MIN(cite) AS example_cite FROM ev "
     "WHERE lower(account) LIKE '%jdoe%' AND category = 'login' AND ts_utc >= '2024-03-01' AND ts_utc < '2024-04-01' "
     "GROUP BY ip ORDER BY logins DESC LIMIT 500"),
    ("Show everything from 159.89.214.31",
     "SELECT cite, ts_utc, account, category, action, port FROM ev WHERE ip = '159.89.214.31' ORDER BY ts_utc LIMIT 500"),
    ("Which accounts share an IP address?",
     "SELECT a.ip, a.account AS account_a, b.account AS account_b, a.events AS events_a, b.events AS events_b FROM ip_accounts a "
     "JOIN ip_accounts b ON a.ip = b.ip AND a.account < b.account ORDER BY a.ip LIMIT 500"),
    ("Which numbers did both +17035550101 and +15715550102 call or text?",
     "SELECT other, COUNT(*) AS records, COUNT(DISTINCT target) AS targets, MIN(ts_utc) AS first_utc, MAX(ts_utc) AS last_utc, "
     "MIN(cite) AS example_cite FROM calls WHERE target IN ('+17035550101', '+15715550102') AND other IS NOT NULL GROUP BY other "
     "HAVING COUNT(DISTINCT target) = 2 ORDER BY records DESC LIMIT 500"),
    ("Where does the bitcoin address bc1qexample appear?",
     "SELECT cite, source, ts_utc, account, value FROM ids WHERE kind = 'btc' AND value = 'bc1qexample' ORDER BY ts_utc LIMIT 500"),
]

SUMMARY_SYSTEM = """You summarise SQL query results for an investigator. Use ONLY values that appear in the result rows.
Copy values exactly; do not compute new numbers; no speculation; no characterisation of people.
Cite the rows you use as R1, R2, ... Reply with JSON only: {"sentences": [{"text": "...", "cites": ["R1"]}]} (at most 3 sentences)."""

_ALLOWED_ACTIONS = {getattr(sqlite3, n, v) for n, v in (("SQLITE_SELECT", 21), ("SQLITE_READ", 20), ("SQLITE_FUNCTION", 31),
                                                       ("SQLITE_RECURSIVE", 33))}
_BLOCKED_FUNCS = {"load_extension", "readfile", "writefile", "edit", "fts3_tokenizer", "zipfile", "sqlar_compress"}


def _authorizer(action, arg1, arg2, dbname, source):
    if action in _ALLOWED_ACTIONS:
        if action == 31 and (arg2 or "").lower() in _BLOCKED_FUNCS:
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK
    return sqlite3.SQLITE_DENY


def run_readonly(db_path: Path, sql: str, limit: int = 500, timeout_s: float = 120) -> tuple[list[str], list[list], bool]:
    s = sql.strip().rstrip(";").strip()
    if not re.match(r"(?is)^(select|with)\b", s):
        raise ValueError("only SELECT queries are allowed")
    con = dbm.connect(db_path, readonly=True)
    try:
        con.execute("PRAGMA query_only=ON")
        con.set_authorizer(_authorizer)
        t0 = time.time()
        con.set_progress_handler(lambda: 1 if time.time() - t0 > timeout_s else 0, 100000)
        cur = con.execute(s)
        cols = [d[0] for d in cur.description or []]
        rows = [list(r) for r in cur.fetchmany(limit + 1)]
        trunc = len(rows) > limit
        return cols, rows[:limit], trunc
    finally:
        con.close()


def _ask_sql(llm: LLM, question: str, error: str | None = None, prev_sql: str | None = None) -> dict:
    msgs = [{"role": "system", "content": SCHEMA_DOC + "\n" + RULES}]
    for q, a in EXAMPLES:
        msgs += [{"role": "user", "content": q}, {"role": "assistant", "content": json.dumps({"sql": a, "explanation": ""})}]
    msgs.append({"role": "user", "content": question})
    if error:
        msgs += [{"role": "assistant", "content": json.dumps({"sql": prev_sql, "explanation": ""})},
                 {"role": "user", "content": f"That query failed: {error}. Write a corrected query."}]
    reply = llm.chat(msgs, schema={"type": "object", "properties": {"sql": {"type": "string"}, "explanation": {"type": "string"}},
                                   "required": ["sql"]}, purpose="sql")
    return parse_json(reply)


def run_ask(case, con, ask_id: int, prog=None, log=None) -> dict:
    a = dbm.rows(con, "SELECT * FROM asks WHERE id=?", (ask_id,))[0]
    q = a["question"]
    llm = LLM(load_settings()["llm"], con, prog.job_id if prog else None)
    con.execute("UPDATE asks SET status='running' WHERE id=?", (ask_id,))
    con.commit()
    try:
        model = llm.resolve_model("sql")
        sql, expl, err, cols, rows, trunc = None, "", None, [], [], False
        for attempt in range(3):
            if prog:
                prog.message(f"Writing the query with {model} (attempt {attempt + 1})")
            d = _ask_sql(llm, q, err, sql)
            sql = (d.get("sql") or "").strip()
            expl = d.get("explanation") or ""
            try:
                cols, rows, trunc = run_readonly(case.db_path, sql)
                err = None
                break
            except Exception as e:  # noqa: BLE001
                err = f"{type(e).__name__}: {e}"
        if err:
            raise ValueError(f"the model could not write a working query ({err})")
        summary = []
        if rows:
            if prog:
                prog.message("Summarising the result rows (verified)")
            def trim(v):
                return v[:200] if isinstance(v, str) else v
            items = [{"id": f"R{i + 1}", "title": "", "statement": "", "values": {c: trim(v) for c, v in zip(cols, r)}}
                     for i, r in enumerate(rows[:25])]
            fb = FactBase(items)
            show = [{"row": f"R{i + 1}", **{c: trim(v) for c, v in zip(cols, r)}} for i, r in enumerate(rows[:25])]
            try:
                reply = llm.chat([{"role": "system", "content": SUMMARY_SYSTEM},
                                  {"role": "user", "content": f"Question: {q}\nRows ({len(rows)} total{', truncated' if trunc else ''}):\n"
                                                              + json.dumps(show, ensure_ascii=False, default=str)}],
                                 schema={"type": "object", "properties": {"sentences": {"type": "array"}}}, purpose="ask_summary")
                for s in (parse_json(reply).get("sentences") or [])[:3]:
                    if not isinstance(s, dict) or not s.get("text"):
                        continue
                    st, reasons, flags, cited = check_sentence(str(s["text"]), s.get("cites") or [], fb, None, {it["id"] for it in items})
                    summary.append({"text": s["text"], "cites": cited, "status": st, "reasons": reasons, "flags": flags})
            except LLMError as e:
                summary.append({"text": "", "status": "rejected", "reasons": [f"summary failed: {e}"], "flags": []})
        con.execute("UPDATE asks SET status='done', sql=?, explanation=?, columns=?, rows=?, row_count=?, truncated=?, summary=?, model=?, "
                    "finished_at=? WHERE id=?",
                    (sql, expl, json.dumps(cols), json.dumps(rows, default=str), len(rows), int(trunc), json.dumps(summary), model,
                     utc_now_str(), ask_id))
        con.commit()
        case.audit(con, "ask_answered", {"ask": ask_id, "question": q, "sql": sql, "rows": len(rows)})
        write_ask_md(case, con, ask_id)
        return {"ask": ask_id, "rows": len(rows)}
    except Exception as e:  # noqa: BLE001
        con.execute("UPDATE asks SET status='error', error=?, finished_at=? WHERE id=?", (f"{type(e).__name__}: {e}", utc_now_str(), ask_id))
        con.commit()
        raise


def write_ask_md(case, con, ask_id: int) -> Path:
    a = dbm.rows(con, "SELECT * FROM asks WHERE id=?", (ask_id,))[0]
    cols = json.loads(a["columns"] or "[]")
    rows = json.loads(a["rows"] or "[]")
    summ = json.loads(a["summary"] or "[]")
    d = case.report_dir / "questions"
    d.mkdir(parents=True, exist_ok=True)
    L = [f"# Q{ask_id:03d} — {md_escape(a['question'])}", "", f"Asked {a['created_at']}; answered {a['finished_at']} with `{a['model']}`.", "",
         "> The answer is the result of the query below, run read-only against the case database. Re-run it to reproduce. "
         "The model's summary sentences were verified against the rows; rejected ones are not shown as answers.", ""]
    ok = [s for s in summ if s.get("status") != "rejected" and s.get("text")]
    if ok:
        L += ["## Summary (verified against the rows)", ""]
        for s in ok:
            L.append(f"- {'⚑ ' if s['status'] == 'flagged' else ''}{s['text']} ({', '.join(s.get('cites') or [])})")
        L.append("")
    L += ["## Query", "", "```sql", a["sql"] or "", "```", "", f"{a['explanation'] or ''}", "",
          f"## Result ({a['row_count']} rows{', truncated at 500' if a['truncated'] else ''})", ""]
    if cols:
        L.append("| # | " + " | ".join(md_escape(c) for c in cols) + " |")
        L.append("|---|" + "|".join("---" for _ in cols) + "|")
        for i, r in enumerate(rows[:500], 1):
            L.append(f"| R{i} | " + " | ".join(md_code(v) if c in ("cite", "example_cite") and v else md_escape(v) for c, v in zip(cols, r)) + " |")
    rej = [s for s in summ if s.get("status") == "rejected" and s.get("text")]
    if rej:
        L += ["", "## Summary sentences removed by verification", ""]
        for s in rej:
            L.append(f"- ~~{md_escape(s['text'])}~~ — {'; '.join(s.get('reasons') or [])}")
    p = d / f"Q{ask_id:03d}.md"
    p.write_text("\n".join(L) + "\n", encoding="utf-8")
    return p
