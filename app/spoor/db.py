"""SQLite schema (WAL mode: the dashboard reads while the worker writes) and small helpers."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from .util import utc_now_str

SCHEMA = r"""
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);

CREATE TABLE IF NOT EXISTS sources (
  id INTEGER PRIMARY KEY,
  label TEXT UNIQUE,
  path TEXT NOT NULL,
  display TEXT,
  parent_id INTEGER,
  member TEXT,
  kind TEXT,
  size INTEGER,
  mtime TEXT,
  sha256 TEXT,
  hashed_at TEXT,
  recheck_sha256 TEXT,
  rechecked_at TEXT,
  status TEXT DEFAULT 'new',
  config TEXT,
  config_rev INTEGER DEFAULT 0,
  ingested_rev INTEGER,
  scan TEXT,
  rows INTEGER DEFAULT 0,
  stats TEXT,
  checkpoint TEXT,
  error TEXT,
  added_at TEXT,
  ingested_at TEXT
);

CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY,
  source_id INTEGER NOT NULL,
  seq INTEGER NOT NULL,
  tbl TEXT,
  loc TEXT NOT NULL,
  line INTEGER,
  byte_offset INTEGER,
  byte_len INTEGER,
  ts_utc TEXT,
  ts_epoch REAL,
  ts_raw TEXT,
  tz_basis TEXT,
  ts_flag TEXT,
  ip TEXT,
  ip_ver INTEGER,
  ip_class TEXT,
  port INTEGER,
  subnet TEXT,
  ip_raw TEXT,
  account TEXT,
  account_basis TEXT,
  action TEXT,
  category TEXT,
  status TEXT,
  user_agent TEXT,
  device TEXT,
  location TEXT,
  counterparty TEXT,
  direction TEXT,
  amount REAL,
  currency TEXT,
  raw TEXT,
  extra TEXT
);

CREATE TABLE IF NOT EXISTS identifiers (
  id INTEGER PRIMARY KEY,
  event_id INTEGER NOT NULL,
  source_id INTEGER NOT NULL,
  kind TEXT,
  value TEXT,
  norm TEXT,
  validity TEXT
);

CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY,
  fid TEXT,
  module TEXT,
  category TEXT,
  kind TEXT,
  title TEXT,
  statement TEXT,
  priority INTEGER,
  sort_key TEXT,
  facts TEXT,
  sql TEXT,
  export TEXT,
  evidence_count INTEGER,
  created_at TEXT
);
CREATE TABLE IF NOT EXISTS finding_evidence (
  finding_id INTEGER, event_id INTEGER, role TEXT, PRIMARY KEY (finding_id, event_id)
);
CREATE TABLE IF NOT EXISTS finding_cites (
  finding_id INTEGER, cite TEXT, source_id INTEGER, loc TEXT, text TEXT, expect TEXT
);

CREATE TABLE IF NOT EXISTS ip_enrich (ip TEXT PRIMARY KEY, asn INTEGER, as_org TEXT, country TEXT, db TEXT);
CREATE TABLE IF NOT EXISTS ip_summary (
  ip TEXT PRIMARY KEY, ip_ver INTEGER, ip_class TEXT, subnet TEXT, events INTEGER, accounts INTEGER,
  sources INTEGER, first_utc TEXT, last_utc TEXT, ports INTEGER, asn INTEGER, as_org TEXT, country TEXT
);
CREATE TABLE IF NOT EXISTS ip_accounts (
  ip TEXT, account TEXT, events INTEGER, first_utc TEXT, last_utc TEXT, first_id INTEGER, last_id INTEGER,
  PRIMARY KEY (ip, account)
);
CREATE TABLE IF NOT EXISTS account_summary (
  account TEXT PRIMARY KEY, events INTEGER, sources INTEGER, logins INTEGER, failures INTEGER, logouts INTEGER,
  changes INTEGER, ips INTEGER, public_ips INTEGER, user_agents INTEGER, first_utc TEXT, last_utc TEXT
);
CREATE TABLE IF NOT EXISTS ident_summary (
  kind TEXT, norm TEXT, validity TEXT, events INTEGER, sources INTEGER, accounts INTEGER, first_utc TEXT,
  last_utc TEXT, PRIMARY KEY (kind, norm)
);

CREATE TABLE IF NOT EXISTS jobs (
  id INTEGER PRIMARY KEY,
  kind TEXT,
  params TEXT,
  status TEXT,
  pid INTEGER,
  created_at TEXT,
  started_at TEXT,
  finished_at TEXT,
  heartbeat REAL,
  stage TEXT,
  stage_no INTEGER,
  stage_total INTEGER,
  stages TEXT,
  done REAL,
  total REAL,
  unit TEXT,
  rate REAL,
  eta_s REAL,
  message TEXT,
  cancel INTEGER DEFAULT 0,
  error TEXT,
  stages_done TEXT,
  result TEXT
);

CREATE TABLE IF NOT EXISTS llm_calls (
  id INTEGER PRIMARY KEY, job_id INTEGER, purpose TEXT, model TEXT, model_digest TEXT, options TEXT,
  prompt TEXT, response TEXT, started_at TEXT, seconds REAL, ok INTEGER, error TEXT
);
CREATE TABLE IF NOT EXISTS narrative (
  id INTEGER PRIMARY KEY, section TEXT, ord INTEGER, text TEXT, cites TEXT, status TEXT, reasons TEXT,
  flags TEXT, llm_call_id INTEGER, attempt INTEGER, created_at TEXT
);
CREATE TABLE IF NOT EXISTS narrative_sections (
  section TEXT PRIMARY KEY, status TEXT, accepted INTEGER, rejected INTEGER, flagged INTEGER, finished_at TEXT
);
CREATE TABLE IF NOT EXISTS asks (
  id INTEGER PRIMARY KEY, question TEXT, status TEXT, sql TEXT, explanation TEXT, columns TEXT, rows TEXT,
  row_count INTEGER, truncated INTEGER, summary TEXT, error TEXT, model TEXT, job_id INTEGER,
  created_at TEXT, finished_at TEXT
);
CREATE TABLE IF NOT EXISTS citation_checks (
  id INTEGER PRIMARY KEY, run_at TEXT, cite TEXT, source_id INTEGER, event_id INTEGER, status TEXT, detail TEXT
);
CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY, at TEXT, action TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS figures (
  no INTEGER PRIMARY KEY, slug TEXT, title TEXT, file TEXT, status TEXT, reason TEXT, caption TEXT, sha256 TEXT,
  notes TEXT, data_sql TEXT, caps TEXT, meta TEXT, warnings TEXT, created_at TEXT
);
CREATE TABLE IF NOT EXISTS figure_refs (figure_no INTEGER, ord INTEGER, marker TEXT, fid TEXT, shows TEXT, cite TEXT);

CREATE VIEW IF NOT EXISTS ev AS
  SELECT e.id, s.label || ':' || e.loc AS cite, s.label AS source, e.ts_utc, e.ts_raw, e.tz_basis, e.ts_flag,
         e.ip, e.ip_class, e.port, e.account, e.category, e.action, e.status, e.user_agent, e.device,
         e.location, e.counterparty, e.direction, e.amount, e.currency, e.raw
  FROM events e JOIN sources s ON s.id = e.source_id;
CREATE VIEW IF NOT EXISTS ids AS
  SELECT i.kind, i.norm AS value, i.validity, s.label || ':' || e.loc AS cite, s.label AS source,
         e.ts_utc, e.account
  FROM identifiers i JOIN events e ON e.id = i.event_id JOIN sources s ON s.id = i.source_id
  UNION ALL
  SELECT CASE e.ip_ver WHEN 6 THEN 'ipv6' ELSE 'ipv4' END, e.ip, 'format', s.label || ':' || e.loc, s.label,
         e.ts_utc, e.account
  FROM events e JOIN sources s ON s.id = e.source_id WHERE e.ip IS NOT NULL;
CREATE VIEW IF NOT EXISTS src AS
  SELECT label AS source, display AS file, kind, sha256, rows FROM sources WHERE status = 'ingested';
CREATE VIEW IF NOT EXISTS fnd AS
  SELECT fid, category, title, statement FROM findings WHERE fid IS NOT NULL;
"""

INDEXES = [
    "CREATE INDEX IF NOT EXISTS ix_ev_source ON events(source_id, seq)",
    "CREATE INDEX IF NOT EXISTS ix_ev_ts ON events(ts_epoch)",
    "CREATE INDEX IF NOT EXISTS ix_ev_ip ON events(ip)",
    "CREATE INDEX IF NOT EXISTS ix_ev_account ON events(account, ts_epoch)",
    "CREATE INDEX IF NOT EXISTS ix_ev_cat ON events(category)",
    "CREATE INDEX IF NOT EXISTS ix_id_norm ON identifiers(norm)",
    "CREATE INDEX IF NOT EXISTS ix_id_event ON identifiers(event_id)",
    "CREATE INDEX IF NOT EXISTS ix_fe_event ON finding_evidence(event_id)",
]
SOURCE_INDEXES = ["CREATE INDEX IF NOT EXISTS ix_ev_source ON events(source_id, seq)",
                  "CREATE INDEX IF NOT EXISTS ix_id_event ON identifiers(event_id)"]


def connect(path, readonly: bool = False) -> sqlite3.Connection:
    p = Path(path)
    if readonly:
        con = sqlite3.connect(p.resolve().as_uri() + "?mode=ro", uri=True, timeout=60, check_same_thread=False)
    else:
        con = sqlite3.connect(str(p), timeout=60, check_same_thread=False)
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA synchronous=NORMAL")
    con.execute("PRAGMA busy_timeout=60000")
    con.execute("PRAGMA cache_size=-131072")
    con.execute("PRAGMA temp_store=FILE")
    con.row_factory = sqlite3.Row
    return con


SCHEMA_VERSION = 2


def init(con: sqlite3.Connection) -> None:
    con.executescript(SCHEMA)
    r = con.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
    if not r or r[0] != str(SCHEMA_VERSION):
        for v in ("ev", "ids", "src", "fnd"):
            con.execute(f"DROP VIEW IF EXISTS {v}")
        con.executescript(SCHEMA)
        con.execute("INSERT OR REPLACE INTO meta(key, value) VALUES ('schema_version', ?)", (str(SCHEMA_VERSION),))
    for ix in SOURCE_INDEXES:
        con.execute(ix)
    con.commit()


def fts_available(con: sqlite3.Connection) -> bool:
    try:
        con.execute("CREATE VIRTUAL TABLE IF NOT EXISTS temp._fts_probe USING fts5(x)")
        con.execute("DROP TABLE IF EXISTS temp._fts_probe")
        return True
    except sqlite3.OperationalError:
        return False


def get_meta(con, key, default=None):
    r = con.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    if not r:
        return default
    try:
        return json.loads(r[0])
    except (ValueError, TypeError):
        return r[0]


def set_meta(con, key, value) -> None:
    con.execute("INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, json.dumps(value, default=str)))


def audit(con, action: str, detail, log_path: Path | None = None) -> None:
    d = json.dumps(detail, default=str, ensure_ascii=False) if not isinstance(detail, str) else detail
    at = utc_now_str()
    con.execute("INSERT INTO audit(at, action, detail) VALUES (?,?,?)", (at, action, d))
    con.commit()
    if log_path is not None:
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps({"at": at, "action": action, "detail": detail}, default=str, ensure_ascii=False) + "\n")
        except OSError:
            pass


def rows(con, sql: str, params=()) -> list[dict]:
    return [dict(r) for r in con.execute(sql, params).fetchall()]


def one(con, sql: str, params=()):
    r = con.execute(sql, params).fetchone()
    return r[0] if r else None
