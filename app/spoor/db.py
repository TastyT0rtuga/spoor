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
  ingested_at TEXT,
  return_id INTEGER
);

CREATE TABLE IF NOT EXISTS returns (
  id INTEGER PRIMARY KEY,
  label TEXT UNIQUE,
  name TEXT,
  root TEXT,
  state TEXT DEFAULT 'active',
  note TEXT,
  added_at TEXT,
  state_at TEXT
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
CREATE TABLE IF NOT EXISTS tel (
  event_id INTEGER PRIMARY KEY, source_id INTEGER, target TEXT, target_basis TEXT, other TEXT, other_raw TEXT,
  dir TEXT, kind TEXT, ts_epoch REAL, ts_utc TEXT, duration_s REAL, cell TEXT, cell_last TEXT, eci INTEGER, enb INTEGER,
  lat REAL, lon REAL, azimuth REAL, beamwidth REAL, site_name TEXT, loc_basis TEXT, loc_event_id INTEGER,
  imei TEXT, imsi TEXT, dev_lat REAL, dev_lon REAL, dev_conf TEXT, src_kind TEXT, section TEXT, note TEXT, loc_ref TEXT
);
CREATE TABLE IF NOT EXISTS cell_sites (
  id INTEGER PRIMARY KEY, cell TEXT, source_id INTEGER, event_id INTEGER, origin TEXT, site_name TEXT,
  lat REAL, lon REAL, azimuth REAL, beamwidth REAL, eci INTEGER, enb INTEGER
);
CREATE TABLE IF NOT EXISTS figure_refs (figure_no INTEGER, ord INTEGER, marker TEXT, fid TEXT, shows TEXT, cite TEXT);

CREATE VIEW IF NOT EXISTS ev AS
  SELECT e.id, s.label || ':' || e.loc AS cite, s.label AS source, r.label AS ret, e.ts_utc, e.ts_raw, e.tz_basis, e.ts_flag,
         e.ip, e.ip_class, e.port, e.account, e.category, e.action, e.status, e.user_agent, e.device,
         e.location, e.counterparty, e.direction, e.amount, e.currency, e.raw
  FROM events e JOIN sources s ON s.id = e.source_id LEFT JOIN returns r ON r.id = s.return_id;
CREATE VIEW IF NOT EXISTS ids AS
  SELECT i.kind, i.norm AS value, i.validity, s.label || ':' || e.loc AS cite, s.label AS source, r.label AS ret,
         e.ts_utc, e.account
  FROM identifiers i JOIN events e ON e.id = i.event_id JOIN sources s ON s.id = i.source_id
       LEFT JOIN returns r ON r.id = s.return_id
  UNION ALL
  SELECT CASE e.ip_ver WHEN 6 THEN 'ipv6' ELSE 'ipv4' END, e.ip, 'format', s.label || ':' || e.loc, s.label, r.label,
         e.ts_utc, e.account
  FROM events e JOIN sources s ON s.id = e.source_id LEFT JOIN returns r ON r.id = s.return_id WHERE e.ip IS NOT NULL;
CREATE VIEW IF NOT EXISTS src AS
  SELECT s.label AS source, r.label AS ret, s.display AS file, s.kind, s.sha256, s.rows
  FROM sources s LEFT JOIN returns r ON r.id = s.return_id WHERE s.status = 'ingested';
CREATE VIEW IF NOT EXISTS calls AS
  SELECT t.event_id AS id, s.label || ':' || e.loc AS cite, s.label AS source, rr.label AS ret, t.ts_utc, t.target, t.other, t.dir,
         t.kind, t.duration_s, t.cell, t.cell_last, t.eci, t.lat, t.lon, t.azimuth, t.site_name, t.loc_basis,
         COALESCE((SELECT s2.label || ':' || e2.loc FROM events e2 JOIN sources s2 ON s2.id = e2.source_id
           WHERE e2.id = t.loc_event_id), t.loc_ref) AS loc_cite, t.imei, t.imsi, t.dev_lat, t.dev_lon, t.dev_conf, t.src_kind,
         t.section, e.raw
  FROM tel t JOIN events e ON e.id = t.event_id JOIN sources s ON s.id = t.source_id
       LEFT JOIN returns rr ON rr.id = s.return_id;
CREATE VIEW IF NOT EXISTS tcore AS
  SELECT * FROM tel WHERE COALESCE(src_kind, 'cdr') != 'dump' AND COALESCE(dir, '') != 'fwd';
CREATE VIEW IF NOT EXISTS ccore AS
  SELECT * FROM calls WHERE COALESCE(src_kind, 'cdr') != 'dump' AND COALESCE(dir, '') != 'fwd';
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
    "CREATE INDEX IF NOT EXISTS ix_tel_target ON tel(target, ts_epoch)",
    "CREATE INDEX IF NOT EXISTS ix_tel_other ON tel(other)",
    "CREATE INDEX IF NOT EXISTS ix_tel_ts ON tel(ts_epoch)",
    "CREATE INDEX IF NOT EXISTS ix_cs_cell ON cell_sites(cell)",
    "CREATE INDEX IF NOT EXISTS ix_cs_eci ON cell_sites(eci)",
    "CREATE INDEX IF NOT EXISTS ix_tel_imsi ON tel(imsi)",
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


SCHEMA_VERSION = 6


def init(con: sqlite3.Connection) -> None:
    con.executescript(SCHEMA)
    r = con.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
    if not r or r[0] != str(SCHEMA_VERSION):
        if "return_id" not in [c[1] for c in con.execute("PRAGMA table_info(sources)")]:
            con.execute("ALTER TABLE sources ADD COLUMN return_id INTEGER")      # schema 6: sources belong to returns
        for v in ("ev", "ids", "src", "fnd", "calls", "tcore", "ccore"):
            con.execute(f"DROP VIEW IF EXISTS {v}")
        for t in ("tel", "cell_sites"):          # derived on every run; rebuilt with the new columns
            con.execute(f"DROP TABLE IF EXISTS {t}")
        con.executescript(SCHEMA)
        con.execute("INSERT OR REPLACE INTO meta(key, value) VALUES ('schema_version', ?)", (str(SCHEMA_VERSION),))
    from .returns import backfill
    backfill(con)
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
