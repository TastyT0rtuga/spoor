"""Indexes, summary tables, offline ASN/country enrichment and the full-text index."""
from __future__ import annotations

import datetime as dt
import hashlib
from pathlib import Path

from . import db as dbm
from .util import app_root


def build_indexes(con, prog=None) -> None:
    for i, ix in enumerate(dbm.INDEXES):
        if prog:
            prog.message(f"Index {i + 1}/{len(dbm.INDEXES)}")
        con.execute(ix)
    con.execute("ANALYZE")
    con.commit()


def geoip_dbs(folder: Path | None = None) -> list[dict]:
    folder = folder or (app_root() / "geoip")
    out = []
    if not folder.exists():
        return out
    try:
        import maxminddb
    except ImportError:
        return out
    for p in sorted(folder.glob("*.mmdb")):
        try:
            r = maxminddb.open_database(str(p))
            md = r.metadata()
            h = hashlib.sha256(p.read_bytes()).hexdigest()
            out.append({"path": str(p), "file": p.name, "type": md.database_type,
                        "built": dt.datetime.fromtimestamp(md.build_epoch, dt.timezone.utc).strftime("%Y-%m-%d"),
                        "sha256": h, "reader": r})
        except Exception:  # noqa: BLE001
            continue
    return out


def enrich_ips(con, prog=None) -> dict:
    dbs = geoip_dbs()
    asn_db = next((d for d in dbs if "ASN" in d["type"].upper()), None)
    geo_db = next((d for d in dbs if "ASN" not in d["type"].upper()), None)
    meta = {"asn": {k: v for k, v in (asn_db or {}).items() if k != "reader"} or None,
            "geo": {k: v for k, v in (geo_db or {}).items() if k != "reader"} or None}
    dbm.set_meta(con, "geoip", meta)
    if not asn_db and not geo_db:
        con.commit()
        return meta
    con.execute("DELETE FROM ip_enrich")
    ips = [r[0] for r in con.execute("SELECT DISTINCT ip FROM events WHERE ip IS NOT NULL AND ip_class='public'")]
    if prog:
        prog.set_total(len(ips) or 1, "IPs")
    batch = []
    label = " + ".join(f"{d['file']} (built {d['built']})" for d in (asn_db, geo_db) if d)
    for i, ip in enumerate(ips):
        asn = org = cc = None
        if asn_db:
            try:
                a = asn_db["reader"].get(ip) or {}
                asn = a.get("autonomous_system_number")
                org = a.get("autonomous_system_organization")
            except Exception:  # noqa: BLE001
                pass
        if geo_db:
            try:
                g = geo_db["reader"].get(ip) or {}
                cc = (g.get("country") or {}).get("iso_code")
            except Exception:  # noqa: BLE001
                pass
        batch.append((ip, asn, org, cc, label))
        if len(batch) >= 5000:
            con.executemany("INSERT OR REPLACE INTO ip_enrich VALUES (?,?,?,?,?)", batch)
            batch = []
            if prog:
                prog.update(i + 1)
    if batch:
        con.executemany("INSERT OR REPLACE INTO ip_enrich VALUES (?,?,?,?,?)", batch)
    con.commit()
    return meta


def build_summaries(con, prog=None) -> None:
    steps = [
        ("IP summary", ["DELETE FROM ip_summary",
                        """INSERT INTO ip_summary(ip, ip_ver, ip_class, subnet, events, accounts, sources, first_utc, last_utc, ports)
                           SELECT ip, MIN(ip_ver), MIN(ip_class), MIN(subnet), COUNT(*), COUNT(DISTINCT account),
                                  COUNT(DISTINCT source_id), MIN(ts_utc), MAX(ts_utc), COUNT(DISTINCT port)
                           FROM events WHERE ip IS NOT NULL GROUP BY ip""",
                        """UPDATE ip_summary SET asn=(SELECT asn FROM ip_enrich x WHERE x.ip=ip_summary.ip),
                                  as_org=(SELECT as_org FROM ip_enrich x WHERE x.ip=ip_summary.ip),
                                  country=(SELECT country FROM ip_enrich x WHERE x.ip=ip_summary.ip)"""]),
        ("IP/account pairs", ["DELETE FROM ip_accounts",
                              """INSERT INTO ip_accounts(ip, account, events, first_utc, last_utc)
                                 SELECT ip, account, COUNT(*), MIN(ts_utc), MAX(ts_utc) FROM events
                                 WHERE ip IS NOT NULL AND account IS NOT NULL GROUP BY ip, account"""]),
        ("Account summary", ["DELETE FROM account_summary",
                             """INSERT INTO account_summary
                                SELECT account, COUNT(*), COUNT(DISTINCT source_id),
                                       SUM(category='login'), SUM(category='login_failed'), SUM(category='logout'),
                                       SUM(category='account_change'), COUNT(DISTINCT ip),
                                       COUNT(DISTINCT CASE WHEN ip_class='public' THEN ip END),
                                       COUNT(DISTINCT user_agent), MIN(ts_utc), MAX(ts_utc)
                                FROM events WHERE account IS NOT NULL GROUP BY account"""]),
        ("Identifier summary", ["DELETE FROM ident_summary",
                                """INSERT INTO ident_summary
                                   SELECT i.kind, i.norm, MAX(i.validity), COUNT(DISTINCT i.event_id), COUNT(DISTINCT i.source_id),
                                          COUNT(DISTINCT e.account), MIN(e.ts_utc), MAX(e.ts_utc)
                                   FROM identifiers i JOIN events e ON e.id=i.event_id
                                   GROUP BY i.kind, i.norm"""]),
    ]
    if prog:
        prog.set_total(len(steps), "steps")
    for i, (name, sqls) in enumerate(steps):
        if prog:
            prog.message(name)
        for s in sqls:
            con.execute(s)
        con.commit()
        if prog:
            prog.update(i + 1)


def build_fts(con, enabled: bool = True, prog=None) -> bool:
    if not enabled or not dbm.fts_available(con):
        con.execute("DROP TABLE IF EXISTS events_fts")
        con.commit()
        return False
    if prog:
        prog.message("Building full-text index (search any string across all returns)")
    con.execute("DROP TABLE IF EXISTS events_fts")
    con.execute("CREATE VIRTUAL TABLE events_fts USING fts5(raw, content='events', content_rowid='id', tokenize=\"unicode61 tokenchars '.@:-_'\")")
    con.execute("INSERT INTO events_fts(events_fts) VALUES('rebuild')")
    con.commit()
    return True
