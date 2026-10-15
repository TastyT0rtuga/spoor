"""Negative results: the checks Spoor ran that found NOTHING, each with what it looked at and the SQL that shows it.

These belong in their own place (REPORT.md appendix and NULL_RESULTS in the dashboard), not among the findings. A check is
listed only when the data it needs is present - 'no failed-login burst' is meaningful only if failed logins exist - and only
when no finding of the kinds it would have produced exists. Computed from the database each time the report is written."""
from __future__ import annotations

from . import db as dbm
from . import returns as rets


def _n(con, sql, args=()) -> int:
    return dbm.one(con, sql, args) or 0


def _kinds(con) -> set:
    return {r[0] for r in con.execute("SELECT DISTINCT kind FROM findings WHERE fid IS NOT NULL")}


def null_results(case, con, p: dict) -> list[dict]:
    have = _kinds(con)
    out: list[dict] = []

    def add(area, title, statement, sql, kinds=()):
        if kinds and any(k in have for k in kinds):
            return
        out.append({"area": area, "title": title, "statement": statement, "sql": sql})

    ev = _n(con, "SELECT COUNT(*) FROM events")
    if not ev:
        return [{"area": "Data", "title": "No records", "statement": "No record was read from the returns that are included in this analysis.",
                 "sql": "SELECT COUNT(*) FROM events"}]
    LA = "Logins & account security"

    # ---- logins and account security
    fails = _n(con, "SELECT COUNT(*) FROM events WHERE category='login_failed'")
    logins = _n(con, "SELECT COUNT(*) FROM events WHERE category IN ('login','login_failed','logout')")
    changes = _n(con, "SELECT COUNT(*) FROM events WHERE category='account_change'")
    if not logins:
        add(LA, "Login records", "The returns contain no login, failed-login or logout records.",
            "SELECT category, COUNT(*) FROM ev GROUP BY category", ("account_logins",))
    else:
        if not fails:
            add(LA, "Failed logins", "No failed-login record is present in the returns.",
                "SELECT COUNT(*) FROM ev WHERE category='login_failed'", ("failed_burst",))
        else:
            add(LA, "Failed-login bursts",
                f"{fails:,} failed logins are present but no account had {int(p.get('burst_failures', 5))} or more within "
                f"{int(p.get('burst_window_min', 10))} minutes.",
                "SELECT account, COUNT(*) AS failures FROM ev WHERE category='login_failed' GROUP BY account ORDER BY failures DESC", ("failed_burst",))
            add(LA, "One IP failing against several accounts",
                "No IP address was the source of failed logins against three or more different accounts.",
                "SELECT ip, COUNT(DISTINCT account) AS accounts FROM ev WHERE category='login_failed' AND ip IS NOT NULL GROUP BY ip ORDER BY accounts DESC",
                ("multi_account_failures",))
    if changes:
        add(LA, "Account changes from a newly seen IP",
            f"None of the {changes:,} account-change records came from an IP address first seen for that account within "
            f"{int(p.get('change_new_ip_hours', 24))} hours before the change.",
            "SELECT cite, account, ts_utc, action, ip FROM ev WHERE category='account_change' ORDER BY ts_utc", ("change_from_new_ip",))
    elif logins:
        add(LA, "Account changes", "The returns contain no password, recovery, two-step or other account-change records.",
            "SELECT COUNT(*) FROM ev WHERE category='account_change'", ("change_from_new_ip", "changes_other"))

    # ---- IPs and links
    IP = "IP addresses and links"
    ips = _n(con, "SELECT COUNT(*) FROM ip_summary")
    accs = _n(con, "SELECT COUNT(*) FROM account_summary")
    attr = _n(con, "SELECT COUNT(*) FROM ip_summary WHERE ip_class IN ('public','documentation')")
    if not ips:
        add(IP, "IP addresses", "No record carries an IP address.", "SELECT COUNT(*) FROM ev WHERE ip IS NOT NULL", ("ip_inventory", "no_ips"))
    else:
        if attr:
            add(IP, "IPs shared by accounts or files",
                "No public (or documentation-range) IP address appears in more than one account or more than one file.",
                "SELECT ip, accounts, sources FROM ip_summary WHERE ip_class IN ('public','documentation') ORDER BY accounts DESC, sources DESC",
                ("notable_ip", "shared_infrastructure"))
        if accs >= 2:
            add(IP, "Accounts linked through IPs", f"None of the {accs:,} accounts is connected to another through an IP address they both used.",
                "SELECT ip, COUNT(DISTINCT account) AS accounts FROM ev WHERE account IS NOT NULL AND ip IS NOT NULL GROUP BY ip HAVING accounts >= 2",
                ("account_cluster",))
    if _n(con, "SELECT COUNT(*) FROM identifiers WHERE kind NOT IN ('ipv4','ipv6')"):
        add(IP, "Identifiers shared across accounts or files",
            "No email address, phone number, cryptocurrency address, MAC address, IMEI or URL appears in more than one account or more than one file.",
            "SELECT kind, value, COUNT(DISTINCT account) AS accounts, COUNT(DISTINCT source) AS files FROM ids WHERE kind NOT IN ('ipv4','ipv6') GROUP BY kind, value ORDER BY accounts DESC",
            ("shared_identifier",))
    else:
        add(IP, "Identifiers", "No email address, phone number, cryptocurrency address, MAC address, IMEI or URL was found in the records.",
            "SELECT kind, COUNT(*) FROM ids GROUP BY kind", ("identifier_inventory", "no_identifiers"))

    # ---- timing
    TM = "Timing patterns"
    timed = _n(con, "SELECT COUNT(*) FROM events WHERE ts_epoch IS NOT NULL")
    if not timed:
        add(TM, "Timestamps", "No record carries a usable timestamp, so no timing analysis was possible.",
            "SELECT COUNT(*) FROM ev WHERE ts_utc IS NOT NULL", ("hour_profile", "no_times"))
    else:
        add(TM, "Long gaps in activity",
            f"No account or file has a stretch without records of at least {p.get('gap_min_days', 7)} days that is also {p.get('gap_factor', 10)} times its usual gap.",
            "SELECT account, MIN(ts_utc), MAX(ts_utc), COUNT(*) FROM ev WHERE ts_utc IS NOT NULL GROUP BY account", ("gap",))
        if logins:
            add(TM, "Rapid network switches",
                f"No account used IPs from different networks within {int(p.get('concurrent_window_min', 10))} minutes of each other.",
                "SELECT account, ts_utc, ip FROM ev WHERE category IN ('login','login_failed') AND ip IS NOT NULL ORDER BY account, ts_utc",
                ("network_switch",))

    # ---- watchlists
    try:
        from .analyses.watchlist import load_watchlists
        items = load_watchlists(case)
    except Exception:  # noqa: BLE001
        items = []
    if items:
        import json as _json
        hit = {(_json.loads(r[0] or "{}").get("values") or {}).get("value") for r in con.execute("SELECT facts FROM findings WHERE kind='watchlist_hit'")}
        miss = [it for it in items if it["value"] not in hit]
        if miss:
            names = sorted({it["file"] for it in items})
            lst = "; ".join(f"{it['value']}" + (f" ({it['label']})" if it["label"] else "") for it in miss[:30])
            out.append({"area": "Watchlists", "title": "Watchlist entries with no match",
                        "statement": f"{len(miss)} of {len(items)} entries on the watchlist{'s' if len(names) > 1 else ''} ({', '.join(names)}) matched no record: "
                                     + lst + (" ..." if len(miss) > 30 else "") + ".",
                        "sql": "-- each entry is searched in ev (ip, account) and ids (value); see METHODS.md, Watchlist hits"})

    # ---- cross-return
    if rets.multi(con):
        from .analyses.crossref import ALL_SQL
        CR = "Cross-return overlap"
        labels = [r[0] for r in con.execute("SELECT DISTINCT r.label FROM returns r JOIN sources s ON s.return_id=r.id WHERE r.state='active' AND s.status='ingested' AND s.rows>0 ORDER BY r.label")]
        f = dbm.rows(con, "SELECT facts FROM findings WHERE kind IN ('crossref_summary','crossref_none') AND fid IS NOT NULL")
        import json
        if f:
            v = (json.loads(f[0]["facts"]) or {}).get("values", {})
            np_ = v.get("pairs_without_overlap") or []
            if np_ and v.get("items"):
                out.append({"area": CR, "title": "Pairs of returns with nothing in common",
                            "statement": f"{len(np_)} of {v.get('pairs_compared')} pairs of returns share no IP address, account, identifier or counterparty: "
                                         + ", ".join(np_[:60]) + (" ..." if len(np_) > 60 else "") + ".",
                            "sql": ALL_SQL})
            if not v.get("items"):
                out.append({"area": CR, "title": "Nothing in common between returns",
                            "statement": f"No IP address, account, identifier or counterparty appears in more than one of the {len(labels)} returns.",
                            "sql": ALL_SQL})

    # ---- telecom
    if _n(con, "SELECT COUNT(*) FROM tel"):
        TL = "Calls, texts & cell sites"
        targets = _n(con, "SELECT COUNT(DISTINCT target) FROM tcore WHERE target IS NOT NULL")
        if targets >= 2:
            add(TL, "Direct contact between targets", f"None of the {targets} target numbers called or texted another target number.",
                "SELECT target, other, COUNT(*) FROM ccore GROUP BY 1,2", ("telecom_direct",))
            add(TL, "Common contacts", f"No number was in contact with {int(p.get('tel_common_min_targets', 2))} or more of the {targets} targets.",
                "SELECT other, COUNT(DISTINCT target) AS targets FROM ccore GROUP BY other HAVING targets >= 2", ("telecom_common",))
            add(TL, "Shared handsets or SIMs", "No IMEI or IMSI was used by more than one target number.",
                "SELECT imei, COUNT(DISTINCT target) FROM ccore WHERE imei IS NOT NULL GROUP BY imei HAVING COUNT(DISTINCT target) >= 2",
                ("telecom_shared_imei", "telecom_shared_imsi"))
            if _n(con, "SELECT COUNT(*) FROM tcore WHERE lat IS NOT NULL"):
                add(TL, "Co-location", f"No two targets used the same or neighbouring cell sites within {int(p.get('tel_coloc_window_min', 15))} minutes of each other.",
                    "SELECT cite, ts_utc, target, cell, lat, lon FROM ccore WHERE lat IS NOT NULL ORDER BY ts_utc", ("telecom_colocation",))
        elif targets == 1:
            out.append({"area": TL, "title": "Cross-reference between targets", "statement": "The records name a single target number, so there is nothing to cross-reference between targets.",
                        "sql": "SELECT DISTINCT target FROM tcore"})
        if _n(con, "SELECT COUNT(*) FROM tcore WHERE imei IS NOT NULL OR imsi IS NOT NULL"):
            add(TL, "Handset or SIM changes", "No target number used more than one IMEI or IMSI.",
                "SELECT target, COUNT(DISTINCT imei), COUNT(DISTINCT imsi) FROM ccore GROUP BY target", ("telecom_imei_change", "telecom_imsi_change"))
        nloc = _n(con, "SELECT COUNT(*) FROM tel")
        if nloc and not _n(con, "SELECT COUNT(*) FROM tel WHERE lat IS NOT NULL"):
            out.append({"area": TL, "title": "Cell-site coordinates",
                        "statement": f"None of the {nloc:,} telecom records could be placed on a map: no cell-site list with coordinates matched them. "
                                     f"Add the carrier's tower list to the case, or install the reference library (cellsites/), and run again.",
                        "sql": "SELECT cell, COUNT(*) FROM calls WHERE lat IS NULL GROUP BY cell ORDER BY 2 DESC"})

    # ---- money
    if _n(con, "SELECT COUNT(*) FROM events WHERE amount IS NOT NULL") == 0 and _n(con, "SELECT COUNT(*) FROM events WHERE category='transaction'") == 0:
        pass  # no financial records at all: not a negative result about money, simply a different kind of case
    return out
