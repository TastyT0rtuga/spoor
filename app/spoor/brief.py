"""One-line statements of findings for the BLUF and the narrative of REPORT.md, built only from the finding's own facts (no model).

Every number, identifier and time in a sentence here is copied from the finding it belongs to; REPORT.md puts the finding's reference
number after it. The long statement stays in FINDINGS.md."""
from __future__ import annotations

import re

# ---------------------------------------------------------------- what a finding is for
NULL_KINDS = {"no_ips", "no_logins", "no_times", "no_identifiers", "crossref_none"}
LEAD_KINDS = {"failed_burst", "multi_account_failures", "change_from_new_ip", "account_cluster", "notable_ip", "shared_infrastructure",
              "shared_identifier", "eth_bad_checksum", "watchlist_hit", "crossref_summary", "crossref_item",
              "telecom_direct", "telecom_overlap", "telecom_common", "telecom_shared_imei", "telecom_shared_imsi", "telecom_imei_change",
              "telecom_imsi_change", "telecom_colocation", "telecom_dump_multi", "telecom_dump_imei", "telecom_dump_target",
              "telecom_path", "telecom_dump_path", "telecom_link_set"}
PATTERN_KINDS = {"network_switch", "gap", "hosting_networks", "hour_profile", "daily_volume", "largest_amounts", "changes_other"}

THEMES = [
    ("access", "Account access and security changes", {"failed_burst", "multi_account_failures", "change_from_new_ip", "network_switch", "changes_other"}),
    ("linked", "Linked accounts and shared infrastructure", {"account_cluster", "notable_ip", "shared_infrastructure", "hosting_networks"}),
    ("returns", "Items present in more than one return", {"crossref_summary", "crossref_item"}),
    ("ident", "Shared identifiers", {"shared_identifier", "eth_bad_checksum"}),
    ("telecom", "Calls, texts and cell sites", {"telecom_direct", "telecom_overlap", "telecom_common", "telecom_shared_imei", "telecom_shared_imsi",
                                                 "telecom_imei_change", "telecom_imsi_change", "telecom_colocation", "telecom_dump_multi",
                                                 "telecom_dump_imei", "telecom_dump_target", "telecom_path",
                                                 "telecom_dump_path", "telecom_link_set", "telecom_degrees"}),
    ("watch", "Watchlist matches", {"watchlist_hit"}),
    ("timing", "Timing and money", {"gap", "hour_profile", "daily_volume", "largest_amounts"}),
]


def role(f: dict) -> str:
    """lead | pattern | context | dataquality | null"""
    k = f["kind"]
    if k in NULL_KINDS:
        return "null"
    if f["category"] == "Sources & data quality" or k == "telecom_quality":
        return "dataquality"
    if k in LEAD_KINDS:
        return "lead"
    if k in PATTERN_KINDS:
        return "pattern"
    return "context"


def theme_of(f: dict) -> str | None:
    for key, _title, kinds in THEMES:
        if f["kind"] in kinds:
            return key
    return None


# ---------------------------------------------------------------- text helpers
def first_sentence(text: str, limit: int = 260) -> str:
    t = " ".join((text or "").split())
    m = re.search(r"(?<=[a-z0-9\)\]])\. (?=[A-Z(])", t)
    s = t[:m.start() + 1] if m else t
    if len(s) > limit:
        cut = max(s.rfind(", ", 0, limit), s.rfind("; ", 0, limit), s.rfind(" ", 0, limit))
        s = s[:cut if cut > limit // 2 else limit].rstrip(",; ") + " ..."
    return s if s.endswith((".", "...")) else s + "."


def _v(f: dict) -> dict:
    return (f.get("facts") or {}).get("values", {}) or {}


def _day(ts) -> str:
    return (ts or "")[:10]


def _hm(ts) -> str:
    return (ts or "")[11:16]


def _rets(v: dict, multi: bool) -> str:
    r = v.get("returns")
    if not (multi and r):
        return ""
    n = len([x for x in str(r).replace(",", " ").split() if x])
    return f" (in {n} return{'s' if n != 1 else ''}: {r})" if n else ""


def _num(n) -> str:
    try:
        return f"{int(n):,}"
    except (TypeError, ValueError):
        return str(n)


def _pl(n, w, pw=None) -> str:
    return f"{_num(n)} {w if n == 1 else (pw or w + 's')}"


# ---------------------------------------------------------------- per-kind briefs
def brief(f: dict, multi: bool = False) -> str:
    k, v = f["kind"], _v(f)
    try:
        fn = BUILDERS.get(k)
        if fn:
            s = fn(f, v, multi)
            if s:
                return s
    except (KeyError, TypeError, ValueError):
        pass
    return first_sentence(f["statement"])


def _failed_burst(f, v, multi):
    s = (f"{v['account']} had {_pl(v['failures'], 'failed login')} from {_pl(v['ip_count'], 'IP')} in {v['duration']} "
         f"(from {v['start_utc']} UTC)")
    if v.get("success_utc"):
        s += (f"; a successful login followed {v['success_after']} after the last failure from {v['success_ip'] or 'an unknown IP'}"
              + (", an IP used in the failures" if v.get("success_ip_in_failures") else ", an IP not used in the failures"))
    else:
        s += f"; no successful login followed within {v.get('followup_minutes', 30)} minutes"
    return s + "."


def _multi_fail(f, v, multi):
    return (f"IP {v['ip']} had {_pl(v['failures'], 'failed login')} against {_pl(v['accounts'], 'different account')} "
            f"between {v['first_utc']} and {v['last_utc']} UTC.")


def _change(f, v, multi):
    return (f"{v['account']}: '{v['action']}' at {v['ts_utc']} UTC from IP {v['ip']}, which first appears for the account "
            f"{_pl(v['minutes_since_first_seen'], 'minute')} earlier.")


def _cluster(f, v, multi):
    s = f"{_pl(v['account_count'], 'account')} are connected through {_pl(v['shared_ips'], 'shared IP')}"
    if v.get("closest"):
        s += f"; the closest activity of two of them was {v['closest']} apart on {v['closest_ip']} ({v['closest_a']} and {v['closest_b']})"
    return s + "."


def _notable_ip(f, v, multi):
    s = f"IP {v['ip']} ({v.get('network') or v.get('ip_class')}) appears in {_pl(v['events'], 'event')}"
    s += _rets(v, multi) if multi else f" across {_pl(v['sources'], 'file')}"
    s += f" and is used by {_pl(v['accounts'], 'account')}"
    if v.get("closest_couse"):
        s += f"; two accounts used it {v['closest_couse']} apart"
    return s + "."


def _shared_ident(f, v, multi):
    from .identifiers import KIND_LABELS
    lab = KIND_LABELS.get(v["kind"], v["kind"])
    s = f"{lab[0].upper() + lab[1:]} {v['value']} appears in {_pl(v['records'], 'record')}"
    s += _rets(v, multi) if multi else f" across {_pl(v['sources'], 'file')}"
    return s + f" and in the records of {_pl(v['account_count'], 'account')}."


def _crossref_item(f, v, multi):
    kind = {"ip": "IP", "account": "Account", "counterparty": "Counterparty"}.get(v["kind"])
    if kind is None:
        from .identifiers import KIND_LABELS
        lab = KIND_LABELS.get(v["kind"], v["kind"])
        kind = lab[0].upper() + lab[1:]
    return f"{kind} {v['value']} is in {v['return_count']} returns ({v['returns']}), {_pl(v['records'], 'record')} in all."


def _watch(f, v, multi):
    s = f"Watchlist entry {v['value']}" + (f" ('{v['label']}')" if v.get("label") else "")
    s += f" matches {_pl(v['records'], 'record')} for {_pl(v['accounts'] or 0, 'account')}"
    s += _rets(v, multi)
    return s + "."


def _gap(f, v, multi):
    return f"{v['account']} has no records for {v['gap']} ({v['gap_start_utc']} to {v['gap_end_utc']} UTC) in {v['source']}."


def _switch(f, v, multi):
    return f"{v['account']} switched networks {_pl(v['switches'], 'time')} within {v['window_minutes']} minutes of each other."


def _crossref_summary(f, v, multi):
    return first_sentence(f["statement"], 420)


def _coloc(f, v, multi):
    s = (f"{v['target_a']} and {v['target_b']} used the same cell-site location (within {_num(v['distance_m'])} m) within {v['window_min']} minutes of each other "
         f"on {_pl(v['occasions'], 'occasion')}")
    if v["occasions"] > 1:
        s += f" (first {v['first_utc']}, last {v['last_utc']} UTC)"
    else:
        s += f" ({v['first_utc']} UTC)"
    return s + f"; closest {v['closest']} apart on cell {v['closest_cell_a']}."


def _tel_direct(f, v, multi):
    return (f"{v['target_a']} and {v['target_b']} were in direct contact: {_pl(v['records'], 'record')} ({_pl(v['calls'], 'call')}, {_pl(v['texts'], 'text')}) "
            f"from {v['first_utc']} to {v['last_utc']} UTC.")


def _tel_common(f, v, multi):
    return (f"{v['other']} was in contact with {v['target_count']} targets ({', '.join(v['targets'])}), "
            f"{_pl(sum(v['records'].values()), 'record')} in all.")


def _tel_imei(f, v, multi):
    per = "; ".join(f"{p[0]} {p[1][:10]} to {p[2][:10]}" for p in v["periods"])
    return f"IMEI {v['imei']} was used by {v['target_count']} target numbers: {per}."


def _tel_path(f, v, multi):
    s = f"{v['a']} and {v['b']} have no direct or shared contact but are linked in {v['hops']} hops: {' - '.join(v['chain'])}"
    if v.get("chains", 1) > 1:
        s += f" ({v['chains']} chains of that length{', more not listed' if v.get('more') else ''})"
    return s + "."


def _dump_path(f, v, multi):
    return (f"Tower dump {v['dump']}: {', '.join(v['phones'][:4])} {'is' if len(v['phones']) == 1 else 'are'} linked to target {v['target']} "
            f"in {v['hops']} contact hops: {' - '.join(v['chain'][1:])}.")


def _link_set(f, v, multi):
    parts = [f"{a} and {b}: {f'{h} hop' + ('s' if h != 1 else '') if h else 'not linked'}" for a, b, h in v.get("pairs", [])]
    s = f"Link group '{v['name']}': " + "; ".join(parts[:6]) + (" ..." if len(parts) > 6 else "")
    if v.get("through"):
        s += f"; most-used links: {', '.join(v['through'][:4])}"
    return s + "."


def _degrees(f, v, multi):
    return (f"Across {v['pairs']} pairs of targets: {v['direct']} in direct contact, {v['shared_contact']} with a contact in common, "
            f"{v['longer']} linked only through longer chains, {v['not_linked']} not linked within {v['max_hops']} hops.")


BUILDERS = {"telecom_path": _tel_path, "telecom_dump_path": _dump_path, "telecom_link_set": _link_set, "telecom_degrees": _degrees,
            "telecom_colocation": _coloc, "telecom_direct": _tel_direct, "telecom_common": _tel_common, "telecom_shared_imei": _tel_imei,
            "failed_burst": _failed_burst, "multi_account_failures": _multi_fail, "change_from_new_ip": _change,
            "account_cluster": _cluster, "notable_ip": _notable_ip, "shared_identifier": _shared_ident, "crossref_item": _crossref_item,
            "watchlist_hit": _watch, "gap": _gap, "network_switch": _switch, "crossref_summary": _crossref_summary}


# ---------------------------------------------------------------- grouping: several findings that tell one thing
def group_changes(fs: list[dict]) -> list[dict]:
    """Account changes from the same IP for the same account become one item ("three changes ... within 9 minutes")."""
    out, buckets = [], {}
    for f in fs:
        if f["kind"] != "change_from_new_ip":
            out.append({"fids": [f["fid"]], "findings": [f], "text": None})
            continue
        v = _v(f)
        buckets.setdefault((v["account"], v["ip"]), []).append(f)
    for (acc, ip), lst in buckets.items():
        lst.sort(key=lambda x: _v(x)["ts_utc"])
        if len(lst) == 1:
            out.append({"fids": [lst[0]["fid"]], "findings": lst, "text": None})
            continue
        v0, v1 = _v(lst[0]), _v(lst[-1])
        from datetime import datetime
        try:
            span = (datetime.strptime(v1["ts_utc"], "%Y-%m-%d %H:%M:%S") - datetime.strptime(v0["ts_utc"], "%Y-%m-%d %H:%M:%S")).total_seconds()
        except ValueError:
            span = None
        acts = ", ".join(f"{_v(x)['action']} ({_hm(_v(x)['ts_utc'])})" for x in lst)
        sp = f" within {max(1, round(span / 60))} minutes" if span is not None else ""
        out.append({"fids": [x["fid"] for x in lst], "findings": lst,
                    "text": f"{acc}: {_pl(len(lst), 'account change')} from IP {ip} on {_day(v0['ts_utc'])}{sp} - {acts}; the IP first appears for the account "
                            f"{_pl(v0['minutes_since_first_seen'], 'minute')} before the first change."})
    order = {f["fid"]: i for i, f in enumerate(fs)}
    out.sort(key=lambda g: min(order[x] for x in g["fids"]))
    return out
