"""Telecom records: call detail records (CDRs) and cell-site lists, turned into one table.

`tel` has one row per call / text / data session (the event it came from is its citation):
target number, other party, direction, kind, duration, first/last cell, and the cell site's
coordinates with the record they were taken from (`loc_event_id`, so a KML point or a co-location
finding cites both the CDR row and the tower-list row). `cell_sites` holds every cell with
coordinates, from tower lists or written inline on CDR rows.

Nothing is guessed silently: a target inferred from the data, a cell matched to a tower list in
another folder, or a cell whose lists disagree is recorded in `target_basis` / `loc_basis` / `note`
and summarised in meta 'telecom' for the data-quality findings."""
from __future__ import annotations

import collections
import json
import math
import re
from pathlib import Path
from typing import Optional

from . import db as dbm
from .identifiers import phone_from_cell

_SEP = re.compile(r"[-:/_ .]+")


# ---------------------------------------------------------------- normalisers

def norm_number(v) -> Optional[str]:
    """E.164 for NANP / '+' numbers; other values (short codes, foreign numbers without '+') as digits."""
    if v in (None, ""):
        return None
    s = str(v).strip()
    ph = phone_from_cell(s)
    if ph:
        return ph
    d = re.sub(r"\D", "", s)
    if not d or set(d) == {"0"}:
        return None
    return ("+" + d) if s.startswith("+") else d


def norm_cell(v) -> Optional[str]:
    """'NL-1021-02' and 'nl 1021 2' -> 'NL-1021-2': upper case, one separator, no leading zeros."""
    if v in (None, ""):
        return None
    s = str(v).strip().upper()
    if not s or s in ("0", "N/A", "NA", "NULL", "NONE", "-", "UNKNOWN"):
        return None
    parts = [p for p in _SEP.split(s) if p]
    out = []
    for p in parts:
        if p.isdigit():
            p = p.lstrip("0") or "0"
        out.append(p)
    return "-".join(out) or None


def parse_duration(v, header: str = "") -> Optional[float]:
    if v in (None, ""):
        return None
    s = str(v).strip().lower()
    m = re.fullmatch(r"(\d+):(\d{1,2}):(\d{1,2})(?:[.,]\d+)?", s)
    if m:
        return int(m.group(1)) * 3600 + int(m.group(2)) * 60 + int(m.group(3))
    m = re.fullmatch(r"(\d+):(\d{1,2})(?:[.,]\d+)?", s)
    if m:
        return int(m.group(1)) * 60 + int(m.group(2))
    m = re.fullmatch(r"(\d+(?:[.,]\d+)?)\s*(s|sec|secs|seconds|m|min|mins|minutes)?", s)
    if m:
        x = float(m.group(1).replace(",", "."))
        unit = m.group(2) or ("min" if re.search(r"\bmin", header.lower()) else "s")
        return x * 60 if unit.startswith("m") else x
    return None


_OUT = re.compile(r"(?:^|[^a-z])(?:out|outgoing|outbound|mo|moc|orig|originat\w*|sent|send|dialed|dialled|o)(?:$|[^a-z])")
_IN = re.compile(r"(?:^|[^a-z])(?:in|incoming|inbound|mt|mtc|term|terminat\w*|received|receive|recv|i)(?:$|[^a-z])")


def norm_dir(direction, action) -> str:
    for v in (direction, action):
        s = str(v or "").lower().replace("_", " ")
        if not s:
            continue
        o, i = bool(_OUT.search(s)), bool(_IN.search(s))
        if o != i:
            return "out" if o else "in"
    return ""


def norm_kind(action, default_category: Optional[str] = None) -> str:
    s = str(action or "").lower()
    if re.search(r"\bmms\b", s):
        return "mms"
    if re.search(r"\b(?:sms|text|txt|message|msg)\b|sms[- ]?m[ot]", s):
        return "sms"
    if re.search(r"\b(?:data|gprs|packet|internet|ip session|pdp|lte data|session)\b", s):
        return "data"
    if re.search(r"\b(?:voice|call|calls|moc|mtc|volte|vowifi|wifi call|voicemail|vm)\b", s):
        return "voice"
    return "voice" if (not s and default_category == "communication") else ("other" if s else "")


def fnum(v, lo, hi) -> Optional[float]:
    if v in (None, ""):
        return None
    try:
        x = float(str(v).strip().replace(",", "."))
    except ValueError:
        return None
    return x if lo <= x <= hi and not math.isnan(x) else None


def km(lat1, lon1, lat2, lon2) -> float:
    r = 6371.0088
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = p2 - p1, math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(min(1.0, math.sqrt(a)))


# ---------------------------------------------------------------- build

def _tel_events(con, source_id: Optional[int] = None):
    q = ("SELECT e.id, e.source_id, e.ts_epoch, e.ts_utc, e.account, e.account_basis, e.action, e.category, "
         "e.counterparty, e.direction, e.extra FROM events e WHERE e.extra LIKE '%\"_tel\"%'")
    args: tuple = ()
    if source_id is not None:
        q += " AND e.source_id=?"
        args = (source_id,)
    for r in con.execute(q + " ORDER BY e.id", args):
        try:
            ex = json.loads(r["extra"])
        except ValueError:
            continue
        tel = ex.get("_tel")
        if isinstance(tel, dict):
            yield r, tel, ex


def _infer_targets(con) -> dict:
    """For sources whose rows carry originating+terminating numbers but no account: the number on
    both-or-either end of (nearly) every row is the target. Returns {source_id: (number, basis)}."""
    out = {}
    srcs = [r[0] for r in con.execute(
        "SELECT DISTINCT source_id FROM events WHERE account IS NULL AND extra LIKE '%\"_tel\"%'")]
    for sid in srcs:
        cnt: collections.Counter = collections.Counter()
        n = 0
        for r, tel, _ex in _tel_events(con, sid):
            if r["account"]:
                continue
            nums = {norm_number(tel.get("orig")), norm_number(tel.get("term"))} - {None}
            if not nums:
                continue
            n += 1
            cnt.update(nums)
        if n and cnt:
            num, k = cnt.most_common(1)[0]
            share = k / n
            if share >= 0.8:
                out[sid] = (num, f"inferred: the number on one end of {share:.0%} of this return's records - VERIFY "
                                 f"against the return's cover letter")
    return out


def build(con, params: dict, prog=None, log=None) -> dict:
    con.execute("DELETE FROM tel")
    con.execute("DELETE FROM cell_sites")
    n_tel = dbm.one(con, "SELECT COUNT(*) FROM events WHERE extra LIKE '%\"_tel\"%'") or 0
    stats: dict = {"records": 0, "tower_rows": 0, "inline_sites": 0, "located": 0, "unlocated": 0,
                   "unlocated_reasons": collections.Counter(), "inferred_targets": {}, "conflicts": [],
                   "no_target": 0, "neither_end_target": 0, "cross_folder_matches": 0}
    if not n_tel:
        dbm.set_meta(con, "telecom", None)
        con.commit()
        return {}
    if prog:
        prog.message("Telecom records: calls, texts and cell sites")
        prog.set_total(n_tel, "records")
    inferred = _infer_targets(con)
    labels = {r[0]: r[1] for r in con.execute("SELECT id, label FROM sources")}
    for sid, (num, basis) in inferred.items():
        con.execute("UPDATE events SET account=?, account_basis=? WHERE source_id=? AND account IS NULL "
                    "AND extra LIKE '%\"_tel\"%'", (num, basis, sid))
        stats["inferred_targets"][labels.get(sid, str(sid))] = {"target": num, "basis": basis}
    con.commit()
    tel_rows, site_rows = [], []
    done = 0
    for r, tel, ex in _tel_events(con):
        done += 1
        cell = norm_cell(tel.get("cell"))
        lat, lon = fnum(tel.get("lat"), -90, 90), fnum(tel.get("lon"), -180, 180)
        if lat is not None and lon is not None and lat == 0 and lon == 0:
            lat = lon = None
        az, bw = fnum(tel.get("azimuth"), 0, 360), fnum(tel.get("beamwidth"), 0, 360)
        name = (tel.get("site_name") or "")[:120] or None
        has_party = bool(tel.get("orig") or tel.get("term") or r["counterparty"])
        if lat is not None and lon is not None and cell:
            origin = "tower list" if (r["ts_epoch"] is None and not has_party) else "inline on a call record"
            site_rows.append((cell, r["source_id"], r["id"], origin, name, lat, lon, az, bw))
            if origin == "tower list":
                stats["tower_rows"] += 1
                continue
            stats["inline_sites"] += 1
        elif r["ts_epoch"] is None and not has_party:
            continue          # a cell-list row without coordinates, or an attribute line
        target = norm_number(r["account"]) if r["account"] else None
        target = target or (r["account"] or None)
        tbasis = r["account_basis"] or ("account column" if r["account"] else None)
        other = other_raw = None
        d = ""
        note = None
        o, t = norm_number(tel.get("orig")), norm_number(tel.get("term"))
        if tel.get("orig") is not None or tel.get("term") is not None:
            if target and o == target and t != target:
                other, other_raw, d = t, tel.get("term"), "out"
            elif target and t == target and o != target:
                other, other_raw, d = o, tel.get("orig"), "in"
            elif target and o == target and t == target:
                d, note = "", "both ends are the target"
            elif target and o is not None and t is None:
                other, other_raw, d = o, tel.get("orig"), "in"
            elif target and t is not None and o is None:
                other, other_raw, d = t, tel.get("term"), "out"
            elif target:
                note = "neither end is the target number (forwarded or conference leg?)"
                stats["neither_end_target"] += 1
        elif r["counterparty"]:
            other, other_raw = norm_number(r["counterparty"]), r["counterparty"]
            d = norm_dir(r["direction"], r["action"])
        if not d:
            d = norm_dir(r["direction"], r["action"]) if not note else ""
        if not target:
            stats["no_target"] += 1
        kind = norm_kind(r["action"], r["category"])
        if kind == "data" and other is None:
            d = d or "out"
        dur = parse_duration(tel.get("duration"), ex.get("_tel_duration_header", ""))
        imei = re.sub(r"\D", "", tel.get("imei") or "") or None
        imsi = re.sub(r"\D", "", tel.get("imsi") or "") or None
        basis = "inline on this record" if (lat is not None and lon is not None) else None
        tel_rows.append((r["id"], r["source_id"], target, tbasis, other, (other_raw or None), d or None, kind or None,
                         r["ts_epoch"], r["ts_utc"], dur, cell, norm_cell(tel.get("cell_last")), lat, lon, az, bw, name,
                         basis, r["id"] if basis else None, imei, imsi, note))
        stats["records"] += 1
        if len(tel_rows) >= 5000:
            _flush(con, tel_rows, site_rows)
            if prog:
                prog.update(done)
                prog.check_cancel()
    _flush(con, tel_rows, site_rows)
    _resolve_locations(con, params, stats)
    stats["located"] = dbm.one(con, "SELECT COUNT(*) FROM tel WHERE lat IS NOT NULL") or 0
    stats["unlocated"] = stats["records"] - stats["located"]
    stats["unlocated_reasons"] = dict(stats["unlocated_reasons"])
    dbm.set_meta(con, "telecom", stats)
    con.commit()
    if log:
        log.info("telecom: %s records, %s located, %s tower-list rows", stats["records"], stats["located"], stats["tower_rows"])
    return stats


def _flush(con, tel_rows, site_rows):
    if site_rows:
        con.executemany("INSERT INTO cell_sites(cell, source_id, event_id, origin, site_name, lat, lon, azimuth, beamwidth)"
                        " VALUES (?,?,?,?,?,?,?,?,?)", site_rows)
    if tel_rows:
        con.executemany(f"INSERT INTO tel VALUES ({','.join('?' * 23)})", tel_rows)
    con.commit()
    tel_rows.clear()
    site_rows.clear()


def _folder(path: str) -> str:
    try:
        return str(Path(path).resolve().parent).lower()
    except OSError:
        return str(Path(path).parent).lower()


def _resolve_locations(con, params: dict, stats: dict) -> None:
    """Give each unlocated call record the coordinates of its first cell from a tower list:
    a list in the same folder as the CDR wins; otherwise a cell is matched only if every list
    that names it agrees to within the same-site distance."""
    agree_km = float(params.get("tel_same_site_km", 0.1))
    folders = {r[0]: _folder(r[1]) for r in con.execute("SELECT id, path FROM sources")}
    sites: dict = collections.defaultdict(list)
    for r in con.execute("SELECT cell, source_id, event_id, origin, site_name, lat, lon, azimuth, beamwidth FROM cell_sites "
                         "WHERE origin='tower list' ORDER BY id"):
        sites[r[0]].append(r)
    if not sites:
        for (n,) in con.execute("SELECT COUNT(*) FROM tel WHERE lat IS NULL AND cell IS NOT NULL"):
            if n:
                stats["unlocated_reasons"]["no tower list loaded"] += n
        n = dbm.one(con, "SELECT COUNT(*) FROM tel WHERE lat IS NULL AND cell IS NULL") or 0
        if n:
            stats["unlocated_reasons"]["no cell on the record"] += n
        return
    upd = []
    conflicts = {}
    for r in con.execute("SELECT event_id, source_id, cell FROM tel WHERE lat IS NULL"):
        eid, sid, cell = r
        if not cell:
            stats["unlocated_reasons"]["no cell on the record"] += 1
            continue
        cands = sites.get(cell) or []
        if not cands:
            stats["unlocated_reasons"]["cell not in any tower list"] += 1
            continue
        same = [c for c in cands if folders.get(c[1]) == folders.get(sid)]
        pick, basis = None, None
        if same:
            pick, basis = same[0], "tower list in the same folder"
        else:
            ref = cands[0]
            if all(km(ref[5], ref[6], c[5], c[6]) <= agree_km for c in cands):
                pick, basis = ref, "tower list in another folder (cell ID match only - VERIFY it is the same carrier)"
                stats["cross_folder_matches"] += 1
            else:
                stats["unlocated_reasons"]["tower lists disagree on this cell"] += 1
                conflicts[cell] = sorted({f"{c[5]:.5f},{c[6]:.5f}" for c in cands})
                continue
        upd.append((pick[5], pick[6], pick[7], pick[8], pick[4], basis, pick[2], eid))
    con.executemany("UPDATE tel SET lat=?, lon=?, azimuth=?, beamwidth=?, site_name=COALESCE(site_name, ?), loc_basis=?, "
                    "loc_event_id=? WHERE event_id=?", upd)
    stats["conflicts"] = [{"cell": k, "coordinates": v} for k, v in sorted(conflicts.items())][:50]
    con.commit()
