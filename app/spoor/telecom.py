"""Telecom records: call detail records (CDRs), tower dumps, timing-advance and ping reports, and cell-site
(tower) lists, turned into one table.

`tel` has one row per call / text / data session / location report (the event it came from is its citation):
the phone it is about (`target`), the other party, direction, kind, duration, the first/last cell, the cell
site's coordinates with the record they were taken from (`loc_event_id`), and - for timing advance and pings -
the carrier's estimate of the DEVICE's position (`dev_lat`/`dev_lon`/`dev_conf`), kept apart from the site.
`src_kind` says what the record came from: cdr, dump (tower dump), ta (timing advance), ping.

Cell identity. Carriers write the same LTE cell many ways; all reduce to the ECI (E-UTRAN cell identity,
eNodeB x 256 + cell) which tower lists also carry:
  decimal ECI / LTE_CI / E_CGI / CGI           12344578
  ECGI, MCC-MNC + hex ECI (Verizon lists)      311480-0c82216
  MCC-MNC-eNodeB-cell (USCC lists, exports)    311580-123456-1, 310260-0012345-005
  15-digit ECGI, MCC MNC + 9-digit ECI          310260012344578
  eNodeB column + cell / sector-ID column       48221 + 2, 51234 + Cell Face 22
  AT&T CellLocation (ECI:eNodeB:lon:lat:az...)  [12344578:48221:-77.30020:38.80010:110:-1.0:200;...]
A record is placed at its cell site from coordinates on the record itself, else from a tower list by ECI
(same folder - the same carrier - first; a list elsewhere only if all lists naming the cell agree), else by
the cell label as written. Nothing is guessed silently: every basis is stored and summarised in meta
'telecom' for the data-quality finding and REVIEW.md."""
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
DUMP_NAME_RE = re.compile(r"(?i)(?:twd_|reporttower|towerdata|tower[ _-]?dump|_enb_|twrdmp|first_serving|last_serving|"
                          r"areasearch|areadump|area[ _-]?search)")


# ---------------------------------------------------------------- normalisers

def norm_number(v) -> Optional[str]:
    """E.164 for NANP / '+' numbers; other values (short codes, foreign numbers without '+', IoT numbers) as digits."""
    if v in (None, ""):
        return None
    s = str(v).strip()
    if s.lower() in ("null", "n/a", "na", "none", "unknown", "-"):
        return None
    if re.fullmatch(r"\d+\.0+", s):
        s = s.split(".")[0]
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


def _int(v) -> Optional[int]:
    if v in (None, ""):
        return None
    s = str(v).strip()
    if re.fullmatch(r"\d+(?:\.0+)?", s):
        return int(s.split(".")[0])
    return None


ECI_MAX = (1 << 28) - 1      # an LTE ECI is 28 bits: 20-bit eNodeB + 8-bit cell


def parse_eci(v) -> tuple[Optional[int], str]:
    """(ECI, form) from any of the spellings in the module docstring; (None, '') when not an LTE cell identity."""
    if v in (None, ""):
        return None, ""
    s = str(v).strip().strip('"').strip()
    if not s or s.lower() in ("n/a", "na", "null", "none", "0", "-"):
        return None, ""
    if ":" in s and not s.startswith("["):
        s = s.split(":")[0].strip()          # 'first:last' (AT&T tower dumps) - the first cell
    if re.fullmatch(r"\d+\.0+", s):
        s = s.split(".")[0]
    parts = [p for p in re.split(r"[-_ ]+", s) if p]
    if len(parts) == 2 and re.fullmatch(r"\d{5,6}", parts[0]) and re.fullmatch(r"[0-9a-fA-F]{1,8}", parts[1]):
        x = parts[1]
        if re.search(r"[a-fA-F]", x) or len(x) == 7:
            return int(x, 16), "MCC-MNC + hex ECI"
        return int(x), "MCC-MNC + ECI"
    if len(parts) == 3 and re.fullmatch(r"\d{5,6}", parts[0]) and parts[1].isdigit() and parts[2].isdigit():
        enb, cell = int(parts[1]), int(parts[2])
        if cell < 256:
            return enb * 256 + cell, "MCC-MNC-eNodeB-cell"
        return None, ""
    if len(parts) == 2 and re.fullmatch(r"0\d{6}", parts[0]) and parts[1].isdigit() and int(parts[1]) < 256:
        return int(parts[0]) * 256 + int(parts[1]), "eNodeB-cell"     # zero-padded 7-digit eNodeB (Sprint lists)
    if len(parts) == 1 and s.isdigit():
        if len(s) == 15 and s[0] in "234567":
            return int(s[6:]), "15-digit ECGI (MCC MNC ECI)"
        n = int(s)
        if 256 <= n <= ECI_MAX:
            return n, "ECI"
    return None, ""     # includes 5G NR identities (36-bit NCI / 17-digit NCGI), which are not LTE ECIs


def parse_cell_location(v) -> Optional[dict]:
    """AT&T 'CellLocation': '[ECI:eNodeB:longitude:latitude:azimuth:...;...]' (longitude before latitude).
    Returns the first listed cell; 0,0 coordinates or azimuth -1 mean unknown."""
    s = str(v or "").strip()
    if not (s.startswith("[") and s.endswith("]") and ":" in s):
        return None
    cells = [c for c in s[1:-1].split(";") if c.strip()]
    if not cells:
        return None
    f = cells[0].split(":")
    out = {"cells_listed": len(cells), "raw_first": cells[0]}
    eci = _int(f[0]) if f else None
    out["eci"] = eci if eci and eci >= 256 else None
    out["enb"] = _int(f[1]) if len(f) > 1 and _int(f[1]) else None
    try:
        lon, lat = float(f[2]), float(f[3])
        if (lat, lon) != (0.0, 0.0) and -90 <= lat <= 90 and -180 <= lon <= 180:
            out["lat"], out["lon"] = lat, lon
    except (IndexError, ValueError):
        pass
    try:
        az = float(f[4])
        if 0 <= az <= 360:
            out["azimuth"] = az
    except (IndexError, ValueError):
        pass
    return out


def parse_duration(v, header: str = "") -> Optional[float]:
    if v in (None, ""):
        return None
    s = str(v).strip().lower()
    if s in ("null", "n/a", "na"):
        return None
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


_OUT = re.compile(r"(?:^|[^a-z])(?:out|outgoing|outbound|mo|m0|moc|orig|originat\w*|sent|send|dialed|dialled|o)(?:$|[^a-z])")
_IN = re.compile(r"(?:^|[^a-z])(?:in|incoming|inbound|mt|mtc|term|terminat\w*|received|receive|recv|i)(?:$|[^a-z])")
_FWD = re.compile(r"(?:^|[^a-z])(?:mf|fwd|forwarded|call ?forward\w*)(?:$|[^a-z])")


def norm_dir(direction, action) -> str:
    for v in (direction, action):
        s = str(v or "").lower().replace("_", " ")
        if not s:
            continue
        if _FWD.search(s):
            return "fwd"
        o, i = bool(_OUT.search(s)), bool(_IN.search(s))
        if o != i:
            return "out" if o else "in"
    return ""


def norm_kind(action, default_category: Optional[str] = None) -> str:
    s = str(action or "").lower()
    if re.search(r"\bmms\b|\bmm1\b", s):
        return "mms"
    if re.search(r"\brcs\b|rcs-", s):
        return "rcs"
    if re.search(r"\b(?:sms|text|txt|message|msg|smsc)\b|sms[- ]?m[ot]|sms\w*inmsc|\bsms\w*", s):
        return "sms"
    if re.search(r"\b(?:data|gprs|packet|internet|ip session|pdp|lte data|session|lte sdr|data only)\b", s):
        return "data"
    if re.search(r"\b(?:voice|call|calls|moc|mtc|volte|vowifi|wifi call|voicemail|vm|audio call)\b|callforward", s):
        return "voice"
    if s in ("null", "n/a", "none"):
        return ""
    return "voice" if (not s and default_category == "communication") else ("other" if s else "")


TEXT_KINDS = ("sms", "mms", "rcs")


def norm_imei(v) -> tuple[Optional[str], str]:
    """IMEIs are compared on their first 14 digits (TAC + serial): carriers append a Luhn check digit, a 0, or a
    two-digit software version. A value shown in scientific notation was damaged by a spreadsheet and is unusable."""
    s = str(v or "").strip()
    if not s or s.lower() in ("null", "n/a", "na", "none"):
        return None, ""
    if re.search(r"\d[eE]\+\d", s):
        return None, "sci"
    if re.fullmatch(r"\d+\.0+", s):
        s = s.split(".")[0]
    d = re.sub(r"\D", "", s)
    if 14 <= len(d) <= 16:
        return d[:14], ""
    if re.fullmatch(r"[0-9A-Fa-f]{14}", s):
        return s.upper(), ""                 # MEID (hex)
    return (d or None), ("short" if d else "")


def fnum(v, lo, hi) -> Optional[float]:
    if v in (None, ""):
        return None
    try:
        x = float(str(v).strip().lstrip("'").replace(",", "."))
    except ValueError:
        return None
    return x if lo <= x <= hi and not math.isnan(x) else None


def km(lat1, lon1, lat2, lon2) -> float:
    r = 6371.0088
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = p2 - p1, math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(min(1.0, math.sqrt(a)))


def cell_identity(tel: dict, hdr: dict, tower: bool) -> dict:
    """ECI, eNodeB, cell, a readable label and any coordinates written in the cell value itself."""
    out: dict = {"eci": None, "enb": None, "cell": None, "label": None, "form": ""}
    loc = parse_cell_location(tel.get("cell"))
    if loc:
        out.update({k: loc.get(k) for k in ("eci", "enb", "lat", "lon", "azimuth")})
        out["form"] = "AT&T CellLocation"
        out["cells_listed"] = loc["cells_listed"]
        if out["eci"]:
            out["cell"] = out["eci"] % 256
            out["enb"] = out["enb"] or out["eci"] // 256
            out["label"] = f"{out['eci'] // 256}-{out['eci'] % 256}"
        return out
    eci, form = parse_eci(tel.get("eci"))
    enb = _int(tel.get("enb"))
    cell = _int(tel.get("cell"))
    if eci is None and enb is not None and cell is not None and 0 <= cell < 256:
        # records: the sector / cell-face column is the cell ID. Tower lists: only a column named as a cell ID
        # ('Cell_ID', 'Cell Number') - a list's 'Sector' (1/2/3) is not the cell ID.
        if not tower or re.search(r"cell", hdr.get("cell", ""), re.I):
            eci, form = enb * 256 + cell, "eNodeB + cell"
    out["eci"], out["form"] = eci, form
    if eci is not None:
        out["enb"], out["cell"] = eci // 256, eci % 256
        out["label"] = f"{eci // 256}-{eci % 256}"
    elif enb is not None:
        out["enb"] = enb
        out["label"] = f"{enb}-{tel.get('cell')}" if tel.get("cell") not in (None, "") else str(enb)
    else:
        out["label"] = norm_cell(tel.get("cell"))
    return out


# ---------------------------------------------------------------- build

TEL_COLS = ["event_id", "source_id", "target", "target_basis", "other", "other_raw", "dir", "kind", "ts_epoch", "ts_utc",
            "duration_s", "cell", "cell_last", "eci", "enb", "lat", "lon", "azimuth", "beamwidth", "site_name", "loc_basis",
            "loc_event_id", "imei", "imsi", "dev_lat", "dev_lon", "dev_conf", "src_kind", "section", "note", "loc_ref"]


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
        for r, tel, ex in _tel_events(con, sid):
            if r["account"] or ex.get("_tel_kind") == "towerlist":
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
                   "no_target": 0, "neither_end_target": 0, "cross_folder_matches": 0,
                   "filename_targets": {}, "imei_sci": 0, "imsi_sci": 0, "fwd_legs": 0, "multi_cell": 0,
                   "dump_sources": {}, "kinds": collections.Counter(), "imsi_targets": {}, "eci_forms": collections.Counter(),
                   "dump_by_direction": 0}
    if not n_tel:
        dbm.set_meta(con, "telecom", None)
        con.commit()
        return {}
    if prog:
        prog.message("Telecom records: calls, texts, tower dumps, location reports and cell sites")
        prog.set_total(n_tel, "records")
    inferred = _infer_targets(con)
    srcrows = {r[0]: (r[1], r[2], r[3], r[4]) for r in con.execute("SELECT id, label, path, display, config FROM sources")}
    labels = {k: v[0] for k, v in srcrows.items()}
    for sid, (num, basis) in inferred.items():
        con.execute("UPDATE events SET account=?, account_basis=? WHERE source_id=? AND account IS NULL "
                    "AND extra LIKE '%\"_tel\"%'", (num, basis, sid))
        stats["inferred_targets"][labels.get(sid, str(sid))] = {"target": num, "basis": basis}
    for sid, (lab, _p, disp, cfgs) in srcrows.items():
        try:
            cfg = json.loads(cfgs or "{}")
        except ValueError:
            cfg = {}
        b = cfg.get("default_account_basis") or ""
        if b.startswith("file name"):
            stats["filename_targets"][lab] = {"target": cfg.get("default_account"), "basis": b}
    con.commit()
    dump_name = {sid for sid, v in srcrows.items() if DUMP_NAME_RE.search(Path(v[2] or v[1] or "").name)}
    tel_rows, site_rows = [], []
    done = 0
    for r, tel, ex in _tel_events(con):
        done += 1
        hdr = ex.get("_tel_hdr") or {}
        towerlist = ex.get("_tel_kind") == "towerlist"
        ident = cell_identity(tel, hdr, towerlist)
        lat, lon = fnum(tel.get("lat"), -90, 90), fnum(tel.get("lon"), -180, 180)
        if lat is not None and lon is not None and lat == 0 and lon == 0:
            lat = lon = None
        if lat is None and ident.get("lat") is not None:
            lat, lon = ident["lat"], ident["lon"]
        az = fnum(tel.get("azimuth"), 0, 360)
        az = az if az is not None else ident.get("azimuth")
        bw = fnum(tel.get("beamwidth"), 0, 360)
        name = (tel.get("site_name") or "")[:120] or None
        has_party = bool(tel.get("orig") or tel.get("term") or r["counterparty"] or tel.get("subject"))
        if ident["form"]:
            stats["eci_forms"][ident["form"]] += 1
        if towerlist or (r["ts_epoch"] is None and not has_party and not tel.get("dev_lat")):
            if ident["label"] and (lat is not None or ident["eci"] is not None):
                site_rows.append((ident["label"], r["source_id"], r["id"], "tower list", name, lat, lon, az, bw,
                                  ident["eci"], ident["enb"]))
                stats["tower_rows"] += 1
            continue
        if lat is not None and lon is not None and ident["label"]:
            site_rows.append((ident["label"], r["source_id"], r["id"], "inline on a call record", name, lat, lon, az, bw,
                              ident["eci"], ident["enb"]))
            stats["inline_sites"] += 1
        notes = []
        if ident.get("cells_listed", 1) > 1:
            stats["multi_cell"] += 1
            notes.append(f"record lists {ident['cells_listed']} cells; the first is used")
        target = norm_number(r["account"]) if r["account"] else None
        target = target or (r["account"] or None)
        tbasis = r["account_basis"] or ("account column" if r["account"] else None)
        dev_lat = fnum(tel.get("dev_lat"), -90, 90)
        dev_lon = fnum(tel.get("dev_lon"), -180, 180)
        if dev_lat is not None and dev_lon is not None and dev_lat == 0 and dev_lon == 0:
            dev_lat = dev_lon = None
        other = other_raw = None
        d = ""
        o, t = norm_number(tel.get("orig")), norm_number(tel.get("term"))
        dirraw = norm_dir(r["direction"], r["action"])
        if not target and (o or t) and dirraw in ("out", "in"):
            # tower dumps: the phone on the tower is the calling number of an outgoing record, the called number
            # of an incoming one
            target = o if dirraw == "out" else t
            tbasis = "phone on the record (calling number when outgoing, called number when incoming)"
            stats["dump_by_direction"] += 1
        if tel.get("orig") is not None or tel.get("term") is not None:
            if target and o == target and t != target:
                other, other_raw, d = t, tel.get("term"), "out"
            elif target and t == target and o != target:
                other, other_raw, d = o, tel.get("orig"), "in"
            elif target and o == target and t == target:
                d = ""
                notes.append("both ends are the target")
            elif target and o is not None and t is None:
                other, other_raw, d = o, tel.get("orig"), "in"
            elif target and t is not None and o is None:
                other, other_raw, d = t, tel.get("term"), "out"
            elif target:
                notes.append("neither end is the target number (forwarded or conference leg?)")
                stats["neither_end_target"] += 1
        elif r["counterparty"]:
            other, other_raw = norm_number(r["counterparty"]), r["counterparty"]
            d = dirraw
        if dirraw == "fwd":
            d = "fwd"
            stats["fwd_legs"] += 1
        if not d:
            d = dirraw if not notes else ""
        if other is not None and target is not None and other == target:
            other = other_raw = None
        if not target:
            stats["no_target"] += 1
        kind = norm_kind(r["action"], r["category"])
        if kind in ("", "other"):
            for k_ in ("Source", "Service_Type", "Service Type", "Type", "Record Type", "RCD_TYPE", "Msg Type",
                       "Charge Info", "Feature", "Apn"):
                if ex.get(k_):
                    k2 = norm_kind(ex[k_])
                    if k2 not in ("", "other"):
                        kind = k2
                        break
        if kind in ("", "other") and ex.get("_section"):
            k2 = norm_kind(re.sub(r"(?i)usage for.*", "", ex["_section"].split("|")[-1]))   # 'Voice Usage For: ...'
            if k2 not in ("", "other"):
                kind = k2
        if kind in ("", "other") and (ex.get("BytesUp") or ex.get("BytesDn") or ex.get("Apn") or ex.get("Access Point Name")):
            kind = "data"
        if kind == "data" and other is None:
            d = d or "out"
        stats["kinds"][kind or "unknown"] += 1
        dur = parse_duration(tel.get("duration"), ex.get("_tel_duration_header", ""))
        imei, why = norm_imei(tel.get("imei"))
        if why == "sci":
            stats["imei_sci"] += 1
            notes.append("IMEI shown in scientific notation (damaged by a spreadsheet) - not used")
        imsi_raw = str(tel.get("imsi") or "")
        if re.search(r"\d[eE]\+\d", imsi_raw):
            imsi = None
            stats["imsi_sci"] += 1
            notes.append("IMSI shown in scientific notation (damaged by a spreadsheet) - not used")
        else:
            imsi = re.sub(r"\D", "", imsi_raw.split(".")[0] if re.fullmatch(r"\d+\.0+", imsi_raw) else imsi_raw) or None
        if dev_lat is not None:
            src_kind = "ta" if ident["label"] else "ping"
        elif r["source_id"] in dump_name:
            src_kind = "dump"
        else:
            src_kind = "cdr"
        basis = "inline on this record" if (lat is not None and lon is not None) else None
        last = cell_identity({"cell": tel.get("cell_last"), "eci": tel.get("eci_last"), "enb": tel.get("enb_last")}, hdr, False)
        tel_rows.append((r["id"], r["source_id"], target, tbasis, other, (other_raw or None), d or None, kind or None,
                         r["ts_epoch"], r["ts_utc"], dur, ident["label"], last["label"], ident["eci"], ident["enb"],
                         lat, lon, az, bw, name, basis, r["id"] if basis else None, imei, imsi, dev_lat, dev_lon,
                         (str(tel.get("conf"))[:40] if tel.get("conf") not in (None, "") else None), src_kind,
                         ex.get("_section"), "; ".join(notes) or None, None))
        stats["records"] += 1
        if len(tel_rows) >= 5000:
            _flush(con, tel_rows, site_rows)
            if prog:
                prog.update(done)
                prog.check_cancel()
    _flush(con, tel_rows, site_rows)
    _classify_dumps(con, stats, dump_name, labels)
    _resolve_imsi_targets(con, stats)
    _resolve_locations(con, params, stats)
    stats["located"] = dbm.one(con, "SELECT COUNT(*) FROM tel WHERE lat IS NOT NULL") or 0
    stats["unlocated"] = stats["records"] - stats["located"]
    stats["unlocated_reasons"] = dict(stats["unlocated_reasons"])
    stats["kinds"] = dict(stats["kinds"])
    stats["eci_forms"] = dict(stats["eci_forms"])
    stats["src_kinds"] = {k: n for k, n in con.execute("SELECT src_kind, COUNT(*) FROM tel GROUP BY src_kind")}
    dbm.set_meta(con, "telecom", stats)
    con.commit()
    if log:
        log.info("telecom: %s records (%s), %s located, %s tower-list rows", stats["records"], stats["src_kinds"],
                 stats["located"], stats["tower_rows"])
    return stats


def _flush(con, tel_rows, site_rows):
    if site_rows:
        con.executemany("INSERT INTO cell_sites(cell, source_id, event_id, origin, site_name, lat, lon, azimuth, beamwidth, eci, enb)"
                        " VALUES (?,?,?,?,?,?,?,?,?,?,?)", site_rows)
    if tel_rows:
        con.executemany(f"INSERT INTO tel({','.join(TEL_COLS)}) VALUES ({','.join('?' * len(TEL_COLS))})", tel_rows)
    con.commit()
    tel_rows.clear()
    site_rows.clear()


def _classify_dumps(con, stats: dict, dump_name: set, labels: dict) -> None:
    """A source is a tower dump when its file name says so, or when it covers many phones with none dominant
    (no target named anywhere). Its records are about whoever was on the tower, not about a target."""
    for sid, n, nt, top in con.execute(
            "SELECT source_id, COUNT(*), COUNT(DISTINCT target), "
            "(SELECT COUNT(*) FROM tel t2 WHERE t2.source_id=tel.source_id GROUP BY target ORDER BY COUNT(*) DESC LIMIT 1) "
            "FROM tel WHERE src_kind IN ('cdr','dump') GROUP BY source_id").fetchall():
        by_name = sid in dump_name
        by_content = nt >= 10 and (top or 0) / max(1, n) < 0.5
        if by_name or by_content:
            con.execute("UPDATE tel SET src_kind='dump' WHERE source_id=? AND src_kind='cdr'", (sid,))
            stats["dump_sources"][labels.get(sid, str(sid))] = {
                "records": n, "phones": nt, "basis": "file name" if by_name else f"{nt} different phones, none on half the records"}
    con.commit()


def _resolve_imsi_targets(con, stats: dict) -> None:
    """Timing-advance reports are requested by IMSI. When another return shows which number used that IMSI,
    the records are filed under that number (the link is cited in the data-quality finding)."""
    for (t,) in con.execute("SELECT DISTINCT target FROM tel WHERE target GLOB '[0-9]*' AND target NOT GLOB '*[^0-9]*' "
                            "AND length(target) BETWEEN 14 AND 15").fetchall():
        rows = con.execute("SELECT target, COUNT(*), MIN(event_id) FROM tel WHERE imsi=? AND target IS NOT NULL AND target != ? "
                           "AND src_kind='cdr' GROUP BY target ORDER BY 2 DESC", (t, t)).fetchall()
        if len(rows) == 1:
            num, n, eid = rows[0]
            con.execute("UPDATE tel SET target=?, target_basis=COALESCE(target_basis,'') || ? WHERE target=?",
                        (num, f"; IMSI {t} is used by {num} in {n} of its call records", t))
            stats["imsi_targets"][t] = {"number": num, "records": n, "event_id": eid}
        elif rows:
            stats["imsi_targets"][t] = {"number": None, "candidates": [x[0] for x in rows[:5]]}
    con.commit()


def _folder(path: str) -> str:
    try:
        return str(Path(path).resolve().parent).lower()
    except OSError:
        return str(Path(path).parent).lower()


def _resolve_locations(con, params: dict, stats: dict) -> None:
    """Give each unlocated record the coordinates of its first cell from a tower list: by ECI when the record
    has one, else by the cell label as written. A list in the same folder as the record wins; otherwise a cell
    is matched only if every list that names it agrees to within the same-site distance. Records still unlocated
    are then looked up in the reference cell-site library (cellsites/, see cellref.py) when one is installed."""
    agree_km = float(params.get("tel_same_site_km", 0.1))
    paths = {r[0]: r[1] for r in con.execute("SELECT id, path FROM sources")}
    folders = {k: _folder(v) for k, v in paths.items()}
    by_eci: dict = collections.defaultdict(list)
    by_label: dict = collections.defaultdict(list)
    for r in con.execute("SELECT cell, source_id, event_id, origin, site_name, lat, lon, azimuth, beamwidth, eci FROM cell_sites "
                         "WHERE origin='tower list' AND lat IS NOT NULL ORDER BY id"):
        if r[9] is not None:
            by_eci[r[9]].append(r)
        else:
            by_label[r[0]].append(r)
    have_lists = bool(by_eci or by_label)
    upd = []
    conflicts = {}
    pending = []          # (event_id, source_id, cell, eci, reason) - not placed by the case's own lists
    for eid, sid, cell, eci in con.execute("SELECT event_id, source_id, cell, eci FROM tel WHERE lat IS NULL").fetchall():
        if eci is None and not cell:
            stats["unlocated_reasons"]["no cell on the record"] += 1
            continue
        if not have_lists:
            pending.append((eid, sid, cell, eci, "no tower list loaded"))
            continue
        if eci is not None:
            cands, key = by_eci.get(eci) or [], f"ECI {eci}"
        else:
            cands, key = by_label.get(cell) or [], cell
        if not cands:
            pending.append((eid, sid, cell, eci, "cell not in any tower list"))
            continue
        same = [c for c in cands if folders.get(c[1]) == folders.get(sid)]
        pick, basis = None, None
        how = "by ECI" if eci is not None else "by cell label"
        if same:
            pick, basis = same[0], f"tower list in the same folder ({how})"
        else:
            ref = cands[0]
            if all(km(ref[5], ref[6], c[5], c[6]) <= agree_km for c in cands):
                pick, basis = ref, f"tower list in another folder ({how} - VERIFY it is the same carrier)"
                stats["cross_folder_matches"] += 1
            else:
                stats["unlocated_reasons"]["tower lists disagree on this cell"] += 1
                conflicts[key] = sorted({f"{c[5]:.5f},{c[6]:.5f}" for c in cands})
                continue
        upd.append((pick[5], pick[6], pick[7], pick[8], pick[4], basis, pick[2], None, eid))
    _resolve_from_library(con, params, stats, pending, paths, agree_km, upd, conflicts)
    con.executemany("UPDATE tel SET lat=?, lon=?, azimuth=COALESCE(azimuth, ?), beamwidth=COALESCE(beamwidth, ?), "
                    "site_name=COALESCE(site_name, ?), loc_basis=?, loc_event_id=?, loc_ref=? WHERE event_id=?", upd)
    stats["conflicts"] = [{"cell": k, "coordinates": v} for k, v in sorted(conflicts.items())][:50]
    # records located from coordinates on the record itself often carry no azimuth / beamwidth: take them from
    # the tower list entry for the same ECI (the same folder first), keeping any value the record gives
    fill = []
    for eid, sid, eci in con.execute("SELECT event_id, source_id, eci FROM tel WHERE eci IS NOT NULL AND lat IS NOT NULL "
                                     "AND (azimuth IS NULL OR beamwidth IS NULL)").fetchall():
        cands = [c for c in by_eci.get(eci) or [] if c[7] is not None or c[8] is not None]
        if not cands:
            continue
        same = [c for c in cands if folders.get(c[1]) == folders.get(sid)]
        c = (same or cands)[0]
        fill.append((c[7], c[8], eid))
    con.executemany("UPDATE tel SET azimuth=COALESCE(azimuth, ?), beamwidth=COALESCE(beamwidth, ?) WHERE event_id=?", fill)
    stats["sector_from_list"] = len(fill)
    con.commit()


def _resolve_from_library(con, params: dict, stats: dict, pending: list, paths: dict, agree_km: float,
                          upd: list, conflicts: dict) -> None:
    """Place records the case's own lists could not, from the reference cell-site library (appends to upd)."""
    from . import cellref

    lib = None
    if params.get("tel_reference_library", True):
        lib = cellref.Library(Path(params["tel_library_dir"]) if params.get("tel_library_dir") else None)
        if not lib.available:
            lib = None
    if lib is None:
        for *_, reason in pending:
            stats["unlocated_reasons"][reason] += 1
        return
    forced = cellref.norm_carrier(str(params.get("tel_carrier") or ""))
    hints: dict = {}
    lstats = {"matched": 0, "by_carrier": collections.Counter(), "carrier_basis": {}, "no_carrier_agreed": 0}
    try:
        for eid, sid, cell, eci, reason in pending:
            if sid not in hints:
                if forced:
                    hints[sid] = (forced, "case setting tel_carrier")
                else:
                    hints[sid] = cellref.carrier_hint(paths.get(sid) or "")
                if hints[sid][0]:
                    lstats["carrier_basis"][paths.get(sid, "")[-120:]] = f"{hints[sid][0]} ({hints[sid][1]})"
            carrier = hints[sid][0]
            if eci is not None:
                cands = lib.by_eci(eci)
                if carrier:
                    cands = [c for c in cands if c["carrier"] == carrier]
                how = "by ECI"
            elif carrier and cell:
                cands, how = lib.by_label(carrier, cell), "by cell label"
            else:
                cands, how = [], ""
            if not cands:
                stats["unlocated_reasons"]["cell not in any tower list or the reference library" if not carrier
                                          else f"cell not in the {carrier} reference list"] += 1
                continue
            ref = cands[0]
            if not all(km(ref["lat"], ref["lon"], c["lat"], c["lon"]) <= agree_km for c in cands):
                carriers = sorted({c["carrier"] for c in cands})
                why = ("reference lists of several carriers name this ECI - set the carrier (tel_carrier)"
                       if len(carriers) > 1 else "reference lists disagree on this cell")
                stats["unlocated_reasons"][why] += 1
                conflicts[f"ECI {eci}" if eci is not None else cell] = sorted(
                    {f"{c['lat']:.5f},{c['lon']:.5f} ({c['carrier']})" for c in cands})[:8]
                continue
            basis = (f"reference library, {ref['carrier']} list ({how}"
                     + ("" if carrier else "; carrier not known - every list naming it agrees") + ")")
            if not carrier:
                lstats["no_carrier_agreed"] += 1
            cite = f"cellsites/{ref['file']} {ref['loc']}"[:300]
            upd.append((ref["lat"], ref["lon"], ref["azimuth"], ref["beamwidth"], ref["site"], basis, None, cite, eid))
            lib.note_used(ref)
            lstats["matched"] += 1
            lstats["by_carrier"][ref["carrier"]] += 1
        stats["library"] = {"path": str(lib.path), "matched": lstats["matched"],
                            "by_carrier": dict(lstats["by_carrier"]), "no_carrier_agreed": lstats["no_carrier_agreed"],
                            "carrier_basis": dict(list(lstats["carrier_basis"].items())[:40]),
                            "files_used": sorted(lib.used_files.values(), key=lambda u: -u["records"])[:60]}
    finally:
        lib.close()
