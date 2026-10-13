"""Source preparation (ZIP extraction, hashing), scanning/mapping, and resumable ingestion."""
from __future__ import annotations

import collections
import datetime as dt
import json
import re
import time
from pathlib import Path
from typing import Callable, Optional

from . import db as dbm
from . import readers
from .identifiers import EMAIL_RE, extract as extract_ids, phone_from_cell
from .ipaddr import classify, find_ips, split_ip_port, subnet_key
from .mapping import (TEL_FIELDS, apply_status, categorize, default_account_from, is_tel_mapping, is_tower_mapping,
                      propose_mapping, suggest_default_category, target_from_filename)
from .timeparse import TsParser, TzSpec, fmt_utc, infer_date_order, suggest_source_tz
from .util import sha256_file, utc_now_str

EVENT_COLS = ["id", "source_id", "seq", "tbl", "loc", "line", "byte_offset", "byte_len", "ts_utc", "ts_epoch",
              "ts_raw", "tz_basis", "ts_flag", "ip", "ip_ver", "ip_class", "port", "subnet", "ip_raw", "account",
              "account_basis", "action", "category", "status", "user_agent", "device", "location", "counterparty",
              "direction", "amount", "currency", "raw", "extra"]
INSERT_EVENT = f"INSERT INTO events({','.join(EVENT_COLS)}) VALUES ({','.join('?' * len(EVENT_COLS))})"
INSERT_ID = "INSERT INTO identifiers(event_id, source_id, kind, value, norm, validity) VALUES (?,?,?,?,?,?)"


# ---------------------------------------------------------------- prepare: zips + hashes

def prepare_sources(case, con, prog=None, log=None) -> None:
    """Extract ZIPs (registering members as sources), hash every file, flag exact duplicates."""
    while True:
        zips = dbm.rows(con, "SELECT * FROM sources WHERE kind='zip' AND status='new' ORDER BY id")
        if not zips:
            break
        for z in zips:
            cfg = json.loads(z["config"]) if z.get("config") else {}
            dest = case.extracted_dir / z["label"]
            try:
                if prog:
                    prog.message(f"Extracting {Path(z['path']).name}")
                members = readers.safe_extract_zip(Path(z["path"]), dest, cfg.get("zip_password") or None)
            except Exception as e:  # noqa: BLE001
                con.execute("UPDATE sources SET status='error', error=? WHERE id=?", (str(e), z["id"]))
                con.commit()
                if log:
                    log.warning("ZIP %s: %s", z["label"], e)
                continue
            for name, path in members:
                kind = readers.detect_kind(path)
                st = path.stat()
                label = f"S{(dbm.one(con, 'SELECT COUNT(*) FROM sources') or 0) + 1:02d}"
                con.execute(
                    "INSERT INTO sources(label, path, display, parent_id, member, kind, size, mtime, status, added_at)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (label, str(path), f"{z['display']} ▸ {name}", z["id"], name, kind, st.st_size, "",
                     "unsupported" if kind in ("unsupported", "empty", "unreadable") else "new", utc_now_str()))
            cfg.pop("zip_password", None)
            con.execute("UPDATE sources SET status='container', config=? WHERE id=?", (json.dumps(cfg), z["id"]))
            con.commit()
            case.audit(con, "zip_extracted", {"source": z["label"], "members": len(members), "to": str(dest)})
    todo = dbm.rows(con, "SELECT id, label, path, size FROM sources WHERE sha256 IS NULL ORDER BY id")
    total = sum(r["size"] or 0 for r in todo) or 1
    done = 0
    if prog:
        prog.set_total(total, "bytes")
    for r in todo:
        if prog:
            prog.message(f"Hashing {r['label']} {Path(r['path']).name}")
            prog.check_cancel()

        def cb(n, _base=done):
            nonlocal done
            done += n
            if prog:
                prog.update(done)
        try:
            h = sha256_file(r["path"], cb)
        except OSError as e:
            con.execute("UPDATE sources SET status='error', error=? WHERE id=?", (f"cannot read: {e}", r["id"]))
            con.commit()
            continue
        con.execute("UPDATE sources SET sha256=?, hashed_at=? WHERE id=?", (h, utc_now_str(), r["id"]))
        dup = dbm.one(con, "SELECT label FROM sources WHERE sha256=? AND id<? AND kind!='zip' AND status!='duplicate' ORDER BY id LIMIT 1",
                      (h, r["id"]))
        if dup:
            con.execute("UPDATE sources SET status='duplicate', error=? WHERE id=?",
                        (f"identical to {dup} (same SHA-256); not ingested twice", r["id"]))
        con.commit()


# ---------------------------------------------------------------- scan + config

def _samples_by_header(table: dict) -> dict:
    hd = table.get("headers") or []
    rows = table.get("raw_samples") or table.get("samples") or []
    out = {h: [] for h in hd}
    for r in rows:
        for i, h in enumerate(hd):
            if i < len(r):
                out[h].append(r[i])
    return out


def build_config(scan: dict, src: dict, params: dict) -> dict:
    name = Path(src.get("member") or src["path"]).name
    cfg = {"kind": scan["kind"], "encoding": scan.get("encoding"), "tables": [], "notes": scan.get("notes", []),
           "skip": False}
    header_cells, ts_header_cells = [], []
    for t in scan.get("tables", []):
        t = dict(t)
        t.pop("raw_samples", None)
        tcfg = {k: v for k, v in t.items() if k != "samples"}
        if t.get("mode") == "table":
            mapping, notes = propose_mapping(t.get("headers") or [], _samples_by_header(next(
                x for x in scan["tables"] if x["name"] == t["name"])))
            tcfg["mapping"] = mapping
            tcfg["mapping_notes"] = notes
            sb = _samples_by_header(next(x for x in scan["tables"] if x["name"] == t["name"]))
            vals = sb.get(mapping.get("ts")) or sb.get(mapping.get("date")) or []
            order, note = infer_date_order([v for v in vals if isinstance(v, str)])
            tcfg["date_order"], tcfg["date_order_note"] = order, note
            cite = t.get("header_cite") or f"{t['name']} header"
            for h in t.get("headers") or []:
                header_cells.append((cite, h))
            for f in ("ts", "date", "time", "tz"):
                if mapping.get(f):
                    ts_header_cells.append((cite, mapping[f]))
        else:
            tcfg["pair_window"] = int(t.get("pair_window") if t.get("pair_window") is not None else params.get("pair_window", 6))
            tcfg["date_order"], tcfg["date_order_note"] = "MDY", ""
            samples = [s[0] for s in t.get("samples", []) if s]
            order, note = infer_date_order([m.group(0) for s in samples for m in re.finditer(r"\b\d{1,2}[/.]\d{1,2}[/.]\d{2,4}\b", str(s))])
            if note == "":
                tcfg["date_order"] = order
        cfg["tables"].append(tcfg)
    pre = [(c, t) for c, t in scan.get("preamble", [])]
    tz = suggest_source_tz(ts_header_cells or header_cells, pre, name)
    cfg["tz"], cfg["tz_assumed"], cfg["tz_basis"], cfg["tz_conflicts"] = tz["tz"], tz["assumed"], tz["basis"], tz["conflicts"]
    acct, abasis = default_account_from(pre)
    if not acct:
        m = EMAIL_RE.search(name)
        if m:
            acct, abasis = m.group(1), f"file name '{name}'"
    has_account_col = any(t.get("mapping", {}).get("account") for t in cfg["tables"])
    tel_file = any(is_tel_mapping(t.get("mapping") or {}) and not is_tower_mapping(t.get("mapping") or {})
                   for t in cfg["tables"])
    if not acct and tel_file and not has_account_col \
            and not any((t.get("mapping") or {}).get("subject") for t in cfg["tables"]):
        acct, abasis = target_from_filename(name)
    cfg["default_account"] = acct or ""
    cfg["default_account_basis"] = abasis if acct else ""
    if acct and has_account_col:
        cfg["default_account_note"] = "used only for rows whose account cell is empty"
    # an account column whose (single) value is named on the same preamble line wins over the label
    if acct:
        for t in cfg["tables"]:
            col = (t.get("mapping") or {}).get("account")
            if not col:
                continue
            vals = [str(v).strip() for v in _samples_by_header(next(x for x in scan["tables"] if x["name"] == t["name"])).get(col, []) if v]
            if vals:
                top = max(set(vals), key=vals.count)
                if top != acct and top.lower() in abasis.lower():
                    cfg["default_account"] = top.lower() if EMAIL_RE.fullmatch(top) else top
                    cfg["default_account_basis"] = abasis + f"; the same line names '{top}', the value in the account column '{col}'"
                    break
    src_cat, src_basis = suggest_default_category([("file name", name)])
    for t in cfg["tables"]:
        if t.get("mode") == "table":
            cat, cb = suggest_default_category([(f"table '{t['name']}'", str(t["name"]))])
            t["default_category"] = cat or src_cat or ""
            t["default_category_basis"] = cb if cat else src_basis
        elif t.get("name") == "text" or cfg["kind"] in ("pdf", "text"):
            t["default_category"] = src_cat or ""
            t["default_category_basis"] = src_basis
    cfg["default_category"] = src_cat or ""
    cfg["default_category_basis"] = src_basis
    return cfg


def scan_sources(case, con, prog=None, log=None, rescan_ids: Optional[list] = None) -> None:
    q = "SELECT * FROM sources WHERE status IN ('new') AND kind NOT IN ('zip')"
    todo = dbm.rows(con, q + " ORDER BY id")
    if rescan_ids:
        todo += dbm.rows(con, f"SELECT * FROM sources WHERE id IN ({','.join('?' * len(rescan_ids))})", rescan_ids)
    if prog:
        prog.set_total(len(todo) or 1, "files")
    params = case.params
    for i, s in enumerate(todo):
        if prog:
            prog.message(f"Scanning {s['label']} {Path(s['path']).name}")
            prog.check_cancel()
        try:
            sc = readers.scan(Path(s["path"]), s["kind"])
            cfg = build_config(sc, s, params)
            con.execute("UPDATE sources SET scan=?, config=?, kind=?, status='scanned', error=NULL, config_rev=config_rev+1 WHERE id=?",
                        (json.dumps(sc, default=str), json.dumps(cfg, default=str), s["kind"], s["id"]))
        except Exception as e:  # noqa: BLE001
            con.execute("UPDATE sources SET status='error', error=? WHERE id=?", (f"scan failed: {e}", s["id"]))
            if log:
                log.exception("scan %s", s["label"])
        con.commit()
        if prog:
            prog.update(i + 1)


# ---------------------------------------------------------------- record -> event

def parse_amount(v) -> Optional[float]:
    if v is None or v == "":
        return None
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return float(v)
    s = str(v).strip()
    neg = s.startswith("(") and s.endswith(")")
    s = re.sub(r"[^\d.,-]", "", s)
    if not s:
        return None
    if "," in s and "." in s:
        s = s.replace(",", "") if s.rfind(".") > s.rfind(",") else s.replace(".", "").replace(",", ".")
    elif "," in s and re.search(r",\d{1,2}$", s) and s.count(",") == 1:
        s = s.replace(",", ".")
    else:
        s = s.replace(",", "")
    try:
        x = float(s)
    except ValueError:
        return None
    return -abs(x) if neg else x


def _txt(v, n=1000) -> Optional[str]:
    if v is None:
        return None
    if isinstance(v, (dt.datetime, dt.date, dt.time)):
        s = v.isoformat()
    elif isinstance(v, float) and v.is_integer():
        s = str(int(v))
    else:
        s = str(v)
    s = s.strip()
    return s[:n] if s else None


class Ctx:
    """Everything needed to turn records of one source into events."""

    def __init__(self, src: dict, cfg: dict, params: dict):
        self.src = src
        self.cfg = cfg
        self.params = params
        self.tz = TzSpec(cfg.get("tz") or "UTC", assumed=bool(cfg.get("tz_assumed", True)), basis=cfg.get("tz_basis", ""))
        self.default_account = (cfg.get("default_account") or "").strip()
        self.default_account_basis = cfg.get("default_account_basis") or ""
        self.default_category = cfg.get("default_category") or None
        self.raw_max = int(params.get("store_raw_max", 4000))
        self.parsers: dict = {}
        self.tables = {t["name"]: t for t in cfg.get("tables", [])}
        self.imei_ctx = any("imei" in (h or "").lower() for t in cfg.get("tables", []) for h in (t.get("headers") or []))
        # tables read as call detail records / cell-site lists (any telecom column mapped)
        self.tel_tables = {t["name"] for t in cfg.get("tables", []) if is_tel_mapping(t.get("mapping") or {})}

    def parser(self, table: Optional[str], column: bool) -> TsParser:
        t = self.tables.get(table or "", {})
        key = (table, column)
        p = self.parsers.get(key)
        if p is None:
            p = TsParser(self.tz, date_order=t.get("date_order", "MDY"), column_mode=column)
            self.parsers[key] = p
        return p


def record_to_event(rec, ctx: Ctx, stats: dict) -> tuple[dict, list]:
    f: dict = {}
    extra: dict = {}
    tmeta = ctx.tables.get(rec.table or "", {})
    mapping = tmeta.get("mapping") or {}
    is_table = rec.cells is not None and bool(mapping or tmeta.get("mode") == "table")
    phone_cells = []
    if rec.cells is not None:
        cells = rec.cells
        used = set()
        for fld, h in mapping.items():
            if h in cells:
                used.add(h)
        tsv = cells.get(mapping["ts"]) if mapping.get("ts") else None
        if tsv in (None, "") and mapping.get("date"):
            d = cells.get(mapping["date"])
            t = cells.get(mapping.get("time")) if mapping.get("time") else None
            if d not in (None, ""):
                ds = d.date().isoformat() if isinstance(d, dt.datetime) else _txt(d)
                ts_ = t.isoformat() if isinstance(t, (dt.time, dt.datetime)) else (_txt(t) or "")
                if isinstance(t, dt.datetime):
                    ts_ = t.time().isoformat()
                tsv = f"{ds} {ts_}".strip()
        if mapping.get("tz") and tsv not in (None, ""):
            tzv = _txt(cells.get(mapping["tz"]))
            if tzv:
                tsv = (tsv.isoformat(sep=" ") if isinstance(tsv, dt.datetime) else str(tsv)) + " " + tzv
        f["ts"] = tsv
        for fld in ("ip", "port", "account", "action", "status", "user_agent", "device", "location",
                    "counterparty", "direction", "amount", "currency"):
            h = mapping.get(fld)
            if h:
                f[fld] = cells.get(h)
        for h, v in cells.items():
            if h not in used and v not in (None, ""):
                extra[h] = _txt(v, 2000)
        tel = {}
        for fld in TEL_FIELDS:
            h = mapping.get(fld)
            if h:
                v = _txt(cells.get(h), 200)
                if v is not None:
                    tel[fld] = v
        if tel and rec.table not in ctx.tel_tables:
            # telecom columns in a table that is not read as telecom (an analyst's mapping): keep them as plain cells
            for fld, v in tel.items():
                extra[mapping[fld]] = v
            tel = {}
        if tel:
            extra["_tel"] = tel
            if mapping.get("duration"):
                extra["_tel_duration_header"] = mapping["duration"]
            if is_tower_mapping(mapping):
                extra["_tel_kind"] = "towerlist"
            hint = {k: mapping[k] for k in ("cell", "eci") if mapping.get(k)}
            if hint:
                extra["_tel_hdr"] = hint
            if tmeta.get("section"):
                extra["_section"] = tmeta["section"][:300]
        for fld in ("account", "counterparty"):
            v = f.get(fld)
            if v not in (None, ""):
                ph = phone_from_cell(_txt(v) or "")
                if ph:
                    phone_cells.append((_txt(v), ph))
        for fld in ("orig", "term", "subject"):
            v = tel.get(fld)
            if v:
                ph = phone_from_cell(v)
                if ph:
                    phone_cells.append((v, ph))
        if tel.get("imsi") and re.fullmatch(r"\d{14,15}", tel["imsi"]):
            phone_cells.append(("__imsi__" + tel["imsi"], tel["imsi"]))
    else:
        f = dict(rec.fields)
    if rec.note:
        extra["_note"] = rec.note
    if rec.extra and rec.extra.get("lines"):
        extra["_lines"] = rec.extra["lines"]
    # timestamp
    ts_utc = ts_epoch = ts_raw = basis = flag = None
    tsv = f.get("ts")
    if tsv not in (None, ""):
        ts_raw = tsv.isoformat(sep=" ") if isinstance(tsv, (dt.datetime, dt.date)) else str(tsv)
        r = ctx.parser(rec.table, column=is_table).parse(tsv)
        if r is None:
            stats["ts_failed"] += 1
            if len(stats["ts_failed_examples"]) < 8:
                stats["ts_failed_examples"].append([rec.loc, ts_raw[:80]])
        else:
            ts_utc, ts_epoch, basis, flag = fmt_utc(r.utc), r.utc.timestamp(), r.basis, r.flags
            if "date_only" in (flag or ""):
                # a date without a time is a calendar date in the provider's zone: keep it as written
                local = r.utc.astimezone(ctx.tz.tz) if basis.startswith(("source tz", "ASSUMED")) else r.utc
                ts_utc = local.strftime("%Y-%m-%d")
                basis = basis + " (date only)"
            stats["ts_parsed"] += 1
            stats["basis"][basis] += 1
            for fl in (flag or "").split(","):
                if fl:
                    stats["flags"][fl] += 1
    else:
        stats["ts_missing"] += 1
    if rec.extra and rec.extra.get("lines"):
        flag = ",".join(x for x in [flag, "paired_by_proximity"] if x)
        stats["flags"]["paired_by_proximity"] += 1
    # ip
    ip = ver = cls = port = subnet = ip_raw = None
    ipv = f.get("ip")
    if ipv not in (None, ""):
        ip_raw = _txt(ipv, 200)
        sp = split_ip_port(ip_raw)
        if sp is None:
            found = find_ips(ip_raw)
            if found:
                sp = (found[0][0], found[0][1], found[0][2])
                extra["_ip_note"] = f"cell holds {len(found)} IPs; first used as the event IP"
        if sp:
            ip, ver, port = sp
            cls = classify(ip, ver)
            subnet = subnet_key(ip, ver)
        else:
            stats["ip_invalid"] += 1
            if len(stats["ip_invalid_examples"]) < 8:
                stats["ip_invalid_examples"].append([rec.loc, ip_raw[:60]])
    if f.get("port") not in (None, ""):
        try:
            pv = int(float(str(f["port"]).strip()))
            if 0 < pv < 65536:
                port = pv
        except ValueError:
            pass
    # account
    acct = _txt(f.get("account"), 300)
    abasis = None
    tel_ = extra.get("_tel") or {}
    if not acct and tel_.get("subject"):
        acct, abasis = tel_["subject"], "phone the record is about (column '" + str(mapping.get("subject")) + "')"
    if not acct and ctx.default_account:
        acct, abasis = ctx.default_account, "source default"
    if acct and EMAIL_RE.fullmatch(acct):
        acct = acct.lower()
    elif acct and (rec.table in ctx.tel_tables):
        ph = phone_from_cell(acct)
        if ph and ph != acct:
            acct = ph                     # a target number written as 7035550101 / (703) 555-0101 -> +17035550101
            abasis = (abasis + "; " if abasis else "") + "phone number normalised to E.164"
    action = _txt(f.get("action"), 500)
    status = apply_status(f.get("status"), action)
    dflt = tmeta.get("default_category", ctx.default_category) if tmeta else ctx.default_category
    if rec.cells is None and ts_utc is None:
        category = "other"   # a free-text line without a time is an attribute (e.g. 'Recovery SMS: ...'), not an event
    else:
        category = categorize(action, status, dflt or None, telecom=rec.table in ctx.tel_tables)
    stats["categories"][category] += 1
    raw = rec.raw if rec.raw is not None else ""
    if len(raw) > ctx.raw_max:
        extra["_raw_truncated_from"] = len(raw)
        raw = raw[: ctx.raw_max]
    ev = {
        "tbl": rec.table, "loc": rec.loc, "line": rec.line, "byte_offset": rec.offset, "byte_len": rec.length,
        "ts_utc": ts_utc, "ts_epoch": ts_epoch, "ts_raw": ts_raw, "tz_basis": basis, "ts_flag": flag or None,
        "ip": ip, "ip_ver": ver, "ip_class": cls, "port": port, "subnet": subnet, "ip_raw": ip_raw,
        "account": acct, "account_basis": abasis, "action": action, "category": category, "status": status or None,
        "user_agent": _txt(f.get("user_agent")), "device": _txt(f.get("device")), "location": _txt(f.get("location")),
        "counterparty": _txt(f.get("counterparty"), 300), "direction": _txt(f.get("direction"), 50),
        "amount": parse_amount(f.get("amount")), "currency": _txt(f.get("currency"), 20),
        "raw": raw, "extra": json.dumps(extra, ensure_ascii=False, default=str) if extra else None,
    }
    if rec.cells is not None:
        # identifiers from every cell except the time columns (they only add digits and colons)
        skip = {mapping.get(k) for k in ("ts", "date", "time", "tz", "imsi", "lat", "lon", "azimuth", "beamwidth",
                                         "duration")}
        id_text = " | ".join(str(v) for h, v in rec.cells.items() if h not in skip and v not in (None, ""))
        ids = extract_ids(id_text, imei_context=ctx.imei_ctx)
    else:
        ids = extract_ids(rec.raw or "", imei_context=ctx.imei_ctx)
    # the record's own IP lives in events.ip; only additional IPs in the record go to identifiers
    if ip:
        ids = [x for x in ids if not (x[0] in ("ipv4", "ipv6") and x[2] == ip)]
    have = {(k, n) for k, _r, n, _v in ids}
    for rawv, ph in phone_cells:
        if rawv.startswith("__imsi__"):
            if ("imsi", ph) not in have:
                ids.append(("imsi", ph, ph, "format"))
                have.add(("imsi", ph))
        elif ("phone", ph) not in have:
            ids.append(("phone", rawv, ph, "format"))
            have.add(("phone", ph))
    return ev, ids


def new_stats() -> dict:
    return {"rows": 0, "ts_parsed": 0, "ts_failed": 0, "ts_missing": 0, "ip_invalid": 0,
            "ts_failed_examples": [], "ip_invalid_examples": [], "nontable": 0, "skipped_lines": 0,
            "empty_pages": [], "basis": collections.Counter(), "flags": collections.Counter(),
            "categories": collections.Counter()}


def _stats_json(st: dict) -> str:
    d = dict(st)
    for k in ("basis", "flags", "categories"):
        d[k] = dict(st[k])
    return json.dumps(d, default=str)


def _stats_load(s: Optional[str]) -> dict:
    st = new_stats()
    if s:
        try:
            d = json.loads(s)
            for k, v in d.items():
                if k in ("basis", "flags", "categories"):
                    st[k] = collections.Counter(v)
                else:
                    st[k] = v
        except ValueError:
            pass
    return st


def _passes(cfg: dict) -> list[dict]:
    if cfg.get("kind") == "html":
        return [{"name": "__html__", "mode": "html"}]
    return [t for t in cfg.get("tables", []) if t.get("mode") in ("table", "text")]


def ingest_source(case, con, src: dict, prog=None, log=None, on_fraction: Optional[Callable] = None) -> dict:
    cfg = json.loads(src["config"]) if isinstance(src["config"], str) else (src["config"] or {})
    params = case.params
    ctx = Ctx(src, cfg, params)
    rev = src.get("config_rev") or 0
    ck = json.loads(src["checkpoint"]) if src.get("checkpoint") else None
    if ck and (ck.get("rev") != rev or src.get("ingested_rev") == rev):
        ck = None
    if ck is None:
        _delete_source_rows(con, src["id"])
        stats = new_stats()
        ck = {"rev": rev, "ti": 0, "seq": 0, "reader": None, "pass_seq0": 0}
    else:
        stats = _stats_load(src.get("stats"))
        keep = ck["seq"] if ck.get("reader") is not None else ck.get("pass_seq0", 0)
        _delete_source_rows(con, src["id"], after_seq=keep)
        ck["seq"] = keep
        if log:
            log.info("%s: resuming at record %s", src["label"], keep)
    con.execute("UPDATE sources SET status='ingesting', error=NULL WHERE id=?", (src["id"],))
    con.commit()
    next_id = (dbm.one(con, "SELECT MAX(id) FROM events") or 0) + 1
    seq = ck["seq"]
    size = src.get("size") or 1
    passes = _passes(cfg)
    ev_batch, id_batch = [], []
    last_flush = time.time()
    last_ck = dict(ck)
    path = Path(src["path"])

    def flush():
        nonlocal ev_batch, id_batch, last_flush
        if ev_batch:
            con.executemany(INSERT_EVENT, ev_batch)
        if id_batch:
            con.executemany(INSERT_ID, id_batch)
        con.execute("UPDATE sources SET checkpoint=?, rows=?, stats=? WHERE id=?",
                    (json.dumps(last_ck), last_ck["seq"], _stats_json(stats), src["id"]))
        con.commit()
        ev_batch, id_batch = [], []
        last_flush = time.time()
        if prog:
            prog.check_cancel()

    for ti in range(ck["ti"], len(passes)):
        t = passes[ti]
        resume = ck["reader"] if (ti == ck["ti"] and ck.get("reader")) else None
        if ti != ck["ti"] or ck.get("reader") is None:
            pass_seq0 = seq
        else:
            pass_seq0 = ck.get("pass_seq0", 0)
        last_ck = {"rev": rev, "ti": ti, "seq": seq, "reader": resume, "pass_seq0": pass_seq0}
        kw = {"empty_pages": stats["empty_pages"]} if cfg.get("kind") == "pdf" else {}
        table = t if t.get("mode") != "html" else {}
        n_est = sum((x.get("rows_estimate") or 0) for x in cfg.get("tables", [])) or None
        pages = (json.loads(src["scan"]).get("pages") if src.get("scan") else None) if cfg.get("kind") == "pdf" else None
        for rec, rck in readers.iterate(path, cfg, table, resume, **kw):
            if rec is not None:
                if rec.extra and rec.extra.get("skip"):
                    stats["skipped_lines"] += 1
                else:
                    if rec.note.startswith("line does not match"):
                        stats["nontable"] += 1
                    ev, ids = record_to_event(rec, ctx, stats)
                    seq += 1
                    stats["rows"] += 1
                    eid = next_id
                    next_id += 1
                    ev_batch.append((eid, src["id"], seq, ev["tbl"], ev["loc"], ev["line"], ev["byte_offset"],
                                     ev["byte_len"], ev["ts_utc"], ev["ts_epoch"], ev["ts_raw"], ev["tz_basis"],
                                     ev["ts_flag"], ev["ip"], ev["ip_ver"], ev["ip_class"], ev["port"], ev["subnet"],
                                     ev["ip_raw"], ev["account"], ev["account_basis"], ev["action"], ev["category"],
                                     ev["status"], ev["user_agent"], ev["device"], ev["location"], ev["counterparty"],
                                     ev["direction"], ev["amount"], ev["currency"], ev["raw"], ev["extra"]))
                    for kind, value, norm, validity in ids:
                        id_batch.append((eid, src["id"], kind, value[:300], norm[:300], validity))
            if rck is not None:
                last_ck = {"rev": rev, "ti": ti, "seq": seq, "reader": rck, "pass_seq0": pass_seq0}
            if len(ev_batch) >= 5000 or time.time() - last_flush > 3:
                flush()
                if on_fraction:
                    on_fraction(_fraction(cfg, rck or last_ck.get("reader") or {}, size, n_est, pages, stats["rows"], ti, len(passes)))
        last_ck = {"rev": rev, "ti": ti + 1, "seq": seq, "reader": None, "pass_seq0": seq}
        flush()
    stats["empty_pages"] = sorted(set(stats["empty_pages"]))
    con.execute("UPDATE sources SET status='ingested', ingested_rev=?, ingested_at=?, rows=?, stats=?, checkpoint=NULL WHERE id=?",
                (rev, utc_now_str(), seq, _stats_json(stats), src["id"]))
    con.commit()
    case.audit(con, "source_ingested", {"source": src["label"], "rows": seq, "config_rev": rev,
                                        "ts_parsed": stats["ts_parsed"], "ts_failed": stats["ts_failed"]})
    return stats


def _fraction(cfg, rck, size, n_est, pages, rows, ti, npass) -> float:
    base = ti / max(1, npass)
    span = 1 / max(1, npass)
    if rck.get("offset"):
        return min(1.0, rck["offset"] / max(1, size))
    if pages and rck.get("page"):
        return min(1.0, rck["page"] / pages)
    if n_est:
        return min(1.0, rows / n_est)
    return base + span * 0.5


def _delete_source_rows(con, source_id: int, after_seq: int = 0) -> None:
    con.execute("DELETE FROM identifiers WHERE event_id IN (SELECT id FROM events WHERE source_id=? AND seq>?)",
                (source_id, after_seq))
    con.execute("DELETE FROM events WHERE source_id=? AND seq>?", (source_id, after_seq))
    con.commit()


def sources_to_ingest(con) -> list[dict]:
    rows = dbm.rows(con, "SELECT * FROM sources WHERE status IN ('scanned','ingesting','ingested') ORDER BY id")
    out = []
    for r in rows:
        cfg = json.loads(r["config"]) if r.get("config") else {}
        if cfg.get("skip"):
            if r["status"] != "skipped":
                _delete_source_rows(con, r["id"])
                con.execute("UPDATE sources SET status='skipped', rows=0 WHERE id=?", (r["id"],))
                con.commit()
            continue
        if r["status"] == "ingested" and r.get("ingested_rev") == r.get("config_rev"):
            continue
        out.append(r)
    return out


def preview(case, src: dict, cfg: dict, limit: int = 25) -> list[dict]:
    """Parse the first records with a (possibly edited) config - used by the mapping screen."""
    ctx = Ctx(src, cfg, case.params)
    stats = new_stats()
    out = []
    for t in _passes(cfg):
        table = t if t.get("mode") != "html" else {}
        try:
            for rec, _ in readers.iterate(Path(src["path"]), cfg, table, None):
                if rec is None or (rec.extra and rec.extra.get("skip")):
                    continue
                ev, ids = record_to_event(rec, ctx, stats)
                out.append({"cite": f"{src['label']}:{ev['loc']}", "table": ev["tbl"], "ts_raw": ev["ts_raw"],
                            "ts_utc": ev["ts_utc"], "tz_basis": ev["tz_basis"], "ts_flag": ev["ts_flag"],
                            "ip": ev["ip"], "ip_class": ev["ip_class"], "port": ev["port"], "account": ev["account"],
                            "category": ev["category"], "action": ev["action"], "status": ev["status"],
                            "identifiers": [f"{k}:{n}" for k, _r, n, _v in ids][:6], "raw": ev["raw"][:300]})
                if len(out) >= limit:
                    return out
        except Exception as e:  # noqa: BLE001
            out.append({"error": f"{type(e).__name__}: {e}"})
            return out
    return out
