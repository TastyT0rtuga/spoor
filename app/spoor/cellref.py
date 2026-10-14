"""Reference cell-site library: carrier tower lists you keep next to the program, used to place records whose
return came without a tower list.

Put the carriers' cell-site lists (CSV, TXT, XLSX, XLS or ZIPs of them) in the cellsites/ folder - one sub-folder
per carrier is best (e.g. cellsites/Verizon_Feb2025/) - and run `spoor cellsites index`. The index
(cellsites/cell_ref.db) holds, for every LTE cell the lists name, the ECI, carrier, coordinates, azimuth and
beamwidth, plus the file, its SHA-256 and the row it came from. Nothing in this folder is shipped with Spoor or
published: the lists are yours.

How a record is matched (telecom._resolve_locations, after any tower list loaded with the case itself):
  - by ECI only (an LTE cell identity is unique within one carrier, not across carriers);
  - the carrier comes from the case setting tel_carrier, else from the return's file name / folder
    (CDR_Mediations, TWD_, TimingAdvance -> T-Mobile; ReportAU / ReportTOWER -> AT&T; CellSites-CDR, VoLTE ->
    Verizon; CXM_HDA -> UScellular; or a carrier name in the path);
  - with no carrier, a cell is matched only if every library list that names it agrees to within
    tel_same_site_km - otherwise it is left unlocated and the REVIEW says why;
  - lists that are not LTE-aware (old CDMA lists keyed by switch / cell / sector) are indexed by label and used
    only when the carrier is known.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import os
import re
import shutil
import sqlite3
import tempfile
from pathlib import Path
from typing import Callable, Optional

from .util import app_root

DB_NAME = "cell_ref.db"
INDEX_VERSION = "1"
READ_EXT = {".csv", ".txt", ".tsv", ".xlsx", ".xlsm", ".xls", ".zip"}

# carrier names, most specific first; matched against folder and file names (lower case)
CARRIERS = [
    ("MetroPCS", r"metro\s*pcs|metropcs"),
    ("Cellular One of Arizona", r"cellular[\s_+]*one"),
    ("T-Mobile", r"t[\s_-]?mob|tmobile|\btmo\b"),
    ("Sprint", r"sprint"),
    ("AT&T", r"\bat&?t\b|(?:^|[^a-z])att(?:[^a-z]|$)|cingular"),
    ("Verizon", r"verizon|\bvzw\b|calea\.v0"),
    ("UScellular", r"us\s*cellular|uscellular|\buscc\b"),
    ("Appalachian Wireless (EKN)", r"(?:^|[^a-z])ekn(?:[^a-z]|$)|appalachian"),
    ("Carolina West Wireless", r"(?:^|[^a-z])cww(?:[^a-z]|$)|carolina\s*west"),
]
# how each carrier's returns are usually named (CAST workbook naming), for records whose path names no carrier
RETURN_HINTS = [
    ("T-Mobile", r"cdr_mediation|(?:^|[^a-z])twd_|timingadvance|tmo_|t-?mobile"),
    ("AT&T", r"reportau|reporttower|(?:^|[^a-z])att_|at&t"),
    ("Verizon", r"cellsites-cdr|volte|verizon|vzw"),
    ("UScellular", r"cxm_hda|uscc|uscellular"),
    ("Sprint", r"sprint"),
]
# MCC-MNC written in an ECGI on a record -> carrier
PLMN = {"310260": "T-Mobile", "310410": "AT&T", "313100": "AT&T", "310280": "AT&T", "311480": "Verizon",
        "311580": "UScellular", "310120": "Sprint", "310830": "Sprint"}


def library_dir() -> Path:
    env = os.environ.get("SPOOR_CELLSITES")
    return Path(env) if env else app_root() / "cellsites"


def db_path(folder: Optional[Path] = None) -> Path:
    return (folder or library_dir()) / DB_NAME


def carrier_from_path(path: str) -> str:
    s = str(path).replace("\\", "/").lower()
    for name, rx in CARRIERS:
        if re.search(rx, s):
            return name
    return ""


def carrier_hint(path: str) -> tuple[str, str]:
    """(carrier, basis) for a return file, from its own name first, then its folders."""
    p = Path(str(path).replace("\\", "/"))
    for part, what in [(p.name, "file name"), (str(p.parent), "folder")]:
        low = part.lower()
        for name, rx in RETURN_HINTS:
            if re.search(rx, low):
                return name, f"{what} '{part[-80:]}'"
        c = carrier_from_path(low)
        if c:
            return c, f"{what} '{part[-80:]}'"
    return "", ""


def norm_carrier(v: str) -> str:
    if not v:
        return ""
    for name, rx in CARRIERS:
        if name.lower() == v.strip().lower() or re.search(rx, v.lower()):
            return name
    return v.strip()


SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS files (
  id INTEGER PRIMARY KEY, path TEXT UNIQUE, size INTEGER, mtime REAL, sha256 TEXT, carrier TEXT, rows INTEGER,
  cells INTEGER, dup INTEGER, skipped INTEGER, status TEXT, note TEXT, indexed_at TEXT
);
CREATE TABLE IF NOT EXISTS cells (
  key TEXT, carrier TEXT, eci INTEGER, label TEXT, lat REAL, lon REAL, azimuth REAL, beamwidth REAL, site TEXT,
  file_id INTEGER, loc TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_cells ON cells(carrier, key, lat, lon, azimuth);
CREATE INDEX IF NOT EXISTS ix_cells_eci ON cells(eci);
CREATE INDEX IF NOT EXISTS ix_cells_label ON cells(carrier, label);
"""


def _open(folder: Path) -> sqlite3.Connection:
    con = sqlite3.connect(str(db_path(folder)))
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA synchronous=NORMAL")
    con.executescript(SCHEMA)
    r = con.execute("SELECT value FROM meta WHERE key='version'").fetchone()
    if r and r[0] != INDEX_VERSION:
        con.executescript("DELETE FROM cells; DELETE FROM files;")
    con.execute("INSERT OR REPLACE INTO meta VALUES ('version', ?)", (INDEX_VERSION,))
    return con


def _sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 22), b""):
            h.update(b)
    return h.hexdigest()


def _candidates(folder: Path, log) -> list[Path]:
    """Every readable list under the folder. A ZIP is skipped when a folder with the same name sits next to it
    (it has already been extracted there)."""
    out = []
    for p in sorted(folder.rglob("*")):
        if not p.is_file() or p.name == DB_NAME or p.name.startswith(DB_NAME) or p.name.startswith("~$"):
            continue
        if p.suffix.lower() not in READ_EXT or p.name.lower() == "readme.txt":
            continue
        if p.suffix.lower() == ".zip" and (p.with_suffix("")).is_dir():
            log(f"  skip {p.relative_to(folder)} (already extracted next to it)")
            continue
        out.append(p)
    return out


def _read_list(path: Path, display: str, carrier: str, con, file_id: int, log) -> dict:
    """Index one tower list (any table in it that maps as a cell-site list)."""
    from . import readers
    from .ingest import build_config
    from .mapping import is_tower_mapping
    from .telecom import cell_identity, fnum

    st = {"rows": 0, "cells": 0, "dup": 0, "skipped": 0, "tables": [], "note": ""}
    kind = readers.detect_kind(path)
    if kind not in ("text", "xlsx", "xls"):
        st["note"] = f"not a list ({kind})"
        return st
    sc = readers.scan(path, kind)
    cfg = build_config(sc, {"path": str(path)}, {})
    batch = []

    def flush():
        if batch:
            before = con.total_changes
            con.executemany("INSERT OR IGNORE INTO cells VALUES (?,?,?,?,?,?,?,?,?,?,?)", batch)
            added = con.total_changes - before
            st["cells"] += added
            st["dup"] += len(batch) - added
            batch.clear()

    for t in cfg["tables"]:
        m = t.get("mapping") or {}
        if t.get("mode") != "table" or not is_tower_mapping(m):
            continue
        lte_aware = bool(m.get("eci") or m.get("enb"))
        hdr = {k: m[k] for k in ("cell", "eci") if m.get(k)}
        st["tables"].append(str(t.get("name")))
        for rec, _ in readers.iterate(path, cfg, t, None):
            if rec is None or rec.cells is None:
                continue
            st["rows"] += 1
            c = rec.cells
            tel = {f: (str(c.get(h)).strip() if c.get(h) not in (None, "") else None)
                   for f, h in m.items() if f in ("cell", "eci", "enb", "lat", "lon", "azimuth", "beamwidth", "site_name")}
            ident = cell_identity(tel, hdr, True)
            lat, lon = fnum(tel.get("lat"), -90, 90), fnum(tel.get("lon"), -180, 180)
            if lat is None or lon is None or (lat == 0 and lon == 0):
                st["skipped"] += 1
                continue
            if ident["eci"] is not None:
                key, label = f"e:{ident['eci']}", ident["label"]
            elif not lte_aware and ident["label"]:
                key, label = f"l:{ident['label']}", ident["label"]
            else:
                st["skipped"] += 1          # 3G / 5G / blank rows in an LTE list
                continue
            batch.append((key, carrier, ident["eci"], label, round(lat, 6), round(lon, 6),
                          fnum(tel.get("azimuth"), 0, 360), fnum(tel.get("beamwidth"), 1, 360),
                          (tel.get("site_name") or "")[:120] or None, file_id, f"{rec.loc}"[:60]))
            if len(batch) >= 20000:
                flush()
                if st["rows"] % 200000 < 20000:
                    log(f"    {display}: {st['rows']:,} rows")
        flush()
    if not st["tables"]:
        st["note"] = "no table in it reads as a cell-site list"
    return st


def index(folder: Optional[Path] = None, log: Callable = print, force: bool = False) -> dict:
    """Build or update the index. Files already indexed with the same size and time are kept."""
    from . import readers

    folder = Path(folder or library_dir())
    if not folder.exists():
        raise SystemExit(f"no {folder} folder - create it and put the carriers' cell-site lists in it")
    con = _open(folder)
    if force:
        con.executescript("DELETE FROM cells; DELETE FROM files;")
    seen = set()
    totals = {"files": 0, "new": 0, "cells": 0}
    tmp = Path(tempfile.mkdtemp(prefix="spoor_cellref_"))
    try:
        for p in _candidates(folder, log):
            rel = p.relative_to(folder).as_posix()
            stt = p.stat()
            members = [(rel, p)]
            if p.suffix.lower() == ".zip":
                members = []
                dest = tmp / str(len(seen))
                for name, ep in readers.safe_extract_zip(p, dest):
                    if Path(name).suffix.lower() in READ_EXT - {".zip"}:
                        members.append((f"{rel}!{name}", ep))
            for disp, fp in members:
                seen.add(disp)
                totals["files"] += 1
                old = con.execute("SELECT id, size, mtime, status FROM files WHERE path=?", (disp,)).fetchone()
                if old and old[1] == stt.st_size and abs((old[2] or 0) - stt.st_mtime) < 1 and old[3] == "indexed":
                    continue
                if old:
                    con.execute("DELETE FROM cells WHERE file_id=?", (old[0],))
                    con.execute("DELETE FROM files WHERE id=?", (old[0],))
                carrier = carrier_from_path(disp) or "unknown"
                log(f"  index {disp}  [{carrier}]")
                cur = con.execute("INSERT INTO files(path, size, mtime, sha256, carrier, status, indexed_at) "
                                  "VALUES (?,?,?,?,?,?,?)",
                                  (disp, stt.st_size, stt.st_mtime, _sha256(fp), carrier, "reading",
                                   dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")))
                fid = cur.lastrowid
                try:
                    st = _read_list(fp, disp, carrier, con, fid, log)
                    fstatus = "indexed"
                except Exception as e:  # noqa: BLE001 - one bad file must not stop the rest
                    st = {"rows": 0, "cells": 0, "dup": 0, "skipped": 0, "note": f"error: {e}"[:300]}
                    fstatus = "indexed"
                    log(f"    ! {disp}: {e}")
                con.execute("UPDATE files SET rows=?, cells=?, dup=?, skipped=?, status=?, note=? WHERE id=?",
                            (st["rows"], st["cells"], st["dup"], st["skipped"], fstatus, st.get("note") or None, fid))
                con.commit()
                totals["new"] += 1
                totals["cells"] += st["cells"]
                log(f"    {st['rows']:,} rows -> {st['cells']:,} cells new, {st['dup']:,} already indexed, "
                    f"{st['skipped']:,} not LTE / no coordinates" + (f"  ({st['note']})" if st.get("note") else ""))
            if p.suffix.lower() == ".zip":
                shutil.rmtree(tmp, ignore_errors=True)       # extracted members are not kept
                tmp.mkdir(exist_ok=True)
        gone = [r for r in con.execute("SELECT id, path FROM files").fetchall() if r[1] not in seen]
        for fid, path in gone:
            log(f"  removed from the index: {path} (no longer in the folder)")
            con.execute("DELETE FROM cells WHERE file_id=?", (fid,))
            con.execute("DELETE FROM files WHERE id=?", (fid,))
        con.commit()
        con.execute("ANALYZE")
        con.commit()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
        con.close()
    return totals | status(folder)


def status(folder: Optional[Path] = None) -> dict:
    p = db_path(folder)
    if not p.exists():
        return {"indexed": False, "lists": 0, "cells": 0, "carriers": {}}
    con = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
    try:
        carriers = {r[0]: {"lists": r[1], "cells": r[2]} for r in con.execute(
            "SELECT f.carrier, COUNT(DISTINCT f.id), COALESCE(SUM(f.cells), 0) FROM files f GROUP BY f.carrier")}
        return {"indexed": True, "lists": sum(v["lists"] for v in carriers.values()),
                "cells": sum(v["cells"] for v in carriers.values()), "carriers": carriers, "path": str(p)}
    finally:
        con.close()


class Library:
    """Read-only lookups against the index. Absent library -> available is False."""

    def __init__(self, folder: Optional[Path] = None):
        self.path = db_path(folder)
        self.con = None
        if self.path.exists():
            try:
                self.con = sqlite3.connect(f"file:{self.path}?mode=ro", uri=True)
                self.con.execute("SELECT 1 FROM cells LIMIT 1")
            except sqlite3.Error:
                self.con = None
        self.used_files: dict = {}

    @property
    def available(self) -> bool:
        return self.con is not None

    def by_eci(self, eci: int) -> list[dict]:
        return self._q("c.eci = ?", (eci,))

    def by_label(self, carrier: str, label: str) -> list[dict]:
        return self._q("c.carrier = ? AND c.key = ?", (carrier, f"l:{label}"))

    def _q(self, where: str, args: tuple) -> list[dict]:
        if not self.con:
            return []
        rows = self.con.execute(
            "SELECT c.carrier, c.eci, c.label, c.lat, c.lon, c.azimuth, c.beamwidth, c.site, c.loc, f.id, f.path, "
            f"f.sha256 FROM cells c JOIN files f ON f.id = c.file_id WHERE {where} ORDER BY f.path", args).fetchall()
        keys = ("carrier", "eci", "label", "lat", "lon", "azimuth", "beamwidth", "site", "loc", "file_id", "file", "sha256")
        return [dict(zip(keys, r)) for r in rows]

    def note_used(self, c: dict) -> None:
        u = self.used_files.setdefault(c["file"], {"file": c["file"], "sha256": c["sha256"], "carrier": c["carrier"],
                                                   "records": 0})
        u["records"] += 1

    def close(self) -> None:
        if self.con:
            self.con.close()
