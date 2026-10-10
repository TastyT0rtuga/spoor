"""Cases: a folder holding case.json, case.db, logs, report output and extracted ZIP members."""
from __future__ import annotations

import datetime as dt
import json
import os
from pathlib import Path
from typing import Optional

from . import db as dbm
from .config import load_settings, merged_params
from .readers import detect_kind, walk_files
from .util import slug, utc_now_str


_INITED: set = set()   # databases whose schema was checked in this process


class Case:
    def __init__(self, cdir: Path):
        self.dir = Path(cdir)
        self.slug = self.dir.name
        p = self.dir / "case.json"
        self.info = json.loads(p.read_text(encoding="utf-8")) if p.exists() else {"name": self.slug}

    # paths
    @property
    def db_path(self) -> Path:
        return self.dir / "case.db"

    @property
    def report_dir(self) -> Path:
        return self.dir / "report"

    @property
    def exports_dir(self) -> Path:
        return self.dir / "report" / "exports"

    @property
    def logs_dir(self) -> Path:
        return self.dir / "logs"

    @property
    def extracted_dir(self) -> Path:
        return self.dir / "extracted"

    @property
    def audit_log(self) -> Path:
        return self.dir / "logs" / "audit.log"

    @property
    def name(self) -> str:
        return self.info.get("name") or self.slug

    @property
    def params(self) -> dict:
        return merged_params(self.info.get("params"))

    @property
    def display_tz(self) -> str:
        return self.info.get("display_tz") or load_settings().get("display_tz") or "UTC"

    def save(self) -> None:
        (self.dir / "case.json").write_text(json.dumps(self.info, indent=2), encoding="utf-8")

    def db(self, readonly: bool = False):
        if readonly and self.db_path.exists() and str(self.db_path) in _INITED:
            return dbm.connect(self.db_path, readonly=True)
        con = dbm.connect(self.db_path, readonly=False)
        if str(self.db_path) not in _INITED:
            dbm.init(con)
            _INITED.add(str(self.db_path))
        if readonly:
            con.close()
            return dbm.connect(self.db_path, readonly=True)
        return con

    def audit(self, con, action: str, detail) -> None:
        dbm.audit(con, action, detail, self.audit_log)


def cases_root(settings: Optional[dict] = None) -> Path:
    s = settings or load_settings()
    p = Path(s["cases_dir"])
    p.mkdir(parents=True, exist_ok=True)
    return p


def create_case(name: str, examiner: str = "", description: str = "", display_tz: str = "",
                settings: Optional[dict] = None) -> Case:
    root = cases_root(settings)
    base = slug(name)
    d = root / base
    i = 2
    while d.exists():
        d = root / f"{base}-{i}"
        i += 1
    d.mkdir(parents=True)
    for sub in ("logs", "report", "report/exports", "extracted"):
        (d / sub).mkdir(parents=True, exist_ok=True)
    info = {"name": name.strip() or d.name, "examiner": examiner.strip(), "description": description.strip(),
            "display_tz": display_tz or (settings or load_settings()).get("display_tz", "UTC"),
            "created": utc_now_str(), "params": {}}
    (d / "case.json").write_text(json.dumps(info, indent=2), encoding="utf-8")
    c = Case(d)
    con = c.db()
    c.audit(con, "case_created", info)
    con.close()
    return c


def list_cases(settings: Optional[dict] = None) -> list[dict]:
    out = []
    for d in sorted(cases_root(settings).iterdir()):
        if d.is_dir() and (d / "case.json").exists():
            c = Case(d)
            out.append({"slug": c.slug, "name": c.name, "examiner": c.info.get("examiner", ""),
                        "created": c.info.get("created", ""), "description": c.info.get("description", "")})
    return out


def get_case(slug_: str, settings: Optional[dict] = None) -> Case:
    d = cases_root(settings) / slug_
    if not (d / "case.json").exists():
        raise FileNotFoundError(f"No case named '{slug_}'")
    return Case(d)


# ---------------------------------------------------------------- source registration

def next_label(con) -> str:
    n = dbm.one(con, "SELECT COUNT(*) FROM sources") or 0
    return f"S{n + 1:02d}"


def register_path(case: Case, con, path: str, recursive: bool = True, zip_password: str = "") -> dict:
    """Register files (fast; hashing and scanning happen in the background job)."""
    p = Path(path).expanduser()
    if not p.exists():
        raise FileNotFoundError(f"Path not found: {p}")
    try:
        if case.dir.resolve() in p.resolve().parents or p.resolve() == case.dir.resolve():
            raise ValueError("That path is inside the case folder. Add the original return files instead.")
    except OSError:
        pass
    added, skipped = [], []
    for f in walk_files(p, recursive):
        rp = str(f.resolve())
        if dbm.one(con, "SELECT id FROM sources WHERE path=? AND parent_id IS NULL", (rp,)):
            skipped.append((rp, "already added"))
            continue
        kind = detect_kind(f)
        st = f.stat()
        label = next_label(con)
        status = "new"
        if kind in ("unsupported", "empty", "unreadable"):
            status = "unsupported"
        cfg = {"zip_password": zip_password} if kind == "zip" and zip_password else None
        con.execute(
            "INSERT INTO sources(label, path, display, kind, size, mtime, status, config, added_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (label, rp, rp, kind, st.st_size,
             dt.datetime.fromtimestamp(st.st_mtime, dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
             status, json.dumps(cfg) if cfg else None, utc_now_str()))
        added.append({"label": label, "path": rp, "kind": kind, "size": st.st_size, "status": status})
    con.commit()
    case.audit(con, "sources_added", {"path": str(p), "recursive": recursive,
                                      "added": [(a["label"], a["path"], a["kind"]) for a in added],
                                      "skipped": skipped})
    return {"added": added, "skipped": skipped}


def source_rows(con) -> list[dict]:
    out = []
    for r in dbm.rows(con, "SELECT * FROM sources ORDER BY id"):
        cfg = json.loads(r["config"]) if r.get("config") else {}
        if "zip_password" in cfg:
            cfg["zip_password"] = "(set)" if cfg["zip_password"] else ""
        r["config"] = cfg
        r["scan"] = json.loads(r["scan"]) if r.get("scan") else None
        r["stats"] = json.loads(r["stats"]) if r.get("stats") else {}
        r["checkpoint"] = json.loads(r["checkpoint"]) if r.get("checkpoint") else None
        r["name"] = os.path.basename(r["path"]) if not r.get("member") else r["member"]
        out.append(r)
    return out
