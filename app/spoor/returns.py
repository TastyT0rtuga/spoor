"""Returns: a return is one provider's response (a folder, a ZIP or a single file you added). Every source file
belongs to exactly one return, shown as R01, R02, ... everywhere an identifier is listed.

A return can be EXCLUDED (left out of the next analysis, reversible) or REMOVED (also hidden from the list; the
files are never touched). Neither changes labels: S03 stays S03 and R02 stays R02, so citations in earlier
reports keep their meaning. The change takes effect on the next run, which reads only the active returns;
excluded files are not re-read, and including a return again simply reads it on the next run."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

from . import db as dbm
from .util import utc_now_str

ACTIVE_SQL = "(return_id IS NULL OR return_id IN (SELECT id FROM returns WHERE state='active'))"
STATES = ("active", "excluded", "removed")


def label_for(n: int) -> str:
    return f"R{n:02d}"


def next_label(con) -> str:
    n = dbm.one(con, "SELECT COUNT(*) FROM returns") or 0
    while dbm.one(con, "SELECT 1 FROM returns WHERE label=?", (label_for(n + 1),)):
        n += 1
    return label_for(n + 1)


def new_return(con, name: str, root: str = "", note: str = "") -> int:
    cur = con.execute("INSERT INTO returns(label, name, root, state, note, added_at, state_at) VALUES (?,?,?,?,?,?,?)",
                      (next_label(con), name, root, "active", note, utc_now_str(), utc_now_str()))
    return cur.lastrowid


def nice_name(path: str | Path) -> str:
    p = Path(path)
    n = p.stem if p.suffix.lower() == ".zip" else p.name
    return n or str(path)


def backfill(con) -> None:
    """Cases made before returns existed: every top-level file becomes its own return; ZIP members join their ZIP's."""
    if not dbm.one(con, "SELECT 1 FROM sources WHERE return_id IS NULL LIMIT 1"):
        return
    for s in dbm.rows(con, "SELECT id, path FROM sources WHERE return_id IS NULL AND parent_id IS NULL ORDER BY id"):
        rid = new_return(con, nice_name(s["path"]), s["path"])
        con.execute("UPDATE sources SET return_id=? WHERE id=?", (rid, s["id"]))
    for s in dbm.rows(con, "SELECT id, parent_id FROM sources WHERE return_id IS NULL AND parent_id IS NOT NULL ORDER BY id"):
        rid = dbm.one(con, "SELECT return_id FROM sources WHERE id=?", (s["parent_id"],))
        if rid:
            con.execute("UPDATE sources SET return_id=? WHERE id=?", (rid, s["id"]))
    con.commit()


# ---------------------------------------------------------------- grouping files into returns when they are added

def plan_groups(root: Path, files: list[Path]) -> list[tuple[str, str, list[Path]]]:
    """[(name, root path, files)]. A file or a ZIP is one return. A folder that holds sub-folders or ZIPs is read as
    a folder of returns: each sub-folder (and each ZIP) is one return, and loose files at its top level together
    form one return named after the folder. A folder with only files is one return."""
    root = Path(root)
    if root.is_file():
        return [(nice_name(root), str(root), [root])]
    kids: dict[str, list[Path]] = {}
    loose: list[Path] = []
    for f in files:
        try:
            rel = f.relative_to(root)
        except ValueError:
            loose.append(f)
            continue
        if len(rel.parts) > 1:
            kids.setdefault(rel.parts[0], []).append(f)
        else:
            loose.append(f)
    zips = [f for f in loose if f.suffix.lower() == ".zip"]
    if not kids and not zips:
        return [(nice_name(root), str(root), files)] if files else []
    out = []
    for name in sorted(kids):
        out.append((name, str(root / name), kids[name]))
    for z in zips:
        out.append((nice_name(z), str(z), [z]))
    rest = [f for f in loose if f not in zips]
    if rest:
        out.append((nice_name(root), str(root), rest))
    return out


def return_for_root(con, name: str, root: str) -> int:
    """Reuse the return created earlier for the same folder or file (files added to it later join it)."""
    rid = dbm.one(con, "SELECT id FROM returns WHERE root=? AND state != 'removed' ORDER BY id LIMIT 1", (root,))
    return rid or new_return(con, name, root)


# ---------------------------------------------------------------- listing

def return_rows(con, include_removed: bool = True) -> list[dict]:
    """Every return with its files, records and time span (read-only; used by the dashboard, reports and tests)."""
    out = []
    for r in dbm.rows(con, "SELECT * FROM returns ORDER BY id"):
        if r["state"] == "removed" and not include_removed:
            continue
        srcs = dbm.rows(con, "SELECT id, label, display, path, kind, status, rows, member FROM sources WHERE return_id=? ORDER BY id", (r["id"],))
        files = [s for s in srcs if s["status"] != "container"]
        span = con.execute("SELECT MIN(e.ts_utc), MAX(e.ts_utc) FROM events e JOIN sources s ON s.id=e.source_id WHERE s.return_id=? "
                           "AND e.ts_epoch IS NOT NULL AND (e.ts_flag IS NULL OR e.ts_flag NOT LIKE '%implausible_year%')", (r["id"],)).fetchone()
        r["files"] = files
        r["labels"] = [s["label"] for s in files]
        r["records"] = sum(s["rows"] or 0 for s in files)
        r["analysed"] = sum(1 for s in files if s["status"] == "ingested")
        r["first_utc"], r["last_utc"] = (span[0], span[1]) if span else (None, None)
        out.append(r)
    return out


def active_returns(con) -> list[dict]:
    return dbm.rows(con, "SELECT * FROM returns WHERE state='active' ORDER BY id")


def return_map(con) -> dict:
    """source id -> (return label, return name)."""
    return {r[0]: (r[1], r[2]) for r in con.execute(
        "SELECT s.id, r.label, r.name FROM sources s JOIN returns r ON r.id=s.return_id")}


def multi(con) -> bool:
    """True when two or more active returns have records (cross-return features apply)."""
    n = dbm.one(con, "SELECT COUNT(DISTINCT s.return_id) FROM sources s JOIN returns r ON r.id=s.return_id "
                     "WHERE r.state='active' AND s.status='ingested' AND s.rows > 0") or 0
    return n >= 2


# ---------------------------------------------------------------- changes (the dashboard, the CLI and the tests use these)

def _find(con, ref: str) -> dict:
    ref = str(ref).strip()
    r = dbm.rows(con, "SELECT * FROM returns WHERE label=? OR id=? OR LOWER(name)=LOWER(?)", (ref.upper(), ref if ref.isdigit() else -1, ref))
    if not r:
        raise ValueError(f"No return '{ref}'. Returns are named R01, R02, ...")
    return r[0]


def mark_dirty(con, case, detail: dict) -> None:
    dbm.set_meta(con, "returns_changed", {"at": utc_now_str(), **detail})
    con.commit()


def set_state(con, case, ref: str, state: str, reason: str = "") -> dict:
    if state not in STATES:
        raise ValueError(f"unknown state {state}")
    r = _find(con, ref)
    if r["state"] == state:
        return r
    con.execute("UPDATE returns SET state=?, state_at=?, note=CASE WHEN ?!='' THEN ? ELSE note END WHERE id=?",
                (state, utc_now_str(), reason, reason, r["id"]))
    con.commit()
    case.audit(con, "return_" + {"active": "included", "excluded": "excluded", "removed": "removed"}[state],
               {"return": r["label"], "name": r["name"], "from": r["state"], "reason": reason})
    mark_dirty(con, case, {"return": r["label"], "state": state})
    return dbm.rows(con, "SELECT * FROM returns WHERE id=?", (r["id"],))[0]


def rename(con, case, ref: str, name: str, note: Optional[str] = None) -> None:
    r = _find(con, ref)
    name = (name or "").strip()
    if not name:
        raise ValueError("A return needs a name.")
    con.execute("UPDATE returns SET name=?, note=COALESCE(?, note) WHERE id=?", (name, note, r["id"]))
    con.commit()
    case.audit(con, "return_renamed", {"return": r["label"], "from": r["name"], "to": name})
    mark_dirty(con, case, {"return": r["label"], "renamed": True})


def move_source(con, case, source_label: str, ref: Optional[str], new_name: str = "") -> dict:
    """Put a file into another return (ref), or into a new return (ref empty; new_name optional)."""
    s = dbm.rows(con, "SELECT * FROM sources WHERE label=?", (source_label,))
    if not s:
        raise ValueError(f"No source '{source_label}'.")
    s = s[0]
    if ref:
        r = _find(con, ref)
    else:
        rid = new_return(con, new_name.strip() or nice_name(s["path"]), s["path"])
        r = dbm.rows(con, "SELECT * FROM returns WHERE id=?", (rid,))[0]
    # a ZIP moves with its members
    ids = [s["id"]] + [x[0] for x in con.execute("SELECT id FROM sources WHERE parent_id=?", (s["id"],))]
    old = dbm.one(con, "SELECT label FROM returns WHERE id=?", (s["return_id"],))
    con.executemany("UPDATE sources SET return_id=? WHERE id=?", [(r["id"], i) for i in ids])
    con.commit()
    case.audit(con, "source_moved", {"source": source_label, "from": old, "to": r["label"]})
    mark_dirty(con, case, {"source": source_label, "to": r["label"]})
    return r


# ---------------------------------------------------------------- the pipeline step: make the sources match the return states

def apply_states(case, con, log=None) -> dict:
    """Run at the start of every analysis. Files of excluded or removed returns are dropped from the database (their rows
    are derived data; the files are untouched) and marked 'excluded'; files of returns that are active again are queued
    to be read. Returns counts."""
    from .ingest import _delete_source_rows
    res = {"excluded": 0, "restored": 0}
    for s in dbm.rows(con, "SELECT s.*, r.state AS rstate, r.label AS rlabel FROM sources s JOIN returns r ON r.id=s.return_id ORDER BY s.id"):
        cfg = json.loads(s["config"]) if s.get("config") else {}
        if s["rstate"] != "active":
            if s["status"] in ("container", "excluded"):
                continue
            _delete_source_rows(con, s["id"])
            cfg["excluded_from"] = s["status"]
            con.execute("UPDATE sources SET status='excluded', rows=0, checkpoint=NULL, config=? WHERE id=?",
                        (json.dumps(cfg, default=str), s["id"]))
            res["excluded"] += 1
        elif s["status"] == "excluded":
            was = cfg.pop("excluded_from", None)
            new = "scanned" if s.get("scan") else ("new" if was in (None, "ingested", "ingesting", "scanned") else was)
            if was in ("unsupported", "error", "duplicate"):
                new = was
            con.execute("UPDATE sources SET status=?, config=?, config_rev=config_rev+1, error=CASE WHEN ?='duplicate' THEN error ELSE NULL END WHERE id=?",
                        (new, json.dumps(cfg, default=str), new, s["id"]))
            res["restored"] += 1
    res.update(_duplicates(con))
    con.commit()
    if any(res.values()):
        case.audit(con, "returns_applied", res)
        if log:
            log.info("returns: %d file(s) left out, %d put back", res["excluded"], res["restored"])
    dbm.set_meta(con, "returns_changed", None)
    con.commit()
    return res


def _duplicates(con) -> dict:
    """Among the files of ACTIVE returns, byte-identical files are read once (the lowest label). A file that was a duplicate of
    one that is now excluded is read again; a file that has become a second copy is dropped from the analysis."""
    from .ingest import _delete_source_rows
    out = {"duplicates_new": 0, "duplicates_cleared": 0}
    groups: dict = {}
    for s in dbm.rows(con, "SELECT s.id, s.status, s.sha256, s.scan, s.label FROM sources s JOIN returns r ON r.id=s.return_id "
                           "WHERE r.state='active' AND s.sha256 IS NOT NULL AND s.kind!='zip' AND s.status IN "
                           "('new','scanned','ingesting','ingested','duplicate') ORDER BY s.id"):
        groups.setdefault(s["sha256"], []).append(s)
    for sha, g in groups.items():
        if len(g) < 2 and g[0]["status"] != "duplicate":
            continue
        first, rest = g[0], g[1:]
        if first["status"] == "duplicate":
            con.execute("UPDATE sources SET status=?, error=NULL, config_rev=config_rev+1 WHERE id=?",
                        ("scanned" if first.get("scan") else "new", first["id"]))
            out["duplicates_cleared"] += 1
        for d in rest:
            if d["status"] != "duplicate":
                _delete_source_rows(con, d["id"])
                con.execute("UPDATE sources SET status='duplicate', rows=0, checkpoint=NULL, error=? WHERE id=?",
                            (f"identical to {first['label']} (same SHA-256); not ingested twice", d["id"]))
                out["duplicates_new"] += 1
    return out


def snapshot(con) -> list[dict]:
    """Compact record of the returns for METHODS.md and the report: label, name, state, files."""
    return [{"label": r["label"], "name": r["name"], "state": r["state"], "state_at": r["state_at"], "files": r["labels"],
             "records": r["records"], "first_utc": r["first_utc"], "last_utc": r["last_utc"], "root": r["root"], "note": r["note"]}
            for r in return_rows(con)]
