"""Report figures: deterministic SVG drawn from the findings and the case database (no model involved).

The Figures stage runs after the first report is written. Each figure is built independently; one
that fails is logged, recorded (REVIEW.md lists it) and does not stop the run. Same findings in,
byte-identical SVG out. Outputs: report/figures/FIGnn-*.svg, rows in the `figures` and `figure_refs`
tables (FIGURES.md, REPORT.md, METHODS.md, REVIEW.md and CITATION_CHECK.md are written from those)."""
from __future__ import annotations

import hashlib
import json
from .. import db as dbm
from ..util import utc_now_str
from . import contacts, linkchart, timeline
from .common import Ctx, Figure
from .svg import check_svg

# (number, file slug, title, report section it belongs to, module with build(ctx) -> Figure)
FIGURES: list[tuple[int, str, str, str, object]] = [
    (1, "timeline", "Activity timeline", "Timing & activity patterns", timeline),
    (2, "links", "Account-IP link chart", "Links & cross-source", linkchart),
    (3, "contacts", "Target-contact chart", "Calls, texts & cell sites", contacts),
]
SECTION = {no: sec for no, _s, _t, sec, _b in FIGURES}


def figures_dir(case):
    return case.report_dir / "figures"


def invalidate(case, con) -> None:
    """Forget drawn figures (their findings are about to change or figures were switched off)."""
    con.execute("DELETE FROM figures")
    con.execute("DELETE FROM figure_refs")
    dbm.set_meta(con, "figures", None)
    con.commit()
    d = figures_dir(case)
    if d.exists():
        for p in d.glob("FIG*.svg"):
            p.unlink()
    fm = case.report_dir / "FIGURES.md"
    if fm.exists():
        fm.unlink()


def run_figures(case, con, prog=None, log=None) -> dict:
    invalidate(case, con)
    out = figures_dir(case)
    out.mkdir(parents=True, exist_ok=True)
    ctx = Ctx(case, con)
    if prog:
        prog.set_total(len(FIGURES), "figures")
    summary = {"drawn": 0, "skipped": 0, "failed": 0}
    has_tel = bool(dbm.one(con, "SELECT 1 FROM tel LIMIT 1"))
    for i, (no, slug, title, _sec, mod) in enumerate(FIGURES):
        if getattr(mod, "TELECOM_ONLY", False) and not has_tel:
            continue          # telecom figures exist only in cases with telecom returns
        if prog:
            prog.message(f"Drawing figure {no}: {title}")
            prog.check_cancel()
        try:
            fig = mod.build(ctx)
        except Exception as e:  # noqa: BLE001
            if type(e).__name__ == "Cancelled":
                raise
            if log:
                log.exception("figure %s (%s)", no, slug)
            fig = Figure(no, slug, title, status="failed", reason=f"{type(e).__name__}: {e}")
        warnings: list[str] = []
        sha = None
        if fig.svg:
            warnings = check_svg(fig.svg)
            data = fig.svg.encode("utf-8")
            (out / fig.file).write_bytes(data)
            sha = hashlib.sha256(data).hexdigest()
            if warnings and log:
                log.warning("figure %s: %d layout warning(s): %s", no, len(warnings), "; ".join(warnings[:3]))
        summary[{"ok": "drawn", "skipped": "skipped"}.get(fig.status, "failed")] += 1
        con.execute("INSERT OR REPLACE INTO figures(no, slug, title, file, status, reason, caption, sha256, notes, data_sql, caps, meta, "
                    "warnings, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (no, slug, fig.title, fig.file if fig.svg else None, fig.status, fig.reason, fig.caption, sha,
                     json.dumps(fig.notes, ensure_ascii=False), json.dumps(fig.data_sql, ensure_ascii=False),
                     json.dumps(fig.caps), json.dumps(fig.meta, ensure_ascii=False, default=str),
                     json.dumps(warnings, ensure_ascii=False), utc_now_str()))
        for k, r in enumerate(fig.refs):
            con.execute("INSERT INTO figure_refs(figure_no, ord, marker, fid, shows, cite) VALUES (?,?,?,?,?,?)",
                        (no, k, r.marker, r.fid, r.shows, r.cite))
        con.commit()
        if prog:
            prog.update(i + 1)
    dbm.set_meta(con, "figures", dict(summary, at=utc_now_str()))
    con.commit()
    return summary


def figure_rows(con) -> list[dict]:
    rows = dbm.rows(con, "SELECT * FROM figures ORDER BY no")
    for r in rows:
        for k in ("notes", "data_sql", "caps", "meta", "warnings"):
            r[k] = json.loads(r[k]) if r.get(k) else ([] if k in ("notes", "data_sql", "warnings") else {})
        r["refs"] = dbm.rows(con, "SELECT * FROM figure_refs WHERE figure_no=? ORDER BY ord", (r["no"],))
    return rows
