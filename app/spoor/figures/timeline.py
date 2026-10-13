"""Figure 1 - activity timeline.

One lane per account (activity records = the TIMELINE data: logins, failures, logouts, account
changes, registrations, transactions, messages), counted per UTC bin and drawn as banded bars. Each
lane cites the account's "activity over time" finding. The UTC axis is on top; the case's local zone
is a second scale underneath. Long silences are cut out of the axis and labelled with their length.
Priority-1 findings whose cited records fall within 24 hours are marked at that moment with numbered
markers (accent colour); a key on the figure and the sources table in FIGURES.md list them."""
from __future__ import annotations

import datetime as dt
import math
from typing import Optional

from .. import db as dbm
from ..analyses.activity import ACTIVITY
from .common import UTC, Ctx, Figure, Ref, fmt_n
from .svg import ACCENT, BAR, INK, MUTED, PAPER, RULE, SOFT, Svg, c4, f4, fit, g4, text_width, wrap

W = 800
MARGIN = 24
LABEL_W = 184
PLOT_X0 = MARGIN + LABEL_W + 16
PLOT_X1 = W - MARGIN
PLOT_W = PLOT_X1 - PLOT_X0
LANE_H = 56
BREAK_W = 56
MAX_SEGMENTS = 4
MOMENT_SECONDS = 86400
NO_ACCOUNT = "(no account)"
DAY = 86400


# ---------------------------------------------------------------- time bins

class Unit:
    def __init__(self, name: str, kind: str, sec: int = 0):
        self.name, self.kind, self.sec = name, kind, sec

    @property
    def subday(self) -> bool:
        return self.kind == "fixed" and self.sec < DAY

    def index(self, t: float) -> int:
        if self.kind == "fixed":
            return int(t // self.sec)
        if self.kind == "week":
            return int((t // DAY - 4) // 7)          # 1970-01-05 was a Monday
        d = dt.datetime.fromtimestamp(t, UTC)
        if self.kind == "month":
            return d.year * 12 + d.month - 1
        if self.kind == "quarter":
            return d.year * 4 + (d.month - 1) // 3
        return d.year

    def start(self, i: int) -> int:
        if self.kind == "fixed":
            return i * self.sec
        if self.kind == "week":
            return (i * 7 + 4) * DAY
        if self.kind == "month":
            y, m = divmod(i, 12)
            return int(dt.datetime(y, m + 1, 1, tzinfo=UTC).timestamp())
        if self.kind == "quarter":
            y, q = divmod(i, 4)
            return int(dt.datetime(y, 3 * q + 1, 1, tzinfo=UTC).timestamp())
        return int(dt.datetime(i, 1, 1, tzinfo=UTC).timestamp())

    def key(self, i: int) -> str:
        """The bin's label exactly as the figure's data SQL returns it."""
        t = dt.datetime.fromtimestamp(self.start(i), UTC)
        if self.kind == "fixed":
            return t.strftime("%Y-%m-%d") if self.sec == DAY else t.strftime("%Y-%m-%d %H:%M:%S")
        if self.kind == "week":
            return t.strftime("%Y-%m-%d")
        if self.kind == "month":
            return t.strftime("%Y-%m")
        if self.kind == "quarter":
            return f"{t.year}-Q{(t.month - 1) // 3 + 1}"
        return str(t.year)

    def sql(self) -> str:
        if self.kind == "fixed" and self.sec == DAY:
            return "substr(ts_utc, 1, 10)"
        if self.kind == "fixed":
            return f"datetime((CAST(ts_epoch AS INTEGER) / {self.sec}) * {self.sec}, 'unixepoch')"
        if self.kind == "week":
            return "date(substr(ts_utc, 1, 10), '-6 days', 'weekday 1')"
        if self.kind == "month":
            return "substr(ts_utc, 1, 7)"
        if self.kind == "quarter":
            return "substr(ts_utc, 1, 4) || '-Q' || ((CAST(substr(ts_utc, 6, 2) AS INTEGER) + 2) / 3)"
        return "substr(ts_utc, 1, 4)"

    def per(self) -> str:
        return {"5min": "5 minutes", "15min": "15 minutes", "1min": "minute"}.get(self.name, self.name)


UNITS = [Unit("minute", "fixed", 60), Unit("5 minutes", "fixed", 300), Unit("15 minutes", "fixed", 900),
         Unit("hour", "fixed", 3600), Unit("3 hours", "fixed", 10800), Unit("6 hours", "fixed", 21600),
         Unit("day", "fixed", DAY), Unit("week", "week"), Unit("month", "month"), Unit("quarter", "quarter"),
         Unit("year", "year")]

TICK_STEPS = [("minute", 1), ("minute", 5), ("minute", 15), ("minute", 30), ("hour", 1), ("hour", 3), ("hour", 6),
              ("hour", 12), ("day", 1), ("day", 2), ("week", 1), ("month", 1), ("month", 3), ("month", 6),
              ("year", 1), ("year", 2), ("year", 5), ("year", 10)]


def tick_times(t0: float, t1: float, step: tuple[str, int], tz) -> list[tuple[int, dt.datetime]]:
    """Calendar boundaries of `step` in zone tz within [t0, t1): [(epoch, local datetime)]."""
    kind, n = step
    lo = dt.datetime.fromtimestamp(t0, tz).replace(tzinfo=None)
    out: list = []
    if kind in ("minute", "hour"):
        unit = 60 if kind == "minute" else 3600
        span = n * unit
        cur = lo.replace(second=0, microsecond=0)
        cur = cur.replace(minute=(cur.minute // n) * n) if kind == "minute" else cur.replace(minute=0, hour=(cur.hour // n) * n)
        guard = 0
        while guard < 5000:
            guard += 1
            aware = cur.replace(tzinfo=tz)
            e = aware.timestamp()
            back = dt.datetime.fromtimestamp(e, tz).replace(tzinfo=None)
            if back == cur and t0 <= e < t1:
                out.append((int(e), aware))
            if e >= t1:
                break
            cur = cur + dt.timedelta(seconds=span)
        return out
    if kind in ("day", "week"):
        cur = dt.datetime(lo.year, lo.month, lo.day)
        if kind == "week":
            cur -= dt.timedelta(days=cur.weekday())
        stepd = n if kind == "day" else 7
        guard = 0
        while guard < 5000:
            guard += 1
            e = cur.replace(tzinfo=tz).timestamp()
            if e >= t1:
                break
            if e >= t0:
                out.append((int(e), cur.replace(tzinfo=tz)))
            cur += dt.timedelta(days=stepd)
        return out
    if kind == "month":
        y, m = lo.year, lo.month - (lo.month - 1) % n
        guard = 0
        while guard < 5000:
            guard += 1
            cur = dt.datetime(y, m, 1)
            e = cur.replace(tzinfo=tz).timestamp()
            if e >= t1:
                break
            if e >= t0:
                out.append((int(e), cur.replace(tzinfo=tz)))
            m += n
            while m > 12:
                y, m = y + 1, m - 12
        return out
    y = lo.year - lo.year % n
    while True:
        cur = dt.datetime(y, 1, 1)
        e = cur.replace(tzinfo=tz).timestamp()
        if e >= t1:
            break
        if e >= t0:
            out.append((int(e), cur.replace(tzinfo=tz)))
        y += n
    return out


def tick_label(step: tuple[str, int], d: dt.datetime) -> str:
    kind = step[0]
    if kind in ("minute", "hour"):
        return d.strftime("%m-%d %H:%M")
    if kind in ("day", "week"):
        return d.strftime("%Y-%m-%d")
    if kind == "month":
        return d.strftime("%Y-%m")
    return d.strftime("%Y")


def split_segments(days: list[int]) -> list[list[int]]:
    """Cut the axis at long silences: repeatedly split at the largest gap while it exceeds a quarter of the
    time still drawn (and a week), up to MAX_SEGMENTS pieces."""
    segs = [sorted(set(days))]
    while len(segs) < MAX_SEGMENTS:
        total = sum(s[-1] - s[0] + 1 for s in segs)
        best = None
        for si, s in enumerate(segs):
            for i in range(1, len(s)):
                g = s[i] - s[i - 1] - 1
                if best is None or g > best[0]:
                    best = (g, si, i)
        if best is None or best[0] < 7 or best[0] <= 0.25 * total:
            break
        g, si, i = best
        s = segs[si]
        segs[si:si + 1] = [s[:i], s[i:]]
    return segs


class Seg:
    def __init__(self, days: list[int]):
        self.days = days
        self.day0, self.day1 = days[0], days[-1]
        self.t0 = (self.day0 - dt.date(1970, 1, 1).toordinal()) * DAY
        self.t1 = (self.day1 + 1 - dt.date(1970, 1, 1).toordinal()) * DAY
        self.first_t: Optional[float] = None   # earliest drawn time in the segment
        self.tmin: Optional[float] = None      # earliest / latest timed record
        self.tmax: Optional[float] = None
        self.dmin: Optional[float] = None      # first / last instant of date-only calendar days
        self.dmax: Optional[float] = None
        self.b0 = self.b1 = 0
        self.x0 = self.width = self.inner = 0
        self.px = 4

    def contains(self, t: float) -> bool:
        return self.t0 <= t < self.t1

    def x(self, unit: Unit, t: float) -> int:
        i = min(max(unit.index(t), self.b0), self.b1)
        s, e = unit.start(i), unit.start(i + 1)
        frac = min(max((t - s) / float(e - s), 0.0), 0.999)
        return f4(self.x0 + self.inner + (i - self.b0) * self.px + frac * self.px)

    def bin_x(self, i: int) -> int:
        return self.x0 + self.inner + (i - self.b0) * self.px


def axis_t(ts_utc: str, ts_epoch: float) -> float:
    """Position on the UTC axis: a date-only record sits at the start of its calendar date."""
    if ts_utc and len(ts_utc) == 10:
        return (dt.date.fromisoformat(ts_utc).toordinal() - dt.date(1970, 1, 1).toordinal()) * DAY
    return ts_epoch


def levels_for(maxc: int) -> list[int]:
    out: list[int] = []
    for i in range(6):
        t = int(math.ceil(maxc ** (i / 6.0) - 1e-9)) if i else 1
        if t <= maxc and (not out or t > out[-1]):
            out.append(t)
    return out


# ---------------------------------------------------------------- the figure

def _lane_name(acc) -> str:
    return NO_ACCOUNT if acc is None else str(acc)


# findings that describe something happening (as opposed to an IP or identifier seen over a period)
EVENT_KINDS = ("failed_burst", "multi_account_failures", "change_from_new_ip", "network_switch", "account_cluster",
               "telecom_colocation")
# findings drawn at their closest pair of records (values closest_a/closest_ts_a, closest_b/closest_ts_b)
CLOSEST_PAIR_KINDS = ("account_cluster", "telecom_colocation")


def _moments(ctx: Ctx, lane_accounts: Optional[set]) -> tuple[list[dict], list[str]]:
    """Priority-1 event findings whose cited records fall within 24 hours:
    [{fid, f, anchors: {account: [t0, t1, cite]}}], plus the FIDs of the other priority-1 findings (not marked)."""
    moments, longp = [], []
    for f in ctx.findings:
        if f["priority"] != 1 or f["category"] == "Sources & data quality" or f["kind"] == "account_activity":
            continue
        if f["kind"] not in EVENT_KINDS:
            longp.append(f["fid"])
            continue
        ev = [e for e in ctx.evidence(f["id"]) if e["ts_epoch"] is not None]
        if f["kind"] in CLOSEST_PAIR_KINDS and f["values"].get("closest_a"):
            v = f["values"]
            pick = []
            for acc, ts in ((v["closest_a"], v.get("closest_ts_a")), (v["closest_b"], v.get("closest_ts_b"))):
                m = [e for e in ev if e["account"] == acc and e["ts_utc"] == ts]
                if m:
                    pick.append(m[0])
            ev = pick
        if not ev:
            longp.append(f["fid"])
            continue
        ts = [axis_t(e["ts_utc"], e["ts_epoch"]) for e in ev]
        if max(ts) - min(ts) > MOMENT_SECONDS:
            longp.append(f["fid"])
            continue
        anchors: dict = {}
        for e, t in zip(ev, ts):
            key = e["account"]
            a = anchors.get(key)
            if a is None:
                anchors[key] = [t, t, e["cite"]]
            else:
                if t < a[0]:
                    a[0], a[2] = t, e["cite"]
                a[1] = max(a[1], t)
        moments.append({"fid": f["fid"], "f": f, "anchors": anchors, "t0": min(ts)})
    return moments, longp


def build(ctx: Ctx) -> Figure:
    fig = Figure(1, "timeline", "Activity timeline")
    p = ctx.p
    max_lanes = max(1, int(p.get("figure_timeline_max_accounts", 12)))
    max_markers = max(0, int(p.get("figure_timeline_max_markers", 12)))
    fig.caps = {"figure_timeline_max_accounts": max_lanes, "figure_timeline_max_markers": max_markers}
    con = ctx.con

    lane_f = {}
    for f in ctx.of_kind("account_activity"):
        lane_f[f["values"].get("account")] = f
    stats = {r["account"]: r for r in dbm.rows(con, f"SELECT account, COUNT(*) AS n, MIN(ts_epoch) AS t FROM events WHERE {ACTIVITY} GROUP BY account")}
    if not stats:
        fig.status, fig.reason = "skipped", "no activity records with a usable timestamp"
        return fig
    has_tel = bool(dbm.one(con, "SELECT 1 FROM tel LIMIT 1"))
    moments, longp = _moments(ctx, None)
    moments.sort(key=lambda m: (m["t0"], m["fid"]))
    drawable = sorted((a for a in stats if a in lane_f), key=lambda a: (a is None, -stats[a]["n"], _lane_name(a)))
    no_finding = [a for a in stats if a not in lane_f]
    # markers and lanes are chosen together, in time order: a moment is drawn when a marker slot is left and
    # its accounts already have lanes or there is room to add them; the busiest accounts fill the other lanes
    lanes: list = []
    drawn_m, undrawn_m, capped_m = [], [], []
    for m in moments:
        accs = [a for a in m["anchors"] if a in lane_f]
        if len(drawn_m) >= max_markers:
            capped_m.append(m)
            continue
        new = [a for a in accs if a not in lanes]
        if accs and len(lanes) + len(new) <= max_lanes:
            lanes += new
            drawn_m.append(m)
        elif any(a in lanes for a in accs):
            drawn_m.append(m)
        else:
            undrawn_m.append(m["fid"])
    for a in drawable:
        if len(lanes) >= max_lanes:
            break
        if a not in lanes:
            lanes.append(a)
    if not lanes:
        fig.status, fig.reason = "skipped", "no account has an activity finding to draw (see max findings per kind)"
        return fig
    lanes.sort(key=lambda a: (a is None, stats[a]["t"], _lane_name(a)))
    lane_set = set(lanes)
    other_only = [r["account"] for r in dbm.rows(con, "SELECT account FROM account_summary ORDER BY account") if r["account"] not in stats]
    drawn_m = [dict(m, anchors={a: v for a, v in m["anchors"].items() if a in lane_set}) for m in drawn_m]
    for m in drawn_m:
        m["t0"] = min(v[0] for v in m["anchors"].values())
    drawn_m.sort(key=lambda m: (m["t0"], m["fid"]))
    for i, m in enumerate(drawn_m, 1):
        m["n"] = i

    # occupancy by day (lanes + markers) -> axis segments
    lane_sql = " OR ".join(["account IS NULL" if a is None else "account = ?" for a in lanes])
    lane_args = tuple(a for a in lanes if a is not None)
    day_rows = dbm.rows(con, f"SELECT account, substr(ts_utc, 1, 10) AS d, COUNT(*) AS n, "
                             "MIN(CASE WHEN length(ts_utc) > 10 THEN ts_epoch END) AS tmin, "
                             "MAX(CASE WHEN length(ts_utc) > 10 THEN ts_epoch END) AS tmax, "
                             f"SUM(length(ts_utc) = 10) AS dateonly FROM events WHERE {ACTIVITY} AND ({lane_sql}) "
                             "GROUP BY account, d ORDER BY d", lane_args)
    epoch0 = dt.date(1970, 1, 1).toordinal()
    days = {dt.date.fromisoformat(r["d"]).toordinal() for r in day_rows}
    anchor_ts = [t for m in drawn_m for v in m["anchors"].values() for t in (v[0], v[1])]
    days |= {dt.datetime.fromtimestamp(t, UTC).date().toordinal() for t in anchor_ts}
    segs = [Seg(s_) for s_ in split_segments(sorted(days))]

    def seg_of_day(o: int) -> Seg:
        return next(s_ for s_ in segs if s_.day0 <= o <= s_.day1)
    for r in day_rows:                       # actual extents: timed records, and date-only calendar days
        sg = seg_of_day(dt.date.fromisoformat(r["d"]).toordinal())
        if r["tmin"] is not None:
            sg.tmin = r["tmin"] if sg.tmin is None else min(sg.tmin, r["tmin"])
            sg.tmax = r["tmax"] if sg.tmax is None else max(sg.tmax, r["tmax"])
        if r["dateonly"]:
            d0 = (dt.date.fromisoformat(r["d"]).toordinal() - epoch0) * DAY
            sg.dmin = d0 if sg.dmin is None else min(sg.dmin, d0)
            sg.dmax = d0 + DAY - 1 if sg.dmax is None else max(sg.dmax, d0 + DAY - 1)
    for t in anchor_ts:
        sg = seg_of_day(dt.datetime.fromtimestamp(t, UTC).date().toordinal())
        sg.tmin = t if sg.tmin is None else min(sg.tmin, t)
        sg.tmax = t if sg.tmax is None else max(sg.tmax, t)
    dateonly = sum(r["dateonly"] or 0 for r in day_rows)

    def extent(sg: Seg, u: Unit) -> tuple[float, float]:
        if u.subday:
            return sg.tmin, sg.tmax
        lo = min(x_ for x_ in (sg.tmin, sg.dmin) if x_ is not None)
        hi = max(x_ for x_ in (sg.tmax, sg.dmax) if x_ is not None)
        return lo, hi

    # unit: the finest that fits with bars at least 8 px wide, else the finest that fits at 4 px
    def seg_label_w(sg: Seg) -> int:
        return c4(text_width("0000-00-00", "mono") + 8)

    def need(u: Unit, k_: int) -> int:
        tot = 0
        for sg in segs:
            lo, hi = extent(sg, u)
            tot += max((u.index(hi) - u.index(lo) + 1) * 4 * k_, seg_label_w(sg))
        return tot + BREAK_W * (len(segs) - 1)
    allow_subday = all(sg.tmin is not None for sg in segs)
    unit = None
    for k_try in (2, 1):
        for u in UNITS:
            if u.subday and not allow_subday:
                continue
            if need(u, k_try) <= PLOT_W:
                unit = u
                break
        if unit:
            break
    unit = unit or UNITS[-1]
    for sg in segs:
        lo, hi = extent(sg, unit)
        sg.first_t = lo
        sg.b0, sg.b1 = unit.index(lo), unit.index(hi)
    k = 1
    for kk in range(8, 0, -1):
        if need(unit, kk) <= PLOT_W:
            k = kk
            break
    px = 4 * k
    used = need(unit, k)
    extra = min((PLOT_W - used) // px, 4)       # a little room around the data, never long empty stretches
    if extra > 0:
        if len(segs) == 1:
            segs[0].b0 -= extra // 2
            segs[0].b1 += extra - extra // 2
        else:
            segs[-1].b1 += extra
    for sg in segs:
        sg.px = px
        sg.t0, sg.t1 = unit.start(sg.b0), unit.start(sg.b1 + 1)
        nbw = (sg.b1 - sg.b0 + 1) * px
        sg.width = max(nbw, seg_label_w(sg))
        sg.inner = f4((sg.width - nbw) / 2)
    x = PLOT_X0 + f4((PLOT_W - sum(sg.width for sg in segs) - BREAK_W * (len(segs) - 1)) / 2)   # centred when narrower
    for sg in segs:
        sg.x0 = x
        x += sg.width + BREAK_W

    def seg_of(t: float) -> Optional[Seg]:
        for s in segs:
            if s.contains(t):
                return s
        return None

    # bins per lane
    bins: dict = {a: {} for a in lanes}
    excluded_dateonly = 0
    if unit.subday:
        rows = dbm.rows(con, f"SELECT account, CAST(ts_epoch AS INTEGER) / 60 AS m, COUNT(*) AS n FROM events WHERE {ACTIVITY} "
                             f"AND length(ts_utc) > 10 AND ({lane_sql}) GROUP BY account, m", lane_args)
        for r in rows:
            i = unit.index(r["m"] * 60)
            bins[r["account"]][i] = bins[r["account"]].get(i, 0) + r["n"]
        excluded_dateonly = dateonly
    else:
        for r in day_rows:
            i = unit.index(axis_t(r["d"], 0))
            bins[r["account"]][i] = bins[r["account"]].get(i, 0) + r["n"]
    maxc = max([n for b in bins.values() for n in b.values()] or [1])
    levels = levels_for(maxc)
    heights = [max(4, c4(24 * (j + 1) / len(levels))) for j in range(len(levels))]

    def level_of(n: int) -> int:
        j = 0
        for i, t in enumerate(levels):
            if n >= t:
                j = i
        return j

    def level_text(j: int) -> str:
        lo = levels[j]
        hi = levels[j + 1] - 1 if j + 1 < len(levels) else maxc
        return fmt_n(lo) if lo == hi else f"{fmt_n(lo)}–{fmt_n(hi)}"

    # ------------------------------------------------------------ layout (top to bottom)
    total_records = sum(stats[a]["n"] for a in lanes)
    y_title = 36
    y_sub = 56
    y_utc_lbl = 88
    y_axis = 96
    lanes_y0 = 100
    lanes_y1 = lanes_y0 + LANE_H * len(lanes)
    y_loc_axis = lanes_y1
    y_loc_lbl = lanes_y1 + 20
    y = y_loc_lbl + 8

    # tick labels per row (computed before drawing so collisions are resolved)
    def row_labels(tz) -> list[tuple[int, str, bool]]:
        cands = []   # (priority, x, label, forced)
        for s in segs:
            chosen = None
            for step in TICK_STEPS:
                if step[0] in ("minute", "hour") and not unit.subday:
                    continue
                ticks = tick_times(s.t0, s.t1, step, tz)
                if not ticks:
                    continue
                lw = max(text_width(tick_label(step, d), "mono") for _, d in ticks)
                xs = [s.x(unit, e) for e, _ in ticks]
                gaps = [b - a for a, b in zip(xs, xs[1:])]
                if all(g >= lw + 16 for g in gaps):
                    chosen = (step, ticks, xs)
                    break
            if chosen and len(chosen[1]) >= (1 if s.width > 2 * seg_label_w(s) else 2):
                step, ticks, xs = chosen
                for (e, d), xx in zip(ticks, xs):
                    cands.append((1, xx, tick_label(step, d), False))
            else:
                t = s.first_t if s.first_t is not None else s.t0
                d = dt.datetime.fromtimestamp(t, tz)
                cands.append((0, g4(s.x0 + s.width / 2), d.strftime("%Y-%m-%d"), True))
        cands.sort(key=lambda c: (c[0], c[1]))
        taken: list[tuple[float, float]] = []
        out = []
        for pri, xx, lab, forced in cands:
            w = text_width(lab, "mono")
            lo, hi = xx - w / 2, xx + w / 2
            if lo < PLOT_X0 - 12 or hi > W - 8:
                if not forced:
                    continue
            if any(lo < b + 8 and a < hi + 8 for a, b in taken):
                continue
            taken.append((lo, hi))
            out.append((xx, lab, forced))
        out.sort()
        return out

    utc_labels = row_labels(UTC)
    loc_labels = row_labels(ctx.tz) if ctx.tz is not UTC else []

    # legend, key and notes
    key_rows = len(drawn_m)
    notes: list[str] = []
    if len(drawable) > len(lanes):
        notes.append(f"Showing {len(lanes)} of {len(drawable)} accounts with activity records (accounts with the earliest priority-1 "
                     "markers first, then the busiest); every record is in exports/timeline.csv.")
    if no_finding:
        notes.append(f"{len(no_finding)} account(s) beyond the per-kind finding limit are not drawn (see max findings per kind).")
    if other_only:
        shown = ", ".join(_lane_name(a) for a in other_only[:6]) + (f" and {len(other_only) - 6} more" if len(other_only) > 6 else "")
        notes.append(f"Not drawn: {len(other_only)} account(s) with no activity records, only other record types ({shown}).")
    if capped_m:
        notes.append(f"Showing {len(drawn_m)} of {len(drawn_m) + len(capped_m)} markers (earliest first); not drawn: "
                     + _fid_list([m["fid"] for m in capped_m], 20) + ".")
    if undrawn_m:
        notes.append("Priority-1 moments outside the drawn lanes: " + _fid_list(undrawn_m, 20) + ".")
    if longp:
        notes.append(("Other priority-1 findings concern IPs, identifiers, contacts, devices or longer periods rather than one moment and are not marked: "
                      if has_tel else "Other priority-1 findings concern IPs, identifiers or longer periods rather than one moment and are not marked: ")
                     + _fid_list(longp, 30) + ".")
    if excluded_dateonly:
        notes.append(f"{fmt_n(excluded_dateonly)} date-only record(s) are not drawn at this {unit.per()} resolution.")
    implaus = dbm.one(con, "SELECT COUNT(*) FROM events WHERE category != 'other' AND ts_flag LIKE '%implausible_year%'") or 0
    if implaus:
        notes.append(f"{fmt_n(implaus)} record(s) with implausible years are not drawn.")
    notes.append(f"Bars count activity records per UTC {unit.per()} (logins, failed logins, logouts, account changes, registrations, "
                 "transactions, messages" + (", calls and texts" if has_tel else "") + ") - the TIMELINE data; each lane cites the account's activity finding. "
                 "Hover any element for its finding and values.")
    note_lines = []
    for n_ in notes:
        note_lines += wrap(n_, "mono", W - 2 * MARGIN)
    lh_mono = 16
    y_legend = y + 32
    y_key0 = y_legend + 24
    y_notes0 = y_key0 + ((key_rows + 1) * 24 + 8 if drawn_m else 0) + 8
    H = c4(y_notes0 + len(note_lines) * lh_mono + 16)

    names = {a: _lane_name(a) for a in lanes}
    desc = (f"Activity records per UTC {unit.per()} for {len(lanes)} account lane(s), {fmt_n(total_records)} records, "
            f"with {len(drawn_m)} numbered priority-1 marker(s). Case {ctx.case.name}.")
    s = Svg("fig01", W, H, "Figure 1. Activity timeline", desc)

    # title block
    s.text(MARGIN, y_title, "Activity timeline", "title")
    first = min(sg.first_t if sg.first_t is not None else sg.t0 for sg in segs)
    last_day = dt.date.fromordinal(segs[-1].day1).isoformat()
    sub = (f"{ctx.case.name} · {fmt_n(total_records)} activity records · {len(lanes)} lane(s) · "
           f"{dt.datetime.fromtimestamp(first, UTC).strftime('%Y-%m-%d')} to {last_day} UTC")
    s.text(MARGIN, y_sub, fit(sub, "mono", W - 2 * MARGIN), "mono", fill=MUTED, tip=sub)

    # axis titles and labels
    s.text(MARGIN, y_utc_lbl, "UTC", "mono", fill=MUTED)
    for xx, lab, forced in utc_labels:
        s.text(xx, y_utc_lbl, lab, "mono", fill=INK if not forced else INK, anchor="middle")
    if loc_labels:
        s.text(MARGIN, y_loc_lbl, fit(ctx.tzname, "mono", LABEL_W), "mono", fill=MUTED, tip=f"Local time zone of the case: {ctx.tzname}")
        for xx, lab, forced in loc_labels:
            s.text(xx, y_loc_lbl, lab, "mono", fill=MUTED, anchor="middle")
    for sg in segs:
        s.line(sg.x0, y_axis, sg.x0 + sg.width, y_axis, stroke=INK)
        s.line(sg.x0, y_loc_axis, sg.x0 + sg.width, y_loc_axis, stroke=RULE)
    for xx, lab, forced in utc_labels:
        if not forced:
            s.line(xx, y_axis - 4, xx, y_axis, stroke=INK)
    for xx, lab, forced in loc_labels:
        if not forced:
            s.line(xx, y_loc_axis, xx, y_loc_axis + 4, stroke=MUTED)
    mid = g4((lanes_y0 + lanes_y1) / 2)
    for a, b in zip(segs, segs[1:]):
        bx = a.x0 + a.width
        for yy in (y_axis, y_loc_axis):
            s.path([(bx + 20, yy + 4), (bx + 24, yy - 4)], stroke=MUTED)
            s.path([(bx + 32, yy + 4), (bx + 36, yy - 4)], stroke=MUTED)
        gap = b.day0 - a.day1 - 1
        tip = (f"{fmt_n(gap)} days without drawn records ({dt.date.fromordinal(a.day1 + 1)} to {dt.date.fromordinal(b.day0 - 1)}) "
               "are cut from the axis")
        s.open({"class": "gap"}, tip=tip, box=(bx, lanes_y0, BREAK_W, lanes_y1 - lanes_y0))
        s.text(bx + BREAK_W // 2, mid - 4, fmt_n(gap), "mono", fill=MUTED, anchor="middle")
        s.text(bx + BREAK_W // 2, mid + 12, "days", "mono", fill=MUTED, anchor="middle")
        s.close()

    # lanes
    for li, acc in enumerate(lanes):
        ly = lanes_y0 + li * LANE_H
        f = lane_f[acc]
        nm = names[acc]
        for sg in segs:
            s.rect(sg.x0, ly + 4, sg.width, LANE_H - 8, fill=SOFT)
        s.line(MARGIN, ly + LANE_H, PLOT_X1, ly + LANE_H, stroke=RULE)
        tip = f"{f['fid']}: {f['statement']}"
        s.open({"data-finding": f["fid"], "class": "lane-label"}, tip=tip, box=(MARGIN, ly + 4, LABEL_W, LANE_H - 8))
        s.rect(MARGIN, ly + 4, LABEL_W, LANE_H - 8, fill="none", attrs={"pointer-events": "all"})   # the whole label is clickable
        s.text(MARGIN, ly + 24, fit(nm, "label", LABEL_W), "label", fill=MUTED if acc is None else INK)
        s.text(MARGIN, ly + 44, fit(f"{fmt_n(stats[acc]['n'])} records · {f['fid']}", "mono", LABEL_W), "mono", fill=MUTED)
        s.close()
        base = ly + 48
        for i in sorted(bins[acc]):
            n = bins[acc][i]
            sg = seg_of(unit.start(i))
            if sg is None or not (sg.b0 <= i <= sg.b1):
                continue
            j = level_of(n)
            h = heights[j]
            bw = px - 4 if px >= 8 else px
            s.rect(sg.bin_x(i), base - h, bw, h, fill=BAR,
                   tip=f"{nm} · {unit.per()} {unit.key(i)} (UTC): {fmt_n(n)} activity record{'s' if n != 1 else ''} · {f['fid']}")
        fig.refs.append(Ref(f"lane {li + 1}", f["fid"], f"activity records of {nm} per UTC {unit.per()}"))

    # markers
    for li, acc in enumerate(lanes):
        ly = lanes_y0 + li * LANE_H
        items = []
        for m in drawn_m:
            v = m["anchors"].get(acc)
            if not v:
                continue
            sg = seg_of(v[0])
            if sg is None:
                continue
            x0 = sg.x(unit, v[0])
            sg1 = seg_of(v[1]) or sg
            x1 = sg1.x(unit, v[1])
            items.append((x0, x1, m, v[2]))
        items.sort(key=lambda t: (t[0], t[2]["n"]))
        merged = _group_markers(items)
        for g in merged:
            lab = _group_label(g["ms"])
            w = _pill_w(lab)
            left = _pill_left(g["xs"][0], w)
            for (x0, x1), m in zip(g["spans"], g["ms"]):
                if x1 - x0 >= 4:
                    s.rect(x0, ly + 48, x1 - x0, 4, fill=ACCENT,
                           tip=f"{m['fid']}: cited records from {_utc(m['anchors'][acc][0])} to {_utc(m['anchors'][acc][1])}")
                s.line(x0, ly + 20, x0, ly + 48, stroke=ACCENT,
                       tip=f"{m['fid']}: first cited record at {_utc(m['anchors'][acc][0])}")
            tip = "; ".join(f"{m['n']} = {m['fid']} {m['f']['title']} ({_utc(m['anchors'][acc][0])})" for m in g["ms"])
            s.pill(left, ly + 4, lab, fill=ACCENT, stroke=None, color=PAPER, tip=tip,
                   attrs={"class": "cite marker", "data-cite": g["cites"][0], "data-finding": g["ms"][0]["fid"]})

    # legend
    lx = MARGIN
    s.text(lx, y_legend, f"Records per UTC {unit.per()}:", "mono", fill=MUTED)
    lx += c4(text_width(f"Records per UTC {unit.per()}:", "mono") + 12)
    for j in range(len(levels)):
        h = heights[j]
        s.rect(lx, y_legend + 4 - h, 8, h, fill=BAR)
        t = level_text(j)
        s.text(lx + 12, y_legend, t, "mono", fill=INK)
        lx += c4(12 + text_width(t, "mono") + 12)
    if drawn_m:
        lx = max(lx, c4(W / 2))
        if lx + 32 + text_width("priority-1 finding (key)", "mono") <= W - MARGIN:
            s.pill(lx, y_legend - 12, "n", fill=ACCENT, stroke=None, color=PAPER)
            s.text(lx + 32, y_legend, "priority-1 finding (key)", "mono", fill=INK)

    # key: one row per marker - number, finding, earliest cited record (UTC), title
    tx_key = MARGIN + 80 + c4(text_width("0000-00-00 00:00", "mono") + 12)
    if drawn_m:
        s.text(MARGIN + 40, y_key0 + 12, "FID", "mono", fill=MUTED)
        s.text(MARGIN + 80, y_key0 + 12, "first record, UTC", "mono", fill=MUTED)
        s.text(tx_key, y_key0 + 12, "finding", "mono", fill=MUTED)
    for idx, m in enumerate(drawn_m):
        kx, ky = MARGIN, y_key0 + (idx + 1) * 24
        first_cite = next(iter(m["anchors"].values()))[2]
        s.pill(kx, ky, str(m["n"]), fill=ACCENT, stroke=None, color=PAPER, tip=f"{m['n']} = {m['fid']}: {m['f']['statement']}",
               attrs={"class": "cite marker", "data-cite": first_cite, "data-finding": m["fid"]})
        s.text(kx + 40, ky + 12, m["fid"], "mono", fill=INK)
        when = _utc(m["t0"], short=True)
        s.text(kx + 80, ky + 12, when, "mono", fill=MUTED)
        tx = kx + 80 + c4(text_width("0000-00-00 00:00", "mono") + 12)
        title = _short_title(m["f"])
        s.text(tx, ky + 12, fit(title, "label", W - MARGIN - tx), "label", fill=INK, tip=f"{m['fid']}: {m['f']['statement']}")
        accs = ", ".join(_lane_name(a) for a in m["anchors"])
        fig.refs.append(Ref(str(m["n"]), m["fid"], f"{m['f']['title']} - earliest cited record {_utc(m['t0'])}; lane(s): {accs}",
                            cite=first_cite))

    # notes
    for i, line in enumerate(note_lines):
        s.text(MARGIN, y_notes0 + i * lh_mono, line, "mono", fill=MUTED)

    fig.svg = s.render()
    fig.notes = notes
    fig.caption = (f"Activity records per account per UTC {unit.per()}"
                   + (f", with {ctx.tzname} as a second scale" if loc_labels else "")
                   + (". Long silences are cut from the axis and labelled with their length in days" if len(segs) > 1 else "")
                   + ". Numbered markers are priority-1 findings whose cited records fall within 24 hours; bar height is banded "
                   f"({', '.join(level_text(j) for j in range(len(levels)))} records).")
    who = " OR ".join(["account IS NULL" if a is None else f"account = '{str(a).replace(chr(39), chr(39) * 2)}'" for a in lanes])
    fig.data_sql.append((f"records per lane and UTC {unit.per()} (bar heights)",
                         f"SELECT account, {unit.sql()} AS bin_utc, COUNT(*) AS records FROM events WHERE {ACTIVITY} "
                         + ("AND length(ts_utc) > 10 " if unit.subday else "") + f"AND ({who}) GROUP BY 1, 2 ORDER BY 1, 2"))
    fig.meta = {"unit": unit.name, "levels": levels, "max_count": maxc, "segments": [[dt.date.fromordinal(sg.day0).isoformat(),
                dt.date.fromordinal(sg.day1).isoformat()] for sg in segs], "lanes": [names[a] for a in lanes],
                "bins": {names[a]: {unit.key(i): n for i, n in sorted(bins[a].items())} for a in lanes}}
    return fig


def _utc(t: float, short: bool = False) -> str:
    d = dt.datetime.fromtimestamp(t, UTC)
    if (d.hour, d.minute, d.second) == (0, 0, 0):
        return d.strftime("%Y-%m-%d")
    return d.strftime("%Y-%m-%d %H:%M") if short else d.strftime("%Y-%m-%d %H:%M:%S UTC")


def _short_title(f: dict) -> str:
    """The finding title without a leading 'account: ' (the lane already names the account)."""
    t = f["title"]
    acc = (f.get("values") or {}).get("account")
    if acc and t.startswith(f"{acc}: "):
        t = t[len(acc) + 2:]
    return t[:1].upper() + t[1:]


def _group_label(ms: list[dict]) -> str:
    nums = sorted(m["n"] for m in ms)
    parts, i = [], 0
    while i < len(nums):
        j = i
        while j + 1 < len(nums) and nums[j + 1] == nums[j] + 1:
            j += 1
        parts.append(str(nums[i]) if j - i < 2 else f"{nums[i]}–{nums[j]}")
        if j - i == 1:
            parts.append(str(nums[j]))
        i = j + 1
    return ",".join(parts)


def _pill_w(lab: str) -> int:
    return max(16, int(math.ceil((text_width(lab, "mono") + 8) / 8.0)) * 8)


def _pill_left(x: int, w: int) -> int:
    left = x - w // 2
    left = f4(left)
    return min(max(left, PLOT_X0), PLOT_X1 - w)


def _group_markers(items: list) -> list[dict]:
    """Merge markers whose pills would touch into one pill ("3,4" or "3\u20135"), left to right, until none overlap."""
    groups = [{"xs": [x0], "spans": [(x0, x1)], "ms": [m], "cites": [c]} for x0, x1, m, c in items]
    changed = True
    while changed:
        changed = False
        out: list[dict] = []
        for g in groups:
            if out:
                pv = out[-1]
                pw = _pill_w(_group_label(pv["ms"]))
                gw = _pill_w(_group_label(g["ms"]))
                if _pill_left(g["xs"][0], gw) < _pill_left(pv["xs"][0], pw) + pw + 4:
                    for k in ("xs", "spans", "ms", "cites"):
                        pv[k] = pv[k] + g[k]
                    changed = True
                    continue
            out.append(g)
        groups = out
    return groups


def _fid_list(fids: list, n: int) -> str:
    return ", ".join(fids[:n]) + (f" and {len(fids) - n} more (FINDINGS.md)" if len(fids) > n else "")
