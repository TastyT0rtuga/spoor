"""Small dependency-free SVG charts for the Markdown report (white background, so they read in
light and dark Markdown viewers alike)."""
from __future__ import annotations

import datetime as dt
from html import escape

PALETTE = ["#2563eb", "#d97706", "#059669", "#7c3aed"]
TEXT = "#1f2937"
GRID = "#e5e7eb"
MUTED = "#6b7280"


def _nice_max(v: float) -> float:
    if v <= 0:
        return 1
    import math
    e = 10 ** math.floor(math.log10(v))
    for m in (1, 2, 2.5, 5, 10):
        if v <= m * e:
            return m * e
    return 10 * e


def bar_chart(title: str, labels: list[str], series: list[tuple[str, list[float]]], ylabel: str = "events",
              width: int = 760, height: int = 300, label_every: int = 1, note: str = "") -> str:
    left, right, top, bottom = 56, 16, 44, 54
    pw, ph = width - left - right, height - top - bottom
    n = len(labels)
    k = len(series)
    vmax = _nice_max(max([max(s[1]) if s[1] else 0 for s in series] + [1]))
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" '
           f'role="img" aria-label="{escape(title)}" font-family="Segoe UI, Arial, sans-serif">',
           f'<rect width="{width}" height="{height}" fill="#ffffff"/>',
           f'<text x="{left}" y="22" font-size="15" font-weight="600" fill="{TEXT}">{escape(title)}</text>']
    if note:
        out.append(f'<text x="{left}" y="38" font-size="11" fill="{MUTED}">{escape(note)}</text>')
    for i in range(5):
        v = vmax * i / 4
        y = top + ph - ph * i / 4
        out.append(f'<line x1="{left}" y1="{y:.1f}" x2="{left + pw}" y2="{y:.1f}" stroke="{GRID}" stroke-width="1"/>')
        out.append(f'<text x="{left - 6}" y="{y + 4:.1f}" font-size="11" text-anchor="end" fill="{MUTED}">{int(v):,}</text>')
    out.append(f'<text x="14" y="{top + ph / 2:.1f}" font-size="11" fill="{MUTED}" transform="rotate(-90 14 {top + ph / 2:.1f})" '
               f'text-anchor="middle">{escape(ylabel)}</text>')
    slot = pw / max(1, n)
    bw = max(1.0, slot * 0.8 / k)
    for si, (name, vals) in enumerate(series):
        color = PALETTE[si % len(PALETTE)]
        for i, v in enumerate(vals):
            h = ph * (v / vmax) if vmax else 0
            x = left + i * slot + slot * 0.1 + si * bw
            out.append(f'<rect x="{x:.1f}" y="{top + ph - h:.1f}" width="{bw:.1f}" height="{h:.1f}" fill="{color}">'
                       f'<title>{escape(labels[i])} - {escape(name)}: {int(v):,}</title></rect>')
    for i, lab in enumerate(labels):
        if i % label_every:
            continue
        x = left + i * slot + slot / 2
        out.append(f'<text x="{x:.1f}" y="{top + ph + 16}" font-size="10" text-anchor="middle" fill="{MUTED}">{escape(lab)}</text>')
    if k > 1:
        lx = left
        for si, (name, _v) in enumerate(series):
            color = PALETTE[si % len(PALETTE)]
            out.append(f'<rect x="{lx}" y="{height - 18}" width="10" height="10" fill="{color}"/>')
            out.append(f'<text x="{lx + 14}" y="{height - 9}" font-size="11" fill="{TEXT}">{escape(name)}</text>')
            lx += 24 + 7 * len(name)
    out.append("</svg>")
    return "\n".join(out)


def daily_chart(rows: list[tuple[str, int]]) -> str:
    """rows: [(YYYY-MM-DD, count)] sorted. Bins to weeks or months when the span is long."""
    if not rows:
        return ""
    d0 = dt.date.fromisoformat(rows[0][0])
    d1 = dt.date.fromisoformat(rows[-1][0])
    span = (d1 - d0).days + 1
    counts = dict(rows)
    if span <= 120:
        labels, vals = [], []
        for i in range(span):
            d = d0 + dt.timedelta(days=i)
            labels.append(d.strftime("%m-%d"))
            vals.append(counts.get(d.isoformat(), 0))
        unit = "day"
    elif span <= 3 * 365:
        start = d0 - dt.timedelta(days=d0.weekday())
        labels, vals = [], []
        d = start
        while d <= d1:
            labels.append(d.strftime("%Y-%m-%d"))
            vals.append(sum(counts.get((d + dt.timedelta(days=j)).isoformat(), 0) for j in range(7)))
            d += dt.timedelta(days=7)
        unit = "week (Monday start)"
    else:
        agg: dict = {}
        for k, v in rows:
            agg[k[:7]] = agg.get(k[:7], 0) + v
        labels, vals = [], []
        y, m = d0.year, d0.month
        while (y, m) <= (d1.year, d1.month):
            key = f"{y:04d}-{m:02d}"
            labels.append(key)
            vals.append(agg.get(key, 0))
            m += 1
            if m == 13:
                y, m = y + 1, 1
        unit = "month"
    every = max(1, len(labels) // 12)
    return bar_chart(f"Events per {unit.split(' ')[0]} (UTC)", labels, [("events", vals)], ylabel=f"events per {unit}",
                     label_every=every, note=f"{d0} to {d1}")
