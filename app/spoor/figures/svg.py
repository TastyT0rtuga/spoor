"""Shared SVG toolkit for the report figures.

Deterministic by construction: integer coordinates on a 4 px grid, text measured with the advance
widths of the bundled Atkinson Hyperlegible fonts (embedded in every SVG, so the figure looks the
same in any viewer and on paper), no scripts, no external references, no timestamps.

`check_svg()` re-reads a finished SVG and reports anything that breaks the house rules: off-grid
coordinates, unsafe content, text outside its box or the canvas, overlapping text."""
from __future__ import annotations

import base64
import math
import re
import xml.etree.ElementTree as ET
from functools import lru_cache
from html import escape
from typing import Optional

from ..util import app_root
from .fontmetrics import FALLBACK, INK_BOTTOM, INK_TOP, MONO_400, NEXT_400, NEXT_700

# ---------------------------------------------------------------- house style (light, print-first)
PAPER = "#ffffff"
INK = "#1b2420"       # text, primary strokes            (15.9:1 on white)
MUTED = "#55645d"     # secondary text                   (6.1:1)
RULE = "#c4cec8"      # hairlines, node outlines
SOFT = "#f3f6f4"      # quiet fills (lane bands, node fills)
BAR = "#71837a"       # activity bars                    (4.1:1, distinct from ink in greyscale)
ACCENT = "#b42318"    # priority-1 only                  (6.6:1)

SANS = "'Atkinson Next', 'Segoe UI', 'DejaVu Sans', Arial, sans-serif"
MONO = "'Atkinson Mono', Consolas, 'DejaVu Sans Mono', monospace"

# three type roles: (family, size px, weight)
ROLES = {
    "title": (SANS, 20, 700),
    "label": (SANS, 14, 400),
    "mono": (MONO, 12, 400),
}
ASC = max(INK_TOP, 950) / 1000.0      # ink above the baseline, in em (covers accents and fallback fonts)
DESC = max(-INK_BOTTOM, 260) / 1000.0  # ink below the baseline, in em
SAFETY = 1.03                          # kerning and hinting margin on measured widths

FONT_FILES = [  # (family, weight, file, unicode-range or None)
    ("Atkinson Next", 400, "atkinson-hyperlegible-next-latin-400-normal.woff2", None),
    ("Atkinson Next", 400, "atkinson-hyperlegible-next-latin-ext-400-normal.woff2", "U+0100-024F, U+1E00-1EFF, U+20A0-20CF"),
    ("Atkinson Next", 700, "atkinson-hyperlegible-next-latin-700-normal.woff2", None),
    ("Atkinson Next", 700, "atkinson-hyperlegible-next-latin-ext-700-normal.woff2", "U+0100-024F, U+1E00-1EFF, U+20A0-20CF"),
    ("Atkinson Mono", 400, "atkinson-hyperlegible-mono-latin-400-normal.woff2", None),
    ("Atkinson Mono", 400, "atkinson-hyperlegible-mono-latin-ext-400-normal.woff2", "U+0100-024F"),
]
ELLIPSIS = "…"


class GridError(ValueError):
    pass


def g4(v: float) -> int:
    """Nearest multiple of 4 (halves round up)."""
    return int(math.floor(v / 4.0 + 0.5)) * 4


def f4(v: float) -> int:
    """Multiple of 4 at or below v."""
    return int(math.floor(v / 4.0)) * 4


def c4(v: float) -> int:
    """Multiple of 4 at or above v."""
    return int(math.ceil(v / 4.0)) * 4


# ---------------------------------------------------------------- text measurement

def _adv(cp: int, role: str) -> int:
    if role == "mono":
        w = MONO_400.get(cp)
        if w is not None:
            return w
        return max(632, FALLBACK.get(cp, 0)) if cp < 0x2E80 else (1250 if 0x1F000 <= cp <= 0x1FAFF else 1000)
    table = NEXT_700 if role == "title" else NEXT_400
    w = table.get(cp)
    if w is not None:
        return w
    if cp in FALLBACK:
        return int(FALLBACK[cp] * (1.1 if role == "title" else 1.0))
    if 0x0300 <= cp <= 0x036F or 0x200B <= cp <= 0x200F or cp == 0xFE0F:
        return 0
    return 1250 if 0x1F000 <= cp <= 0x1FAFF else 1000


@lru_cache(maxsize=65536)
def text_width(s: str, role: str) -> float:
    size = ROLES[role][1]
    return sum(_adv(ord(ch), role) for ch in s) * size / 1000.0 * SAFETY + 1.0


def clean(s) -> str:
    """Text as it may appear in a figure: one line, no control characters."""
    s = "" if s is None else str(s)
    s = re.sub(r"[\x00-\x1f\x7f  ]+", " ", s)
    return re.sub(r" {2,}", " ", s).strip()


def fit(s, role: str, max_w: float) -> str:
    """The text itself if it fits in max_w px, else the longest prefix that fits followed by an ellipsis."""
    s = clean(s)
    if text_width(s, role) <= max_w:
        return s
    lo, hi = 0, len(s)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if text_width(s[:mid].rstrip() + ELLIPSIS, role) <= max_w:
            lo = mid
        else:
            hi = mid - 1
    cut = lo
    while 0 < cut < len(s) and 0x0300 <= ord(s[cut]) <= 0x036F:   # never split a letter from its accent
        cut -= 1
    return (s[:cut].rstrip() + ELLIPSIS) if cut > 0 else ELLIPSIS


def wrap(s, role: str, max_w: float, max_lines: int = 6) -> list[str]:
    """Greedy word wrap; the last allowed line is truncated with an ellipsis if text remains."""
    words = clean(s).split(" ")
    lines: list[str] = []
    cur = ""
    i = 0
    while i < len(words):
        w = words[i]
        cand = (cur + " " + w) if cur else w
        if text_width(cand, role) <= max_w:
            cur = cand
            i += 1
            continue
        if not cur:                       # a single word wider than the line
            lines.append(fit(w, role, max_w))
            i += 1
        else:
            lines.append(cur)
            cur = ""
        if len(lines) == max_lines:
            break
    if cur and len(lines) < max_lines:
        lines.append(cur)
    elif i < len(words) and lines:
        rest = " ".join([lines[-1]] + words[i:])
        lines[-1] = fit(rest, role, max_w)
    return lines


def ink_box(x: float, y: float, s: str, role: str, anchor: str = "start") -> tuple[float, float, float, float]:
    """(left, top, right, bottom) of a text drawn at baseline (x, y)."""
    w = text_width(s, role)
    size = ROLES[role][1]
    left = x if anchor == "start" else (x - w / 2 if anchor == "middle" else x - w)
    return left, y - ASC * size, left + w, y + DESC * size


def line_height(role: str) -> int:
    return c4((ASC + DESC) * ROLES[role][1] + 2)


# ---------------------------------------------------------------- builder

def _num(v) -> str:
    if isinstance(v, bool) or not isinstance(v, int):
        raise GridError(f"coordinate {v!r} is not an integer")
    if v % 4:
        raise GridError(f"coordinate {v} is not on the 4 px grid")
    return str(v)


@lru_cache(maxsize=1)
def font_css() -> str:
    folder = app_root() / "app" / "spoor" / "web" / "static" / "fonts"
    out = []
    for fam, wt, fn, rng in FONT_FILES:
        p = folder / fn
        if not p.exists():
            continue
        b64 = base64.b64encode(p.read_bytes()).decode("ascii")
        out.append(f"@font-face{{font-family:'{fam}';font-weight:{wt};font-style:normal;"
                   f"src:url(data:font/woff2;base64,{b64}) format('woff2')" + (f";unicode-range:{rng}" if rng else "") + "}")
    return "\n".join(out)


class Svg:
    """Collects elements; every coordinate must be an int on the 4 px grid (checked as they are added)."""

    def __init__(self, fig_id: str, width: int, height: int, title: str, desc: str):
        self.id = fig_id
        self.w = width
        self.h = height
        self.title = clean(title)
        self.desc = clean(desc)
        self.body: list[str] = []
        self.texts: list[tuple] = []   # (box, container, s) for self-checks while drawing

    # ---- primitives
    def raw(self, s: str) -> None:
        self.body.append(s)

    @staticmethod
    def _attrs(attrs: Optional[dict]) -> str:
        if not attrs:
            return ""
        return "".join(f' {k}="{escape(str(v), quote=True)}"' for k, v in attrs.items() if v is not None)

    @staticmethod
    def _tip(tip: Optional[str]) -> str:
        return f"<title>{escape(clean(tip), quote=False)}</title>" if tip else ""

    def rect(self, x: int, y: int, w: int, h: int, fill: str = "none", stroke: Optional[str] = None, rx: int = 0,
             tip: Optional[str] = None, attrs: Optional[dict] = None, dash: Optional[str] = None) -> None:
        if w <= 0 or h <= 0:
            return
        a = f'<rect x="{_num(x)}" y="{_num(y)}" width="{_num(w)}" height="{_num(h)}"'
        if rx:
            if rx > 10:
                raise GridError("corner radius above 10")
            a += f' rx="{_num(rx)}"'
        a += f' fill="{fill}"'
        if stroke:
            a += f' stroke="{stroke}" stroke-width="1"'
            if dash:
                a += f' stroke-dasharray="{dash}"'
        a += self._attrs(attrs)
        tipx = self._tip(tip)
        self.body.append(a + (f">{tipx}</rect>" if tipx else "/>"))

    def line(self, x1: int, y1: int, x2: int, y2: int, stroke: str = RULE, dash: Optional[str] = None,
             tip: Optional[str] = None, attrs: Optional[dict] = None) -> None:
        a = (f'<line x1="{_num(x1)}" y1="{_num(y1)}" x2="{_num(x2)}" y2="{_num(y2)}" stroke="{stroke}" stroke-width="1"'
             + (f' stroke-dasharray="{dash}"' if dash else "") + self._attrs(attrs))
        tipx = self._tip(tip)
        self.body.append(a + (f">{tipx}</line>" if tipx else "/>"))

    def path(self, pts: list[tuple[int, int]], stroke: str = RULE, fill: str = "none", close: bool = False,
             tip: Optional[str] = None, attrs: Optional[dict] = None) -> None:
        d = "M" + " L".join(f"{_num(x)} {_num(y)}" for x, y in pts) + (" Z" if close else "")
        a = f'<path d="{d}" fill="{fill}"' + (f' stroke="{stroke}" stroke-width="1"' if stroke else "") + self._attrs(attrs)
        tipx = self._tip(tip)
        self.body.append(a + (f">{tipx}</path>" if tipx else "/>"))

    def circle(self, cx: int, cy: int, r: int, fill: str, stroke: Optional[str] = None, tip: Optional[str] = None,
               attrs: Optional[dict] = None) -> None:
        a = (f'<circle cx="{_num(cx)}" cy="{_num(cy)}" r="{_num(r)}" fill="{fill}"'
             + (f' stroke="{stroke}" stroke-width="1"' if stroke else "") + self._attrs(attrs))
        tipx = self._tip(tip)
        self.body.append(a + (f">{tipx}</circle>" if tipx else "/>"))

    def text(self, x: int, y: int, s, role: str = "label", fill: str = INK, anchor: str = "start",
             tip: Optional[str] = None, attrs: Optional[dict] = None, container: Optional[tuple] = None) -> tuple:
        s = clean(s)
        fam, size, wt = ROLES[role]
        box = ink_box(x, y, s, role, anchor)
        self.texts.append((box, container, s))
        a = (f'<text x="{_num(x)}" y="{_num(y)}" font-family="{fam}" font-size="{size}"'
             + (f' font-weight="{wt}"' if wt != 400 else "") + f' fill="{fill}"'
             + (f' text-anchor="{anchor}"' if anchor != "start" else "") + self._attrs(attrs) + ">")
        self.body.append(a + self._tip(tip) + escape(s, quote=False) + "</text>")
        return box

    def open(self, attrs: Optional[dict] = None, tip: Optional[str] = None, box: Optional[tuple] = None) -> None:
        a = dict(attrs or {})
        if box is not None:
            a["data-box"] = " ".join(_num(v) for v in box)
        self.body.append(f"<g{self._attrs(a)}>" + self._tip(tip))

    def close(self) -> None:
        self.body.append("</g>")

    # ---- composites
    def pill(self, x: int, y: int, s: str, role: str = "mono", fill: str = PAPER, stroke: str = RULE,
             color: str = INK, tip: Optional[str] = None, attrs: Optional[dict] = None, min_w: int = 0) -> int:
        """A small rounded label 16 px tall whose top-left corner is (x, y); returns its width."""
        w = max(min_w, int(math.ceil((text_width(s, role) + 8) / 8.0)) * 8)   # multiple of 8, so the centre is on the grid
        a = dict(attrs or {})
        a["class"] = (str(a.get("class") or "") + " node").strip()
        self.open(a, tip)
        self.rect(x, y, w, 16, fill=fill, stroke=stroke, rx=8)
        self.text(x + w // 2, y + 12, s, role, fill=color, anchor="middle")
        self.close()
        return w

    def render(self) -> str:
        head = (f'<svg xmlns="http://www.w3.org/2000/svg" width="{_num(self.w)}" height="{_num(self.h)}" '
                f'viewBox="0 0 {_num(self.w)} {_num(self.h)}" role="img" aria-labelledby="{self.id}-title {self.id}-desc" '
                f'id="{self.id}">')
        parts = [head,
                 f'<title id="{self.id}-title">{escape(self.title, quote=False)}</title>',
                 f'<desc id="{self.id}-desc">{escape(self.desc, quote=False)}</desc>',
                 f"<defs><style>{font_css()}</style></defs>",
                 f'<rect x="0" y="0" width="{_num(self.w)}" height="{_num(self.h)}" fill="{PAPER}"/>']
        return "\n".join(parts + self.body + ["</svg>"]) + "\n"


# ---------------------------------------------------------------- checker

SVGNS = "{http://www.w3.org/2000/svg}"
GRID_ATTRS = ("x", "y", "x1", "y1", "x2", "y2", "cx", "cy", "r", "rx", "ry", "width", "height")
NUM = re.compile(r"-?\d+(?:\.\d+)?")


def _role_of(el) -> Optional[str]:
    fam = el.get("font-family") or ""
    size = el.get("font-size")
    wt = el.get("font-weight") or "400"
    for name, (f, s, w) in ROLES.items():
        if f == fam and str(s) == size and str(w) == wt:
            return name
    return None


def check_svg(svg: str) -> list[str]:
    """Problems with a figure, as readable strings (empty list = passes every rule)."""
    probs: list[str] = []
    low = svg.lower()
    for bad in ("<script", "@import", "javascript:", "<foreignobject", "<iframe", "<image", "href="):
        if bad in low:
            probs.append(f"forbidden content: {bad}")
    if re.search(r"\son[a-z]+\s*=", svg, re.I):
        probs.append("event-handler attribute (on...=)")
    stripped = svg.replace('xmlns="http://www.w3.org/2000/svg"', "")
    if "http:" in stripped.lower() or "https:" in stripped.lower():
        probs.append("external http(s) reference")
    for m in re.finditer(r"url\(([^)]*)\)", svg):
        if not m.group(1).startswith("data:"):
            probs.append(f"non-data url(): {m.group(1)[:40]}")
    try:
        root = ET.fromstring(svg)
    except ET.ParseError as e:
        return probs + [f"not well-formed XML: {e}"]
    if root.tag != SVGNS + "svg":
        probs.append("root element is not <svg>")
    if root.get("role") != "img":
        probs.append('root lacks role="img"')
    fid = root.get("id") or ""
    kids = list(root)
    if len(kids) < 2 or kids[0].tag != SVGNS + "title" or kids[1].tag != SVGNS + "desc":
        probs.append("first children must be <title> and <desc>")
    if (root.get("aria-labelledby") or "").split() != [f"{fid}-title", f"{fid}-desc"]:
        probs.append("aria-labelledby does not name the title and desc")
    ids = [el.get("id") for el in root.iter() if el.get("id")]
    if len(ids) != len(set(ids)):
        probs.append("duplicate id")
    for i in ids:
        if not i.startswith(fid):
            probs.append(f"id {i} not prefixed with {fid}")
    vb = [float(v) for v in (root.get("viewBox") or "0 0 0 0").split()]
    W, H = vb[2], vb[3]
    for v in vb + [float(root.get("width") or 0), float(root.get("height") or 0)]:
        if v % 4:
            probs.append(f"canvas size {v} off the 4 px grid")
    for el in root.iter():
        tag = el.tag.replace(SVGNS, "")
        for a in GRID_ATTRS:
            v = el.get(a)
            if v is None:
                continue
            if not re.fullmatch(r"-?\d+", v) or int(v) % 4:
                probs.append(f"<{tag} {a}={v}> off the 4 px grid")
        if el.get("transform"):
            probs.append(f"<{tag}> uses a transform")
        if tag == "path":
            for n in NUM.findall(el.get("d") or ""):
                if "." in n or int(n) % 4:
                    probs.append(f"<path> coordinate {n} off the 4 px grid")
                    break
        rx = el.get("rx")
        if rx and int(rx) > 10:
            probs.append("corner radius above 10")
        sw = el.get("stroke-width")
        if sw and sw != "1":
            probs.append(f"stroke-width {sw} (hairlines only)")
    # text placement: inside the canvas, inside its box, not overlapping other text
    boxes = []
    parent = {c: p for p in root.iter() for c in p}

    def container_of(el):
        p = parent.get(el)
        while p is not None:
            if p.get("data-box"):
                x, y, w, h = (int(v) for v in p.get("data-box").split())
                return (x, y, x + w, y + h)
            if "node" in (p.get("class") or "").split():
                r = p.find(SVGNS + "rect")
                if r is not None:
                    x, y = int(r.get("x")), int(r.get("y"))
                    return (x, y, x + int(r.get("width")), y + int(r.get("height")))
            p = parent.get(p)
        return None

    for el in root.iter(SVGNS + "text"):
        role = _role_of(el)
        s = "".join(t for t in el.itertext() if t)
        tip = el.find(SVGNS + "title")
        if tip is not None and tip.text:
            s = s.replace(tip.text, "", 1)
        if role is None:
            probs.append(f"text {s[:30]!r} does not use one of the three type roles")
            continue
        b = ink_box(float(el.get("x")), float(el.get("y")), s, role, el.get("text-anchor") or "start")
        if b[0] < 0 or b[1] < 0 or b[2] > W or b[3] > H:
            probs.append(f"text {s[:40]!r} extends outside the canvas")
        c = container_of(el)
        if c and (b[0] < c[0] or b[1] < c[1] or b[2] > c[2] or b[3] > c[3]):
            probs.append(f"text {s[:40]!r} extends outside its box")
        boxes.append((b, s))
    boxes.sort(key=lambda t: t[0][0])
    for i, (b, s) in enumerate(boxes):
        for b2, s2 in boxes[i + 1:]:
            if b2[0] >= b[2]:
                break
            if b2[1] < b[3] and b[1] < b2[3]:
                probs.append(f"text {s[:30]!r} overlaps {s2[:30]!r}")
    return probs


def svg_texts(svg: str) -> list[str]:
    root = ET.fromstring(svg)
    return ["".join(el.itertext()) for el in root.iter(SVGNS + "text")]
