"""HTML returns: data tables become rows; everything else becomes text lines (with proximity
pairing, which suits key/value layouts used by several providers). Citations: L<line>[:C<col>]
in the HTML source - open the file in a text editor and go to that line."""
from __future__ import annotations

import re
from collections import deque
from html.parser import HTMLParser
from typing import Iterator, Optional

from ..util import detect_encoding
from .delimited import _is_headerish
from .textmode import Rec, TextModeExtractor

BLOCK = {"p", "div", "br", "tr", "li", "ul", "ol", "table", "h1", "h2", "h3", "h4", "h5", "h6", "section",
         "article", "header", "footer", "pre", "hr", "dt", "dd", "dl", "title", "blockquote", "form",
         "fieldset", "address", "caption", "tbody", "thead", "tfoot", "body", "html", "main", "nav", "aside",
         "figure", "figcaption", "summary", "details", "label", "option"}
SKIP = {"script", "style", "noscript", "template", "svg"}
_WS = re.compile(r"\s+")


class _Collector(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.events: deque = deque()
        self.skip = 0
        self.tables: list[dict] = []
        self.table_no = 0
        self.text: list[str] = []
        self.text_pos = None

    def _loc(self, pos):
        line, col = pos
        return f"L{line}" if col == 0 else f"L{line}:C{col + 1}", line

    def _flush_text(self):
        if self.text:
            t = _WS.sub(" ", "".join(self.text)).strip()
            if t:
                loc, line = self._loc(self.text_pos)
                self.events.append(("text", loc, line, t))
        self.text = []
        self.text_pos = None

    def handle_starttag(self, tag, attrs):
        if tag in SKIP:
            self.skip += 1
            return
        if self.skip:
            return
        if tag == "table":
            self._flush_text()
            if self.tables:
                self.tables[-1]["nested"] = True
                self._end_cell()
            self.table_no += 1
            self.tables.append({"no": self.table_no, "nested": False, "row": None, "cell": None, "row_pos": None,
                                "th": True})
            return
        if self.tables:
            t = self.tables[-1]
            if tag == "tr":
                self._end_row()
                t["row"], t["row_pos"], t["th"] = [], self.getpos(), True
                return
            if tag in ("td", "th"):
                if t["row"] is None:
                    t["row"], t["row_pos"], t["th"] = [], self.getpos(), True
                self._end_cell()
                t["cell"] = []
                if tag == "td":
                    t["th"] = False
                return
            if tag == "br" and t["cell"] is not None:
                t["cell"].append(" ")
                return
        if tag in BLOCK:
            self._flush_text()

    def handle_endtag(self, tag):
        if tag in SKIP:
            self.skip = max(0, self.skip - 1)
            return
        if self.skip:
            return
        if tag == "table" and self.tables:
            self._end_row()
            self.tables.pop()
            return
        if self.tables:
            if tag == "tr":
                self._end_row()
                return
            if tag in ("td", "th"):
                self._end_cell()
                return
        if tag in BLOCK:
            self._flush_text()

    def _end_cell(self):
        t = self.tables[-1] if self.tables else None
        if t and t["cell"] is not None and t["row"] is not None:
            t["row"].append(_WS.sub(" ", "".join(t["cell"])).strip())
        if t:
            t["cell"] = None

    def _end_row(self):
        t = self.tables[-1] if self.tables else None
        if not t or t["row"] is None:
            return
        self._end_cell()
        if any(c for c in t["row"]):
            loc, line = self._loc(t["row_pos"])
            self.events.append(("row", t["no"], loc, line, t["row"], t["th"], t["nested"]))
        t["row"] = None

    def handle_data(self, data):
        if self.skip:
            return
        if self.tables and self.tables[-1]["cell"] is not None:
            self.tables[-1]["cell"].append(data)
            return
        if self.tables and self.tables[-1]["row"] is not None:
            return
        if data.strip():
            if self.text_pos is None:
                self.text_pos = self.getpos()
            self.text.append(data)
        elif self.text:
            self.text.append(" ")

    def close(self):
        super().close()
        while self.tables:
            self._end_row()
            self.tables.pop()
        self._flush_text()


def _encoding(path) -> str:
    with open(path, "rb") as f:
        head = f.read(64 * 1024)
    m = re.search(rb"<meta[^>]+charset=[\"']?([A-Za-z0-9_-]+)", head, re.I)
    if m:
        enc = m.group(1).decode("ascii", "ignore").lower()
        try:
            "x".encode(enc)
            return "utf-8" if enc in ("utf8", "utf-8") else enc
        except LookupError:
            pass
    return detect_encoding(head)


def _events(path, enc) -> Iterator[tuple]:
    p = _Collector()
    with open(path, "r", encoding="utf-8" if enc == "utf-8-sig" else enc, errors="replace", newline="") as f:
        while True:
            chunk = f.read(1 << 20)
            if not chunk:
                break
            p.feed(chunk)
            while p.events:
                yield p.events.popleft()
    p.close()
    while p.events:
        yield p.events.popleft()


def scan(path, name: str) -> dict:
    enc = _encoding(path)
    tables: dict[int, dict] = {}
    texts = []
    n_text = 0
    for ev in _events(path, enc):
        if ev[0] == "text":
            n_text += 1
            if len(texts) < 60:
                texts.append((ev[1], ev[3]))
            continue
        _, no, loc, line, cells, th, nested = ev
        t = tables.setdefault(no, {"rows": 0, "widths": {}, "first": None, "first_loc": None, "nested": nested,
                                   "samples": [], "th_first": th})
        t["rows"] += 1
        t["nested"] = t["nested"] or nested
        t["widths"][len(cells)] = t["widths"].get(len(cells), 0) + 1
        if t["first"] is None:
            t["first"], t["first_loc"], t["th_first"] = cells, loc, th
        elif len(t["samples"]) < 200:
            t["samples"].append(cells)
    out = {"kind": "html", "encoding": enc, "tables": [], "preamble": texts, "notes": []}
    data_tables = 0
    for no, t in sorted(tables.items()):
        ncols = max(t["widths"], key=lambda k: t["widths"][k])
        if t["rows"] >= 2 and ncols >= 2 and not t["nested"]:
            data_tables += 1
            hdr = t["first"] if (t["th_first"] or _is_headerish(t["first"])) else None
            headers = []
            seen = {}
            for i in range(ncols):
                h = (hdr[i] if hdr and i < len(hdr) else "") or f"col{i + 1}"
                if h in seen:
                    seen[h] += 1
                    h = f"{h}_{seen[h]}"
                else:
                    seen[h] = 1
                headers.append(h)
            samples = t["samples"] if hdr else [t["first"]] + t["samples"]
            out["tables"].append({"name": f"table{no}", "no": no, "mode": "table", "headers": headers,
                                  "ncols": ncols, "has_header": bool(hdr), "header_cite": t["first_loc"] if hdr else None,
                                  "samples": [s[:ncols] + [""] * (ncols - len(s)) for s in samples[:200]],
                                  "rows_estimate": t["rows"]})
    out["tables"].append({"name": "text", "mode": "text", "pair_window": 6, "headers": ["line"],
                          "samples": [[t[1]] for t in texts[:20]], "layout_tables": [no for no, t in tables.items()
                                                                                   if f"table{no}" not in [x["name"] for x in out["tables"]]]})
    out["notes"].append(f"HTML: {data_tables} data table(s), {n_text:,} text lines (proximity pairing on, window 6)")
    return out


def iterate(path, cfg: dict, table_unused: dict, resume: Optional[dict] = None) -> Iterator[tuple[Rec, dict]]:
    """One pass over the file for all of its tables (HTML is read once, in order)."""
    enc = cfg.get("encoding") or "utf-8"
    tabs = {t.get("no"): t for t in cfg.get("tables", []) if t.get("mode") == "table" and t.get("no") is not None}
    skipped = {t.get("no") for t in cfg.get("tables", []) if t.get("mode") == "skip" and t.get("no") is not None}
    text_t = next((t for t in cfg.get("tables", []) if t.get("name") == "text"), {"pair_window": 6, "mode": "text"})
    text_on = text_t.get("mode") != "skip"
    ex = TextModeExtractor(window=int(text_t.get("pair_window") or 1), table="text")
    seen_header: set = set()
    rows = 0
    skip = (resume or {}).get("rows", 0)

    def emit(rec):
        nonlocal rows
        rows += 1
        if rows > skip:
            return rec, {"rows": rows}
        return None

    for ev in _events(path, enc):
        if ev[0] == "text":
            if text_on:
                for r in ex.feed(ev[1], ev[2], None, None, ev[3]):
                    e = emit(r)
                    if e:
                        yield e
            continue
        _, no, loc, line, cells, th, nested = ev
        if no in skipped:
            continue
        t = tabs.get(no)
        if t is None:
            if text_on:
                for r in ex.feed(loc, line, None, None, " | ".join(c for c in cells if c)):
                    e = emit(r)
                    if e:
                        yield e
            continue
        if t.get("has_header") and no not in seen_header:
            seen_header.add(no)
            continue
        n = t["ncols"]
        vals = cells[:n] + [""] * (n - len(cells))
        raw = " | ".join(cells)
        e = emit(Rec(loc, line, None, None, raw, dict(zip(t["headers"], vals)), t["name"]))
        if e:
            yield e
    for r in ex.finish():
        e = emit(r)
        if e:
            yield e
