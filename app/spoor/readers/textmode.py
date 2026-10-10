"""Free-text extraction for PDFs, HTML text, logs and other non-tabular content.

A line becomes a record when it carries a timestamp, an IP, or another identifier. An IP line
with no timestamp is paired with the nearest timestamp line inside a small window (not crossing
another IP line); paired records cite every line they use, so the pairing can be checked by eye."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterator, Optional

from ..identifiers import extract as extract_ids
from ..ipaddr import find_ips
from ..timeparse import TS_SEARCH, TsParser, TzSpec

ACTION_HINT = re.compile(
    r"(?i)(?:^|[^a-z])(log ?in|logged in|log ?out|logged out|sign ?in|sign ?out|signed in|logon|logoff|"
    r"fail\w*|invalid|denied|password|2fa|two[- ]factor|mfa|recovery|reset|session|registration|"
    r"register\w*|created|deposit\w*|withdraw\w*|transfer\w*|payment|call|sms|message)(?:$|[^a-z])")

_PROBE = TsParser(TzSpec("UTC", assumed=True), column_mode=False)


@dataclass
class Rec:
    loc: str
    line: Optional[int]
    offset: Optional[int]
    length: Optional[int]
    raw: str
    cells: Optional[dict] = None
    table: Optional[str] = None
    fields: dict = field(default_factory=dict)
    note: str = ""
    extra: Optional[dict] = None


@dataclass
class _Line:
    loc: str
    line: Optional[int]
    offset: Optional[int]
    length: Optional[int]
    text: str
    ts: list
    ips: list
    consumed: bool = False


def analyse_line(loc, line, offset, length, text) -> _Line:
    ts = []
    if any(ch.isdigit() for ch in text):
        for m in TS_SEARCH.finditer(text):
            if _PROBE.parse(m.group(0)) is not None:
                ts.append(m.group(0))
    ips = find_ips(text) if ("." in text or ":" in text) else []
    return _Line(loc, line, offset, length, text, ts, ips)


def _ip_field(ln: _Line) -> tuple[str, str]:
    ip, ver, port, s, e = ln.ips[0]
    return ln.text[s:e], (str(port) if port else "")


def single_line_record(loc, line, offset, length, text, table=None, note="") -> Optional[Rec]:
    ln = analyse_line(loc, line, offset, length, text)
    return _record_from([ln], table, note) if (ln.ts or ln.ips or _has_ids(text)) else None


def _has_ids(text: str) -> bool:
    return bool(extract_ids(text, with_ips=False))


def _record_from(lines: list[_Line], table=None, note="") -> Rec:
    first = lines[0]
    f: dict = {}
    for ln in lines:
        if ln.ips and "ip" not in f:
            f["ip"], port = _ip_field(ln)
            if port:
                f["port"] = port
        if ln.ts and "ts" not in f:
            f["ts"] = ln.ts[0]
    for ln in lines:
        if ACTION_HINT.search(ln.text):
            f["action"] = ln.text.strip()[:300]
            break
    if len(lines) == 1:
        return Rec(first.loc, first.line, first.offset, first.length, first.text.rstrip("\r\n"), None, table, f, note)
    loc = "+".join(l.loc for l in lines)
    raw = "\n".join(l.text.rstrip("\r\n") for l in lines)
    extra = {"lines": [[l.loc, l.line, l.offset, l.length] for l in lines]}
    return Rec(loc, first.line, first.offset, None, raw, None, table, f,
               note or "IP and timestamp paired by proximity (lines cited)", extra)


class TextModeExtractor:
    """Streaming extractor. Each IP line without a timestamp is paired with the nearest timestamp
    line within `window` lines that is not separated from it by another IP line (greedy by
    distance; ties go to the side most pairs used so far). Deterministic and explainable."""

    def __init__(self, window: int = 6, table: Optional[str] = None, chunk: int = 2000):
        self.window = window
        self.table = table
        self.chunk = chunk
        self.buf: list[_Line] = []
        self.after_votes = 0
        self.before_votes = 0

    def feed(self, loc, line, offset, length, text) -> Iterator[Rec]:
        if not text or not text.strip():
            return
        self.buf.append(analyse_line(loc, line, offset, length, text))
        if len(self.buf) >= self.chunk + 2 * self.window:
            yield from self._flush(final=False)

    def finish(self) -> Iterator[Rec]:
        yield from self._flush(final=True)

    def _flush(self, final: bool) -> Iterator[Rec]:
        buf, W = self.buf, self.window
        n = len(buf)
        decide_end = n if final else n - W
        emit_end = n if final else n - 2 * W
        ip_pos = [i for i, l in enumerate(buf) if l.ips]
        cands = []
        for i in ip_pos:
            l = buf[i]
            if i >= decide_end or l.ts or l.consumed or getattr(l, "group", None) is not None:
                continue
            for j in range(max(0, i - W), min(n, i + W + 1)):
                t = buf[j]
                if j == i or not t.ts or t.ips or t.consumed or getattr(t, "taken", False):
                    continue
                lo, hi = (j, i) if j < i else (i, j)
                if any(lo < k < hi for k in ip_pos):
                    continue
                after = j > i
                pref = 0 if (after and self.after_votes >= self.before_votes) or \
                    (not after and self.before_votes > self.after_votes) else 1
                cands.append((abs(j - i), pref, i, j))
        cands.sort()
        for _d, _p, i, j in cands:
            l, t = buf[i], buf[j]
            if getattr(l, "group", None) is not None or getattr(t, "taken", False):
                continue
            t.taken = True
            group = [l, t]
            if j > i:
                self.after_votes += 1
            else:
                self.before_votes += 1
            lo, hi = min(i, j), max(i, j)
            for k in list(range(lo + 1, hi)) + list(range(hi + 1, min(n, hi + W + 1))):
                a = buf[k]
                if a.ips or (a.ts and k > hi):
                    break
                if not a.ts and not a.consumed and not getattr(a, "taken", False) and ACTION_HINT.search(a.text):
                    a.taken = True
                    group.append(a)
                    break
            group.sort(key=lambda x: (x.line or 0, x.loc))
            l.group = group
        for idx in range(emit_end):
            l = buf[idx]
            if l.consumed:
                continue
            g = getattr(l, "group", None)
            if g is not None:
                for x in g:
                    x.consumed = True
                yield _record_from(g, self.table)
                continue
            if getattr(l, "taken", False):
                continue  # emitted with its IP line
            l.consumed = True
            if l.ips or l.ts or _has_ids(l.text):
                yield _record_from([l], self.table)
        self.buf = [l for l in buf[emit_end:]]
