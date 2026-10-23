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


_KEY_INLINE = re.compile(r"^\s*([A-Za-z][A-Za-z _/().'-]{0,40}?)\s*[:=]\s*\S")
KEY_INLINE = _KEY_INLINE
_KEY_EMPTY = re.compile(r"^\s*([A-Za-z][A-Za-z _/().'-]{0,40}?)\s*[:=]\s*$")


def _label_like(ln: "_Line") -> bool:
    t = ln.text.strip()
    return bool(t) and len(t) <= 40 and not ln.ts and not ln.ips and not any(ch.isdigit() for ch in t) and len(t.split()) <= 5


class TextModeExtractor:
    """Streaming extractor. An IP line without a timestamp is paired with a timestamp line of the SAME record.

    Records are found from the layout itself: in key/value text ("Time: ...", "IP Address: ...", or an HTML label
    followed by its value) a key that repeats starts a new record, so a time and an IP are only ever paired when
    they belong to one block, whichever comes first. Without keys, the nearest timestamp line within `window`
    lines is used, but never across another IP line or another timestamp line, and an IP with candidates at the
    same distance on both sides is left unpaired. An IP that cannot be paired becomes a record without a time
    (flagged), never a guess. Paired records cite every line they use. Deterministic."""

    def __init__(self, window: int = 6, table: Optional[str] = None, chunk: int = 2000):
        self.window = window
        self.table = table
        self.chunk = chunk
        self.buf: list[_Line] = []
        self._prev: Optional[_Line] = None

    def feed(self, loc, line, offset, length, text) -> Iterator[Rec]:
        m = _KEY_INLINE.match(text) if text else None
        # "Time:" with nothing after it, followed by another "Key: value" line or a blank line, is an EMPTY FIELD of the
        # record (not a label for the next line): it still marks where the record starts (review #3 c03)
        pv = self._prev
        if pv is not None and getattr(pv, "key", None) is None and (m or not (text or "").strip()):
            e = _KEY_EMPTY.match(pv.text)
            if e:
                pv.key = e.group(1).strip().lower()
        if not text or not text.strip():
            if self._prev is not None:
                self._prev.blank_after = True
            return
        ln = analyse_line(loc, line, offset, length, text)
        if m and (ln.ts or ln.ips or any(ch.isdigit() for ch in text)):
            ln.key = m.group(1).strip().lower()
        elif (ln.ts or ln.ips) and self._prev is not None and _label_like(self._prev) and not getattr(self._prev, "blank_after", False):
            ln.key = self._prev.text.strip().lower()
        self.buf.append(ln)
        self._prev = ln
        if len(self.buf) >= self.chunk + 2 * self.window:
            yield from self._flush(final=False)

    def finish(self) -> Iterator[Rec]:
        yield from self._flush(final=True)

    @staticmethod
    def _segments(buf) -> list[int]:
        """Segment id per line: a key seen before in the current segment, or a blank line, starts a new one."""
        seg, cur, seen = [], 0, set()
        for i, l in enumerate(buf):
            k = getattr(l, "key", None)
            if k is not None:
                if k in seen:
                    cur += 1
                    seen = set()
                seen.add(k)
            seg.append(cur)
            if getattr(l, "blank_after", False) and seen:
                cur += 1
                seen = set()
        return seg

    def _flush(self, final: bool) -> Iterator[Rec]:
        buf, W = self.buf, self.window
        n = len(buf)
        seg = self._segments(buf)
        keyed = {}
        for i, l in enumerate(buf):
            if getattr(l, "key", None) is not None:
                keyed[seg[i]] = keyed.get(seg[i], 0) + 1
        if final:
            decide_end = emit_end = n
        else:
            last = seg[-1] if seg else 0
            start_last = next((i for i in range(n) if seg[i] == last), n)
            if keyed.get(last, 0) >= 2 and n - start_last <= self.chunk:
                decide_end = emit_end = start_last          # an unfinished keyed record waits for the next chunk
            else:
                decide_end, emit_end = n - W, n - 2 * W
        ip_pos = [i for i, l in enumerate(buf) if l.ips]
        ts_pos = [i for i, l in enumerate(buf) if l.ts]
        cands = []
        for i in ip_pos:
            l = buf[i]
            if i >= decide_end or l.ts or l.consumed or getattr(l, "group", None) is not None:
                continue
            block = keyed.get(seg[i], 0) >= 2
            reach = range(0, n) if block else range(max(0, i - W), min(n, i + W + 1))
            found = []
            for j in reach:
                t = buf[j]
                if j == i or seg[j] != seg[i] or not t.ts or t.ips or t.consumed or getattr(t, "taken", False):
                    continue
                lo, hi = (j, i) if j < i else (i, j)
                if any(lo < k < hi for k in ip_pos) or any(lo < k < hi for k in ts_pos):
                    continue          # never across another IP line or another timestamp line
                found.append((abs(j - i), j))
            if not found:
                continue
            found.sort()
            if len(found) > 1 and found[0][0] == found[1][0]:
                l.unresolved = True   # a time before and after at the same distance: do not guess
                continue
            cands.append((found[0][0], i, found[0][1]))
        cands.sort()
        for _d, i, j in cands:
            l, t = buf[i], buf[j]
            if getattr(l, "group", None) is not None or getattr(t, "taken", False):
                continue
            t.taken = True
            group = [l, t]
            lo, hi = min(i, j), max(i, j)
            for k in list(range(lo + 1, hi)) + list(range(hi + 1, min(n, hi + W + 1))):
                a = buf[k]
                if seg[k] != seg[i] or a.ips or (a.ts and k > hi):
                    break
                if not a.ts and not a.consumed and not getattr(a, "taken", False) and ACTION_HINT.search(a.text):
                    a.taken = True
                    group.append(a)
                    break
            group.sort(key=lambda x: (x.line or 0, x.loc))
            l.group = group
        for idx in range(max(0, emit_end)):
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
                r = _record_from([l], self.table)
                if l.ips and not l.ts and (getattr(l, "unresolved", False) or W):
                    r.note = r.note or ("IP with a time before and after at the same distance - not paired" if getattr(l, "unresolved", False)
                                        else "IP with no time in its record - not paired")
                yield r
        self.buf = [l for l in buf[max(0, emit_end):]]
