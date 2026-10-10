"""Timestamp parsing with explicit timezone provenance.

Every parsed timestamp carries
  utc    aware datetime in UTC
  basis  how the UTC offset was decided, e.g. 'explicit +00:00', 'explicit PST (-08:00)',
         'epoch', 'source tz America/Los_Angeles', 'ASSUMED UTC'
  flags  '' or a comma list: ambiguous_dst, nonexistent_local_time, abbr_dst_mismatch,
         date_only, two_digit_year, implausible_year
Nothing is guessed silently: every assumption is visible in basis/flags and in SOURCES.md.
"""
from __future__ import annotations

import datetime as dt
import re
from typing import NamedTuple, Optional

try:
    from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
except ImportError:  # pragma: no cover
    ZoneInfo = None  # type: ignore
    ZoneInfoNotFoundError = Exception  # type: ignore

UTC = dt.timezone.utc
THIS_YEAR = dt.datetime.now(UTC).year

# abbreviation -> (minutes east of UTC, region zone used for the DST-consistency check)
ABBR = {
    "UTC": (0, None), "GMT": (0, None), "UT": (0, None), "Z": (0, None), "ZULU": (0, None),
    "EST": (-300, "America/New_York"), "EDT": (-240, "America/New_York"),
    "CST": (-360, "America/Chicago"), "CDT": (-300, "America/Chicago"),
    "MST": (-420, "America/Denver"), "MDT": (-360, "America/Denver"),
    "PST": (-480, "America/Los_Angeles"), "PDT": (-420, "America/Los_Angeles"),
    "AKST": (-540, "America/Anchorage"), "AKDT": (-480, "America/Anchorage"),
    "HST": (-600, None),
    "WET": (0, "Europe/Lisbon"), "WEST": (60, "Europe/Lisbon"),
    "CET": (60, "Europe/Paris"), "CEST": (120, "Europe/Paris"),
    "EET": (120, "Europe/Athens"), "EEST": (180, "Europe/Athens"),
    "MSK": (180, None), "JST": (540, None), "KST": (540, None),
    "SGT": (480, None), "HKT": (480, None),
    "AEST": (600, "Australia/Sydney"), "AEDT": (660, "Australia/Sydney"),
}
_ABBR_RE = "|".join(sorted(ABBR, key=len, reverse=True))
_TZ_RE = (r"(?:Z|[+-]\d{2}(?::?\d{2})?|(?:UTC|GMT)\s?[+-]\s?\d{1,2}(?::?\d{2})?|"
          + _ABBR_RE + r"|[A-Z][a-z]+/[A-Za-z_]+(?:/[A-Za-z_]+)?)")

MONTHS = {}
for _i, _names in enumerate([
    ("jan", "january", "янв", "январь", "января"), ("feb", "february", "фев", "февраль", "февраля"),
    ("mar", "march", "мар", "март", "марта"), ("apr", "april", "апр", "апрель", "апреля"),
    ("may", "мая", "май"), ("jun", "june", "июн", "июнь", "июня"),
    ("jul", "july", "июл", "июль", "июля"), ("aug", "august", "авг", "август", "августа"),
    ("sep", "sept", "september", "сен", "сентябрь", "сентября"),
    ("oct", "october", "окт", "октябрь", "октября"), ("nov", "november", "ноя", "ноябрь", "ноября"),
    ("dec", "december", "дек", "декабрь", "декабря"),
], start=1):
    for _n in _names:
        MONTHS[_n] = _i
_MON_RE = r"(?:" + "|".join(sorted(MONTHS, key=len, reverse=True)) + r")\.?"

_WEEKDAY_PREFIX = re.compile(
    r"^(?:mon|tue|tues|wed|thu|thur|thurs|fri|sat|sun)(?:day|nesday|sday|urday)?\.?,?\s+", re.I)
_MULTI_WS = re.compile(r"\s+")
_PAREN_TZ = re.compile(r"\s*\(\s*(" + _TZ_RE + r")\s*\)\s*$")
_TIME = r"(\d{1,2}):(\d{2})(?::(\d{2})(?:[.,](\d{1,9}))?)?"
_AMPM = r"(?:\s*([AaPp])\.?\s?[Mm]\.?)?"

P_ISO = re.compile(r"^(\d{4})-(\d{1,2})-(\d{1,2})(?:[T ]+" + _TIME + r")?\s*(" + _TZ_RE + r")?$")
P_NUM = re.compile(r"^(\d{1,4})[/.-](\d{1,2})[/.-](\d{2,4})(?:[ T,]+" + _TIME + _AMPM + r")?\s*(" + _TZ_RE + r")?$")
P_DMONY = re.compile(r"^(\d{1,2})[ -]+(" + _MON_RE + r")[ -,]+(\d{2,4})(?:[ ,T:]+" + _TIME + _AMPM + r")?\s*(" + _TZ_RE + r")?$", re.I)
P_MONDY = re.compile(r"^(" + _MON_RE + r")\s+(\d{1,2})(?:st|nd|rd|th)?,?\s+(\d{4})(?:[ ,T]+(?:at\s+)?" + _TIME + _AMPM + r")?\s*(" + _TZ_RE + r")?$", re.I)
P_UNIX = re.compile(r"^(" + _MON_RE + r")\s+(\d{1,2})\s+" + _TIME + r"\s+(?:(" + _TZ_RE + r")\s+)?(\d{4})$", re.I)
P_CLF = re.compile(r"^(\d{1,2})/(" + _MON_RE + r")/(\d{4}):" + _TIME + r"\s*(" + _TZ_RE + r")?$", re.I)
P_COMPACT = re.compile(r"^(\d{4})(\d{2})(\d{2})[T ]?(\d{2})(\d{2})(\d{2})(?:[.,](\d{1,9}))?(Z)?$")
P_EPOCH = re.compile(r"^(\d{9,19})(?:\.(\d{1,9}))?$")

# For finding timestamps inside free text (PDF/HTML/TXT lines).
TS_SEARCH = re.compile(
    r"(?<![\d/.:-])(?:"
    r"\d{4}-\d{1,2}-\d{1,2}(?:[T ]+\d{1,2}:\d{2}(?::\d{2}(?:[.,]\d{1,9})?)?)?(?:\s*" + _TZ_RE + r")?"
    r"|\d{1,2}/" + _MON_RE + r"/\d{4}:\d{2}:\d{2}:\d{2}(?:\s*[+-]\d{4})?"
    r"|\d{1,2}[/.]\d{1,2}[/.](?:\d{4}|\d{2}(?=[ ,]+\d{1,2}:\d{2}))(?:[ ,]+\d{1,2}:\d{2}(?::\d{2}(?:[.,]\d{1,9})?)?(?:\s*[AaPp]\.?\s?[Mm]\.?)?)?(?:\s*" + _TZ_RE + r")?"
    r"|\d{1,2}[ -]" + _MON_RE + r"[ -,]+\d{4}(?:[ ,T]+\d{1,2}:\d{2}(?::\d{2}(?:[.,]\d{1,9})?)?(?:\s*[AaPp]\.?\s?[Mm]\.?)?)?(?:\s*" + _TZ_RE + r")?"
    r"|" + _MON_RE + r"\s+\d{1,2}(?:st|nd|rd|th)?,?\s+\d{4}(?:[ ,T]+(?:at\s+)?\d{1,2}:\d{2}(?::\d{2}(?:[.,]\d{1,9})?)?(?:\s*[AaPp]\.?\s?[Mm]\.?)?)?(?:\s*" + _TZ_RE + r")?"
    r"|" + _MON_RE + r"\s+\d{1,2}\s+\d{1,2}:\d{2}:\d{2}\s+(?:" + _TZ_RE + r"\s+)?\d{4}"
    r")(?![\d:]|\.\d)", re.I)


class TsResult(NamedTuple):
    utc: dt.datetime
    basis: str
    flags: str


class TzSpec:
    """The timezone that applies to a source's timestamps that carry no offset of their own."""

    def __init__(self, name: str = "UTC", assumed: bool = True, basis: str = ""):
        self.name = (name or "UTC").strip()
        self.assumed = assumed
        self.basis = basis
        self.tz = parse_tz_name(self.name)
        if self.tz is None:
            raise ValueError(f"Unknown timezone: {self.name!r}")
        self.is_zone = ZoneInfo is not None and isinstance(self.tz, ZoneInfo)

    @property
    def label(self) -> str:
        if self.assumed:
            return f"ASSUMED {self.name}"
        return f"source tz {self.name}"


def parse_tz_name(name: str):
    """'UTC', 'America/New_York', 'UTC-05:00', '+0530', 'PST' -> tzinfo (or None)."""
    if not name:
        return None
    n = name.strip()
    u = n.upper()
    if u in ("UTC", "GMT", "Z", "UT", "ZULU"):
        return UTC
    m = re.fullmatch(r"(?:UTC|GMT)?\s*([+-])\s*(\d{1,2})(?::?(\d{2}))?", u)
    if m:
        mins = int(m.group(2)) * 60 + int(m.group(3) or 0)
        if mins > 14 * 60:
            return None
        return dt.timezone(dt.timedelta(minutes=mins if m.group(1) == "+" else -mins))
    if u in ABBR:
        return dt.timezone(dt.timedelta(minutes=ABBR[u][0]))
    if ZoneInfo is not None and "/" in n:
        try:
            return ZoneInfo(n)
        except (ZoneInfoNotFoundError, ValueError, OSError):
            return None
    return None


def fmt_utc(d: dt.datetime) -> str:
    """'YYYY-MM-DD HH:MM:SS[.ffffff]' with trailing zeros of the fraction removed."""
    s = d.strftime("%Y-%m-%d %H:%M:%S")
    if d.microsecond:
        s += ("." + f"{d.microsecond:06d}").rstrip("0")
    return s


def _offset_label(td: dt.timedelta) -> str:
    mins = int(td.total_seconds() // 60)
    sign = "+" if mins >= 0 else "-"
    mins = abs(mins)
    return f"{sign}{mins // 60:02d}:{mins % 60:02d}"


def localize(naive: dt.datetime, tz) -> tuple[dt.datetime, str]:
    """Attach a zone to a wall-clock time, reporting DST ambiguity instead of hiding it."""
    if ZoneInfo is None or not isinstance(tz, ZoneInfo):
        return naive.replace(tzinfo=tz).astimezone(UTC), ""
    a = naive.replace(tzinfo=tz, fold=0)
    b = naive.replace(tzinfo=tz, fold=1)
    if a.utcoffset() == b.utcoffset():
        return a.astimezone(UTC), ""
    ua = a.astimezone(UTC)
    back = ua.astimezone(tz).replace(tzinfo=None)
    if back == naive:
        return ua, "ambiguous_dst"
    return ua, "nonexistent_local_time"


def _frac(s: Optional[str]) -> int:
    if not s:
        return 0
    return int((s + "000000")[:6])


def _year(y: str, flags: list) -> int:
    v = int(y)
    if len(y) == 2:
        flags.append("two_digit_year")
        v += 2000 if v < 70 else 1900
    return v


def _hour(h: str, ampm: Optional[str]) -> int:
    hv = int(h)
    if ampm:
        a = ampm.lower()
        if hv == 12:
            hv = 0
        if a == "p":
            hv += 12
    return hv


class TsParser:
    """Parses one column (or free text) of a source, caching the last pattern that worked."""

    def __init__(self, default_tz: TzSpec, date_order: str = "MDY", column_mode: bool = True):
        self.tz = default_tz
        self.date_order = date_order if date_order in ("MDY", "DMY", "YMD") else "MDY"
        self.column_mode = column_mode
        self._order = [self._iso, self._num, self._mondy, self._dmony, self._unix, self._clf]
        if column_mode:
            self._order += [self._compact, self._epoch]

    # ---------------------------------------------------------------- public
    def parse(self, value) -> Optional[TsResult]:
        if value is None:
            return None
        if isinstance(value, dt.datetime):
            return self._finish_dt(value, [])
        if isinstance(value, dt.date):
            return self._finish_dt(dt.datetime(value.year, value.month, value.day), ["date_only"])
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            if not self.column_mode:
                return None
            value = repr(value) if isinstance(value, float) else str(value)
        s = str(value).strip().strip("'\"").strip()
        if not s or len(s) > 80:
            return None
        if "  " in s or "\t" in s or "\n" in s:
            s = _MULTI_WS.sub(" ", s)
        if s[:1].isalpha():
            s = _WEEKDAY_PREFIX.sub("", s)
        if s.endswith(")"):
            m = _PAREN_TZ.search(s)
            if m:
                s = s[: m.start()] + " " + m.group(1)
        for i, fn in enumerate(self._order):
            try:
                r = fn(s)
            except (ValueError, OverflowError):
                r = None
            if r is not None:
                if i:
                    self._order.insert(0, self._order.pop(i))
                return r
        return None

    def find_all(self, text: str) -> list[tuple[int, int, TsResult]]:
        """All timestamps inside free text: (start, end, result)."""
        out = []
        for m in TS_SEARCH.finditer(text):
            r = self.parse(m.group(0))
            if r is not None:
                out.append((m.start(), m.end(), r))
        return out

    # ---------------------------------------------------------------- helpers
    def _finish(self, y, mo, d, h=0, mi=0, se=0, us=0, tz=None, flags=None, date_only=False):
        flags = flags or []
        if date_only:
            flags.append("date_only")
        if se == 60:  # leap second notation
            se = 59
        naive = dt.datetime(y, mo, d, h, mi, se, us)
        return self._finish_dt(naive, flags, tz)

    def _finish_dt(self, naive: dt.datetime, flags: list, tz_token: Optional[str] = None):
        if naive.tzinfo is not None:
            utc = naive.astimezone(UTC)
            basis = "explicit " + _offset_label(naive.utcoffset() or dt.timedelta())
        elif tz_token:
            utc, basis, f2 = self._apply_token(naive, tz_token)
            flags.extend(f2)
        else:
            utc, f = localize(naive, self.tz.tz)
            if f:
                flags.append(f)
            basis = self.tz.label
        if utc.year < 1995 or utc.year > THIS_YEAR + 1:
            flags.append("implausible_year")
        return TsResult(utc, basis, ",".join(dict.fromkeys(flags)))

    def _apply_token(self, naive: dt.datetime, tok: str):
        flags: list = []
        t = tok.strip()
        u = t.upper().replace(" ", "")
        if u in ABBR:
            mins, region = ABBR[u]
            utc = naive.replace(tzinfo=dt.timezone(dt.timedelta(minutes=mins))).astimezone(UTC)
            if region and ZoneInfo is not None:
                try:
                    expect = utc.astimezone(ZoneInfo(region)).tzname()
                    if expect and expect.upper() != u:
                        flags.append("abbr_dst_mismatch")
                except Exception:
                    pass
            if u in ("Z", "UTC", "GMT", "UT", "ZULU"):
                return utc, f"explicit {u}", flags
            return utc, f"explicit {u} ({_offset_label(dt.timedelta(minutes=mins))})", flags
        tz = parse_tz_name(t)
        if tz is None:
            raise ValueError("unknown tz token")
        if ZoneInfo is not None and isinstance(tz, ZoneInfo):
            utc, f = localize(naive, tz)
            if f:
                flags.append(f)
            return utc, f"explicit zone {t}", flags
        off = tz.utcoffset(None)
        return naive.replace(tzinfo=tz).astimezone(UTC), f"explicit {_offset_label(off)}", flags

    # ---------------------------------------------------------------- patterns
    def _iso(self, s):
        m = P_ISO.match(s)
        if not m:
            return None
        y, mo, d, h, mi, se, fr, tz = m.groups()
        if h is None:
            return self._finish(int(y), int(mo), int(d), tz=tz, date_only=True)
        return self._finish(int(y), int(mo), int(d), int(h), int(mi), int(se or 0), _frac(fr), tz)

    def _num(self, s):
        m = P_NUM.match(s)
        if not m:
            return None
        a, b, c, h, mi, se, fr, ap, tz = m.groups()
        flags: list = []
        if len(a) == 4:
            y, mo, d = int(a), int(b), int(c)
        else:
            if len(c) not in (2, 4):
                return None
            y = _year(c, flags)
            if self.date_order == "DMY":
                d, mo = int(a), int(b)
            else:
                mo, d = int(a), int(b)
            if mo > 12 and d <= 12:  # impossible as stated -> the column order setting is wrong
                return None
        if h is None:
            return self._finish(y, mo, d, tz=tz, flags=flags, date_only=True)
        return self._finish(y, mo, d, _hour(h, ap), int(mi), int(se or 0), _frac(fr), tz, flags)

    def _mondy(self, s):
        m = P_MONDY.match(s)
        if not m:
            return None
        mon, d, y, h, mi, se, fr, ap, tz = m.groups()
        mo = MONTHS.get(mon.lower().rstrip("."))
        if not mo:
            return None
        if h is None:
            return self._finish(int(y), mo, int(d), tz=tz, date_only=True)
        return self._finish(int(y), mo, int(d), _hour(h, ap), int(mi), int(se or 0), _frac(fr), tz)

    def _dmony(self, s):
        m = P_DMONY.match(s)
        if not m:
            return None
        d, mon, y, h, mi, se, fr, ap, tz = m.groups()
        mo = MONTHS.get(mon.lower().rstrip("."))
        if not mo:
            return None
        flags: list = []
        yv = _year(y, flags)
        if h is None:
            return self._finish(yv, mo, int(d), tz=tz, flags=flags, date_only=True)
        return self._finish(yv, mo, int(d), _hour(h, ap), int(mi), int(se or 0), _frac(fr), tz, flags)

    def _unix(self, s):
        m = P_UNIX.match(s)
        if not m:
            return None
        mon, d, h, mi, se, fr, tz, y = m.groups()
        mo = MONTHS.get(mon.lower().rstrip("."))
        if not mo:
            return None
        return self._finish(int(y), mo, int(d), int(h), int(mi), int(se or 0), _frac(fr), tz)

    def _clf(self, s):
        m = P_CLF.match(s)
        if not m:
            return None
        d, mon, y, h, mi, se, fr, tz = m.groups()
        mo = MONTHS.get(mon.lower().rstrip("."))
        if not mo:
            return None
        return self._finish(int(y), mo, int(d), int(h), int(mi), int(se or 0), _frac(fr), tz)

    def _compact(self, s):
        m = P_COMPACT.match(s)
        if not m:
            return None
        y, mo, d, h, mi, se, fr, z = m.groups()
        return self._finish(int(y), int(mo), int(d), int(h), int(mi), int(se), _frac(fr), z)

    def _epoch(self, s):
        m = P_EPOCH.match(s)
        if not m:
            return None
        whole, frac = m.groups()
        n = len(whole)
        if 9 <= n <= 10:
            scale = 1
        elif 12 <= n <= 13:
            scale = 1_000
        elif 15 <= n <= 16:
            scale = 1_000_000
        elif 18 <= n <= 19:
            scale = 1_000_000_000
        else:
            return None
        secs = int(whole) / scale
        if frac and scale == 1:
            secs = int(whole) + float("0." + frac)
        if not (788918400 <= secs <= 4102444800):  # 1995-01-01 .. 2100-01-01
            return None
        whole_s = int(whole) // scale
        rem = int(whole) % scale
        us = int(rem * 1_000_000 // scale) if scale > 1 else _frac(frac)
        utc = dt.datetime.fromtimestamp(whole_s, UTC).replace(microsecond=us)
        unit = {1: "s", 1_000: "ms", 1_000_000: "us", 1_000_000_000: "ns"}[scale]
        return TsResult(utc, f"epoch ({unit}, UTC by definition)", "")


# ---------------------------------------------------------------- column inference

def infer_date_order(values) -> tuple[str, str]:
    """Look at numeric dates like 03/04/2024 and decide MDY vs DMY.

    Returns (order, note). note is '' when the data proves the order."""
    first_gt12 = second_gt12 = seen = 0
    for v in values:
        if v is None:
            continue
        m = re.match(r"^\s*(\d{1,2})[/.-](\d{1,2})[/.-](\d{2,4})\b", str(v))
        if not m:
            continue
        seen += 1
        a, b = int(m.group(1)), int(m.group(2))
        if a > 12 >= b:
            first_gt12 += 1
        elif b > 12 >= a:
            second_gt12 += 1
    if not seen:
        return "MDY", ""
    if first_gt12 and second_gt12:
        return "MDY", "inconsistent day/month order in sample; assumed MM/DD"
    if first_gt12:
        return "DMY", ""
    if second_gt12:
        return "MDY", ""
    return "MDY", "day/month order cannot be proven from the data (all day values <= 12); assumed MM/DD (US)"


TZ_HINTS = [
    (re.compile(r"\b(?:UTC|GMT|Zulu|Coordinated Universal Time|Greenwich Mean Time)\b(?!\s*[+-]\s*\d)", re.I), "UTC"),
    (re.compile(r"\b(?:UTC|GMT)\s*([+-])\s*(\d{1,2})(?::?(\d{2}))?\b", re.I), "FIXED"),
    (re.compile(r"\bPacific(?: Standard| Daylight)?(?: Time)?\b|\bPST/PDT\b|\bPDT\b|\bPST\b", re.I), "America/Los_Angeles"),
    (re.compile(r"\bEastern(?: Standard| Daylight)?(?: Time)?\b|\bEST/EDT\b|\bEDT\b|\bEST\b", re.I), "America/New_York"),
    (re.compile(r"\bCentral(?: Standard| Daylight)?(?: Time)\b|\bCST/CDT\b|\bCDT\b|\bCST\b", re.I), "America/Chicago"),
    (re.compile(r"\bArizona\b", re.I), "America/Phoenix"),
    (re.compile(r"\bMountain(?: Standard| Daylight)?(?: Time)\b|\bMST/MDT\b|\bMDT\b|\bMST\b", re.I), "America/Denver"),
    (re.compile(r"\bMoscow(?: Time)?\b|\bMSK\b|МСК|Москв", re.I), "Europe/Moscow"),
    (re.compile(r"\b([A-Z][a-z]+/[A-Za-z_]+(?:/[A-Za-z_]+)?)\b"), "IANA"),
]
HEADER_ONLY_HINTS = [
    (re.compile(r"[(\[ _-]PT[)\] _-]|\(PT\)|\bPT$"), "America/Los_Angeles"),
    (re.compile(r"[(\[ _-]ET[)\] _-]|\(ET\)|\bET$"), "America/New_York"),
    (re.compile(r"[(\[ _-]CT[)\] _-]|\(CT\)|\bCT$"), "America/Chicago"),
    (re.compile(r"[(\[ _-]MT[)\] _-]|\(MT\)|\bMT$"), "America/Denver"),
]


def tz_hints_in(text: str, header: bool = False) -> list[str]:
    found = []
    for rx, zone in TZ_HINTS:
        for m in rx.finditer(text):
            if zone == "FIXED":
                sign, hh, mm = m.group(1), int(m.group(2)), int(m.group(3) or 0)
                found.append(f"UTC{sign}{hh:02d}:{mm:02d}")
            elif zone == "IANA":
                if parse_tz_name(m.group(1)) is not None:
                    found.append(m.group(1))
            else:
                found.append(zone)
    if header:
        for rx, zone in HEADER_ONLY_HINTS:
            if rx.search(" " + text + " "):
                found.append(zone)
    return list(dict.fromkeys(found))


def suggest_source_tz(header_cells: list[tuple[str, str]], preamble: list[tuple[str, str]],
                      filename: str) -> dict:
    """Decide the default timezone for a source and say exactly why.

    header_cells / preamble: (citation, text). Returns {tz, assumed, basis, conflicts}."""
    hits: list[tuple[str, str, str]] = []
    for cite, txt in header_cells:
        for z in tz_hints_in(txt, header=True):
            hits.append((z, cite, f"header '{txt.strip()[:60]}'"))
    for cite, txt in preamble:
        for z in tz_hints_in(txt):
            hits.append((z, cite, f"text '{txt.strip()[:80]}'"))
    for z in tz_hints_in(filename.replace("_", " ")):
        hits.append((z, "file name", f"file name '{filename}'"))

    if not hits:
        return {"tz": "UTC", "assumed": True,
                "basis": "no timezone indicator found in header, preamble or file name; treated as UTC - VERIFY with the provider's cover letter",
                "conflicts": []}
    z, cite, why = hits[0]
    note = f"{why} at {cite}" if cite != "file name" else why
    if z in ("America/Los_Angeles", "America/New_York", "America/Chicago", "America/Denver") and \
            re.search(r"\b(PST|EST|CST|MST)\b", why) and not re.search(r"(PDT|EDT|CDT|MDT|/)", why):
        note += "; a standard-time abbreviation was read as the DST-observing zone - if the provider means a fixed offset year-round, set the source timezone to a fixed UTC offset"
    return {"tz": z, "assumed": False, "basis": note,
            "conflicts": [f"{h[0]} ({h[2]} at {h[1]})" for h in hits[1:] if h[0] != z]}


def looks_like_timestamp(v) -> bool:
    if v is None:
        return False
    if isinstance(v, (dt.datetime, dt.date)):
        return True
    p = _PROBE
    return p.parse(v) is not None


_PROBE = TsParser(TzSpec("UTC", assumed=True), column_mode=False)
