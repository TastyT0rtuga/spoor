"""Mechanical verification of model-written sentences against the findings they cite.

A sentence is REJECTED when any checkable value in it is missing from the cited findings:
IP addresses, emails, phones, crypto addresses, MACs, URLs, timestamps, dates, times, numbers
(exact, or within the stated rounding when preceded by 'about'/'over'/...), percentages
(rounding allowed), ASNs, source labels, capitalised names, and known account names. A sentence
with nothing checkable in it is rejected as well. Inference and characterisation words do not
reject a sentence but FLAG it for the analyst's judgment."""
from __future__ import annotations

import datetime as dt
import json
import re
from dataclasses import dataclass, field

from .identifiers import extract as extract_ids
from .ipaddr import find_ips

MONTHS = {m: i for i, m in enumerate(["january", "february", "march", "april", "may", "june", "july", "august",
                                      "september", "october", "november", "december"], 1)}
MONTHS.update({k[:3]: v for k, v in list(MONTHS.items())})
MONTHS["sept"] = 9
NUMBER_WORDS = {"two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7, "eight": 8, "nine": 9, "ten": 10,
                "eleven": 11, "twelve": 12, "thirteen": 13, "fourteen": 14, "fifteen": 15, "sixteen": 16, "seventeen": 17,
                "eighteen": 18, "nineteen": 19, "twenty": 20, "thirty": 30, "forty": 40, "fifty": 50, "sixty": 60,
                "hundred": 100, "dozen": 12, "twice": 2}
APPROX_UP = ("over", "more than", "at least", "above", "exceeding")
APPROX_DOWN = ("under", "less than", "fewer than", "at most", "up to", "below")
APPROX_ANY = ("about", "approximately", "approx", "around", "roughly", "nearly", "almost", "some", "~", "close to")
INFERENCE = [r"\blikely\b", r"\bunlikely\b", r"\bprobabl[ey]\b", r"\bpossibl[ey]\b", r"\bperhaps\b", r"\bsuggest\w*",
             r"\bindicat\w*", r"\bappear(?:s|ed)? (?:to|that)\b", r"\bit appears\b", r"\bapparently\b", r"\bseem(?:s|ed)?\b",
             r"(?<![A-Za-z])may(?!\s+\d)\b", r"\bmight\b", r"\bcould\b", r"\bpresumabl[ey]\b", r"\bconsistent with\b",
             r"\bbelieved?\b", r"\bimpl(?:y|ies|ied)\b", r"\bevidently\b", r"\bclearly\b", r"\bobviously\b",
             r"\bpotential(?:ly)?\b", r"\bpoints? to\b", r"\bstrongly\b"]
CHARACTERISATION = ["attacker", "attack", "attacked", "hacker", "hacked", "compromise", "compromised", "takeover",
                    "take-over", "fraud", "fraudulent", "criminal", "crime", "suspect", "suspicious", "malicious", "illicit",
                    "laundering", "stolen", "theft", "victim", "perpetrator", "guilty", "unauthorized", "unauthorised",
                    "belongs to", "controlled by", "same person", "same individual", "owner", "operated by", "brute force",
                    "brute-force", "password spray", "account takeover"]
COMMON_CAPS = {
    "utc", "ip", "ips", "ipv4", "ipv6", "asn", "asns", "isp", "isps", "vpn", "vpns", "cgnat", "dst", "id", "ids", "url", "urls",
    "the", "this", "these", "those", "that", "there", "then", "than", "account", "accounts", "source", "sources", "records",
    "record", "events", "event", "finding", "findings", "between", "during", "from", "after", "before", "within", "while",
    "both", "each", "all", "and", "but", "also", "its", "their", "his", "her", "one", "two", "three", "public", "private",
    "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday", "mac", "imei", "email", "e-mail", "phone",
    "bitcoin", "ethereum", "litecoin", "tron", "monero", "dogecoin", "local", "time", "times", "local time", "sql",
    "login", "logins", "logout", "logouts", "network", "networks", "country", "countries", "address", "addresses",
    "january", "february", "march", "april", "may", "june", "july", "august", "september", "october", "november",
    "december", "jan", "feb", "mar", "apr", "jun", "jul", "aug", "sep", "sept", "oct", "nov", "dec",
}
CITE_RE = re.compile(r"\[?\(?\b(F\d{3,}|R\d+)\b\)?\]?")
DT_RE = re.compile(r"\b(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?)(?:\s*(?:UTC|Z))?\b")
DATE_RE = re.compile(r"\b(\d{4}-\d{2}-\d{2})\b")
MDY_RE = re.compile(r"\b(Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|June?|July?|Aug(?:ust)?|Sep(?:t(?:ember)?)?|"
                    r"Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\.?\s+(\d{1,2})(?:st|nd|rd|th)?,?\s+(\d{4})\b", re.I)
DMY_RE = re.compile(r"\b(\d{1,2})\s+(Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|June?|July?|Aug(?:ust)?|"
                    r"Sep(?:t(?:ember)?)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\.?,?\s+(\d{4})\b", re.I)
MY_RE = re.compile(r"\b(January|February|March|April|May|June|July|August|September|October|November|December)\s+(\d{4})\b", re.I)
TIME_RE = re.compile(r"\b(\d{1,2}):(\d{2})(?::(\d{2}))?(?:\s*([AaPp])\.?[Mm]\.?)?")
ASN_RE = re.compile(r"\bAS\s?(\d{1,10})\b")
LABEL_RE = re.compile(r"\bS\d{2,}\b")
NUM_RE = re.compile(r"(?<![\w.:/-])([-+]?\d[\d,]*(?:\.\d+)?)(\s?%|\s?percent)?(?![\w:]|\.\d)")
YEAR_RE = re.compile(r"^(19|20)\d{2}$")
WORD_NUM_RE = re.compile(r"\b(" + "|".join(NUMBER_WORDS) + r")\b", re.I)
CAP_RE = re.compile(r"\b[A-Z][A-Za-z0-9'’.&-]{2,}")


@dataclass
class Toks:
    ips: set = field(default_factory=set)
    idents: set = field(default_factory=set)
    datetimes: set = field(default_factory=set)
    dates: set = field(default_factory=set)
    months: set = field(default_factory=set)
    times: set = field(default_factory=set)
    asns: set = field(default_factory=set)
    labels: set = field(default_factory=set)
    numbers: list = field(default_factory=list)   # (value, raw, is_pct, decimals, approx)
    years: set = field(default_factory=set)

    def merge(self, o: "Toks"):
        for k in ("ips", "idents", "datetimes", "dates", "months", "times", "asns", "labels", "years"):
            getattr(self, k).update(getattr(o, k))
        self.numbers += o.numbers

    def count(self) -> int:
        return (len(self.ips) + len(self.idents) + len(self.datetimes) + len(self.dates) + len(self.months) + len(self.times)
                + len(self.asns) + len(self.labels) + len(self.numbers) + len(self.years))


def _blank(s: str, a: int, b: int) -> str:
    return s[:a] + " " * (b - a) + s[b:]


def tokens(text: str) -> Toks:
    t = Toks()
    s = text
    for ip, _v, _p, a, b in find_ips(s):
        t.ips.add(ip)
        s = _blank(s, a, b)
    for kind, raw, norm, _val in extract_ids(s, with_ips=False):
        t.idents.add(f"{kind}:{norm.lower()}")
        i = s.find(raw)
        if i >= 0:
            s = _blank(s, i, i + len(raw))
    for m in DT_RE.finditer(s):
        tm = m.group(2)
        t.datetimes.add(f"{m.group(1)} {tm}")
        t.dates.add(m.group(1))
        s = _blank(s, m.start(), m.end())
    for m in DATE_RE.finditer(s):
        t.dates.add(m.group(1))
        s = _blank(s, m.start(), m.end())
    for rx, order in ((MDY_RE, "mdy"), (DMY_RE, "dmy")):
        for m in rx.finditer(s):
            if order == "mdy":
                mon, d, y = m.group(1), m.group(2), m.group(3)
            else:
                d, mon, y = m.group(1), m.group(2), m.group(3)
            mo = MONTHS.get(mon.lower().rstrip("."))
            try:
                t.dates.add(dt.date(int(y), mo, int(d)).isoformat())
            except (TypeError, ValueError):
                continue
            s = _blank(s, m.start(), m.end())
    for m in MY_RE.finditer(s):
        t.months.add(f"{int(m.group(2)):04d}-{MONTHS[m.group(1).lower()]:02d}")
        s = _blank(s, m.start(), m.end())
    for m in TIME_RE.finditer(s):
        h, mi = int(m.group(1)), int(m.group(2))
        if m.group(4):
            h = h % 12 + (12 if m.group(4).lower() == "p" else 0)
        if h > 23 or mi > 59:
            continue
        t.times.add(f"{h:02d}:{mi:02d}" + (f":{int(m.group(3)):02d}" if m.group(3) else ""))
        s = _blank(s, m.start(), m.end())
    for m in ASN_RE.finditer(s):
        t.asns.add(m.group(1))
        s = _blank(s, m.start(), m.end())
    for m in LABEL_RE.finditer(s):
        t.labels.add(m.group(0).upper())
        s = _blank(s, m.start(), m.end())
    for m in NUM_RE.finditer(s):
        raw = m.group(1)
        v = raw.replace(",", "")
        try:
            val = float(v)
        except ValueError:
            continue
        if YEAR_RE.match(v) and not m.group(2):
            t.years.add(v)
            continue
        before = s[max(0, m.start() - 24): m.start()].lower()
        approx = next((w for w in APPROX_UP + APPROX_DOWN + APPROX_ANY if before.rstrip().endswith(w)), None)
        dec = len(v.split(".")[1]) if "." in v else 0
        t.numbers.append((val, raw, bool(m.group(2)), dec, approx))
    for m in WORD_NUM_RE.finditer(s):
        t.numbers.append((float(NUMBER_WORDS[m.group(1).lower()]), m.group(1), False, 0, None))
    return t


def _walk_strings(obj, out: list):
    if obj is None:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            _walk_strings(v, out)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            _walk_strings(v, out)
    elif isinstance(obj, bool):
        out.append("yes" if obj else "no")
    elif isinstance(obj, float):
        out.append(repr(obj) if not obj.is_integer() else str(int(obj)))
    else:
        out.append(str(obj))


class FactBase:
    """Allowed values per citable item (finding F### or result row R#)."""

    def __init__(self, items: list[dict]):
        self.items: dict[str, dict] = {}
        for it in items:
            strings = [it.get("title") or "", it.get("statement") or ""]
            _walk_strings(it.get("values"), strings)
            rows = []
            for tb in it.get("tables") or []:
                for r in tb.get("rows") or []:
                    rs = []
                    _walk_strings(r, rs)
                    rows.append(rs)
                    strings += rs
            tk = Toks()
            nums = set()
            for s in strings:
                tt = tokens(s)
                tk.merge(tt)
                for n in tt.numbers:
                    nums.add(n[0])
                try:
                    nums.add(float(str(s).replace(",", "")))
                except ValueError:
                    pass
            blob = " ".join(strings).lower()
            row_sets = []
            vals = []          # scalar values only: a list of accounts is not a statement that they did anything together
            _walk_strings({k: v for k, v in (it.get("values") or {}).items() if not isinstance(v, (list, dict))}, vals)
            # units in which values must occur TOGETHER: each table row, the finding's values, each sentence of the statement
            for rs in [vals] + rows:
                row_sets.append(" ".join(rs).lower())
            for sent in re.split(r"(?<=[.;])\s+", it.get("statement") or ""):
                if sent.strip():
                    row_sets.append(sent.lower())
            self.items[it["id"]] = {"tok": tk, "nums": nums, "blob": blob, "rows": row_sets}

    def union(self, ids: list[str]) -> dict:
        tk = Toks()
        nums, blobs, rows = set(), [], []
        for i in ids:
            it = self.items.get(i)
            if not it:
                continue
            tk.merge(it["tok"])
            nums |= it["nums"]
            blobs.append(it["blob"])
            rows += it["rows"]
        dates = set(tk.dates) | {d[:10] for d in tk.datetimes}
        return {"tok": tk, "nums": nums, "blob": " ".join(blobs), "rows": rows, "dates": dates,
                "years": {d[:4] for d in dates} | set(tk.years), "months": {d[:7] for d in dates} | set(tk.months)}


NEG_RE = re.compile(r"\b(?:never|not|no|none|neither|nor|without|didn't|did not|wasn't|weren't|isn't|aren't|hasn't|haven't|cannot|can't)\b")
COUNT_RE = re.compile(r"(?<![\d.:/-])(\d[\d,]*)\s+(?:[a-z-]+\s+){0,2}?(calls?|texts?|messages?|records?|failed logins?|logins?|accounts?|ips?|"
                      r"ip addresses|addresses|events?|transactions?|contacts?|occasions?|hops?|returns?|days?|targets?|numbers?|sessions?)\b")


ACTION_RE = re.compile(r"\b(password|passcode|2-step|two-step|2fa|two-factor|mfa|recovery (?:e-?mail|phone)|withdraw\w*|deposit\w*|"
                       r"deleted|disabled|enabled|reset)\b")


def _has(x: str, unit: str) -> bool:
    return re.search(r"(?<![\w.@-])" + re.escape(x) + r"(?![\w@-]|\.\d)", unit) is not None


def _num_ok(n, allowed: set) -> bool:
    val, raw, is_pct, dec, approx = n
    cands = allowed | {abs(a) for a in allowed}
    if approx in APPROX_UP:
        return any(a >= val for a in cands)
    if approx in APPROX_DOWN:
        return any(a <= val for a in cands)
    if approx and is_pct:
        tol = 0.5 * 10 ** (-dec) + 0.5          # 'about 76%' for 76.2% - never more than one point off
        return any(abs(abs(val) - abs(a)) <= tol for a in cands)
    if approx:
        z = len(raw.replace(",", "").split(".")[0]) - len(raw.replace(",", "").split(".")[0].rstrip("0"))
        tol = max(0.5 * (10 ** z), 0.5 * 10 ** (-dec))
        tol = min(tol, max(1.0, abs(val) * 0.05))  # rounding to the stated precision, at most 5 %
        return any(abs(abs(val) - abs(a)) <= tol for a in cands)
    if is_pct or dec:
        tol = 0.5 * 10 ** (-dec) + 1e-9
        return any(abs(abs(val) - abs(a)) <= tol for a in cands)
    return abs(val) in {abs(a) for a in cands}


def check_sentence(text: str, cites: list[str], fb: FactBase, known_accounts: set | None = None,
                   allowed_ids: set | None = None) -> tuple[str, list[str], list[str], list[str]]:
    """Return (status, reasons, flags, cited_ids). status: accepted | flagged | rejected.

    allowed_ids: the items the model was shown; citing anything else rejects the sentence."""
    reasons, flags = [], []
    in_text = [m.group(1) for m in CITE_RE.finditer(text)]
    all_cites = list(dict.fromkeys([str(c).strip().strip("[]()") for c in (cites or [])] + in_text))
    pool = set(fb.items) if allowed_ids is None else (set(fb.items) & set(allowed_ids))
    valid = [c for c in all_cites if c in pool]
    bad = [c for c in all_cites if c not in pool]
    if bad:
        reasons.append(f"cites {', '.join(bad)}, which {'do' if len(bad) > 1 else 'does'} not exist or {'were' if len(bad) > 1 else 'was'} not provided")
    if not valid:
        return "rejected", reasons + ["no valid citation"], flags, valid
    clean = CITE_RE.sub(" ", text)
    allowed = fb.union(valid)
    at = allowed["tok"]
    st = tokens(clean)
    for ip in sorted(st.ips):
        if ip not in at.ips:
            reasons.append(f"IP {ip} is not in the cited findings")
    for x in sorted(st.idents):
        if x not in at.idents:
            reasons.append(f"{x.split(':', 1)[0]} {x.split(':', 1)[1]} is not in the cited findings")
    for d in sorted(st.datetimes):
        if not any(a.startswith(d) for a in at.datetimes):
            reasons.append(f"timestamp {d} is not in the cited findings")
    for d in sorted(st.dates - {x[:10] for x in st.datetimes}):
        if d not in allowed["dates"]:
            reasons.append(f"date {d} is not in the cited findings")
    for m in sorted(st.months):
        if m not in allowed["months"]:
            reasons.append(f"month {m} is not in the cited findings")
    for tm in sorted(st.times):
        if not any(a.startswith(tm) for a in at.times) and not any(x.split(" ")[1].startswith(tm) for x in at.datetimes):
            reasons.append(f"time {tm} is not in the cited findings")
    for a in sorted(st.asns):
        if a not in at.asns and f"as{a}" not in allowed["blob"]:
            reasons.append(f"AS{a} is not in the cited findings")
    for lab in sorted(st.labels):
        if lab not in at.labels and lab.lower() not in allowed["blob"]:
            reasons.append(f"source {lab} is not in the cited findings")
    for y in sorted(st.years):
        if y not in allowed["years"] and y not in allowed["blob"]:
            reasons.append(f"year {y} is not in the cited findings")
    for n in st.numbers:
        if not _num_ok(n, allowed["nums"]):
            reasons.append(f"number {n[1]}{'%' if n[2] else ''} is not in the cited findings")
    # names
    words = CAP_RE.finditer(clean)
    first = True
    for m in words:
        w = m.group(0).rstrip(".'’")
        if first and m.start() <= len(clean) - len(clean.lstrip()) + 1:
            first = False
            continue
        first = False
        lw = w.lower()
        if lw in COMMON_CAPS or len(lw) < 3:
            continue
        if lw not in allowed["blob"]:
            reasons.append(f"name '{w}' is not in the cited findings")
    if known_accounts:
        low = clean.lower()
        for acc in known_accounts:
            a = acc.lower()
            if len(a) >= 3 and re.search(r"(?<![\w.@-])" + re.escape(a) + r"(?![\w@-]|\.\w)", low) and a not in allowed["blob"]:
                reasons.append(f"account {acc} is not in the cited findings")
    if st.count() == 0:
        reasons.append("no specific value (number, time, IP, identifier, name) to verify")
    low = " " + clean.lower() + " "
    inf = [m.group(0) for rx in INFERENCE for m in [re.search(rx, " " + clean + " ") if rx.startswith("(?<![A-Za-z])may")
                                                     else re.search(rx, low)] if m]
    char = [w for w in CHARACTERISATION if re.search(r"\b" + re.escape(w) + r"\b", low)]
    if inf:
        flags.append("inference: " + ", ".join(inf))
    if char:
        flags.append("characterisation: " + ", ".join(char))
    ents = [ip for ip in st.ips] + [x.split(":", 1)[1] for x in st.idents]
    if known_accounts:
        ents += [a.lower() for a in known_accounts if re.search(r"(?<![\w.@-])" + re.escape(a.lower()) + r"(?![\w@-])", clean.lower())]
    # relations: every two entities named in the sentence must occur together in ONE row, value set or sentence of a
    # cited finding ("account A used IP X" is not supported by a finding that lists A and X in different places)
    ul = list(dict.fromkeys(e.lower() for e in ents))
    for i in range(len(ul)):
        for j in range(i + 1, len(ul)):
            if not any(_has(ul[i], r) and _has(ul[j], r) for r in allowed["rows"]):
                reasons.append(f"{ul[i]} and {ul[j]} do not appear together in any record of the cited findings")
    # an account-security action ('changed the password', 'disabled 2-step') must be stated with that entity
    for act in ACTION_RE.findall(low):
        stem = act.split()[0][:6]
        if ul and not any(stem in r and any(_has(e, r) for e in ul) for r in allowed["rows"]):
            reasons.append(f"'{act}' is not stated for {', '.join(ul[:3])} in the cited findings")
    # negation: 'never', 'not', 'no' ... only when a cited finding itself says it
    neg = NEG_RE.findall(low)
    if neg and not any(NEG_RE.search(fb.items[c]["blob"]) for c in valid if c in fb.items):
        reasons.append(f"'{neg[0].strip()}' - the cited findings do not state a negative")
    # counts bound to what they count: '4 texts' must be a count of texts in a cited finding
    for mm in COUNT_RE.finditer(clean.lower()):
        num, noun = mm.group(1), mm.group(2)
        if re.search(r"\b(?:about|around|approximately|roughly|nearly|almost|over|more than|less than|fewer than|under|some|at least|at most|up to)\s*$",
                     clean.lower()[max(0, mm.start() - 20):mm.start()]):
            continue          # an approximate count is checked by the number rule above
        n = num.replace(",", "")
        stem = noun.rstrip("s")
        if not any(re.search(r"(?<![\d.])" + re.escape(n) + r"\s+(?:[a-z-]+\s+){0,2}?" + re.escape(stem), r.replace(",", "")) or
                   re.search(r"\b" + re.escape(stem) + r"s?\W{1,3}" + re.escape(n) + r"\b", r.replace(",", ""))
                   for r in allowed["rows"]):
            reasons.append(f"'{num} {noun}' - no cited finding counts {noun} as {num}")
    vals = [d for d in st.datetimes] + [n[1].replace(",", "") for n in st.numbers if not n[4]]
    if ents and len(ents) + len(vals) >= 2 and not reasons:
        need = [e.lower() for e in ents] + [v.lower() for v in vals]
        if not any(all(x in r.replace(",", "") for x in need) for r in allowed["rows"]):
            flags.append("values come from different rows of the cited findings - check that they belong together")
    status = "rejected" if reasons else ("flagged" if flags else "accepted")
    return status, reasons, flags, valid


def items_from_findings(findings: list[dict]) -> list[dict]:
    out = []
    for f in findings:
        facts = f["facts"] if isinstance(f["facts"], dict) else json.loads(f["facts"] or "{}")
        tables = list(facts.get("tables") or [])
        if facts.get("columns"):
            tables.insert(0, {"columns": facts["columns"], "rows": facts.get("rows", [])})
        out.append({"id": f["fid"], "title": f["title"], "statement": f["statement"], "values": facts.get("values"),
                    "tables": tables})
    return out
