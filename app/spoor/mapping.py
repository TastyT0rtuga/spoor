"""Column mapping (header synonyms + value evidence) and event categorisation.

Every mapping decision is recorded with the reason, and is editable per source in the UI."""
from __future__ import annotations

import re
from typing import Iterable

from .identifiers import EMAIL_RE, phone_from_cell
from .ipaddr import split_ip_port
from .timeparse import TsParser, TzSpec

FIELDS = ["ts", "date", "time", "tz", "ip", "port", "account", "action", "status", "user_agent",
          "device", "location", "counterparty", "direction", "amount", "currency",
          # telecom (call detail records and cell-site lists)
          "orig", "term", "duration", "cell", "cell_last", "lat", "lon", "azimuth", "beamwidth",
          "site_name", "imei", "imsi", "enb", "enb_last", "eci", "eci_last", "subject", "dev_lat", "dev_lon", "conf"]
TEL_FIELDS = ("orig", "term", "duration", "cell", "cell_last", "lat", "lon", "azimuth", "beamwidth",
              "site_name", "imei", "imsi", "enb", "enb_last", "eci", "eci_last", "subject", "dev_lat", "dev_lon", "conf")
CELL_ID_FIELDS = ("cell", "cell_last", "enb", "enb_last", "eci", "eci_last")


def is_tel_mapping(m: dict) -> bool:
    """A table is read as telecom records (CDRs, tower dumps, timing advance, pings or a cell-site list) only on
    a telecom-specific signal: originating and terminating numbers, a cell / eNodeB / ECI column, an IMSI, an
    other party with a duration, or the phone a location estimate is about. An IMEI, a session duration or
    coordinates alone (an app's login log) are not enough."""
    loc = (m.get("lat") and m.get("lon")) or (m.get("dev_lat") and m.get("dev_lon"))
    return bool(m.get("orig") or m.get("term") or any(m.get(k) for k in CELL_ID_FIELDS) or m.get("imsi")
                or (m.get("counterparty") and m.get("duration")) or (m.get("subject") and loc))


def is_tower_mapping(m: dict) -> bool:
    """A cell-site (tower) list: cell identities with coordinates, and nothing about calls or phones."""
    has_id = any(m.get(k) for k in ("cell", "enb", "eci"))
    has_loc = bool(m.get("lat") and m.get("lon")) or bool(m.get("eci"))
    calls = any(m.get(k) for k in ("orig", "term", "counterparty", "account", "subject", "duration", "imsi", "imei",
                                    "dev_lat", "dev_lon", "cell_last", "eci_last", "enb_last", "direction"))
    return has_id and has_loc and not calls
FIELD_LABELS = {
    "ts": "Timestamp", "date": "Date (separate column)", "time": "Time (separate column)",
    "tz": "Per-row timezone", "ip": "IP address", "port": "Source port", "account": "Account / user",
    "action": "Event / activity", "status": "Result / status", "user_agent": "User agent",
    "device": "Device / platform", "location": "Provider location", "counterparty": "Counterparty / other party",
    "direction": "Direction", "amount": "Amount", "currency": "Currency / asset",
    "orig": "Originating number (A party)", "term": "Terminating number (B party)",
    "duration": "Call / session duration", "cell": "Cell / sector (first)", "cell_last": "Cell / sector (last)",
    "lat": "Cell site latitude", "lon": "Cell site longitude", "azimuth": "Sector azimuth (degrees)",
    "beamwidth": "Sector beamwidth (degrees)", "site_name": "Cell site name", "imei": "IMEI / device ID",
    "imsi": "IMSI (SIM)", "enb": "eNodeB / LTE site ID (first)", "enb_last": "eNodeB / LTE site ID (last)",
    "eci": "Cell identity: ECI / ECGI / LTE_CI / CGI (first)", "eci_last": "Cell identity: ECI / ECGI (last)",
    "subject": "Phone the record is about (tower dumps, pings)", "dev_lat": "Device location estimate - latitude",
    "dev_lon": "Device location estimate - longitude", "conf": "Location confidence / uncertainty",
}
CATEGORIES = ["login", "login_failed", "logout", "account_change", "registration", "communication",
              "transaction", "other"]

SYN: dict[str, list[str]] = {
    "ts": ["дата", "время", "дата и время", "дата время", "дата события", "timestamp", "time stamp", "datetime", "date time", "date and time", "event time", "login time",
           "logintime", "created at", "createdat", "created", "occurred", "occurred at", "event timestamp",
           "activity time", "access time", "session start", "start time", "time of login", "login timestamp",
           "eventtime", "utc time", "time utc", "timestamp utc", "date time utc", "datetime utc", "logged at",
           "login date", "last login", "connection time", "transaction time", "transaction date", "call time",
           "time", "date"],
    "date": ["date", "event date", "call date", "login date", "day", "transaction date"],
    "time": ["time", "call time", "login time", "event time", "hour"],
    "tz": ["timezone", "time zone", "tz", "utc offset", "offset"],
    "ip": ["ip адрес", "айпи", "ip", "ip address", "ipaddress", "ip addr", "source ip", "src ip", "client ip", "remote ip", "login ip",
           "ipv4", "ipv6", "remote address", "remote addr", "origin ip", "c ip", "cip", "client address",
           "user ip", "ip used", "ip address used", "registration ip", "last ip", "public ip", "ip v4", "ip v6"],
    "port": ["порт", "port", "source port", "src port", "client port", "remote port", "sport", "c port"],
    "account": ["логин", "пользователь", "аккаунт", "учетная запись", "учётная запись", "subscriber id", "subscriberid", "customer number", "account", "account id", "accountid", "user", "username", "user name", "userid", "user id",
                "login", "account name", "subscriber", "customer id", "customer", "target", "account identifier",
                "screen name", "handle", "uid", "member id", "profile", "email address", "account email",
                "user email", "principal", "gaia id", "target account", "account number", "msisdn",
                "target number", "target msisdn", "target mdn", "mdn", "target phone", "subscriber number", "mtn"],
    "action": ["действие", "событие", "тип события", "операция", "action", "activity", "event", "event type", "type", "activity type", "operation",
               "description", "login type", "event name", "event description", "action type", "activity name",
               "record type", "method", "auth type", "call type", "service type", "usage type",
               "event type", "cdr type"],
    "status": ["статус", "результат", "status", "result", "outcome", "success", "login status", "succeeded", "login result", "auth result"],
    "user_agent": ["браузер", "юзер агент", "user agent", "useragent", "ua", "browser", "user agent string", "client", "client info",
                   "cs user agent", "http user agent", "agent"],
    "device": ["устройство", "mac", "mac address", "macaddress", "hardware address", "device", "device id", "device name", "device model", "platform", "os", "operating system",
               "device type", "hardware", "model", "device info", "app version", "client name", "handset", "handset model"],
    "location": ["город", "страна", "местоположение", "location", "city", "region", "country", "geo", "geolocation", "approximate location",
                 "country code", "state"],
    "counterparty": ["получатель", "отправитель", "контрагент", "собеседник", "to", "from", "recipient", "sender", "counterparty", "destination", "dialed", "called",
                     "calling", "other party", "beneficiary", "payee", "payer", "to address", "from address",
                     "destination address", "source address", "originating", "terminating", "called number",
                     "calling number", "to number", "from number", "receiver", "peer", "contact", "other number",
                     "other party number", "other party", "dialed number", "remote number"],
    "direction": ["direction", "call direction", "in out", "inbound outbound", "dir"],
    "amount": ["сумма", "amount", "value", "amount usd", "usd amount", "quantity", "total", "sum", "amt", "debit", "credit"],
    "currency": ["валюта", "currency", "asset", "coin", "ccy", "token", "symbol", "unit"],
    "orig": ["originating number", "originating", "originating party", "calling number", "calling party",
             "calling party number", "a number", "a party", "a party number", "from number", "caller", "orig number",
             "originating msisdn", "calling msisdn", "source number", "cpn", "originatingnumber", "orig address",
             "originating address", "calling nbr"],
    "term": ["terminating number", "terminating", "terminating party", "called number", "called party",
             "called party number", "b number", "b party", "b party number", "to number", "term number",
             "terminating msisdn", "called msisdn", "called", "terminatingnumber", "dest address", "called nbr"],
    "duration": ["duration", "elapsed time", "call duration", "duration sec", "duration secs", "duration seconds",
                 "duration s", "duration min", "duration mins", "duration minutes", "air time", "airtime",
                 "call length", "session duration", "elapsed", "dur", "duration hh mm ss", "et", "sou", "minutes",
                 "conn dur sec", "seizure duration"],
    "cell": ["first cell", "first cell site", "first cell id", "cell", "cell id", "cellid", "cell site", "cell site id",
             "sector id", "sector", "lac ci", "lac cell", "tower id", "first tower", "originating cell", "serving cell",
             "cell tower", "first serving cell", "cell sector", "first sector", "1st lte sector id", "lte sector id",
             "1st sector id", "cell face", "start sector", "sec", "celllocation", "cell location", "init sector",
             "starting cell id", "first serving cell face", "enodeb sector", "enb sector", "sector key"],
    "cell_last": ["last cell", "last cell site", "last cell id", "ending cell", "terminating cell", "last tower",
                  "final cell", "last serving cell", "last sector", "last lte sector id", "end sector"],
    "enb": ["enodeb id", "enodeb", "enb id", "enb", "e g nodeb id", "nodeb id", "1st lte site id", "lte site id",
            "start enodeb", "nodealias", "gnodeb id", "gnodeb", "enodeb number", "starting enb number", "site enodeb"],
    "enb_last": ["last lte site id", "end enodeb"],
    "eci": ["lte ci", "ecgi", "e cgi", "eci", "cgi", "eutrancellfdd", "tower lac cid or ecgi", "lac cid or ecgi",
            "cell global id", "e utran cell id", "start cell", "ncgi", "nci", "cell sector ecgi cellid"],
    "eci_last": ["end cell", "last ecgi", "end ecgi"],
    "subject": ["number associated w tower", "number associated with tower", "phonenumber", "phone number",
                "mobile number", "target phone number", "phone"],
    "lat": ["latitude", "lat", "tower latitude", "site latitude", "cell latitude", "tower lat", "site lat", "lat dd",
            "latitude dd", "e 911 latitude degrees", "ant lat", "antenna latitude", "antenna lat"],
    "lon": ["longitude", "long", "lon", "lng", "tower longitude", "site longitude", "cell longitude", "tower long",
            "tower lon", "site lon", "site long", "long dd", "longitude dd", "e 911 longitude degrees", "ant long", "ant lon",
            "antenna longitude", "antenna long"],
    "dev_lat": ["end latitude", "end lat", "device latitude", "estimated latitude", "location latitude", "ping latitude"],
    "dev_lon": ["end longitude", "end long", "end lon", "device longitude", "estimated longitude", "location longitude",
                "ping longitude"],
    "conf": ["confidence", "conf", "uncertainty", "uncertainty radius", "accuracy", "confidence radius", "error radius",
             "horizontal accuracy"],
    "azimuth": ["azimuth", "azm", "az", "sector azimuth", "orientation", "azimuth deg", "antenna azimuth", "bearing",
                "tower azimuth", "1st tower azimuth", "sector orientation", "ant orientation", "antenna orientation",
                "azimuth degrees"],
    "beamwidth": ["beamwidth", "beam width", "horizontal beamwidth", "hbw", "beam width deg", "antenna beamwidth",
                  "antenna h bw", "horizontal bw", "h bw", "ant beamwidth", "horizontal beamwidth deg"],
    "site_name": ["site name", "tower name", "cell site name", "cell name", "sector name", "site address", "tower address",
                  "1st tower address", "street address"],
    "imei": ["imei", "imeisv", "imei sv", "device imei", "meid", "esn", "imei number", "handset imei",
             "imei associated w tower", "device identifier", "user equip type", "meid esn"],
    "imsi": ["imsi", "subscriber imsi", "sim imsi", "imsi number", "imsi associated w tower"],
}
_NORM_RE = re.compile(r"[^0-9a-z\u0430-\u044f\u0451]+")
_PAREN_RE = re.compile(r"\([^)]*\)|\[[^\]]*\]")


def norm_header(h: str) -> str:
    h = str(h or "").lower()
    h = _PAREN_RE.sub(" ", h)
    h = h.replace("utc", " utc ")
    return _NORM_RE.sub(" ", h).strip()


def header_score(field: str, header: str) -> float:
    n = norm_header(header)
    if not n:
        return 0.0
    syns = SYN.get(field, [])
    if n in syns:
        return 3.0 if n not in ("time", "date", "type", "login", "from", "to", "value", "total", "client") else 2.0
    words = set(n.split())
    best = 0.0
    for s in syns:
        sw = s.split()
        if len(sw) > 1 and s in n:
            best = max(best, 2.0)
        elif len(sw) == 1 and sw[0] in words and len(sw[0]) > 2:
            best = max(best, 1.0)
    if field == "ts" and ({"time", "date", "timestamp"} & words):
        best = max(best, 1.0)
    return best


_TIME_ONLY = re.compile(r"^\d{1,2}:\d{2}(?::\d{2}(?:[.,]\d+)?)?(?:\s*[AaPp]\.?[Mm]\.?)?(?:\s*[A-Za-z]{1,5}|\s*[+-]\d{2}:?\d{2})?$")
_NUMERIC = re.compile(r"^[-+]?\(?\s?[$€£¥]?\s?\d[\d.,' ]*\)?\s?[$€£¥]?$")
_UA = re.compile(r"Mozilla/|AppleWebKit|Dalvik/|CFNetwork|okhttp|Windows NT|Android \d|iPhone OS|Darwin/", re.I)
_DECIMAL = re.compile(r"^[-+]?\d{1,3}(?:\.\d+)?$")
_NULLISH = {"n/a", "na", "null", "none", "-", "--", "nan", "(null)", "#n/a", "0"}
_MIDNIGHT_RE = re.compile(r"(?:^|\D)\d{4}-\d\d-\d\d(?:[ T]00:00(?::00(?:\.0+)?)?)?$|^\d{1,2}/\d{1,2}/\d{2,4}(?: 0?0:00(?::00)?(?: ?AM)?)?$")
_STATUS_WORDS = re.compile(r"^(?:success\w*|succeeded|ok|true|false|fail\w*|denied|rejected|invalid|error|blocked|"
                           r"allowed|accepted|approved|declined|completed|pending|yes|no|pass|passed)$", re.I)


def _share(e: dict, k: str) -> float:
    """Share of the non-null values ('NULL', 'N/A', ...) that show evidence k."""
    nn = 1.0 - e.get("nullish", 0)
    return e.get(k, 0) / nn if nn > 0.05 else 0.0


def value_evidence(values: list) -> dict[str, float]:
    """Fraction of sample values that look like each kind of data."""
    vals = [v for v in values if v not in (None, "")][:200]
    if not vals:
        return {}
    n = len(vals)
    p = TsParser(TzSpec("UTC", assumed=True), column_mode=False)
    p2 = TsParser(TzSpec("UTC", assumed=True), date_order="DMY", column_mode=False)
    pe = TsParser(TzSpec("UTC", assumed=True), column_mode=True)
    ev = {k: 0.0 for k in ("ip", "ts", "ts_epoch", "date_only", "time_only", "ua", "email", "numeric",
                          "status", "port", "ip_port", "phone", "lat", "lon", "deg", "nullish", "midnight")}
    for v in vals:
        s = str(v).strip()
        if s.lower() in _NULLISH:
            ev["nullish"] += 1
        if hasattr(v, "hour") and hasattr(v, "year") and (v.hour, v.minute, v.second) == (0, 0, 0):
            ev["midnight"] += 1
        elif _MIDNIGHT_RE.search(s):
            ev["midnight"] += 1
        sp = split_ip_port(s) if len(s) <= 60 else None
        if sp:
            ev["ip"] += 1
            if sp[2]:
                ev["ip_port"] += 1
        r = p.parse(v)
        if r is None:
            r = p2.parse(v)
        if r is not None:
            if "date_only" in r.flags:
                ev["date_only"] += 1
            else:
                ev["ts"] += 1
        elif pe.parse(v) is not None:
            ev["ts_epoch"] += 1
        if _TIME_ONLY.match(s):
            ev["time_only"] += 1
        if _UA.search(s):
            ev["ua"] += 1
        if EMAIL_RE.fullmatch(s):
            ev["email"] += 1
        if _NUMERIC.match(s):
            ev["numeric"] += 1
            if s.isdigit() and 0 < int(s) < 65536:
                ev["port"] += 1
        if _STATUS_WORDS.match(s):
            ev["status"] += 1
        if phone_from_cell(s):
            ev["phone"] += 1
        sd = s[1:] if s.startswith("'") else s       # Excel text-forcing apostrophe ('-104.6)
        if _DECIMAL.match(sd):
            x = float(sd)
            if abs(x) <= 90 and "." in sd:
                ev["lat"] += 1
            if abs(x) <= 180 and "." in sd:
                ev["lon"] += 1
            if 0 <= x <= 360:
                ev["deg"] += 1
    return {k: v / n for k, v in ev.items()}


def propose_mapping(headers: list[str], samples: dict[str, list]) -> tuple[dict, list[str]]:
    """Return ({field: header}, notes). Deterministic; the analyst can override every choice."""
    ev = {h: value_evidence(samples.get(h, [])) for h in headers}
    scores: dict[str, dict[str, float]] = {f: {} for f in FIELDS}
    for h in headers:
        e = ev[h]
        for f in FIELDS:
            s = header_score(f, h)
            if f == "ip":
                s = s + 4 * e.get("ip", 0) if e.get("ip", 0) >= 0.5 else (s if e.get("ip", 0) > 0 else s * 0.3)
            elif f == "ts":
                tsf = e.get("ts", 0)
                if tsf >= 0.5:
                    s = s + 3 + tsf
                elif s >= 1 and e.get("ts_epoch", 0) >= 0.8:
                    s = s + 3
                else:
                    s = 0 if tsf == 0 else s * tsf
            elif f == "date":
                s = s + 2 if e.get("date_only", 0) >= 0.8 else 0
            elif f == "time":
                s = s + 2 if e.get("time_only", 0) >= 0.8 else 0
            elif f == "user_agent":
                s = s + 3 * e.get("ua", 0) if e.get("ua", 0) >= 0.3 else s * 0.5
            elif f == "port":
                s = s if e.get("port", 0) >= 0.8 else 0
            elif f == "account":
                if e.get("ip", 0) > 0.5 or e.get("ts", 0) > 0.5:
                    s = 0
                elif e.get("email", 0) >= 0.8 and s:
                    s += 1
            elif f == "status":
                s = s + 1 if e.get("status", 0) >= 0.8 else (s if e.get("status", 0) > 0.3 else s * 0.3)
            elif f == "amount":
                s = s if e.get("numeric", 0) >= 0.8 else 0
            elif f in ("action", "device", "location", "counterparty", "direction", "currency", "tz",
                       "orig", "term", "duration", "imei", "imsi", "site_name", "subject", "conf"):
                if e.get("ip", 0) > 0.5 or e.get("ts", 0) > 0.5:
                    s = 0
                if f in ("orig", "term", "subject", "imei", "imsi") and e.get("nullish", 0) >= 0.95:
                    s = 0
            elif f in ("enb", "enb_last", "eci", "eci_last"):
                if e.get("ip", 0) > 0.5 or e.get("ts", 0) > 0.5 or e.get("nullish", 0) >= 0.95:
                    s = 0
            elif f in ("dev_lat", "dev_lon"):
                s = s if _share(e, f[4:]) >= 0.8 else 0
            elif f in ("cell", "cell_last"):
                if e.get("ip", 0) > 0.5 or e.get("ts", 0) > 0.5 or e.get("phone", 0) >= 0.8 or e.get("email", 0) > 0.5:
                    s = 0       # a column named 'Cell' holding phone numbers is a mobile number, not a cell site
                elif e.get("nullish", 0) >= 0.95:
                    s = 0       # a cell column that is 'N/A' on every row (the cell is in another column)
            elif f in ("lat", "lon"):
                s = s if _share(e, f) >= 0.8 else 0
            elif f in ("azimuth", "beamwidth"):
                s = s if _share(e, "deg") >= 0.8 else 0
            scores[f][h] = s
    mapping: dict[str, str] = {}
    notes: list[str] = []
    used: set[str] = set()
    order = ["ip", "ts", "date", "time", "user_agent", "orig", "term", "subject", "account", "action", "status", "port",
             "eci_last", "eci", "enb_last", "enb", "cell_last", "cell", "dev_lat", "dev_lon", "lat", "lon", "azimuth",
             "beamwidth", "site_name", "duration", "imei", "imsi", "conf", "counterparty", "amount", "currency", "device",
             "location", "direction", "tz"]
    for f in order:
        cands = sorted(((s, h) for h, s in scores[f].items() if h not in used and s >= 1.5),
                       key=lambda t: (-t[0], headers.index(t[1])))
        if not cands:
            continue
        s, h = cands[0]
        if f in ("date", "time") and "ts" in mapping:
            continue
        mapping[f] = h
        used.add(h)
        e = ev[h]
        why = []
        hs = header_score(f, h)
        if hs >= 2:
            why.append("header name")
        elif hs >= 1:
            why.append("header word")
        if f == "ip":
            why.append(f"{e.get('ip', 0):.0%} of sample values are IP addresses")
        if f == "ts":
            if e.get("ts", 0):
                why.append(f"{e.get('ts', 0):.0%} of sample values parse as timestamps")
            elif e.get("ts_epoch", 0):
                why.append(f"{e.get('ts_epoch', 0):.0%} of sample values are epoch numbers")
        if f == "user_agent" and e.get("ua"):
            why.append(f"{e.get('ua', 0):.0%} of sample values look like user-agent strings")
        notes.append(f"{f} = column '{h}' ({'; '.join(why) or 'best match'})")
    if ("orig" in mapping) != ("term" in mapping):
        # one of the pair alone is just 'the other party' (the target is the other end)
        f = "orig" if "orig" in mapping else "term"
        h = mapping.pop(f)
        notes = [n for n in notes if not n.startswith(f + " = ")]
        if "counterparty" not in mapping:
            mapping["counterparty"] = h
            notes.append(f"counterparty = column '{h}' (only one of originating/terminating present)")
    if ("lat" in mapping) != ("lon" in mapping):
        f = "lat" if "lat" in mapping else "lon"
        mapping.pop(f)
        notes = [n for n in notes if not n.startswith(f + " = ")]
        notes.append(f"{f} column ignored: latitude and longitude must both be present")
    if not is_tel_mapping(mapping):
        # not a telecom table: read it exactly as before telecom support existed
        for f in ("duration", "lat", "lon", "azimuth", "beamwidth", "site_name", "imei", "subject", "dev_lat",
                  "dev_lon", "conf"):
            h = mapping.pop(f, None)
            if h is None:
                continue
            notes = [n for n in notes if not n.startswith(f + " = ")]
            if f == "imei" and "device" not in mapping:
                mapping["device"] = h
                notes.append(f"device = column '{h}' (header name)")
    if is_tel_mapping(mapping):
        notes = _telecom_post(mapping, notes, headers, ev, samples)
    notes = split_date_time(mapping, notes, headers, ev)
    if "ts" not in mapping and ("date" in mapping) != ("time" in mapping):
        # a lone date column is still a (date-only) timestamp
        if "date" in mapping:
            mapping["ts"] = mapping.pop("date")
            notes = [n for n in notes if not n.startswith("date = ")]
            notes.append(f"ts = column '{mapping['ts']}' (date-only column; hour-of-day analysis will exclude it)")
        else:
            mapping.pop("time")
    if "ts" not in mapping and "date" not in mapping:
        notes.append("no timestamp column found - rows will have no time (temporal analysis skips them)")
    if "ip" not in mapping:
        notes.append("no IP column found - IPs are still extracted from every cell as identifiers")
    return mapping, notes


def _drop(mapping: dict, notes: list, fields, why: str) -> list:
    for f in fields:
        if f in mapping:
            h = mapping.pop(f)
            notes = [n for n in notes if not n.startswith(f + " = ")]
            notes.append(f"{f}: column '{h}' not used ({why})")
    return notes


def _telecom_post(mapping: dict, notes: list, headers: list, ev: dict, samples: dict) -> list:
    """Telecom-only adjustments (other tables are never affected)."""
    used = set(mapping.values())
    if is_tower_mapping(mapping):
        notes = _drop(mapping, notes, ("ts", "date", "time", "tz", "action", "status", "amount", "currency", "ip", "port"),
                      "a cell-site list: its dates describe the list, not events")
        notes.append("read as a cell-site (tower) list")
        return notes
    # location estimates (pings, timing advance) are positions of the device, not of a cell site
    calls = any(mapping.get(k) for k in ("orig", "term", "counterparty", "duration"))
    if mapping.get("lat") and mapping.get("lon") and not any(mapping.get(k) for k in CELL_ID_FIELDS) \
            and not mapping.get("dev_lat") and not calls:
        mapping["dev_lat"], mapping["dev_lon"] = mapping.pop("lat"), mapping.pop("lon")
        notes = [n for n in notes if not n.startswith(("lat = ", "lon = "))]
        notes.append(f"dev_lat/dev_lon = columns '{mapping['dev_lat']}'/'{mapping['dev_lon']}' (no cell column: "
                     "the coordinates are a location estimate for the device, not a cell site)")
    # carriers that give the time twice (local and GMT/UTC): use the UTC one
    ts = mapping.get("ts")
    if ts and not re.search(r"gmt|utc|zulu", ts, re.I):
        for h in headers:
            if h not in used and re.search(r"gmt|utc|zulu", h, re.I) and ev.get(h, {}).get("ts", 0) >= 0.8:
                mapping["ts"] = h
                notes = [n for n in notes if not n.startswith("ts = ")]
                notes.append(f"ts = column '{h}' (the carrier also gives '{ts}'; the column labelled UTC/GMT is used)")
                break
    return notes


def split_date_time(mapping: dict, notes: list, headers: list, ev: dict) -> list:
    """A timestamp column that is midnight on every row, next to a column named 'time': the date comes from the
    first and the time of day from the second (some carriers' spreadsheets store the time with a dummy date)."""
    ts = mapping.get("ts")
    if not ts or ev.get(ts, {}).get("midnight", 0) < 0.95:
        return notes
    used = set(mapping.values())
    for h in headers:
        if h in used or h == ts:
            continue
        words = set(norm_header(h).split()) | set(re.sub(r"[^a-z]+", " ", str(h).lower()).split())
        e = ev.get(h, {})
        if "time" in words and "date" not in words and (e.get("time_only", 0) >= 0.8 or
                                                        (e.get("ts", 0) >= 0.8 and e.get("midnight", 0) < 0.5)):
            mapping["date"], mapping["time"] = mapping.pop("ts"), h
            notes = [n for n in notes if not n.startswith("ts = ")]
            notes.append(f"date = column '{ts}' and time = column '{h}' ('{ts}' is midnight on every row; the time of day "
                         f"is taken from '{h}')")
            break
    return notes


_FN_PHONE = re.compile(r"(?<!\d)(\+?1?[2-9]\d{2}[2-9]\d{6})(?!\d)")
_FN_IMSI = re.compile(r"(?i)timingadvance_+(\d{14,15})(?!\d)")


def target_from_filename(name: str) -> tuple:
    """Carriers name call-record files after the target: 'CDR_Mediations_<number>_<id>.xls',
    'CellSites-CDR_..._<number>_<dates>.csv', '<case>_CXM_HDA_volte_<number>_<dates>.xlsx' - and timing-advance
    reports after the IMSI ('TimingAdvance_<IMSI>_<dates>'). Used only for a telecom file that names no target
    in its preamble or columns, and only when the name holds exactly one such number."""
    m = _FN_IMSI.search(name)
    if m:
        return m.group(1), f"file name '{name}' (timing-advance reports are named after the IMSI) - VERIFY"
    nums = {x for x in _FN_PHONE.findall(name.replace(" ", "_"))}
    norm = {phone_from_cell(x) for x in nums} - {None}
    if len(norm) == 1:
        return norm.pop(), f"file name '{name}' (carriers name call-record files after the target number) - VERIFY"
    return None, ""


# ---------------------------------------------------------------- categorisation

_W = r"(?:^|[^a-z0-9])"
_E = r"(?:$|[^a-z0-9])"
RE_LOGOUT = re.compile(_W + r"(?:log ?out|logged out|log ?off|logged off|sign ?out|signed out|session (?:end|ended|terminated|expired|closed)|выход\w*)" + _E)
RE_LOGIN = re.compile(_W + r"(?:log ?in|logged in|log ?on|logon|sign ?in|signed in|authenticat\w*|session (?:start|started|created|begin|opened)|web login|reauth\w*|access granted|вход\w*|авторизац\w*)" + _E)
RE_FAIL = re.compile(_W + r"(?:fail\w*|invalid|incorrect|denied|unsuccessful|wrong|bad password|rejected|blocked|error|locked out|not authorized|unauthori[sz]ed|неудач\w*|ошибк\w*|неверн\w*|отказ\w*)" + _E)
RE_REG = re.compile(_W + r"(?:sign ?up|signup|regist(?:er|ered|ration)|account (?:created|creation|opened)|created account|new account|account open\w*|регистрац\w*)" + _E)
RE_CHANGE = re.compile(_W + r"(?:password|passcode|pin change|2fa|two ?factor|2 step|two step|mfa|multi ?factor|authenticator|recovery|reset|"
                       r"security (?:question|key|setting|settings|info)|api key|whitelist|allowlist|withdrawal address|"
                       r"(?:email|e mail|phone|mobile|number|name|username|address|device|recovery|backup) (?:change|changed|update|updated|added|removed|verified)|"
                       r"(?:change|changed|update|updated|add|added|remove|removed) (?:email|e mail|phone|mobile|password|recovery|address|name|username|device|2fa|mfa)|"
                       r"account (?:recovery|update|updated|deactivat\w*|reactivat\w*|delet\w*|disabled|enabled|locked|unlocked|suspend\w*|restor\w*)|парол\w*|смена\w*)" + _E)
RE_COMM = re.compile(_W + r"(?:call|calls|called|voice|sms|mms|text message|message|messages|messaged|chat|direct message|dm|voicemail|dialed|"
                     r"mo call|mt call|moc|mtc|incoming call|outgoing call|missed call)" + _E)
# extra call-record wording, applied only to tables read as telecom records
RE_COMM_TEL = re.compile(_W + r"(?:text|texts|txt|sms mo|sms mt|volte|vowifi)" + _E)
RE_TXN = re.compile(_W + r"(?:deposit\w*|withdraw\w*|transfer\w*|payment\w*|purchase\w*|trade|traded|trades|buy|bought|sell|sold|"
                    r"send|sent|receive|received|transaction\w*|charge\w*|refund\w*|wire|ach|zelle|payout\w*|swap\w*|convert\w*)" + _E)
SUCCESS_WORDS = {"success", "successful", "succeeded", "ok", "true", "pass", "passed", "allowed", "accepted",
                 "approved", "completed", "complete", "yes", "y", "granted"}
FAIL_WORDS = {"fail", "failed", "failure", "false", "denied", "rejected", "invalid", "error", "blocked",
              "unsuccessful", "no", "n", "declined", "locked"}


_CLEAN_RE = re.compile(r"[_\-/.:]+")


def _clean(s) -> str:
    return _CLEAN_RE.sub(" ", str(s or "").lower())


def normalize_status(v) -> str:
    s = _clean(v).strip()
    if not s:
        return ""
    if s in SUCCESS_WORDS or s.startswith("success"):
        return "success"
    if s in FAIL_WORDS or s.startswith("fail") or RE_FAIL.search(s):
        return "failure"
    return ""


def categorize(action, status: str, default: str | None, telecom: bool = False) -> str:
    a = _clean(action)
    st = status or ""
    if a and telecom and RE_COMM_TEL.search(a) and not (RE_LOGIN.search(a) or RE_LOGOUT.search(a) or RE_CHANGE.search(a)):
        return "communication"
    if a:
        if RE_LOGOUT.search(a):
            return "logout"
        if RE_LOGIN.search(a):
            return "login_failed" if (st == "failure" or RE_FAIL.search(a)) else "login"
        if RE_REG.search(a):
            return "registration"
        if RE_CHANGE.search(a):
            return "account_change"
        if RE_COMM.search(a):
            return "communication"
        if RE_TXN.search(a):
            return "transaction"
        if default == "login" and (st == "failure" or RE_FAIL.search(a)):
            return "login_failed"
        return default if default and default != "login" else "other"
    if default == "login":
        return "login_failed" if st == "failure" else "login"
    return default or "other"


def suggest_default_category(texts: Iterable[tuple[str, str]]) -> tuple[str | None, str]:
    """From file name / preamble / sheet names guess what every row is (only used when rows say nothing)."""
    for cite, t in texts:
        lt = _clean(t)
        if re.search(r"(?:log ?ins?|sign ?ins?|logon|ip activity|ip log|ip address log|access log|sessions?|authentication)", lt):
            return "login", f"'{t.strip()[:60]}' ({cite})"
        if re.search(r"(?:call detail|cdr|call log|sms|messages)", lt):
            return "communication", f"'{t.strip()[:60]}' ({cite})"
        if re.search(r"(?:transactions?|transfers?|payments?|deposits?|withdrawals?|ledger|statement)", lt):
            return "transaction", f"'{t.strip()[:60]}' ({cite})"
    return None, ""


def apply_status(status_val, action_val) -> str:
    s = normalize_status(status_val)
    if not s and action_val:
        a = _clean(action_val)
        if RE_FAIL.search(a):
            s = "failure"
    return s


def default_account_from(texts: list[tuple[str, str]]) -> tuple[str | None, str]:
    """An account named in a return's preamble ('Account: x@y.com', 'Target: 12345').

    Values containing spaces (a person's name, an address) are not treated as account identifiers."""
    lab = re.compile(r"(?:^|\b)(?:account|target|subscriber|user ?name|user|e-?mail|account id|uid|screen name|handle|login|"
                     r"логин|аккаунт|пользователь)\s*(?:identifier|id|name)?\s*[:=#]\s*(.+)$", re.I)
    # telecom returns name the target number ("Target Number: 7035550101", "MSISDN: ...")
    tel_lab = re.compile(r"(?:^|\b)(?:target\s*(?:number|no\.?|phone|phone number|telephone number|msisdn|mdn)|msisdn|mdn|"
                         r"(?:voice|data|sms|text|messaging)\s+usage\s+for)\s*[:=#]\s*(.+)$", re.I)
    for cite, t in texts:
        mt = tel_lab.search(t.strip())
        if mt:
            raw = mt.group(1).strip().split("  ")[0].strip()
            ph = phone_from_cell(raw.replace(" ", ""))
            if ph:
                return ph, f"'{t.strip()[:80]}' ({cite})"
        m = lab.search(t.strip()) or mt
        if m:
            v = re.split(r"[,;|()\[\]<>]", m.group(1).strip())[0].strip().strip("'\"")
            if v and " " not in v and len(v) >= 3:
                return v, f"'{t.strip()[:80]}' ({cite})"
    for cite, t in texts:
        m = EMAIL_RE.search(t)
        if m:
            return m.group(1), f"'{t.strip()[:80]}' ({cite})"
    return None, ""
