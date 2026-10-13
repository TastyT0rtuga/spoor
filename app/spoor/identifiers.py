"""Identifier extraction with validation, so the inventory holds real identifiers, not look-alikes.

Validity values
  checksum  - verified by the identifier's own checksum (Base58Check, Bech32/Bech32m, EIP-55, Luhn)
  format    - matches the identifier's format; that format has no checksum to verify
  bad_checksum - looks like the identifier but the checksum fails (kept only where informative)
"""
from __future__ import annotations

import hashlib
import re
from typing import Iterable

from .ipaddr import find_ips

EMAIL_RE = re.compile(r"(?<![\w.+-])([A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,24})(?![\w-])")
PHONE_INTL_RE = re.compile(r"(?<![\w+])\+(\d[\d ().-]{6,20}\d)(?!\d)")
PHONE_NANP_RE = re.compile(
    r"(?<![\w+])(?:1[ .-]?)?(?:\(([2-9]\d{2})\)\s?|([2-9]\d{2})[ .-])([2-9]\d{2})[ .-]?(\d{4})(?![\d-])")
PHONE_BARE_RE = re.compile(r"^\+?1?([2-9]\d{2})([2-9]\d{2})(\d{4})$")
MAC_RE = re.compile(r"(?<![0-9A-Fa-f:.-])([0-9A-Fa-f]{2}(?:([:-])[0-9A-Fa-f]{2})(?:\2[0-9A-Fa-f]{2}){4})(?![0-9A-Fa-f:-])"
                    r"|(?<![0-9A-Fa-f.])([0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4})(?![0-9A-Fa-f.])")
IMEI_RE = re.compile(r"(?<!\d)(\d{2}[ -]?\d{6}[ -]?\d{6}[ -]?\d)(?!\d)")
URL_RE = re.compile(r"\bhttps?://[^\s\"'<>|]{3,500}", re.I)
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B58_IDX = {c: i for i, c in enumerate(B58)}
BTC_B58_RE = re.compile(r"(?<![0-9A-Za-z])([13LMD9A][1-9A-HJ-NP-Za-km-z]{25,34})(?![0-9A-Za-z])")
TRX_RE = re.compile(r"(?<![0-9A-Za-z])(T[1-9A-HJ-NP-Za-km-z]{33})(?![0-9A-Za-z])")
BECH32_RE = re.compile(r"(?<![0-9A-Za-z])((?:bc|ltc)1[ac-hj-np-z02-9]{8,87}|(?:BC|LTC)1[AC-HJ-NP-Z02-9]{8,87})(?![0-9A-Za-z])")
ETH_RE = re.compile(r"(?<![0-9A-Za-z])(0x[0-9A-Fa-f]{40})(?![0-9A-Za-z])")
XMR_RE = re.compile(r"(?<![0-9A-Za-z])([48][1-9A-HJ-NP-Za-km-z]{94})(?![0-9A-Za-z])")

KIND_LABELS = {
    "ipv4": "IPv4 address", "ipv6": "IPv6 address", "email": "email address", "phone": "phone number",
    "btc": "Bitcoin address", "ltc": "Litecoin address", "doge": "Dogecoin address",
    "trx": "TRON address", "eth": "Ethereum/EVM address", "xmr": "Monero address",
    "mac": "MAC address", "imei": "IMEI", "imsi": "IMSI", "url": "URL",
}


# ---------------------------------------------------------------- checksums

def b58decode(s: str) -> bytes | None:
    n = 0
    for c in s:
        i = B58_IDX.get(c)
        if i is None:
            return None
        n = n * 58 + i
    full = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + full


def b58check(s: str) -> bytes | None:
    raw = b58decode(s)
    if raw is None or len(raw) < 5:
        return None
    body, chk = raw[:-4], raw[-4:]
    if hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4] != chk:
        return None
    return body


_BECH32_CHARS = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _polymod(values: Iterable[int]) -> int:
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= gen[i] if ((b >> i) & 1) else 0
    return chk


def segwit_valid(addr: str) -> bool:
    if addr.lower() != addr and addr.upper() != addr:
        return False
    a = addr.lower()
    pos = a.rfind("1")
    hrp, data = a[:pos], a[pos + 1:]
    if hrp not in ("bc", "ltc") or len(data) < 6:
        return False
    try:
        d = [_BECH32_CHARS.index(c) for c in data]
    except ValueError:
        return False
    pm = _polymod([ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp] + d)
    if pm not in (1, 0x2BC830A3):
        return False
    ver = d[0]
    if ver > 16:
        return False
    # convert 5-bit groups to bytes
    acc = bits = 0
    prog = []
    for v in d[1:-6]:
        acc = (acc << 5) | v
        bits += 5
        while bits >= 8:
            bits -= 8
            prog.append((acc >> bits) & 0xFF)
    if bits >= 5 or ((acc << (8 - bits)) & 0xFF if bits else 0):
        return False
    if not (2 <= len(prog) <= 40):
        return False
    if ver == 0:
        return pm == 1 and len(prog) in (20, 32)
    return pm == 0x2BC830A3


_RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
       0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
       0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
       0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
       0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
       0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
_ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56],
        [27, 20, 39, 8, 14]]
_M64 = (1 << 64) - 1


def _rol(v: int, n: int) -> int:
    return ((v << n) | (v >> (64 - n))) & _M64 if n else v


def keccak256(data: bytes) -> bytes:
    """Original Keccak-256 (as used by Ethereum), not NIST SHA3-256."""
    rate = 136
    msg = bytearray(data) + b"\x01"
    while len(msg) % rate:
        msg.append(0)
    msg[-1] |= 0x80
    st = [[0] * 5 for _ in range(5)]
    for off in range(0, len(msg), rate):
        block = msg[off: off + rate]
        for i in range(rate // 8):
            x, y = i % 5, i // 5
            st[x][y] ^= int.from_bytes(block[i * 8: i * 8 + 8], "little")
        for rc in _RC:
            c = [st[x][0] ^ st[x][1] ^ st[x][2] ^ st[x][3] ^ st[x][4] for x in range(5)]
            d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
            st = [[st[x][y] ^ d[x] for y in range(5)] for x in range(5)]
            b = [[0] * 5 for _ in range(5)]
            for x in range(5):
                for y in range(5):
                    b[y][(2 * x + 3 * y) % 5] = _rol(st[x][y], _ROT[x][y])
            st = [[b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y]) for y in range(5)] for x in range(5)]
            st[0][0] ^= rc
    out = b""
    for i in range(4):
        out += st[i % 5][i // 5].to_bytes(8, "little")
    return out


def eip55_status(addr: str) -> str:
    h = addr[2:]
    if h == h.lower() or h == h.upper():
        return "format"
    digest = keccak256(h.lower().encode("ascii")).hex()
    for ch, hv in zip(h, digest):
        if ch.isalpha() and (ch.isupper() != (int(hv, 16) >= 8)):
            return "bad_checksum"
    return "checksum"


def luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


B58_VERSIONS = {0x00: "btc", 0x05: "btc", 0x30: "ltc", 0x32: "ltc", 0x1E: "doge", 0x16: "doge"}


def classify_b58(s: str) -> tuple[str, str] | None:
    body = b58check(s)
    if body is None or len(body) != 21:
        return None
    kind = B58_VERSIONS.get(body[0])
    if kind is None:
        return None
    return kind, "checksum"


# ---------------------------------------------------------------- phones

def norm_phone_digits(d: str) -> str | None:
    d = re.sub(r"\D", "", d)
    if len(d) == 10 and d[0] in "23456789" and d[3] in "23456789":
        return "+1" + d
    if len(d) == 11 and d[0] == "1" and d[1] in "23456789" and d[4] in "23456789":
        return "+" + d
    return None


def phone_from_cell(v: str) -> str | None:
    """A cell already known to be a phone column: accept bare digits too."""
    s = str(v).strip()
    if not s:
        return None
    if s.startswith("+"):
        d = re.sub(r"\D", "", s)
        if d.startswith("1"):
            return norm_phone_digits(d)
        return "+" + d if 8 <= len(d) <= 15 else None
    return norm_phone_digits(s) if re.fullmatch(r"[\d ().+-]{10,20}", s) else None


# ---------------------------------------------------------------- extraction

def extract(text: str, imei_context: bool = False, with_ips: bool = True) -> list[tuple[str, str, str, str]]:
    """Return [(kind, raw, normalised, validity)] for every identifier found in text."""
    out: list[tuple[str, str, str, str]] = []
    if not text:
        return out
    seen = set()

    def add(kind, raw, norm, val):
        k = (kind, norm)
        if k not in seen:
            seen.add(k)
            out.append((kind, raw, norm, val))

    if with_ips:
        for ip, ver, _port, s, e in find_ips(text):
            add("ipv4" if ver == 4 else "ipv6", text[s:e], ip, "format")
    if "@" in text:
        for m in EMAIL_RE.finditer(text):
            raw = m.group(1)
            local, _, dom = raw.rpartition("@")
            if dom.lower().endswith((".png", ".jpg", ".gif", ".css", ".js")):
                continue
            add("email", raw, local.lower() + "@" + dom.lower(), "format")
    if "+" in text:
        for m in PHONE_INTL_RE.finditer(text):
            d = re.sub(r"\D", "", m.group(1))
            if d.startswith("1"):
                n = norm_phone_digits(d)
                if n:
                    add("phone", m.group(0), n, "format")
            elif 8 <= len(d) <= 15:
                add("phone", m.group(0), "+" + d, "format")
    if any(c.isdigit() for c in text):
        for m in PHONE_NANP_RE.finditer(text):
            area = m.group(1) or m.group(2)
            n = norm_phone_digits(area + m.group(3) + m.group(4))
            if n:
                add("phone", m.group(0).strip(), n, "format")
    for m in BTC_B58_RE.finditer(text):
        r = classify_b58(m.group(1))
        if r:
            add(r[0], m.group(1), m.group(1), r[1])
    if "T" in text:
        for m in TRX_RE.finditer(text):
            body = b58check(m.group(1))
            if body is not None and len(body) == 21 and body[0] == 0x41:
                add("trx", m.group(1), m.group(1), "checksum")
    if "1" in text:
        for m in BECH32_RE.finditer(text):
            a = m.group(1)
            if segwit_valid(a):
                add("ltc" if a.lower().startswith("ltc") else "btc", a, a.lower(), "checksum")
    if "0x" in text or "0X" in text:
        for m in ETH_RE.finditer(text):
            a = m.group(1)
            add("eth", a, "0x" + a[2:].lower(), eip55_status(a))
    if len(text) >= 95:
        for m in XMR_RE.finditer(text):
            if b58decode(m.group(1)) is not None:
                add("xmr", m.group(1), m.group(1), "format")
    if ":" in text or "-" in text or "." in text:
        for m in MAC_RE.finditer(text):
            raw = m.group(1) or m.group(3)
            hexs = re.sub(r"[^0-9A-Fa-f]", "", raw).lower()
            if hexs in ("000000000000", "ffffffffffff"):
                continue
            add("mac", raw, ":".join(hexs[i:i + 2] for i in range(0, 12, 2)), "format")
    if imei_context or "imei" in text.lower():
        for m in IMEI_RE.finditer(text):
            d = re.sub(r"\D", "", m.group(1))
            if len(d) == 15 and luhn_ok(d):
                add("imei", m.group(1), d, "checksum")
    if "http" in text.lower():
        for m in URL_RE.finditer(text):
            u = m.group(0).rstrip(".,;)]}")
            add("url", u, u, "format")
    return out
