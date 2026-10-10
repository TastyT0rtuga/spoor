"""IP address extraction, normalisation and classification (no network access)."""
from __future__ import annotations

import ipaddress
import re
from functools import lru_cache
from typing import Optional

IPV4_RE = re.compile(r"(?<![\w.])((?:\d{1,3}\.){3}\d{1,3})(?::(\d{1,5}))?(?!\w|\.\d)")
IPV6_BRACKET_RE = re.compile(r"\[([0-9A-Fa-f:.]+(?:%[\w.]+)?)\](?::(\d{1,5}))?")
IPV6_RE = re.compile(r"(?<![\w:.])((?:[0-9A-Fa-f]{0,4}:){2,7}(?:(?:\d{1,3}\.){3}\d{1,3}|[0-9A-Fa-f]{0,4}))(?:%[\w.]+)?(?![\w:]|\.\d)")

_V4_NETS = [
    ("loopback", "127.0.0.0/8"), ("private", "10.0.0.0/8"), ("private", "172.16.0.0/12"),
    ("private", "192.168.0.0/16"), ("cgnat", "100.64.0.0/10"), ("link-local", "169.254.0.0/16"),
    ("multicast", "224.0.0.0/4"), ("documentation", "192.0.2.0/24"),
    ("documentation", "198.51.100.0/24"), ("documentation", "203.0.113.0/24"),
    ("reserved", "0.0.0.0/8"), ("reserved", "240.0.0.0/4"), ("reserved", "192.0.0.0/24"),
    ("reserved", "198.18.0.0/15"),
]
_V6_NETS = [
    ("loopback", "::1/128"), ("reserved", "::/128"), ("private", "fc00::/7"),
    ("link-local", "fe80::/10"), ("multicast", "ff00::/8"), ("documentation", "2001:db8::/32"),
    ("nat64", "64:ff9b::/96"), ("reserved", "100::/64"),
]
V4_NETS = [(c, ipaddress.ip_network(n)) for c, n in _V4_NETS]
V6_NETS = [(c, ipaddress.ip_network(n)) for c, n in _V6_NETS]

CLASS_NOTES = {
    "public": "globally routable",
    "private": "RFC 1918 / RFC 4193 private space - not attributable outside the network that issued it",
    "cgnat": "RFC 6598 carrier-grade NAT shared space (100.64.0.0/10)",
    "loopback": "loopback",
    "link-local": "link-local",
    "multicast": "multicast",
    "documentation": "RFC 5737 / RFC 3849 documentation range (not used on the Internet)",
    "reserved": "reserved / special-purpose",
    "nat64": "NAT64 well-known prefix (embeds an IPv4 address)",
}


@lru_cache(maxsize=65536)
def normalize_ip(s: str) -> Optional[tuple[str, int]]:
    """'010.001.002.003' -> ('10.1.2.3', 4); '::ffff:1.2.3.4' -> ('1.2.3.4', 4)."""
    if not s:
        return None
    s = s.strip().strip("[]")
    if "%" in s:
        s = s.split("%", 1)[0]
    if ":" not in s:
        parts = s.split(".")
        if len(parts) != 4:
            return None
        try:
            nums = [int(p) for p in parts]
        except ValueError:
            return None
        if any(n > 255 or n < 0 for n in nums) or any(len(p) == 0 or len(p) > 3 for p in parts):
            return None
        return ".".join(str(n) for n in nums), 4
    try:
        a = ipaddress.IPv6Address(s)
    except ValueError:
        return None
    if a.ipv4_mapped is not None:
        return str(a.ipv4_mapped), 4
    return a.compressed, 6


@lru_cache(maxsize=65536)
def classify(ip: str, ver: int) -> str:
    a = ipaddress.ip_address(ip)
    nets = V4_NETS if ver == 4 else V6_NETS
    for cls, net in nets:
        if a in net:
            return cls
    if ver == 4 and str(a) == "255.255.255.255":
        return "reserved"
    if ver == 6 and not a.is_global:
        return "reserved"
    return "public"


def subnet_key(ip: str, ver: int) -> str:
    if ver == 4:
        o = ip.split(".")
        return f"{o[0]}.{o[1]}.{o[2]}.0/24"
    return str(ipaddress.IPv6Network(f"{ip}/64", strict=False))


def split_ip_port(value: str) -> Optional[tuple[str, int, Optional[int]]]:
    """Parse a cell that should contain one IP, optionally with a port."""
    if value is None:
        return None
    v = str(value).strip()
    if not v:
        return None
    m = IPV6_BRACKET_RE.fullmatch(v)
    if m:
        n = normalize_ip(m.group(1))
        if n:
            return n[0], n[1], _port(m.group(2))
    n = normalize_ip(v)
    if n:
        return n[0], n[1], None
    m = re.fullmatch(r"((?:\d{1,3}\.){3}\d{1,3})[:\s]+(\d{1,5})", v)
    if m:
        n = normalize_ip(m.group(1))
        if n:
            return n[0], n[1], _port(m.group(2))
    found = find_ips(v)
    if len(found) == 1:
        ip, ver, port, _, _ = found[0]
        return ip, ver, port
    return None


def _port(p) -> Optional[int]:
    try:
        n = int(p)
    except (TypeError, ValueError):
        return None
    return n if 0 < n < 65536 else None


def find_ips(text: str) -> list[tuple[str, int, Optional[int], int, int]]:
    """All IPs in free text: (ip, version, port, start, end). Validated, de-duplicated by span."""
    out = []
    if not text:
        return out
    if "." in text:
        for m in IPV4_RE.finditer(text):
            n = normalize_ip(m.group(1))
            if n:
                out.append((n[0], 4, _port(m.group(2)), m.start(), m.end()))
    if "::" in text or text.count(":") >= 7 or "[" in text:
        taken = [(o[3], o[4]) for o in out]
        for m in IPV6_BRACKET_RE.finditer(text):
            n = normalize_ip(m.group(1))
            if n and n[1] == 6:
                out.append((n[0], 6, _port(m.group(2)), m.start(), m.end()))
                taken.append((m.start(), m.end()))
        for m in IPV6_RE.finditer(text):
            cand = m.group(1)
            # every IPv6 address has '::' or exactly seven colons (times like 09:15:30 have neither)
            if "::" not in cand and cand.count(":") != 7:
                continue
            if any(s <= m.start() < e for s, e in taken):
                continue
            n = normalize_ip(cand)
            if n and n[1] == 6:
                out.append((n[0], 6, None, m.start(), m.end()))
    out.sort(key=lambda o: o[3])
    return out
