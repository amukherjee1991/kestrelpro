"""CNAME chains, so protection follows a protected site to the CDN names it points at.

secure.chase.com is protected, but devices that follow its CNAME then look up
gtm.secure.chase.com.akadns.net and e1234.a.akamaiedge.net on their own. Those names say
nothing about who they serve, and the model has blocked them as "ad infrastructure".
chain() asks the DNS server for the protected name and returns every name its answer
passes through, so ingest.py can treat them as part of the protected site.
Standard library only, like privacy.py.
"""
import random
import socket
import struct
import time

A, CNAME = 1, 5
CACHE_SECONDS = 600
FAILED_CACHE_SECONDS = 60
_cache = {}  # (qname, server) -> (expires_at, names)


def _encode(qname):
    return b"".join(bytes([len(p)]) + p.encode("ascii") for p in qname.rstrip(".").split(".")) + b"\0"


def read_name(msg, i):
    """(name, index after the name) at msg[i], following compression pointers."""
    labels, end, hops = [], None, 0
    while True:
        n = msg[i]
        if n == 0:
            i += 1
            break
        if n & 0xC0 == 0xC0:  # pointer: the rest of the name is elsewhere
            if end is None:
                end = i + 2
            i = ((n & 0x3F) << 8) | msg[i + 1]
            hops += 1
            if hops > 32:
                raise ValueError("DNS name compression loop")
            continue
        labels.append(msg[i + 1:i + 1 + n].decode("ascii", "replace"))
        i += n + 1
    return ".".join(labels).lower(), (end if end is not None else i)


def parse_cnames(msg, qid):
    """The CNAME targets in a DNS response's answer section, in order."""
    if len(msg) < 12:
        raise ValueError("short DNS response")
    rid, flags, qd, an = struct.unpack(">HHHH", msg[:8])
    if rid != qid:
        raise ValueError("DNS response for another query")
    if flags & 0xF:
        raise ValueError(f"DNS error code {flags & 0xF}")
    i = 12
    for _ in range(qd):
        i = read_name(msg, i)[1] + 4
    out = []
    for _ in range(an):
        i = read_name(msg, i)[1]
        rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", msg[i:i + 10])
        i += 10
        if rtype == CNAME:
            out.append(read_name(msg, i)[0])
        i += rdlen
    return out


def query(qname, server, port=53, timeout=2):
    qid = random.randrange(1, 0xFFFF)
    packet = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + _encode(qname) + struct.pack(">HH", A, 1)
    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(packet, (server, port))
        msg, _ = s.recvfrom(4096)
    return parse_cnames(msg, qid)


def chain(qname, server, now=None):
    """Every name `qname` resolves through (CNAME targets), cached. Empty on any failure."""
    now = now or time.time()
    key = (qname, server)
    hit = _cache.get(key)
    if hit and hit[0] > now:
        return hit[1]
    try:
        names, ttl = set(query(qname, server)), CACHE_SECONDS
    except (OSError, ValueError, struct.error, IndexError):
        names, ttl = set(), FAILED_CACHE_SECONDS
    _cache[key] = (now + ttl, names)
    if len(_cache) > 5000:
        for k in [k for k, v in _cache.items() if v[0] <= now]:
            del _cache[k]
    return names
