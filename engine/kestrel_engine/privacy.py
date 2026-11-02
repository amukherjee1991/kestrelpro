"""DNS privacy check: does your network's address leave with your lookups?

EDNS Client Subnet (ECS) lets a resolver pass part of the asking network's address on to the
sites' own name servers, which use it to pick nearby servers, and to see roughly where you
are. dnsmasq doesn't send it unless configured to (`add-subnet`), but some public resolvers
add it themselves.

The check has two parts:
- a live test: one lookup of Google's `o-o.myaddr.l.google.com` through the DNS server.
  Google's name server answers with the address of the resolver that asked it and, when one
  arrived, the client subnet it was given. That is what every site's name server sees.
- the configuration: upstream resolvers known to send ECS, and dnsmasq options that attach
  the subnet, a device's MAC address or an ID to queries going out.
"""
import ipaddress
import os
import random
import socket
import struct

import requests

from . import config

TEST_NAME = "o-o.myaddr.l.google.com"
TXT = 16

# Public resolvers that pass client subnets on (their documented ECS behaviour).
SENDS_ECS = {
    "8.8.8.8": "Google Public DNS", "8.8.4.4": "Google Public DNS",
    "2001:4860:4860::8888": "Google Public DNS", "2001:4860:4860::8844": "Google Public DNS",
    "208.67.222.222": "OpenDNS", "208.67.220.220": "OpenDNS",
    "2620:119:35::35": "OpenDNS", "2620:119:53::53": "OpenDNS",
    "9.9.9.11": "Quad9 (ECS variant)", "149.112.112.11": "Quad9 (ECS variant)",
    "2620:fe::11": "Quad9 (ECS variant)", "2620:fe::fe:11": "Quad9 (ECS variant)",
}
LEAKY_OPTIONS = {
    "add-subnet": "sends part of each device's address (EDNS Client Subnet) to the upstream resolver",
    "add-mac": "sends each device's MAC address to the upstream resolver",
    "add-cpe-id": "sends an identifier for this network to the upstream resolver",
}
DNSMASQ_D = "/etc/dnsmasq.d"


def _name(qname):
    return b"".join(bytes([len(p)]) + p.encode("ascii") for p in qname.rstrip(".").split(".")) + b"\0"


def _skip_name(msg, i):
    while True:
        n = msg[i]
        if n == 0:
            return i + 1
        if n & 0xC0 == 0xC0:  # compression pointer
            return i + 2
        i += n + 1


def parse_txt(msg, qid):
    """TXT strings from a DNS response (each record's strings joined)."""
    if len(msg) < 12:
        raise ValueError("short DNS response")
    rid, flags, qd, an = struct.unpack(">HHHH", msg[:8])
    if rid != qid:
        raise ValueError("DNS response for another query")
    rcode = flags & 0xF
    if rcode:
        raise ValueError(f"DNS error code {rcode}")
    i = 12
    for _ in range(qd):
        i = _skip_name(msg, i) + 4
    out = []
    for _ in range(an):
        i = _skip_name(msg, i)
        rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", msg[i:i + 10])
        i += 10
        rdata, i = msg[i:i + rdlen], i + rdlen
        if rtype == TXT:
            parts, j = [], 0
            while j < len(rdata):
                n = rdata[j]
                parts.append(rdata[j + 1:j + 1 + n].decode("utf-8", "replace"))
                j += n + 1
            out.append("".join(parts))
    return out


def query_txt(qname, server, port=53, timeout=4):
    qid = random.randrange(1, 0xFFFF)
    packet = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + _name(qname) + struct.pack(">HH", TXT, 1)
    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(packet, (server, port))
        msg, _ = s.recvfrom(4096)
    if msg[2] & 0x02:  # truncated: ask again over TCP
        with socket.create_connection((server, port), timeout=timeout) as s:
            s.sendall(struct.pack(">H", len(packet)) + packet)
            size = struct.unpack(">H", s.recv(2))[0]
            msg = b""
            while len(msg) < size:
                chunk = s.recv(size - len(msg))
                if not chunk:
                    break
                msg += chunk
    return parse_txt(msg, qid)


def live_test(server=None):
    """What the sites' name servers see: {"resolver", "subnet", "error"}."""
    try:
        answers = query_txt(TEST_NAME, server or config.DNS_SERVER)
    except (OSError, ValueError, struct.error, IndexError) as e:
        return {"resolver": None, "subnet": None, "error": f"The test lookup failed: {e}"}
    subnet = next((a.split(" ", 1)[1] for a in answers if a.startswith("edns0-client-subnet ")), None)
    resolver = next((a for a in answers if _is_ip(a)), None)
    return {"resolver": resolver, "subnet": subnet, "error": None}


def _is_ip(text):
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def upstream_notes(upstreams):
    out = []
    for u in upstreams:
        host = u.split("#", 1)[0].strip().strip("[]")
        note = None
        if host in SENDS_ECS:
            note = f"{SENDS_ECS[host]} passes part of your address on to sites' name servers."
        elif _is_ip(host) and (ipaddress.ip_address(host).is_private or ipaddress.ip_address(host).is_loopback):
            note = "A resolver on your own network: its own settings decide what it passes on (the live test shows it)."
        out.append({"server": u, "sends_ecs": host in SENDS_ECS, "note": note})
    return out


def option_findings(lines):
    out = []
    for line in lines:
        key = line.strip().split("=", 1)[0].strip()
        if key in LEAKY_OPTIONS:
            out.append({"line": line.strip(), "what": LEAKY_OPTIONS[key]})
    return out


def _dnsmasq_d_lines(path=DNSMASQ_D):
    lines = []
    try:
        for name in sorted(os.listdir(path)):
            if name.endswith(".conf"):
                with open(os.path.join(path, name), encoding="utf-8", errors="replace") as f:
                    lines += [l for l in f if l.strip() and not l.lstrip().startswith("#")]
    except OSError:
        pass
    return lines


def check(ftl, server=None):
    """The whole check, for the Location privacy page."""
    problems = []
    try:
        upstreams = ftl.config_value("dns/upstreams") or []
    except (requests.RequestException, KeyError, TypeError):
        upstreams = []
        problems.append("Couldn't read the upstream DNS servers from the DNS server's settings.")
    try:
        lines = list(ftl.config_value("misc/dnsmasq_lines") or [])
    except (requests.RequestException, KeyError, TypeError):
        lines = []
    try:
        if ftl.config_value("misc/etc_dnsmasq_d"):
            lines += _dnsmasq_d_lines()
    except (requests.RequestException, KeyError, TypeError):
        pass
    live = live_test(server)
    notes = upstream_notes(upstreams)
    options = option_findings(lines)
    leaks = bool(live["subnet"]) or bool(options) or any(n["sends_ecs"] for n in notes)
    return {"live": live, "upstreams": notes, "options": options, "problems": problems,
            "ok": not leaks and not live["error"]}
