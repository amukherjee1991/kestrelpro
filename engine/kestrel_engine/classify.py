"""Asks a local model (Ollama) what each domain is for."""
import json
import logging
import time

import requests

from . import config

log = logging.getLogger("kestrel.classify")

CATEGORIES = ["ads", "tracking", "telemetry", "malicious", "legitimate", "unknown"]
# Bump when SYSTEM_PROMPT or VERDICT_SCHEMA changes; stored on every verdict.
PROMPT_VERSION = "2026-10-29.1"

SYSTEM_PROMPT = """You review DNS lookups from a home network's DNS ad blocker. \
For each domain, decide what it is mainly used for:
- ads: serves or brokers advertising (ad servers, ad exchanges, sponsored-content networks)
- tracking: cross-site tracking, analytics, fingerprinting, attribution or data brokers
- telemetry: a vendor's own product telemetry or crash reporting
- malicious: malware, phishing, scam, cryptojacking or known-bad infrastructure
- legitimate: needed for a site, app, login, CDN, API, update or content to work
- unknown: you cannot tell

The household relies on these domains working, so a wrong block costs more than a \
missed ad. Give high confidence only when you recognise the domain or its owner and \
its purpose is clear. Domains that mix content with ads (e.g. a CDN or a first-party \
API) are legitimate. Confidence is a whole-number percentage from 0 (a guess) to 100 (certain). \
Keep each reason under 15 words."""

VERDICT_SCHEMA = {
    "type": "object",
    "properties": {
        "verdicts": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "domain": {"type": "string"},
                    "category": {"type": "string", "enum": CATEGORIES},
                    "confidence": {"type": "integer"},
                    "reason": {"type": "string"},
                },
                "required": ["domain", "category", "confidence", "reason"],
            },
        }
    },
    "required": ["verdicts"],
}

_digests = {"at": 0.0, "map": {}}


def model_digest(model):
    """The digest of the installed model, so a later `ollama pull` shows up in the verdicts."""
    if time.time() - _digests["at"] > 600:
        try:
            tags = requests.get(f"{config.OLLAMA_URL}/api/tags", timeout=5).json().get("models", [])
            _digests["map"] = {m["name"]: m.get("digest") for m in tags}
            _digests["at"] = time.time()
        except (requests.RequestException, ValueError):
            pass
    m = _digests["map"]
    return m.get(model) or m.get(f"{model}:latest")


def classify(batch, model):
    """batch: list of (domain, query_count, client_count). Returns {domain: verdict}."""
    rows = "\n".join(f"{d}\t{n} lookups\t{c} device(s)" for d, n, c in batch)
    r = requests.post(f"{config.OLLAMA_URL}/api/chat", timeout=900, json={
        "model": model,
        "stream": False,
        "think": False,
        "format": VERDICT_SCHEMA,
        "options": {"temperature": 0, "num_ctx": 8192},
        "keep_alive": "15m",
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"Classify every domain below.\n\n{rows}"},
        ],
    })
    r.raise_for_status()
    data = r.json()
    if data.get("done_reason") != "stop":
        log.warning("model stopped with %s; skipping batch", data.get("done_reason"))
        return {}
    try:
        verdicts = json.loads(data["message"]["content"])["verdicts"]
    except (json.JSONDecodeError, KeyError, TypeError):
        log.warning("model returned unparseable output; skipping batch")
        return {}
    wanted = {d for d, _, _ in batch}
    out = {}
    for v in verdicts:
        if v.get("domain") not in wanted or v.get("category") not in CATEGORIES or not isinstance(v.get("confidence"), (int, float)):
            continue
        # Asked for a percentage: small models are far more consistent with 0-100
        # than with 0-1. Stored as a fraction.
        out[v["domain"]] = {**v, "confidence": min(max(v["confidence"] / 100, 0.0), 1.0)}
    return out
