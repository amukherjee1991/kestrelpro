"""Your decisions as a labelled set: how often the model agrees with you, and examples for it.

A domain is labelled by your latest decision on it:
  blocked  - you approved a suggestion or blocked it yourself
  kept     - you said "Don't block" or unblocked it
Withdrawals by the trial period (safety.py) and bulk removals (`kestrel_engine undo`) are not
decisions about a domain and don't count. Domains you
blocked without the model ever judging them ("blocked by you") have no model opinion to grade.

"The model wanted it blocked" uses the current global threshold and categories, so the page
answers: with today's settings, how often would the model and you agree?
"""
import time

from . import policy, store

POSITIVE = (store.APPROVED, store.MANUAL_BLOCKED)
NEGATIVE = (store.REJECTED, store.UNBLOCKED)
NOT_JUDGED = "blocked by you"
MIN_EXAMPLES = 4
BULK = "%undo`%"  # reason logged by policy.undo()


def labelled(db, limit=None):
    """[{domain, blocked (bool), at, category, confidence, reason, model}] newest first."""
    actions = POSITIVE + NEGATIVE
    sql = (f"select e.domain, e.action, e.at, v.category, v.confidence, v.reason, v.model "
           f"from events e join verdicts v on v.domain = e.domain "
           f"where e.action in ({','.join('?' * len(actions))}) and coalesce(e.reason, '') not like ? "
           f"and e.at = (select max(at) from events e2 where e2.domain = e.domain "
           f"            and e2.action in ({','.join('?' * len(actions))}) and coalesce(e2.reason, '') not like ?) "
           f"and coalesce(v.reason, '') != ? order by e.at desc")
    args = list(actions) + [BULK] + list(actions) + [BULK, NOT_JUDGED]
    if limit:
        sql += " limit ?"
        args.append(limit)
    return [{"domain": r["domain"], "blocked": r["action"] in POSITIVE, "at": r["at"],
             "category": r["category"], "confidence": r["confidence"], "reason": r["reason"],
             "model": r["model"] or "earlier model"} for r in db.execute(sql, args)]


def grade(rows, settings):
    """Agreement counts for labelled rows under `settings`."""
    tp = fp = fn = tn = 0
    for r in rows:
        wanted = policy.flags({"category": r["category"], "confidence": r["confidence"] or 0}, settings)
        if wanted and r["blocked"]:
            tp += 1
        elif wanted:
            fp += 1
        elif r["blocked"]:
            fn += 1
        else:
            tn += 1
    n = tp + fp + fn + tn
    return {"labelled": n, "agree": tp + tn, "agreement": (tp + tn) / n if n else None,
            "flagged_right": tp, "flagged_wrong": fp, "missed": fn, "kept_right": tn,
            "precision": tp / (tp + fp) if tp + fp else None}


def report(db, settings):
    rows = labelled(db)
    by_category, by_model = {}, {}
    for r in rows:
        by_category.setdefault(r["category"] or "unknown", []).append(r)
        by_model.setdefault(r["model"], []).append(r)
    disagreements = []
    for r in rows:
        wanted = policy.flags({"category": r["category"], "confidence": r["confidence"] or 0}, settings)
        if wanted != r["blocked"]:
            disagreements.append({**r, "model_wanted_block": wanted})
    return {
        "overall": grade(rows, settings),
        "by_category": sorted(({"category": c, **grade(rs, settings),
                                "you_blocked": sum(r["blocked"] for r in rs)} for c, rs in by_category.items()),
                              key=lambda x: -x["labelled"]),
        "by_model": sorted(({"model": m, **grade(rs, settings)} for m, rs in by_model.items()),
                           key=lambda x: -x["labelled"]),
        "disagreements": disagreements[:100],
        "settings": {"min_confidence": settings["min_confidence"], "block_categories": settings["block_categories"]},
        "generated_at": time.time(),
    }


def examples(db, n=8):
    """Up to n recent decisions, balanced between blocked and kept, for the prompt."""
    rows = labelled(db, limit=200)
    blocked = [r["domain"] for r in rows if r["blocked"]][: n // 2]
    kept = [r["domain"] for r in rows if not r["blocked"]][: n - len(blocked)]
    # A couple of examples would just bias the model; wait until there is a small set.
    return {"blocked": blocked, "kept": kept} if len(blocked) + len(kept) >= MIN_EXAMPLES else None
