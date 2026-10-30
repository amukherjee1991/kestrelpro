"""KestrelPro engine.

Usage:
  python -m kestrel_engine serve    API for the admin UI's KestrelPro pages, and the review loop (container default)
  python -m kestrel_engine once     read everything new and review it now
  python -m kestrel_engine report   show recent decisions
  python -m kestrel_engine undo     remove every domain KestrelPro has blocked
  python -m kestrel_engine pause    disable every KestrelPro block (nothing is deleted)
  python -m kestrel_engine resume   enable them again
"""
import logging
import sys

from . import ftl as ftl_api, ingest, policy, safety, store


def report(db, limit=40):
    rows = db.execute("select domain, category, confidence, status, reason from verdicts "
                      "order by updated_at desc limit ?", (limit,)).fetchall()
    for d, cat, conf, status, reason in rows:
        print(f"{status:<13}{cat:<11}{conf:4.2f}  {d}  - {reason}")
    total = db.execute("select count(*) from verdicts").fetchone()[0]
    nblocked = db.execute("select count(*) from verdicts where status in (?, ?)",
                          (store.BLOCKED, store.USER_BLOCKED)).fetchone()[0]
    print(f"\n{total} domains reviewed, {nblocked} blocked")


def main(argv):
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    cmd = argv[0] if argv else "serve"
    if cmd == "serve":
        from . import api
        return api.serve()
    if cmd not in ("once", "report", "undo", "pause", "resume"):
        print(__doc__)
        return 2
    db = store.open_db()
    if cmd == "report":
        return report(db)
    ftl = ftl_api.FTL()
    try:
        if cmd == "undo":
            print(f"removed {len(policy.undo(ftl, db))} domain(s) added by KestrelPro")
        elif cmd == "pause":
            print(f"paused: {safety.pause(ftl, db)} KestrelPro block(s) disabled; `resume` turns them back on")
        elif cmd == "resume":
            print(f"resumed: {safety.resume(ftl, db)} KestrelPro block(s) enabled")
        else:
            print(f"reviewed {ingest.Ingest(ftl).run_once(db)} domain(s)")
    finally:
        ftl.logout()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
