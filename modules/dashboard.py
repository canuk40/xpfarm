# modules/dashboard.py
"""
Bare-min dashboard stats: counts verified/unverified per type, per target.
Writes a short text summary and numeric metrics you can graph later.
"""

from collections import Counter, defaultdict
from app.db import SessionLocal
from app.models import ScopeItem, Target
from app.metrics import record_metric

NAME = "dashboard"
DESCRIPTION = "Summarize counts of scope items (verified/unverified) for the dashboard."

def run():
    db = SessionLocal()
    try:
        rows = db.query(ScopeItem).all()

        total = len(rows)
        verified = sum(1 for r in rows if r.verified)
        unverified = total - verified

        by_type = Counter(r.stype for r in rows)
        by_type_verified = Counter(r.stype for r in rows if r.verified)

        # per-target verified ratio
        tgt_counts = defaultdict(lambda: {"total":0,"verified":0})
        for r in rows:
            tgt_counts[r.target_id]["total"] += 1
            if r.verified:
                tgt_counts[r.target_id]["verified"] += 1

        # metrics to plot later
        record_metric(db, NAME, "total", value_num=float(total))
        record_metric(db, NAME, "verified", value_num=float(verified))
        record_metric(db, NAME, "unverified", value_num=float(unverified))

        # short text summary
        lines = [f"total={total} verified={verified} unverified={unverified}"]
        lines.append("by_type:")
        for t, c in sorted(by_type.items()):
            v = by_type_verified.get(t, 0)
            lines.append(f"  - {t}: {c} (verified {v})")

        # Top 5 targets by unverified backlog
        if tgt_counts:
            # map target IDs to names
            names = {t.id: t.name for t in db.query(Target).all()}
            backlog = sorted(
                ((names.get(tid, str(tid)), d["total"] - d["verified"]) for tid, d in tgt_counts.items()),
                key=lambda x: x[1], reverse=True
            )[:5]
            lines.append("top_unverified_targets:")
            for name, cnt in backlog:
                lines.append(f"  - {name}: {cnt}")

        return "\n".join(lines)

    finally:
        db.close()

