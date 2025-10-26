from datetime import datetime
from sqlalchemy.orm import Session
from .models import Module, ModuleMetric

def record_metric(
    db: Session,
    module_name: str,
    key: str,
    value_text: str = "",
    value_num: float | None = None,
) -> bool:
    """
    Upsert a metric row identified by (module_name, key).
    - value_text: free-form payload (status, path, notes, JSON-ish text, etc.)
    - value_num:  optional numeric value for counters/graphs
    Returns True if the module exists and the metric was written, else False.
    """
    mod = db.query(Module).filter(Module.name == module_name).first()
    if not mod:
        return False

    mm = (
        db.query(ModuleMetric)
        .filter(ModuleMetric.module_id == mod.id, ModuleMetric.key == key)
        .first()
    )
    if not mm:
        mm = ModuleMetric(module_id=mod.id, key=key)

        # When inserting a fresh metric, default updated_at to now.
        db.add(mm)

    # Update fields
    if value_text is not None:
        mm.value_text = value_text
    mm.value_num = value_num
    mm.updated_at = datetime.utcnow()

    db.commit()
    return True

