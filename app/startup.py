from sqlalchemy.orm import Session
from datetime import datetime
from .models import Module
from . import module_loader
from .metrics import record_metric

def run_startup_sequence(db: Session, loaded_map: dict):
    """
    Always called on boot. Ensures baseline metrics exist and runs enabled modules by order.
    """
    # Ensure baseline metrics for all discovered modules
    all_mods = db.query(Module).order_by(Module.order.asc(), Module.name.asc()).all()
    for m in all_mods:
        record_metric(db, m.name, "present", value_text=m.path)
        record_metric(db, m.name, "order", value_text=str(m.order), value_num=float(m.order))
        record_metric(db, m.name, "heartbeat", value_text=datetime.utcnow().isoformat())

    # Run enabled modules by order
    enabled_mods = [m for m in all_mods if m.enabled]
    for m in enabled_mods:
        lm = loaded_map.get(m.name)
        if lm:
            ok, _ = module_loader.run_module(db, m, lm)
            # record last boot run status
            record_metric(db, m.name, "boot_run", value_text=("ok" if ok else "error"))

