# xpfarm/app/module_loader.py
import importlib
import pkgutil
import traceback
from typing import Dict, List, Tuple
from sqlalchemy.orm import Session
from .models import Module

MODULES_PKG = "modules"

class LoadedModule:
    def __init__(self, name: str, mod):
        self.name = name                  # e.g. "modules.initialise"
        self.module = mod
        self.description = getattr(mod, "DESCRIPTION", "")
        self.has_run = hasattr(mod, "run") and callable(mod.run)

def discover_modules() -> List[Tuple[str, object]]:
    """
    Find importable modules under /app/modules (non-packages).
    Returns list of (import_path, module_obj), e.g. ("modules.initialise", <module>)
    """
    discovered = []
    for m in pkgutil.iter_modules([MODULES_PKG]):
        if m.ispkg:
            continue
        import_path = f"{MODULES_PKG}.{m.name}"
        try:
            mod = importlib.import_module(import_path)
            discovered.append((import_path, mod))
        except Exception:
            # Ignore broken modules during discovery; they'll show up in metrics when run is attempted
            continue
    return discovered

def sync_db_with_fs(db: Session) -> Dict[str, LoadedModule]:
    """
    Ensure DB rows exist for each discovered module.
    Rules:
      - New modules default enabled=False, order=1000.
      - Exceptions:
          * modules.initialise -> enabled=True, order=0
          * modules.dashboard  -> enabled=True, order=1
      - Existing rows keep their enabled/order (we do not overwrite user choices).
    Returns a map of import_path -> LoadedModule for quick lookup at runtime.
    """
    loaded_map: Dict[str, LoadedModule] = {}

    for import_path, mod in discover_modules():
        name = import_path
        lm = LoadedModule(name, mod)
        loaded_map[name] = lm

        rec = db.query(Module).filter(Module.name == name).first()
        if not rec:
            enabled = False
            order = 1000
            base = name.split(".")[-1].lower()
            if base == "initialise":
                enabled = True
                order = 0
            elif base == "dashboard":
                enabled = True
                order = 1

            rec = Module(
                name=name,
                path=import_path,
                description=lm.description,
                enabled=enabled,
                order=order,
            )
            db.add(rec)
        else:
            # refresh metadata only; preserve enabled/order
            rec.path = import_path
            rec.description = lm.description

    db.commit()
    return loaded_map

def run_module(db: Session, mod_rec: Module, loaded: LoadedModule) -> Tuple[bool, str]:
    """
    Execute a module's run() and record status via Module.touch_run().
    Returns (ok, output_or_tb).
    """
    if not loaded or not loaded.has_run:
        msg = "module has no callable run()"
        mod_rec.touch_run("error", msg)
        db.commit()
        return False, msg

    try:
        out = loaded.module.run()
        if out is None:
            out = "(no output)"
        mod_rec.touch_run("ok", str(out))
        db.commit()
        return True, str(out)
    except Exception:
        tb = traceback.format_exc()
        mod_rec.touch_run("error", tb)
        db.commit()
        return False, tb

