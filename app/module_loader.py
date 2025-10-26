import importlib
import pkgutil
import traceback
from typing import Dict, List, Tuple
from sqlalchemy.orm import Session
from .models import Module

MODULES_PKG = "modules"

class LoadedModule:
    def __init__(self, name: str, mod):
        self.name = name
        self.module = mod
        self.description = getattr(mod, "DESCRIPTION", "")
        self.has_run = hasattr(mod, "run") and callable(mod.run)

def discover_modules() -> List[Tuple[str, object]]:
    discovered = []
    for m in pkgutil.iter_modules([MODULES_PKG]):
        if m.ispkg:
            continue
        import_path = f"{MODULES_PKG}.{m.name}"
        try:
            mod = importlib.import_module(import_path)
            discovered.append((import_path, mod))
        except Exception:
            continue
    return discovered

def sync_db_with_fs(db: Session) -> Dict[str, LoadedModule]:
    fs = discover_modules()
    loaded_map: Dict[str, LoadedModule] = {}

    for import_path, mod in fs:
        name = getattr(mod, "NAME", import_path.split(".")[-1])
        lm = LoadedModule(name, mod)
        loaded_map[name] = lm

        rec = db.query(Module).filter(Module.name == name).first()
        if not rec:
            rec = Module(
                name=name,
                path=import_path,
                description=lm.description,
                enabled=True,
                order=1000,
            )
            db.add(rec)
        else:
            rec.path = import_path
            rec.description = lm.description
    db.commit()
    return loaded_map

def run_module(db: Session, mod_rec: Module, loaded: LoadedModule):
    if not loaded.has_run:
        msg = "Module has no run()"
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

