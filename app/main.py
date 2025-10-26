import os
from typing import List, Iterable
from fastapi import FastAPI, Depends, HTTPException, Request, Form, UploadFile, File
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from .db import Base, engine, get_db
from .models import Module as ModuleModel, Target, ScopeItem, ConfigKV, ModuleMetric
from . import module_loader
from .startup import run_startup_sequence

app = FastAPI(title="CTF Microserver", version="0.4.0")

Base.metadata.create_all(bind=engine)

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")
TPL_DIR = os.path.join(os.path.dirname(__file__), "templates")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
templates = Jinja2Templates(directory=TPL_DIR)

_loaded: dict = {}
SCOPE_TYPES = ["CIDR", "Domain", "Wildcard", "IP Address", "URL", "API", "Other Asset"]

from sqlalchemy import text

from sqlalchemy import text

def ensure_schema(db: Session):
    cols = {r[1] for r in db.execute(text("PRAGMA table_info(scope_items)")).fetchall()}
    to_add = []
    if "verified" not in cols:
        to_add.append('ALTER TABLE scope_items ADD COLUMN verified INTEGER DEFAULT 0')
    if "verified_at" not in cols:
        to_add.append('ALTER TABLE scope_items ADD COLUMN verified_at TEXT')
    if "verified_note" not in cols:
        to_add.append('ALTER TABLE scope_items ADD COLUMN verified_note TEXT DEFAULT ""')
    for stmt in to_add:
        db.execute(text(stmt))
    if to_add:
        db.commit()

    # Unique index on normalized key to block dup inserts (case-insensitive)
    try:
        db.execute(text(
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_scope_norm "
            "ON scope_items (target_id, stype, lower(value))"
        ))
        db.commit()
    except Exception:
        # If duplicates still exist, the index creation will fail; initialise.py will clean them.
        pass

def _split_tokens(raw: str):
    for chunk in raw.replace(",", "\n").splitlines():
        tok = chunk.strip()
        if tok:
            yield tok

def seed_config_defaults(db: Session):
    def ensure(key: str, values: list[str]):
        kv = db.query(ConfigKV).filter(ConfigKV.key == key).first()
        if not kv:
            db.add(ConfigKV(key=key, value="\n".join(values)))
    ensure("IPv4_cloudflare", [
        "173.245.48.0/20","103.21.244.0/22","103.22.200.0/22","103.31.4.0/22",
        "141.101.64.0/18","108.162.192.0/18","190.93.240.0/20","188.114.96.0/20",
        "197.234.240.0/22","198.41.128.0/17","162.158.0.0/15","104.16.0.0/13",
        "104.24.0.0/14","172.64.0.0/13",
    ])
    ensure("IPv6_cloudflare", [
        "131.0.72.0/22","2400:cb00::/32","2606:4700::/32","2803:f800::/32",
        "2405:b500::/32","2405:8100::/32","2a06:98c0::/29","2c0f:f248::/32",
    ])
    db.commit()

@app.on_event("startup")
def on_startup():
    from .db import SessionLocal
    db = SessionLocal()
    try:
        seed_config_defaults(db)
        ensure_schema(db)
        global _loaded
        _loaded = module_loader.sync_db_with_fs(db)
        run_startup_sequence(db, _loaded)
    finally:
        db.close()

@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    total = db.query(ModuleModel).count()
    enabled = db.query(ModuleModel).filter(ModuleModel.enabled == True).count()
    failures = db.query(ModuleModel).filter(ModuleModel.last_run_status == "error").count()

    # latest metrics (flat read)
    metrics = db.query(ModuleMetric).all()
    view = {}
    for m in metrics:
        d = view.setdefault(m.module.name, {})
        d[m.key] = {
            "value_text": m.value_text,
            "value_num": m.value_num,
            "updated_at": m.updated_at,
        }

    # modules list for a small status table
    modules = (
        db.query(ModuleModel)
        .order_by(ModuleModel.order.asc(), ModuleModel.name.asc())
        .all()
    )

    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "total": total,
            "enabled": enabled,
            "failures": failures,
            "modules": modules,
            "metrics": view,
        },
    )

from datetime import datetime, timezone

@app.get("/api/dashboard")
def dashboard_data(db: Session = Depends(get_db)):
    # Modules overview
    mods = db.query(ModuleModel).order_by(ModuleModel.order.asc(), ModuleModel.name.asc()).all()
    total = len(mods)
    enabled = sum(1 for m in mods if m.enabled)
    disabled = total - enabled
    ok_count = sum(1 for m in mods if m.last_run_status == "ok")
    err_count = sum(1 for m in mods if m.last_run_status == "error")
    never_count = sum(1 for m in mods if m.last_run_status == "never")

    # Latest metrics keyed by module
    mm = db.query(ModuleMetric).all()
    metrics = {}
    for m in mm:
        d = metrics.setdefault(m.module.name, {})
        d[m.key] = {
            "value_text": m.value_text,
            "value_num": m.value_num,
            "updated_at": (m.updated_at.isoformat() if m.updated_at else None),
        }

    # Per-module payload for charts
    per_module = []
    now = datetime.now(timezone.utc)
    for m in mods:
        last_run_age_sec = None
        if m.last_run_at:
            # treat naive as UTC
            dt = m.last_run_at.replace(tzinfo=timezone.utc) if m.last_run_at.tzinfo is None else m.last_run_at
            last_run_age_sec = max(0, int((now - dt).total_seconds()))
        per_module.append({
            "name": m.name,
            "enabled": m.enabled,
            "order": m.order,
            "last_run_status": m.last_run_status,
            "last_run_age_sec": last_run_age_sec,
        })

    return {
        "totals": {
            "total": total,
            "enabled": enabled,
            "disabled": disabled,
            "ok": ok_count,
            "error": err_count,
            "never": never_count,
        },
        "per_module": per_module,
        "metrics": metrics,  # baseline metrics (present/order/heartbeat/boot_run, etc.)
    }

# ---------- MODULES PAGE (old dashboard moved here) ----------
@app.get("/modules", response_class=HTMLResponse)
def modules_page(request: Request, db: Session = Depends(get_db)):
    modules = (
        db.query(ModuleModel)
        .order_by(ModuleModel.order.asc(), ModuleModel.name.asc())
        .all()
    )
    return templates.TemplateResponse(
        "modules.html",
        {"request": request, "modules": modules, "version": app.version},
    )

# ---------- Modules API ----------
@app.get("/api/modules")
def list_modules(db: Session = Depends(get_db)):
    mods = db.query(ModuleModel).order_by(ModuleModel.order.asc(), ModuleModel.name.asc()).all()
    return [
        {
            "id": m.id,
            "name": m.name,
            "path": m.path,
            "description": m.description,
            "enabled": m.enabled,
            "order": m.order,
            "last_run_at": m.last_run_at,
            "last_run_status": m.last_run_status,
        }
        for m in mods
    ]

@app.post("/api/modules/{mid}/toggle")
def toggle_enabled(mid: int, db: Session = Depends(get_db)):
    m = db.query(ModuleModel).get(mid)
    if not m:
        raise HTTPException(404, "module not found")
    m.enabled = not m.enabled
    db.commit()
    return {"id": m.id, "enabled": m.enabled}

@app.post("/api/modules/{mid}/run")
def run_now(mid: int, db: Session = Depends(get_db)):
    m = db.query(ModuleModel).get(mid)
    if not m:
        raise HTTPException(404, "module not found")
    global _loaded
    if m.name not in _loaded:
        _loaded = module_loader.sync_db_with_fs(db)
        if m.name not in _loaded:
            raise HTTPException(500, "module not loadable")
    ok, out = module_loader.run_module(db, m, _loaded[m.name])
    return JSONResponse({"ok": ok, "output": out})

@app.post("/api/modules/reorder")
async def reorder(mod_ids: List[int], db: Session = Depends(get_db)):
    for idx, mid in enumerate(mod_ids):
        m = db.query(ModuleModel).get(mid)
        if m:
            m.order = idx
    db.commit()
    return {"ok": True}

# ---------- Scope & Config handlers remain as in your current build ----------
@app.get("/scope", response_class=HTMLResponse)
def scope_page(request: Request, db: Session = Depends(get_db)):
    targets = db.query(Target).order_by(Target.name.asc()).all()
    # shape data for simple rendering
    view = []
    for t in targets:
        items = db.query(ScopeItem).filter(ScopeItem.target_id == t.id).order_by(ScopeItem.stype.asc(), ScopeItem.value.asc()).all()
        view.append({"target": t, "items": items})
    return templates.TemplateResponse(
        "scope.html",
        {"request": request, "targets": view, "types": SCOPE_TYPES},
    )

@app.post("/scope/target")
def create_target(name: str = Form(...), notes: str = Form(""), db: Session = Depends(get_db)):
    name = name.strip()
    if not name:
        raise HTTPException(400, "target name required")
    exists = db.query(Target).filter(Target.name == name).first()
    if exists:
        return RedirectResponse(url="/scope", status_code=303)
    db.add(Target(name=name, notes=notes))
    db.commit()
    return RedirectResponse(url="/scope", status_code=303)

@app.post("/scope/item")
async def add_scope_items(
    target_id: int = Form(...),
    stype: str = Form(...),
    manual: str = Form(""),
    file: UploadFile | None = File(None),
    db: Session = Depends(get_db),
):
    if stype not in SCOPE_TYPES:
        raise HTTPException(400, "invalid scope type")
    # Collect tokens from manual + file (if any)
    tokens: List[str] = []
    tokens.extend(list(_split_tokens(manual)))
    if file and file.filename:
        blob = await file.read()
        try:
            txt = blob.decode("utf-8", errors="ignore")
        except Exception:
            txt = ""
        tokens.extend(list(_split_tokens(txt)))

    tokens = list(dict.fromkeys(tokens))  # de-dup preserve order
    for tok in tokens:
        # ignore insane long entries
        if len(tok) > 2048:
            continue
        # Upsert-ish: rely on UniqueConstraint to avoid dup, but be graceful
        exists = db.query(ScopeItem).filter(
            ScopeItem.target_id == target_id,
            ScopeItem.value == tok,
            ScopeItem.stype == stype
        ).first()
        if not exists:
            db.add(ScopeItem(target_id=target_id, value=tok, stype=stype))
    db.commit()
    return RedirectResponse(url="/scope", status_code=303)

@app.post("/scope/item/{iid}/delete")
def delete_scope_item(iid: int, db: Session = Depends(get_db)):
    item = db.query(ScopeItem).get(iid)
    if item:
        db.delete(item)
        db.commit()
    return RedirectResponse(url="/scope", status_code=303)

@app.post("/scope/target/{tid}/delete")
def delete_target(tid: int, db: Session = Depends(get_db)):
    t = db.query(Target).get(tid)
    if t:
        db.delete(t)  # cascades to items
        db.commit()
    return RedirectResponse(url="/scope", status_code=303)

# ---------- Config ----------
@app.get("/config", response_class=HTMLResponse)
def config_page(request: Request, db: Session = Depends(get_db)):
    kvs = db.query(ConfigKV).order_by(ConfigKV.key.asc()).all()
    return templates.TemplateResponse(
        "config.html",
        {"request": request, "kvs": kvs},
    )

@app.post("/config/set")
def config_set(key: str = Form(...), value: str = Form(""), db: Session = Depends(get_db)):
    key = key.strip()
    if not key:
        raise HTTPException(400, "key required")
    kv = db.query(ConfigKV).filter(ConfigKV.key == key).first()
    if kv:
        kv.value = value
    else:
        kv = ConfigKV(key=key, value=value)
        db.add(kv)
    db.commit()
    return RedirectResponse(url="/config", status_code=303)

