from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime, Text, Float,
    ForeignKey, UniqueConstraint
)
from sqlalchemy.orm import relationship
from .db import Base

# -------- Modules --------
class Module(Base):
    __tablename__ = "modules"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    path = Column(String, nullable=False)
    description = Column(Text, default="")
    enabled = Column(Boolean, default=True)
    order = Column(Integer, default=1000)
    last_run_at = Column(DateTime, nullable=True)
    last_run_status = Column(String, default="never")
    last_run_output = Column(Text, default="")

    def touch_run(self, status: str, output: str = ""):
        self.last_run_at = datetime.utcnow()
        self.last_run_status = status
        self.last_run_output = (output or "")[:32768]

# -------- Scope / Targets --------
class Target(Base):
    __tablename__ = "targets"

    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True, nullable=False)
    notes = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.utcnow)

class ScopeItem(Base):
    __tablename__ = "scope_items"
    __table_args__ = ({ "extend_existing": True },)

    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)
    stype = Column(String, nullable=False)   # CIDR | Domain | Wildcard | IP Address | Other Asset | URL | API
    value = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    verified = Column(Boolean, default=False)
    verified_at = Column(DateTime, nullable=True)
    verified_note = Column(Text, default="")

    target = relationship("Target", lazy="joined")

# -------- Config --------
class ConfigKV(Base):
    __tablename__ = "config_kv"

    id = Column(Integer, primary_key=True)
    key = Column(String, unique=True, nullable=False)
    value = Column(Text, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

# -------- Metrics --------
class ModuleMetric(Base):
    __tablename__ = "module_metrics"
    __table_args__ = ( UniqueConstraint("module_id", "key", name="uq_metric_per_module_key"), )

    id = Column(Integer, primary_key=True)
    module_id = Column(Integer, ForeignKey("modules.id"), nullable=False, index=True)
    key = Column(String, nullable=False, index=True)
    value_text = Column(Text, default="")
    value_num = Column(Float, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow)

    module = relationship("Module", lazy="joined")

