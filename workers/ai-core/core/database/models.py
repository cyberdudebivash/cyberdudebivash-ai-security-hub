# ============================================================
# CYBERDUDEBIVASH AI — UNIFIED DATABASE MODELS (HARDENED)
# Fixes: JSON columns use Text+serialization for SQLite compat,
#        server_default for timestamps, proper nullable constraints
# ============================================================

import json
from sqlalchemy import (
    Column, Integer, String, DateTime, Float, Boolean,
    ForeignKey, Text, Index, event
)
from sqlalchemy.orm import relationship, DeclarativeBase
from sqlalchemy.types import TypeDecorator, TEXT
from datetime import datetime, timezone


def utcnow():
    return datetime.now(timezone.utc)


# ── Safe JSON type — works on SQLite and PostgreSQL ───────────
class JSONText(TypeDecorator):
    """
    Stores JSON as TEXT for SQLite compatibility.
    PostgreSQL users can switch to native JSON via migration.
    """
    impl = TEXT
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        try:
            return json.dumps(value, default=str)
        except Exception:
            return json.dumps(str(value))

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        try:
            return json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return value


class Base(DeclarativeBase):
    pass


# ── TENANT ────────────────────────────────────────────────────
class Tenant(Base):
    __tablename__ = "tenants"

    id = Column(String(64), primary_key=True, index=True, nullable=False)
    name = Column(String(256), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)

    users = relationship("User", back_populates="tenant", lazy="select")
    api_keys = relationship("APIKey", back_populates="tenant", lazy="select")
    subscriptions = relationship("Subscription", back_populates="tenant", uselist=False, lazy="select")
    usage_logs = relationship("UsageLog", back_populates="tenant", lazy="select")


# ── USER ──────────────────────────────────────────────────────
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String(64), ForeignKey("tenants.id", ondelete="CASCADE"), index=True, nullable=False)
    username = Column(String(64), unique=True, index=True, nullable=False)
    email = Column(String(254), unique=True, index=True, nullable=False)
    hashed_password = Column(String(256), nullable=False)
    role = Column(String(32), default="user", nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)

    tenant = relationship("Tenant", back_populates="users")
    api_keys = relationship("APIKey", back_populates="user", lazy="select")


# ── API KEY ───────────────────────────────────────────────────
class APIKey(Base):
    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String(64), ForeignKey("tenants.id", ondelete="CASCADE"), index=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    key = Column(String(128), unique=True, index=True, nullable=False)
    name = Column(String(64), default="default", nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    last_used_at = Column(DateTime, nullable=True)

    tenant = relationship("Tenant", back_populates="api_keys")
    user = relationship("User", back_populates="api_keys")


# ── SUBSCRIPTION ──────────────────────────────────────────────
class Subscription(Base):
    __tablename__ = "subscriptions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String(64), ForeignKey("tenants.id", ondelete="CASCADE"),
                       unique=True, index=True, nullable=False)
    plan = Column(String(32), default="free", nullable=False)
    credits = Column(Float, default=100.0, nullable=False)
    renewal_date = Column(DateTime, nullable=True)
    stripe_customer_id = Column(String(128), nullable=True)
    stripe_subscription_id = Column(String(128), nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)

    tenant = relationship("Tenant", back_populates="subscriptions")


# ── USAGE LOG ─────────────────────────────────────────────────
class UsageLog(Base):
    __tablename__ = "usage_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String(64), ForeignKey("tenants.id", ondelete="CASCADE"), index=True, nullable=False)
    user_id = Column(Integer, nullable=True)
    action = Column(String(128), nullable=False)
    tokens_used = Column(Integer, default=0, nullable=False)
    cost = Column(Float, default=0.0, nullable=False)
    metadata = Column(JSONText, nullable=True)
    timestamp = Column(DateTime, default=utcnow, nullable=False, index=True)

    tenant = relationship("Tenant", back_populates="usage_logs")


# ── TASK LOG ──────────────────────────────────────────────────
class TaskLog(Base):
    __tablename__ = "task_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    task_id = Column(String(64), unique=True, index=True, nullable=False)
    tenant_id = Column(String(64), ForeignKey("tenants.id", ondelete="SET NULL"), index=True, nullable=True)
    task_type = Column(String(64), nullable=False)
    prompt = Column(Text, nullable=True)
    status = Column(String(32), default="pending", nullable=False)
    result = Column(JSONText, nullable=True)
    error = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)

    __table_args__ = (Index("ix_task_logs_status", "status"),)


# ── THREAT LOG ────────────────────────────────────────────────
class ThreatLog(Base):
    __tablename__ = "threat_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_type = Column(String(64), nullable=False)
    target = Column(String(500), nullable=False)
    severity = Column(String(32), default="info", nullable=False, index=True)
    findings = Column(JSONText, nullable=True)
    raw_output = Column(Text, nullable=True)
    tenant_id = Column(String(64), ForeignKey("tenants.id", ondelete="SET NULL"), index=True, nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False, index=True)


# ── AGENT LOG ─────────────────────────────────────────────────
class AgentLog(Base):
    __tablename__ = "agent_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    agent_name = Column(String(64), nullable=False, index=True)
    task = Column(Text, nullable=True)
    result = Column(JSONText, nullable=True)
    success = Column(Boolean, default=True, nullable=False)
    duration_ms = Column(Integer, default=0, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)


# ── AUDIT LOG ─────────────────────────────────────────────────
class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String(64), ForeignKey("tenants.id", ondelete="SET NULL"), index=True, nullable=True)
    user_id = Column(Integer, nullable=True)
    action = Column(String(128), nullable=False)
    details = Column(JSONText, nullable=True)
    ip_address = Column(String(45), nullable=True)  # IPv6 max = 45 chars
    timestamp = Column(DateTime, default=utcnow, nullable=False, index=True)
