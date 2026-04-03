# ============================================================
# CYBERDUDEBIVASH AI — API SCHEMAS (HARDENED)
# Fixes: input length limits, strict validation, secure defaults
# ============================================================

from pydantic import BaseModel, Field, field_validator
from typing import Any, Dict, List, Optional
from datetime import datetime
import re


# ── Auth ──────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=64)
    password: str = Field(..., min_length=8, max_length=128)

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int

class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=64, pattern=r"^[a-zA-Z0-9_-]+$")
    email: str = Field(..., max_length=254)
    password: str = Field(..., min_length=8, max_length=128)
    tenant_id: str = Field(default="default", max_length=64)
    role: str = Field(default="user", pattern=r"^(user|admin)$")

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", v):
            raise ValueError("Invalid email format")
        return v.lower().strip()

class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    role: str
    tenant_id: str
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


# ── Task ─────────────────────────────────────────────────────
class TaskRequest(BaseModel):
    task: str = Field(..., min_length=3, max_length=10000)
    agent: Optional[str] = Field(default=None, max_length=64)
    priority: str = Field(default="normal", pattern=r"^(low|normal|high)$")
    metadata: Optional[Dict[str, Any]] = None

class TaskResponse(BaseModel):
    task_id: str
    status: str
    message: str
    queue: str = "ai_tasks"

class TaskStatusResponse(BaseModel):
    task_id: str
    status: str
    result: Optional[Any] = None
    error: Optional[str] = None


# ── Cybersecurity ─────────────────────────────────────────────
class ThreatIntelRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=500,
                        description="IP, domain, hash, URL, or CVE")
    type: Optional[str] = Field(default=None, max_length=50)
    context: Optional[str] = Field(default=None, max_length=1000)

    @field_validator("target")
    @classmethod
    def sanitize_target(cls, v: str) -> str:
        return v.strip()

class VulnScanRequest(BaseModel):
    cve_id: Optional[str] = Field(default=None, max_length=30,
                                   pattern=r"^(CVE-\d{4}-\d{4,})?$")
    software: Optional[str] = Field(default=None, max_length=200)
    version: Optional[str] = Field(default=None, max_length=50)
    description: Optional[str] = Field(default=None, max_length=2000)

class MalwareRequest(BaseModel):
    sample: str = Field(..., min_length=1, max_length=500)
    sample_type: str = Field(default="hash", pattern=r"^(hash|filename|url|behavior)$")
    behavior: Optional[str] = Field(default=None, max_length=2000)

class OSINTRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=500)
    target_type: str = Field(
        default="organization",
        pattern=r"^(organization|domain|person|ip_range)$"
    )

class SecurityAuditRequest(BaseModel):
    code: str = Field(..., min_length=1, max_length=50000,  # 50KB max — Fix #18
                      description="Code or config to audit (max 50KB)")
    language: str = Field(
        default="python",
        pattern=r"^(python|javascript|typescript|go|java|php|ruby|bash|yaml|json|sql)$"
    )
    audit_type: str = Field(default="code", pattern=r"^(code|config|dockerfile|terraform)$")

class CyberTaskResponse(BaseModel):
    execution_id: str
    task: str
    status: str
    duration_seconds: float
    results: List[Any]
    agents_used: List[str]


# ── Swarm ─────────────────────────────────────────────────────
class SwarmRequest(BaseModel):
    task: str = Field(..., min_length=3, max_length=5000)
    target: Optional[str] = Field(default=None, max_length=500)
    agents: Optional[List[str]] = Field(default=None, max_items=10)
    parallel: bool = False


# ── Generate ─────────────────────────────────────────────────
class GenerateRequest(BaseModel):
    prompt: str = Field(..., min_length=5, max_length=10000)
    tenant_id: str = Field(default="default", max_length=64)
    mode: str = Field(default="general", pattern=r"^(general|code|cyber|threat_intel)$")
    metadata: Optional[Dict[str, Any]] = None

class GenerateResponse(BaseModel):
    task_id: str
    status: str
    message: str


# ── System ───────────────────────────────────────────────────
class HealthResponse(BaseModel):
    status: str
    timestamp: datetime
    version: str
    components: Dict[str, str]

class MemoryStatsResponse(BaseModel):
    total_entries: int
    size_bytes: int
    memory_file: str
