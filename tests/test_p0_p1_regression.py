"""
CYBERDUDEBIVASH(R) AI SECURITY HUB — P0/P1 Regression Guard
==========================================================
Locks in the production-stabilization fixes so this class of failure can
never silently reach production again. Each test maps to a proven defect:

  P0  ai-core/core/settings.py        — undefined _DEFAULT_SECRET_SENTINEL
                                         (NameError on import of central settings)
  P1  agents/core/orchestrator.py     — orphaned SQL / IndentationError
  P1  agents/__init__.py              — wrong import path (.core.registry)
  P1  api/main.py                     — await outside async function

It also enforces a repository-wide byte-compile, which is the gate that the
previous CI (a hardcoded 7-file py_compile list) lacked — the reason the
P0/P1 defects shipped while CI stayed green.

Run: pytest tests/test_p0_p1_regression.py -v
"""
from __future__ import annotations

import compileall
import os
import secrets
import sys
import warnings

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AI_CORE = os.path.join(REPO_ROOT, "ai-core")
MULTI_AGENT = os.path.join(REPO_ROOT, "multi-agent-os")

# Directories excluded from the repo-wide compile scan (not first-party source).
_EXCLUDE_DIRS = {".git", "node_modules", "__pycache__", ".wrangler", "dist", "build", ".venv"}

pydantic_settings = pytest.importorskip(
    "pydantic_settings",
    reason="pydantic-settings required to validate central settings import",
)


def _iter_py_files(root: str):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _EXCLUDE_DIRS]
        for fn in filenames:
            if fn.endswith(".py"):
                yield os.path.join(dirpath, fn)


# ─────────────────────────────────────────────────────────────────────────────
# Repository-wide compile gate (the missing CI guard)
# ─────────────────────────────────────────────────────────────────────────────
def test_repository_wide_byte_compile():
    """Every first-party .py file must byte-compile.

    This is the regression guard for the CI false-positive: a syntax/compile
    error (IndentationError, 'await' outside async, etc.) anywhere in the tree
    must fail the build, not just in a hardcoded file list.
    """
    failures = []
    for path in _iter_py_files(REPO_ROOT):
        try:
            with open(path, "rb") as fh:
                compile(fh.read(), path, "exec")
        except SyntaxError as exc:  # noqa: PERF203
            failures.append(f"{os.path.relpath(path, REPO_ROOT)}: {exc}")
    assert not failures, "Files failed to compile:\n" + "\n".join(failures)


# ─────────────────────────────────────────────────────────────────────────────
# P0 — central settings module
# ─────────────────────────────────────────────────────────────────────────────
@pytest.fixture()
def _ai_core_on_path():
    added = AI_CORE not in sys.path
    if added:
        sys.path.insert(0, AI_CORE)
    # Ensure a clean import each time.
    for mod in [m for m in list(sys.modules) if m == "core" or m.startswith("core.")]:
        del sys.modules[mod]
    try:
        yield
    finally:
        if added and AI_CORE in sys.path:
            sys.path.remove(AI_CORE)
        for mod in [m for m in list(sys.modules) if m == "core" or m.startswith("core.")]:
            del sys.modules[mod]


def test_settings_sentinel_symbol_defined(_ai_core_on_path, monkeypatch):
    """The sentinel referenced by the validator/default must actually exist.

    Regression for the P0 NameError: before the fix, importing this module
    raised ``NameError: name '_DEFAULT_SECRET_SENTINEL' is not defined``.
    """
    monkeypatch.setenv("SECRET_KEY", secrets.token_hex(32))  # allow import to complete
    monkeypatch.setenv("APP_ENV", "production")
    import importlib

    mod = importlib.import_module("core.settings")
    assert hasattr(mod, "_DEFAULT_SECRET_SENTINEL"), "_DEFAULT_SECRET_SENTINEL missing"
    # Backward-compatible alias must remain.
    assert mod._WEAK_SECRET == mod._DEFAULT_SECRET_SENTINEL


def test_settings_imports_and_starts_with_valid_secret(_ai_core_on_path, monkeypatch):
    """Production startup succeeds when a strong SECRET_KEY is provided."""
    monkeypatch.setenv("SECRET_KEY", secrets.token_hex(32))
    monkeypatch.setenv("APP_ENV", "production")
    import importlib

    settings_mod = importlib.import_module("core.settings")
    cfg = settings_mod.get_settings()
    assert cfg.app_name == "CYBERDUDEBIVASH AI SYSTEM"
    assert cfg.is_production is True
    # lru_cache identity.
    assert settings_mod.get_settings() is cfg


def test_settings_fail_closed_without_secret(_ai_core_on_path, monkeypatch):
    """Fail-closed: a missing/weak SECRET_KEY must raise, never run insecurely.

    The module instantiates ``settings = get_settings()`` at import, so the
    failure surfaces at import time — exactly the desired fail-closed posture.
    """
    monkeypatch.delenv("SECRET_KEY", raising=False)
    monkeypatch.setenv("APP_ENV", "production")
    import importlib

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        with pytest.raises(Exception):
            importlib.import_module("core.settings")


def test_settings_rejects_short_secret(_ai_core_on_path, monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "tooshort")
    monkeypatch.setenv("APP_ENV", "production")
    import importlib

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        with pytest.raises(Exception):
            importlib.import_module("core.settings")


# ─────────────────────────────────────────────────────────────────────────────
# P1 — multi-agent orchestrator + agents package
# ─────────────────────────────────────────────────────────────────────────────
@pytest.fixture()
def _multi_agent_on_path():
    added = MULTI_AGENT not in sys.path
    if added:
        sys.path.insert(0, MULTI_AGENT)
    try:
        yield
    finally:
        if added and MULTI_AGENT in sys.path:
            sys.path.remove(MULTI_AGENT)


def test_orchestrator_methods_present(_multi_agent_on_path):
    from agents.core.orchestrator import MasterOrchestrator, INTENT_ROUTING

    for name in ("_persist_audit", "get_diagnostics", "orchestrate"):
        assert hasattr(MasterOrchestrator, name), f"{name} missing"
    assert len(INTENT_ROUTING) > 50  # routing table intact


def test_agents_package_imports(_multi_agent_on_path):
    """The whole agents package (50+ specialists) must import — proves the
    orchestrator orphan and the registry import-path defects are gone."""
    import importlib

    agents = importlib.import_module("agents")
    assert hasattr(agents, "MasterOrchestrator")
    assert hasattr(agents, "AgentRegistry")


def test_persist_audit_is_noop_without_pool(_multi_agent_on_path):
    import asyncio

    from agents.core.orchestrator import MasterOrchestrator

    orch = MasterOrchestrator.__new__(MasterOrchestrator)
    orch.registry = type("R", (), {"count": lambda self: 0})()
    orch.db = None  # no pool configured

    class _QR:
        overall_score = 99.0

    # Must complete without raising (best-effort persistence).
    asyncio.run(orch._persist_audit("id", "t", "u", "intent", ["a"], _QR(), 1.0, True))


# ─────────────────────────────────────────────────────────────────────────────
# Container-boot guards (skip unless the full runtime deps are installed —
# they run in the verify-runtime-integrity CI job which installs requirements.txt)
# ─────────────────────────────────────────────────────────────────────────────
def test_orm_models_map_cleanly(_ai_core_on_path, monkeypatch):
    """SQLAlchemy models must map without reserved-attribute errors.

    Regression for: UsageLog defined an attribute named 'metadata', which is
    reserved by the Declarative API and raised InvalidRequestError on import.
    """
    pytest.importorskip("sqlalchemy")
    monkeypatch.setenv("SECRET_KEY", secrets.token_hex(32))
    monkeypatch.setenv("APP_ENV", "production")
    import importlib

    models = importlib.import_module("core.database.models")
    # Reserved name was remapped to a safe attribute over the same DB column.
    assert hasattr(models.UsageLog, "event_metadata")
    assert models.UsageLog.__table__.c.metadata.name == "metadata"  # DB column unchanged


def test_container_app_boots_and_health_ok(monkeypatch):
    """generated_app.main:app (the container CMD target) must import and its
    /health endpoint must return 200 — proves the container can boot.

    Skips unless fastapi + full deps are present (verify-runtime-integrity CI).
    """
    pytest.importorskip("fastapi")
    pytest.importorskip("sqlalchemy")
    monkeypatch.setenv("SECRET_KEY", secrets.token_hex(32))
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("PAYMENT_ADMIN_SECRET", secrets.token_hex(32))
    for p in (REPO_ROOT, AI_CORE):
        if p not in sys.path:
            sys.path.insert(0, p)
    # Clear any cached core.* and generated_app.* modules so monkeypatched
    # env vars are visible on the fresh import.
    for mod in list(sys.modules):
        if mod == "core" or mod.startswith("core.") or \
                mod == "generated_app" or mod.startswith("generated_app."):
            del sys.modules[mod]

    import importlib

    main = importlib.import_module("generated_app.main")
    paths = {r.path for r in main.app.routes if hasattr(r, "path")}
    assert "/health" in paths

    from starlette.testclient import TestClient

    with TestClient(main.app) as client:
        assert client.get("/health").status_code == 200
