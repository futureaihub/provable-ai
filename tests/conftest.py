"""
pytest conftest — sets ALL env vars BEFORE any module is imported.

Python executes module-level code at import time. server/auth.py loads
_API_KEYS from ZORYNEX_API_KEYS when first imported. If the env var is not
set before the import, you get the default "dev-key:admin" only — and every
test that uses "audit-key" or "sys-key" gets 401.

This conftest is the ONLY correct place to set env vars for tests.
Never set os.environ inside the test file after imports.
"""
import os

# Must be first — before any server.* import happens
os.environ["ZORYNEX_API_KEYS"]       = "admin-key:admin,audit-key:auditor,sys-key:system"
os.environ["ZORYNEX_WEBHOOK_SECRET"] = "test-secret-zorynex-session2"
os.environ["ZORYNEX_DATABASE_URL"]   = "postgresql+asyncpg://zorynex:zorynex@localhost:5432/zorynex_test"
os.environ["ZORYNEX_REQUIRE_TENANT"] = "true"