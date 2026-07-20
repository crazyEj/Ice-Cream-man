"""
db.py — asyncpg connection pool + parameterized queries against the schema
in database/schema.sql. Every query uses $1/$2 placeholders, never string
concatenation, to prevent SQL injection.
"""
from __future__ import annotations

import asyncpg
from typing import Optional

import config

_pool: Optional[asyncpg.Pool] = None


async def init_pool() -> None:
    global _pool
    _pool = await asyncpg.create_pool(config.DATABASE_URL, min_size=1, max_size=10)


async def close_pool() -> None:
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None


def pool() -> asyncpg.Pool:
    if _pool is None:
        raise RuntimeError("DB pool not initialized — call init_pool() on startup.")
    return _pool


async def get_user_by_email(email: str) -> Optional[dict]:
    row = await pool().fetchrow(
        "SELECT * FROM users WHERE email = $1", email
    )
    return dict(row) if row else None


async def get_user_by_id(user_id: str) -> Optional[dict]:
    row = await pool().fetchrow(
        "SELECT * FROM users WHERE user_id = $1", user_id
    )
    return dict(row) if row else None


async def get_user_roles(user_id: str) -> list[dict]:
    rows = await pool().fetch(
        """
        SELECT r.role_name, ur.scope_type, ur.scope_id
        FROM user_roles ur
        JOIN roles r ON r.role_id = ur.role_id
        WHERE ur.user_id = $1
        """,
        user_id,
    )
    return [dict(r) for r in rows]


async def register_failed_attempt(user_id: str, max_attempts: int, lockout_minutes: int) -> None:
    await pool().execute(
        """
        UPDATE users
        SET failed_login_attempts = failed_login_attempts + 1,
            locked_until = CASE
                WHEN failed_login_attempts + 1 >= $2
                THEN now() + ($3 || ' minutes')::interval
                ELSE locked_until
            END
        WHERE user_id = $1
        """,
        user_id, max_attempts, str(lockout_minutes),
    )


async def reset_failed_attempts(user_id: str) -> None:
    await pool().execute(
        "UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE user_id = $1",
        user_id,
    )


async def fetch_wholesale_order(order_id: str) -> Optional[dict]:
    row = await pool().fetchrow(
        "SELECT * FROM wholesale_orders WHERE order_id = $1", order_id
    )
    return dict(row) if row else None


async def create_user(
    email: str, password_hash: str, full_name: str,
    mfa_enabled: bool, mfa_secret_encrypted: Optional[bytes],
) -> dict:
    row = await pool().fetchrow(
        """
        INSERT INTO users (email, password_hash, full_name, mfa_enabled, mfa_secret_encrypted)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING *
        """,
        email, password_hash, full_name, mfa_enabled, mfa_secret_encrypted,
    )
    return dict(row)


async def grant_role(user_id: str, role_name: str) -> None:
    await pool().execute(
        """
        INSERT INTO user_roles (user_id, role_id)
        SELECT $1, role_id FROM roles WHERE role_name = $2
        """,
        user_id, role_name,
    )


async def write_audit_event(
    actor_user_id: Optional[str], action: str, target_type: str,
    target_id: Optional[str], ip_address: Optional[str], user_agent: Optional[str],
) -> None:
    await pool().execute(
        """
        INSERT INTO audit_logs (actor_user_id, action, target_entity_type, target_entity_id, ip_address, user_agent)
        VALUES ($1, $2, $3, $4, $5::inet, $6)
        """,
        actor_user_id, action, target_type, target_id, ip_address, user_agent,
    )