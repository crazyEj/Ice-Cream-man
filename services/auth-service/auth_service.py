"""
auth_service.py
-----------------
Boilerplate secure authentication endpoint set for the Ice Cream Platform.

Demonstrates:
  - OAuth2 password + MFA (TOTP) second factor
  - Short-lived JWT access tokens + rotating refresh tokens
  - RBAC enforcement via a reusable dependency
  - Strict Pydantic input validation (the Python analogue of Zod/Joi)
  - Account lockout after repeated failed attempts (brute-force mitigation)
  - Audit logging hook on every sensitive action

Run with: uvicorn auth_service:app --reload
Requires: fastapi, uvicorn, pydantic, python-jose[cryptography], passlib[argon2], pyotp, asyncpg
"""

from __future__ import annotations

import datetime as dt
import uuid
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr, constr, field_validator
from jose import jwt, JWTError
from passlib.context import CryptContext
import pyotp

# ---------------------------------------------------------------------
# Config (in production: pull from a secrets manager, never hardcode)
# ---------------------------------------------------------------------

JWT_SECRET = "__LOAD_FROM_SECRETS_MANAGER__"          # e.g. AWS Secrets Manager / GCP Secret Manager
JWT_ALGORITHM = "RS256"                                  # prefer asymmetric signing (RS256) over HS256
ACCESS_TOKEN_TTL_MINUTES = 15                            # short-lived by design
REFRESH_TOKEN_TTL_DAYS = 7
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")   # argon2id > bcrypt for new systems
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

app = FastAPI(title="IceCreamPlatform Auth Service")


# ---------------------------------------------------------------------
# Strict input schemas (equivalent role to Zod/Joi on the Node side)
# ---------------------------------------------------------------------

class LoginRequest(BaseModel):
    email: EmailStr
    password: constr(min_length=12, max_length=128)

    @field_validator("password")
    @classmethod
    def password_complexity(cls, v: str) -> str:
        if not any(c.isupper() for c in v) or not any(c.isdigit() for c in v):
            raise ValueError("Password must contain an uppercase letter and a digit")
        return v


class MfaVerifyRequest(BaseModel):
    mfa_challenge_token: constr(min_length=10, max_length=512)
    totp_code: constr(min_length=6, max_length=6, pattern=r"^\d{6}$")


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


# ---------------------------------------------------------------------
# Simulated data-access layer
# In production these are parameterized queries via an ORM / query
# builder (SQLAlchemy, asyncpg with $1 placeholders) — NEVER raw string
# concatenation, which is how SQL injection happens.
# ---------------------------------------------------------------------

async def get_user_by_email(email: str) -> Optional[dict]:
    """Placeholder — replace with a parameterized query, e.g.:
    await conn.fetchrow("SELECT * FROM users WHERE email = $1", email)
    """
    raise NotImplementedError


async def record_audit_event(actor_user_id: Optional[str], action: str,
                              target_type: str, target_id: Optional[str],
                              request: Request) -> None:
    """Fire-and-forget onto a queue (SQS/PubSub) in production so it never
    blocks the auth path; still guaranteed via DLQ + retry consumer."""
    _ = {
        "actor_user_id": actor_user_id,
        "action": action,
        "target_entity_type": target_type,
        "target_entity_id": target_id,
        "ip_address": request.client.host if request.client else None,
        "user_agent": request.headers.get("user-agent"),
        "created_at": dt.datetime.utcnow().isoformat(),
    }
    # await audit_queue.publish(_)


# ---------------------------------------------------------------------
# Step 1: Password login -> issues a short-lived MFA challenge token
# (NOT a full access token) if credentials are valid.
# ---------------------------------------------------------------------

@app.post("/auth/login", response_model=dict, status_code=status.HTTP_200_OK)
async def login(payload: LoginRequest, request: Request):
    user = await get_user_by_email(payload.email)

    # Constant-shape response whether the user exists or not, to avoid
    # user-enumeration via response timing/content differences.
    generic_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid email or password.",
    )

    if user is None:
        pwd_context.dummy_verify()  # burn equivalent CPU time to avoid timing side-channel
        raise generic_error

    if user.get("locked_until") and user["locked_until"] > dt.datetime.utcnow():
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail="Account temporarily locked due to repeated failed attempts.",
        )

    if not pwd_context.verify(payload.password, user["password_hash"]):
        await _register_failed_attempt(user)
        raise generic_error

    if not user.get("mfa_enabled"):
        # Platform policy: MFA is mandatory for all staff/admin/wholesale roles.
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="MFA setup required before login can complete.",
        )

    mfa_challenge_token = _issue_short_lived_challenge(user["user_id"], ttl_seconds=300)
    await record_audit_event(user["user_id"], "LOGIN_PASSWORD_OK_MFA_PENDING", "users", user["user_id"], request)

    return {"mfa_challenge_token": mfa_challenge_token, "mfa_method": "totp"}


# ---------------------------------------------------------------------
# Step 2: MFA verification -> issues real access + refresh tokens
# ---------------------------------------------------------------------

@app.post("/auth/mfa/verify", response_model=TokenResponse)
async def verify_mfa(payload: MfaVerifyRequest, request: Request):
    try:
        claims = jwt.decode(
            payload.mfa_challenge_token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],
            options={"require": ["exp", "sub", "purpose"]},
        )
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired MFA challenge.")

    if claims.get("purpose") != "mfa_challenge":
        raise HTTPException(status_code=401, detail="Invalid token purpose.")

    user_id = claims["sub"]
    user = await get_user_by_id(user_id)  # implement alongside get_user_by_email

    totp = pyotp.TOTP(_decrypt_mfa_secret(user["mfa_secret_encrypted"]))
    if not totp.verify(payload.totp_code, valid_window=1):
        await record_audit_event(user_id, "MFA_VERIFY_FAILED", "users", user_id, request)
        raise HTTPException(status_code=401, detail="Invalid MFA code.")

    roles = await get_user_roles(user_id)   # [{role_name, scope_type, scope_id}, ...]

    access_token = _issue_access_token(user_id, roles)
    refresh_token = _issue_refresh_token(user_id)

    await record_audit_event(user_id, "LOGIN_SUCCESS", "users", user_id, request)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=ACCESS_TOKEN_TTL_MINUTES * 60,
    )


# ---------------------------------------------------------------------
# Token issuance helpers
# ---------------------------------------------------------------------

def _issue_short_lived_challenge(user_id: str, ttl_seconds: int) -> str:
    now = dt.datetime.utcnow()
    claims = {
        "sub": user_id,
        "purpose": "mfa_challenge",
        "iat": now,
        "exp": now + dt.timedelta(seconds=ttl_seconds),
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(claims, JWT_SECRET, algorithm=JWT_ALGORITHM)


def _issue_access_token(user_id: str, roles: list[dict]) -> str:
    now = dt.datetime.utcnow()
    claims = {
        "sub": user_id,
        "purpose": "access",
        "roles": [r["role_name"] for r in roles],
        # scope claims let services enforce row-level isolation (e.g. wholesale_client_id)
        "scopes": [{"type": r["scope_type"], "id": r["scope_id"]} for r in roles if r["scope_type"]],
        "iat": now,
        "exp": now + dt.timedelta(minutes=ACCESS_TOKEN_TTL_MINUTES),
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(claims, JWT_SECRET, algorithm=JWT_ALGORITHM)


def _issue_refresh_token(user_id: str) -> str:
    now = dt.datetime.utcnow()
    claims = {
        "sub": user_id,
        "purpose": "refresh",
        "iat": now,
        "exp": now + dt.timedelta(days=REFRESH_TOKEN_TTL_DAYS),
        "jti": str(uuid.uuid4()),   # store jti server-side to allow revocation / rotation detection
    }
    return jwt.encode(claims, JWT_SECRET, algorithm=JWT_ALGORITHM)


async def _register_failed_attempt(user: dict) -> None:
    """Increment failed_login_attempts; lock account after threshold.
    Implement as: UPDATE users SET failed_login_attempts = failed_login_attempts + 1,
    locked_until = CASE WHEN failed_login_attempts + 1 >= $1 THEN now() + interval '15 minutes' END
    WHERE user_id = $2
    """
    raise NotImplementedError


async def get_user_by_id(user_id: str) -> dict:
    raise NotImplementedError


async def get_user_roles(user_id: str) -> list[dict]:
    raise NotImplementedError


def _decrypt_mfa_secret(encrypted_secret: bytes) -> str:
    """Decrypt using an envelope-encryption pattern: data key wrapped by KMS.
    Never store or log the plaintext TOTP secret."""
    raise NotImplementedError


# ---------------------------------------------------------------------
# RBAC dependency — reusable across every protected route in every
# service (POS, Wholesale, Catering, Subscription)
# ---------------------------------------------------------------------

class CurrentUser(BaseModel):
    user_id: str
    roles: list[str]
    scopes: list[dict]


async def get_current_user(token: str = Depends(oauth2_scheme)) -> CurrentUser:
    try:
        claims = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],
            options={"require": ["exp", "sub", "purpose"]},
        )
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token.")

    if claims.get("purpose") != "access":
        raise HTTPException(status_code=401, detail="Wrong token type for this operation.")

    return CurrentUser(user_id=claims["sub"], roles=claims.get("roles", []), scopes=claims.get("scopes", []))


def require_roles(*allowed_roles: str):
    """Usage: @app.get('/wholesale/orders', dependencies=[Depends(require_roles('wholesale_partner','wholesale_ops','global_admin'))])"""

    async def checker(current_user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if not set(current_user.roles) & set(allowed_roles):
            raise HTTPException(status_code=403, detail="Insufficient permissions for this resource.")
        return current_user

    return checker


# ---------------------------------------------------------------------
# Example protected route showing object-level authorization (anti-BOLA)
# A wholesale_partner may only ever see their OWN client's orders — the
# scope check happens server-side, never trusting a client-supplied ID alone.
# ---------------------------------------------------------------------

@app.get("/wholesale/orders/{order_id}")
async def get_wholesale_order(
    order_id: str,
    current_user: CurrentUser = Depends(require_roles("wholesale_partner", "wholesale_ops", "global_admin")),
):
    if "wholesale_ops" in current_user.roles or "global_admin" in current_user.roles:
        pass  # internal roles may access any client's orders
    else:
        allowed_client_ids = {s["id"] for s in current_user.scopes if s["type"] == "wholesale_client"}
        order = await _fetch_order(order_id)  # implement with parameterized query
        if order is None or order["wholesale_client_id"] not in allowed_client_ids:
            # Return 404, not 403, to avoid leaking existence of other tenants' resources
            raise HTTPException(status_code=404, detail="Order not found.")

    return await _fetch_order(order_id)


async def _fetch_order(order_id: str) -> Optional[dict]:
    raise NotImplementedError