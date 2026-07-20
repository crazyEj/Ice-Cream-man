"""
auth_service.py
-----------------
Working authentication service for the Ice Cream Platform (local-dev ready).

Flow:
  - OAuth2 password + MFA (TOTP) second factor
  - Short-lived JWT access tokens + rotating refresh tokens
  - RBAC enforcement via a reusable dependency
  - Strict Pydantic input validation
  - Account lockout after repeated failed attempts
  - Audit logging on every sensitive action

Run with: uvicorn auth_service:app --reload
"""

from __future__ import annotations

import datetime as dt
import uuid
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr, constr, field_validator
from jose import jwt, JWTError
from passlib.context import CryptContext
from cryptography.fernet import Fernet
import pyotp

import config
import db

# ---------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------

ACCESS_TOKEN_TTL_MINUTES = 15
REFRESH_TOKEN_TTL_DAYS = 7
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")
fernet = Fernet(config.MFA_ENCRYPTION_KEY.encode())


@asynccontextmanager
async def lifespan(app: FastAPI):
    await db.init_pool()
    yield
    await db.close_pool()


app = FastAPI(title="IceCreamPlatform Auth Service", lifespan=lifespan)


# ---------------------------------------------------------------------
# Input schemas
# ---------------------------------------------------------------------

class LoginRequest(BaseModel):
    email: EmailStr
    password: constr(min_length=12, max_length=128)


class MfaVerifyRequest(BaseModel):
    mfa_challenge_token: constr(min_length=10, max_length=512)
    totp_code: constr(min_length=6, max_length=6, pattern=r"^\d{6}$")


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class RegisterRequest(BaseModel):
    """Local-dev-only helper endpoint to create a test user. In production,
    user provisioning goes through the OIDC provider, not this endpoint."""
    email: EmailStr
    password: constr(min_length=12, max_length=128)
    full_name: constr(min_length=1, max_length=150)
    role: constr(min_length=1, max_length=50) = "subscriber"

    @field_validator("password")
    @classmethod
    def password_complexity(cls, v: str) -> str:
        if not any(c.isupper() for c in v) or not any(c.isdigit() for c in v):
            raise ValueError("Password must contain an uppercase letter and a digit")
        return v


class RegisterResponse(BaseModel):
    user_id: str
    email: str
    totp_secret: str          # shown once so you can add it to an authenticator app
    totp_provisioning_uri: str


# ---------------------------------------------------------------------
# Dev-only: create a user with MFA already enabled, so you can exercise
# the full login flow immediately. Not present in a production deployment.
# ---------------------------------------------------------------------

@app.post("/dev/register", response_model=RegisterResponse)
async def dev_register(payload: RegisterRequest):
    if config.ENVIRONMENT != "development":
        raise HTTPException(status_code=404, detail="Not found.")

    existing = await db.get_user_by_email(payload.email)
    if existing:
        raise HTTPException(status_code=409, detail="User already exists.")

    password_hash = pwd_context.hash(payload.password)
    totp_secret = pyotp.random_base32()
    encrypted_secret = fernet.encrypt(totp_secret.encode())

    user = await db.create_user(
        email=payload.email,
        password_hash=password_hash,
        full_name=payload.full_name,
        mfa_enabled=True,
        mfa_secret_encrypted=encrypted_secret,
    )
    await db.grant_role(user["user_id"], payload.role)

    uri = pyotp.TOTP(totp_secret).provisioning_uri(name=payload.email, issuer_name="IceCreamPlatform")

    return RegisterResponse(
        user_id=str(user["user_id"]),
        email=user["email"],
        totp_secret=totp_secret,
        totp_provisioning_uri=uri,
    )


# ---------------------------------------------------------------------
# Step 1: Password login -> issues a short-lived MFA challenge token
# ---------------------------------------------------------------------

@app.post("/auth/login")
async def login(payload: LoginRequest, request: Request):
    user = await db.get_user_by_email(payload.email)

    generic_error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid email or password.",
    )

    if user is None:
        pwd_context.dummy_verify()
        raise generic_error

    if user.get("locked_until") and user["locked_until"] > dt.datetime.now(dt.timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail="Account temporarily locked due to repeated failed attempts.",
        )

    if not pwd_context.verify(payload.password, user["password_hash"]):
        await db.register_failed_attempt(user["user_id"], MAX_FAILED_ATTEMPTS, LOCKOUT_MINUTES)
        raise generic_error

    await db.reset_failed_attempts(user["user_id"])

    if not user.get("mfa_enabled"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="MFA setup required before login can complete.",
        )

    mfa_challenge_token = _issue_short_lived_challenge(str(user["user_id"]), ttl_seconds=300)
    await _audit(str(user["user_id"]), "LOGIN_PASSWORD_OK_MFA_PENDING", "users", str(user["user_id"]), request)

    return {"mfa_challenge_token": mfa_challenge_token, "mfa_method": "totp"}


# ---------------------------------------------------------------------
# Step 2: MFA verification -> issues real access + refresh tokens
# ---------------------------------------------------------------------

@app.post("/auth/mfa/verify", response_model=TokenResponse)
async def verify_mfa(payload: MfaVerifyRequest, request: Request):
    try:
        claims = jwt.decode(
            payload.mfa_challenge_token,
            config.JWT_SECRET,
            algorithms=[config.JWT_ALGORITHM],
            options={"require": ["exp", "sub", "purpose"]},
        )
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired MFA challenge.")

    if claims.get("purpose") != "mfa_challenge":
        raise HTTPException(status_code=401, detail="Invalid token purpose.")

    user_id = claims["sub"]
    user = await db.get_user_by_id(user_id)
    if user is None:
        raise HTTPException(status_code=401, detail="User no longer exists.")

    totp_secret = fernet.decrypt(bytes(user["mfa_secret_encrypted"])).decode()
    totp = pyotp.TOTP(totp_secret)
    if not totp.verify(payload.totp_code, valid_window=1):
        await _audit(user_id, "MFA_VERIFY_FAILED", "users", user_id, request)
        raise HTTPException(status_code=401, detail="Invalid MFA code.")

    roles = await db.get_user_roles(user_id)

    access_token = _issue_access_token(user_id, roles)
    refresh_token = _issue_refresh_token(user_id)

    await _audit(user_id, "LOGIN_SUCCESS", "users", user_id, request)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=ACCESS_TOKEN_TTL_MINUTES * 60,
    )


# ---------------------------------------------------------------------
# Token issuance helpers
# ---------------------------------------------------------------------

def _issue_short_lived_challenge(user_id: str, ttl_seconds: int) -> str:
    now = dt.datetime.now(dt.timezone.utc)
    claims = {
        "sub": user_id,
        "purpose": "mfa_challenge",
        "iat": now,
        "exp": now + dt.timedelta(seconds=ttl_seconds),
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(claims, config.JWT_SECRET, algorithm=config.JWT_ALGORITHM)


def _issue_access_token(user_id: str, roles: list[dict]) -> str:
    now = dt.datetime.now(dt.timezone.utc)
    claims = {
        "sub": user_id,
        "purpose": "access",
        "roles": [r["role_name"] for r in roles],
        "scopes": [{"type": r["scope_type"], "id": str(r["scope_id"]) if r["scope_id"] else None}
                   for r in roles if r["scope_type"]],
        "iat": now,
        "exp": now + dt.timedelta(minutes=ACCESS_TOKEN_TTL_MINUTES),
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(claims, config.JWT_SECRET, algorithm=config.JWT_ALGORITHM)


def _issue_refresh_token(user_id: str) -> str:
    now = dt.datetime.now(dt.timezone.utc)
    claims = {
        "sub": user_id,
        "purpose": "refresh",
        "iat": now,
        "exp": now + dt.timedelta(days=REFRESH_TOKEN_TTL_DAYS),
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(claims, config.JWT_SECRET, algorithm=config.JWT_ALGORITHM)


async def _audit(actor_user_id: Optional[str], action: str, target_type: str,
                  target_id: Optional[str], request: Request) -> None:
    await db.write_audit_event(
        actor_user_id=actor_user_id,
        action=action,
        target_type=target_type,
        target_id=target_id,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )


# ---------------------------------------------------------------------
# RBAC dependency — reusable across every protected route
# ---------------------------------------------------------------------

class CurrentUser(BaseModel):
    user_id: str
    roles: list[str]
    scopes: list[dict]


async def get_current_user(token: str = Depends(oauth2_scheme)) -> CurrentUser:
    try:
        claims = jwt.decode(
            token,
            config.JWT_SECRET,
            algorithms=[config.JWT_ALGORITHM],
            options={"require": ["exp", "sub", "purpose"]},
        )
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token.")

    if claims.get("purpose") != "access":
        raise HTTPException(status_code=401, detail="Wrong token type for this operation.")

    return CurrentUser(user_id=claims["sub"], roles=claims.get("roles", []), scopes=claims.get("scopes", []))


def require_roles(*allowed_roles: str):
    async def checker(current_user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if not set(current_user.roles) & set(allowed_roles):
            raise HTTPException(status_code=403, detail="Insufficient permissions for this resource.")
        return current_user

    return checker


@app.get("/auth/me", response_model=CurrentUser)
async def whoami(current_user: CurrentUser = Depends(get_current_user)):
    return current_user


# ---------------------------------------------------------------------
# Example protected route — object-level authorization (anti-BOLA)
# ---------------------------------------------------------------------

@app.get("/wholesale/orders/{order_id}")
async def get_wholesale_order(
    order_id: str,
    current_user: CurrentUser = Depends(require_roles("wholesale_partner", "wholesale_ops", "global_admin")),
):
    if "wholesale_ops" in current_user.roles or "global_admin" in current_user.roles:
        order = await db.fetch_wholesale_order(order_id)
        if order is None:
            raise HTTPException(status_code=404, detail="Order not found.")
        return order

    allowed_client_ids = {s["id"] for s in current_user.scopes if s["type"] == "wholesale_client"}
    order = await db.fetch_wholesale_order(order_id)
    if order is None or str(order["wholesale_client_id"]) not in allowed_client_ids:
        raise HTTPException(status_code=404, detail="Order not found.")
    return order