"""
config.py — loads runtime configuration from environment variables / .env
"""
import os
from dotenv import load_dotenv

load_dotenv()  # reads .env in the current working directory if present


def _require(name: str, default: str | None = None) -> str:
    val = os.getenv(name, default)
    if val is None:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return val


DATABASE_URL = _require("DATABASE_URL")

# NOTE: production should use RS256 with a real keypair (see .env.example).
# For local development this app falls back to HS256 with a shared secret
# so you don't need to generate a keypair just to run it locally.
JWT_SECRET = _require("JWT_SECRET", "local_dev_insecure_secret_change_me")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")

# Fernet key used to encrypt TOTP secrets at rest. Generate one with:
#   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
MFA_ENCRYPTION_KEY = _require(
    "MFA_ENCRYPTION_KEY", "2ssrszvBtzDOUCB6S3nw1ZFUwfdBaYfQkkRAKDHWPvA="
)

ENVIRONMENT = os.getenv("ENVIRONMENT", "development")