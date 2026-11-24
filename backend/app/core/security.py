"""Password hashing and session tokens.

PASSWORDS
  We never store a password. We store an Argon2id *hash*: a one-way
  fingerprint. At login we hash what the user typed and compare. Argon2 is
  deliberately slow and memory-hungry, so an attacker who steals the database
  cannot cheaply try billions of guesses. Each hash includes a random salt,
  so two users with the same password get different hashes.

TOKENS (JWT)
  After a successful login the server issues a signed token saying
  "user 7, role analyst, valid until 10:30". The signature (HMAC-SHA256 with
  SECRET_KEY) means the token cannot be modified without the server noticing.
  The token travels in an HttpOnly cookie (see api/v1/auth.py).
"""

import secrets
import uuid
from datetime import UTC, datetime, timedelta

import jwt
from pwdlib import PasswordHash

from app.core.config import get_settings

# PasswordHash.recommended() = Argon2id with current recommended parameters.
_password_hash = PasswordHash.recommended()

# A real hash of a random value. Used when a username does not exist, so the
# login takes the same time either way (prevents "timing" username discovery).
_DUMMY_HASH = _password_hash.hash(secrets.token_urlsafe(16))

JWT_ALGORITHM = "HS256"


def hash_password(password: str) -> str:
    return _password_hash.hash(password)


def verify_password(password: str, password_hash: str | None) -> bool:
    """Check a password. Pass None for unknown users to keep timing constant."""
    if password_hash is None:
        _password_hash.verify(password, _DUMMY_HASH)
        return False
    return _password_hash.verify(password, password_hash)


def create_access_token(user_id: int, role: str, token_version: int) -> tuple[str, int]:
    """Create a signed JWT. Returns (token, lifetime_in_seconds)."""
    settings = get_settings()
    now = datetime.now(UTC)
    lifetime = timedelta(minutes=settings.access_token_minutes)
    claims = {
        "sub": str(user_id),      # subject: who the token is for
        "role": role,             # informational; the DB role is what we enforce
        "ver": token_version,     # must match user.token_version (revocation)
        "iat": now,               # issued at
        "exp": now + lifetime,    # expiry: PyJWT rejects the token after this
        "jti": uuid.uuid4().hex,  # unique token ID
    }
    token = jwt.encode(claims, settings.secret_key, algorithm=JWT_ALGORITHM)
    return token, int(lifetime.total_seconds())


def decode_access_token(token: str) -> dict | None:
    """Verify signature + expiry. Returns the claims, or None if invalid."""
    try:
        return jwt.decode(
            token,
            get_settings().secret_key,
            algorithms=[JWT_ALGORITHM],  # never let the token choose its own algorithm
            options={"require": ["sub", "exp", "iat", "ver"]},
        )
    except jwt.PyJWTError:
        return None
