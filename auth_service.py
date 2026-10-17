"""QM-5: Customer registration with email verification (in-memory demo service)."""
import base64
import hashlib
import hmac
import os
import re
import time

_EMAIL_RE = re.compile(r"^[^@\s|]+@[^@\s|]+\.[^@\s|]+$")
_SECRET = os.environ.get("QM_TOKEN_SECRET", "dev-only-secret-change-me").encode()
TOKEN_TTL_SECONDS = 24 * 60 * 60  # 24-hour verification window (acceptance criteria)

_USERS = {}
OUTBOX = []  # stands in for the email worker: every "sent" verification mail lands here


class DuplicateUserError(Exception):
    """An account already exists for this email (maps to HTTP 409 Conflict)."""


class InvalidTokenError(Exception):
    """Token is malformed, forged or refers to an unknown account."""


class ExpiredTokenError(Exception):
    """Token signature is valid but its 24-hour lifetime has passed."""


def hash_password(password, salt=None):
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return salt, digest


def verify_password(password, salt, digest):
    return hmac.compare_digest(hash_password(password, salt)[1], digest)


def _sign(payload):
    return hmac.new(_SECRET, payload.encode(), hashlib.sha256).hexdigest()


def create_verification_token(email, now=None, ttl=TOKEN_TTL_SECONDS):
    expires = int((time.time() if now is None else now) + ttl)
    payload = f"{email.lower()}|{expires}"
    return base64.urlsafe_b64encode(f"{payload}|{_sign(payload)}".encode()).decode()


def register_user(email, password):
    """Create an unverified account and queue the verification email (HTTP 201)."""
    if not _EMAIL_RE.match(email):
        raise ValueError("invalid email")
    if len(password) < 12:
        raise ValueError("password must be at least 12 characters")
    if email.lower() in _USERS:
        raise DuplicateUserError("An account with this email already exists")
    salt, digest = hash_password(password)
    _USERS[email.lower()] = {"salt": salt, "hash": digest, "verified": False}
    token = create_verification_token(email)
    OUTBOX.append({"to": email.lower(), "token": token})
    return {"status": "pending_verification", "http": 201}


def verify_token(token, now=None):
    """Mark the account verified if the token is genuine and still within 24 hours."""
    try:
        raw = base64.urlsafe_b64decode(token.encode()).decode()
        email, expires, sig = raw.rsplit("|", 2)
        expires = int(expires)
    except Exception:
        raise InvalidTokenError("malformed token")
    if not hmac.compare_digest(sig, _sign(f"{email}|{expires}")):
        raise InvalidTokenError("bad signature")
    if (time.time() if now is None else now) > expires:
        raise ExpiredTokenError("verification token expired")
    if email not in _USERS:
        raise InvalidTokenError("unknown account")
    _USERS[email]["verified"] = True
    return {"status": "verified", "http": 200}


def is_verified(email):
    return _USERS[email.lower()]["verified"]


def stored_hash(email):
    return _USERS[email.lower()]["hash"]


def reset():
    _USERS.clear()
    OUTBOX.clear()
