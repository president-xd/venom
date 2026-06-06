"""
Multi-user authentication for the web console (std-lib only).

- Users live in ``$VENOM_DATA_DIR/web/users.json``; passwords are stored as
  PBKDF2-HMAC-SHA256 hashes with a per-user salt (never plaintext).
- A login issues an HMAC-SHA256 *signed* session token (``user.expiry.sig``) set as
  an HttpOnly cookie, so the server trusts the cookie only if the signature and the
  expiry verify. No server-side session store needed.
- The signing key is ``VENOM_WEB_SECRET`` (falls back to the audit key, then a
  generated-per-process key); set it in prod so sessions survive a restart.

This isolates each operator's engagements/findings from the others on a shared
console. It is intentionally simple and dependency-free; for internet-facing
deployments put it behind real SSO / a reverse proxy.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path

COOKIE_NAME = "venom_session"
_SESSION_TTL = 12 * 3600          # 12h
_PBKDF2_ROUNDS = 200_000

# A process-stable fallback key so sessions at least work within one run when no
# secret is configured; configure VENOM_WEB_SECRET for persistence across restarts.
_FALLBACK_KEY = secrets.token_hex(32)

# ---- login brute-force throttle (in-memory, per-username) ------------------
# A security console that can launch authenticated attacks must not let an
# attacker grind the login. After _MAX_FAILS failures inside the window the
# account is locked for _LOCKOUT_SECONDS (any correct password is refused while
# locked). A successful login clears the counter.
_MAX_FAILS = int(os.getenv("VENOM_WEB_MAX_FAILS", "8"))
_LOCKOUT_SECONDS = int(os.getenv("VENOM_WEB_LOCKOUT_SECONDS", "300"))
_fail_log: dict[str, list[float]] = {}


def _is_locked(username: str) -> bool:
    now = time.time()
    fails = [t for t in _fail_log.get(username, []) if now - t < _LOCKOUT_SECONDS]
    _fail_log[username] = fails
    return len(fails) >= _MAX_FAILS


def _record_failure(username: str) -> None:
    _fail_log.setdefault(username, []).append(time.time())


def _clear_failures(username: str) -> None:
    _fail_log.pop(username, None)


def _data_dir() -> Path:
    base = Path(os.getenv("VENOM_DATA_DIR", "venom_data")) / "web"
    base.mkdir(parents=True, exist_ok=True)
    return base


def _users_path() -> Path:
    return _data_dir() / "users.json"


def _secret() -> bytes:
    return (os.getenv("VENOM_WEB_SECRET") or os.getenv("VENOM_AUDIT_KEY") or _FALLBACK_KEY).encode()


# --------------------------------------------------------------- password hashing
def hash_password(password: str, *, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", (password or "").encode(), bytes.fromhex(salt), _PBKDF2_ROUNDS)
    return f"pbkdf2_sha256${_PBKDF2_ROUNDS}${salt}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, rounds, salt, digest = (stored or "").split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", (password or "").encode(), bytes.fromhex(salt), int(rounds))
        return hmac.compare_digest(dk.hex(), digest)
    except (ValueError, TypeError):
        return False


# --------------------------------------------------------------- user store
def _load_users() -> dict:
    p = _users_path()
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            return {}
    return {}


def _save_users(users: dict) -> None:
    _users_path().write_text(json.dumps(users, indent=2), encoding="utf-8")


def ensure_seed_user() -> dict | None:
    """Create a default operator on first run so the console is usable out of the box.
    Username from VENOM_WEB_USER (default 'admin'); password from VENOM_WEB_PASSWORD if
    set, otherwise a STRONG RANDOM one-time password (surfaced once at startup). There
    is deliberately NO weak built-in default (the old 'admin/venom') - this console can
    launch authenticated attacks, so it must never ship with guessable credentials.
    Returns {username, password} when it just created one (so it can be surfaced once)."""
    users = _load_users()
    if users:
        return None
    user = os.getenv("VENOM_WEB_USER", "admin")
    pw = os.getenv("VENOM_WEB_PASSWORD") or secrets.token_urlsafe(15)
    users[user] = {"password": hash_password(pw), "name": os.getenv("VENOM_WEB_NAME", "Operator"),
                   "role": "lead", "created": int(time.time())}
    _save_users(users)
    return {"username": user, "password": pw}


def add_user(username: str, password: str, *, name: str = "", role: str = "operator") -> bool:
    username = (username or "").strip().lower()
    if not username or not password:
        return False
    users = _load_users()
    if username in users:
        return False
    users[username] = {"password": hash_password(password), "name": name or username.title(),
                       "role": role, "created": int(time.time())}
    _save_users(users)
    return True


# A real PBKDF2 hash computed once, used to equalize verification time for unknown
# usernames so login response time does not leak which accounts exist (user
# enumeration). verify_password against this runs the SAME 200k-round KDF a real
# account would, so "no such user" and "wrong password" are timing-indistinguishable.
_DUMMY_HASH = hash_password("venom-timing-equalizer-not-a-real-password")


def authenticate(username: str, password: str) -> dict | None:
    username = (username or "").strip().lower()
    # Refuse while locked - even with the correct password - so a flood of guesses
    # cannot be ground out, and a near-miss right after the lockout still fails.
    if not username or _is_locked(username):
        return None
    rec = _load_users().get(username)
    # Always run a PBKDF2 verification (against the real hash, or a dummy of equal
    # cost) so an unknown username is not distinguishable from a wrong password by
    # response time. `ok` is only honored when the account actually exists.
    stored = rec.get("password", "") if rec else _DUMMY_HASH
    ok = verify_password(password, stored)
    if rec and ok:
        _clear_failures(username)
        return {"username": username, "name": rec.get("name") or username.title(),
                "role": rec.get("role") or "operator"}
    _record_failure(username)
    return None


def user_profile(username: str) -> dict | None:
    rec = _load_users().get((username or "").strip().lower())
    if not rec:
        return None
    return {"username": username, "name": rec.get("name") or username.title(),
            "role": rec.get("role") or "operator"}


# --------------------------------------------------------------- session tokens
def make_session(username: str, *, ttl: int = _SESSION_TTL) -> str:
    exp = str(int(time.time()) + ttl)
    msg = f"{username}.{exp}".encode()
    sig = hmac.new(_secret(), msg, hashlib.sha256).hexdigest()
    return f"{username}.{exp}.{sig}"


def read_session(token: str) -> str | None:
    """Return the username if the token's signature + expiry verify, else None."""
    try:
        username, exp, sig = (token or "").rsplit(".", 2)
    except ValueError:
        return None
    expected = hmac.new(_secret(), f"{username}.{exp}".encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig):
        return None
    try:
        if int(exp) < int(time.time()):
            return None
    except ValueError:
        return None
    return username


def parse_cookie(cookie_header: str) -> dict:
    out: dict[str, str] = {}
    for part in (cookie_header or "").split(";"):
        if "=" in part:
            k, v = part.strip().split("=", 1)
            out[k] = v
    return out


def _secure_flag() -> str:
    # Secure is opt-in via VENOM_WEB_SECURE so the cookie still works over plain http
    # on localhost; set it to 1 whenever the console is served behind TLS (any
    # internet-facing deployment) so the session cookie is never sent in clear text.
    return "; Secure" if os.getenv("VENOM_WEB_SECURE", "").lower() in ("1", "true", "yes") else ""


def session_cookie(token: str, *, max_age: int = _SESSION_TTL) -> str:
    return f"{COOKIE_NAME}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}{_secure_flag()}"


def clear_cookie() -> str:
    return f"{COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{_secure_flag()}"


def user_from_cookie(cookie_header: str) -> str | None:
    return read_session(parse_cookie(cookie_header).get(COOKIE_NAME, ""))
