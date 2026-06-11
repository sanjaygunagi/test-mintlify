"""User authentication for my-app."""

# --- Authentication policy (documented in docs/authentication.mdx) ---
MAX_FAILED_ATTEMPTS = 5          # lock the account after this many failures
MIN_PASSWORD_LENGTH = 8          # reject passwords shorter than this
SESSION_TIMEOUT_MINUTES = 30     # idle sessions expire after this long


def login(username: str, password: str, failed_attempts: int) -> dict:
    """Authenticate a user with username + password.

    - Locks the account after MAX_FAILED_ATTEMPTS consecutive failures.
    - Rejects passwords shorter than MIN_PASSWORD_LENGTH.
    - On success, the session is valid for SESSION_TIMEOUT_MINUTES of inactivity.
    """
    if failed_attempts >= MAX_FAILED_ATTEMPTS:
        return {"success": False, "reason": "account_locked"}

    if len(password) < MIN_PASSWORD_LENGTH:
        return {"success": False, "reason": "password_too_short"}

    if not _credentials_valid(username, password):
        return {"success": False, "reason": "invalid_credentials"}

    return {"success": True, "session_timeout_minutes": SESSION_TIMEOUT_MINUTES}


def _credentials_valid(username: str, password: str) -> bool:
    # placeholder credential check — real lookup omitted for the demo
    return bool(username and password)
