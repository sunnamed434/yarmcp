import os
import secrets
from functools import wraps


def verify_auth_token(token: str) -> bool:
    """
    Verify the provided bearer token against the configured auth token.

    Uses constant-time comparison to prevent timing attacks.
    """
    expected_token = os.environ.get("BEARER_AUTH_TOKEN", "")

    if not expected_token:
        # If no token configured, deny all requests
        return False

    # Constant-time comparison
    return secrets.compare_digest(token, expected_token)


def extract_bearer_token(authorization_header: str | None) -> str | None:
    """
    Extract the bearer token from an Authorization header.

    Expected format: "Bearer <token>"
    """
    if not authorization_header:
        return None

    parts = authorization_header.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None

    return parts[1]


class AuthenticationError(Exception):
    """Raised when authentication fails."""
    pass


def require_auth(func):
    """
    Decorator to require authentication for a function.

    Note: FastMCP may handle auth differently - this is for custom routes.
    """
    @wraps(func)
    async def wrapper(*args, **kwargs):
        request = kwargs.get("request") or (args[0] if args else None)

        if request is None:
            raise AuthenticationError("No request object available")

        auth_header = request.headers.get("Authorization")
        token = extract_bearer_token(auth_header)

        if not token or not verify_auth_token(token):
            raise AuthenticationError("Invalid or missing authentication token")

        return await func(*args, **kwargs)

    return wrapper
