"""
PKCE (Proof Key for Code Exchange) implementation for OAuth 2.1.

RFC 7636: https://tools.ietf.org/html/rfc7636

MCP requires PKCE with S256 method for all authorization code flows.
"""

import base64
import hashlib
import secrets
import re


def generate_code_verifier(length: int = 64) -> str:
    """
    Generate a cryptographically random code verifier.

    The verifier must be between 43-128 characters and use only
    unreserved URI characters: [A-Z], [a-z], [0-9], "-", ".", "_", "~"
    """
    # Generate random bytes and encode as URL-safe base64
    random_bytes = secrets.token_bytes(length)
    verifier = base64.urlsafe_b64encode(random_bytes).decode("ascii")
    # Remove padding and limit length
    verifier = verifier.rstrip("=")[:128]
    return verifier


def generate_code_challenge(verifier: str) -> str:
    """
    Generate a code challenge from a verifier using S256 method.

    S256: BASE64URL(SHA256(code_verifier))
    """
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return challenge


def verify_code_challenge(verifier: str, challenge: str, method: str = "S256") -> bool:
    """
    Verify that a code verifier matches the stored challenge.

    Args:
        verifier: The code_verifier from the token request
        challenge: The code_challenge stored during authorization
        method: The challenge method (only S256 is supported per MCP spec)

    Returns:
        True if the verifier matches the challenge
    """
    if method.upper() != "S256":
        # MCP spec requires S256
        return False

    if not verifier or not challenge:
        return False

    # Validate verifier format (43-128 chars, URL-safe)
    if not is_valid_verifier(verifier):
        return False

    # Compute challenge from verifier and compare
    computed_challenge = generate_code_challenge(verifier)

    # Constant-time comparison to prevent timing attacks
    return secrets.compare_digest(computed_challenge, challenge)


def is_valid_verifier(verifier: str) -> bool:
    """
    Validate that a code verifier meets RFC 7636 requirements.

    Must be 43-128 characters using only [A-Z], [a-z], [0-9], "-", ".", "_", "~"
    """
    if not verifier:
        return False

    if len(verifier) < 43 or len(verifier) > 128:
        return False

    # RFC 7636 unreserved characters
    pattern = r'^[A-Za-z0-9\-._~]+$'
    return bool(re.match(pattern, verifier))


def is_valid_challenge(challenge: str) -> bool:
    """
    Validate that a code challenge is properly formatted.

    Must be BASE64URL encoded (no padding).
    """
    if not challenge:
        return False

    # SHA256 produces 32 bytes, BASE64URL encoded without padding = 43 chars
    if len(challenge) != 43:
        return False

    # BASE64URL characters only (no padding)
    pattern = r'^[A-Za-z0-9\-_]+$'
    return bool(re.match(pattern, challenge))
