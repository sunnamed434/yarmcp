"""
OAuth 2.1 JWT token handling for YARMCP.

Provides JWT generation and validation with full claims support:
- iss (issuer)
- sub (subject)
- aud (audience) - RFC 8707 resource indicators
- exp (expiration)
- iat (issued at)
- jti (JWT ID)
- client_id
- scope
"""

import time
import secrets
import base64
import hashlib
from dataclasses import dataclass

import jwt


@dataclass
class TokenData:
    """Decoded token data."""
    client_id: str
    subject: str
    audience: str
    scope: str
    expires_at: int
    issued_at: int
    token_id: str


class JWTManager:
    """
    JWT token manager for OAuth 2.1.

    Uses HS256 (HMAC-SHA256) for signing. This is appropriate for
    self-hosted single-server deployments where the same server
    issues and verifies tokens.
    """

    def __init__(self, secret_key: str, issuer: str, default_expiry: int = 3600):
        """
        Initialize JWT manager.

        Args:
            secret_key: Secret key for signing tokens (min 32 chars recommended)
            issuer: The issuer (iss) claim value
            default_expiry: Default token expiry in seconds
        """
        self._secret = secret_key
        self._issuer = issuer
        self._default_expiry = default_expiry
        self._algorithm = "HS256"
        self._key_id = hashlib.sha256(secret_key.encode()).hexdigest()[:16]

    @property
    def issuer(self) -> str:
        return self._issuer

    def generate_access_token(
        self,
        client_id: str,
        subject: str | None = None,
        audience: str | None = None,
        scope: str = "",
        expires_in: int | None = None,
    ) -> tuple[str, int]:
        """
        Generate a JWT access token.

        Args:
            client_id: The OAuth client ID
            subject: The subject (defaults to client_id for client credentials)
            audience: The resource server URL (RFC 8707)
            scope: Space-separated list of scopes
            expires_in: Token lifetime in seconds

        Returns:
            Tuple of (token, expires_in)
        """
        now = int(time.time())
        expiry = expires_in or self._default_expiry
        exp = now + expiry

        payload = {
            "iss": self._issuer,
            "sub": subject or client_id,
            "aud": audience or self._issuer,
            "exp": exp,
            "iat": now,
            "jti": secrets.token_hex(16),
            "client_id": client_id,
            "scope": scope,
        }

        token = jwt.encode(
            payload,
            self._secret,
            algorithm=self._algorithm,
            headers={"kid": self._key_id}
        )
        return token, expiry

    def verify_access_token(self, token: str, audience: str | None = None) -> TokenData | None:
        """
        Verify and decode a JWT access token.

        Args:
            token: The JWT token to verify
            audience: Expected audience (optional, for validation)

        Returns:
            TokenData if valid, None if invalid
        """
        import logging
        try:
            options = {
                "require": ["iss", "sub", "aud", "exp", "iat"],
                "verify_aud": False,  # We validate audience manually if needed
            }
            payload = jwt.decode(
                token,
                self._secret,
                algorithms=[self._algorithm],
                issuer=self._issuer,
                options=options,
            )

            # Validate audience if specified
            if audience and payload.get("aud") != audience:
                return None

            return TokenData(
                client_id=payload.get("client_id", ""),
                subject=payload.get("sub", ""),
                audience=payload.get("aud", ""),
                scope=payload.get("scope", ""),
                expires_at=payload.get("exp", 0),
                issued_at=payload.get("iat", 0),
                token_id=payload.get("jti", ""),
            )

        except jwt.ExpiredSignatureError:
            logging.warning("JWT token expired")
            return None
        except jwt.InvalidTokenError as e:
            logging.warning(f"JWT validation failed: {e}")
            return None

    def get_jwks(self) -> dict:
        """
        Get JWKS endpoint response.

        For HS256, we return an empty key set since the symmetric key
        cannot be shared publicly. External services should use the
        token introspection endpoint instead.
        """
        return {
            "keys": []
        }


def generate_authorization_code() -> str:
    """Generate a cryptographically secure authorization code."""
    return secrets.token_urlsafe(32)


def generate_jwt_secret() -> str:
    """Generate a secure secret for JWT signing."""
    return secrets.token_hex(32)
