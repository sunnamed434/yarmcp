"""
OAuth storage for YARMCP.

Provides:
- TTLDict: In-memory storage with automatic expiration for auth codes and PKCE verifiers
- ClientStorage: JSON file storage with file locking for DCR registered clients
"""

import json
import time
import threading
import secrets
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Any


@dataclass
class AuthCodeData:
    """Data associated with an authorization code."""
    client_id: str
    redirect_uri: str
    scope: str
    code_challenge: str
    code_challenge_method: str
    created_at: float


@dataclass
class RegisteredClient:
    """A dynamically registered OAuth client."""
    client_id: str
    client_secret: str
    client_name: str
    redirect_uris: list[str]
    grant_types: list[str]
    response_types: list[str]
    created_at: float


class TTLDict:
    """
    Thread-safe dictionary with automatic TTL expiration.

    Used for storing authorization codes and PKCE verifiers.
    Items are automatically removed after TTL expires.
    """

    def __init__(self, ttl_seconds: int = 600):
        self._store: dict[str, tuple[Any, float]] = {}
        self._ttl = ttl_seconds
        self._lock = threading.Lock()

    def set(self, key: str, value: Any, ttl: int | None = None) -> None:
        """Store a value with TTL."""
        expires_at = time.time() + (ttl or self._ttl)
        with self._lock:
            self._store[key] = (value, expires_at)
            self._cleanup()

    def get(self, key: str) -> Any | None:
        """Get a value if it exists and hasn't expired."""
        with self._lock:
            self._cleanup()
            if key not in self._store:
                return None
            value, expires_at = self._store[key]
            if time.time() > expires_at:
                del self._store[key]
                return None
            return value

    def pop(self, key: str) -> Any | None:
        """Get and remove a value (for one-time use codes)."""
        with self._lock:
            self._cleanup()
            if key not in self._store:
                return None
            value, expires_at = self._store.pop(key)
            if time.time() > expires_at:
                return None
            return value

    def delete(self, key: str) -> bool:
        """Delete a key."""
        with self._lock:
            if key in self._store:
                del self._store[key]
                return True
            return False

    def _cleanup(self) -> None:
        """Remove expired entries."""
        now = time.time()
        expired = [k for k, (_, exp) in self._store.items() if now > exp]
        for k in expired:
            del self._store[k]


class ClientStorage:
    """
    Persistent storage for OAuth clients using JSON file with file locking.

    Supports both pre-configured clients (from environment) and
    dynamically registered clients (DCR).
    """

    def __init__(self, file_path: Path, preconfigured_client_id: str = "",
                 preconfigured_client_secret: str = "", max_clients: int = 100):
        self._file_path = file_path
        self._lock = threading.Lock()
        self._max_clients = max_clients
        self._preconfigured_client_id = preconfigured_client_id
        self._preconfigured_client_secret = preconfigured_client_secret
        self._clients: dict[str, RegisteredClient] = {}
        self._load()

    def _load(self) -> None:
        """Load clients from JSON file."""
        if not self._file_path.exists():
            self._clients = {}
            return

        try:
            with open(self._file_path, "r") as f:
                data = json.load(f)
                self._clients = {
                    k: RegisteredClient(**v) for k, v in data.items()
                }
        except (json.JSONDecodeError, TypeError, KeyError):
            self._clients = {}

    def _save(self) -> None:
        """Save clients to JSON file."""
        self._file_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._file_path, "w") as f:
            json.dump(
                {k: asdict(v) for k, v in self._clients.items()},
                f,
                indent=2
            )

    def get_client(self, client_id: str) -> RegisteredClient | None:
        """Get a client by ID (checks both preconfigured and DCR clients)."""
        # Check preconfigured client first
        if (self._preconfigured_client_id and
            secrets.compare_digest(client_id, self._preconfigured_client_id)):
            # Get allowed redirect domains from settings
            from config import settings
            allowed_domains = settings.oauth_allowed_redirect_domains

            # Convert to list of redirect URIs
            if allowed_domains == "*":
                redirect_uris = ["*"]  # Wildcard (unsafe, but default for convenience)
            else:
                # Parse comma-separated domains into redirect URIs
                domains = [d.strip() for d in allowed_domains.split(",")]
                redirect_uris = []
                for domain in domains:
                    # Support localhost with any port
                    if domain in ["localhost", "127.0.0.1", "::1"]:
                        redirect_uris.append(f"http://{domain}:*")
                        redirect_uris.append(f"https://{domain}:*")
                    else:
                        redirect_uris.append(f"https://{domain}/*")

            return RegisteredClient(
                client_id=self._preconfigured_client_id,
                client_secret=self._preconfigured_client_secret,
                client_name="Preconfigured Client",
                redirect_uris=redirect_uris,
                grant_types=["authorization_code", "client_credentials"],
                response_types=["code"],
                created_at=0,
            )

        # Check DCR clients
        with self._lock:
            return self._clients.get(client_id)

    def verify_client(self, client_id: str, client_secret: str) -> bool:
        """Verify client credentials."""
        client = self.get_client(client_id)
        if not client:
            return False
        return secrets.compare_digest(client_secret, client.client_secret)

    def register_client(self, client_name: str, redirect_uris: list[str],
                       grant_types: list[str] | None = None,
                       response_types: list[str] | None = None) -> RegisteredClient | None:
        """
        Register a new OAuth client (DCR).

        Returns None if max clients reached.
        """
        with self._lock:
            if len(self._clients) >= self._max_clients:
                return None

            client_id = f"dcr_{secrets.token_hex(16)}"
            client_secret = secrets.token_hex(32)

            client = RegisteredClient(
                client_id=client_id,
                client_secret=client_secret,
                client_name=client_name,
                redirect_uris=redirect_uris,
                grant_types=grant_types or ["authorization_code"],
                response_types=response_types or ["code"],
                created_at=time.time(),
            )

            self._clients[client_id] = client
            self._save()

            return client

    def delete_client(self, client_id: str) -> bool:
        """Delete a registered client."""
        with self._lock:
            if client_id in self._clients:
                del self._clients[client_id]
                self._save()
                return True
            return False

    def list_clients(self) -> list[dict]:
        """List all registered clients (without secrets)."""
        with self._lock:
            return [
                {
                    "client_id": c.client_id,
                    "client_name": c.client_name,
                    "redirect_uris": c.redirect_uris,
                    "created_at": c.created_at,
                }
                for c in self._clients.values()
            ]
