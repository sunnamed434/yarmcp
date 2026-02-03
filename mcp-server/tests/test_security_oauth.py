"""
Security tests for OAuth 2.1 implementation.

These tests verify:
- JWT token generation and validation
- OAuth client registration and validation
- Authorization code flow security
- Protection against common OAuth attacks
"""
import pytest
import time
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from security.oauth import JWTManager, generate_authorization_code
from security.storage import ClientStorage, RegisteredClient, TTLDict, AuthCodeData


class TestJWTManager:
    """Test JWT token generation and validation."""

    def test_generate_access_token(self, oauth_test_config):
        """Test JWT access token generation."""
        jwt_mgr = JWTManager(
            secret_key=oauth_test_config["jwt_secret"],
            issuer=oauth_test_config["issuer"],
            default_expiry=oauth_test_config["token_expiry"],
        )

        token, expiry = jwt_mgr.generate_access_token(
            client_id="test_client",
            subject="user123",
            scope="mcp:read mcp:write",
        )

        assert isinstance(token, str)
        assert len(token) > 50  # JWT should be reasonably long
        assert expiry == oauth_test_config["token_expiry"]

    def test_verify_valid_token(self, oauth_test_config):
        """Test verification of valid JWT token."""
        jwt_mgr = JWTManager(
            secret_key=oauth_test_config["jwt_secret"],
            issuer=oauth_test_config["issuer"],
        )

        token, _ = jwt_mgr.generate_access_token(
            client_id="test_client",
            subject="user123",
            scope="mcp:read",
        )

        token_data = jwt_mgr.verify_access_token(token)

        assert token_data is not None
        assert token_data.client_id == "test_client"
        assert token_data.subject == "user123"
        assert token_data.scope == "mcp:read"

    def test_verify_expired_token(self, oauth_test_config):
        """Test that expired tokens are rejected."""
        jwt_mgr = JWTManager(
            secret_key=oauth_test_config["jwt_secret"],
            issuer=oauth_test_config["issuer"],
            default_expiry=1,  # 1 second expiry
        )

        token, _ = jwt_mgr.generate_access_token(client_id="test_client")

        # Wait for token to expire
        time.sleep(2)

        token_data = jwt_mgr.verify_access_token(token)
        assert token_data is None  # Should be rejected

    def test_verify_tampered_token(self, oauth_test_config):
        """Test that tampered tokens are rejected."""
        jwt_mgr = JWTManager(
            secret_key=oauth_test_config["jwt_secret"],
            issuer=oauth_test_config["issuer"],
        )

        token, _ = jwt_mgr.generate_access_token(client_id="test_client")

        # Tamper with the token
        tampered_token = token[:-10] + "tampered00"

        token_data = jwt_mgr.verify_access_token(tampered_token)
        assert token_data is None  # Should be rejected

    def test_verify_wrong_secret(self, oauth_test_config):
        """Test that tokens signed with different secret are rejected."""
        jwt_mgr1 = JWTManager(
            secret_key="secret1_minimum_32_chars_required_here",
            issuer=oauth_test_config["issuer"],
        )
        jwt_mgr2 = JWTManager(
            secret_key="secret2_minimum_32_chars_different_key",
            issuer=oauth_test_config["issuer"],
        )

        token, _ = jwt_mgr1.generate_access_token(client_id="test_client")

        # Try to verify with wrong secret
        token_data = jwt_mgr2.verify_access_token(token)
        assert token_data is None  # Should be rejected


class TestClientStorage:
    """Test OAuth client storage and validation."""

    def test_register_client(self, tmp_path):
        """Test dynamic client registration."""
        storage = ClientStorage(
            file_path=tmp_path / "oauth_clients.json",
            max_clients=10,
        )

        client = storage.register_client(
            client_name="Test Client",
            redirect_uris=["http://localhost:3000/callback"],
            grant_types=["authorization_code"],
        )

        assert client is not None
        assert client.client_name == "Test Client"
        assert len(client.client_id) > 10
        assert len(client.client_secret) > 20
        assert "http://localhost:3000/callback" in client.redirect_uris

    def test_get_registered_client(self, tmp_path):
        """Test retrieving registered client."""
        storage = ClientStorage(
            file_path=tmp_path / "oauth_clients.json",
            max_clients=10,
        )

        registered = storage.register_client(
            client_name="Test Client",
            redirect_uris=["http://localhost:3000/callback"],
        )

        retrieved = storage.get_client(registered.client_id)

        assert retrieved is not None
        assert retrieved.client_id == registered.client_id
        assert retrieved.client_secret == registered.client_secret

    def test_verify_client_credentials(self, tmp_path):
        """Test client credential verification."""
        storage = ClientStorage(
            file_path=tmp_path / "oauth_clients.json",
            max_clients=10,
        )

        client = storage.register_client(
            client_name="Test Client",
            redirect_uris=["http://localhost:3000/callback"],
        )

        # Valid credentials
        assert storage.verify_client(client.client_id, client.client_secret) is True

        # Invalid secret
        assert storage.verify_client(client.client_id, "wrong_secret") is False

        # Invalid client_id
        assert storage.verify_client("wrong_id", client.client_secret) is False

    def test_max_clients_limit(self, tmp_path):
        """Test that max clients limit is enforced."""
        storage = ClientStorage(
            file_path=tmp_path / "oauth_clients.json",
            max_clients=3,
        )

        # Register 3 clients (max)
        for i in range(3):
            client = storage.register_client(
                client_name=f"Client {i}",
                redirect_uris=[f"http://localhost:300{i}/callback"],
            )
            assert client is not None

        # 4th client should be rejected
        client = storage.register_client(
            client_name="Client 4",
            redirect_uris=["http://localhost:3004/callback"],
        )
        assert client is None

    def test_preconfigured_client(self, tmp_path):
        """Test preconfigured client with wildcard redirect."""
        storage = ClientStorage(
            file_path=tmp_path / "oauth_clients.json",
            preconfigured_client_id="pre_configured_id",
            preconfigured_client_secret="pre_configured_secret_12345678",
        )

        client = storage.get_client("pre_configured_id")

        assert client is not None
        assert client.client_name == "Preconfigured Client"
        assert client.redirect_uris == ["*"]  # SECURITY ISSUE: wildcard allowed

    def test_wildcard_redirect_security_issue(self, tmp_path):
        """
        SECURITY TEST: Verify that preconfigured client with wildcard redirect
        allows ANY redirect_uri (this is the Open Redirect vulnerability).
        """
        storage = ClientStorage(
            file_path=tmp_path / "oauth_clients.json",
            preconfigured_client_id="pre_configured_id",
            preconfigured_client_secret="pre_configured_secret_12345678",
        )

        client = storage.get_client("pre_configured_id")

        # This is the vulnerability: "*" in redirect_uris allows anything
        assert "*" in client.redirect_uris

        # An attacker can use ANY redirect_uri with this client:
        malicious_uris = [
            "https://evil.com/steal-token",
            "http://attacker.com/phishing",
            "https://malicious-site.net/capture",
        ]

        # Current implementation would allow all of these!
        # This test documents the vulnerability.
        for uri in malicious_uris:
            # In main.py:939-940, this check passes because "*" is present:
            # if "*" not in client.redirect_uris and redirect_uri not in client.redirect_uris:
            #     return error
            # Since "*" IS in redirect_uris, the check is bypassed!
            assert "*" in client.redirect_uris  # Vulnerability exists


class TestTTLDict:
    """Test TTL-based storage for authorization codes."""

    def test_set_and_get(self):
        """Test storing and retrieving values."""
        ttl_dict = TTLDict(ttl_seconds=60)
        ttl_dict.set("key1", "value1")

        assert ttl_dict.get("key1") == "value1"

    def test_expiration(self):
        """Test that values expire after TTL."""
        ttl_dict = TTLDict(ttl_seconds=1)
        ttl_dict.set("key1", "value1")

        # Should exist immediately
        assert ttl_dict.get("key1") == "value1"

        # Wait for expiration
        time.sleep(2)

        # Should be expired
        assert ttl_dict.get("key1") is None

    def test_pop_removes_value(self):
        """Test that pop removes value (for one-time codes)."""
        ttl_dict = TTLDict(ttl_seconds=60)
        ttl_dict.set("code", "auth_code_data")

        # First pop succeeds
        assert ttl_dict.pop("code") == "auth_code_data"

        # Second pop fails (already removed)
        assert ttl_dict.pop("code") is None

    def test_custom_ttl(self):
        """Test setting custom TTL per item."""
        ttl_dict = TTLDict(ttl_seconds=60)
        ttl_dict.set("short_lived", "value", ttl=1)
        ttl_dict.set("long_lived", "value", ttl=60)

        time.sleep(2)

        # Short-lived should be expired
        assert ttl_dict.get("short_lived") is None

        # Long-lived should still exist
        assert ttl_dict.get("long_lived") == "value"


class TestAuthorizationCodeSecurity:
    """Test authorization code security."""

    def test_authorization_code_format(self):
        """Test that authorization codes are cryptographically secure."""
        code = generate_authorization_code()

        # Should be URL-safe
        assert isinstance(code, str)
        assert len(code) >= 32  # Reasonably long

        # Generate multiple codes - should be unique
        codes = [generate_authorization_code() for _ in range(100)]
        assert len(set(codes)) == 100  # All unique

    def test_pkce_code_challenge_required(self):
        """
        Test that PKCE code_challenge is required for authorization code flow.
        (This should be tested in integration tests with the actual endpoint)
        """
        # This is a placeholder - actual test needs to be in integration tests
        # that call the /oauth/authorize endpoint
        pass


class TestOAuthFlowSecurity:
    """Test OAuth flow security (integration-style tests)."""

    def test_auth_code_single_use(self):
        """Test that authorization codes can only be used once."""
        ttl_dict = TTLDict(ttl_seconds=600)

        auth_data = AuthCodeData(
            client_id="test_client",
            redirect_uri="http://localhost:3000/callback",
            scope="mcp:read",
            code_challenge="challenge_hash",
            code_challenge_method="S256",
            created_at=time.time(),
        )

        code = generate_authorization_code()
        ttl_dict.set(code, auth_data)

        # First use should work
        data1 = ttl_dict.pop(code)
        assert data1 is not None

        # Second use should fail (already consumed)
        data2 = ttl_dict.pop(code)
        assert data2 is None

    def test_auth_code_expiration(self):
        """Test that authorization codes expire after 10 minutes."""
        ttl_dict = TTLDict(ttl_seconds=2)  # 2 seconds for testing

        auth_data = AuthCodeData(
            client_id="test_client",
            redirect_uri="http://localhost:3000/callback",
            scope="mcp:read",
            code_challenge="challenge_hash",
            code_challenge_method="S256",
            created_at=time.time(),
        )

        code = generate_authorization_code()
        ttl_dict.set(code, auth_data)

        # Wait for expiration
        time.sleep(3)

        # Should be expired
        assert ttl_dict.pop(code) is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
