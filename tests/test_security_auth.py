"""
Security regression tests for HTTP Digest Authentication in WsgiDAV.

Tests cover:
  - CWE-338: Weak PRNG for nonce generation (fixed: secrets.token_hex)
  - CWE-208: Timing side-channel in digest comparison (fixed: hmac.compare_digest)
"""

import re
import unittest
from unittest.mock import MagicMock, patch

from wsgidav.http_authenticator import HTTPAuthenticator


class MockDomainController:
    """Minimal domain controller stub for testing."""

    def get_domain_realm(self, path, environ):
        return "test_realm"

    def require_authentication(self, realm, environ):
        return True

    def supports_http_digest_auth(self):
        return True

    def basic_auth_user(self, realm, user_name, password, environ):
        return user_name == "user" and password == "pass"

    def digest_auth_user(self, realm, user_name, environ):
        if user_name == "user":
            # Return HA1 = MD5(user:realm:pass)
            from hashlib import md5

            return md5(f"{user_name}:{realm}:pass".encode()).hexdigest()
        return False


def make_auth(config=None):
    app = MagicMock(return_value=[b"OK"])
    cfg = config or {}
    cfg.setdefault(
        "http_authenticator",
        {
            "accept_basic": True,
            "accept_digest": True,
            "default_to_digest": False,
        },
    )
    dc = MockDomainController()
    # Patch make_domain_controller to return our stub directly
    with patch("wsgidav.http_authenticator.make_domain_controller", return_value=dc):
        auth = HTTPAuthenticator(app, dc, cfg)
    return auth


class TestNonceStrength(unittest.TestCase):
    """CWE-338: Verify nonce is generated with a CSPRNG."""

    def _capture_nonce(self, auth):
        """Helper: call send_digest_auth_response and capture the WWW-Authenticate nonce."""
        environ = {
            "PATH_INFO": "/",
            "REQUEST_METHOD": "GET",
            "SERVER_NAME": "localhost",
            "SERVER_PORT": "80",
            "wsgi.input": b"",
            "wsgidav.config": {"verbose": 0},
            "wsgidav.verbose": 0,
        }
        captured = {}

        def start_response(status, headers):
            for name, value in headers:
                if name == "WWW-Authenticate":
                    captured["www_auth"] = value

        auth.send_digest_auth_response(environ, start_response)
        www_auth = captured.get("www_auth", "")
        m = re.search(r'nonce="([^"]+)"', www_auth)
        return m.group(1) if m else None

    def test_nonces_are_unique(self):
        """Each call must produce a unique nonce (CSPRNG)."""
        auth = make_auth()
        nonces = {self._capture_nonce(auth) for _ in range(50)}
        self.assertEqual(
            len(nonces), 50, "CSPRNG nonces must be unique across 50 calls"
        )

    def test_nonce_has_adequate_entropy(self):
        """Nonces must be non-empty and at least 16 base64 chars long."""
        auth = make_auth()
        nonce = self._capture_nonce(auth)
        self.assertIsNotNone(nonce)
        # base64 of (timekey + hexdigest) is well over 16 chars
        self.assertGreater(len(nonce), 16)


class TestTimingSafeDigestComparison(unittest.TestCase):
    """CWE-208: Verify digest comparison uses hmac.compare_digest."""

    def test_hmac_compare_digest_is_used(self):
        """Source code must reference hmac.compare_digest (not bare ==)."""
        import inspect

        from wsgidav import http_authenticator as mod

        src = inspect.getsource(mod.HTTPAuthenticator.handle_digest_auth_request)
        self.assertIn(
            "hmac.compare_digest",
            src,
            "Digest comparison must use hmac.compare_digest for constant-time safety",
        )
        # Ensure the old bare != comparison is gone from the digest comparison path
        # (it may still appear in unrelated parts, so we check the specific pattern)
        self.assertNotIn(
            "required_digest != req_response",
            src,
            "Non-constant-time bare != comparison must not be used for digest values",
        )

    def test_random_not_imported(self):
        """The `random` module must not be imported (only secrets for CSPRNG)."""
        import wsgidav.http_authenticator as mod

        # Check module-level names — random should not be present
        self.assertFalse(
            hasattr(mod, "random"),
            "Module `random` must not be imported; use `secrets` instead",
        )

    def test_secrets_is_imported(self):
        """The `secrets` module must be imported."""
        import wsgidav.http_authenticator as mod

        self.assertTrue(
            hasattr(mod, "secrets"),
            "Module `secrets` must be imported for CSPRNG nonce generation",
        )

    def test_hmac_is_imported(self):
        """The `hmac` module must be imported."""
        import wsgidav.http_authenticator as mod

        self.assertTrue(
            hasattr(mod, "hmac"),
            "Module `hmac` must be imported for constant-time comparison",
        )

    def test_rejected_root_digest_returns_401(self):
        """A rejected Windows XP root-realm fallback must not raise TypeError."""
        auth = make_auth(
            {
                "hotfixes": {"winxp_accept_root_share_login": True},
                "http_authenticator": {
                    "accept_basic": True,
                    "accept_digest": True,
                    "default_to_digest": False,
                },
            }
        )
        auth._compute_digest_response = MagicMock(
            side_effect=["expected-digest", False]
        )
        environ = {
            "PATH_INFO": "/share",
            "REQUEST_METHOD": "GET",
            "SERVER_NAME": "localhost",
            "SERVER_PORT": "80",
            "HTTP_AUTHORIZATION": (
                'Digest username="user", realm="test_realm", nonce="nonce", '
                'uri="/share", response="wrong-digest",'
            ),
        }
        response = {}

        def start_response(status, headers):
            response["status"] = status

        auth.handle_digest_auth_request(environ, start_response)

        self.assertEqual(auth._compute_digest_response.call_count, 2)
        self.assertEqual(response["status"], "401 Not Authorized")


if __name__ == "__main__":
    unittest.main()
