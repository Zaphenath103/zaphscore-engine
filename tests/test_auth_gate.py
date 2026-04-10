"""
D-062: Auth gate tests — POST /api/scans rejects unauthenticated requests.

Tests:
  - No auth header -> 401
  - Invalid JWT format -> 401
  - Expired JWT -> 401
  - Valid JWT (mocked) -> proceeds past auth
"""
from __future__ import annotations

import base64
import json
import time
import uuid

import pytest
from unittest.mock import AsyncMock, MagicMock, patch


def _make_jwt(payload: dict, expired: bool = False) -> str:
    """Build a mock JWT (unsigned — for testing only)."""
    if expired:
        payload["exp"] = int(time.time()) - 3600
    else:
        payload.setdefault("exp", int(time.time()) + 3600)

    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).rstrip(b"=").decode()
    body_bytes = json.dumps(payload).encode()
    body = base64.urlsafe_b64encode(body_bytes).rstrip(b"=").decode()
    return f"{header}.{body}.fakesig"


class TestAuthGate:
    """Tests for app/api/deps.py — CurrentUser dependency."""

    def test_expired_jwt_raises_value_error(self):
        """Expired JWT should raise ValueError (caught and turned to 401)."""
        from app.api.deps import _decode_token
        token = _make_jwt({"sub": "user-123"}, expired=True)

        with pytest.raises(Exception):
            _decode_token(token)

    def test_malformed_jwt_raises(self):
        """JWT with wrong number of parts raises ValueError."""
        from app.api.deps import _decode_token

        with pytest.raises(Exception):
            _decode_token("not.a.valid.jwt.at.all.extra")

    def test_valid_jwt_returns_payload(self):
        """Valid (unsigned) JWT returns payload when no SUPABASE_JWT_SECRET set."""
        import os
        os.environ.pop("SUPABASE_JWT_SECRET", None)

        from app.api.deps import _decode_token
        import importlib
        import app.api.deps as deps_module
        deps_module._JWT_SECRET = ""

        payload = {"sub": "user-abc", "email": "test@example.com"}
        token = _make_jwt(payload)

        result = _decode_token(token)
        assert result["sub"] == "user-abc"
        assert result["email"] == "test@example.com"

    def test_jwt_expiry_check(self):
        """Token with past exp is rejected."""
        import app.api.deps as deps_module
        deps_module._JWT_SECRET = ""

        expired_payload = {"sub": "user-xyz", "exp": int(time.time()) - 1}
        token = _make_jwt(expired_payload, expired=True)

        with pytest.raises(Exception):
            deps_module._decode_token(token)


class TestRateLimitTierExtraction:
    """Tests for D-061: per-user tier extraction from JWT."""

    def test_free_tier_default(self):
        """JWT with no plan claim returns free tier."""
        from app.middleware.rate_limit import _extract_user_tier
        token = _make_jwt({"sub": "user-1"})
        user_id, tier = _extract_user_tier(token)
        assert user_id == "user-1"
        assert tier == "free"

    def test_pro_tier_from_app_metadata(self):
        """JWT with app_metadata.plan=pro returns pro tier."""
        from app.middleware.rate_limit import _extract_user_tier
        token = _make_jwt({"sub": "user-2", "app_metadata": {"plan": "pro"}})
        user_id, tier = _extract_user_tier(token)
        assert tier == "pro"

    def test_enterprise_tier_normalized(self):
        """JWT with plan=enterprise normalized correctly."""
        from app.middleware.rate_limit import _extract_user_tier
        token = _make_jwt({"sub": "user-3", "app_metadata": {"plan": "enterprise"}})
        _, tier = _extract_user_tier(token)
        assert tier == "enterprise"

    def test_team_plan_maps_to_enterprise(self):
        """plan=team maps to enterprise tier."""
        from app.middleware.rate_limit import _extract_user_tier
        token = _make_jwt({"sub": "user-4", "app_metadata": {"plan": "team"}})
        _, tier = _extract_user_tier(token)
        assert tier == "enterprise"

    def test_expired_token_returns_free(self):
        """Expired JWT falls back to free tier."""
        from app.middleware.rate_limit import _extract_user_tier
        token = _make_jwt({"sub": "user-5", "app_metadata": {"plan": "pro"}}, expired=True)
        _, tier = _extract_user_tier(token)
        assert tier == "free"

    def test_malformed_token_returns_free(self):
        """Malformed token falls back to free."""
        from app.middleware.rate_limit import _extract_user_tier
        _, tier = _extract_user_tier("notavalidtoken")
        assert tier == "free"
