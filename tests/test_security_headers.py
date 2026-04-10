"""
D-062: Security headers middleware tests.

Tests:
  - All required security headers present in every response
  - X-Content-Type-Options: nosniff
  - X-Frame-Options: DENY
  - CSP includes frame-ancestors 'none'
  - Referrer-Policy set
  - Permissions-Policy disables dangerous APIs
"""
from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.middleware.security_headers import SecurityHeadersMiddleware, _SECURITY_HEADERS


@pytest.fixture()
def test_app():
    app = FastAPI()
    app.add_middleware(SecurityHeadersMiddleware)

    @app.get("/test")
    async def _():
        return {"ok": True}

    return app


@pytest.fixture()
def client(test_app):
    return TestClient(test_app)


class TestSecurityHeaders:
    def test_x_content_type_options_present(self, client):
        resp = client.get("/test")
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"

    def test_x_frame_options_deny(self, client):
        resp = client.get("/test")
        assert resp.headers.get("X-Frame-Options") == "DENY"

    def test_referrer_policy_set(self, client):
        resp = client.get("/test")
        policy = resp.headers.get("Referrer-Policy", "")
        assert "strict-origin" in policy

    def test_permissions_policy_disables_camera(self, client):
        resp = client.get("/test")
        policy = resp.headers.get("Permissions-Policy", "")
        assert "camera=()" in policy

    def test_permissions_policy_disables_geolocation(self, client):
        resp = client.get("/test")
        policy = resp.headers.get("Permissions-Policy", "")
        assert "geolocation=()" in policy

    def test_csp_frame_ancestors_none(self, client):
        resp = client.get("/test")
        csp = resp.headers.get("Content-Security-Policy", "")
        assert "frame-ancestors 'none'" in csp

    def test_csp_default_src_self(self, client):
        resp = client.get("/test")
        csp = resp.headers.get("Content-Security-Policy", "")
        assert "default-src 'self'" in csp

    def test_xss_protection_header(self, client):
        resp = client.get("/test")
        xss = resp.headers.get("X-XSS-Protection", "")
        assert "mode=block" in xss

    def test_all_security_headers_present(self, client):
        """Every header in _SECURITY_HEADERS dict must appear in responses."""
        resp = client.get("/test")
        for header in _SECURITY_HEADERS:
            assert header in resp.headers, f"Missing header: {header}"

    def test_headers_on_every_response(self, client):
        """Headers must be present on all responses, not just GET /test."""
        resp = client.get("/nonexistent")
        # Even 404s should have security headers
        assert "X-Content-Type-Options" in resp.headers
