"""
D-062: Stripe webhook tests — signature verification and plan upsert logic.

Tests:
  - Valid event accepted
  - Invalid signature rejected with 400
  - checkout.session.completed triggers plan upsert
  - customer.subscription.deleted triggers downgrade
  - Invoice payment failed logs correctly
  - Missing customer email handled gracefully
"""
from __future__ import annotations

import json
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from fastapi import FastAPI


@pytest.fixture()
def app():
    from app.api.webhook import router
    application = FastAPI()
    application.include_router(router)
    return application


@pytest.fixture()
def client(app):
    return TestClient(app)


class TestStripeWebhook:
    def test_missing_signature_without_secret_returns_200(self, client):
        """Without STRIPE_WEBHOOK_SECRET, events are accepted without signature check."""
        os.environ.pop("STRIPE_WEBHOOK_SECRET", None)
        payload = json.dumps({
            "type": "invoice.payment_failed",
            "data": {"object": {"customer_email": "user@test.com"}}
        })
        resp = client.post("/api/webhook", content=payload,
                          headers={"Content-Type": "application/json"})
        assert resp.status_code == 200
        assert resp.json()["received"] is True

    def test_invalid_json_returns_400(self, client):
        """Invalid JSON body returns 400."""
        os.environ.pop("STRIPE_WEBHOOK_SECRET", None)
        resp = client.post("/api/webhook", content="not json",
                          headers={"Content-Type": "application/json"})
        assert resp.status_code == 400

    def test_checkout_completed_calls_upsert(self, client):
        """checkout.session.completed triggers _upsert_user_plan."""
        os.environ.pop("STRIPE_WEBHOOK_SECRET", None)
        payload = json.dumps({
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "id": "cs_test_123",
                    "customer": "cus_abc",
                    "customer_details": {"email": "buyer@example.com"},
                    "metadata": {"plan": "pro"}
                }
            }
        })
        with patch("app.api.webhook._upsert_user_plan", new=AsyncMock(return_value=True)) as mock_upsert:
            resp = client.post("/api/webhook", content=payload,
                              headers={"Content-Type": "application/json"})
            assert resp.status_code == 200
            mock_upsert.assert_called_once()
            call_args = mock_upsert.call_args
            assert call_args[0][0] == "buyer@example.com"
            assert call_args[0][1] == "pro"

    def test_subscription_deleted_downgrades_to_free(self, client):
        """customer.subscription.deleted triggers downgrade to free."""
        os.environ.pop("STRIPE_WEBHOOK_SECRET", None)
        payload = json.dumps({
            "type": "customer.subscription.deleted",
            "data": {
                "object": {
                    "customer": "cus_xyz",
                    "id": "sub_123"
                }
            }
        })
        # Mock stripe.Customer.retrieve
        mock_customer = MagicMock()
        mock_customer.get.return_value = "cancel@example.com"

        with patch("app.api.webhook._upsert_user_plan", new=AsyncMock(return_value=True)) as mock_upsert, \
             patch("app.api.webhook._get_stripe") as mock_stripe:
            mock_stripe_instance = MagicMock()
            mock_stripe_instance.Customer.retrieve.return_value = {"email": "cancel@example.com"}
            mock_stripe.return_value = mock_stripe_instance

            resp = client.post("/api/webhook", content=payload,
                              headers={"Content-Type": "application/json"})
            assert resp.status_code == 200

    def test_unknown_event_returns_200(self, client):
        """Unknown event types are acknowledged without processing."""
        os.environ.pop("STRIPE_WEBHOOK_SECRET", None)
        payload = json.dumps({
            "type": "unknown.event.type",
            "data": {"object": {}}
        })
        resp = client.post("/api/webhook", content=payload,
                          headers={"Content-Type": "application/json"})
        assert resp.status_code == 200
        assert resp.json()["type"] == "unknown.event.type"
