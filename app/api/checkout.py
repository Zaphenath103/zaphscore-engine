"""
D-058: Stripe Idempotency Keys — prevent double-charges on retry/network errors.

This module provides the checkout session creation endpoint with proper
idempotency keys on every Stripe API call. Without idempotency keys,
a double-click or network retry = double charge = chargeback.

Idempotency key format: scan_{user_id}_{price_id}_{date}
This ensures:
  - Same user + same plan + same day = idempotent (no double charge)
  - Different day = new key (allows re-subscribing after cancellation)
"""

from __future__ import annotations

import hashlib
import logging
import os
from datetime import date
from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app.api.deps import CurrentUser

logger = logging.getLogger("zse.api.checkout")

router = APIRouter(prefix="/api", tags=["checkout"])


# ---------------------------------------------------------------------------
# Supported price tiers
# ---------------------------------------------------------------------------
_PRICE_MAP: dict[str, str] = {
    "pro_monthly":  os.environ.get("STRIPE_PRICE_PRO_MONTHLY", ""),
    "pro_annual":   os.environ.get("STRIPE_PRICE_PRO_ANNUAL", ""),
    "ent_monthly":  os.environ.get("STRIPE_PRICE_ENT_MONTHLY", ""),
    "ent_annual":   os.environ.get("STRIPE_PRICE_ENT_ANNUAL", ""),
}


def _build_idempotency_key(user_id: str, tier: str) -> str:
    """Generate a stable, collision-resistant idempotency key.

    Key rotates daily so users can re-subscribe after cancellation.
    Uses SHA-256 to keep the key short and opaque (max 255 chars for Stripe).
    """
    today = date.today().isoformat()
    raw = f"checkout:{user_id}:{tier}:{today}"
    return hashlib.sha256(raw.encode()).hexdigest()[:64]


class CheckoutRequest(BaseModel):
    tier: str = Field(..., description="Price tier: pro_monthly | pro_annual | ent_monthly | ent_annual")
    success_url: Optional[str] = Field(None, description="Redirect after successful payment")
    cancel_url:  Optional[str] = Field(None, description="Redirect on payment cancel")


@router.post("/checkout")
async def create_checkout_session(
    body: CheckoutRequest,
    request: Request,
    current_user: CurrentUser,
) -> JSONResponse:
    """Create a Stripe Checkout Session with idempotency key.

    Returns the checkout URL for the client to redirect to.
    Idempotency key prevents double-charges on network retries or double-clicks.
    """
    stripe_key = os.environ.get("STRIPE_SECRET_KEY", "")
    if not stripe_key:
        raise HTTPException(
            status_code=503,
            detail="Payment processing is not configured. Contact support.",
        )

    tier = body.tier.lower().strip()
    price_id = _PRICE_MAP.get(tier, "")
    if not price_id:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown tier '{tier}'. Valid options: {list(_PRICE_MAP.keys())}",
        )

    user_id: str = current_user.get("sub", "unknown")
    user_email: str = current_user.get("email", "")

    idempotency_key = _build_idempotency_key(user_id, tier)

    base_url = str(request.base_url).rstrip("/")
    success_url = body.success_url or f"{base_url}/dashboard?session_id={{CHECKOUT_SESSION_ID}}"
    cancel_url  = body.cancel_url  or f"{base_url}/pricing?cancelled=1"

    try:
        import stripe as stripe_sdk  # type: ignore[import-not-found]
        stripe_sdk.api_key = stripe_key

        # D-058: All Stripe API calls include idempotency_key
        session = stripe_sdk.checkout.Session.create(
            mode="subscription",
            line_items=[{"price": price_id, "quantity": 1}],
            success_url=success_url,
            cancel_url=cancel_url,
            customer_email=user_email or None,
            metadata={"user_id": user_id, "tier": tier},
            idempotency_key=idempotency_key,
        )

        logger.info(
            "Checkout session created: user=%s tier=%s session=%s idempotency_key=%s",
            user_id, tier, session.id, idempotency_key,
        )

        return JSONResponse({
            "checkout_url": session.url,
            "session_id": session.id,
            "tier": tier,
        })

    except Exception as exc:
        logger.error("Stripe checkout error: user=%s tier=%s error=%s", user_id, tier, exc)
        raise HTTPException(
            status_code=502,
            detail=f"Payment provider error. Please try again or contact support.",
        )


@router.post("/billing/cancel")
async def cancel_subscription(
    request: Request,
    current_user: CurrentUser,
) -> JSONResponse:
    """Cancel the current user's active subscription.

    Uses Stripe idempotency key to prevent duplicate cancellation calls.
    """
    stripe_key = os.environ.get("STRIPE_SECRET_KEY", "")
    if not stripe_key:
        raise HTTPException(status_code=503, detail="Payment processing not configured.")

    user_id: str = current_user.get("sub", "unknown")
    user_email: str = current_user.get("email", "")

    if not user_email:
        raise HTTPException(status_code=400, detail="No email in JWT. Cannot identify subscription.")

    idempotency_key = _build_idempotency_key(user_id, "cancel")

    try:
        import stripe as stripe_sdk  # type: ignore[import-not-found]
        stripe_sdk.api_key = stripe_key

        # Find customer by email
        customers = stripe_sdk.Customer.list(email=user_email, limit=1)
        if not customers.data:
            raise HTTPException(status_code=404, detail="No active subscription found for this account.")

        customer = customers.data[0]
        subscriptions = stripe_sdk.Subscription.list(customer=customer.id, status="active", limit=1)
        if not subscriptions.data:
            raise HTTPException(status_code=404, detail="No active subscription found.")

        sub = subscriptions.data[0]

        # Cancel at period end (graceful), with idempotency key
        cancelled = stripe_sdk.Subscription.modify(
            sub.id,
            cancel_at_period_end=True,
            idempotency_key=idempotency_key,
        )

        logger.info("Subscription set to cancel: user=%s sub=%s ends=%s", user_id, sub.id, cancelled.current_period_end)

        return JSONResponse({
            "cancelled": True,
            "subscription_id": sub.id,
            "access_until": cancelled.current_period_end,
        })

    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Subscription cancel error: user=%s error=%s", user_id, exc)
        raise HTTPException(status_code=502, detail="Could not cancel subscription. Contact support.")
