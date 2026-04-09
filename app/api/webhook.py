"""
D-001: Stripe Webhook Handler — the missing final mile between payment and Pro access.

This endpoint receives Stripe event notifications and:
1. Verifies the Stripe-Signature header (prevents spoofed webhook calls)
2. On checkout.session.completed → upserts the user's plan to 'pro' in Supabase
3. On customer.subscription.deleted → downgrades plan back to 'free'

Without this endpoint, users can complete Stripe checkout and never receive Pro access.
ZaphScore was shipping $0 MRR despite payment infrastructure in place.

Mount in main.py:
    from app.api.webhook import router as webhook_router
    app.include_router(webhook_router)
"""

from __future__ import annotations

import logging
import os
from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

logger = logging.getLogger("zse.webhook")

router = APIRouter(prefix="/api", tags=["webhook"])


# ---------------------------------------------------------------------------
# Stripe plan mapping: price_id → plan name
# ---------------------------------------------------------------------------
# Map Stripe Price IDs to internal plan names.
# Add your actual Stripe price IDs from the dashboard here.
_PRICE_TO_PLAN: dict[str, str] = {
    # Pro monthly
    os.environ.get("STRIPE_PRICE_PRO_MONTHLY", ""): "pro",
    # Pro annual
    os.environ.get("STRIPE_PRICE_PRO_ANNUAL", ""): "pro",
    # Enterprise monthly
    os.environ.get("STRIPE_PRICE_ENT_MONTHLY", ""): "enterprise",
    # Enterprise annual
    os.environ.get("STRIPE_PRICE_ENT_ANNUAL", ""): "enterprise",
}
# Remove empty-string keys (env vars not set)
_PRICE_TO_PLAN = {k: v for k, v in _PRICE_TO_PLAN.items() if k}


def _get_stripe():
    """Lazy import stripe — not installed in dev if not configured."""
    try:
        import stripe  # type: ignore[import-not-found]
        return stripe
    except ImportError:
        return None


async def _upsert_user_plan(email: str, plan: str, stripe_customer_id: Optional[str] = None) -> bool:
    """Write the user's plan to Supabase (or log if Supabase is not configured).

    Returns True if persisted, False if Supabase is unavailable (demo mode).
    The caller logs the outcome — we never raise here.
    """
    try:
        supabase_url = os.environ.get("SUPABASE_URL", "")
        supabase_key = os.environ.get("SUPABASE_ANON_KEY", "") or os.environ.get("SUPABASE_KEY", "")

        if not supabase_url or not supabase_key:
            logger.warning(
                "Supabase not configured — plan upgrade logged but not persisted. "
                "email=%s plan=%s customer=%s",
                email, plan, stripe_customer_id,
            )
            return False

        from supabase import create_client  # type: ignore[import-not-found]
        client = create_client(supabase_url, supabase_key)
        client.table("users").upsert(
            {
                "email": email,
                "plan": plan,
                "stripe_customer_id": stripe_customer_id,
                "plan_updated_at": "now()",
            },
            on_conflict="email",
        ).execute()

        logger.info("Plan upserted: email=%s → plan=%s", email, plan)
        return True

    except Exception as exc:
        logger.error("Failed to upsert plan for %s: %s", email, exc, exc_info=True)
        return False


@router.post("/webhook")
async def stripe_webhook(request: Request) -> JSONResponse:
    """Receive and verify Stripe webhook events.

    Security: Verifies the Stripe-Signature header using STRIPE_WEBHOOK_SECRET.
    Without verification, anyone could POST a fake checkout.session.completed
    and grant themselves Pro access for free.

    Handled events:
    - checkout.session.completed → activate Pro/Enterprise plan
    - customer.subscription.deleted → downgrade to free
    - invoice.payment_failed → log (future: send dunning email)
    """
    stripe = _get_stripe()
    webhook_secret = os.environ.get("STRIPE_WEBHOOK_SECRET", "")

    payload = await request.body()
    sig_header = request.headers.get("stripe-signature", "")

    # --- Verify signature ---
    if stripe and webhook_secret:
        try:
            event = stripe.Webhook.construct_event(payload, sig_header, webhook_secret)
        except Exception as exc:
            logger.warning("Stripe signature verification failed: %s", exc)
            raise HTTPException(status_code=400, detail=f"Invalid signature: {exc}")
    else:
        # Demo mode: no verification — log and accept (development only)
        import json
        try:
            event = json.loads(payload)
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON payload")
        logger.warning(
            "STRIPE_WEBHOOK_SECRET not set — processing webhook WITHOUT verification. "
            "This is UNSAFE in production. Set STRIPE_WEBHOOK_SECRET in Vercel env vars."
        )

    event_type = event.get("type", "") if isinstance(event, dict) else event.type
    event_data = event.get("data", {}) if isinstance(event, dict) else event.data
    event_obj = event_data.get("object", {}) if isinstance(event_data, dict) else event_data.object

    logger.info("Stripe webhook received: type=%s", event_type)

    # --- Handle checkout.session.completed ---
    if event_type == "checkout.session.completed":
        session = event_obj if isinstance(event_obj, dict) else {}

        customer_email = (
            session.get("customer_details", {}).get("email")
            or session.get("customer_email")
        )
        customer_id = session.get("customer")
        price_id = None

        # Extract price from line items (not always present in session object)
        # Try metadata fallback first
        metadata = session.get("metadata", {})
        plan_from_meta = metadata.get("plan")

        if not plan_from_meta and price_id is None:
            # Try to get price from subscription if available
            sub_id = session.get("subscription")
            if sub_id and stripe:
                try:
                    sub = stripe.Subscription.retrieve(sub_id)
                    price_id = sub["items"]["data"][0]["price"]["id"]
                except Exception as exc:
                    logger.warning("Could not retrieve subscription price: %s", exc)

        # Resolve plan name
        plan = _PRICE_TO_PLAN.get(price_id or "", "") or plan_from_meta or "pro"

        if customer_email:
            persisted = await _upsert_user_plan(customer_email, plan, customer_id)
            logger.info(
                "checkout.session.completed: email=%s plan=%s persisted=%s",
                customer_email, plan, persisted,
            )
        else:
            logger.warning(
                "checkout.session.completed: no customer email found in session %s",
                session.get("id"),
            )

    # --- Handle subscription cancellation ---
    elif event_type == "customer.subscription.deleted":
        sub = event_obj if isinstance(event_obj, dict) else {}
        customer_id = sub.get("customer")

        # Look up email from customer ID if Stripe is available
        email = None
        if stripe and customer_id:
            try:
                customer = stripe.Customer.retrieve(customer_id)
                email = customer.get("email")
            except Exception as exc:
                logger.warning("Could not retrieve customer %s: %s", customer_id, exc)

        if email:
            await _upsert_user_plan(email, "free", customer_id)
            logger.info("Subscription cancelled: email=%s → downgraded to free", email)
        else:
            logger.warning(
                "customer.subscription.deleted: could not resolve email for customer %s",
                customer_id,
            )

    # --- invoice.payment_failed ---
    elif event_type == "invoice.payment_failed":
        invoice = event_obj if isinstance(event_obj, dict) else {}
        email = invoice.get("customer_email")
        logger.warning("Payment failed for %s — dunning email not yet implemented", email)

    # Always return 200 to acknowledge receipt (Stripe retries on non-2xx)
    return JSONResponse({"received": True, "type": event_type})
