"""
ZaphNews Newsletter Subscribe API
POST /api/newsletter/subscribe
"""
from __future__ import annotations

import logging
import os
import re
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, EmailStr, validator

logger = logging.getLogger("zse.newsletter")

router = APIRouter(prefix="/api/newsletter", tags=["newsletter"])

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class SubscribeRequest(BaseModel):
    email: str

    @validator("email")
    def validate_email(cls, v: str) -> str:
        v = v.strip().lower()
        if not EMAIL_RE.match(v):
            raise ValueError("Invalid email address")
        if len(v) > 254:
            raise ValueError("Email address too long")
        return v


class SubscribeResponse(BaseModel):
    status: str
    message: str
    subscribed_at: str


async def _store_subscriber(email: str) -> None:
    """
    Store subscriber. Tries Supabase first, falls back to logging.
    In production: configure SUPABASE_URL and SUPABASE_SERVICE_KEY.
    """
    supabase_url = os.environ.get("SUPABASE_URL")
    supabase_key = os.environ.get("SUPABASE_SERVICE_KEY")

    if supabase_url and supabase_key:
        try:
            import httpx  # type: ignore

            url = f"{supabase_url}/rest/v1/newsletter_subscribers"
            headers = {
                "apikey": supabase_key,
                "Authorization": f"Bearer {supabase_key}",
                "Content-Type": "application/json",
                "Prefer": "return=minimal",
            }
            payload = {
                "email": email,
                "source": "zaphnews",
                "subscribed_at": datetime.now(timezone.utc).isoformat(),
            }
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.post(url, json=payload, headers=headers)
                if r.status_code == 409:
                    raise HTTPException(status_code=409, detail="Already subscribed.")
                r.raise_for_status()
            logger.info("Newsletter subscriber stored: %s", email)
            return
        except HTTPException:
            raise
        except Exception as exc:
            logger.warning("Supabase storage failed, falling back: %s", exc)

    # Fallback: log only (no-op in production without Supabase)
    logger.info("NEWSLETTER_SUBSCRIBER (no-db fallback): %s at %s", email, datetime.now(timezone.utc).isoformat())


@router.post("/subscribe", response_model=SubscribeResponse, status_code=201)
async def subscribe(request: Request, body: SubscribeRequest) -> SubscribeResponse:
    """
    Subscribe an email address to ZaphNews.

    - Validates email format
    - Stores in Supabase (if configured) or logs
    - Returns 409 if already subscribed
    - Rate limited by upstream middleware
    """
    logger.info("Newsletter subscribe request: %s", body.email)

    await _store_subscriber(body.email)

    now = datetime.now(timezone.utc).isoformat()
    return SubscribeResponse(
        status="subscribed",
        message="Welcome. First issue drops Thursday.",
        subscribed_at=now,
    )
