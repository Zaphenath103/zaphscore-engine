"""
Waitlist / email capture endpoint.

POST /api/waitlist  { "email": "..." }
→ Logs the email. Ready to hook into Supabase or Resend once env vars are set.
"""
from __future__ import annotations

import logging
import os
import re

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel

logger = logging.getLogger("zse.waitlist")
router = APIRouter(prefix="/api", tags=["waitlist"])

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class WaitlistRequest(BaseModel):
    email: str
    source: str = "zaphscore-landing"


@router.post("/waitlist")
async def join_waitlist(body: WaitlistRequest):
    email = body.email.strip().lower()

    if not email or not _EMAIL_RE.match(email):
        return JSONResponse(
            status_code=422,
            content={"ok": False, "error": "Invalid email address"},
        )

    logger.info("Waitlist signup: %s (source=%s)", email, body.source)

    # --- Future: persist to Supabase ---
    # supabase_url = os.environ.get("SUPABASE_URL")
    # supabase_key = os.environ.get("SUPABASE_ANON_KEY")
    # if supabase_url and supabase_key:
    #     ... upsert into waitlist table ...

    return {"ok": True, "message": "You're on the list. We'll be in touch."}
