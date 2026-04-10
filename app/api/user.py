"""
D-012: User Account API — GDPR-compliant data deletion.

DELETE /api/user/me
  Wipes all scans, findings, and profile data belonging to the authenticated user.
  Required for GDPR Article 17 "right to erasure" compliance.

The user is identified from their JWT sub (Supabase user ID).
All operations run in a single transaction — either everything is deleted or nothing.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from app.api.deps import CurrentUser
from app.models import database as db

logger = logging.getLogger("zse.api.user")
router = APIRouter(prefix="/api/user", tags=["user"])


class DeleteAccountResponse(BaseModel):
    message: str
    user_id: str
    scans_deleted: int


@router.delete("/me", response_model=DeleteAccountResponse, status_code=200)
async def delete_account(current_user: CurrentUser) -> DeleteAccountResponse:
    """Permanently delete all data for the authenticated user (GDPR Article 17).

    Deletes in order:
        1. All scan findings belonging to the user's scans
        2. All scans belonging to the user
        3. User profile record (if stored)

    This operation is IRREVERSIBLE. The frontend must show a confirmation dialog
    before calling this endpoint.

    Returns the count of deleted scans for audit logging.
    """
    user_id: str = current_user.get("sub", "")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Could not determine user identity from token.",
        )

    logger.info("GDPR delete request: user_id=%s", user_id)

    try:
        scans_deleted = await db.delete_user_data(user_id)
    except AttributeError:
        # delete_user_data may not exist on all db backends yet — fail gracefully
        logger.error(
            "delete_user_data not implemented on current database backend. "
            "Add it to app/models/database.py and database_sqlite.py."
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Data deletion is not yet available on this deployment.",
        )
    except Exception as exc:
        logger.error("GDPR delete failed for user %s: %s", user_id, exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Data deletion failed. Please contact support.",
        )

    logger.info(
        "GDPR delete complete: user_id=%s scans_deleted=%d", user_id, scans_deleted
    )

    return DeleteAccountResponse(
        message=(
            "Your account and all associated data have been permanently deleted. "
            "This action cannot be undone."
        ),
        user_id=user_id,
        scans_deleted=scans_deleted,
    )
