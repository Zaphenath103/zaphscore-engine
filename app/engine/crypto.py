"""
D-013: Findings Encryption at Rest — Fernet AES-128-CBC symmetric encryption.

Encrypts scan findings before they are stored in the database and decrypts
them on retrieval. Uses the cryptography library's Fernet implementation
(AES-128-CBC + HMAC-SHA256 authentication).

Environment variable required:
    FINDINGS_ENCRYPTION_KEY — base64-urlsafe 32-byte key generated with:
        python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

If FINDINGS_ENCRYPTION_KEY is not set, findings are stored unencrypted with a
warning logged. This allows the app to start in development without the key.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

logger = logging.getLogger("zse.engine.crypto")

_KEY: bytes | None = None
_fernet = None


def _get_fernet():
    """Lazily initialise Fernet with the encryption key from env."""
    global _KEY, _fernet
    if _fernet is not None:
        return _fernet

    key_str = os.environ.get("FINDINGS_ENCRYPTION_KEY", "")
    if not key_str:
        logger.warning(
            "FINDINGS_ENCRYPTION_KEY not set — findings stored unencrypted. "
            "Generate a key with: python -c \"from cryptography.fernet import Fernet; "
            "print(Fernet.generate_key().decode())\""
        )
        return None

    try:
        from cryptography.fernet import Fernet
        _fernet = Fernet(key_str.encode())
        logger.info("Findings encryption initialised (Fernet AES-128-CBC)")
        return _fernet
    except Exception as exc:
        logger.error("Failed to initialise encryption: %s", exc)
        return None


def encrypt_findings(findings: list[dict[str, Any]]) -> str:
    """Encrypt a list of findings dicts to a base64 ciphertext string.

    Returns plain JSON string if encryption key is not configured (with warning).
    The returned string is safe to store in any text column.
    """
    payload = json.dumps(findings, default=str)
    f = _get_fernet()
    if f is None:
        return payload  # Unencrypted fallback

    encrypted = f.encrypt(payload.encode("utf-8"))
    return encrypted.decode("utf-8")


def decrypt_findings(data: str) -> list[dict[str, Any]]:
    """Decrypt a ciphertext string back to a list of findings dicts.

    Handles both encrypted (Fernet token) and plain JSON (no-key fallback).
    """
    if not data:
        return []

    f = _get_fernet()
    if f is None:
        # No key configured — assume plain JSON
        try:
            return json.loads(data)
        except Exception:
            return []

    try:
        decrypted = f.decrypt(data.encode("utf-8"))
        return json.loads(decrypted.decode("utf-8"))
    except Exception:
        # Fallback: try plain JSON (for data stored before encryption was enabled)
        try:
            logger.warning("Fernet decryption failed — falling back to plain JSON parse")
            return json.loads(data)
        except Exception:
            logger.error("Could not decrypt or parse findings data")
            return []


def encrypt_field(value: str) -> str:
    """Encrypt a single string field (e.g. repo_url, error message)."""
    f = _get_fernet()
    if f is None or not value:
        return value
    return f.encrypt(value.encode("utf-8")).decode("utf-8")


def decrypt_field(value: str) -> str:
    """Decrypt a single encrypted string field."""
    if not value:
        return value
    f = _get_fernet()
    if f is None:
        return value
    try:
        return f.decrypt(value.encode("utf-8")).decode("utf-8")
    except Exception:
        return value  # Return raw if decryption fails (plain text stored before key was set)
