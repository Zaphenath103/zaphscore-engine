"""
D-062: Crypto engine tests — encrypt/decrypt roundtrip for findings.

Tests:
  - Encrypt then decrypt returns original findings
  - Empty list roundtrip
  - No key configured -> plain JSON passthrough
  - Invalid ciphertext falls back gracefully
  - encrypt_field / decrypt_field roundtrip
  - Findings with special characters roundtrip cleanly
"""
from __future__ import annotations

import os
import pytest
from cryptography.fernet import Fernet


@pytest.fixture(autouse=True)
def reset_crypto_state():
    """Reset the crypto module global state between tests."""
    import app.engine.crypto as crypto_mod
    crypto_mod._fernet = None
    crypto_mod._KEY = None
    yield
    crypto_mod._fernet = None
    crypto_mod._KEY = None


@pytest.fixture()
def encryption_key() -> str:
    return Fernet.generate_key().decode()


class TestEncryptDecryptFindings:
    def test_roundtrip_with_key(self, encryption_key):
        """encrypt then decrypt returns original list."""
        os.environ["FINDINGS_ENCRYPTION_KEY"] = encryption_key
        import app.engine.crypto as crypto_mod
        crypto_mod._fernet = None  # force re-init

        findings = [
            {"id": "abc", "type": "vulnerability", "severity": "critical", "title": "Log4Shell"},
            {"id": "def", "type": "secret", "severity": "high", "title": "AWS Key"},
        ]

        ciphertext = crypto_mod.encrypt_findings(findings)
        assert ciphertext != str(findings)  # must be encrypted
        assert "Log4Shell" not in ciphertext  # plaintext not visible

        recovered = crypto_mod.decrypt_findings(ciphertext)
        assert recovered == findings

        del os.environ["FINDINGS_ENCRYPTION_KEY"]

    def test_empty_list_roundtrip(self, encryption_key):
        """Empty findings list encrypts and decrypts cleanly."""
        os.environ["FINDINGS_ENCRYPTION_KEY"] = encryption_key
        import app.engine.crypto as crypto_mod
        crypto_mod._fernet = None

        result = crypto_mod.decrypt_findings(crypto_mod.encrypt_findings([]))
        assert result == []

        del os.environ["FINDINGS_ENCRYPTION_KEY"]

    def test_no_key_returns_plain_json(self):
        """Without encryption key, findings stored as plain JSON."""
        os.environ.pop("FINDINGS_ENCRYPTION_KEY", None)
        import app.engine.crypto as crypto_mod
        crypto_mod._fernet = None

        findings = [{"title": "test", "severity": "low"}]
        stored = crypto_mod.encrypt_findings(findings)
        import json
        parsed = json.loads(stored)
        assert parsed == findings

    def test_decrypt_plain_json_without_key(self):
        """Decrypt gracefully handles plain JSON when no key is set."""
        os.environ.pop("FINDINGS_ENCRYPTION_KEY", None)
        import app.engine.crypto as crypto_mod
        crypto_mod._fernet = None

        import json
        plain = json.dumps([{"title": "finding", "severity": "medium"}])
        result = crypto_mod.decrypt_findings(plain)
        assert result[0]["title"] == "finding"

    def test_decrypt_empty_string_returns_empty(self):
        """Decrypt of empty string returns empty list, never raises."""
        import app.engine.crypto as crypto_mod
        result = crypto_mod.decrypt_findings("")
        assert result == []

    def test_decrypt_invalid_ciphertext_falls_back(self, encryption_key):
        """Invalid ciphertext does not crash — returns empty list."""
        os.environ["FINDINGS_ENCRYPTION_KEY"] = encryption_key
        import app.engine.crypto as crypto_mod
        crypto_mod._fernet = None

        result = crypto_mod.decrypt_findings("this-is-not-valid-ciphertext")
        assert isinstance(result, list)  # Never raises

        del os.environ["FINDINGS_ENCRYPTION_KEY"]

    def test_special_characters_in_findings(self, encryption_key):
        """Findings with special characters/unicode roundtrip correctly."""
        os.environ["FINDINGS_ENCRYPTION_KEY"] = encryption_key
        import app.engine.crypto as crypto_mod
        crypto_mod._fernet = None

        findings = [{"title": "SQL Injection — `'; DROP TABLE users; --`", "file": "src/db.py"}]
        result = crypto_mod.decrypt_findings(crypto_mod.encrypt_findings(findings))
        assert result[0]["title"] == findings[0]["title"]

        del os.environ["FINDINGS_ENCRYPTION_KEY"]


class TestEncryptField:
    def test_field_roundtrip(self, encryption_key):
        """Single string field encrypts and decrypts correctly."""
        os.environ["FINDINGS_ENCRYPTION_KEY"] = encryption_key
        import app.engine.crypto as crypto_mod
        crypto_mod._fernet = None

        original = "https://github.com/owner/private-repo"
        encrypted = crypto_mod.encrypt_field(original)
        assert encrypted != original
        assert crypto_mod.decrypt_field(encrypted) == original

        del os.environ["FINDINGS_ENCRYPTION_KEY"]

    def test_empty_field_passthrough(self):
        """Empty string is returned as-is without error."""
        import app.engine.crypto as crypto_mod
        assert crypto_mod.encrypt_field("") == ""
        assert crypto_mod.decrypt_field("") == ""
