# SPDX-License-Identifier: Apache-2.0
"""Quarantine store: Fernet-encrypted payload storage with TTL."""

import logging
import os
import sqlite3
import stat
import time
from pathlib import Path

from cryptography.fernet import Fernet

logger = logging.getLogger(__name__)


class QuarantineStore:
    """Stores encrypted input/output payloads with TTL.

    Attributes:
        db_path: Path to SQLite database.
        key_path: Path to Fernet key file.
        ttl_hours: TTL for quarantined payloads (default 168 = 7 days).
        _cipher: Cached Fernet cipher instance.
    """

    def __init__(self, db_path: str, key_path: str | None = None, ttl_hours: int = 168) -> None:
        """Initialize the quarantine store.

        Args:
            db_path: Path to SQLite database.
            key_path: Path to Fernet key file. If None, uses <db_dir>/.key.
            ttl_hours: TTL for quarantined payloads (default 168).
        """
        self.db_path = db_path
        self.ttl_hours = ttl_hours

        if key_path is None:
            db_dir = Path(db_path).parent
            key_path = str(db_dir / ".key")

        self.key_path = key_path
        self._cipher: Fernet | None = None

    def _load_or_create_key(self) -> Fernet:
        """Load or create the Fernet encryption key.

        Returns:
            Fernet cipher instance.

        Raises:
            ValueError: If key path directory is world-writable.
        """
        if self._cipher is not None:
            return self._cipher

        key_path_obj = Path(self.key_path)
        key_dir = key_path_obj.parent

        # Security: verify key directory is not world-writable
        if key_dir.exists():
            dir_stat = key_dir.stat()
            if dir_stat.st_mode & stat.S_IWOTH:
                raise ValueError(f"Security error: quarantine key directory is world-writable: {key_dir}")

        # Load existing key or generate new one
        if key_path_obj.exists():
            with open(key_path_obj, "rb") as f:
                key_bytes = f.read()
            logger.info(f"Loaded quarantine key from {self.key_path}")
        else:
            key_bytes = Fernet.generate_key()

            # Ensure directory exists
            key_dir.mkdir(parents=True, exist_ok=True)

            # Write key with mode 0600 (owner read/write only)
            with open(key_path_obj, "wb") as f:
                f.write(key_bytes)

            # Enforce mode 0600
            os.chmod(key_path_obj, 0o600)
            logger.info(f"Generated and persisted quarantine key to {self.key_path} (mode 0600)")

        self._cipher = Fernet(key_bytes)
        return self._cipher

    async def write(self, input_text: str, output_text: str | None = None) -> int:
        """Write a quarantined payload (encrypted).

        Args:
            input_text: The input text to quarantine.
            output_text: The output text (optional).

        Returns:
            The quarantine row ID.
        """
        import asyncio

        return await asyncio.to_thread(self._write_sync, input_text, output_text)

    def _write_sync(self, input_text: str, output_text: str | None = None) -> int:
        """Synchronous implementation of write.

        Args:
            input_text: The input text to quarantine.
            output_text: The output text (optional).

        Returns:
            The quarantine row ID.
        """
        cipher = self._load_or_create_key()

        # Encrypt payloads
        encrypted_input = cipher.encrypt(input_text.encode()).decode()
        encrypted_output = cipher.encrypt(output_text.encode()).decode() if output_text else None

        # Compute expires_at using UTC localtime (to match datetime('now') in SQLite)
        expires_at = time.strftime(
            "%Y-%m-%d %H:%M:%S",
            time.localtime(time.time() + self.ttl_hours * 3600),
        )

        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()

            cursor.execute(
                "INSERT INTO QuarantinedPayload (input_text, output_text, expires_at) VALUES (?, ?, ?)",
                (encrypted_input, encrypted_output, expires_at),
            )
            conn.commit()

            row_id = cursor.lastrowid
            assert row_id is not None
            return row_id

        finally:
            conn.close()

    async def sweep_expired(self) -> int:
        """Delete expired quarantine rows.

        Returns:
            Number of rows deleted.
        """
        import asyncio

        return await asyncio.to_thread(self._sweep_expired_sync)

    def _sweep_expired_sync(self) -> int:
        """Synchronous implementation of sweep_expired.

        Returns:
            Number of rows deleted.
        """
        now = time.strftime("%Y-%m-%d %H:%M:%S")

        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()

            cursor.execute("DELETE FROM QuarantinedPayload WHERE expires_at < ?", (now,))
            conn.commit()

            deleted = cursor.rowcount
            if deleted > 0:
                logger.info(f"Swept {deleted} expired quarantine rows")

            return deleted

        finally:
            conn.close()

    async def decrypt_payload(self, encrypted_text: str) -> str:
        """Decrypt a quarantine payload (for forensic inspection).

        Args:
            encrypted_text: The encrypted payload.

        Returns:
            The decrypted plaintext.
        """
        cipher = self._load_or_create_key()
        decrypted = cipher.decrypt(encrypted_text.encode())
        return decrypted.decode()
