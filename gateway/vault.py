"""
gateway/vault.py — Secure PII Vault
======================================

Session-isolated SQLite storage for original ↔ placeholder mappings.

Security constraints:
- Each session has its own isolated namespace.
- Cross-session queries are impossible by design (session_id is always required).
- Mappings are NEVER logged or exposed in audit trails.
- The vault is the ONLY component that holds raw PII values.

Usage:
    vault = PIIVault("privacy_vault.db")
    vault.initialize()

    # Store a mapping
    vault.store("session-abc", "PERSON", "PERSON_1", "Rahul Sharma")

    # Look up by original value (for consistency across turns)
    placeholder = vault.get_placeholder("session-abc", "Rahul Sharma")
    # → "PERSON_1"

    # Restore placeholder to original (for safe response restoration)
    original = vault.get_original("session-abc", "PERSON_1")
    # → "Rahul Sharma"

    vault.close()
"""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path
from typing import Optional


class PIIVault:
    """
    Session-isolated SQLite vault for PII placeholder mappings.

    Parameters
    ----------
    db_path : str or Path
        Path to the SQLite database file. Use ":memory:" for testing.
    """

    def __init__(self, db_path: str | Path = ":memory:"):
        self._db_path = str(db_path)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
        if self._db_path != ":memory:":
            self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.row_factory = sqlite3.Row
        self.initialize()

    def _get_conn(self) -> sqlite3.Connection:
        """Get database connection."""
        return self._conn

    def initialize(self) -> None:
        """Create the database schema if it doesn't exist."""
        with self._lock:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS mappings (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id      TEXT    NOT NULL,
                    entity_type     TEXT    NOT NULL,
                    placeholder     TEXT    NOT NULL,
                    original_value  TEXT    NOT NULL,
                    original_lower  TEXT    NOT NULL,
                    turn_number     INTEGER NOT NULL DEFAULT 1,
                    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE INDEX IF NOT EXISTS idx_session
                    ON mappings(session_id);

                CREATE INDEX IF NOT EXISTS idx_session_placeholder
                    ON mappings(session_id, placeholder);

                CREATE INDEX IF NOT EXISTS idx_session_original
                    ON mappings(session_id, original_lower);

                CREATE UNIQUE INDEX IF NOT EXISTS idx_session_placeholder_unique
                    ON mappings(session_id, placeholder);

                CREATE TABLE IF NOT EXISTS session_counters (
                    session_id  TEXT NOT NULL,
                    entity_type TEXT NOT NULL,
                    next_index  INTEGER NOT NULL DEFAULT 1,
                    PRIMARY KEY (session_id, entity_type)
                );

                CREATE TABLE IF NOT EXISTS aliases (
                    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id            TEXT    NOT NULL,
                    entity_type           TEXT    NOT NULL,
                    alias_value           TEXT    NOT NULL,
                    alias_lower           TEXT    NOT NULL,
                    canonical_placeholder TEXT    NOT NULL,
                    created_at            TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE UNIQUE INDEX IF NOT EXISTS idx_session_alias_unique
                    ON aliases(session_id, alias_lower);
                """
            )
            self._conn.commit()

    # ── Store & Lookup ────────────────────────────────────────

    def store(
        self,
        session_id: str,
        entity_type: str,
        placeholder: str,
        original_value: str,
        turn_number: int = 1,
    ) -> None:
        """
        Store a PII mapping.

        Parameters
        ----------
        session_id : str
            The session this mapping belongs to.
        entity_type : str
            Entity type (e.g., "PERSON", "EMAIL_ADDRESS").
        placeholder : str
            The placeholder string (e.g., "PERSON_1").
        original_value : str
            The original PII text.
        turn_number : int
            Conversation turn where this entity was first seen.
        """
        with self._lock:
            self._conn.execute(
                """
                INSERT OR IGNORE INTO mappings
                    (session_id, entity_type, placeholder, original_value, original_lower, turn_number)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (session_id, entity_type, placeholder, original_value,
                 original_value.lower().strip(), turn_number),
            )
            self._conn.commit()

    def get_placeholder(
        self, session_id: str, original_value: str
    ) -> Optional[str]:
        """
        Look up the placeholder for a known original value (case-insensitive).

        Returns None if no mapping exists for this session + original value.
        """
        with self._lock:
            row = self._conn.execute(
                """
                SELECT placeholder FROM mappings
                WHERE session_id = ? AND original_lower = ?
                LIMIT 1
                """,
                (session_id, original_value.lower().strip()),
            ).fetchone()
            return row["placeholder"] if row else None

    def get_original(
        self, session_id: str, placeholder: str
    ) -> Optional[str]:
        """
        Look up the original value for a placeholder.

        Returns None if no mapping exists for this session + placeholder.
        """
        with self._lock:
            row = self._conn.execute(
                """
                SELECT original_value FROM mappings
                WHERE session_id = ? AND placeholder = ?
                LIMIT 1
                """,
                (session_id, placeholder),
            ).fetchone()
            return row["original_value"] if row else None

    # ── Alias Operations ──────────────────────────────────────

    def store_alias(
        self,
        session_id: str,
        entity_type: str,
        alias_value: str,
        canonical_placeholder: str,
    ) -> None:
        """Store an alias mapped to a canonical placeholder."""
        val_clean = alias_value.strip()
        if not val_clean:
            return
        with self._lock:
            self._conn.execute(
                """
                INSERT OR IGNORE INTO aliases
                    (session_id, entity_type, alias_value, alias_lower, canonical_placeholder)
                VALUES (?, ?, ?, ?, ?)
                """,
                (session_id, entity_type, val_clean, val_clean.lower(), canonical_placeholder),
            )
            self._conn.commit()

    def get_alias_placeholder(
        self, session_id: str, alias_value: str
    ) -> Optional[str]:
        """Look up canonical placeholder for an alias."""
        with self._lock:
            row = self._conn.execute(
                """
                SELECT canonical_placeholder FROM aliases
                WHERE session_id = ? AND alias_lower = ?
                LIMIT 1
                """,
                (session_id, alias_value.lower().strip()),
            ).fetchone()
            return row["canonical_placeholder"] if row else None

    def get_all_aliases(self, session_id: str) -> list[dict[str, str]]:
        """Get all registered aliases for a session."""
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT entity_type, alias_value, canonical_placeholder
                FROM aliases
                WHERE session_id = ?
                ORDER BY LENGTH(alias_value) DESC
                """,
                (session_id,),
            ).fetchall()
            return [dict(row) for row in rows]

    # ── Placeholder Index Management ─────────────────────────

    def get_next_index(self, session_id: str, entity_type: str) -> int:
        """
        Get and increment the next placeholder index for an entity type.

        First call for (session, PERSON) returns 1, next returns 2, etc.
        """
        with self._lock:
            row = self._conn.execute(
                """
                SELECT next_index FROM session_counters
                WHERE session_id = ? AND entity_type = ?
                """,
                (session_id, entity_type),
            ).fetchone()

            if row is None:
                # First entity of this type in this session
                self._conn.execute(
                    """
                    INSERT INTO session_counters (session_id, entity_type, next_index)
                    VALUES (?, ?, 2)
                    """,
                    (session_id, entity_type),
                )
                self._conn.commit()
                return 1
            else:
                current = row["next_index"]
                self._conn.execute(
                    """
                    UPDATE session_counters
                    SET next_index = next_index + 1
                    WHERE session_id = ? AND entity_type = ?
                    """,
                    (session_id, entity_type),
                )
                self._conn.commit()
                return current

    # ── Session Management ───────────────────────────────────

    def get_all_mappings(self, session_id: str) -> list[dict]:
        """
        Get all mappings for a session (for restoration purposes).

        Returns list of dicts with keys: entity_type, placeholder, original_value, turn_number.
        """
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT entity_type, placeholder, original_value, turn_number
                FROM mappings
                WHERE session_id = ?
                ORDER BY id
                """,
                (session_id,),
            ).fetchall()
            return [dict(row) for row in rows]

    def get_session_stats(self, session_id: str) -> dict:
        """
        Get aggregate stats for a session (safe to log — no PII values).

        Returns dict with entity_type → count.
        """
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT entity_type, COUNT(*) as count
                FROM mappings
                WHERE session_id = ?
                GROUP BY entity_type
                """,
                (session_id,),
            ).fetchall()
            return {row["entity_type"]: row["count"] for row in rows}

    def delete_session(self, session_id: str) -> int:
        """
        Delete all mappings and counters for a session. Returns rows deleted.
        """
        with self._lock:
            cursor = self._conn.execute(
                "DELETE FROM mappings WHERE session_id = ?",
                (session_id,),
            )
            self._conn.execute(
                "DELETE FROM session_counters WHERE session_id = ?",
                (session_id,),
            )
            self._conn.execute(
                "DELETE FROM aliases WHERE session_id = ?",
                (session_id,),
            )
            self._conn.commit()
            return cursor.rowcount

    # ── Lifecycle ─────────────────────────────────────────────

    def close(self) -> None:
        """Close the database connection."""
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None

    def __repr__(self) -> str:
        return f"PIIVault(db={self._db_path!r})"

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
