"""Issuer persistence (sqlite).

The accounts table is the complete, normative list of what the issuer may
store about a user: an opaque account id, the device public key, the maximum
scope, and two timestamps. No date of birth, no attester artifacts, no
issuance contents (blinded messages are never persisted).
"""

from __future__ import annotations

import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
    account_id BLOB PRIMARY KEY,
    device_pub BLOB NOT NULL,
    max_scope INTEGER NOT NULL,
    enrolled_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS seen_requests (
    request_id BLOB PRIMARY KEY,
    ts INTEGER NOT NULL
);
"""


@dataclass(frozen=True)
class Account:
    """The complete issuer-side record for one enrollment."""

    account_id: bytes
    device_pub: bytes
    max_scope: int
    enrolled_at: int
    expires_at: int


class IssuerStore:
    """Thread-safe sqlite-backed store for accounts and issuance request ids."""

    def __init__(self, path: str | Path) -> None:
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._lock = threading.Lock()
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    def add_account(self, account: Account) -> None:
        """Persist a new enrollment."""
        with self._lock:
            self._conn.execute(
                "INSERT INTO accounts VALUES (?, ?, ?, ?, ?)",
                (
                    account.account_id,
                    account.device_pub,
                    account.max_scope,
                    account.enrolled_at,
                    account.expires_at,
                ),
            )
            self._conn.commit()

    def get_account(self, account_id: bytes) -> Account | None:
        """Fetch an enrollment by account id."""
        with self._lock:
            row = self._conn.execute(
                "SELECT account_id, device_pub, max_scope, enrolled_at, expires_at"
                " FROM accounts WHERE account_id = ?",
                (account_id,),
            ).fetchone()
        return Account(*row) if row else None

    def mark_request(self, request_id: bytes, now: int, window: int = 600) -> bool:
        """Record a request id; return False if it was already seen in the window.

        Old entries are swept opportunistically on each call.
        """
        with self._lock:
            self._conn.execute("DELETE FROM seen_requests WHERE ts < ?", (now - window,))
            cursor = self._conn.execute(
                "INSERT OR IGNORE INTO seen_requests VALUES (?, ?)", (request_id, now)
            )
            self._conn.commit()
            return cursor.rowcount == 1
