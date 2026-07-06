"""Knowledge base for verified function identity pairs.

Stores ground-truth "function X in binary A = function Y in binary B"
links, populated from Diaphora high-confidence matches and emulation
verification.
"""
from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass
class KBEntry:
    """A verified or high-confidence function identity link."""
    binary_old: str
    addr_old: int
    name_old: str
    binary_new: str
    addr_new: int
    name_new: str
    similarity: float        # fingerprint similarity
    ratio: float             # Diaphora ratio (if available)
    source: str              # "diaphora", "emulation", "fingerprint"
    verified: bool           # True if emulation-verified
    timestamp: float = 0.0


class KnowledgeBase:
    """SQLite-backed knowledge base for function identity pairs."""

    def __init__(self, db_path: str = ""):
        if not db_path:
            from spectrida.config import CONFIG_DIR
            db_path = str(Path.home() / ".spectrida" / "memory.db")
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS pairs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    binary_old TEXT,
                    addr_old INTEGER,
                    name_old TEXT,
                    binary_new TEXT,
                    addr_new INTEGER,
                    name_new TEXT,
                    similarity REAL,
                    ratio REAL,
                    source TEXT,
                    verified INTEGER,
                    timestamp REAL
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_pairs_old
                ON pairs(binary_old, addr_old)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_pairs_new
                ON pairs(binary_new, addr_new)
            """)

    def add_pair(self, entry: KBEntry) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO pairs
                (binary_old, addr_old, name_old, binary_new, addr_new, name_new,
                 similarity, ratio, source, verified, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                entry.binary_old, entry.addr_old, entry.name_old,
                entry.binary_new, entry.addr_new, entry.name_new,
                entry.similarity, entry.ratio, entry.source,
                1 if entry.verified else 0,
                entry.timestamp or time.time(),
            ))

    def add_pairs(self, entries: list[KBEntry]) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.executemany("""
                INSERT INTO pairs
                (binary_old, addr_old, name_old, binary_new, addr_new, name_new,
                 similarity, ratio, source, verified, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, [
                (e.binary_old, e.addr_old, e.name_old,
                 e.binary_new, e.addr_new, e.name_new,
                 e.similarity, e.ratio, e.source,
                 1 if e.verified else 0,
                 e.timestamp or time.time())
                for e in entries
            ])

    def query_by_function(
        self, binary: str, addr: int
    ) -> list[KBEntry]:
        """Find all known identities for a function."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("""
                SELECT * FROM pairs
                WHERE (binary_old = ? AND addr_old = ?)
                   OR (binary_new = ? AND addr_new = ?)
                ORDER BY similarity DESC
            """, (binary, addr, binary, addr)).fetchall()
        return [self._row_to_entry(r) for r in rows]

    def query_by_binary(self, binary: str) -> list[KBEntry]:
        """Get all pairs involving a binary."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("""
                SELECT * FROM pairs
                WHERE binary_old = ? OR binary_new = ?
                ORDER BY similarity DESC
            """, (binary, binary)).fetchall()
        return [self._row_to_entry(r) for r in rows]

    def stats(self) -> dict:
        with sqlite3.connect(self.db_path) as conn:
            total = conn.execute("SELECT count(*) FROM pairs").fetchone()[0]
            verified = conn.execute("SELECT count(*) FROM pairs WHERE verified = 1").fetchone()[0]
            binaries = conn.execute(
                "SELECT count(DISTINCT binary_old) + count(DISTINCT binary_new) FROM pairs"
            ).fetchone()[0]
        return {"total_pairs": total, "verified": verified, "binaries": binaries}

    def _row_to_entry(self, row) -> KBEntry:
        return KBEntry(
            binary_old=row["binary_old"], addr_old=row["addr_old"],
            name_old=row["name_old"], binary_new=row["binary_new"],
            addr_new=row["addr_new"], name_new=row["name_new"],
            similarity=row["similarity"], ratio=row["ratio"],
            source=row["source"], verified=bool(row["verified"]),
            timestamp=row["timestamp"],
        )
