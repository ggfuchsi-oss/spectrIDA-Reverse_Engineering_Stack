"""Cache for verified functions — avoid re-verifying the same code."""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from pathlib import Path


class VerifiedCache:
    """SQLite-backed cache for verified function C code."""
    
    def __init__(self, db_path: str = ""):
        if not db_path:
            db_path = str(Path.home() / ".spectrida" / "verified_cache.db")
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._ensure_schema()
    
    def _ensure_schema(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS verified (
                    code_hash TEXT PRIMARY KEY,
                    c_code TEXT,
                    func_name TEXT,
                    verified_at REAL,
                    attempts INTEGER DEFAULT 1
                )
            """)
    
    def get(self, code_bytes: bytes) -> str | None:
        """Check if we've already verified this code."""
        code_hash = hashlib.md5(code_bytes).hexdigest()
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT c_code FROM verified WHERE code_hash = ?",
                (code_hash,)
            ).fetchone()
        return row[0] if row else None
    
    def put(self, code_bytes: bytes, c_code: str, func_name: str = "") -> None:
        """Cache a verified function."""
        code_hash = hashlib.md5(code_bytes).hexdigest()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO verified (code_hash, c_code, func_name, verified_at) VALUES (?, ?, ?, ?)",
                (code_hash, c_code, func_name, time.time())
            )
    
    def stats(self) -> dict:
        """Get cache statistics."""
        with sqlite3.connect(self.db_path) as conn:
            total = conn.execute("SELECT count(*) FROM verified").fetchone()[0]
        return {"total_verified": total, "db": self.db_path}
