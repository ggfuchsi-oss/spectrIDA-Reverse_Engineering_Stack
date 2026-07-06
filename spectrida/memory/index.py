"""In-memory vector index for cross-binary function lookup.

Simple numpy-based index for now. Upgrade to turbovec or FAISS later
when the dataset gets big.
"""
from __future__ import annotations

import json
import pickle
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class IndexEntry:
    """One function in the index."""
    binary: str
    addr: int
    name: str
    vector: list[float]
    verified: bool = False       # True if emulation-verified
    source: str = ""             # "diaphora", "emulation", "manual"
    confidence: float = 0.0      # 0-1


@dataclass
class VectorIndex:
    """Simple vector index with linear scan. Good enough for <100k entries."""
    entries: list[IndexEntry] = field(default_factory=list)

    def add(self, entry: IndexEntry) -> None:
        self.entries.append(entry)

    def add_batch(self, entries: list[IndexEntry]) -> None:
        self.entries.extend(entries)

    def query(
        self,
        vector: list[float],
        top_k: int = 10,
        min_similarity: float = 0.0,
        exclude_binary: str = "",
    ) -> list[tuple[IndexEntry, float]]:
        """Find the top_k most similar entries.

        Returns list of (entry, similarity) tuples, sorted by similarity desc.
        """
        results: list[tuple[IndexEntry, float]] = []

        for entry in self.entries:
            if exclude_binary and entry.binary == exclude_binary:
                continue

            sim = _cosine(vector, entry.vector)
            if sim >= min_similarity:
                results.append((entry, sim))

        results.sort(key=lambda x: x[1], reverse=True)
        return results[:top_k]

    def query_by_binary(
        self,
        binary: str,
        vector: list[float],
        top_k: int = 10,
    ) -> list[tuple[IndexEntry, float]]:
        """Query only within a specific binary."""
        return self.query(vector, top_k=top_k, exclude_binary="")

    def stats(self) -> dict:
        return {
            "total": len(self.entries),
            "binaries": len(set(e.binary for e in self.entries)),
            "verified": sum(1 for e in self.entries if e.verified),
        }

    def save(self, path: str) -> None:
        with open(path, "wb") as f:
            pickle.dump(self.entries, f)

    @classmethod
    def load(cls, path: str) -> VectorIndex:
        with open(path, "rb") as f:
            entries = pickle.load(f)
        idx = cls()
        idx.entries = entries
        return idx


def _cosine(a: list[float], b: list[float]) -> float:
    """Fast cosine similarity."""
    dot = 0.0
    norm_a = 0.0
    norm_b = 0.0
    for x, y in zip(a, b):
        dot += x * y
        norm_a += x * x
        norm_b += y * y
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a ** 0.5 * norm_b ** 0.5)
