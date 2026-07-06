"""Evaluation harness for cross-binary function recall.

Phase 0: establishes the metric. Given function F in binary A, does the
system retrieve its true counterpart in binary B in the top-k?

Reports recall@1 and recall@5 against a baseline of byte-hash lookup.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from spectrida.memory.fingerprint import (
    FunctionFeatures,
    fingerprint_v0,
    cosine_similarity,
)
from spectrida.memory.index import IndexEntry, VectorIndex


@dataclass
class EvalPair:
    """A known-matching function pair across binaries."""
    binary_a: str
    addr_a: int
    name_a: str
    binary_b: str
    addr_b: int
    name_b: str
    ground_truth_ratio: float = 1.0  # Diaphora ratio


@dataclass
class EvalResult:
    """Result of an evaluation run."""
    method: str
    recall_at_1: float = 0.0
    recall_at_5: float = 0.0
    total_pairs: int = 0
    correct_at_1: int = 0
    correct_at_5: int = 0
    elapsed_ms: float = 0.0


def build_eval_set_from_diaphora(
    diff_results: str,
    min_ratio: float = 0.95,
) -> list[EvalPair]:
    """Build an eval set from Diaphora diff results.

    Takes high-confidence (≥min_ratio) matches as ground truth.
    """
    import sqlite3

    conn = sqlite3.connect(diff_results)
    conn.row_factory = sqlite3.Row

    pairs = []
    for row in conn.execute(
        "SELECT address, name, address2, name2, ratio "
        "FROM results WHERE ratio >= ?",
        (min_ratio,)
    ):
        try:
            addr_a = int(row["address"], 16) if isinstance(row["address"], str) else row["address"]
            addr_b = int(row["address2"], 16) if isinstance(row["address2"], str) else row["address2"]
            pairs.append(EvalPair(
                binary_a="old", addr_a=addr_a, name_a=row["name"] or "",
                binary_b="new", addr_b=addr_b, name_b=row["name2"] or "",
                ground_truth_ratio=row["ratio"] or 1.0,
            ))
        except (ValueError, TypeError):
            continue

    conn.close()
    return pairs


def evaluate_recall(
    eval_pairs: list[EvalPair],
    index_a: VectorIndex,
    features_b: dict[int, FunctionFeatures],
    method_name: str = "fingerprint_v0",
) -> EvalResult:
    """Evaluate recall@k for a set of known pairs.

    For each pair (F_a in binary_a, F_b in binary_b):
    1. Look up F_a's vector in index_a
    2. Query the index with F_b's features
    3. Check if F_a appears in the top-k results

    Returns EvalResult with recall@1 and recall@5.
    """
    correct_1 = 0
    correct_5 = 0
    total = 0

    t0 = time.time()

    for pair in eval_pairs:
        if pair.addr_b not in features_b:
            continue

        feat_b = features_b[pair.addr_b]
        vec_b = fingerprint_v0(feat_b)

        # Query index_a (which contains binary_a functions)
        # We want to find pair.addr_a in the results
        results = index_a.query(
            vec_b, top_k=5, exclude_binary=pair.binary_b,
        )

        # Check if the ground truth is in top-1 and top-5
        addrs_seen = [entry.addr for entry, _ in results]

        if addrs_seen and addrs_seen[0] == pair.addr_a:
            correct_1 += 1
        if pair.addr_a in addrs_seen:
            correct_5 += 1

        total += 1

    elapsed = (time.time() - t0) * 1000

    return EvalResult(
        method=method_name,
        recall_at_1=correct_1 / max(1, total),
        recall_at_5=correct_5 / max(1, total),
        total_pairs=total,
        correct_at_1=correct_1,
        correct_at_5=correct_5,
        elapsed_ms=elapsed,
    )


def evaluate_byte_hash_baseline(
    eval_pairs: list[EvalPair],
    hash_a: dict[int, str],
    hash_b: dict[int, str],
) -> EvalResult:
    """Baseline: byte-hash lookup (exact match only).

    This is what fingerprint_v0 needs to beat.
    """
    correct_1 = 0
    correct_5 = 0  # byte hash is exact, so 1 = 5
    total = 0

    for pair in eval_pairs:
        if pair.addr_a not in hash_a or pair.addr_b not in hash_b:
            continue

        h_b = hash_b[pair.addr_b]
        h_a = hash_a[pair.addr_a]

        # Byte-hash baseline: exact match only
        if h_a == h_b:
            correct_1 += 1
            correct_5 += 1

        total += 1

    return EvalResult(
        method="byte_hash_baseline",
        recall_at_1=correct_1 / max(1, total),
        recall_at_5=correct_5 / max(1, total),
        total_pairs=total,
        correct_at_1=correct_1,
        correct_at_5=correct_5,
    )
