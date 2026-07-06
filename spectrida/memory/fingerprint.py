"""Cheap semantic fingerprints for functions — Phase 1.

fingerprint_v0(func) produces a feature vector from robust, cheap signals:
  - Instruction mnemonic histogram (normalized)
  - Callgraph degree (in/out)
  - Referenced string set (hashed)
  - Distinctive constant set (hashed)
  - Function size (log-scaled)
  - Pseudocode token shape (keyword frequencies)

These survive recompiles and minor code changes that kill byte-hash matching.
"""
from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass, field


# ── Feature dimensions ───────────────────────────────────────────────────────

# Mnemonic categories for ARM64/x86-64 — group similar instructions
_MNEM_CATEGORIES = {
    # Data movement
    "mov": 0, "ldr": 0, "str": 0, "ldp": 0, "stp": 0, "ldrb": 0, "strb": 0,
    "ldrh": 0, "strh": 0, "ldrsw": 0, "movz": 0, "movk": 0, "adrp": 0, "add": 0,
    "lea": 0, "movzx": 0, "movsx": 0, "cmov": 0,
    # Arithmetic
    "add": 1, "sub": 1, "mul": 1, "div": 1, "sdiv": 1, "udiv": 1, "mod": 1,
    "srem": 1, "urem": 1, "neg": 1, "inc": 1, "dec": 1, "imul": 1, "idiv": 1,
    "fadd": 1, "fsub": 1, "fmul": 1, "fdiv": 1,
    # Logic
    "and": 2, "or": 2, "xor": 2, "not": 2, "shl": 2, "shr": 2, "sar": 2,
    "lsl": 2, "lsr": 2, "asr": 2, "bic": 2, "orn": 2,
    # Compare/test
    "cmp": 3, "tst": 3, "teq": 3, "test": 3, "cmn": 3,
    # Branch
    "b": 4, "bl": 4, "br": 4, "blr": 4, "ret": 4, "jmp": 4, "call": 4,
    "je": 4, "jne": 4, "jz": 4, "jnz": 4, "jg": 4, "jl": 4, "jge": 4, "jle": 4,
    "cbz": 4, "cbnz": 4, "tbz": 4, "tbnz": 4,
    # Stack
    "push": 5, "pop": 5, "sub": 5,  # sp adjustments
    # SIMD/FP
    "fmla": 6, "fmul": 6, "fadd": 6, "fdiv": 6, "fcvt": 6, "scvtf": 6,
    "ldr": 6,  # q-register loads
}

_NUM_CATEGORIES = 7  # 0-6


# ── Pseudocode keywords ──────────────────────────────────────────────────────

_PSEUDO_KEYWORDS = [
    "if", "else", "for", "while", "do", "switch", "case", "break", "continue",
    "return", "goto", "sizeof", "NULL", "nullptr", "true", "false",
    "malloc", "free", "realloc", "calloc", "memcpy", "memset", "memmove",
    "strlen", "strcmp", "strncmp", "strcpy", "strncpy", "sprintf", "snprintf",
    "printf", "fprintf", "vprintf", "vsnprintf",
    "new", "delete", "throw", "try", "catch",
    "class", "struct", "union", "enum", "typedef", "virtual", "override",
    "public", "private", "protected", "static", "extern", "const", "volatile",
    "int", "char", "void", "bool", "float", "double", "long", "short",
    "unsigned", "signed", "size_t", "uint8_t", "uint16_t", "uint32_t", "uint64_t",
    "int8_t", "int16_t", "int32_t", "int64_t",
    "FILE", "HANDLE", "HWND", "LPARAM", "WPARAM", "LRESULT",
]

_NUM_KEYWORDS = len(_PSEUDO_KEYWORDS)


# ── Feature vector ───────────────────────────────────────────────────────────

# Total dimensions:
#   7 mnemonic categories
# + 2 callgraph degrees (in, out)
# + 1 function size (log)
# + 78 pseudocode keyword frequencies
# + 8 string hash buckets
# + 8 constant hash buckets
# = 104 dimensions

DIM = 104


@dataclass
class FunctionFeatures:
    """Raw features extracted from a function before vectorization."""
    addr: int = 0
    name: str = ""
    binary: str = ""
    size: int = 0
    disasm: list[dict] = field(default_factory=list)
    pseudocode: str = ""
    strings: list[str] = field(default_factory=list)
    constants: list[int] = field(default_factory=list)
    num_callers: int = 0
    num_callees: int = 0


def _hash_bucket(val: str, num_buckets: int = 8) -> int:
    """Hash a string to a bucket index."""
    h = int(hashlib.md5(val.encode()).hexdigest(), 16)
    return h % num_buckets


def _log_scale(val: int, max_val: int = 10000) -> float:
    """Log-scale a value to [0, 1]."""
    if val <= 0:
        return 0.0
    return min(1.0, math.log1p(val) / math.log1p(max_val))


def _mnemonic_histogram(disasm: list[dict]) -> list[float]:
    """Compute normalized mnemonic category histogram."""
    counts = [0.0] * _NUM_CATEGORIES
    total = 0

    for insn in disasm:
        text = insn.get("text", "")
        parts = text.split()
        if not parts:
            continue
        mnem = parts[0].lower()
        cat = _MNEM_CATEGORIES.get(mnem, -1)
        if cat >= 0:
            counts[cat] += 1
            total += 1

    # Normalize
    if total > 0:
        counts = [c / total for c in counts]
    return counts


def _pseudocode_keywords(pseudocode: str) -> list[float]:
    """Compute normalized pseudocode keyword frequencies."""
    if not pseudocode:
        return [0.0] * _NUM_KEYWORDS

    # Tokenize: split on non-alphanumeric, case-insensitive
    tokens = re.findall(r'[a-zA-Z_]\w*', pseudocode)
    token_set = {}
    for t in tokens:
        t_lower = t.lower()
        token_set[t_lower] = token_set.get(t_lower, 0) + 1

    total = max(1, len(tokens))
    freqs = []
    for kw in _PSEUDO_KEYWORDS:
        freqs.append(token_set.get(kw.lower(), 0) / total)
    return freqs


def _string_hash_buckets(strings: list[str]) -> list[float]:
    """Hash strings into buckets for a rough string fingerprint."""
    buckets = [0.0] * 8
    for s in strings:
        if not s:
            continue
        b = _hash_bucket(s, 8)
        buckets[b] += 1
    # Normalize
    total = max(1, sum(buckets))
    return [b / total for b in buckets]


def _constant_hash_buckets(constants: list[int]) -> list[float]:
    """Hash constants into buckets."""
    buckets = [0.0] * 8
    for c in constants:
        b = _hash_bucket(str(c), 8)
        buckets[b] += 1
    total = max(1, sum(buckets))
    return [b / total for b in buckets]


def fingerprint_v0(features: FunctionFeatures) -> list[float]:
    """Compute a cheap semantic fingerprint for a function.

    Returns a list of floats (DIM dimensions) that can be compared
    with cosine similarity to find semantically similar functions.
    """
    vec: list[float] = []

    # Mnemonic histogram (7 dims)
    vec.extend(_mnemonic_histogram(features.disasm))

    # Callgraph degree (2 dims)
    vec.append(_log_scale(features.num_callers))
    vec.append(_log_scale(features.num_callees))

    # Function size (1 dim)
    vec.append(_log_scale(features.size))

    # Pseudocode keywords (47 dims)
    vec.extend(_pseudocode_keywords(features.pseudocode))

    # String hash buckets (8 dims)
    vec.extend(_string_hash_buckets(features.strings))

    # Constant hash buckets (8 dims)
    vec.extend(_constant_hash_buckets(features.constants))

    assert len(vec) == DIM, f"Expected {DIM} dims, got {len(vec)}"
    return vec


# ── Similarity ───────────────────────────────────────────────────────────────

def cosine_similarity(a: list[float], b: list[float]) -> float:
    """Compute cosine similarity between two vectors."""
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(x * x for x in b))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


def l2_distance(a: list[float], b: list[float]) -> float:
    """Compute L2 distance between two vectors."""
    return math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b)))
