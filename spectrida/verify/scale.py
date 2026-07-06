"""Scale + triage — run verified decompilation across many functions.

Reports:
- oracle-eligible %: how many functions can be emulated in isolation
- verified %: of eligible, how many reach verified status
- repairable %: of eligible, how many compile but don't verify (fixable)
"""
from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from spectrida.verify.lift import lift_function
from spectrida.verify.oracle import emulate_function, EmulationResult


# ── Types ────────────────────────────────────────────────────────────────────

@dataclass
class FunctionLift:
    """Result of attempting to lift one function."""
    addr: int
    name: str
    pseudocode: str
    oracle_eligible: bool = False
    verified: bool = False
    compile_fail: bool = False
    attempts: int = 0
    verified_c: str = ""
    error: str = ""


@dataclass
class ScaleResult:
    """Aggregate results from scaling across many functions."""
    binary: str = ""
    total_functions: int = 0
    oracle_eligible: int = 0
    verified: int = 0
    compile_fail: int = 0
    not_eligible: int = 0
    elapsed_seconds: float = 0.0
    functions: list[FunctionLift] = field(default_factory=list)


# ── Oracle eligibility check ─────────────────────────────────────────────────

def check_eligibility(pseudocode: str) -> bool:
    """Quick check if a function is likely oracle-eligible.

    Criteria:
    - No syscalls or external function calls (except basic math)
    - No hardware access
    - Pure-ish logic
    """
    if not pseudocode:
        return False

    # Reject if it calls external functions we can't emulate
    external_calls = [
        "syscall", "svc ", "swi ", "int ",  # system calls
        "malloc", "free", "calloc", "realloc",  # heap
        "printf", "fprintf", "snprintf",  # I/O
        "memcpy", "memset", "memmove",  # memory (might be ok, but complex)
        "strlen", "strcmp", "strncmp",  # string (might be ok)
        "open", "close", "read", "write",  # file I/O
        "pthread", "mutex",  # threading
    ]

    pseudo_lower = pseudocode.lower()
    for ext in external_calls:
        if ext in pseudo_lower:
            return False

    # Reject if too complex (many branches)
    branch_count = pseudocode.count("if") + pseudocode.count("else") + pseudocode.count("switch")
    if branch_count > 10:
        return False

    # Reject if too large (many lines)
    line_count = len(pseudocode.split("\n"))
    if line_count > 50:
        return False

    return True


# ── Scale runner ─────────────────────────────────────────────────────────────

async def scale_lift(
    functions: list[dict],
    *,
    http: httpx.AsyncClient | None = None,
    ollama_url: str = "",
    ollama_model: str = "",
    max_attempts: int = 2,
    sample_size: int = 50,
    on_progress=None,
) -> ScaleResult:
    """Run verified decompilation across many functions.

    Args:
        functions: list of {addr, name, pseudocode, original_bytes}
        sample_size: how many to attempt (functions are sampled)
    """
    import httpx as _httpx

    if http is None:
        http = _httpx.AsyncClient(timeout=120)
        own_client = True
    else:
        own_client = False

    result = ScaleResult(total_functions=len(functions))
    t0 = time.time()

    # Sample functions (prefer smaller, simpler ones)
    candidates = [f for f in functions if f.get("pseudocode")]
    candidates.sort(key=lambda f: len(f.get("pseudocode", "")))
    sample = candidates[:sample_size]

    try:
        for i, func in enumerate(sample):
            lift = FunctionLift(
                addr=func["addr"],
                name=func.get("name", f"sub_{func['addr']:x}"),
                pseudocode=func.get("pseudocode", ""),
            )

            # Check eligibility
            if not check_eligibility(func.get("pseudocode", "")):
                lift.error = "not oracle-eligible"
                result.not_eligible += 1
                result.functions.append(lift)
                continue

            result.oracle_eligible += 1

            # Try to lift
            try:
                # Get original bytes if available
                original_bytes = func.get("original_bytes", b"")
                if not original_bytes:
                    lift.error = "no original bytes"
                    result.functions.append(lift)
                    continue

                lift_result = await lift_function(
                    pseudocode=func["pseudocode"],
                    original_bytes=original_bytes,
                    func_name=func.get("name", "target"),
                    http=http,
                    ollama_url=ollama_url,
                    ollama_model=ollama_model,
                    max_attempts=max_attempts,
                    args=func.get("args", [0, 0, 0, 0]),
                )

                lift.attempts = lift_result.total_attempts
                lift.verified = lift_result.success
                lift.verified_c = lift_result.verified_c

                if lift.verified:
                    result.verified += 1
                elif any(a.compiled for a in lift_result.attempts):
                    result.compile_fail += 1  # compiles but doesn't verify
                else:
                    lift.error = "compile failed"

            except Exception as e:
                lift.error = str(e)[:200]

            result.functions.append(lift)

            if on_progress:
                await on_progress(i + 1, len(sample), result)

    finally:
        if own_client:
            await http.aclose()

    result.elapsed_seconds = time.time() - t0
    return result


# ── Persistence ──────────────────────────────────────────────────────────────

def save_verified_source(
    result: ScaleResult,
    out_dir: str,
) -> str:
    """Save verified C functions to a source tree."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    # Write each verified function
    verified_count = 0
    for func in result.functions:
        if func.verified and func.verified_c:
            safe_name = func.name.replace("::", "_").replace(" ", "_")
            c_file = out / f"{safe_name}.c"
            c_file.write_text(func.verified_c, encoding="utf-8")
            verified_count += 1

    # Write index
    index = {
        "binary": result.binary,
        "total": result.total_functions,
        "eligible": result.oracle_eligible,
        "verified": result.verified,
        "functions": [
            {"name": f.name, "addr": hex(f.addr), "verified": f.verified}
            for f in result.functions if f.verified
        ],
    }
    (out / "index.json").write_text(json.dumps(index, indent=2), encoding="utf-8")

    return str(out)


def format_report(result: ScaleResult) -> str:
    """Format a human-readable report."""
    lines = [
        f"=== Verified Decompilation Report ===",
        f"Binary: {result.binary}",
        f"Total functions: {result.total_functions}",
        f"",
        f"Oracle-eligible: {result.oracle_eligible} ({100*result.oracle_eligible/max(1,result.total_functions):.1f}%)",
        f"Verified: {result.verified} ({100*result.verified/max(1,result.oracle_eligible):.1f}% of eligible)",
        f"Compile fail: {result.compile_fail}",
        f"Not eligible: {result.not_eligible}",
        f"",
        f"Time: {result.elapsed_seconds:.1f}s",
    ]
    return "\n".join(lines)
