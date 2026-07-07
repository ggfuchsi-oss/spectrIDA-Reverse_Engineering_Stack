"""Self-verifying decompilation loop.

Feed pseudocode to the model → compile → emulate → compare with original.
On mismatch, feed the behavioral diff back as a repair hint and retry.

This is the core loop that turns plausible-looking decompilation into
provably-correct, editable source.
"""
from __future__ import annotations

import os

import asyncio
import re
from dataclasses import dataclass, field

from spectrida.verify.helpers import parse_struct_layout, find_external_calls, estimate_function_complexity
from spectrida.verify.oracle import (
    EmulationResult,
    OracleVerdict,
    compile_c_to_shared,
    emulate_function,
    compare_emulations,
    extract_function_bytes,
)


# ── Types ────────────────────────────────────────────────────────────────────

@dataclass
class LiftAttempt:
    """One attempt at lifting a function to C."""
    attempt_num: int
    c_code: str = ""
    compiled: bool = False
    compile_error: str = ""
    verified: bool = False
    verdict: OracleVerdict | None = None
    oracle_error: str = ""


@dataclass
class LiftResult:
    """Final result of the self-verifying loop."""
    func_name: str
    verified_c: str = ""
    attempts: list[LiftAttempt] = field(default_factory=list)
    final_verdict: OracleVerdict | None = None
    total_attempts: int = 0
    success: bool = False


# ── Prompt ───────────────────────────────────────────────────────────────────

LIFT_SYSTEM = (
    "You are an expert C programmer specializing in reverse engineering. "
    "Given Hex-Rays pseudocode from a stripped binary, produce clean, "
    "compilable C code. The output must be a complete function with:\n"
    "- Correct types (use int, long long, void*, etc. based on context)\n"
    "- Correct return type\n"
    "- No placeholders or TODOs\n"
    "- No external function calls (implement inline if needed)\n"
    "- Just the function, no headers or main\n\n"
    "IMPORTANT: The code must compile with gcc -O2 -nostdlib -shared."
)

LIFT_PROMPT_TEMPLATE = (
    "Convert this pseudocode to compilable C:\n\n"
    "```c\n{pseudocode}\n```\n\n"
    "Return ONLY the C function, nothing else."
)

REPAIR_PROMPT_TEMPLATE = (
    "Your previous C code had issues. Here's the feedback:\n\n"
    "{feedback}\n\n"
    "Original pseudocode:\n```c\n{pseudocode}\n```\n\n"
    "Your previous attempt:\n```c\n{previous_c}\n```\n\n"
    "Fix the issues and return ONLY the corrected C function."
)


# ── Model interaction ────────────────────────────────────────────────────────

async def _query_model(
    http: httpx.AsyncClient,
    ollama_url: str,
    system: str,
    user_msg: str,
    *,
    ollama_model: str = "",
    temperature: float = 0.3,
) -> str:
    """Query the model for C code generation."""
    import json

    # Build ChatML prompt
    NL = "\n"
    LT = "<"
    GT = ">"
    BT = "`"

    prompt = (
        LT + "im" + GT + "system" + LT + "/im" + GT + NL + system + LT + "/im" + GT + NL
        + LT + "im" + GT + "user" + LT + "/im" + GT + NL + user_msg + LT + "/im" + GT + NL
        + LT + "im" + GT + "assistant" + LT + "/im" + GT + NL
    )

    if ollama_model:
        url = ollama_url.rstrip("/") + "/api/generate"
        payload = {
            "model": ollama_model,
            "prompt": prompt,
            "stream": False,
            "think": False,
            "options": {"temperature": temperature, "num_predict": 1024},
        }
        resp = await http.post(url, json=payload)
        resp.raise_for_status()
        return resp.json().get("response", "").strip()
    else:
        payload = {
            "prompt": prompt,
            "temperature": temperature,
            "n_predict": 1024,
        }
        resp = await http.post(ollama_url, json=payload)
        resp.raise_for_status()
        return resp.json().get("content", "").strip()


NL = chr(10)

def _extract_struct_context(pseudocode: str) -> str:
    """Extract struct definitions from pseudocode for the model prompt."""
    import re
    
    structs = []
    
    # Find struct field accesses in both styles:
    # Style 1: *((TYPE *)this + offset)
    # Style 2: ptr->field_name
    type_offsets = {}
    field_names = {}
    
    # Style 1: *((TYPE *)this + offset)
    for m in re.finditer(r'\*\(\((\w+)\s*\*\)\s*\((\w+)\s*\+\s*(\d+)\)\)', pseudocode):
        field_type = m.group(1)
        offset = int(m.group(3))
        if field_type not in type_offsets:
            type_offsets[field_type] = []
        type_offsets[field_type].append(offset)
    
    # Style 2: ptr->field_name (infer offset from order)
    for m in re.finditer(r'(\w+)->(\w+)', pseudocode):
        ptr_name = m.group(1)
        field_name = m.group(2)
        if ptr_name not in field_names:
            field_names[ptr_name] = []
        field_names[ptr_name].append(field_name)
    
    # Build struct definitions from type-offset pairs
    for field_type, offsets in type_offsets.items():
        offsets.sort()
        struct_name = "GameData"  # Generic name
        fields = []
        for i, offset in enumerate(offsets):
            field_name = f"field_{offset}"
            fields.append(f"    {field_type} {field_name};")
        
        struct_def = "typedef struct {" + NL + NL.join(fields) + NL + "} " + struct_name + ";"
        structs.append(struct_def)
    
    # Build struct definitions from ptr->field patterns
    for ptr_name, fields in field_names.items():
        if len(fields) >= 2:  # Only if we have multiple fields
            struct_name = ptr_name.capitalize() + "Data"
            struct_fields = []
            for i, field_name in enumerate(fields):
                struct_fields.append(f"    int {field_name};")  # Assume int for now
            
            struct_def = "typedef struct {" + NL + NL.join(struct_fields) + NL + "} " + struct_name + ";"
            structs.append(struct_def)
    
    return NL.join(structs) if structs else ""


def _extract_c_code(text: str) -> str:
    """Extract C code from model response (strip markdown, comments, etc.)."""
    # Remove markdown code blocks
    text = re.sub(r'```c?\s*\n?', '', text)
    text = re.sub(r'```\s*$', '', text, flags=re.MULTILINE)

    # Remove leading/trailing whitespace
    text = text.strip()

    # If it starts with a comment, skip to the function
    lines = text.split('\n')
    start = 0
    for i, line in enumerate(lines):
        if re.match(r'^\s*(typedef|struct|static|void|int|long|char|unsigned|float|double|__int|const|inline)', line):
            start = i
            break

    return '\n'.join(lines[start:]).strip()


# ── Oracle interaction ───────────────────────────────────────────────────────

def _build_verdict_feedback(verdict: OracleVerdict, c_code: str) -> str:
    """Build a feedback string from a failed oracle verdict."""
    parts = []

    if not verdict.return_match:
        parts.append(f"Return value mismatch: original={verdict.details}")

    if not verdict.memory_match:
        parts.append(f"Memory write mismatch: the function writes to different addresses or with different values than expected.")

    if verdict.reason:
        parts.append(f"Oracle verdict: {verdict.reason}")

    return "\n".join(parts)


# ── Main loop ────────────────────────────────────────────────────────────────

async def lift_function(
    pseudocode: str,
    original_bytes: bytes,
    func_name: str = "target",
    *,
    http: httpx.AsyncClient | None = None,
    ollama_url: str = "",
    ollama_model: str = "",
    max_attempts: int = 3,
    args: list[int] | None = None,
) -> LiftResult:
    """Self-verifying decompilation loop.

    1. Ask model to convert pseudocode to C
    2. Compile the C
    3. Emulate both original and recompiled
    4. Compare via oracle
    5. On mismatch, feed back the error and retry

    Returns LiftResult with the verified C (if successful) and all attempts.
    """
    import httpx as _httpx

    if http is None:
        http = _httpx.AsyncClient(timeout=120)
        own_client = True
    else:
        own_client = False

    result = LiftResult(func_name=func_name)
    previous_c = ""

    try:
        for attempt_num in range(1, max_attempts + 1):
            attempt = LiftAttempt(attempt_num=attempt_num)

            # Analyze function context
            ctx = estimate_function_complexity(pseudocode)
            externals = find_external_calls(pseudocode)
            
            # 1. Build prompt
            if previous_c and attempt_num > 1:
                user_msg = REPAIR_PROMPT_TEMPLATE.format(
                    feedback=last_feedback,
                    pseudocode=pseudocode,
                    previous_c=previous_c,
                )
            else:
                struct_ctx = _extract_struct_context(pseudocode)
            user_msg = LIFT_PROMPT_TEMPLATE.format(
                struct_context=struct_ctx,
                pseudocode=pseudocode,
            )

            # 2. Query model
            try:
                raw_response = await _query_model(
                    http, ollama_url, LIFT_SYSTEM, user_msg,
                    ollama_model=ollama_model,
                )
                c_code = _extract_c_code(raw_response)
                attempt.c_code = c_code
            except Exception as e:
                attempt.compile_error = f"model query failed: {e}"
                result.attempts.append(attempt)
                continue

            if not c_code:
                attempt.compile_error = "model returned empty C code"
                result.attempts.append(attempt)
                continue

            # 3. Compile
            import tempfile as _tf; _fd, _dll = _tf.mkstemp(suffix=".dll"); os.close(_fd); compile_result = compile_c_to_shared(c_code, _dll)
            if not compile_result["ok"]:
                attempt.compile_error = compile_result["error"][:300]
                result.attempts.append(attempt)
                last_feedback = f"Compilation failed:\n{attempt.compile_error}"
                continue

            attempt.compiled = True

            # 4. Extract bytes
            extract_result = extract_function_bytes(
                _dll, func_name
            )
            if not extract_result["ok"]:
                attempt.oracle_error = f"extract failed: {extract_result['error']}"
                result.attempts.append(attempt)
                last_feedback = attempt.oracle_error
                continue

            recompiled_bytes = bytes.fromhex(extract_result["bytes"])

            # 5. Emulate original
            orig_result = emulate_function(original_bytes, args=args)
            if orig_result.error:
                attempt.oracle_error = f"original emulation failed: {orig_result.error}"
                result.attempts.append(attempt)
                last_feedback = attempt.oracle_error
                continue

            # 6. Emulate recompiled
            recomp_result = emulate_function(recompiled_bytes, args=args)
            if recomp_result.error:
                attempt.oracle_error = f"recompiled emulation failed: {recomp_result.error}"
                result.attempts.append(attempt)
                last_feedback = attempt.oracle_error
                continue

            # 7. Compare
            verdict = compare_emulations(orig_result, recomp_result)
            attempt.verdict = verdict

            if verdict.equivalent:
                attempt.verified = True
                result.verified_c = c_code
                result.final_verdict = verdict
                result.success = True
                result.attempts.append(attempt)
                break
            else:
                last_feedback = _build_verdict_feedback(verdict, c_code)
                result.attempts.append(attempt)
                previous_c = c_code

    finally:
        if own_client:
            await http.aclose()

    result.total_attempts = len(result.attempts)
    return result
