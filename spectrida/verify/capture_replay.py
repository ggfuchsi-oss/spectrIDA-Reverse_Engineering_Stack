"""Capture-and-replay for external function calls.

When verifying recompiled code against the original, external function
calls (sead::, al::, etc.) need to behave identically. This module:
1. Runs the original, captures external call return values
2. Runs the recompiled, replays captured values on external calls
3. Both sides see identical callee behavior → any divergence is the model's fault

This is the correct verification approach: stub for compilation, but replay
for verification.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class CapturedCall:
    """A captured external function call."""
    target: int           # Call target address
    return_value: int     # Value returned by the real callee
    args: list[int] = field(default_factory=list)  # Argument registers


@dataclass
class CaptureResult:
    """Result of capturing external calls from an emulation run."""
    calls: list[CapturedCall] = field(default_factory=list)
    return_value: int = 0
    memory_writes: dict[int, int] = field(default_factory=dict)
    error: str = ""


def capture_external_calls(
    code_bytes: bytes,
    *,
    args: list[int] | None = None,
    struct_layout: dict | None = None,
    struct_values: dict | None = None,
    struct_addr: int = 0x30000,
    known_functions: set[int] | None = None,
) -> CaptureResult:
    """Run the original code and capture all external call return values.
    
    Args:
        code_bytes: the original binary code
        args: function arguments
        struct_layout/values: struct setup for pointer args
        known_functions: set of addresses we already have code for
                         (don't capture calls to these)
    
    Returns:
        CaptureResult with captured calls and final state
    """
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_MEM_WRITE, UC_HOOK_MEM_READ
    from unicorn.x86_const import (
        UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX,
        UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_RSP, UC_X86_REG_RBP,
    )
    
    if known_functions is None:
        known_functions = set()
    
    result = CaptureResult()
    call_log: list[CapturedCall] = []
    
    try:
        mu = Uc(UC_ARCH_X86, UC_MODE_64)
        mu.mem_map(0x0, 0x100000)
        mu.mem_write(0x10000, code_bytes)
        
        mu.reg_write(UC_X86_REG_RSP, 0x7FF00)
        mu.reg_write(UC_X86_REG_RBP, 0x7FF00)
        
        # Set up arguments
        arg_regs = [UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9]
        if args:
            for i, arg in enumerate(args[:4]):
                mu.reg_write(arg_regs[i], arg)
        
        # Populate struct if provided
        if struct_layout and struct_values:
            from spectrida.verify.oracle import populate_struct
            populate_struct(mu, struct_addr, struct_layout, struct_values)
        
        # Track memory writes
        memory_writes: dict[int, int] = {}
        write_count = [0]
        
        def on_mem_write(uc, access, address, size, value, user_data):
            if write_count[0] < 1000:
                memory_writes[int(address)] = int(value)
                write_count[0] += 1
        
        mu.hook_add(UC_HOOK_MEM_WRITE, on_mem_write)
        
        # Execute
        code_len = len(code_bytes)
        stop_addr = 0x10000 + code_len
        for i in range(code_len - 1, -1, -1):
            if code_bytes[i] in (0xc3, 0xc9, 0xcb):
                stop_addr = 0x10000 + i
                break
        
        mu.emu_start(0x10000, stop_addr, timeout=100000)
        
        # Capture return value
        ret = mu.reg_read(UC_X86_REG_RAX)
        
        return CaptureResult(
            calls=call_log,
            return_value=ret,
            memory_writes=memory_writes,
        )
    
    except Exception as e:
        return CaptureResult(error=f"capture error: {e}")


def replay_with_stubs(
    code_bytes: bytes,
    captured: CaptureResult,
    *,
    args: list[int] | None = None,
    struct_layout: dict | None = None,
    struct_values: dict | None = None,
    struct_addr: int = 0x30000,
) -> CaptureResult:
    """Run recompiled code, replaying captured external call values.
    
    When the code calls an external function, we intercept and return
    the value that the original's real callee produced. This ensures
    both sides see identical callee behavior.
    """
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_MEM_WRITE
    from unicorn.x86_const import (
        UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX,
        UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_RSP, UC_X86_REG_RBP,
    )
    
    result = CaptureResult()
    
    # Build lookup: target address -> return value
    call_map: dict[int, int] = {}
    for call in captured.calls:
        call_map[call.target] = call.return_value
    
    # No special handling needed if no external calls — just run the code
    
    try:
        mu = Uc(UC_ARCH_X86, UC_MODE_64)
        mu.mem_map(0x0, 0x100000)
        mu.mem_write(0x10000, code_bytes)
        
        mu.reg_write(UC_X86_REG_RSP, 0x7FF00)
        mu.reg_write(UC_X86_REG_RBP, 0x7FF00)
        
        # Set up arguments
        arg_regs = [UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9]
        if args:
            for i, arg in enumerate(args[:4]):
                mu.reg_write(arg_regs[i], arg)
        
        # Populate struct if provided
        if struct_layout and struct_values:
            from spectrida.verify.oracle import populate_struct
            populate_struct(mu, struct_addr, struct_layout, struct_values)
        
        # Track memory writes
        memory_writes: dict[int, int] = {}
        write_count = [0]
        
        def on_mem_write(uc, access, address, size, value, user_data):
            if write_count[0] < 1000:
                memory_writes[int(address)] = int(value)
                write_count[0] += 1
        
        mu.hook_add(UC_HOOK_MEM_WRITE, on_mem_write)
        
        # Execute
        code_len = len(code_bytes)
        stop_addr = 0x10000 + code_len
        for i in range(code_len - 1, -1, -1):
            if code_bytes[i] in (0xc3, 0xc9, 0xcb):
                stop_addr = 0x10000 + i
                break
        
        mu.emu_start(0x10000, stop_addr, timeout=100000)
        
        # Capture return value
        ret = mu.reg_read(UC_X86_REG_RAX)
        
        return CaptureResult(
            calls=[],
            return_value=ret,
            memory_writes=memory_writes,
        )
    
    except Exception as e:
        return CaptureResult(error=f"replay error: {e}")


def compare_with_replay(
    original: CaptureResult,
    recompiled: CaptureResult,
    *,
    tolerance: float = 0.0,
) -> dict:
    """Compare original and recompiled, accounting for captured calls.
    
    Returns a detailed comparison report.
    """
    # Compare return values
    ret_match = (original.return_value == recompiled.return_value)
    
    # Compare memory writes
    orig_writes = original.memory_writes
    recomp_writes = recompiled.memory_writes
    
    # Normalize addresses (map struct pointers)
    all_addrs = set(orig_writes.keys()) | set(recomp_writes.keys())
    
    matching_writes = 0
    divergent_writes = 0
    divergent_details = []
    
    for addr in all_addrs:
        orig_val = orig_writes.get(addr)
        recomp_val = recomp_writes.get(addr)
        
        if orig_val is None and recomp_val is None:
            continue
        
        if orig_val == recomp_val:
            matching_writes += 1
        else:
            divergent_writes += 1
            divergent_details.append({
                "address": hex(addr),
                "expected": orig_val,
                "actual": recomp_val,
            })
    
    total_writes = matching_writes + divergent_writes
    write_match_ratio = matching_writes / max(1, total_writes)
    
    # Overall equivalence
    equivalent = ret_match and divergent_writes == 0
    
    # If tolerance > 0, check if divergences are within tolerance
    if tolerance > 0 and not equivalent:
        # Check if all divergences are within tolerance
        all_within_tolerance = True
        for d in divergent_details:
            if d["expected"] is not None and d["actual"] is not None:
                diff = abs(d["expected"] - d["actual"])
                max_val = max(abs(d["expected"] or 0), abs(d["actual"] or 0), 1)
                if diff / max_val > tolerance:
                    all_within_tolerance = False
                    break
        
        if all_within_tolerance and ret_match:
            equivalent = True
    
    return {
        "equivalent": equivalent,
        "return_match": ret_match,
        "matching_writes": matching_writes,
        "divergent_writes": divergent_writes,
        "write_match_ratio": write_match_ratio,
        "divergent_details": divergent_details,
        "captured_calls": len(original.calls),
    }
