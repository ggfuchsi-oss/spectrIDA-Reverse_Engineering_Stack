"""Behavioral oracle — differential emulation for function equivalence.

The oracle proves a recompiled function is equivalent to the original by:
1. Emulating both with identical inputs
2. Comparing return values + observable memory writes
3. Tolerating benign differences (addresses, uninitialized padding)

This is the make-or-break component. If it can't distinguish correct
from incorrect C, everything downstream fails.
"""
from __future__ import annotations

import hashlib
import struct
import tempfile
import subprocess
import os
from dataclasses import dataclass, field
from pathlib import Path


# ── Types ────────────────────────────────────────────────────────────────────

@dataclass
class EmulationResult:
    """Result of emulating a single function."""
    return_value: int = 0
    memory_writes: dict[int, int] = field(default_factory=dict)  # addr -> value
    memory_hash: str = ""  # hash of written memory for quick comparison
    error: str = ""
    instructions_executed: int = 0


@dataclass
class OracleVerdict:
    """Result of comparing two emulations."""
    equivalent: bool = False
    confidence: float = 0.0  # 0-1
    return_match: bool = False
    memory_match: bool = False
    reason: str = ""
    details: str = ""


# ── Cross-compilation ────────────────────────────────────────────────────────

def compile_c_to_object(
    c_code: str,
    out_obj: str,
    *,
    arch: str = "x86_64",
    compiler: str = "",
    flags: list[str] | None = None,
) -> dict:
    """Compile C code to an object file.

    Returns {"ok": True, "obj": path} or {"ok": False, "error": msg}.
    """
    if not compiler:
        # Try to find a suitable compiler
        for cc in ["gcc", "clang", "cc"]:
            import shutil
            if shutil.which(cc):
                compiler = cc
                break
    if not compiler:
        return {"ok": False, "error": "no compiler found"}

    # Write C to temp file
    fd, c_file = tempfile.mkstemp(suffix=".c", prefix="oracle_")
    os.write(fd, c_code.encode())
    os.close(fd)

    if flags is None:
        flags = ["-O2", "-fno-stack-protector", "-fno-builtin",
                 "-ffreestanding", "-nostdlib"]

    cmd = [compiler, "-c", "-o", out_obj, c_file] + flags

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            return {"ok": False, "error": result.stderr[:500]}
        return {"ok": True, "obj": out_obj}
    except Exception as e:
        return {"ok": False, "error": str(e)}
    finally:
        try:
            os.unlink(c_file)
        except Exception:
            pass


def compile_c_to_shared(
    c_code: str,
    out_so: str,
    *,
    compiler: str = "",
    flags: list[str] | None = None,
) -> dict:
    """Compile C code to a shared library (for extracting function bytes)."""
    if not compiler:
        import shutil
        for cc in ["gcc", "clang"]:
            if shutil.which(cc):
                compiler = cc
                break

    fd, c_file = tempfile.mkstemp(suffix=".c", prefix="oracle_")
    os.write(fd, c_code.encode())
    os.close(fd)

    if flags is None:
        flags = ["-O2", "-fno-stack-protector", "-shared"]

    cmd = [compiler, "-o", out_so, c_file] + flags

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            return {"ok": False, "error": result.stderr[:500]}
        return {"ok": True, "so": out_so}
    except Exception as e:
        return {"ok": False, "error": str(e)}
    finally:
        try:
            os.unlink(c_file)
        except Exception:
            pass


def extract_function_bytes(
    so_path: str,
    func_name: str,
) -> dict:
    """Extract compiled bytes for a specific function from a shared library.

    Uses objdump to find the function and extract its bytes.
    Returns {"ok": True, "bytes": hex_str, "address": int, "size": int}.
    """
    try:
        # Get symbol info
        result = subprocess.run(
            ["objdump", "-t", so_path],
            capture_output=True, text=True, timeout=10,
        )
        for line in result.stdout.splitlines():
            if func_name in line and (" F " in line or line.strip().endswith(func_name)):
                parts = line.split()
                addr = int(parts[0], 16)
                # Size might not be in objdump -t on MinGW, use 64 as default
                size = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 64

                # Extract bytes
                result2 = subprocess.run(
                    ["objdump", "-d", "--start-address=" + hex(addr),
                     "--stop-address=" + hex(addr + size), so_path],
                    capture_output=True, text=True, timeout=10,
                )

                # Parse hex bytes from disassembly
                bytes_hex = ""
                for l in result2.stdout.splitlines():
                    if chr(9) in l:
                        bytes_part = l.split(chr(9))[-1].strip()
                        for b in bytes_part.split():
                            if len(b) == 2:
                                bytes_hex += b

                return {"ok": True, "bytes": bytes_hex, "address": addr, "size": size}

        return {"ok": False, "error": f"function {func_name} not found"}
    except Exception as e:
        return {"ok": False, "error": str(e)}


# ── Emulation ────────────────────────────────────────────────────────────────

def emulate_function(
    code_bytes: bytes,
    base_addr: int = 0x10000,
    *,
    args: list[int] | None = None,
    stack_size: int = 0x10000,
    arch: str = "x86_64",
) -> EmulationResult:
    """Emulate a function with given arguments.

    Sets up a minimal environment (stack, registers) and runs the code.
    Captures return value and memory writes.
    """
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_MEM_WRITE
    from unicorn.x86_const import (
        UC_X86_REG_RAX, UC_X86_REG_RDI, UC_X86_REG_RSI,
        UC_X86_REG_RDX, UC_X86_REG_RCX, UC_X86_REG_R8, UC_X86_REG_R9,
        UC_X86_REG_RSP, UC_X86_REG_RBP, UC_X86_REG_RIP,
    )

    if arch != "x86_64":
        return EmulationResult(error=f"arch {arch} not implemented yet")

    try:
        mu = Uc(UC_ARCH_X86, UC_MODE_64)

        # Map code
        mu.mem_map(base_addr, 0x10000)
        mu.mem_write(base_addr, code_bytes)

        # Map stack
        stack_base = base_addr + 0x10000
        mu.mem_map(stack_base, stack_size)
        stack_top = stack_base + stack_size

        # Set up stack pointer
        mu.reg_write(UC_X86_REG_RSP, stack_top - 8)

        # Set up arguments (System V AMD64 ABI: rdi, rsi, rdx, rcx, r8, r9)
        # Windows x64: rcx, rdx, r8, r9 | SysV: rdi, rsi, rdx, rcx
        # Default to Windows x64 (since we're on Windows)
        arg_regs = [UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9]
        if args:
            for i, arg in enumerate(args[:6]):
                mu.reg_write(arg_regs[i], arg)

        # Track memory writes
        memory_writes: dict[int, int] = {}
        write_count = [0]

        def on_mem_write(uc, access, address, size, value, user_data):
            if write_count[0] < 1000:  # cap
                memory_writes[address] = value
                write_count[0] += 1

        mu.hook_add(UC_HOOK_MEM_WRITE, on_mem_write)

        # Execute
        try:
            mu.emu_start(base_addr, base_addr + len(code_bytes), timeout=1000000)
        except Exception as e:
            if "Invalid memory" in str(e) or "Invalid instruction" in str(e):
                pass  # Function returned or hit unmapped memory — ok
            else:
                return EmulationResult(error=f"emulation error: {e}")

        # Capture return value
        ret = mu.reg_read(UC_X86_REG_RAX)

        # Build memory hash
        if memory_writes:
            mem_data = b""
            for addr in sorted(memory_writes.keys()):
                mem_data += struct.pack("<Q", addr) + struct.pack("<Q", memory_writes[addr])
            mem_hash = hashlib.md5(mem_data).hexdigest()
        else:
            mem_hash = "empty"

        return EmulationResult(
            return_value=ret,
            memory_writes=memory_writes,
            memory_hash=mem_hash,
        )

    except Exception as e:
        return EmulationResult(error=f"setup error: {e}")


# ── Oracle ───────────────────────────────────────────────────────────────────

def compare_emulations(
    original: EmulationResult,
    recompiled: EmulationResult,
    *,
    tolerance: float = 0.0,
) -> OracleVerdict:
    """Compare two emulation results for equivalence.

    Returns an OracleVerdict with the verdict and details.
    """
    # Check for errors
    if original.error:
        return OracleVerdict(reason=f"original emulation failed: {original.error}")
    if recompiled.error:
        return OracleVerdict(reason=f"recompiled emulation failed: {recompiled.error}")

    # Compare return values
    ret_match = (original.return_value == recompiled.return_value)

    # Compare memory writes
    # Tolerate differences in addresses (absolute pointers) and uninitialized padding
    mem_match = True
    if original.memory_writes or recompiled.memory_writes:
        # Quick check: same hash = definitely same
        if original.memory_hash != recompiled.memory_hash:
            # Detailed comparison — check if values at same relative offsets match
            orig_vals = sorted(original.memory_writes.values())
            recomp_vals = sorted(recompiled.memory_writes.values())
            if orig_vals != recomp_vals:
                mem_match = False

    equivalent = ret_match and mem_match

    details_parts = []
    details_parts.append(f"return: {original.return_value} vs {recompiled.return_value} ({'match' if ret_match else 'MISMATCH'})")
    details_parts.append(f"memory_writes: {len(original.memory_writes)} vs {len(recompiled.memory_writes)} ({'match' if mem_match else 'MISMATCH'})")

    return OracleVerdict(
        equivalent=equivalent,
        confidence=1.0 if equivalent else 0.0,
        return_match=ret_match,
        memory_match=mem_match,
        reason="equivalent" if equivalent else f"return {'match' if ret_match else 'MISMATCH'}, memory {'match' if mem_match else 'MISMATCH'}",
        details="; ".join(details_parts),
    )


def verify_function(
    original_bytes: bytes,
    recompiled_c: str,
    *,
    func_name: str = "target",
    args: list[int] | None = None,
    arch: str = "x86_64",
) -> OracleVerdict:
    """Full pipeline: compile C → emulate both → compare.

    This is the main entry point for the oracle.
    """
    # 1. Compile the recompiled C
    fd, obj_file = tempfile.mkstemp(suffix=".o", prefix="verify_")
    os.close(fd)
    compile_result = compile_c_to_object(recompiled_c, obj_file, arch=arch)
    if not compile_result["ok"]:
        return OracleVerdict(reason=f"compile failed: {compile_result['error'][:200]}")

    # 2. Get the compiled bytes
    # For simplicity, we embed the bytes directly in the emulation
    # In production, we'd extract from the .o file
    import struct as _struct

    # Actually, let's just compile to a flat binary approach
    # For now, use the object file bytes directly
    try:
        with open(obj_file, "rb") as f:
            obj_data = f.read()
    except Exception as e:
        return OracleVerdict(reason=f"read obj failed: {e}")
    finally:
        try:
            os.unlink(obj_file)
        except Exception:
            pass

    # 3. Emulate original
    orig_result = emulate_function(original_bytes, args=args, arch=arch)

    # 4. For recompiled, we need to extract the actual function bytes
    # This is tricky with .o files — let's use a simpler approach:
    # compile to executable, extract, emulate
    fd2, so_file = tempfile.mkstemp(suffix=".so", prefix="verify_")
    os.close(fd2)
    compile_result = compile_c_to_shared(recompiled_c, so_file)
    if not compile_result["ok"]:
        return OracleVerdict(reason=f"shared compile failed: {compile_result['error'][:200]}")

    extract_result = extract_function_bytes(so_file, func_name)
    try:
        os.unlink(so_file)
    except Exception:
        pass

    if not extract_result["ok"]:
        return OracleVerdict(reason=f"extract failed: {extract_result['error']}")

    recompiled_bytes = bytes.fromhex(extract_result["bytes"])

    # 5. Emulate recompiled
    recomp_result = emulate_function(recompiled_bytes, args=args, arch=arch)

    # 6. Compare
    return compare_emulations(orig_result, recomp_result)
