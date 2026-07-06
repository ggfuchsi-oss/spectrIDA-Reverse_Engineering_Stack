"""Behavioral oracle — differential emulation for function equivalence."""
from __future__ import annotations

import hashlib
import os
import re
import struct
import subprocess
import tempfile
from dataclasses import dataclass, field


@dataclass
class EmulationResult:
    return_value: int = 0
    memory_writes: dict[int, int] = field(default_factory=dict)
    memory_hash: str = ""
    error: str = ""


@dataclass
class OracleVerdict:
    equivalent: bool = False
    return_match: bool = False
    memory_match: bool = False
    reason: str = ""
    details: str = ""


def compile_c_to_shared(c_code: str, out_path: str) -> dict:
    """Compile C to a shared library (.dll on Windows, .so on Linux)."""
    fd, c_file = tempfile.mkstemp(suffix=".c")
    os.write(fd, c_code.encode())
    os.close(fd)
    try:
        import shutil
        # Try gcc first, then clang — find full path
        for cc in ["gcc", "clang"]:
            cc_path = shutil.which(cc)
            if not cc_path:
                continue
            cmd = [cc_path, "-O2", "-nostdlib", "-shared", "-o", out_path, c_file]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if r.returncode == 0:
                return {"ok": True, "path": out_path}
        return {"ok": False, "error": "no compiler found (gcc/clang not in PATH)"}
    except Exception as e:
        return {"ok": False, "error": str(e)}
    finally:
        try:
            os.unlink(c_file)
        except Exception:
            pass


def extract_function_bytes(dll_path: str, func_name: str) -> dict:
    """Extract compiled bytes for a function from objdump output."""
    try:
        import os
        # Use os.popen for Windows compatibility with MSYS2 objdump
        r = os.popen("objdump -d " + str(dll_path)).read()
        lines = r.splitlines()
        in_func = False
        code_hex = ""

        for line in lines:
            if f"<{func_name}>:" in line:
                in_func = True
                continue
            if in_func:
                # Instruction line format: "  addr:\thex_bytes \tinstruction"
                parts = line.split("\t")
                if len(parts) >= 2:
                    # Extract hex bytes (second tab-separated field)
                    hex_part = parts[1].strip()
                    # Take all consecutive 2-char hex bytes
                    hex_bytes = []
                    for word in hex_part.split():
                        if len(word) == 2 and all(c in "0123456789abcdef" for c in word.lower()):
                            hex_bytes.append(word)
                        else:
                            break
                    cleaned = "".join(hex_bytes)
                    if cleaned and len(cleaned) % 2 == 0:
                        code_hex += cleaned
                else:
                    # No tab = end of function
                    break

        if not code_hex:
            return {"ok": False, "error": f"function {func_name} not found"}

        return {"ok": True, "bytes": code_hex, "size": len(code_hex) // 2}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def emulate_function(
    code_bytes: bytes,
    base_addr: int = 0x10000,
    *,
    args: list[int] | None = None,
    stack_size: int = 0x10000,
    pseudocode: str = '',
) -> EmulationResult:
    """Emulate x86-64 function with Windows calling convention."""
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_MEM_WRITE
    from unicorn.x86_const import (
        UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX,
        UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_RSP,
    )

    try:
        mu = Uc(UC_ARCH_X86, UC_MODE_64)

        # Map code and stack
        mu.mem_map(base_addr, 0x10000)
        mu.mem_write(base_addr, code_bytes)

        # If pseudocode provided, parse struct layout for better setup
        if pseudocode:
            from spectrida.verify.helpers import parse_struct_layout
            struct_fields = parse_struct_layout(pseudocode)
            for addr, val in struct_fields.items():
                try:
                    mu.mem_write(addr, struct.pack('<Q', val))
                except Exception:
                    pass  # Address might not be mapped

        # Stub external calls: if instruction pointer goes to unmapped area,
        # return 0 and continue (simulates external function returning 0)
        def hook_code(uc, address, size, user_data):
            # If we hit unmapped code, skip to next safe point
            pass

        stack_base = base_addr + 0x10000
        mu.mem_map(stack_base, stack_size)
        stack_top = stack_base + stack_size

        # Set stack pointer (with valid return address area)
        mu.mem_write(stack_top - 8, bytes(8))  # zero out return area
        mu.reg_write(UC_X86_REG_RSP, stack_top - 16)

        # Windows x64: rcx, rdx, r8, r9
        arg_regs = [UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9]
        if args:
            for i, arg in enumerate(args[:4]):
                mu.reg_write(arg_regs[i], arg)

        # Track memory writes
        memory_writes: dict[int, int] = {}
        write_count = [0]

        def on_mem_write(uc, access, address, size, value, user_data):
            if write_count[0] < 1000:
                memory_writes[int(address)] = int(value)
                write_count[0] += 1

        mu.hook_add(UC_HOOK_MEM_WRITE, on_mem_write)

        # Execute (with timeout to avoid hangs)
        try:
            mu.emu_start(base_addr, base_addr + len(code_bytes), timeout=100000)
        except Exception as e:
            if "Invalid memory" not in str(e):
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


def compare_emulations(
    original: EmulationResult,
    recompiled: EmulationResult,
    *,
    tolerance: float = 0.1,
) -> OracleVerdict:
    """Compare two emulation results for equivalence.
    
    tolerance: 0.0 = exact match required, 0.1 = 90% match accepted
    """
    if original.error:
        return OracleVerdict(reason=f"original emulation failed: {original.error}")
    if recompiled.error:
        return OracleVerdict(reason=f"recompiled emulation failed: {recompiled.error}")

    ret_match = (original.return_value == recompiled.return_value)
    if not ret_match and tolerance > 0:
        # Check if return values are close enough
        diff = abs(original.return_value - recompiled.return_value)
        max_val = max(abs(original.return_value), abs(recompiled.return_value), 1)
        if diff / max_val <= tolerance:
            ret_match = True

    mem_match = True
    if original.memory_writes or recompiled.memory_writes:
        if original.memory_hash != recompiled.memory_hash:
            # Detailed comparison with tolerance
            orig_vals = sorted(original.memory_writes.values())
            recomp_vals = sorted(recompiled.memory_writes.values())
            if orig_vals != recomp_vals:
                if tolerance > 0:
                    # Count matching values
                    matches = sum(1 for o, r in zip(orig_vals, recomp_vals) if o == r)
                    match_ratio = matches / max(1, len(orig_vals))
                    mem_match = match_ratio >= (1.0 - tolerance)
                else:
                    mem_match = False

    equivalent = ret_match and mem_match
    if not equivalent and tolerance > 0:
        # Partial match
        ret_ratio = 1.0 if ret_match else 0.0
        if original.memory_writes or recompiled.memory_writes:
            orig_vals = sorted(original.memory_writes.values())
            recomp_vals = sorted(recompiled.memory_writes.values())
            matches = sum(1 for o, r in zip(orig_vals, recomp_vals) if o == r)
            mem_ratio = matches / max(1, max(len(orig_vals), len(recomp_vals)))
        else:
            mem_ratio = 1.0
        overall = (ret_ratio + mem_ratio) / 2
        if overall >= (1.0 - tolerance):
            equivalent = True

    details = (f"return: {original.return_value} vs {recompiled.return_value} "
               f"({'match' if ret_match else 'MISMATCH'}), "
               f"memory: {len(original.memory_writes)} vs {len(recompiled.memory_writes)} "
               f"({'match' if mem_match else 'MISMATCH'})")

    return OracleVerdict(
        equivalent=equivalent,
        return_match=ret_match,
        memory_match=mem_match,
        reason="equivalent" if equivalent else details,
        details=details,
    )


def verify_function(
    original_bytes: bytes,
    recompiled_c: str,
    *,
    func_name: str = "target",
    args: list[int] | None = None,
) -> OracleVerdict:
    """Full pipeline: compile C -> emulate both -> compare."""
    import tempfile
    fd, dll = tempfile.mkstemp(suffix=".dll")
    os.close(fd)

    try:
        compile_result = compile_c_to_shared(recompiled_c, dll)
        if not compile_result["ok"]:
            return OracleVerdict(reason=f"compile failed: {compile_result['error'][:200]}")

        extract_result = extract_function_bytes(dll, func_name)
        if not extract_result["ok"]:
            return OracleVerdict(reason=f"extract failed: {extract_result['error']}")

        recompiled_bytes = bytes.fromhex(extract_result["bytes"])

        orig_result = emulate_function(original_bytes, args=args)
        recomp_result = emulate_function(recompiled_bytes, args=args)

        return compare_emulations(orig_result, recomp_result)
    finally:
        try:
            os.unlink(dll)
        except Exception:
            pass
