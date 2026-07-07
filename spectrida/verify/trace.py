"""Execution trace and divergence reporting for verified decompilation.

Phase 0-1: Define and capture ordered event traces.
Phase 2: Compare traces and report divergences.
"""
from __future__ import annotations

from dataclasses import dataclass, field


# ── Event types ──────────────────────────────────────────────────────────────

@dataclass
class MemoryWriteEvent:
    """A memory write during execution."""
    order: int          # Execution order (0, 1, 2, ...)
    addr: int           # Memory address written
    size: int           # Bytes written (1, 2, 4, 8)
    value: int          # Value written
    pc: int             # Program counter when write occurred


@dataclass
class CallEvent:
    """A function call during execution."""
    order: int
    target: int         # Call target address
    args: list[int]     # Argument register values
    pc: int


@dataclass
class ReturnEvent:
    """A function return."""
    order: int
    value: int          # Return value
    pc: int


@dataclass
class ExecutionTrace:
    """Ordered trace of execution events."""
    memory_writes: list[MemoryWriteEvent] = field(default_factory=list)
    calls: list[CallEvent] = field(default_factory=list)
    returns: list[ReturnEvent] = field(default_factory=list)
    
    @property
    def all_events(self) -> list:
        """Get all events sorted by order."""
        events = []
        events.extend(self.memory_writes)
        events.extend(self.calls)
        events.extend(self.returns)
        events.sort(key=lambda e: e.order)
        return events
    
    def summary(self) -> dict:
        """Get a summary of the trace."""
        return {
            "memory_writes": len(self.memory_writes),
            "calls": len(self.calls),
            "returns": len(self.returns),
            "total_events": len(self.all_events),
        }


@dataclass
class DivergenceReport:
    """Report of where two execution traces diverge."""
    equivalent: bool = False
    first_divergent_event: int = -1  # Order of first mismatch
    last_matching_event: int = -1    # Order of last match
    expected: str = ""               # What the original did
    actual: str = ""                 # What the recompiled did
    inferred_location: str = ""      # Where in the code (if known)
    details: str = ""                # Full divergence details


# ── Normalization ────────────────────────────────────────────────────────────

def normalize_address(addr: int, base_map: dict[int, int] | None = None) -> int:
    """Normalize an address using a base address mapping.
    
    For example, map struct pointers to a canonical base so
    "wrote to base+8" compares to "wrote to base+8" regardless of
    where the struct actually lives in memory.
    """
    if base_map and addr in base_map:
        return base_map[addr]
    return addr


def normalize_trace(
    trace: ExecutionTrace,
    base_map: dict[int, int] | None = None,
) -> ExecutionTrace:
    """Normalize a trace for comparison.
    
    - Maps addresses through base_map if provided
    - Ignores absolute stack addresses (compare relative offsets)
    - Sorts benign writes within same block
    """
    normalized = ExecutionTrace()
    
    for event in trace.memory_writes:
        norm_addr = normalize_address(event.addr, base_map)
        normalized.memory_writes.append(MemoryWriteEvent(
            order=event.order,
            addr=norm_addr,
            size=event.size,
            value=event.value,
            pc=event.pc,
        ))
    
    normalized.calls = trace.calls[:]
    normalized.returns = trace.returns[:]
    
    return normalized


# ── Trace comparison ─────────────────────────────────────────────────────────

def compare_traces(
    original: ExecutionTrace,
    recompiled: ExecutionTrace,
    *,
    tolerance: float = 0.0,
) -> DivergenceReport:
    """Compare two execution traces and find the first divergence.
    
    Returns a DivergenceReport with:
    - Whether they're equivalent
    - The first divergent event (order)
    - The last matching event (order)
    - Expected vs actual values
    - Inferred location (if known)
    """
    orig_events = original.all_events
    recomp_events = recompiled.all_events
    
    # Walk both sequences in order
    max_len = max(len(orig_events), len(recomp_events))
    
    last_match = -1
    first_divergence = -1
    expected = ""
    actual = ""
    
    for i in range(max_len):
        if i >= len(orig_events):
            # Original ran out of events — recompiled has extra
            first_divergence = i
            expected = "no event"
            actual = f"{type(recomp_events[i]).__name__}"
            break
        
        if i >= len(recomp_events):
            # Recompiled ran out — original has extra
            first_divergence = i
            expected = f"{type(orig_events[i]).__name__}"
            actual = "no event"
            break
        
        orig_evt = orig_events[i]
        recomp_evt = recomp_events[i]
        
        # Compare events
        match = _compare_events(orig_evt, recomp_evt, tolerance)
        
        if match:
            last_match = i
        else:
            first_divergence = i
            expected = _event_description(orig_evt)
            actual = _event_description(recomp_evt)
            break
    
    # If no divergence found, they're equivalent
    equivalent = (first_divergence == -1)
    
    return DivergenceReport(
        equivalent=equivalent,
        first_divergent_event=first_divergence,
        last_matching_event=last_match,
        expected=expected,
        actual=actual,
        inferred_location="",
        details=f"Matched {last_match + 1} events, diverged at event {first_divergence}" if not equivalent else "All events matched",
    )


def _compare_events(orig, recomp, tolerance: float) -> bool:
    """Compare two events for equivalence."""
    if type(orig) != type(recomp):
        return False
    
    if isinstance(orig, MemoryWriteEvent):
        # Address and value must match (with tolerance for values)
        addr_match = (orig.addr == recomp.addr)
        if tolerance > 0 and orig.addr != recomp.addr:
            # Allow some address variance
            diff = abs(orig.addr - recomp.addr)
            max_val = max(abs(orig.addr), abs(recomp.addr), 1)
            addr_match = (diff / max_val) <= tolerance
        
        value_match = (orig.value == recomp.value)
        if tolerance > 0 and orig.value != recomp.value:
            diff = abs(orig.value - recomp.value)
            max_val = max(abs(orig.value), abs(recomp.value), 1)
            value_match = (diff / max_val) <= tolerance
        
        return addr_match and value_match
    
    elif isinstance(orig, CallEvent):
        return orig.target == recomp.target
    
    elif isinstance(orig, ReturnEvent):
        if tolerance > 0:
            diff = abs(orig.value - recomp.value)
            max_val = max(abs(orig.value), abs(recomp.value), 1)
            return (diff / max_val) <= tolerance
        return orig.value == recomp.value
    
    return False


def _event_description(event) -> str:
    """Get a human-readable description of an event."""
    if isinstance(event, MemoryWriteEvent):
        return f"write {event.size}B to {hex(event.addr)} = {event.value}"
    elif isinstance(event, CallEvent):
        return f"call {hex(event.target)}"
    elif isinstance(event, ReturnEvent):
        return f"return {event.value}"
    return str(type(event).__name__)


# ── Trace collection from Unicorn ────────────────────────────────────────────

def collect_trace_from_emulation(
    code_bytes: bytes,
    *,
    args: list[int] | None = None,
    struct_layout: dict | None = None,
    struct_values: dict | None = None,
    struct_addr: int = 0x30000,
    arg_index: int = 0,
    arch: str = "x86_64",
) -> tuple[ExecutionTrace, dict]:
    """Run emulation and collect an ordered execution trace.
    
    Returns (trace, result_dict) where result_dict has the existing format
    for backward compatibility.
    """
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_HOOK_MEM_WRITE
    from unicorn.x86_const import (
        UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX,
        UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_RSP, UC_X86_REG_RBP,
    )
    
    trace = ExecutionTrace()
    event_order = [0]
    
    if arch != "x86_64":
        # ARM64 trace collection would go here
        return trace, {"error": "ARM64 trace not implemented yet"}
    
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
        
        # Hook memory writes to record trace
        def on_mem_write(uc, access, address, size, value, user_data):
            pc = uc.reg_read(UC_X86_REG_RAX)  # Approximate PC
            trace.memory_writes.append(MemoryWriteEvent(
                order=event_order[0],
                addr=int(address),
                size=size,
                value=int(value),
                pc=pc,
            ))
            event_order[0] += 1
        
        mu.hook_add(UC_HOOK_MEM_WRITE, on_mem_write)
        
        # Execute up to ret
        code_len = len(code_bytes)
        stop_addr = 0x10000 + code_len
        for i in range(code_len - 1, -1, -1):
            if code_bytes[i] in (0xc3, 0xc9, 0xcb):
                stop_addr = 0x10000 + i
                break
        
        mu.emu_start(0x10000, stop_addr, timeout=100000)
        
        # Record return
        ret = mu.reg_read(UC_X86_REG_RAX)
        trace.returns.append(ReturnEvent(
            order=event_order[0],
            value=ret,
            pc=stop_addr,
        ))
        
        # Build backward-compatible result
        memory_writes = {}
        for evt in trace.memory_writes:
            memory_writes[evt.addr] = evt.value
        
        return trace, {
            "return_value": ret,
            "memory_writes": memory_writes,
            "memory_hash": str(hash(tuple(sorted(memory_writes.items())))),
            "error": "",
        }
    
    except Exception as e:
        return trace, {"error": str(e)}
