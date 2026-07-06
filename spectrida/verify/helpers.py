"""Helper functions for verified decompilation."""
from __future__ import annotations

import re
import struct


def parse_struct_layout(pseudocode: str, base_addr: int = 0x20000) -> dict[int, int]:
    """Parse struct fields from pseudocode and set up initial memory.
    
    Returns dict of address -> initial value for struct fields.
    Uses heuristics to guess field types and set reasonable defaults.
    """
    fields = {}
    
    # Pattern 1: *((TYPE *)this + N) — direct offset access
    for m in re.finditer(r'\*\(\((\w+\s*\*?)\)\s*\(this\s*\+\s*(\d+)\)', pseudocode):
        field_type = m.group(1).strip()
        offset = int(m.group(2))
        fields[base_addr + offset] = 0
    
    # Pattern 2: *((_BYTE *)this + N)
    for m in re.finditer(r'\*\(\((_BYTE)\s*\*\)\s*\(this\s*\+\s*(\d+)\)', pseudocode):
        offset = int(m.group(2))
        fields[base_addr + offset] = 0
    
    # Pattern 3: *((_QWORD *)this + N)
    for m in re.finditer(r'\*\(\((_QWORD)\s*\*\)\s*\(this\s*\+\s*(\d+)\)', pseudocode):
        offset = int(m.group(2)) * 8  # QWORD is 8 bytes
        fields[base_addr + offset] = 0
    
    # Pattern 4: *((_DWORD *)this + N)
    for m in re.finditer(r'\*\(\((_DWORD)\s*\*\)\s*\(this\s*\+\s*(\d+)\)', pseudocode):
        offset = int(m.group(2)) * 4  # DWORD is 4 bytes
        fields[base_addr + offset] = 0
    
    return fields


def find_external_calls(pseudocode: str) -> list[str]:
    """Find external function calls in pseudocode."""
    externals = []
    
    # Pattern: function_name(args)
    # Skip known C functions and operators
    skip = {'if', 'else', 'for', 'while', 'return', 'sizeof', 'switch', 'case',
            'malloc', 'free', 'memcpy', 'memset', 'strlen', 'strcmp'}
    
    for m in re.finditer(r'\b([a-zA-Z_]\w*)\s*\(', pseudocode):
        name = m.group(1)
        if name not in skip and not name.startswith('_'):
            # Check if it's likely external (not a local variable or type)
            if name[0].isupper() or '::' in name or '.' in name:
                externals.append(name)
    
    return list(set(externals))


def estimate_function_complexity(pseudocode: str) -> str:
    """Estimate function complexity for verification strategy."""
    lines = pseudocode.split('\n')
    line_count = len(lines)
    
    branch_count = pseudocode.count('if') + pseudocode.count('else') + pseudocode.count('switch')
    loop_count = pseudocode.count('for') + pseudocode.count('while')
    call_count = len(re.findall(r'\w+\s*\(', pseudocode))
    
    if line_count <= 5 and branch_count == 0 and loop_count == 0:
        return 'trivial'
    elif line_count <= 15 and branch_count <= 2 and loop_count == 0:
        return 'simple'
    elif line_count <= 30 and branch_count <= 5 and loop_count <= 1:
        return 'moderate'
    elif line_count <= 50 and branch_count <= 10 and loop_count <= 3:
        return 'complex'
    else:
        return 'very_complex'


def build_emulation_context(
    pseudocode: str,
    func_name: str,
    args: list[int] | None = None,
) -> dict:
    """Build a complete emulation context from pseudocode.
    
    Returns setup instructions for the emulator.
    """
    # Parse struct layout
    struct_fields = parse_struct_layout(pseudocode)
    
    # Find external calls
    externals = find_external_calls(pseudocode)
    
    # Estimate complexity
    complexity = estimate_function_complexity(pseudocode)
    
    # Determine what args are pointers
    pointer_args = []
    if args:
        for i, arg in enumerate(args):
            # Heuristic: if arg looks like a pointer (large value), it's probably a struct
            if arg > 0x1000 and arg < 0x7FFFFFFFFFFFFFFF:
                pointer_args.append(i)
    
    return {
        'struct_fields': struct_fields,
        'externals': externals,
        'complexity': complexity,
        'pointer_args': pointer_args,
        'estimated_difficulty': 'easy' if complexity in ('trivial', 'simple') else 'medium' if complexity == 'moderate' else 'hard',
    }
