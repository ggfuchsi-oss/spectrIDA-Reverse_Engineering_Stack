"""Symbol database for compilation.

Extract all known symbols from a binary's IDA database and generate
stub declarations for compilation. This resolves the "undefined symbol"
problem without whack-a-mole stubbing.
"""
from __future__ import annotations

import re


def extract_symbols_from_pseudocode(pseudocode: str) -> set[str]:
    """Extract all external function calls from pseudocode."""
    externals = set()
    
    # Find function calls: name(args)
    for m in re.finditer(r'\b([a-zA-Z_]\w*(?:::[a-zA-Z_]\w*)*)\s*\(', pseudocode):
        name = m.group(1)
        # Skip C keywords and common operators
        if name in ('if', 'else', 'for', 'while', 'return', 'sizeof', 'typeof',
                     'switch', 'case', 'break', 'continue', 'goto', 'do'):
            continue
        # Skip if it looks like a variable (starts with lowercase, no ::)
        if '::' not in name and name[0].islower() and '_' not in name:
            continue
        externals.add(name)
    
    # Find type references: (Type *) or Type *
    for m in re.finditer(r'(?:\(|\s)([A-Z]\w*(?:::[A-Z]\w*)*)\s*\*', pseudocode):
        externals.add(m.group(1))
    
    return externals


def generate_stubs(symbols: set[str], known_types: set[str] | None = None) -> str:
    """Generate stub declarations for undefined symbols."""
    if known_types is None:
        known_types = set()
    
    stubs = []
    
    for sym in sorted(symbols):
        # Clean up namespace
        clean_name = sym.replace('::', '_')
        
        # Skip if already a known type
        if sym in known_types:
            continue
        
        # Generate stub based on naming patterns
        if '::' in sym:
            # Class method or namespaced function
            stubs.append(f'// Stub for {sym}')
            stubs.append(f'long long {clean_name}(long long* args) {{ return 0; }}')
        elif sym[0].isupper():
            # Likely a class constructor or type
            stubs.append(f'// Stub for {sym}')
            stubs.append(f'long long {clean_name}(long long* args) {{ return 0; }}')
        else:
            # Regular function
            stubs.append(f'// Stub for {sym}')
            stubs.append(f'long long {clean_name}(long long* args) {{ return 0; }}')
    
    return '\n'.join(stubs)


def generate_symbol_stubs_from_pseudocode(
    pseudocode: str,
    existing_stubs: str = "",
) -> str:
    """Generate all stubs needed for a pseudocode snippet."""
    # Extract external symbols
    symbols = extract_symbols_from_pseudocode(pseudocode)
    
    # Extract existing type definitions from pseudocode
    known_types = set()
    for m in re.finditer(r'typedef\s+\w+\s+(\w+)', pseudocode):
        known_types.add(m.group(1))
    for m in re.finditer(r'struct\s+(\w+)', pseudocode):
        known_types.add(m.group(1))
    for m in re.finditer(r'class\s+(\w+)', pseudocode):
        known_types.add(m.group(1))
    
    # Generate stubs
    stubs = generate_stubs(symbols, known_types)
    
    # Combine with existing stubs
    if existing_stubs:
        return existing_stubs + '\n' + stubs
    return stubs
