"""N-hop call-graph context gathering for improved function naming.

Instead of naming functions in isolation, this feeds the model rich
neighborhood context: callers, callees, strings, and constants from the
surrounding code.  The key insight is that a function called by
``Player$$TakeDamage`` is more likely ``ReduceHealth`` than ``sub_140012340``.

Phases covered:
  Phase 1 — N-hop BFS context (callers/callees to depth hops)
  Phase 3 — String literal & magic-constant extraction from pseudocode

Usage from populate.py::

    from spectrida.context import gather_context, format_context_block

    ctx = gather_context(graph, binary, func_addr, pseudocode=code)
    prompt_block = format_context_block(ctx)

No Neo4j imports here — the graph object is passed in so the module stays
testable without a running database.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from spectrida.idb_knowledge import harvest_references, gather_knowledge, format_knowledge_block as _format_idb_block

# ── constants ────────────────────────────────────────────────────────────────

# Skip common / low-signal constants — every function has 0, 1, -1, etc.
_COMMON_CONSTS = frozenset({
    0, 1, -1, 2, 4, 8, 0xFFFF, 0xFF, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
})

# Hard cap on the serialized context block (characters, not tokens —
# tokens ≈ chars / 4 for English-ish text, so 3000 chars ≈ 750 tokens,
# within the 600-800 token budget the plan recommends).
_MAX_CONTEXT_CHARS = 3000


# ── data model ───────────────────────────────────────────────────────────────

@dataclass
class NeighborInfo:
    addr: int
    name: str
    relation: str  # "caller" | "callee"
    hops: int
    is_named: bool  # True if not sub_*


@dataclass
class FunctionContext:
    func_addr: int
    callers: list[NeighborInfo] = field(default_factory=list)
    callees: list[NeighborInfo] = field(default_factory=list)
    strings: list[str] = field(default_factory=list)
    constants: list[int] = field(default_factory=list)
    summary: str = ""
    idb_knowledge: list = field(default_factory=list)


# ── helpers ──────────────────────────────────────────────────────────────────

def _is_named(name: str | None) -> bool:
    if not name:
        return False
    return not name.lower().startswith("sub_")


def _to_int(addr) -> int:
    if isinstance(addr, int):
        return addr
    if isinstance(addr, str):
        return int(addr, 16) if addr.startswith("0x") else int(addr)
    return 0


def _bfs_neighbors(
    graph,
    binary: str,
    start_addr: int,
    direction: str,  # "callers" | "callees"
    depth: int,
    max_neighbors: int,
) -> list[NeighborInfo]:
    """BFS over callers or callees, ranked by (a) named first, (b) closer hops.

    The graph object must expose ``.callers(binary, addr)`` and
    ``.callees(binary, addr)`` (duck-typed — no import needed).
    """
    visited: set[int] = {start_addr}
    queue: list[tuple[int, int]] = [(start_addr, 0)]  # (addr, hop)
    results: list[NeighborInfo] = []
    get_fn = graph.callers if direction == "callers" else graph.callees

    while queue and len(results) < max_neighbors * 3:  # over-fetch, trim later
        current, hop = queue.pop(0)
        if hop >= depth:
            continue

        try:
            neighbors = get_fn(binary, current)
        except Exception:
            continue

        for n in neighbors:
            addr = _to_int(n.get("addr", n.get("address", 0)))
            if addr in visited or addr == start_addr:
                continue
            visited.add(addr)

            name = n.get("name", "") or ""
            info = NeighborInfo(
                addr=addr,
                name=name or f"sub_{addr:x}",
                relation=direction.rstrip("s"),  # "callers" → "caller"
                hops=hop + 1,
                is_named=_is_named(name),
            )
            results.append(info)

            # Continue BFS through named functions (they're signal, not noise)
            if info.is_named:
                queue.append((addr, hop + 1))

    # Sort: named first, then by hop distance (closer = more relevant)
    results.sort(key=lambda x: (not x.is_named, x.hops))
    return results[:max_neighbors]


# ── string extraction (Phase 3) ─────────────────────────────────────────────

def extract_strings(pseudocode: str, max_strings: int = 8, max_len: int = 40) -> list[str]:
    """Pull string literals out of C pseudocode.

    Filters out format-specifier-only strings (``"%s"``, ``"%d"``) since
    they're too generic to help naming.  Deduplicates while preserving order.
    """
    if not pseudocode:
        return []

    found = re.findall(r'"([^"]{1,200})"', pseudocode)
    seen: set[str] = set()
    result: list[str] = []

    for s in found:
        if s in seen:
            continue
        # Skip bare format specifiers — "%s" and friends are everywhere
        if re.fullmatch(r'["%# +\-0-9.*hlLzjt]*[diouxXeEfFgAcspn%]', s):
            continue
        if len(s) < 2:
            continue
        seen.add(s)
        result.append(s[:max_len])
        if len(result) >= max_strings:
            break

    return result


def extract_constants(pseudocode: str, max_constants: int = 6) -> list[int]:
    """Pull distinctive hex / large decimal constants from pseudocode.

    Skips the boring ones (0, 1, -1, powers of two ≤ 8, etc.) that don't
    help the model understand what the function does.
    """
    if not pseudocode:
        return []

    found: list[int] = []

    # Hex constants (0x...), at least 2 hex digits to skip trivial 0x0-0xF
    for m in re.finditer(r'\b(0x[0-9a-fA-F]{2,})\b', pseudocode):
        try:
            val = int(m.group(1), 16)
            if val not in _COMMON_CONSTS:
                found.append(val)
        except ValueError:
            pass

    # Large-ish decimal constants (≥4 digits or negative ≥4 digits)
    for m in re.finditer(r'\b(-?[0-9]{4,})\b', pseudocode):
        try:
            val = int(m.group(1))
            if val not in _COMMON_CONSTS:
                found.append(val)
        except ValueError:
            pass

    # Dedup, preserve order
    seen: set[int] = set()
    result: list[int] = []
    for v in found:
        if v not in seen:
            seen.add(v)
            result.append(v)
        if len(result) >= max_constants:
            break

    return result


# ── main entry point ─────────────────────────────────────────────────────────

async def gather_context(
    graph,
    binary: str,
    func_addr: int,
    *,
    depth: int = 2,
    max_neighbors: int = 10,
    pseudocode: str = "",
    db=None,
) -> FunctionContext:
    """Gather N-hop context for a function.

    Combines:
      • Call-graph BFS over callers AND callees (Phase 1)
      • String literal extraction from pseudocode (Phase 3)
      • Magic-constant extraction from pseudocode (Phase 3)

    Returns a ``FunctionContext`` that ``format_context_block()`` serializes
    into a compact prompt fragment.
    """
    callers = _bfs_neighbors(graph, binary, func_addr, "callers", depth, max_neighbors)
    callees = _bfs_neighbors(graph, binary, func_addr, "callees", depth, max_neighbors)

    strings = extract_strings(pseudocode)
    constants = extract_constants(pseudocode)

    # Build overflow summary for anything we didn't include
    total_named_callers = sum(1 for c in callers if c.is_named)
    total_named_callees = sum(1 for c in callees if c.is_named)
    total_unnamed_callers = len(callers) - total_named_callers
    total_unnamed_callees = len(callees) - total_named_callees

    extras: list[str] = []
    if total_unnamed_callers > 0:
        extras.append(f"+{total_unnamed_callers} more unnamed callers")
    if total_unnamed_callees > 0:
        extras.append(f"+{total_unnamed_callees} more unnamed callees")

    ctx = FunctionContext(
        func_addr=func_addr,
        callers=callers,
        callees=callees,
        strings=strings,
        constants=constants,
        summary="; ".join(extras),
    )

    # Phase 3: IDB-as-RAG — harvest referenced knowledge
    if db is not None:
        try:
            refs = await harvest_references(db, func_addr)
            knowledge = await gather_knowledge(db, refs)
            ctx.idb_knowledge = knowledge
        except Exception:
            ctx.idb_knowledge = []

    return ctx


def format_context_block(ctx: FunctionContext) -> str:
    """Serialize a ``FunctionContext`` into a compact prompt block.

    Designed to stay under ~800 tokens.  Named neighbors first for maximum
    signal; unnamed counts as overflow.  Strings and constants after the
    call graph.
    """
    lines: list[str] = []

    # ── callers ──
    named_callers = [c for c in ctx.callers if c.is_named]
    unnamed_callers = [c for c in ctx.callers if not c.is_named]
    if named_callers:
        lines.append("Called by: " + ", ".join(c.name for c in named_callers[:6]))
    if unnamed_callers:
        lines.append(f"Also called by: {len(unnamed_callers)} unnamed functions")

    # ── callees ──
    named_callees = [c for c in ctx.callees if c.is_named]
    unnamed_callees = [c for c in ctx.callees if not c.is_named]
    if named_callees:
        lines.append("Calls: " + ", ".join(c.name for c in named_callees[:6]))
    if unnamed_callees:
        lines.append(f"Also calls: {len(unnamed_callees)} unnamed functions")

    # ── strings (Phase 3) ──
    if ctx.strings:
        escaped = [f'"{s}"' for s in ctx.strings[:6]]
        lines.append("References strings: " + ", ".join(escaped))

    # ── constants (Phase 3) ──
    if ctx.constants:
        fmt = [f"0x{c:X}" if c > 255 else str(c) for c in ctx.constants[:4]]
        lines.append("Key constants: " + ", ".join(fmt))

    # ── IDB-as-RAG knowledge ──
    if ctx.idb_knowledge:
        from spectrida.idb_knowledge import format_knowledge_block
        # Dedup against names already in context
        already = set()
        for c in ctx.callers:
            if c.is_named:
                already.add(c.name)
        for c in ctx.callees:
            if c.is_named:
                already.add(c.name)
        idb_block = format_knowledge_block(ctx.idb_knowledge, already)
        if idb_block:
            lines.append(idb_block)

    # ── overflow ──
    if ctx.summary:
        lines.append(ctx.summary)

    if not lines:
        return ""

    block = "Context:\n" + "\n".join(lines)

    # Hard truncate if we somehow blew the budget
    if len(block) > _MAX_CONTEXT_CHARS:
        block = block[:_MAX_CONTEXT_CHARS - 20] + "\n…(truncated)"

    return block
