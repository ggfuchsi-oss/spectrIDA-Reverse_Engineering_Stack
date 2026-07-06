"""spectrIDA programmatic API — use spectrIDA from scripts, notebooks, or Claude Code
without launching the TUI.

    import asyncio
    from spectrida.api import open_i64

    async def main():
        async with open_i64("path/to/file.i64") as db:
            funcs = await db.list_functions()
            name  = await db.name_function(funcs[0]["start"])
            print(name)

    asyncio.run(main())
"""
from __future__ import annotations

import asyncio
import json
import random
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import TypedDict

from spectrida.core.backend import DemoBackend, RealBackend
from spectrida.core.ollama import extract_name, name_function, stream_name


# ── public types ────────────────────────────────────────────────────────────

class FunctionInfo(TypedDict):
    name:  str
    start: int
    end:   int
    size:  int


class NameResult(TypedDict):
    address:    int
    old_name:   str
    new_name:   str
    reasoning:  str
    confidence: str   # "high" | "medium" | "low"


class OverviewResult(TypedDict):
    summary:    str
    subsystems: list[str]
    notes:      str


# ── funny loading lines (opt-in) ─────────────────────────────────────────────

_LOADING = [
    "bribing idalib with coffee…",
    "deciphering ancient x86 scrolls…",
    "asking the ghost nicely…",
    "warming up the neurons (literally, the GPU is hot)…",
    "counting push/pop pairs for fun…",
    "pretending to understand the calling convention…",
    "loading 150k functions. send help.",
    "this is fine. everything is fine.",
    "reverse engineering the reverse engineering tool…",
    "the compiler threw away all the names. rude.",
    "idalib is doing its thing. probably.",
    "sub_XXXXXX → something meaningful, maybe…",
]

def loading_line() -> str:
    return random.choice(_LOADING)


# ── DB handle ────────────────────────────────────────────────────────────────

class IDADatabase:
    """Open .i64 database handle. Use via `open_i64()` context manager."""

    def __init__(self, backend: RealBackend | DemoBackend) -> None:
        self._b = backend
        self._funcs: list[FunctionInfo] | None = None

    # ── core queries ────────────────────────────────────────────────────────

    async def list_functions(self) -> list[FunctionInfo]:
        """Return all functions. Cached after first call."""
        if self._funcs is None:
            self._funcs = await self._b.list_functions()
        return self._funcs

    async def disasm(self, address: int | str) -> list[dict]:
        """Disassemble a function at *address*. Returns list of {address, text}."""
        return await self._b.disasm(address)

    async def decompile(self, address: int | str) -> str:
        """Return pseudocode for the function at *address* (requires Hex-Rays)."""
        return await self._b.decompile(address)

    async def xrefs_to(self, address: int | str) -> list[dict]:
        """Functions that call the function at *address*."""
        return await self._b.xrefs_to(address)

    async def xrefs_from(self, address: int | str) -> list[dict]:
        """Functions called by the function at *address*."""
        return await self._b.xrefs_from(address)

    async def demangle(self, names: list[str]) -> dict[str, str]:
        """Demangle a batch of mangled C++ names (Itanium or MSVC, whichever
        this binary actually uses — IDA auto-detects). Free, deterministic,
        no AI involved. Returns {original: demangled}; non-mangled or
        unresolvable names are simply omitted from the result."""
        return await self._b.demangle(names)

    async def info(self, address: int | str) -> dict | None:
        """Live {name, start, end, size} for the function at *address* —
        ground truth, not a cached graph snippet. None if no function there."""
        return await self._b.info(address)

    async def rename(self, address: int | str, new_name: str) -> bool:
        """Rename the function at *address* and persist to the .i64."""
        ok = await self._b.rename(address, new_name)
        if ok and self._funcs:
            a = address if isinstance(address, int) else int(address, 16)
            for f in self._funcs:
                if f["start"] == a:
                    f["name"] = new_name
        return ok

    # ── AI naming ───────────────────────────────────────────────────────────

    async def name_function(
        self,
        address: int | str,
        *,
        rename: bool = False,
    ) -> NameResult:
        """Ask the model to name one function.

        Args:
            address: function start address
            rename:  if True, also persist the AI name to the .i64

        Returns a NameResult dict with old_name, new_name, reasoning, confidence.
        """
        funcs = await self.list_functions()
        a = address if isinstance(address, int) else int(address, 16)
        func = next((f for f in funcs if f["start"] == a), None)
        old_name = func["name"] if func else hex(a)

        insns   = await self.disasm(a)
        callees = [x.get("name") or x["address"] for x in await self.xrefs_from(a)]
        callers = [x.get("name") or x["address"] for x in await self.xrefs_to(a)]

        full = ""
        async for tok in self._b.stream_name(a, insns, callees, callers):
            full += tok

        new_name  = extract_name(full) or ""
        reasoning = ""
        if "REASON:" in full:
            reasoning = full.partition("REASON:")[2].strip()

        confidence = "high" if new_name and not old_name.startswith("sub_") else (
                     "medium" if new_name else "low")

        if rename and new_name:
            await self.rename(a, new_name)

        return NameResult(
            address=a, old_name=old_name, new_name=new_name,
            reasoning=reasoning, confidence=confidence,
        )

    def stream_name_tokens(
        self,
        address: int | str,
        insns: list[dict],
        callees: list[str],
        callers: list[str],
    ) -> AsyncIterator[str]:
        """Raw token stream for custom UIs."""
        return self._b.stream_name(address, insns, callees, callers)

    async def batch_name(
        self,
        *,
        limit: int = 50,
        unnamed_only: bool = True,
        rename: bool = True,
        progress_cb=None,
    ) -> list[NameResult]:
        """Name multiple functions.

        Args:
            limit:       max functions to name
            unnamed_only: only process sub_* functions
            rename:      persist names to the .i64
            progress_cb: optional async callable(done, total, result) for progress

        Returns list of NameResult, one per function processed.
        """
        funcs = await self.list_functions()
        targets = [f for f in funcs
                   if not unnamed_only or f["name"].lower().startswith("sub_")]
        targets = targets[:limit]
        results: list[NameResult] = []
        for i, f in enumerate(targets):
            r = await self.name_function(f["start"], rename=rename)
            results.append(r)
            if progress_cb:
                await progress_cb(i + 1, len(targets), r)
        return results

    # ── binary overview ──────────────────────────────────────────────────────

    async def overview(
        self,
        *,
        sample_size: int = 120,
        extra_addresses: list[int] | None = None,
        stream: bool = False,
    ) -> str | AsyncIterator[str]:
        """Ask the model to describe what this binary does.

        Samples functions weighted by size (larger = more important), plus any
        addresses you explicitly pass in *extra_addresses*.

        Args:
            sample_size:      how many functions to include as context
            extra_addresses:  specific functions you want the model to consider
            stream:           if True, return an async token iterator instead of
                              waiting for the full response

        Returns the full overview string, or an async iterator if stream=True.
        """
        from spectrida.config import ollama_model, ollama_url

        funcs = await self.list_functions()

        # weighted sample: bigger functions are more likely to be interesting
        named = [f for f in funcs if not f["name"].lower().startswith("sub_")]
        unnamed = [f for f in funcs if f["name"].lower().startswith("sub_")]

        # always include explicitly requested addresses
        pinned: list[FunctionInfo] = []
        if extra_addresses:
            addr_set = set(extra_addresses)
            pinned = [f for f in funcs if f["start"] in addr_set]

        # fill remainder with weighted sample (named first, then by size)
        pool = named + sorted(unnamed, key=lambda f: f["size"], reverse=True)
        pool = [f for f in pool if f not in pinned]
        sample = pinned + pool[:max(0, sample_size - len(pinned))]

        # build context block
        lines = []
        for f in sample[:sample_size]:
            lines.append(f"  {f['name']}  ({f['size']} bytes)")
        context = "\n".join(lines)

        prompt = (
            f"Here are up to {len(sample)} functions from a binary "
            f"({len(funcs):,} total functions):\n\n"
            f"{context}\n\n"
            "Based on these function names and sizes:\n"
            "1. What does this binary likely do? (2-3 sentences)\n"
            "2. What are its major subsystems or components?\n"
            "3. Anything security-relevant, unusual, or interesting?\n\n"
            "Be concise and specific. If function names are mostly sub_*, "
            "say so and give your best guess from patterns you can see."
        )

        import httpx
        payload = {
            "model": ollama_model(),
            "prompt": prompt,
            "stream": True,
            "options": {"temperature": 0.3, "num_predict": 512},
        }

        async def _token_stream() -> AsyncIterator[str]:
            async with httpx.AsyncClient(timeout=120) as client:
                async with client.stream(
                    "POST", f"{ollama_url()}/api/generate", json=payload
                ) as resp:
                    async for line in resp.aiter_lines():
                        if not line:
                            continue
                        try:
                            chunk = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        if chunk.get("error"):
                            raise RuntimeError(chunk["error"])
                        if chunk.get("response"):
                            yield chunk["response"]
                        if chunk.get("done"):
                            break

        if stream:
            return _token_stream()

        full = "".join([tok async for tok in _token_stream()])
        return full

    # ── export ───────────────────────────────────────────────────────────────

    async def export(
        self,
        path: str | Path,
        *,
        fmt: str = "json",
        named_only: bool = False,
    ) -> Path:
        """Export function list to *path*.

        Args:
            path:       output file path
            fmt:        "json" | "csv" | "idc" | "symbols"
            named_only: skip sub_* functions

        Returns the resolved output path.
        """
        funcs = await self.list_functions()
        if named_only:
            funcs = [f for f in funcs if not f["name"].lower().startswith("sub_")]

        out = Path(path).expanduser().resolve()
        out.parent.mkdir(parents=True, exist_ok=True)

        if fmt == "json":
            out.write_text(json.dumps(funcs, indent=2), encoding="utf-8")

        elif fmt == "csv":
            rows = ["address,name,size"]
            for f in funcs:
                rows.append(f'{f["start"]:#x},{f["name"]},{f["size"]}')
            out.write_text("\n".join(rows), encoding="utf-8")

        elif fmt == "idc":
            lines = [
                '// spectrIDA export — apply with IDA File > Script file',
                '#include <idc.idc>',
                'static main() {',
            ]
            for f in funcs:
                safe = f["name"].replace('"', '\\"')
                lines.append(f'  set_name({f["start"]:#x}, "{safe}", SN_NOWARN);')
            lines.append("}")
            out.write_text("\n".join(lines), encoding="utf-8")

        elif fmt == "symbols":
            lines = [f'{f["start"]:#018x} {f["name"]}' for f in funcs]
            out.write_text("\n".join(lines), encoding="utf-8")

        else:
            raise ValueError(f"unknown format {fmt!r} — use json, csv, idc, or symbols")

        return out

        # ── FLIRT + RTTI ─────────────────────────────────────────────────────

    async def flirt(self) -> dict:
        """Apply FLIRT signatures to identify library functions.

        Renames sub_* functions to their real library names (memcpy,
        std:: stuff, etc.) for free. Run BEFORE AI naming.
        """
        return await self._b.flirt()

    async def rtti(self) -> dict:
        """Extract RTTI metadata: class names, vtable addresses.

        Huge context for C++ binaries — tells the model which functions
        belong to the same class.
        """
        return await self._b.rtti()

    async def refs(self, address):
        """Get all referenced addresses from a function body."""
        return await self._b.refs(address)

    async def knowledge(self, addresses):
        """Look up what IDA knows at a set of addresses."""
        return await self._b.knowledge(addresses)

    async def write_name(self, address, name, comment=""):
        """Rename a function and optionally add a comment."""
        return await self._b.write_name(address, name, comment)

    async def close(self) -> None:
        await self._b.close()


# ── context manager ──────────────────────────────────────────────────────────

@asynccontextmanager
async def open_i64(path: str | Path, *, verbose: bool = False):
    """Async context manager that opens a .i64 and yields an IDADatabase.

        async with open_i64("file.i64") as db:
            funcs = await db.list_functions()

    Args:
        path:    path to an IDA .i64 database
        verbose: print a funny loading line while opening
    """
    if verbose:
        print(loading_line())
    b = RealBackend(str(Path(path).expanduser().resolve()))
    await b.ensure_open()
    db = IDADatabase(b)
    try:
        yield db
    finally:
        await db.close()


@asynccontextmanager
async def open_demo(*, verbose: bool = False):
    """Open the built-in demo database (no IDA required). Good for testing."""
    if verbose:
        print("loading demo — no IDA needed.")
    b = DemoBackend()
    db = IDADatabase(b)
    try:
        yield db
    finally:
        await db.close()
