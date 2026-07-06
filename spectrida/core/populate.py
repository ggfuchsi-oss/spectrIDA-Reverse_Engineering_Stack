"""Walk an open .i64 and push functions + call edges into Neo4j, with
N-hop context (Phase 1+3), two-pass iterative naming (Phase 2), and
Ollama/llama-server dual-backend support.

Used by both scripts/populate_graph.py (standalone CLI) and the MCP server
analyze_binary tool (chained right after a fresh analysis pass).
"""
from __future__ import annotations

import asyncio
import re
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING

import httpx

from spectrida.config import naming_llama_url, ollama_model as _ollama_model
from spectrida.context import format_context_block, gather_context

if TYPE_CHECKING:
    from spectrida.api import IDADatabase
    from spectrida.core.graph import FunctionGraph

BATCH_SIZE = 200
PSEUDOCODE_CHARS = 3000

NAMING_SYSTEM = (
    "You are an expert reverse engineer analyzing a stripped game binary. "
    "The Context section shows what calls this function and what it calls -- "
    "use this to INFER what the function does, do NOT copy function names from it. "
    "Respond with ONLY a descriptive snake_case name for THIS function."
)

_THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL)


def _strip_think(text: str) -> str:
    """Remove Qwen3 think blocks from model output."""
    return _THINK_RE.sub("", text).strip()


def _chat(system: str, user_msg: str) -> str:
    """Build a ChatML prompt."""
    return (
        "<im>system</im>\n" + system + "</im>\n"
        "<im>user</im>\n" + user_msg + "</im>\n"
        "<im>assistant</im>\n"
    )


async def name_from_pseudocode(
    pseudocode: str,
    http: httpx.AsyncClient,
    llama_url: str,
    *,
    context_block: str = "",
    ollama_model: str = "",
) -> str:
    """Name a function using pseudocode + optional N-hop context.

    Supports Ollama (/api/generate) and llama-server (/completion).
    If ollama_model is provided, uses Ollama; otherwise llama-server.
    """
    if not pseudocode.strip():
        return ""

    parts: list[str] = []
    if context_block:
        parts.append(context_block)
    code_block = "Pseudocode:\n```c\n" + pseudocode[:2000] + "\n```"
    parts.append(code_block)
    user_msg = "\n\n".join(parts) + "\n\nProposed function name:"

    prompt = _chat(NAMING_SYSTEM, user_msg)

    # Retry with backoff — Ollama can hiccup under rapid-fire requests
    last_err = None
    for attempt in range(4):
        try:
            if ollama_model:
                url = llama_url.rstrip("/") + "/api/generate"
                payload = {
                    "model": ollama_model, "prompt": prompt,
                    "stream": False, "think": False,
                    "options": {"temperature": 0.3, "num_predict": 40},
                }
                resp = await http.post(url, json=payload)
                resp.raise_for_status()
                text = _strip_think(resp.json().get("response", ""))
            else:
                payload = {"prompt": prompt, "temperature": 0.3, "n_predict": 40}
                resp = await http.post(llama_url, json=payload)
                resp.raise_for_status()
                text = _strip_think(resp.json().get("content", ""))
            break
        except Exception as e:
            last_err = e
            if attempt < 3:
                await asyncio.sleep(1.0 * (attempt + 1))
            else:
                text = ""

    first_line = text.splitlines()[0].strip() if text else ""
    return first_line[:80]


async def _const(value):
    return value


async def populate_graph(
    db: IDADatabase,
    graph: FunctionGraph,
    binary: str,
    *,
    limit: int | None = None,
    skip: int = 0,
    min_size: int = 0,
    name_chunk: int = 8,
    sample: str = "sequential",
    seed: int = 42,
    passes: int = 2,
    on_progress: Callable[[int, int], Awaitable[None]] | None = None,
) -> dict:
    """Populate the Neo4j graph with functions, edges, and AI-generated names.

    Args:
        passes: number of naming passes (1 = pseudocode-only,
                2 = context-enriched two-pass).

    Returns dict with total, named, demangled, attempted, renamed_pass2.
    """
    funcs = await db.list_functions()

    if sample == "random":
        import random
        random.seed(seed)
        funcs = list(funcs)
        random.shuffle(funcs)

    targets = funcs[skip:]
    if limit:
        targets = targets[:limit]

    llama_url = naming_llama_url()
    model = _ollama_model()

    # -- Pass 1: collect data, name with context, write to graph ----------
    func_batch: list[dict] = []
    edge_batch: list[tuple[int, int]] = []
    named_count = 0
    demangled_count = 0
    attempted_count = 0
    done = 0
    func_data: dict[int, dict] = {}

    async with httpx.AsyncClient(timeout=120) as http:
        for chunk_start in range(0, len(targets), name_chunk):
            chunk = targets[chunk_start: chunk_start + name_chunk]

            mangled = [f["name"] for f in chunk if f["name"].startswith(("_Z", "?"))]
            demangled = await db.demangle(mangled) if mangled else {}
            demangled_count += len(demangled)

            pending: list[dict] = []
            for f in chunk:
                addr = f["start"]
                name = demangled.get(f["name"], f["name"])

                pseudocode = ""
                try:
                    code = await db.decompile(addr)
                    pseudocode = (code or "")[:PSEUDOCODE_CHARS]
                except Exception:
                    pass

                edges = []
                try:
                    callees = await db.xrefs_from(addr)
                    for c in callees:
                        ca = c["address"] if isinstance(c["address"], int) else int(c["address"], 16)
                        edges.append((addr, ca))
                except Exception:
                    pass

                disasm = []
                try:
                    disasm = await db.disasm(addr)
                except Exception:
                    pass

                needs = name.lower().startswith("sub_") and f.get("size", 0) >= min_size
                func_data[addr] = {"pseudocode": pseudocode, "disasm": disasm,
                                   "edges": edges, "name": name, "needs_naming": needs}
                pending.append({"addr": addr, "name": name, "size": f.get("size", 0),
                                "pseudocode": pseudocode, "disasm": disasm,
                                "edges": edges, "needs_naming": needs})

            attempted_count += sum(1 for p in pending if p["needs_naming"])
            results = await asyncio.gather(
                *[_name_with_ctx(p, graph, binary, http, llama_url, model) if p["needs_naming"]
                  else _const("") for p in pending],
                return_exceptions=True,
            )

            for p, new_name in zip(pending, results, strict=True):
                if not isinstance(new_name, Exception) and new_name:
                    p["name"] = new_name
                    func_data[p["addr"]]["name"] = new_name
                    named_count += 1
                func_batch.append({"addr": p["addr"], "name": p["name"],
                                   "size": p["size"], "pseudocode": p["pseudocode"],
                                   "disasm": p["disasm"]})
                edge_batch.extend(p["edges"])

            done += len(chunk)
            if len(func_batch) >= BATCH_SIZE:
                graph.upsert_functions(binary, func_batch)
                graph.upsert_calls(binary, edge_batch)
                func_batch, edge_batch = [], []

            if on_progress:
                await on_progress(done, len(targets))

    if func_batch or edge_batch:
        graph.upsert_functions(binary, func_batch)
        graph.upsert_calls(binary, edge_batch)

    # -- Pass 2: re-name with enriched context ----------------------------
    renamed_pass2 = 0
    if passes >= 2:
        func_batch_2: list[dict] = []

        async with httpx.AsyncClient(timeout=120) as http2:
            for addr, data in func_data.items():
                if not data["needs_naming"] or not data["pseudocode"]:
                    continue

                old_name = data["name"]
                ctx_block = ""
                try:
                    ctx = gather_context(graph, binary, addr, depth=2,
                                         max_neighbors=10, pseudocode=data["pseudocode"])
                    ctx_block = format_context_block(ctx)
                except Exception:
                    pass

                new_name = await name_from_pseudocode(
                    data["pseudocode"], http2, llama_url,
                    context_block=ctx_block, ollama_model=model,
                )

                if new_name and new_name != old_name:
                    data["name"] = new_name
                    renamed_pass2 += 1

                func_batch_2.append({
                    "addr": addr, "name": data["name"],
                    "size": data.get("size", 0),
                    "pseudocode": data["pseudocode"],
                    "disasm": data["disasm"],
                })

                if len(func_batch_2) >= BATCH_SIZE:
                    graph.upsert_functions(binary, func_batch_2)
                    func_batch_2 = []

        if func_batch_2:
            graph.upsert_functions(binary, func_batch_2)

    return {
        "total": len(targets), "named": named_count,
        "demangled": demangled_count, "attempted": attempted_count,
        "renamed_pass2": renamed_pass2,
    }


async def _name_with_ctx(
    p: dict,
    graph: FunctionGraph,
    binary: str,
    http: httpx.AsyncClient,
    llama_url: str,
    ollama_model: str = "",
) -> str:
    """Name a single function with N-hop context from the graph."""
    ctx_block = ""
    try:
        ctx = gather_context(graph, binary, p["addr"], depth=2,
                             max_neighbors=10, pseudocode=p["pseudocode"])
        ctx_block = format_context_block(ctx)
    except Exception:
        pass
    return await name_from_pseudocode(
        p["pseudocode"], http, llama_url,
        context_block=ctx_block, ollama_model=ollama_model,
    )
