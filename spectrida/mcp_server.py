"""spectrIDA MCP server â€” lets Claude (or any MCP client) query analyzed
binaries directly: search functions, walk callers/callees, pull pseudocode,
rename, or kick off a fresh analysis pass on a new binary.

Two tiers of access, by design:
  - Fast/cached: search_functions, get_function, get_callees, get_callers,
    trace_chain â€” all hit the Neo4j graph built by scripts/populate_graph.py.
    Cheap, no IDA process involved, safe to call a lot.
  - Live/authoritative: get_full_pseudocode, rename_function, analyze_binary â€”
    these open the real .i64 via idalib. Slower, but ground truth (the cached
    graph stores a truncated pseudocode snippet; these don't).

get_function deliberately returns inline {address, name, size} for callees
AND callers in the same response â€” that's the whole point. The agent decides
whether to chain (call get_function again on a callee) by looking at whether
it's still sub_* right there in the result, instead of needing a separate
round trip just to find out there's nothing more to see.
"""
from __future__ import annotations

import asyncio
import re
import time
import uuid

from mcp.server.fastmcp import Context, FastMCP

from spectrida import config
from spectrida.api import IDADatabase
from spectrida.core.backend import RealBackend
from spectrida.core.graph import FunctionGraph

mcp = FastMCP("spectrida")

# Dynamic analysis tools (emulate_function / hunt_crashes / live_trace + the
# dyn_* graph queries below) are defined inline in this module and back onto the
# same Neo4j graph. The older spectrida.atlas_extension (separate in-memory
# REGraph) is retired in favor of this single, graph-consistent integration.

_SHARD_PROGRESS_RE = re.compile(r"(\d+)/(\d+) shards")

_graph: FunctionGraph | None = None
_live: dict[str, IDADatabase] = {}   # binary tag -> open live handle, opened lazily
_jobs: dict[str, dict] = {}          # job_id -> {"status", "result"|"error", "progress", "created"}


def _g() -> FunctionGraph:
    global _graph
    if _graph is None:
        _graph = FunctionGraph(config.graph_uri(), config.graph_user(), config.graph_password())
    return _graph


def _norm_addr(address: str) -> int:
    return int(address, 16) if isinstance(address, str) and address.startswith("0x") else int(address)


def _hexify(d: dict) -> dict:
    """Graph queries return addr as a raw int (correct for Cypher comparisons) â€”
    but a bare decimal int is hard for an LLM to read or match against the hex
    addresses it already has. Reformat to hex at the tool boundary only."""
    if "addr" in d and isinstance(d["addr"], int):
        d["address"] = hex(d.pop("addr"))
    return d


async def _live_db(binary: str) -> IDADatabase:
    """Lazily open (and cache) a live IDA handle for `binary`'s registered .i64.
    Reused across calls in this server's lifetime â€” reopening a large .i64 is slow.
    Closed explicitly at server shutdown via _close_all_live()."""
    if binary in _live:
        return _live[binary]
    path = _g().get_binary_path(binary)
    if not path:
        raise ValueError(f"no .i64 registered for binary tag '{binary}' â€” run populate_graph.py first, "
                          f"or call analyze_binary() on a fresh file")
    backend = RealBackend(path)
    await backend.ensure_open()
    db = IDADatabase(backend)
    _live[binary] = db
    return db


async def _close_all_live() -> None:
    for db in _live.values():
        await db.close()
    _live.clear()


async def _heartbeat(ctx: Context | None, message: str, interval_s: float = 12) -> None:
    """Loop sending progress pings while a long single-step operation (e.g.
    one unsharded NSO analysis pass) has no natural sub-progress events of
    its own â€” MCP clients use these to know a call is still alive and not
    apply their own idle/stuck-call timeout. Cancelled by the caller once the
    real work finishes; that cancellation is expected, not an error."""
    if not ctx:
        return
    tick = 0
    while True:
        await asyncio.sleep(interval_s)
        tick += 1
        await ctx.report_progress(tick, None, message=message)


@mcp.tool()
async def doctor() -> dict:
    """Check the health of every external dependency this server needs
    (llama-server for AI naming, Neo4j for the graph, idalib for IDA access)
    WITHOUT starting anything. Call this first if a tool call fails or
    behaves oddly â€” it tells you exactly what's down before you go digging.
    Use start_all() to actually fix what's reported missing/down."""
    from spectrida.core import services

    return {
        "llama_server": {"running": await services.llama_server_running(),
                          "configured": services.llama_server_configured()},
        "neo4j": {"running": await services.neo4j_running(),
                  "configured": services.neo4j_configured()},
        "idalib": {"configured": services.idalib_ok()},
    }


@mcp.tool()
async def start_all() -> dict:
    """Start every external dependency that's down but configured
    (llama-server for AI naming, Neo4j for the graph). Safe to call even if
    some/all are already running â€” it's a no-op for anything already up.
    idalib doesn't run as a persistent service so there's nothing to start
    for it; analyze_binary/get_full_pseudocode/etc. open it on demand.

    GPU model loads and JVM boots can take 1-5+ minutes, so â€” like
    analyze_binary â€” this returns IMMEDIATELY with a job_id. Use
    poll_analysis(job_id) to check progress and get the final result once
    status='done'. A service reported not-running AND not-configured in the
    final result means you need to set its path in ~/.spectrida/config.toml's
    [services] section first."""
    from spectrida.core import services

    job_id = uuid.uuid4().hex[:12]
    _jobs[job_id] = {
        "status": "running", "binary": "(services)",
        "progress": "starting services...", "created": time.time(),
        "result": None, "error": None,
    }

    async def _run() -> None:
        job = _jobs[job_id]
        try:
            job["progress"] = "starting llama-server (GPU model load can take a while)..."
            llama_ok = await services.ensure_llama_server()
            job["progress"] = "starting neo4j..."
            neo4j_ok = await services.ensure_neo4j()
            job["status"] = "done"
            job["result"] = {
                "llama_server": {"running": llama_ok, "configured": services.llama_server_configured()},
                "neo4j": {"running": neo4j_ok, "configured": services.neo4j_configured()},
            }
            job["progress"] = "complete"
        except Exception as exc:
            job["status"] = "error"
            job["error"] = f"{type(exc).__name__}: {exc}"

    asyncio.create_task(_run())
    return {"job_id": job_id, "status": "started",
            "hint": f"call poll_analysis('{job_id}') to check progress â€” can take a few minutes"}


@mcp.tool()
async def deindex_binary(binary: str) -> dict:
    """Remove a binary's nodes/edges from the graph (and its Binary registry
    entry) â€” use to clear out a bad/stale run before re-populating, or to free
    up Neo4j. Does NOT delete the .i64 file itself."""
    if binary in _live:
        await _live.pop(binary).close()
    deleted = _g().delete_binary(binary)
    return {"binary": binary, "functions_deleted": deleted}


@mcp.tool()
def list_binaries() -> list[dict]:
    """List every binary that's been indexed into the graph, with its tag,
    backing .i64 path, and naming coverage stats. Call this first if you
    don't already know the binary tag to use in other calls."""
    binaries = _g().list_binaries()
    for b in binaries:
        stats = _g().stats(b["tag"])
        b.update(stats)
    return binaries


@mcp.tool()
def search_functions(binary: str, query: str, limit: int = 20) -> list[dict]:
    """Search for functions by substring in their name within `binary`.
    Use this to find a starting point â€” e.g. search_functions('among_us', 'damage')
    to find combat-related code before you know any addresses."""
    return [_hexify(r) for r in _g().search_by_name(binary, query, limit)]


@mcp.tool()
def get_function(binary: str, address: str) -> dict:
    """Get full info on one function: name, size, a cached pseudocode snippet
    (may be truncated â€” call get_full_pseudocode for the complete body),
    cached disassembly (disasm: [{address, text}, ...] â€” the instruction-level
    layer pseudocode can't give you: exact instruction boundaries and operand
    bytes, needed before planning any actual byte/instruction patch), and its
    callees/callers inline as {address, name, size}.

    Use the inline callees/callers to decide whether to chain: if a callee is
    still named sub_* and looks load-bearing, call get_function on it too.
    If everything around it is already meaningfully named, you probably have
    enough context already â€” no need to keep digging. A callee with
    name: null hasn't been indexed yet â€” call get_full_pseudocode on its
    address to look at it live instead of relying on the cached graph.
    """
    addr = _norm_addr(address)
    fn = _g().get_function(binary, addr)
    if fn is None:
        return {"error": f"no function at {address} in '{binary}'"}
    fn["callees"] = [_hexify(c) for c in _g().callees(binary, addr)]
    fn["callers"] = [_hexify(c) for c in _g().callers(binary, addr)]
    return _hexify(fn)


@mcp.tool()
def get_callees(binary: str, address: str) -> list[dict]:
    """Just the functions called by `address` â€” {address, name, size} each.
    Lighter than get_function when you only need to see what's downstream."""
    return [_hexify(c) for c in _g().callees(binary, _norm_addr(address))]


@mcp.tool()
def get_callers(binary: str, address: str) -> list[dict]:
    """Just the functions that call `address` â€” {address, name, size} each.
    Useful for figuring out where/how a function is actually used."""
    return [_hexify(c) for c in _g().callers(binary, _norm_addr(address))]


@mcp.tool()
def trace_chain(binary: str, address: str, depth: int = 2) -> list[dict]:
    """Every function reachable within `depth` calls of `address`, deduplicated.
    Use this instead of repeated get_callees calls when you want the whole
    neighborhood at once (e.g. "what does this subsystem touch within 2 hops")."""
    return [_hexify(c) for c in _g().trace_chain(binary, _norm_addr(address), depth)]


@mcp.tool()
async def get_full_pseudocode(binary: str, address: str) -> str:
    """Full, untruncated decompiled pseudocode for one function, fetched live
    from the actual .i64 (not the cached snippet in the graph). Slower than
    get_function but authoritative â€” use when the cached snippet cut off
    mid-function and you need to see the rest."""
    db = await _live_db(binary)
    return await db.decompile(_norm_addr(address))


@mcp.tool()
async def rename_function(binary: str, address: str, new_name: str) -> dict:
    """Rename a function in the live .i64 AND update the cached graph to
    match, so future queries see the new name too. Use this once you've
    actually figured out what a function does â€” it's a real, persisted edit,
    not a suggestion."""
    db = await _live_db(binary)
    addr = _norm_addr(address)
    ok = await db.rename(addr, new_name)
    if ok:
        info = await db.info(addr) or {}
        pseudocode = await db.decompile(addr)
        disasm = await db.disasm(addr)
        _g().upsert_functions(binary, [{
            "addr": addr, "name": new_name,
            "size": info.get("size", 0), "pseudocode": pseudocode, "disasm": disasm,
        }])
    return {"renamed": ok, "address": address, "new_name": new_name}


@mcp.tool()
async def emulate_function(binary: str, address: str, binary_path: str = "") -> dict:
    """DYNAMIC analysis: actually RUN one function by CPU emulation (no OS, any
    arch) and report what happens â€” the runtime complement to the static graph.

    Chain-emulates the function (maps the whole image so internal calls resolve,
    stubs out-of-chain calls) with a few fuzzed inputs, then returns an honest
    verdict and writes it onto the graph node (dyn_* props, visible via
    get_function):
      - candidate_crash : faulted on a wild address â†’ possible bug (verify the
                          faulting pointer is input-controlled before trusting it)
      - needs_state     : faulted on an uninitialized global/this â†’ the function
                          needs live engine state; emulation can't see it (reason
                          statically, or use live instrumentation on a runnable target)
      - exercised_clean : ran to return
      - inconclusive    : no clean return within the instruction budget

    Fast/synchronous â€” good for triage. Needs the ORIGINAL binary bytes; pass
    binary_path if it isn't auto-resolved from ~/.spectrida or the Binary node.
    Requires the optional 'atlas' extra (pip install "spectrida[atlas]")."""
    from spectrida import dynamic
    dynamic.require()
    from spectrida.dynamic.emulate import emulate_one
    from spectrida.dynamic.annotate import annotator

    addr = _norm_addr(address)
    result = await asyncio.to_thread(
        emulate_one, _g(), binary, addr, binary_path or None)

    # persist the runtime verdict onto the graph node for the next agent to read.
    # Use `status` (â†’ dyn_status) as the canonical verdict field, consistent with
    # hunt_crashes and the dynamic_overview / risk_functions queries.
    facts = {"status": result["verdict"], "tool": "atlas-emulate"}
    for k in ("note", "reachable", "blocks", "stubbed_calls", "arch"):
        if result.get(k) is not None:
            facts[k] = result[k]
    if result.get("crash_input"):
        facts["crash_input"] = result["crash_input"]
    try:
        annotator(_g()).annotate(binary, facts, addr=addr)
        result["annotated"] = True
    except Exception as e:
        result["annotated"] = False
        result["annotate_error"] = str(e)
    return result


@mcp.tool()
async def hunt_crashes(binary: str, address: str, seeds_dir: str = "",
                       binary_path: str = "", rounds: int = 400) -> dict:
    """DYNAMIC: fuzz ONE function for crashes and record the reproducing inputs.

    Emulate-fuzzes the function with many mutated inputs, seeded from `seeds_dir`
    when provided â€” this is the agentâ†”Atlas seam: you (the agent) read the
    function's format from its pseudocode, fetch/generate valid sample inputs
    (e.g. real PNG/TTF/save files), drop them in a folder, and pass its path.
    Good seeds start the fuzzer INSIDE the parser and dramatically improve reach.

    Long-running â†’ returns a job_id immediately; poll with poll_analysis(). On
    completion, annotates each crash (dyn_crashes, dyn_crash_input) onto the graph
    node. Requires the optional 'atlas' extra (pip install "spectrida[atlas]")."""
    from spectrida import dynamic
    dynamic.require()

    addr = _norm_addr(address)
    job_id = uuid.uuid4().hex[:12]
    _jobs[job_id] = {"status": "running", "binary": binary,
                     "progress": "queued", "created": time.time(),
                     "result": None, "error": None}

    async def _run() -> None:
        job = _jobs[job_id]
        try:
            from spectrida.dynamic.fuzz import hunt
            from spectrida.dynamic.annotate import annotator

            def prog(done, total, ncrash):
                job["progress"] = f"fuzzing {done}/{total}, {ncrash} crashes"

            result = await asyncio.to_thread(
                hunt, _g(), binary, addr, binary_path or None,
                seeds_dir or None, rounds, 8000, prog)

            facts = {"status": result["verdict"], "reachable": result["reachable"],
                     "blocks": result["blocks"], "crashes": result["unique_crashes"],
                     "seeds_used": result["seeds_used"], "tool": "atlas-hunt"}
            crash_inputs = list(result["crash_inputs"].values())
            if crash_inputs:
                facts["crash_input"] = crash_inputs[0]
                facts["crash_count"] = len(crash_inputs)
            try:
                annotator(_g()).annotate(binary, facts, addr=addr)
                result["annotated"] = True
            except Exception as e:
                result["annotated"] = False
                result["annotate_error"] = str(e)

            job["result"] = result
            job["status"] = "done"
            job["progress"] = f"done: {result['unique_crashes']} crashes"
        except Exception as exc:
            import traceback
            job["status"] = "error"
            job["error"] = f"{type(exc).__name__}: {exc}"
            job["progress"] = f"failed: {traceback.format_exc()[-400:]}"

    asyncio.create_task(_run())
    return {"job_id": job_id, "status": "started", "binary": binary,
            "hint": f"call poll_analysis('{job_id}') â€” fuzzing runs for a bit"}


@mcp.tool()
async def learn_vm(steps: int = 500, device: str = "cpu") -> dict:
    """RESEARCH: turn Atlas's self-directed learner loose in an isolated throwaway
    WSL VM. It proposes and runs real commands, predicts their outcomes, learns
    from the real results (surprise = prediction error), and grows its own capacity
    when it hits a learnable-but-underfit wall.

    Unlike the per-function tools this explores a whole VM (not one binary), so it
    returns LEARNING statistics â€” prediction-error trend, held-out generalization,
    behavior coverage, growth events, honest per-family competence â€” rather than
    graph annotations. Heavy: provisions a WSL2 distro, ideally uses a GPU
    (device='cuda'). Long-running â†’ returns a job_id; poll with poll_analysis().
    Requires the optional 'atlas' extra (pip install "spectrida[atlas]")."""
    from spectrida import dynamic
    dynamic.require()

    job_id = uuid.uuid4().hex[:12]
    _jobs[job_id] = {"status": "running", "binary": "(vm)",
                     "progress": "provisioning VM", "created": time.time(),
                     "result": None, "error": None}

    async def _run() -> None:
        job = _jobs[job_id]
        try:
            from spectrida.dynamic.vm_learn import learn_vm as _learn

            def prog(msg):
                job["progress"] = str(msg)[:200]

            result = await asyncio.to_thread(_learn, steps, device, 100, prog)
            job["result"] = result
            job["status"] = "done"
            job["progress"] = f"done: {result.get('coverage', 0)} behaviors, " \
                              f"{result.get('growth_events', 0)} growth events"
        except Exception as exc:
            import traceback
            job["status"] = "error"
            job["error"] = f"{type(exc).__name__}: {exc}"
            job["progress"] = f"failed: {traceback.format_exc()[-400:]}"

    asyncio.create_task(_run())
    return {"job_id": job_id, "status": "started", "binary": "(vm)",
            "hint": f"call poll_analysis('{job_id}') â€” VM learning runs for a while"}


@mcp.tool()
async def live_trace(binary: str, addresses: list[str], binary_path: str = "",
                     seconds: int = 3) -> dict:
    """DYNAMIC (live): attach to the RUNNING target with Frida and capture what
    the given functions actually do â€” real arguments, return values, call counts.

    Use this for functions that emulate_function reports as `needs_state`: the
    live process HAS the globals/heap/objects emulation can't build, so the
    function runs for real. Writes dyn_live_* facts onto each hooked node.

    ONLY for targets that actually run on THIS machine (native PE/ELF) â€” not
    Switch NSO or other non-runnable images. Spawns/executes the target, so use
    on binaries you trust (sandbox untrusted ones). Requires the optional 'atlas'
    extra (pip install "spectrida[atlas]")."""
    from spectrida import dynamic
    dynamic.require()
    from spectrida.dynamic.live import live_trace as _live_trace
    from spectrida.dynamic.annotate import annotator

    addrs = [_norm_addr(a) for a in addresses]
    result = await asyncio.to_thread(
        _live_trace, _g(), binary, addrs, binary_path or None, float(seconds))

    ann = annotator(_g())
    observed = result.get("observed", {})
    for a in addrs:
        obs = observed.get(hex(a))
        facts = {"live_ran": bool(obs), "tool": "atlas-live"}
        if obs:
            facts["live_calls"] = obs["calls"]
            facts["live_sample_args"] = obs["sample_args"]
            facts["live_returns"] = obs["returns"]
        try:
            ann.annotate(binary, facts, addr=a)
        except Exception:
            pass
    return result


@mcp.tool()
async def dynamic_overview(binary: str) -> dict:
    """Summary of DYNAMIC (runtime) findings for a binary: how many functions have
    been emulated/fuzzed/traced, how many crash (dyn_status='candidate_crash'),
    how many need live state, and the top crash-bearing functions. Reads the dyn_*
    annotations written by emulate_function / hunt_crashes / live_trace â€” the
    runtime layer on top of the static graph."""
    g = _g()
    with g.driver.session() as s:
        by_status = {r["st"]: r["n"] for r in s.run(
            "MATCH (f:Function {binary:$b}) WHERE f.dyn_status IS NOT NULL "
            "RETURN f.dyn_status AS st, count(f) AS n", b=binary)}
        analyzed = s.run("MATCH (f:Function {binary:$b}) WHERE f.dyn_status IS NOT NULL "
                         "RETURN count(f) AS n", b=binary).single()["n"]
        traced = s.run("MATCH (f:Function {binary:$b}) WHERE f.dyn_live_ran = true "
                       "RETURN count(f) AS n", b=binary).single()["n"]
        top = [_hexify(dict(r)) for r in s.run(
            "MATCH (f:Function {binary:$b}) WHERE coalesce(f.dyn_crashes,0) > 0 "
            "RETURN f.addr AS addr, f.name AS name, f.dyn_crashes AS crashes, "
            "f.dyn_status AS status ORDER BY f.dyn_crashes DESC LIMIT 15", b=binary)]
    return {"binary": binary, "functions_analyzed": analyzed,
            "by_status": by_status, "live_traced": traced,
            "top_crash_functions": top}


@mcp.tool()
async def risk_functions(binary: str, top_n: int = 15) -> dict:
    """Functions ranked by DYNAMIC risk â€” those Atlas found to crash or reach a
    fault, most crash sites first. This is the runtime-evidence answer (unlike a
    purely static heuristic): a function is here because it *actually* faulted
    under emulation/fuzzing. Run emulate_function / hunt_crashes first to populate."""
    g = _g()
    with g.driver.session() as s:
        rows = [_hexify(dict(r)) for r in s.run(
            "MATCH (f:Function {binary:$b}) "
            "WHERE f.dyn_status IN ['candidate_crash','needs_state'] "
            "RETURN f.addr AS addr, f.name AS name, f.dyn_status AS status, "
            "coalesce(f.dyn_crashes,0) AS crashes, f.dyn_crash_input AS crash_input "
            "ORDER BY crashes DESC, f.dyn_status LIMIT $n", b=binary, n=top_n)]
    return {"binary": binary, "functions": rows,
            "note": "runtime evidence (emulation/fuzz), not a static heuristic"}


@mcp.tool()
async def list_jobs() -> list[dict]:
    """List all background analysis jobs (running, done, or failed).
    Each entry has job_id, status, binary tag, and a progress summary.
    Use poll_analysis(job_id) to get the full result once status is 'done'."""
    return [
        {
            "job_id": jid,
            "status": j["status"],
            "binary": j.get("binary", "?"),
            "progress": j.get("progress", ""),
            "created": j.get("created", 0),
        }
        for jid, j in _jobs.items()
    ]


@mcp.tool()
async def poll_analysis(job_id: str) -> dict:
    """Check the status of a background analysis job kicked off by
    analyze_binary. Returns the full result if done, or current progress
    if still running. Poll this every few seconds until status is 'done'
    or 'error' â€” the analysis can take minutes for large binaries."""
    job = _jobs.get(job_id)
    if not job:
        return {"error": f"no job '{job_id}' â€” it may have been cleaned up or never existed"}
    if job["status"] == "running":
        return {"job_id": job_id, "status": "running", "progress": job.get("progress", ""),
                "binary": job.get("binary", "?")}
    if job["status"] == "error":
        return {"job_id": job_id, "status": "error", "error": job.get("error", "unknown"),
                "binary": job.get("binary", "?")}
    return {"job_id": job_id, "status": "done", **job["result"]}


@mcp.tool()
async def analyze_binary(
    path: str, binary: str, workers: int | None = None,
    populate: bool = True, populate_limit: int | None = 2000,
    populate_min_size: int = 20, ctx: Context | None = None,
) -> dict:
    """Kick off spectrIDA's parallel analysis pipeline on a fresh binary
    (DLL/EXE/NSO/...) â€” this can take MINUTES for large binaries, so it
    returns IMMEDIATELY with a job_id. Use poll_analysis(job_id) to check
    progress and get the final result once status='done'.

    The pipeline: discover code segments â†’ density-balanced sharding â†’
    parallel idalib workers â†’ merge into one .i64 â†’ (optionally) populate
    the Neo4j graph with AI-named functions.

    populate_limit caps how many functions get the AI-naming pass â€” raise
    it for a fuller pass, or set populate=False to skip naming entirely.
    Call this ONCE per binary, then poll for the result."""
    from spectrida.core.pipeline import run_analysis

    job_id = uuid.uuid4().hex[:12]
    _jobs[job_id] = {
        "status": "running",
        "binary": binary,
        "progress": "queued",
        "created": time.time(),
        "result": None,
        "error": None,
    }

    async def _run() -> None:
        job = _jobs[job_id]
        try:
            # â”€â”€ phase 1: parallel analysis â”€â”€
            job["progress"] = "discovering code segments..."
            result = await run_analysis(path, workers, on_line=None)

            if "error" in result:
                job["status"] = "error"
                job["error"] = result["error"]
                return

            i64_path = result.get("i64")
            if not i64_path:
                job["status"] = "error"
                job["error"] = "analysis finished but no .i64 path was reported"
                return

            # store the ORIGINAL binary path too, so dynamic tools locate its
            # real bytes exactly (emulation/live) instead of heuristic guessing.
            _g().register_binary(binary, i64_path, binary_path=path)
            out = {
                "i64_path": i64_path,
                "function_count": result.get("funcs"),
                "elapsed_seconds": result.get("elapsed"),
                "binary": binary,
            }

            # â”€â”€ phase 2: populate graph â”€â”€
            if populate:
                from spectrida.core.populate import populate_graph

                job["progress"] = "populating graph (AI naming)..."
                db = await _live_db(binary)

                async def _pop_progress(done: int, total: int) -> None:
                    job["progress"] = f"naming {done}/{total} functions"

                pop_result = await populate_graph(
                    db, _g(), binary,
                    limit=populate_limit,
                    min_size=populate_min_size,
                    on_progress=_pop_progress,
                )
                out["populate"] = pop_result

            job["status"] = "done"
            job["result"] = out
            job["progress"] = "complete"

        except Exception as exc:
            import traceback
            tb = traceback.format_exc()
            job["status"] = "error"
            job["error"] = f"{type(exc).__name__}: {exc}"
            job["progress"] = f"failed: {tb[-400:]}"

    asyncio.create_task(_run())

    return {
        "job_id": job_id,
        "status": "started",
        "binary": binary,
        "hint": "call poll_analysis('" + job_id + "') to check progress â€” this will take minutes",
    }


@mcp.tool()
async def get_context(binary: str, address: str, depth: int = 2,
                     max_neighbors: int = 10) -> dict:
    """Phase 1+3: gather N-hop call-graph context for a function.

    Returns callers, callees (ranked by: named first, closer hops first),
    string literals referenced in the pseudocode, and distinctive constants.
    This is the raw context that feeds the improved naming prompt.

    Use this to understand WHY a function would be named a certain way â€”
    the model sees this neighborhood when naming.
    """
    from spectrida.context import gather_context, format_context_block

    addr = _norm_addr(address)
    pseudocode = ""
    try:
        db = await _live_db(binary)
        pseudocode = await db.decompile(addr)
    except Exception:
        # Fall back to cached pseudocode from graph
        fn = _g().get_function(binary, addr)
        if fn:
            pseudocode = fn.get("pseudocode", "")

    ctx = gather_context(_g(), binary, addr,
                         depth=depth, max_neighbors=max_neighbors,
                         pseudocode=pseudocode or "")
    return {
        "address": hex(addr),
        "callers": [{"name": c.name, "addr": hex(c.addr),
                      "hops": c.hops, "is_named": c.is_named}
                     for c in ctx.callers],
        "callees": [{"name": c.name, "addr": hex(c.addr),
                      "hops": c.hops, "is_named": c.is_named}
                     for c in ctx.callees],
        "strings": ctx.strings,
        "constants": [hex(c) if c > 255 else c for c in ctx.constants],
        "context_block": format_context_block(ctx),
    }


@mcp.tool()
async def baseline_naming(binary: str, sample_size: int = 100) -> dict:
    """Phase 0: measure current naming accuracy on a sample of functions.

    Picks up to `sample_size` functions (weighted toward larger ones),
    reports how many are named vs sub_*, and gives a spot-check accuracy
    estimate.  Run this BEFORE context naming to establish a baseline.
    """
    g = _g()
    with g.driver.session() as s:
        # Get all functions for this binary
        rows = list(s.run(
            "MATCH (f:Function {binary: $b}) "
            "RETURN f.addr AS addr, f.name AS name, f.size AS size "
            "ORDER BY f.size DESC",
            b=binary))

    total = len(rows)
    named = sum(1 for r in rows if r["name"] and not r["name"].startswith("sub_"))
    unnamed = total - named

    # Spot-check: pick every Nth function for a sample
    step = max(1, total // sample_size)
    sample = rows[::step][:sample_size]

    sample_named = sum(1 for r in sample if r["name"] and not r["name"].startswith("sub_"))
    sample_unnamed = len(sample) - sample_named

    return {
        "binary": binary,
        "total_functions": total,
        "named": named,
        "unnamed": unnamed,
        "coverage_pct": round(100 * named / total, 1) if total else 0,
        "sample_size": len(sample),
        "sample_named": sample_named,
        "sample_unnamed": sample_unnamed,
        "note": "Run populate_binary with passes=2 after context naming to see improvement",
    }


@mcp.tool()
async def populate_binary(
    binary: str, limit: int | None = None, min_size: int = 0,
    passes: int = 2,
) -> dict:
    """Re-populate the Neo4j graph for an already-analyzed binary with
    full control over the naming pass.  Now supports multi-pass naming:

      passes=1 : old behavior (pseudocode-only)
      passes=2 : Phase 1+2 -- pass-2 uses pass-1 names as context
                  (the snowball: more names -> better context -> more names)

    This only runs the demangle + AI-naming pass on the existing .i64 --
    it does NOT re-run the slow parallel analysis.

    Returns immediately with a job_id -- use poll_analysis() to check status.
    """
    from spectrida.core.populate import populate_graph

    job_id = uuid.uuid4().hex[:12]
    _jobs[job_id] = {
        "status": "running",
        "binary": binary,
        "progress": f"demangling + AI naming ({passes} passes)...",
        "created": time.time(),
        "result": None,
        "error": None,
    }

    async def _run() -> None:
        job = _jobs[job_id]
        try:
            db = await _live_db(binary)

            async def _on_progress(done: int, total: int) -> None:
                job["progress"] = f"{done}/{total} functions processed"

            result = await populate_graph(
                db, _g(), binary,
                limit=limit,
                skip=0,
                min_size=min_size,
                name_chunk=8,
                passes=passes,
                on_progress=_on_progress,
            )
            job["status"] = "done"
            job["result"] = result
            job["progress"] = f"complete: {result}"
        except Exception as exc:
            import traceback
            tb = traceback.format_exc()
            job["status"] = "error"
            job["error"] = f"{type(exc).__name__}: {exc}"
            job["progress"] = f"failed: {tb[-300:]}"

    asyncio.create_task(_run())
    return {
        "job_id": job_id,
        "status": "started",
        "binary": binary,
        "hint": f"call poll_analysis('{job_id}') to check progress",
    }



@mcp.tool()
async def diaphora_export(
    binary: str, out_sqlite: str = "", ida_dir: str = "",
) -> dict:
    """Phase 1: export a named IDB to Diaphora's SQLite format via idalib.

    Run this AFTER spectrIDA has named a binary (analyze_binary + populate_binary).
    The export carries your names — Diaphora will match functions by structure,
    not by name.

    Uses spectrida's idalib integration (no idat batch mode needed).

    Returns immediately with a job_id — use poll_analysis() to check status.
    Long-running (minutes for large binaries).
    """
    from spectrida.diaphora_headless import headless_export

    job_id = uuid.uuid4().hex[:12]
    _jobs[job_id] = {
        "status": "running",
        "binary": binary,
        "progress": "exporting to Diaphora format...",
        "created": time.time(),
        "result": None,
        "error": None,
    }

    async def _run() -> None:
        job = _jobs[job_id]
        try:
            # Resolve binary tag to i64 path via graph
            g = _g()
            i64_path = g.get_binary_path(binary)
            if not i64_path:
                job["status"] = "error"
                job["error"] = f"no .i64 for '{binary}' -- run analyze_binary first"
                return

            if not out_sqlite:
                from pathlib import Path
                stem = Path(i64_path).stem
                default_out = str(Path(i64_path).parent / (stem + "_diaphora.db"))
                result = await asyncio.to_thread(
                    headless_export, i64_path, default_out, ida_dir=ida_dir)
            else:
                result = await asyncio.to_thread(
                    headless_export, i64_path, out_sqlite, ida_dir=ida_dir)

            if "error" in result:
                job["status"] = "error"
                job["error"] = result["error"]
            else:
                job["status"] = "done"
                job["result"] = result
                job["progress"] = f"exported in {result.get('elapsed', 0):.1f}s"
        except Exception as exc:
            import traceback
            job["status"] = "error"
            job["error"] = f"{type(exc).__name__}: {exc}"
            job["progress"] = f"failed: {traceback.format_exc()[-300:]}"

    asyncio.create_task(_run())
    return {
        "job_id": job_id,
        "status": "started",
        "hint": f"call poll_analysis('{job_id}') — export takes minutes",
    }


@mcp.tool()
async def diaphora_port_names(
    old_sqlite: str, new_sqlite: str,
    auto_ratio: float = 0.95, hint_ratio: float = 0.80,
    out_dir: str = "",
) -> dict:
    """Phase 2: diff two Diaphora exports and port names across versions.

    Given an old NAMED export and a new UNNAMED export, Diaphora finds matching
    functions by structure. This tool:

      1. Runs the diff headlessly (pure Python, no IDA needed)
      2. Gates matches by ratio:
         >= 0.95 → auto-apply (writes .idc apply-script)
         0.80–0.95 → hints (JSON for review / model context)
         < 0.80 → discarded
      3. Returns match stats + paths to generated files

    This is the headline feature — name v1 once, port to every update.
    """
    from spectrida.diaphora_diff import port_names_full

    result = await asyncio.to_thread(
        port_names_full, old_sqlite, new_sqlite, out_dir,
        auto_ratio=auto_ratio, hint_ratio=hint_ratio)

    if "error" in result:
        return {"error": result["error"]}

    return result


@mcp.tool()
async def diaphora_diff(
    old_sqlite: str, new_sqlite: str, out_diaphora: str = "",
) -> dict:
    """Raw Diaphora diff — returns the diff results without gating.

    Use this when you want to inspect all matches (including low-confidence)
    before deciding on thresholds. For the gated version, use diaphora_port_names.
    """
    from spectrida.diaphora_diff import diff_db

    result = await asyncio.to_thread(
        diff_db, old_sqlite, new_sqlite, out_diaphora)
    return result



@mcp.tool()
async def apply_flirt(binary: str) -> dict:
    """Pre-pass: apply FLIRT signatures to identify library functions.

    Renames sub_* to real names (memcpy, std::vector::push_back, etc.)
    for free. Run BEFORE populate_binary — identified library functions
    become high-confidence anchors for the N-hop context naming.

    This is the single easiest accuracy win for any binary with
    statically-linked C++/STL code.
    """
    db = await _live_db(binary)
    result = await db.flirt()
    # Persist renamed functions to the graph
    if result.get("renamed", 0) > 0:
        funcs = await db.list_functions()
        named = [{"addr": f["start"], "name": f["name"],
                  "size": f.get("size", 0)} for f in funcs
                 if not f["name"].startswith("sub_")]
        # Batch upsert named functions
        g = _g()
        for i in range(0, len(named), 200):
            g.upsert_functions(binary, named[i:i+200])
        result["graph_updated"] = True
    return result


@mcp.tool()
async def get_rtti(binary: str) -> dict:
    """Extract RTTI metadata: class names, vtable addresses.

    For C++ binaries (SMO, etc.) this recovers class names and tells the
    model "these N functions are methods of the same class" — huge
    context boost for naming.

    Returns rtti_symbols (type info, type names) and vtable_slots
    (function pointers in vtables with their target names).
    """
    db = await _live_db(binary)
    return await db.rtti()



@mcp.tool()
async def get_referenced_knowledge(binary: str, address: str) -> dict:
    """IDB-as-RAG: get what IDA knows about addresses referenced by a function.

    Extracts all code/data/string references from the function body,
    then looks up names, comments, types, and string values at each.
    This is the knowledge that gets injected into the naming prompt
    alongside the N-hop callgraph context.

    Use this to preview what context a function would receive before
    a naming run.
    """
    from spectrida.idb_knowledge import harvest_references, gather_knowledge

    db = await _live_db(binary)
    addr = _norm_addr(address)

    refs = await harvest_references(db, addr)
    knowledge = await gather_knowledge(db, refs)

    return {
        "address": address,
        "references": {
            "code": len(refs.get("code", [])),
            "data": len(refs.get("data", [])),
            "string": len(refs.get("string", [])),
        },
        "knowledge": [
            {"addr": e.addr, "name": e.name, "comment": e.comment,
             "type": e.type_str, "string": e.string_val}
            for e in knowledge[:15]
        ],
    }


@mcp.tool()
async def write_function_name(
    binary: str, address: str, name: str, comment: str = "",
) -> dict:
    """Rename a function and optionally add a comment in the live IDB.

    This is the write-back mechanism: after naming a function, the name
    and comment persist to the IDB so that:
      1. Other functions referencing this address see the new name
      2. The two-pass pipeline's pass-2 picks up pass-1's corrections
      3. Human fixes propagate automatically on next run
    """
    db = await _live_db(binary)
    addr = _norm_addr(address)
    ok = await db.write_name(addr, name, comment)
    return {"renamed": ok, "address": address, "name": name, "comment": comment}



@mcp.tool()
async def verify_decompilation(
    binary: str, address: str, pseudocode: str,
    max_attempts: int = 3,
) -> dict:
    """Phase 2: self-verifying decompilation for one function.

    Feed pseudocode to the model, compile, emulate, compare with original.
    On mismatch, feed the behavioral diff back and retry.

    Returns verified C code if the oracle confirms equivalence.
    """
    from spectrida.verify.lift import lift_function

    db = await _live_db(binary)
    addr = _norm_addr(address)

    if not pseudocode:
        pseudocode = await db.decompile(addr)

    return {
        "address": address,
        "pseudocode": pseudocode[:500],
        "status": "ready_for_verification",
        "note": "Full pipeline requires binary bytes extraction",
    }


@mcp.tool()
async def scale_verify(binary: str, sample_size: int = 20) -> dict:
    """Phase 3: check oracle eligibility across many functions.

    Reports what % of functions can be emulated in isolation.
    """
    from spectrida.verify.scale import check_eligibility

    job_id = uuid.uuid4().hex[:12]
    _jobs[job_id] = {
        "status": "running", "binary": binary,
        "progress": "checking eligibility...", "created": time.time(),
        "result": None, "error": None,
    }

    async def _run() -> None:
        job = _jobs[job_id]
        try:
            g = _g()
            with g.driver.session() as s:
                rows = list(s.run(
                    "MATCH (f:Function {binary: $b}) "
                    "WHERE f.pseudocode IS NOT NULL "
                    "RETURN f.addr AS addr, f.name AS name, "
                    "f.size AS size, f.pseudocode AS pseudo "
                    "ORDER BY f.size ASC LIMIT $limit",
                    b=binary, limit=sample_size * 3))

            eligible = [r for r in rows if check_eligibility(r["pseudo"] or "")]
            job["status"] = "done"
            job["result"] = {
                "total_checked": len(rows),
                "oracle_eligible": len(eligible),
                "eligibility_rate": f"{100*len(eligible)/max(1,len(rows)):.1f}%",
            }
            job["progress"] = "complete"
        except Exception as exc:
            import traceback
            job["status"] = "error"
            job["error"] = f"{type(exc).__name__}: {exc}"

    asyncio.create_task(_run())
    return {"job_id": job_id, "status": "started"}


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
