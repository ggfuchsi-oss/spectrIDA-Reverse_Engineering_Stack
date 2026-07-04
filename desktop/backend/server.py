"""
spectrIDA Desktop — local backend.

A thin FastAPI layer the Electron UI fetches from. It reuses spectrIDA's own graph
+ analysis + dynamic (phantomrt) modules — no logic lives here that isn't already
in the library; this is just an HTTP face on it so a browser renderer can drive it.

Endpoints
  GET  /health                        - is the graph up
  GET  /binaries                      - indexed binaries + function counts
  POST /analyze            {path,tag}  - start indexing a binary  -> {job_id}
  GET  /jobs/{id}                      - analysis progress / result
  GET  /functions   ?binary=&q=&limit  - search functions by name/addr
  GET  /function    ?binary=&addr=     - full detail (+ callers/callees/dyn_*)
  POST /dynamic/emulate    {binary,addr}
  POST /dynamic/hunt       {binary,addr,rounds,seeds_dir}
  POST /dynamic/live       {binary,addresses,seconds}
"""
from __future__ import annotations

import asyncio
import logging
import re
import time
import uuid
from pathlib import Path


def estimate_seconds(prologues: int, naming: bool = True, name_limit: int = 2000) -> int:
    """Rough ETA from function/prologue count, calibrated on a measured run
    (main.nso: ~28k funcs -> 83s parallel + 152s merge auto_wait). The merge is
    ~linear in function count and dominates; parallel is partly amortised by
    cores; naming is a per-function model inference (capped). Deliberately a
    rough estimate — labelled as such in the UI."""
    parallel = prologues * 0.0032          # ~3.2 ms/func across 16 workers
    merge    = prologues * 0.0055          # ~5.5 ms/func, single-threaded auto_wait
    name     = (min(prologues, name_limit) * 0.9) if naming else 0   # ~0.9s/func
    return int(parallel + merge + name + 15)   # + fixed startup

logging.getLogger("neo4j").setLevel(logging.ERROR)

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from spectrida import config
from spectrida.core.graph import FunctionGraph

app = FastAPI(title="spectrIDA Desktop backend")
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)

_graph: FunctionGraph | None = None
_jobs: dict[str, dict] = {}
_live: dict[str, object] = {}   # binary tag -> open live IDA handle (cached)


def g() -> FunctionGraph:
    global _graph
    if _graph is None:
        _graph = FunctionGraph(config.graph_uri(), config.graph_user(), config.graph_password())
    return _graph


async def live_db(binary: str):
    """Open (and cache) a live idalib handle for a binary's registered .i64 —
    needed for the AI naming pass. Reopening a big .i64 is slow, so it's cached."""
    if binary in _live:
        return _live[binary]
    from spectrida.api import IDADatabase
    from spectrida.core.backend import RealBackend
    path = g().get_binary_path(binary)
    if not path:
        raise HTTPException(400, f"no .i64 registered for '{binary}'")
    backend = RealBackend(path)
    await backend.ensure_open()
    db = IDADatabase(backend)
    _live[binary] = db
    return db


def _hex(d: dict) -> dict:
    if isinstance(d.get("addr"), int):
        d["address"] = hex(d["addr"])
    return d


# ── read / browse ─────────────────────────────────────────────────────────────
@app.get("/health")
def health():
    try:
        with g().driver.session() as s:
            s.run("RETURN 1").single()
        return {"ok": True}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@app.get("/binaries")
def binaries():
    with g().driver.session() as s:
        rows = s.run(
            "MATCH (b:Binary) OPTIONAL MATCH (f:Function {binary:b.tag}) "
            "WITH b, count(f) AS funcs, "
            "     count(CASE WHEN f.name IS NOT NULL AND NOT f.name STARTS WITH 'sub_' "
            "                THEN 1 END) AS named, "
            "     count(CASE WHEN f.dyn_status IS NOT NULL THEN 1 END) AS analyzed "
            "RETURN b.tag AS tag, b.i64_path AS i64, b.binary_path AS path, "
            "       funcs, named, analyzed ORDER BY funcs DESC"
        )
        return [dict(r) for r in rows]


@app.get("/functions")
def functions(binary: str, q: str = "", limit: int = 100):
    with g().driver.session() as s:
        if q and q.lower().startswith("0x"):        # address search
            try:
                addr = int(q, 16)
            except ValueError:
                addr = -1
            rows = s.run(
                "MATCH (f:Function {binary:$b}) WHERE f.addr = $a "
                "RETURN f.addr AS addr, f.name AS name, f.size AS size, "
                "f.dyn_status AS dyn LIMIT $l", b=binary, a=addr, l=limit)
        else:
            rows = s.run(
                "MATCH (f:Function {binary:$b}) "
                "WHERE ($q = '' OR toLower(f.name) CONTAINS toLower($q)) "
                "RETURN f.addr AS addr, f.name AS name, f.size AS size, "
                "f.dyn_status AS dyn "
                "ORDER BY (f.name STARTS WITH 'sub_'), f.name LIMIT $l",
                b=binary, q=q, l=limit)
        return [_hex(dict(r)) for r in rows]


@app.get("/function")
def function(binary: str, addr: str):
    a = int(addr, 16) if addr.startswith("0x") else int(addr)
    fn = g().get_function(binary, a)
    if not fn:
        raise HTTPException(404, f"no function {addr} in {binary}")
    fn = _hex(fn)
    fn["callers"] = [_hex(dict(c)) for c in g().callers(binary, a)]
    fn["callees"] = [_hex(dict(c)) for c in g().callees(binary, a)]
    fn["dynamic"] = {k: v for k, v in fn.items() if k.startswith("dyn_")}
    return fn


# ── analyze (index a new binary) ───────────────────────────────────────────────
class AnalyzeReq(BaseModel):
    path: str
    tag: str | None = None


@app.get("/estimate")
def estimate(path: str):
    """Quick pre-run estimate from file size (rough — the accurate ETA comes once
    the density scan reports the real function count during the run)."""
    p = Path(path)
    if not p.exists():
        raise HTTPException(400, "file not found")
    mb = p.stat().st_size / 1e6
    # very rough: ~2000 functions per MB of file for a code-dense DLL/IL2CPP,
    # far fewer for a small exe. Clamp to a sane band; it's just a heads-up.
    approx_funcs = int(mb * 1800)
    eta = estimate_seconds(approx_funcs)
    return {"size_mb": round(mb, 1), "approx_functions": approx_funcs,
            "eta_seconds": eta, "large": mb > 100}


@app.post("/analyze")
async def analyze(req: AnalyzeReq):
    if not Path(req.path).exists():
        raise HTTPException(400, f"file not found: {req.path}")
    tag = req.tag or Path(req.path).name
    job_id = uuid.uuid4().hex[:12]
    _jobs[job_id] = {"status": "running", "tag": tag, "progress": "queued",
                     "created": time.time(), "result": None, "error": None,
                     "lines": [], "seen": 0}

    async def _run():
        job = _jobs[job_id]
        try:
            from spectrida.core.pipeline import run_analysis
            from spectrida.core.populate import populate_graph
            # phase 1: parallel analysis. Stream the pipeline's own log lines so the
            # UI shows live shard/merge progress instead of a static "analysing…".
            # on_line MUST be async (run_analysis awaits it) — a sync lambda would
            # cause `await None`.
            job["progress"] = "starting parallel analysis…"
            job["phase"] = "analyze"; job["started"] = time.time()

            def log_line(line: str):
                line = (line or "").rstrip()
                if not line:
                    return
                job["progress"] = line.strip()[:140]
                job["lines"].append(line[:200])
                if len(job["lines"]) > 400:          # keep the tail
                    job["lines"] = job["lines"][-400:]; job["seen"] += 1
                # once the density scan reports the prologue count, compute an ETA
                m = re.search(r"density scan:\s*(\d+)\s*prologues", line)
                if m and not job.get("eta_s"):
                    n = int(m.group(1))
                    job["eta_s"] = estimate_seconds(n)
                    job["lines"].append(f"⏱ ~{job['eta_s']//60}m estimated "
                                        f"({n:,} functions — rough)")

            async def on_line(line: str):
                log_line(line)

            log_line("👻 waking the ghost…")
            result = await run_analysis(req.path, None, on_line=on_line)
            if "error" in result:
                job["status"] = "error"; job["error"] = result["error"]; return
            i64 = result.get("i64")
            if not i64:
                job["status"] = "error"; job["error"] = "no .i64 produced"; return
            g().register_binary(tag, i64, binary_path=req.path)
            # phase 2: AI-name the functions + populate the graph
            log_line(f"⚑ analysis done — {result.get('funcs')} functions. naming…")
            db = await live_db(tag)

            async def prog(done, total):
                job["progress"] = f"naming {done}/{total} functions"
                if done % 50 == 0 or done == total:
                    log_line(f"  named {done}/{total}")

            pop = await populate_graph(db, g(), tag, limit=2000, min_size=20, on_progress=prog)
            log_line("✓ ghosted through it. done.")
            job["result"] = {"tag": tag, "i64": i64, "functions": result.get("funcs"), "named": pop}
            job["status"] = "done"
            job["progress"] = f"done: {result.get('funcs')} functions"
        except Exception as e:
            import traceback
            job["status"] = "error"; job["error"] = f"{type(e).__name__}: {e}"
            job["progress"] = traceback.format_exc()[-300:]

    asyncio.create_task(_run())
    return {"job_id": job_id, "tag": tag}


class NameReq(BaseModel):
    binary: str
    limit: int = 500


@app.post("/name")
async def name_functions(req: NameReq):
    """Run the AI naming pass on the still-unnamed (sub_*) functions of an
    already-indexed binary. Long-running → returns a job_id; poll /jobs."""
    job_id = uuid.uuid4().hex[:12]
    _jobs[job_id] = {"status": "running", "tag": req.binary, "progress": "opening .i64…",
                     "created": time.time(), "result": None, "error": None}

    async def _run():
        job = _jobs[job_id]
        try:
            from spectrida.core.populate import populate_graph
            db = await live_db(req.binary)

            async def prog(done, total):
                job["progress"] = f"naming {done}/{total}"

            pop = await populate_graph(db, g(), req.binary, limit=req.limit,
                                       min_size=20, on_progress=prog)
            job["result"] = {"named": pop}
            job["status"] = "done"; job["progress"] = "done"
        except Exception as e:
            import traceback
            job["status"] = "error"; job["error"] = f"{type(e).__name__}: {e}"
            job["progress"] = traceback.format_exc()[-300:]

    asyncio.create_task(_run())
    return {"job_id": job_id, "tag": req.binary}


@app.get("/jobs/{job_id}")
def job(job_id: str):
    j = _jobs.get(job_id)
    if not j:
        raise HTTPException(404, "no such job")
    out = {"job_id": job_id, **{k: j[k] for k in ("status", "tag", "progress", "result", "error")}}
    out["elapsed"] = round(time.time() - j.get("created", time.time()))
    out["lines"] = j.get("lines", [])
    out["eta_s"] = j.get("eta_s")
    return out


# ── dynamic (phantomrt) ─────────────────────────────────────────────────────────
class EmuReq(BaseModel):
    binary: str
    addr: str
    binary_path: str | None = None


def _addr(a: str) -> int:
    return int(a, 16) if a.startswith("0x") else int(a)


@app.post("/dynamic/emulate")
async def dyn_emulate(req: EmuReq):
    try:
        from spectrida import dynamic
        dynamic.require()
        from spectrida.dynamic.emulate import emulate_one
        from spectrida.dynamic.annotate import annotator
    except Exception as e:
        raise HTTPException(400, str(e))
    a = _addr(req.addr)
    try:
        res = await asyncio.to_thread(emulate_one, g(), req.binary, a, req.binary_path)
    except FileNotFoundError as e:
        raise HTTPException(400, str(e).split(".")[0])   # clean, not a stack trace
    except Exception as e:
        raise HTTPException(400, f"{type(e).__name__}: {e}")
    facts = {"status": res["verdict"], "note": res["note"], "reachable": res["reachable"],
             "blocks": res["blocks"], "tool": "atlas-emulate"}
    if res.get("crash_input"):
        facts["crash_input"] = res["crash_input"]
    try:
        annotator(g()).annotate(req.binary, facts, addr=a)
    except Exception:
        pass
    return res


class HuntReq(BaseModel):
    binary: str
    addr: str
    rounds: int = 300
    seeds_dir: str | None = None
    binary_path: str | None = None


@app.post("/dynamic/hunt")
async def dyn_hunt(req: HuntReq):
    try:
        from spectrida import dynamic
        dynamic.require()
        from spectrida.dynamic.fuzz import hunt
        from spectrida.dynamic.annotate import annotator
    except Exception as e:
        raise HTTPException(400, str(e))
    a = _addr(req.addr)
    try:
        res = await asyncio.to_thread(hunt, g(), req.binary, a, req.binary_path,
                                      req.seeds_dir, req.rounds)
    except FileNotFoundError as e:
        raise HTTPException(400, str(e).split(".")[0])
    except Exception as e:
        raise HTTPException(400, f"{type(e).__name__}: {e}")
    facts = {"status": res["verdict"], "reachable": res["reachable"],
             "crashes": res["unique_crashes"], "tool": "atlas-hunt"}
    ci = list(res["crash_inputs"].values())
    if ci:
        facts["crash_input"] = ci[0]
    try:
        annotator(g()).annotate(req.binary, facts, addr=a)
    except Exception:
        pass
    return res


class LiveReq(BaseModel):
    binary: str
    addresses: list[str]
    seconds: int = 3
    binary_path: str | None = None


@app.post("/dynamic/live")
async def dyn_live(req: LiveReq):
    try:
        from spectrida import dynamic
        dynamic.require()
        from spectrida.dynamic.live import live_trace
    except Exception as e:
        raise HTTPException(400, str(e))
    addrs = [_addr(a) for a in req.addresses]
    try:
        res = await asyncio.to_thread(live_trace, g(), req.binary, addrs,
                                      req.binary_path, float(req.seconds))
    except FileNotFoundError as e:
        raise HTTPException(400, str(e).split(".")[0])
    except Exception as e:
        msg = str(e).lower()
        if "spawn" in msg or "unsupported" in msg or "executable" in msg:
            raise HTTPException(400, "live trace needs a binary that RUNS on this "
                "machine — Frida can't launch it (Switch NSO / other-arch binaries "
                "can't run here). Use Emulate instead.")
        raise HTTPException(400, f"{type(e).__name__}: {e}")
    return res


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8737, log_level="warning")
