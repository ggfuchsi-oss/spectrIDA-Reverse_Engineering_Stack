"""Service checks for Ollama, llama-server, Neo4j + idalib — used by the CLI,
the onboarding wizard, and the MCP server's doctor()/start_all() tools."""
from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
import sys
from pathlib import Path

import httpx


def _spawn_service(cmd, *, cwd=None, env=None, log_name="service"):
    """Spawn a long-lived background service that OUTLIVES this launcher.

    CREATE_NEW_PROCESS_GROUP alone is not enough on Windows: when the launcher
    runs inside a Job Object (the MCP host / start_all worker), the child is
    killed the moment that job closes — which is why llama-server/Neo4j would
    'start then vanish'. DETACHED_PROCESS + CREATE_BREAKAWAY_FROM_JOB frees the
    child from the job so it survives; we fall back if the job forbids breakaway.
    Output goes to a logfile (not DEVNULL) so a failed launch is diagnosable
    instead of silent.
    """
    logdir = Path.home() / ".spectrida" / "logs"
    logdir.mkdir(parents=True, exist_ok=True)
    logf = open(logdir / f"{log_name}.log", "ab")
    kw = dict(cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=logf, stderr=logf)
    if sys.platform == "win32":
        base = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS
        try:
            return subprocess.Popen(
                cmd, creationflags=base | subprocess.CREATE_BREAKAWAY_FROM_JOB, **kw)
        except OSError:
            return subprocess.Popen(cmd, creationflags=base, **kw)
    return subprocess.Popen(cmd, start_new_session=True, **kw)


from spectrida.config import (
    graph_password,
    graph_uri,
    graph_user,
    idalib_dir,
    java_home,
    llama_exe,
    llama_extra_args,
    llama_model_path,
    naming_health_url,
    neo4j_dir,
    ollama_model,
    ollama_url,
)

# ── Ollama ──────────────────────────────────────────────────────────────────

def ollama_installed() -> bool:
    return shutil.which("ollama") is not None


def ollama_install_hint() -> str:
    if sys.platform == "win32":
        return "winget install Ollama.Ollama   (or download from https://ollama.com/download)"
    if sys.platform == "darwin":
        return "brew install ollama   (or download from https://ollama.com/download)"
    return "curl -fsSL https://ollama.com/install.sh | sh"


async def ollama_running() -> bool:
    try:
        async with httpx.AsyncClient(timeout=2) as c:
            return (await c.get(f"{ollama_url()}/api/tags")).status_code == 200
    except Exception:
        return False


async def ensure_ollama() -> bool:
    """True if Ollama is reachable; tries to start `ollama serve` if not."""
    if await ollama_running():
        return True
    if not ollama_installed():
        return False
    try:
        subprocess.Popen(["ollama", "serve"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        return False
    for _ in range(20):
        await asyncio.sleep(0.5)
        if await ollama_running():
            return True
    return False


async def installed_models() -> list[str]:
    try:
        async with httpx.AsyncClient(timeout=3) as c:
            tags = (await c.get(f"{ollama_url()}/api/tags")).json()
        return [m.get("name", "") for m in tags.get("models", [])]
    except Exception:
        return []


async def model_present(model: str | None = None) -> bool:
    model = model or ollama_model()
    # Exact match (optionally tagged). A substring check falsely passes when only
    # `hf.co/.../spectrida-re-gguf` is installed but inference/`ollama show` need
    # the exact `spectrida-re` — which is the name the runtime actually calls.
    return any(n == model or n.startswith(f"{model}:") for n in await installed_models())


async def ensure_model_loaded() -> bool:
    """Warm the model so the first real inference isn't cold."""
    try:
        async with httpx.AsyncClient(timeout=60) as c:
            await c.post(f"{ollama_url()}/api/generate", json={
                "model": ollama_model(), "prompt": "hi", "stream": False,
                "options": {"num_predict": 1},
            })
        return True
    except Exception:
        return False


# ── llama-server (AI naming) ────────────────────────────────────────────────

async def llama_server_running() -> bool:
    try:
        async with httpx.AsyncClient(timeout=2) as c:
            return (await c.get(naming_health_url())).status_code == 200
    except Exception:
        return False


def llama_server_configured() -> bool:
    return bool(llama_exe()) and Path(llama_exe()).exists() and bool(llama_model_path()) and Path(llama_model_path()).exists()


def llama_server_install_hint() -> str:
    if sys.platform == "win32":
        return "winget install -e --id ggml.llamacpp   (or download from https://github.com/ggml-org/llama.cpp/releases)"
    if sys.platform == "darwin":
        return "brew install llama.cpp"
    return "see https://github.com/ggml-org/llama.cpp#building-the-project"


async def ensure_llama_server_binary(timeout_s: float = 180) -> str:
    """Return a usable llama-server path, installing it via the platform's
    package manager first if it isn't anywhere to be found.

    No bundled binary, no manual hunt for a release zip: anyone who already
    has winget (every Windows 10/11 box) or brew gets this for free, the same
    way `spectrida onboard` already leans on winget for Ollama.
    """
    found = llama_exe()
    if found and Path(found).exists():
        return found

    if sys.platform == "win32" and shutil.which("winget"):
        try:
            proc = await asyncio.create_subprocess_exec(
                "winget", "install", "-e", "--id", "ggml.llamacpp",
                "--accept-package-agreements", "--accept-source-agreements",
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(proc.wait(), timeout=timeout_s)
        except Exception:
            pass
    elif sys.platform == "darwin" and shutil.which("brew"):
        try:
            proc = await asyncio.create_subprocess_exec(
                "brew", "install", "llama.cpp",
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(proc.wait(), timeout=timeout_s)
        except Exception:
            pass

    # winget (at least for portable/zip packages) can return control to the
    # CLI slightly before the actual file extraction finishes -- give it a
    # few seconds of grace before concluding the install didn't take.
    for _ in range(8):
        found = llama_exe()
        if found and Path(found).exists():
            return found
        await asyncio.sleep(2)
    return llama_exe()


async def ensure_llama_server(timeout_s: float = 120) -> bool:
    """True if llama-server is reachable; installs the binary if it's
    missing entirely, then tries to launch it (GPU model load can take
    30-60s+, hence the generous default timeout)."""
    if await llama_server_running():
        return True
    exe_path = await ensure_llama_server_binary()
    if not exe_path or not llama_model_path():
        return False
    exe = Path(exe_path)
    # llama-server defaults to port 8080, but everything here polls the naming
    # URL's port (8090). Without forcing --port they never agree and the launch
    # looks "stuck/dead" while llama is actually serving, just on the wrong port.
    args = list(llama_extra_args())
    if not any(a in ("--port", "-p") for a in args):
        from urllib.parse import urlparse
        port = urlparse(naming_health_url()).port or 8090
        args += ["--port", str(port)]
    try:
        _spawn_service(
            [str(exe), "-m", llama_model_path(), *args],
            cwd=str(exe.parent), log_name="llama-server")
    except Exception:
        return False
    elapsed = 0.0
    while elapsed < timeout_s:
        await asyncio.sleep(2)
        elapsed += 2
        if await llama_server_running():
            return True
    return False


# ── Neo4j ────────────────────────────────────────────────────────────────────

async def neo4j_running() -> bool:
    try:
        from neo4j import GraphDatabase

        def _check():
            driver = GraphDatabase.driver(graph_uri(), auth=(graph_user(), graph_password()))
            try:
                driver.verify_connectivity()
                return True
            finally:
                driver.close()

        return await asyncio.to_thread(_check)
    except Exception:
        return False


def neo4j_configured() -> bool:
    d = neo4j_dir()
    return bool(d) and (Path(d) / "bin" / "neo4j.bat" if sys.platform == "win32" else Path(d) / "bin" / "neo4j").exists()


async def ensure_neo4j(timeout_s: float = 60) -> bool:
    """True if Neo4j is reachable; tries to start it if not.

    Uses `console` mode, not `start` — `start` (daemon mode) requires the
    Windows service to be pre-installed (`neo4j windows-service install`,
    needs admin rights), which this zip-distribution install never did.
    `console` has no such requirement; spawning it detached (own process
    group, no inherited stdio) makes it behave like a background daemon
    anyway since nothing is waiting on it."""
    if await neo4j_running():
        return True
    if not neo4j_configured():
        return False
    bat = Path(neo4j_dir()) / "bin" / ("neo4j.bat" if sys.platform == "win32" else "neo4j")
    env = os.environ.copy()
    if java_home():
        env["JAVA_HOME"] = java_home()
        env["PATH"] = str(Path(java_home()) / "bin") + os.pathsep + env.get("PATH", "")
    try:
        _spawn_service([str(bat), "console"], env=env, log_name="neo4j")
    except Exception:
        return False
    elapsed = 0.0
    while elapsed < timeout_s:
        await asyncio.sleep(2)
        elapsed += 2
        if await neo4j_running():
            return True
    return False


# ── idalib ──────────────────────────────────────────────────────────────────

def idalib_ok(path: str | None = None) -> bool:
    """Cheap validity check that `path` looks like an IDA install with idalib."""
    p = Path(path or idalib_dir())
    if not path and not idalib_dir():
        return False
    if not p.is_dir():
        return False
    markers = ["idalib.dll", "libidalib.so", "libidalib.dylib", "idapro.py"]
    return any((p / m).exists() for m in markers) or any(p.glob("**/idapro.py"))
