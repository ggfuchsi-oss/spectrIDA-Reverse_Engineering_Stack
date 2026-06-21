"""spectrIDA config — reads ~/.spectrida/config.toml, falls back to env vars.

Every path the tool needs comes from here; nothing is hardcoded. A first-run
marker (``~/.spectrida/.onboarded``) records whether the wizard has run, so it
only auto-launches once.
"""
from __future__ import annotations

import functools
import os
import shutil
import subprocess
from pathlib import Path

try:
    import tomllib
except ImportError:  # py < 3.11
    try:
        import tomli as tomllib  # type: ignore
    except ImportError:
        tomllib = None  # type: ignore

CONFIG_DIR  = Path.home() / ".spectrida"
CONFIG_FILE = CONFIG_DIR / "config.toml"
_ONBOARD_MARKER = CONFIG_DIR / ".onboarded"

_DEFAULT = {
    "ida":      {"idalib": "", "output_dir": str(CONFIG_DIR / "output")},
    "ollama":   {"base_url": "http://localhost:11434", "model": "spectrida-re"},
    "pipeline": {"workers": 16},
    "graph":    {"uri": "bolt://localhost:7687", "user": "neo4j", "password": ""},
    "naming":   {"llama_url": "http://127.0.0.1:8090/completion",
                 "health_url": "http://127.0.0.1:8090/health"},
    "services": {"llama_exe": "", "llama_model": "", "llama_args": "--ctx-size 8192 --parallel 4 --cont-batching -ngl 99",
                 "neo4j_dir": "", "java_home": ""},
}


def _load() -> dict:
    if tomllib is None or not CONFIG_FILE.exists():
        return {k: dict(v) for k, v in _DEFAULT.items()}
    try:
        with open(CONFIG_FILE, "rb") as f:
            raw = f.read()
        # strip BOM if present (written by some Windows editors)
        if raw.startswith(b"\xef\xbb\xbf"):
            raw = raw[3:]
        user = tomllib.loads(raw.decode("utf-8", errors="replace"))
        result = {k: dict(v) for k, v in _DEFAULT.items()}
        for section, values in user.items():
            if isinstance(result.get(section), dict) and isinstance(values, dict):
                result[section].update(values)
            else:
                result[section] = values
        return result
    except Exception:
        return {k: dict(v) for k, v in _DEFAULT.items()}


_cfg = _load()


def get(section: str, key: str, env_var: str | None = None) -> str:
    if env_var and os.environ.get(env_var):
        return os.environ[env_var]
    return str(_cfg.get(section, {}).get(key, ""))


# ── path / service accessors ────────────────────────────────────────────────

def idalib_dir() -> str:
    return get("ida", "idalib", "SPECTRIDA_IDALIB")


def output_dir() -> Path:
    p = Path(get("ida", "output_dir", "SPECTRIDA_OUTPUT_DIR") or (CONFIG_DIR / "output"))
    p.mkdir(parents=True, exist_ok=True)
    return p


def ollama_url() -> str:
    return get("ollama", "base_url", "SPECTRIDA_OLLAMA_URL") or "http://localhost:11434"


def ollama_model() -> str:
    return get("ollama", "model", "SPECTRIDA_MODEL") or "spectrida-re"


def pipeline_workers() -> int:
    try:
        return int(get("pipeline", "workers", "SPECTRIDA_WORKERS") or 16)
    except ValueError:
        return 16


def pipeline_script() -> Path:
    """parallel_analyze.py — bundled in the package, or overridden by env."""
    env = os.environ.get("SPECTRIDA_PIPELINE_DIR", "")
    base = Path(env) if env else Path(__file__).parent / "analysis"
    return base / "parallel_analyze.py"


def graph_uri() -> str:
    return get("graph", "uri", "SPECTRIDA_GRAPH_URI") or "bolt://localhost:7687"


def graph_user() -> str:
    return get("graph", "user", "SPECTRIDA_GRAPH_USER") or "neo4j"


def graph_password() -> str:
    return get("graph", "password", "SPECTRIDA_GRAPH_PASS")


def naming_llama_url() -> str:
    return get("naming", "llama_url", "SPECTRIDA_LLAMA_URL") or "http://127.0.0.1:8090/completion"


def naming_health_url() -> str:
    return get("naming", "health_url", "SPECTRIDA_LLAMA_HEALTH_URL") or "http://127.0.0.1:8090/health"


def llama_exe() -> str:
    configured = get("services", "llama_exe", "SPECTRIDA_LLAMA_EXE")
    if configured and Path(configured).exists():
        return configured
    # If llama.cpp's server binary is just sitting on PATH (a manual install,
    # a package manager, whatever), use that instead of requiring an exact
    # config.toml path no one's going to remember to set.
    found = shutil.which("llama-server") or shutil.which("llama-server.exe")
    return found or configured


@functools.lru_cache(maxsize=8)
def _resolve_ollama_blob(model_name: str) -> str:
    """Find the raw GGUF Ollama already has on disk for ``model_name``.

    Anyone who's done onboarding's `ollama pull hf.co/gdfhhjk/spectrida-re-gguf`
    step already has the real weights sitting in Ollama's blob store -- no
    reason to also require a separate, manually-pointed llama.cpp model file
    just for the MCP server's naming path. Cached for the process lifetime;
    the blob a pulled tag points at doesn't change mid-session.
    """
    if not shutil.which("ollama"):
        return ""
    try:
        out = subprocess.run(
            ["ollama", "show", model_name, "--modelfile"],
            capture_output=True, text=True, timeout=10,
        ).stdout
    except Exception:
        return ""
    for line in out.splitlines():
        line = line.strip()
        if line.upper().startswith("FROM "):
            path = line[5:].strip()
            if path and Path(path).exists():
                return path
    return ""


def llama_model_path() -> str:
    configured = get("services", "llama_model", "SPECTRIDA_LLAMA_MODEL")
    if configured and Path(configured).exists():
        return configured
    return _resolve_ollama_blob(ollama_model())


def llama_extra_args() -> list[str]:
    raw = get("services", "llama_args", "SPECTRIDA_LLAMA_ARGS") or "--ctx-size 8192 --parallel 4 --cont-batching -ngl 99"
    return raw.split()


def neo4j_dir() -> str:
    return get("services", "neo4j_dir", "SPECTRIDA_NEO4J_DIR")


def java_home() -> str:
    return get("services", "java_home", "SPECTRIDA_JAVA_HOME")


# ── onboarding flag ─────────────────────────────────────────────────────────

def onboarded() -> bool:
    """True once the wizard has completed/skipped. Env forces a skip for CI/scripts."""
    if os.environ.get("SPECTRIDA_NO_ONBOARD"):
        return True
    return _ONBOARD_MARKER.exists()


def set_onboarded() -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    _ONBOARD_MARKER.touch()


# ── starter config ──────────────────────────────────────────────────────────

def write_config(idalib: str = "", model: str = "spectrida-re") -> Path:
    """Write config.toml with concrete values (used by onboarding auto-setup)."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    ida_line = (f'idalib = "{Path(idalib).as_posix()}"\n' if idalib
                else '# idalib = "C:/Program Files/IDA Professional 9.1"\n')
    CONFIG_FILE.write_text(
        "# spectrIDA configuration - https://github.com/ggfuchsi-oss/spectrIDA\n\n"
        f"[ida]\n{ida_line}"
        f'output_dir = "{output_dir().as_posix()}"\n\n'
        "[ollama]\n"
        'base_url = "http://localhost:11434"\n'
        f'model = "{model}"\n\n'
        "[pipeline]\nworkers = 16\n",
        encoding="utf-8",
    )
    return CONFIG_FILE


def write_default_config() -> Path:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if not CONFIG_FILE.exists():
        CONFIG_FILE.write_text(
            "# spectrIDA configuration - https://github.com/ggfuchsi-oss/spectrIDA\n\n"
            "[ida]\n"
            '# Path to the IDA install dir containing idalib.dll / libidalib.so\n'
            '# idalib = "C:/Program Files/IDA Professional 9.1"\n'
            f'output_dir = "{output_dir().as_posix()}"\n\n'
            "[ollama]\n"
            'base_url = "http://localhost:11434"\n'
            "# run: ollama pull hf.co/gdfhhjk/spectrida-re-gguf\n"
            'model = "spectrida-re"\n\n'
            "[pipeline]\n"
            "workers = 16\n",
            encoding="utf-8",
        )
    return CONFIG_FILE
