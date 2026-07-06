"""Headless Diaphora export via idalib — the real deal.

Opens the .i64 with idalib, patches GUI calls, imports Diaphora, runs export.
No Qt, no forms, no interactive prompts.
"""
from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path

DIAPHORA_DIR = Path(__file__).parents[2] / "diaphora"

# Script that runs INSIDE the idalib process
_INNER = r'''
import sys, os, json, time

# Patch GUI before Diaphora import
try:
    import ida_kernwin
    ida_kernwin.show_wait_box = lambda msg: None
    ida_kernwin.hide_wait_box = lambda: None
    ida_kernwin.replace_wait_box = lambda msg: None
    ida_kernwin.warning = lambda msg: print(f"[dia-warn] {msg}", flush=True)
    ida_kernwin.ask_yn = lambda d, m: d
    ida_kernwin.ask_file = lambda *a, **k: None
except ImportError:
    pass

try:
    import idautils
    idautils.user_cancelled = lambda: False
except:
    pass

# Suppress Diaphora's optional-dependency warnings
os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")

# Import Diaphora
diaphora_dir = sys.argv[1]
sys.path.insert(0, diaphora_dir)

# Quiet down optional import warnings
import sqlite3
import diaphora_config
diaphora_config.SHOW_IMPORT_WARNINGS = False

import diaphora
import diaphora_ida

# Export
export_file = sys.argv[2]
# Clean stale DB
if os.path.exists(export_file):
    os.remove(export_file)
print("[dia] Exporting to " + export_file, flush=True)

t0 = time.time()
bd = diaphora_ida.CIDABinDiff(export_file)
bd.export()
elapsed = time.time() - t0

# Count results
conn = sqlite3.connect(export_file)
count = conn.execute("SELECT count(*) FROM functions").fetchone()[0]
edges = conn.execute("SELECT count(*) FROM callgraph").fetchone()[0]
conn.close()

result = json.dumps({"ok": True, "functions": count, "edges": edges, "elapsed": round(elapsed, 1)})
print("[dia] @@DONE " + result, flush=True)
'''


def headless_export(
    i64_path: str,
    out_sqlite: str,
    *,
    ida_dir: str = "",
    timeout_s: int = 600,
) -> dict:
    """Export .i64 to Diaphora SQLite via idalib headlessly.

    Returns {"ok": True, "functions": N, "edges": N, "elapsed": S, "sqlite": path}
    """
    i64 = Path(i64_path).expanduser().resolve()
    out = Path(out_sqlite).expanduser().resolve()
    out.parent.mkdir(parents=True, exist_ok=True)

    if not i64.exists():
        return {"ok": False, "error": f"i64 not found: {i64}"}
    if not DIAPHORA_DIR.exists():
        return {"ok": False, "error": f"diaphora not found at {DIAPHORA_DIR}"}

    # Cache: skip if export exists and is newer than source
    if out.exists() and out.stat().st_mtime > i64.stat().st_mtime:
        try:
            conn = sqlite3.connect(str(out))
            count = conn.execute("SELECT count(*) FROM functions").fetchone()[0]
            conn.close()
            if count > 0:
                return {"ok": True, "functions": count, "elapsed": 0,
                        "sqlite": str(out), "cached": True}
        except Exception:
            pass

    # Find idalib
    if not ida_dir:
        ida_dir = os.environ.get("SPECTRIDA_IDALIB", "")
    if not ida_dir:
        for c in [r"C:\Program Files\IDA Professional 9.1",
                  r"C:\Program Files\IDA 9.1"]:
            if Path(c).exists():
                ida_dir = c
                break
    if not ida_dir:
        return {"ok": False, "error": "IDA directory not found"}

    # Write inner script
    fd, script = tempfile.mkstemp(suffix=".py", prefix="diaexport_")
    os.write(fd, _INNER.encode("utf-8"))
    os.close(fd)

    # Run: open database → exec Diaphora export → close
    idalib_code = (
        f"import sys; sys.path.insert(0, {ida_dir!r}); "
        f"import idapro; "
        f"idapro.open_database({str(i64)!r}, False); "
        f"exec(open({script!r}).read(), {{'sys': sys}}); "
        f"idapro.close_database(True)"
    )

    try:
        result = subprocess.run(
            [sys.executable, "-c", idalib_code,
             str(DIAPHORA_DIR), str(out)],
            capture_output=True, text=True, timeout=timeout_s,
        )

        # Parse result
        for line in result.stdout.splitlines():
            if "[dia] @@DONE " in line:
                data = json.loads(line.split("@@DONE ", 1)[1])
                data["sqlite"] = str(out)
                return data

        if result.returncode != 0:
            return {"ok": False, "error": f"exit {result.returncode}",
                    "stderr": result.stderr[-600:] if result.stderr else "",
                    "stdout": result.stdout[-600:] if result.stdout else ""}

        # Fallback: check if file exists
        if out.exists():
            conn = sqlite3.connect(str(out))
            count = conn.execute("SELECT count(*) FROM functions").fetchone()[0]
            conn.close()
            return {"ok": True, "functions": count, "elapsed": 0, "sqlite": str(out)}

        return {"ok": False, "error": "no output", "stdout": result.stdout[-600:]}

    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"timed out after {timeout_s}s"}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}
    finally:
        try:
            os.unlink(script)
        except Exception:
            pass


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("i64")
    p.add_argument("output")
    p.add_argument("--ida-dir", default="")
    p.add_argument("--timeout", type=int, default=600)
    args = p.parse_args()
    print(json.dumps(headless_export(args.i64, args.output,
                                     ida_dir=args.ida_dir,
                                     timeout_s=args.timeout), indent=2))
