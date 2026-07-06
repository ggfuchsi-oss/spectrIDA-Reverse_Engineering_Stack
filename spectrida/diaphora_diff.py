"""Diaphora diff + name porting — the headline feature.

Given an old **named** Diaphora export and a new **unnamed** export,
port names across versions using Diaphora's similarity ratios.

Workflow:
  1. export_db() both binaries (old named, new unnamed) — Phase 1
  2. diff_db() headlessly → matches with ratios
  3. port_names() — gate by ratio, emit apply-script

Ratio gating (conservative by design):
  >= 0.95 → auto-apply old name to new function
  0.80–0.95 → emit as hints (feed to SpectrIDA as context, or review file)
  < 0.80 → discard (noise)

No IDA dependency for diffing — pure Python over SQLite exports.
"""
from __future__ import annotations

import os
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path


# ── config ───────────────────────────────────────────────────────────────────

DIAPHORA_SCRIPT = Path(__file__).parents[2] / "diaphora" / "diaphora.py"

# Default ratio thresholds
AUTO_APPLY_RATIO = 0.95    # >= this: auto-rename
HINT_RATIO = 0.80          # >= this: emit as hint


# ── types ────────────────────────────────────────────────────────────────────

@dataclass
class Match:
    address_old: str
    name_old: str
    address_new: str
    name_new: str
    ratio: float
    match_type: str     # "best", "partial", "unreliable", etc.
    nodes1: int = 0
    nodes2: int = 0
    description: str = ""


@dataclass
class PortResult:
    auto_applied: list[Match] = field(default_factory=list)
    hints: list[Match] = field(default_factory=list)
    discarded: list[Match] = field(default_factory=list)
    total_functions_new: int = 0
    total_matched: int = 0
    elapsed_seconds: float = 0.0


# ── export (Phase 1) ────────────────────────────────────────────────────────

def export_db(
    binary_path: str,
    out_sqlite: str,
    *,
    ida_path: str = "",
    timeout_s: int = 600,
) -> dict:
    """Run Diaphora headless export against a binary.

    Requires IDA in batch mode. Sets DIAPHORA_EXPORT_FILE + DIAPHORA_AUTO
    and runs idat -A -B -S<diaphora.py> <binary>.

    Returns {"sqlite": path, "elapsed": seconds} or {"error": msg}.
    """
    out = Path(out_sqlite).expanduser().resolve()
    out.parent.mkdir(parents=True, exist_ok=True)

    # Cache: skip if export exists and is newer than source
    src = Path(binary_path).expanduser().resolve()
    if out.exists() and out.stat().st_mtime > src.stat().st_mtime:
        return {"sqlite": str(out), "elapsed": 0, "cached": True}

    if not DIAPHORA_SCRIPT.exists():
        return {"error": f"diaphora.py not found at {DIAPHORA_SCRIPT}"}

    # Find idat
    if not ida_path:
        import shutil
        ida_path = shutil.which("idat") or shutil.which("idat64") or ""
    if not ida_path:
        # Try common locations
        for candidate in [
            r"C:\Program Files\IDA Professional 9.1\idat.exe",
            r"C:\Program Files\IDA 9.1\idat.exe",
        ]:
            if Path(candidate).exists():
                ida_path = candidate
                break
    if not ida_path:
        return {"error": "idat not found — set ida_path or add idat to PATH"}

    env = os.environ.copy()
    env["DIAPHORA_EXPORT_FILE"] = str(out)
    env["DIAPHORA_AUTO"] = "1"

    cmd = [ida_path, "-A", "-B", f"-S{DIAPHORA_SCRIPT}", str(src)]

    t0 = time.time()
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout_s, env=env,
        )
        elapsed = time.time() - t0

        if not out.exists():
            return {
                "error": f"export failed (exit {result.returncode})",
                "stderr": result.stderr[-500:] if result.stderr else "",
                "stdout": result.stdout[-500:] if result.stdout else "",
                "elapsed": elapsed,
            }

        return {"sqlite": str(out), "elapsed": elapsed}
    except subprocess.TimeoutExpired:
        return {"error": f"export timed out after {timeout_s}s"}
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}


# ── diff (Phase 2) ──────────────────────────────────────────────────────────

def diff_db(
    old_sqlite: str,
    new_sqlite: str,
    out_diaphora: str = "",
    *,
    timeout_s: int = 600,
) -> dict:
    """Run Diaphora diff headlessly (pure Python, no IDA needed).

    Returns {"results": path, "elapsed": seconds, "match_count": N}.
    """
    old = Path(old_sqlite).expanduser().resolve()
    new = Path(new_sqlite).expanduser().resolve()

    if not old.exists():
        return {"error": f"old export not found: {old}"}
    if not new.exists():
        return {"error": f"new export not found: {new}"}
    if not DIAPHORA_SCRIPT.exists():
        return {"error": f"diaphora.py not found at {DIAPHORA_SCRIPT}"}

    if not out_diaphora:
        out_diaphora = str(
            new.parent / f"{new.stem}_vs_{old.stem}.diaphora"
        )
    out = Path(out_diaphora).expanduser().resolve()

    cmd = [
        "python", str(DIAPHORA_SCRIPT),
        str(old), str(new), "-o", str(out),
    ]

    t0 = time.time()
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout_s,
        )
        elapsed = time.time() - t0

        if not out.exists():
            return {
                "error": f"diff failed (exit {result.returncode})",
                "stderr": result.stderr[-500:] if result.stderr else "",
                "elapsed": elapsed,
            }

        # Count matches
        import sqlite3
        conn = sqlite3.connect(str(out))
        try:
            count = conn.execute("SELECT count(*) FROM results").fetchone()[0]
        except Exception:
            count = 0
        conn.close()

        return {"results": str(out), "elapsed": elapsed, "match_count": count}
    except subprocess.TimeoutExpired:
        return {"error": f"diff timed out after {timeout_s}s"}
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}


# ── name porting (Phase 2 core) ─────────────────────────────────────────────

def port_names(
    diff_results: str,
    *,
    auto_ratio: float = AUTO_APPLY_RATIO,
    hint_ratio: float = HINT_RATIO,
) -> PortResult:
    """Read Diaphora diff results and gate matches by ratio.

    Returns a PortResult with:
      - auto_applied: >= auto_ratio → auto-rename
      - hints: >= hint_ratio → feed as context to model
      - discarded: < hint_ratio → noise
    """
    import sqlite3

    db_path = Path(diff_results).expanduser().resolve()
    if not db_path.exists():
        raise FileNotFoundError(f"diff results not found: {db_path}")

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row

    # Diaphora results schema:
    # type, line, address, name, address2, name2, ratio, nodes1, nodes2, description
    try:
        rows = conn.execute(
            "SELECT type, address, name, address2, name2, "
            "ratio, nodes1, nodes2, description "
            "FROM results ORDER BY ratio DESC"
        ).fetchall()
    except Exception as e:
        conn.close()
        raise RuntimeError(f"Failed to read results: {e}")

    result = PortResult(total_matched=len(rows))

    for row in rows:
        ratio = row["ratio"] or 0.0
        match = Match(
            address_old=row["address"] or "",
            name_old=row["name"] or "",
            address_new=row["address2"] or "",
            name_new=row["name2"] or "",
            ratio=ratio,
            match_type=row["type"] or "",
            nodes1=row["nodes1"] or 0,
            nodes2=row["nodes2"] or 0,
            description=row["description"] or "",
        )

        if ratio >= auto_ratio:
            result.auto_applied.append(match)
        elif ratio >= hint_ratio:
            result.hints.append(match)
        else:
            result.discarded.append(match)

    conn.close()
    return result


def emit_idc(
    port_result: PortResult,
    out_path: str,
) -> str:
    """Write an IDC script that applies auto-mapped names.

    Returns the output path.
    """
    out = Path(out_path).expanduser().resolve()
    out.parent.mkdir(parents=True, exist_ok=True)

    lines = [
        "// spectrIDA + Diaphora name porting",
        f"// Auto-applied: {len(port_result.auto_applied)} names",
        f"// Hints (review manually): {len(port_result.hints)} names",
        "//",
        "#include <idc.idc>",
        "static main() {",
    ]

    for m in port_result.auto_applied:
        safe = m.name_old.replace('"', '\\"')
        addr = m.address_new
        if isinstance(addr, str) and addr.startswith("0x"):
            addr = int(addr, 16)
        lines.append(f'  set_name({addr:#x}, "{safe}", SN_NOWARN);')

    lines.append("}")
    out.write_text("\n".join(lines), encoding="utf-8")
    return str(out)


def emit_hints(
    port_result: PortResult,
    out_path: str,
) -> str:
    """Write a JSON file with hint matches for review / model context.

    Returns the output path.
    """
    import json

    out = Path(out_path).expanduser().resolve()
    out.parent.mkdir(parents=True, exist_ok=True)

    hints = [
        {
            "address_new": m.address_new,
            "name_old": m.name_old,
            "ratio": round(m.ratio, 3),
            "description": m.description,
        }
        for m in port_result.hints
    ]

    out.write_text(json.dumps(hints, indent=2), encoding="utf-8")
    return str(out)


# ── convenience: full pipeline ──────────────────────────────────────────────

def port_names_full(
    old_sqlite: str,
    new_sqlite: str,
    out_dir: str = "",
    *,
    auto_ratio: float = AUTO_APPLY_RATIO,
    hint_ratio: float = HINT_RATIO,
) -> dict:
    """End-to-end: diff + gate + emit IDC + emit hints.

    Returns dict with paths to generated files + stats.
    """
    # Step 1: Diff
    diff_result = diff_db(old_sqlite, new_sqlite)
    if "error" in diff_result:
        return diff_result

    # Step 2: Port names
    port = port_names(
        diff_result["results"],
        auto_ratio=auto_ratio,
        hint_ratio=hint_ratio,
    )

    # Step 3: Emit files
    if not out_dir:
        out_dir = str(Path(new_sqlite).parent)
    out = Path(out_dir)

    idc_path = emit_idc(port, str(out / "ported_names.idc"))
    hints_path = emit_hints(port, str(out / "port_hints.json"))

    return {
        "diff_results": diff_result["results"],
        "diff_elapsed": diff_result["elapsed"],
        "total_matched": port.total_matched,
        "auto_applied": len(port.auto_applied),
        "hints": len(port.hints),
        "discarded": len(port.discarded),
        "idc_script": idc_path,
        "hints_file": hints_path,
    }
