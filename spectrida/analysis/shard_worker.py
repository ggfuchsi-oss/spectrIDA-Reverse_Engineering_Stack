"""
shard_worker.py
Run inside ONE idalib subprocess. Analyzes a specific address range of a binary.

Args: <binary_path> <shard_start_hex> <shard_end_hex> <result_json_path>

Strategy:
  1. open_database(binary, run_auto_analysis=False)
  2. Mark all code segments outside [shard_start, shard_end) as SEG_DATA
  3. GPU fast-scan: find prologues/entry points, seed into IDA
  4. Capstone recursive descent: build full function list
  5. Apply Capstone results into IDA
  6. auto_wait() for type propagation only (discovery already done)
  7. Export functions + names to JSON
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

IDA_DIR   = os.environ.get("SPECTRIDA_IDALIB") or r"C:\Program Files\IDA Professional 9.1"
ACCEL_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, IDA_DIR)
sys.path.insert(0, ACCEL_DIR)

binary       = sys.argv[1]
shard_start  = int(sys.argv[2], 16)
shard_end    = int(sys.argv[3], 16)
result_path  = sys.argv[4]
arch_hint    = sys.argv[5] if len(sys.argv) > 5 else None
entries_path = sys.argv[6] if len(sys.argv) > 6 else None

def log(msg: str):
    print(f"[shard {shard_start:#x}] {msg}", flush=True)

import idapro

idapro.enable_console_messages(False)

rc = idapro.open_database(binary, run_auto_analysis=False)
if rc != 0:
    sys.exit(f"open_database failed rc={rc}")

import ida_bytes
import ida_segment
import idaapi
import idautils
import idc

# IDA has no native NSO loader -- open_database() above just dumps the raw
# (possibly still LZ4-compressed) file bytes into whatever segment its
# generic Binary File fallback creates, at the wrong base, on the wrong
# processor. Decompress + remap it properly before any scanning happens.
is_nso = Path(binary).read_bytes()[:4] == b"NSO0"
if is_nso:
    from nso_loader import load_into_ida
    load_into_ida(binary)

# ── Detect arch ───────────────────────────────────────────────────────────────
# A caller that already knows the binary format (e.g. NSO == always AArch64 on
# Switch) can hand it down directly -- IDA's headless binary loader has no
# native NSO support and silently defaults to metapc, so procname can't be
# trusted to tell us this on its own.
if arch_hint:
    arch = arch_hint
else:
    try:
        info = idaapi.get_inf_structure()
        proc = info.procname.lower() if hasattr(info, "procname") else ""
        arch = "arm64" if ("arm" in proc or "aarch" in proc) else "x86_64"
    except Exception:
        arch = "x86_64"

log(f"arch={arch}")

# ── Mark segments outside shard as DATA ──────────────────────────────────────
for seg_ea in list(idautils.Segments()):
    seg   = ida_segment.getseg(seg_ea)
    stype = idc.get_segm_attr(seg_ea, idc.SEGATTR_TYPE)
    if stype == idc.SEG_CODE:
        if seg.end_ea <= shard_start or seg.start_ea >= shard_end:
            idc.set_segm_type(seg_ea, idc.SEG_DATA)

t_start = time.time()

raw = ida_bytes.get_bytes(shard_start, shard_end - shard_start)

# ── Entry points ───────────────────────────────────────────────────────────────
# A precomputed global entry-points file (entries_path) takes priority -- a
# per-shard scan only ever sees BL targets whose CALLING instruction happens
# to live in this same narrow shard, missing every cross-shard call. A single
# whole-binary scan done once up front doesn't have that blind spot.
entry_points = []
if entries_path:
    try:
        all_entries = json.loads(Path(entries_path).read_text())
        entry_points = [ea for ea in all_entries if shard_start <= ea < shard_end]
        log(f"global entry points: {len(entry_points)} in range")
    except Exception as _e:
        log(f"failed to load global entries ({_e}), falling back to local scan")
        entries_path = None

if not entries_path:
    try:
        if arch == "x86_64":
            from ida_gpu_accel.config import GPU_ENABLED
            from ida_gpu_accel.x86_64_scanner import _gpu_scan_x86, _x86_prologues_numpy
            if raw:
                if GPU_ENABLED:
                    entry_points = _gpu_scan_x86(raw, shard_start)
                else:
                    entry_points = _x86_prologues_numpy(raw, shard_start)
                log(f"GPU scan: {len(entry_points)} entry points")
        else:
            from ida_gpu_accel.arm64_scanner import scan
            if raw:
                # Prologue pattern alone misses leaf functions / non-standard
                # frame setups -- BL targets (real call destinations) catch those.
                prologues, bl_targets, _, _ = scan(raw, shard_start)
                entry_points = sorted(set(prologues) | set(bl_targets))
                log(f"GPU scan: {len(entry_points)} entry points")
    except Exception as _e:
        log(f"GPU scan error (non-fatal): {_e}")

# ── Capstone recursive descent ────────────────────────────────────────────────
# We write JSON directly from Capstone results — no add_func() in workers.
# add_func() causes idalib C++ crashes under parallel load.
# The merge pass applies all functions to a single IDA instance safely.
capstone_funcs: list[dict] = []

try:
    from ida_gpu_accel.capstone_scanner import HAS_CAPSTONE, scan_shard
    if not HAS_CAPSTONE:
        raise ImportError("capstone not installed")
    if not raw:
        raise RuntimeError("no raw bytes")

    log(f"Capstone pass starting ({len(entry_points)} seeds)...")
    result = scan_shard(raw, shard_start, shard_start, shard_end, arch=arch,
                       entry_points=entry_points if entries_path else None)

    for fi in result.funcs:
        if shard_start <= fi.ea < shard_end:
            capstone_funcs.append({"ea": fi.ea, "name": f"sub_{fi.ea:x}", "size": getattr(fi, "size", 0), "callers": []})

    log(f"Capstone: {len(capstone_funcs)} funcs found")

except Exception as _exc:
    log(f"Capstone failed ({_exc}), falling back to GPU preseed only")
    for ea in entry_points:
        if shard_start <= ea < shard_end:
            capstone_funcs.append({"ea": ea, "name": f"sub_{ea:x}", "size": 0, "callers": []})

elapsed = time.time() - t_start
log(f"done in {elapsed:.1f}s")

# ── Export ────────────────────────────────────────────────────────────────────
funcs = capstone_funcs

Path(result_path).write_text(json.dumps({
    "shard_start": shard_start,
    "shard_end":   shard_end,
    "elapsed_s":   elapsed,
    "funcs":       funcs,
}))

log(f"{len(funcs)} funcs exported")
try:
    idapro.close_database()
except Exception:
    pass
