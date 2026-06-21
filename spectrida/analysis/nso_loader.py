"""Minimal Nintendo Switch NSO loader for idalib's headless workflow.

IDA Pro ships no native NSO support. A freshly open_database()'d NSO file is
just raw, possibly LZ4-compressed, file bytes sitting wherever IDA's generic
"Binary File" fallback loader happened to place them -- not the decompressed,
correctly-based ARM64 image spectrIDA's scanners actually need. That gap is
why the parallel NSO pipeline was finding almost nothing: it was scanning
either compressed garbage or the wrong address range.

This ports just the load-time logic from reswitched/loaders' nxo64.py
(decompress + idaapi.mem2base + idaapi.add_segm at the synthetic base every
NSO loader plugin has historically used: 0x7100000000) -- not its ELF
relocation/symbol-resolution machinery, which spectrIDA's own Capstone-based
scanner doesn't need.
"""
from __future__ import annotations

import struct

import lz4.block

NSO_LOAD_BASE = 0x7100000000


def parse_nso(path: str) -> dict:
    """Parse an NSO0 file: decompress .text/.rodata/.data, return layout info."""
    with open(path, "rb") as f:
        data = f.read()

    if data[:4] != b"NSO0":
        raise ValueError("not an NSO0 file")

    flags = struct.unpack_from("<I", data, 0xC)[0]
    t_off, t_loc, t_size = struct.unpack_from("<III", data, 0x10)
    r_off, r_loc, r_size = struct.unpack_from("<III", data, 0x20)
    d_off, d_loc, d_size = struct.unpack_from("<III", data, 0x30)
    t_fsize, r_fsize, d_fsize = struct.unpack_from("<III", data, 0x60)
    bss_size = struct.unpack_from("<I", data, 0x3C)[0]

    def _segment(off: int, fsize: int, size: int, flag_bit: int) -> bytes:
        raw = data[off:off + fsize]
        if flags & flag_bit:
            return lz4.block.decompress(raw, uncompressed_size=size)
        if len(raw) < size:
            raw = raw + b"\x00" * (size - len(raw))
        return raw[:size]

    return {
        "text": _segment(t_off, t_fsize, t_size, 1), "text_loc": t_loc, "text_size": t_size,
        "rodata": _segment(r_off, r_fsize, r_size, 2), "rodata_loc": r_loc, "rodata_size": r_size,
        "data": _segment(d_off, d_fsize, d_size, 4), "data_loc": d_loc, "data_size": d_size,
        "bss_size": bss_size,
    }


def load_into_ida(path: str) -> dict:
    """Decompress + map an NSO into the currently-open idalib database.

    Must be called after idapro.open_database(path, run_auto_analysis=False)
    inside the same process. Returns {"base", "text_start", "text_end"}.
    """
    import idaapi
    import idc

    info = parse_nso(path)
    base = NSO_LOAD_BASE

    idaapi.set_processor_type("arm", idaapi.SETPROC_LOADER_NON_FATAL | idaapi.SETPROC_LOADER)
    idc.set_inf_attr(idc.INF_LFLAGS, idc.get_inf_attr(idc.INF_LFLAGS) | idc.LFLG_64BIT)

    # .text/.rodata/.data sit at their real (decompressed) virtual offsets,
    # back-to-back -- same layout nxo64.py's load_file() builds.
    blob_size = info["data_loc"] + info["data_size"]
    blob = bytearray(blob_size)
    blob[info["text_loc"]:info["text_loc"] + len(info["text"])] = info["text"]
    blob[info["rodata_loc"]:info["rodata_loc"] + len(info["rodata"])] = info["rodata"]
    blob[info["data_loc"]:info["data_loc"] + len(info["data"])] = info["data"]
    idaapi.mem2base(bytes(blob), base, -1)

    for off, size, name, kind, perm in [
        (info["text_loc"], info["text_size"], ".text", "CODE",
         idaapi.SEGPERM_READ | idaapi.SEGPERM_EXEC),
        (info["rodata_loc"], info["rodata_size"], ".rodata", "CONST",
         idaapi.SEGPERM_READ),
        (info["data_loc"], info["data_size"], ".data", "DATA",
         idaapi.SEGPERM_READ | idaapi.SEGPERM_WRITE),
    ]:
        if size == 0:
            continue
        idaapi.add_segm(0, base + off, base + off + size, name, kind)
        segm = idaapi.get_segm_by_name(name)
        segm.perm = perm
        idaapi.update_segm(segm)

    return {
        "base": base,
        "text_start": base + info["text_loc"],
        "text_end": base + info["text_loc"] + info["text_size"],
    }
