"""NSO (Nintendo Switch executable) — a thin FormatHandler adapter around
``nso_loader.py``. nso_loader's decompress/mem2base/add_segm logic is
already correct and hard-won (see its own docstring + the NSO pipeline
history: wrong-arch, still-compressed, and locally-blind-entry-point bugs,
all fixed there already) — this module does not re-implement any of that,
it just exposes it through the FormatHandler contract so the registry can
find it and the generic sharding/discovery code in parallel_analyze.py
doesn't need an ``if is_nso`` branch.
"""
from __future__ import annotations

from spectrida.analysis import nso_loader
from spectrida.analysis.formats.base import FormatHandler, PreparedImage, Section


class NSOHandler(FormatHandler):
    name = "NSO"

    def __init__(self) -> None:
        self._info: dict | None = None  # cached parse_nso() result from prepare()
        self._path: str | None = None

    @staticmethod
    def sniff(header: bytes, path: str) -> bool:
        return header[:4] == b"NSO0"

    def prepare(self, path: str, workdir: str) -> PreparedImage:
        self._path = path
        info = nso_loader.parse_nso(path)
        self._info = info
        base = nso_loader.NSO_LOAD_BASE

        sections = [
            Section(name=".text", va=info["text_loc"], raw_off=0,
                    raw_size=len(info["text"]), vsize=info["text_size"], is_code=True),
            Section(name=".rodata", va=info["rodata_loc"], raw_off=0,
                    raw_size=len(info["rodata"]), vsize=info["rodata_size"]),
            Section(name=".data", va=info["data_loc"], raw_off=0,
                    raw_size=len(info["data"]), vsize=info["data_size"]),
            Section(name=".bss", va=info["data_loc"] + info["data_size"], raw_off=0,
                    raw_size=0, vsize=info["bss_size"]),
        ]
        return PreparedImage(binary_path=path, image_base=base, sections=sections, arch="arm64")

    def post_open(self) -> None:
        # Re-parses internally (cheap LZ4 decompress, not the expensive scan
        # step) — fine to call independently of prepare()'s cached _info,
        # and keeps this a faithful pass-through of the validated loader.
        nso_loader.load_into_ida(self._path)

    def read_bytes(self, image: PreparedImage, va_start: int, va_end: int) -> bytes:
        # Decompressed already, in memory from prepare() — no need to touch
        # the (still LZ4-compressed) file on disk.
        if not self._info:
            return b""
        text_va = image.image_base + self._info["text_loc"]
        text_blob = self._info["text"]
        start_off = max(va_start - text_va, 0)
        end_off = min(va_end - text_va, len(text_blob))
        if end_off <= start_off:
            return b""
        return text_blob[start_off:end_off]

    def global_entry_points(self, image: PreparedImage, text_start: int, text_end: int) -> list[int] | None:
        # NSO has no PE-style section table to drive a density prescan and
        # AArch64 leaf functions need BL-target seeds, not just prologues —
        # see base.FormatHandler.global_entry_points for why this matters.
        from spectrida.analysis.ida_gpu_accel.arm64_scanner import scan
        full_text = self.read_bytes(image, text_start, text_end)
        if not full_text:
            return None
        prologues, bl_targets, _, _ = scan(full_text, text_start)
        return sorted(set(prologues) | set(bl_targets))

    def make_shard_binary(self, image: PreparedImage, dst: str, shard_start_va: int, shard_end_va: int) -> None:
        # The source file is LZ4-compressed; there's no PE-style section
        # table to selectively zero, and zeroing raw compressed bytes would
        # break decompression for every shard, not just this one. Each
        # worker decompresses the *full* NSO in its own prepare() call and
        # rebuilds full segments in post_open() — VA-range isolation happens
        # via shard_worker's existing SEG_DATA marking, not via the file.
        import shutil
        shutil.copy2(image.binary_path, dst)


HANDLER = NSOHandler()
