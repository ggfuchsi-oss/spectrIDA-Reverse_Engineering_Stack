"""The contract every binary-format plugin implements.

A handler's job is narrow: look at a file and say whether it owns it
(``sniff``), turn it into something idalib's native loader can open
(``prepare``), do any manual idaapi segment setup idalib's loader can't do on
its own (``post_open`` — only formats IDA has no native loader for, like NSO,
need this), and know how to carve a binary into VA-range shards
(``make_shard_binary``). Everything else (sharding strategy, GPU prologue
scanning, merging) is format-agnostic and lives outside this package.
"""
from __future__ import annotations

import shutil
from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Section:
    """One mapped region of the binary, in the handler's own native units."""
    name: str
    va: int           # virtual address, relative to image_base
    raw_off: int      # offset of this section's bytes within the file prepare() produced
    raw_size: int     # size of the section's bytes on disk (may be < vsize, e.g. .bss)
    vsize: int        # size of the section once mapped
    is_code: bool = False


@dataclass
class PreparedImage:
    """What prepare() hands back to the caller.

    ``binary_path`` is the file idalib's ``open_database`` should actually be
    pointed at — usually the original path unchanged, but for formats idalib
    can't parse directly (compressed/headerless) this is a decompressed
    stand-in built by prepare() itself.
    """
    binary_path: str
    image_base: int = 0
    sections: list[Section] = field(default_factory=list)
    arch: str | None = None  # hint for shard_worker when IDA's own detection can't be trusted


class FormatHandler(ABC):
    """Base class for a binary-format plugin. Subclass and register it."""

    name: str = "unknown"

    @staticmethod
    @abstractmethod
    def sniff(header: bytes, path: str) -> bool:
        """Return True if this handler owns the file. ``header`` is the first
        4 KiB or so — enough for any magic-byte check; avoid re-reading the
        file here, the registry already did."""

    @abstractmethod
    def prepare(self, path: str, workdir: str) -> PreparedImage:
        """Turn ``path`` into a PreparedImage. For formats IDA loads natively
        (PE, ELF, Mach-O) this is just header parsing — return the original
        path untouched. For formats idalib can't open as-is (NSO: LZ4
        compressed, no native loader) this is where decompression happens;
        ``workdir`` is a private scratch directory for any files this needs
        to write."""

    def post_open(self) -> None:
        """Called immediately after a successful idapro.open_database() on
        the file prepare() returned, before any analysis. Default: no-op —
        only formats with no native IDA loader (NSO) need to manually build
        segments here via idaapi/ida_segment."""

    def make_shard_binary(self, image: PreparedImage, dst: str, shard_start_va: int, shard_end_va: int) -> None:
        """Copy ``image.binary_path`` -> dst, zeroing the raw bytes of any
        section that falls entirely outside [shard_start_va, shard_end_va) so
        each worker's IDA instance only sees its own code range. Takes the
        already-prepared image (not the original path) so formats that had to
        decompress in prepare() don't redo that work per shard. Default
        implementation is generic over Section lists via
        ``zero_sections_outside_range`` — most handlers don't need to
        override this, just populate ``sections``/``image_base`` in
        prepare(). Formats with no usable section table (no sections at all)
        fall back to a plain copy; sharding then relies on the equal-byte
        split + SEG_DATA masking that's already format-agnostic."""
        if not image.sections:
            shutil.copy2(image.binary_path, dst)
            return
        zero_sections_outside_range(
            image.binary_path, dst, image.sections, image.image_base,
            shard_start_va, shard_end_va,
        )

    def code_range(self, image: PreparedImage) -> tuple[int, int] | None:
        """Return (va_start, va_end) spanning every section marked
        ``is_code``, or None if the handler couldn't determine one (caller
        falls back to a slower IDA-assisted discovery pass). Default
        implementation works for any handler that populates ``sections``
        with accurate ``is_code``/``va``/``vsize`` — override only if a
        format needs something cleverer."""
        code_sections = [s for s in image.sections if s.is_code]
        if not code_sections:
            return None
        start = min(image.image_base + s.va for s in code_sections)
        end = max(image.image_base + s.va + s.vsize for s in code_sections)
        return start, end

    def read_bytes(self, image: PreparedImage, va_start: int, va_end: int) -> bytes:
        """Return the mapped bytes for [va_start, va_end) — used for prologue
        density scanning before any IDA segments exist. Default reads
        straight from ``image.binary_path`` via the section table (works for
        flat, uncompressed images like PE). Formats whose prepare() already
        holds the relevant bytes in memory (NSO, post-decompression) should
        override this to avoid re-reading/re-decompressing the file."""
        if not image.sections:
            return b""
        rel_s = va_start - image.image_base
        rel_e = va_end - image.image_base
        buf = bytearray()
        with open(image.binary_path, "rb") as f:
            for sect in sorted(image.sections, key=lambda s: s.va):
                sect_end = sect.va + sect.vsize
                if sect_end <= rel_s or sect.va >= rel_e:
                    continue
                overlap_start = max(sect.va, rel_s)
                overlap_end = min(sect_end, rel_e)
                file_off = sect.raw_off + (overlap_start - sect.va)
                byte_count = min(overlap_end - overlap_start, sect.raw_size - (overlap_start - sect.va))
                if byte_count <= 0:
                    continue
                f.seek(file_off)
                buf += f.read(byte_count)
        return bytes(buf)

    def global_entry_points(self, image: PreparedImage, text_start: int, text_end: int) -> list[int] | None:
        """Return a one-time, whole-binary entry-point pre-scan (prologues +
        call targets) for [text_start, text_end), or None if the format
        doesn't need one. Default: None — most formats are fine with each
        shard worker doing its own local scan of just its own narrow window.

        NSO overrides this: AArch64 leaf functions often have no recognizable
        prologue and are only discoverable via a BL target seen elsewhere in
        the binary, so a per-shard scan that only sees its own narrow window
        misses every call whose *calling* instruction lives in a different
        shard — most calls, in a binary of any size. A single global scan
        computed once here and handed to every worker doesn't have that
        blind spot. (This was a real, hard-won correctness bug — see NSO
        pipeline history — not a hypothetical.)"""
        return None

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name!r}>"


def zero_sections_outside_range(
    src: str, dst: str, sections: list[Section], image_base: int,
    shard_start_va: int, shard_end_va: int,
) -> None:
    """Shared implementation: copy src -> dst, zero raw bytes of sections (or
    the parts of them) that fall outside [shard_start_va, shard_end_va).
    Used by handlers whose underlying format is an uncompressed flat image
    with a section table (PE today; ELF/Mach-O could reuse this too)."""
    shutil.copy2(src, dst)
    rel_s = shard_start_va - image_base
    rel_e = shard_end_va - image_base
    with open(dst, "r+b") as f:
        for sect in sections:
            sect_end = sect.va + sect.vsize
            if sect_end <= rel_s or sect.va >= rel_e:
                if sect.raw_off and sect.raw_size:
                    f.seek(sect.raw_off)
                    f.write(b"\x00" * sect.raw_size)
                continue
            if sect.va < rel_s:
                zero_bytes = min(rel_s - sect.va, sect.raw_size)
                if sect.raw_off and zero_bytes > 0:
                    f.seek(sect.raw_off)
                    f.write(b"\x00" * zero_bytes)
            if sect_end > rel_e and sect.va < rel_e:
                start_in_sect = max(rel_e - sect.va, 0)
                zero_off = sect.raw_off + start_in_sect
                zero_bytes = sect.raw_size - start_in_sect
                if zero_off < sect.raw_off + sect.raw_size and zero_bytes > 0:
                    f.seek(zero_off)
                    f.write(b"\x00" * zero_bytes)
