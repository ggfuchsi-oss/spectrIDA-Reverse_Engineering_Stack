"""Format-handler plugin system: sniff/detect/prepare for the built-ins, plus
registry priority and fallback behavior. No IDA/idalib needed — these only
exercise the pure-Python header parsing and decompression."""
from __future__ import annotations

import struct

import pytest

from spectrida.analysis import formats
from spectrida.analysis.formats.elf import ELFHandler
from spectrida.analysis.formats.generic import GenericHandler
from spectrida.analysis.formats.nso import NSOHandler
from spectrida.analysis.formats.pe import PEHandler


def _make_pe(tmp_path, machine=0x8664, image_base=0x140000000):
    data = bytearray(0x1000)
    data[0:2] = b"MZ"
    pe_off = 0x100
    struct.pack_into("<I", data, 0x3C, pe_off)
    data[pe_off:pe_off + 4] = b"PE\x00\x00"
    struct.pack_into("<H", data, pe_off + 4, machine)
    struct.pack_into("<H", data, pe_off + 6, 1)            # NumberOfSections
    opt_hdr_size = 112
    struct.pack_into("<H", data, pe_off + 20, opt_hdr_size)
    struct.pack_into("<H", data, pe_off + 24, 0x020B)       # PE32+ magic
    struct.pack_into("<Q", data, pe_off + 24 + 24, image_base)

    sect_off = pe_off + 24 + opt_hdr_size
    data[sect_off:sect_off + 8] = b".text\x00\x00\x00"
    struct.pack_into("<I", data, sect_off + 8, 0x1000)      # vsize
    struct.pack_into("<I", data, sect_off + 12, 0x1000)     # vaddr
    struct.pack_into("<I", data, sect_off + 16, 0x200)      # raw_size
    struct.pack_into("<I", data, sect_off + 20, 0x400)      # raw_off
    struct.pack_into("<I", data, sect_off + 36, 0x20)       # IMAGE_SCN_CNT_CODE

    p = tmp_path / "test.dll"
    p.write_bytes(bytes(data))
    return p


def _make_nso(tmp_path, *, compress_text: bool, text_plain: bytes | None = None):
    lz4_block = pytest.importorskip("lz4.block")

    text_plain = text_plain if text_plain is not None else bytes(range(64))
    ro_plain = b"RODATA__" * 8
    data_plain = b"DATA1234" * 8

    text_bytes = lz4_block.compress(text_plain, store_size=False) if compress_text else text_plain
    flags = 0x1 if compress_text else 0x0

    header = bytearray(0x100)
    header[0:4] = b"NSO0"
    struct.pack_into("<I", header, 0x0C, flags)

    text_file_off = 0x100
    ro_file_off = text_file_off + len(text_bytes)
    data_file_off = ro_file_off + len(ro_plain)

    struct.pack_into("<III", header, 0x10, text_file_off, 0x0, len(text_plain))
    struct.pack_into("<III", header, 0x20, ro_file_off, 0x1000, len(ro_plain))
    struct.pack_into("<III", header, 0x30, data_file_off, 0x2000, len(data_plain))
    struct.pack_into("<I", header, 0x3C, 0x40)              # bss size
    struct.pack_into("<I", header, 0x60, len(text_bytes))
    struct.pack_into("<I", header, 0x64, len(ro_plain))
    struct.pack_into("<I", header, 0x68, len(data_plain))

    p = tmp_path / "main.nso"
    p.write_bytes(bytes(header) + text_bytes + ro_plain + data_plain)
    return p, text_plain, ro_plain, data_plain


def _make_elf64_so(tmp_path, machine=62, name="libtest.so"):
    text_data = bytes(range(32))
    shoff = 64
    shentsize = 64
    shnum = 3
    text_off = shoff + shentsize * shnum

    header = bytearray(64)
    header[0:4] = b"\x7fELF"
    header[4] = 2   # ELFCLASS64
    header[5] = 1   # ELFDATA2LSB
    header[6] = 1   # EV_CURRENT
    struct.pack_into("<H", header, 16, 3)             # e_type = ET_DYN (.so)
    struct.pack_into("<H", header, 18, machine)       # e_machine
    struct.pack_into("<Q", header, 40, shoff)         # e_shoff
    struct.pack_into("<H", header, 58, shentsize)     # e_shentsize
    struct.pack_into("<H", header, 60, shnum)         # e_shnum

    shdrs = bytearray(shentsize * shnum)
    # section 0: SHT_NULL, no flags — must be filtered out (not SHF_ALLOC)

    # section 1: PROGBITS .text-like, ALLOC|EXECINSTR
    o = shentsize * 1
    struct.pack_into("<I", shdrs, o + 4, 1)            # sh_type = SHT_PROGBITS
    struct.pack_into("<Q", shdrs, o + 8, 0x6)          # sh_flags = ALLOC|EXECINSTR
    struct.pack_into("<Q", shdrs, o + 16, 0x1000)      # sh_addr
    struct.pack_into("<Q", shdrs, o + 24, text_off)    # sh_offset
    struct.pack_into("<Q", shdrs, o + 32, len(text_data))  # sh_size

    # section 2: NOBITS .bss-like, ALLOC|WRITE
    o = shentsize * 2
    struct.pack_into("<I", shdrs, o + 4, 8)            # sh_type = SHT_NOBITS
    struct.pack_into("<Q", shdrs, o + 8, 0x3)          # sh_flags = ALLOC|WRITE
    struct.pack_into("<Q", shdrs, o + 16, 0x2000)      # sh_addr
    struct.pack_into("<Q", shdrs, o + 32, 0x40)        # sh_size

    p = tmp_path / name
    p.write_bytes(bytes(header) + bytes(shdrs) + text_data)
    return p, text_data


def test_elf_sniff_and_prepare(tmp_path):
    p, text_data = _make_elf64_so(tmp_path)
    handler = ELFHandler()
    header = p.read_bytes()[:0x1000]
    assert handler.sniff(header, str(p))

    image = handler.prepare(str(p), workdir=str(tmp_path))
    assert image.arch == "x86_64"
    # the SHT_NULL section has no SHF_ALLOC and must be filtered out
    assert len(image.sections) == 2
    code_sections = [s for s in image.sections if s.is_code]
    assert len(code_sections) == 1
    assert handler.code_range(image) == (0x1000, 0x1000 + len(text_data))
    assert handler.read_bytes(image, 0x1000, 0x1000 + len(text_data)) == text_data


def test_registry_detects_elf(tmp_path):
    p, _ = _make_elf64_so(tmp_path)
    handler = formats.detect(str(p))
    assert handler.name == "ELF"


def test_elf_arch_hint_distinguishes_arm32_from_arm64(tmp_path):
    # Regression: 32-bit ARM (EM_ARM=40) was unmapped, so image.arch fell
    # through to None -- which then got misclassified as "arm64" by IDA
    # procname substring matching ("arm" matches both ARM and AArch64),
    # silently routing real 32-bit ARM/Thumb bytes through the AArch64
    # Capstone decoder. "arm32" must be its own distinct, never-confused-
    # with-"arm64" value.
    handler = ELFHandler()

    p64, _ = _make_elf64_so(tmp_path, machine=183, name="lib64.so")   # EM_AARCH64
    assert handler.prepare(str(p64), workdir=str(tmp_path)).arch == "arm64"

    p32, _ = _make_elf64_so(tmp_path, machine=40, name="lib32.so")    # EM_ARM
    arch32 = handler.prepare(str(p32), workdir=str(tmp_path)).arch
    assert arch32 == "arm32"
    assert arch32 != "arm64"


def test_pe_sniff_and_prepare(tmp_path):
    p = _make_pe(tmp_path)
    handler = PEHandler()
    header = p.read_bytes()[:0x1000]
    assert handler.sniff(header, str(p))

    image = handler.prepare(str(p), workdir=str(tmp_path))
    assert image.image_base == 0x140000000
    assert image.binary_path == str(p)
    assert len(image.sections) == 1
    sect = image.sections[0]
    assert sect.name == ".text"
    assert sect.is_code
    assert handler.code_range(image) == (0x140000000 + 0x1000, 0x140000000 + 0x1000 + 0x1000)


def test_nso_sniff_and_decompress(tmp_path):
    p, text_plain, ro_plain, data_plain = _make_nso(tmp_path, compress_text=True)
    handler = NSOHandler()
    header = p.read_bytes()[:0x1000]
    assert handler.sniff(header, str(p))

    image = handler.prepare(str(p), workdir=str(tmp_path))
    assert image.arch == "arm64"
    crange = handler.code_range(image)
    assert crange is not None
    text_va = image.image_base + 0x0
    assert crange == (text_va, text_va + len(text_plain))
    # read_bytes() pulls straight from the decompressed in-memory segment
    assert handler.read_bytes(image, text_va, text_va + len(text_plain)) == text_plain


def test_nso_uncompressed_segment_roundtrips(tmp_path):
    p, text_plain, ro_plain, data_plain = _make_nso(tmp_path, compress_text=False)
    handler = NSOHandler()
    image = handler.prepare(str(p), workdir=str(tmp_path))
    text_va = image.image_base
    assert handler.read_bytes(image, text_va, text_va + len(text_plain)) == text_plain


def test_nso_global_entry_points_returns_seeds(tmp_path):
    pytest.importorskip("numpy")
    # A real STP X29,X30,[SP,#-0x10]! prologue (0xa9bf7bfd, little-endian)
    # repeated so the scanner has something real to find.
    prologue = bytes.fromhex("fd7bbfa9")
    text_plain = prologue * 4
    p, *_ = _make_nso(tmp_path, compress_text=False, text_plain=text_plain)
    handler = NSOHandler()
    image = handler.prepare(str(p), workdir=str(tmp_path))
    text_va = image.image_base
    entries = handler.global_entry_points(image, text_va, text_va + len(text_plain))
    assert entries is not None
    assert all(text_va <= ea < text_va + len(text_plain) for ea in entries)


def test_generic_handler_always_matches():
    handler = GenericHandler()
    assert handler.sniff(b"\x00" * 16, "whatever.bin")


def test_registry_detects_pe(tmp_path):
    p = _make_pe(tmp_path)
    handler = formats.detect(str(p))
    assert handler.name == "PE"


def test_registry_detects_nso(tmp_path):
    p, *_ = _make_nso(tmp_path, compress_text=False)
    handler = formats.detect(str(p))
    assert handler.name == "NSO"


def test_registry_falls_back_to_generic(tmp_path):
    p = tmp_path / "mystery.bin"
    p.write_bytes(b"\xDE\xAD\xBE\xEF" * 16)
    handler = formats.detect(str(p))
    assert handler.name == "generic"


def test_list_handlers_includes_builtins_and_generic_last():
    handlers = formats.list_handlers()
    names = [h.name for h in handlers]
    assert "PE" in names
    assert "NSO" in names
    assert names[-1] == "generic"
