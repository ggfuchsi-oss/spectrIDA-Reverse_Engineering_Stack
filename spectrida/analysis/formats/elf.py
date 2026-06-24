"""ELF (Linux executables, .so shared objects) — idalib loads these natively,
so like PE this handler is pure header parsing: walk the section header
table for SHF_ALLOC sections so the generic shard-zeroing/code-range/density
logic in base.py has something to work with. Supports both ELF32 and ELF64.
No decompression, no post_open — included as the reference example for
"how do I add a new format" (see README.md)."""
from __future__ import annotations

import struct

from spectrida.analysis.formats.base import FormatHandler, PreparedImage, Section

_MAGIC = b"\x7fELF"

_SHF_ALLOC = 0x2
_SHF_EXECINSTR = 0x4
_SHT_NOBITS = 8

_EM_386 = 3
_EM_ARM = 40
_EM_X86_64 = 62
_EM_AARCH64 = 183

# "arm32" is a real, distinct value -- NOT a typo for "arm64". There is no
# GPU/Capstone scanner support for 32-bit ARM/Thumb anywhere in this project
# (capstone_scanner.py only builds CS_ARCH_X86 and CS_ARCH_ARM64 instances).
# Reporting it explicitly lets the scan-dispatch code in parallel_analyze.py
# and shard_worker.py skip those scanners cleanly instead of silently
# misrouting 32-bit ARM bytes through the AArch64 decoder (which doesn't
# crash loudly so much as just confidently produce garbage / blow up deep in
# whatever assumption the AArch64 path makes about instruction alignment).
_ARCH_HINTS = {_EM_X86_64: "x86_64", _EM_AARCH64: "arm64", _EM_ARM: "arm32"}


class ELFHandler(FormatHandler):
    name = "ELF"

    @staticmethod
    def sniff(header: bytes, path: str) -> bool:
        return header[:4] == _MAGIC

    def prepare(self, path: str, workdir: str) -> PreparedImage:
        with open(path, "rb") as f:
            data = f.read()
        is64 = data[4] == 2  # EI_CLASS: 1=ELF32, 2=ELF64
        e_machine = struct.unpack_from("<H", data, 18)[0]

        if is64:
            shoff = struct.unpack_from("<Q", data, 40)[0]
            shentsize = struct.unpack_from("<H", data, 58)[0]
            shnum = struct.unpack_from("<H", data, 60)[0]
        else:
            shoff = struct.unpack_from("<I", data, 32)[0]
            shentsize = struct.unpack_from("<H", data, 46)[0]
            shnum = struct.unpack_from("<H", data, 48)[0]

        sections = []
        for i in range(shnum):
            o = shoff + i * shentsize
            if is64:
                sh_type, sh_flags, sh_addr, sh_offset, sh_size = struct.unpack_from("<IQQQQ", data, o + 4)
            else:
                sh_type, sh_flags, sh_addr, sh_offset, sh_size = struct.unpack_from("<IIIII", data, o + 4)
            if not (sh_flags & _SHF_ALLOC):
                continue  # not memory-mapped — irrelevant to sharding/code-range
            raw_size = 0 if sh_type == _SHT_NOBITS else sh_size
            raw_off = 0 if sh_type == _SHT_NOBITS else sh_offset
            is_code = bool(sh_flags & _SHF_EXECINSTR)
            sections.append(Section(name=f"sec{i}", va=sh_addr, raw_off=raw_off, raw_size=raw_size,
                                     vsize=sh_size, is_code=is_code))

        return PreparedImage(
            binary_path=path,
            image_base=0,  # ELF section addresses are already absolute (or PIE-relative-to-0, same thing here)
            sections=sections,
            arch=_ARCH_HINTS.get(e_machine),
        )


HANDLER = ELFHandler()
