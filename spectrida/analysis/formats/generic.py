"""Catch-all handler: anything IDA's own loader chain already understands on
its own (ELF, Mach-O, raw binaries, ...) needs nothing from spectrIDA — hand
the file to idalib unchanged. No section table means the density-shard
partitioner falls back to its existing equal-byte split, and shard_worker's
SEG_DATA masking (already format-agnostic) is what keeps each worker scoped
to its own VA range."""
from __future__ import annotations

from spectrida.analysis.formats.base import FormatHandler, PreparedImage


class GenericHandler(FormatHandler):
    name = "generic"

    @staticmethod
    def sniff(header: bytes, path: str) -> bool:
        return True  # always last in the registry's handler list — the fallback

    def prepare(self, path: str, workdir: str) -> PreparedImage:
        return PreparedImage(binary_path=path)


HANDLER = GenericHandler()
