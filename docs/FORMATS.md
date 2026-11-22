# 🧩 Adding a new binary format

Format support is a plugin system, not a pile of if/elif branches — PE, NSO, and ELF are all
just files under `spectrida/analysis/formats/`, discovered automatically. Run `spectrida formats`
to see what's currently registered.

```bash
$ spectrida formats
ELF        spectrida.analysis.formats.elf.ELFHandler
NSO        spectrida.analysis.formats.nso.NSOHandler
PE         spectrida.analysis.formats.pe.PEHandler
generic    spectrida.analysis.formats.generic.GenericHandler
```

A format handler's job is narrow — look at a file and say whether you own it, then describe its
code layout. Everything else (sharding strategy, GPU prologue scanning, merging shards into one
`.i64`) is handled once, generically, outside the format package. NSO is the full example: its
LZ4 decompress + idaapi `mem2base`/`add_segm` logic already lived in `nso_loader.py` (the fix for
the wrong-arch/still-compressed/locally-blind-entry-point bugs from Chapter 2's history) —
`formats/nso.py` is a thin adapter exposing that existing, validated module through the
`FormatHandler` contract, not a rewrite.

**To add a format, drop one new file in `spectrida/analysis/formats/` and nothing else.** No
edits to `parallel_analyze.py`, `shard_worker.py`, or the registry — it's picked up by scanning
the directory for any module exposing a `HANDLER` instance.

```python
# spectrida/analysis/formats/myformat.py
from spectrida.analysis.formats.base import FormatHandler, PreparedImage, Section

class MyFormatHandler(FormatHandler):
    name = "MYFMT"

    @staticmethod
    def sniff(header: bytes, path: str) -> bool:
        return header[:4] == b"MYF0"          # however you recognize the format

    def prepare(self, path: str, workdir: str) -> PreparedImage:
        # Format idalib already loads natively (ELF, PE, Mach-O)? Just parse
        # the section/segment table — return the original path unchanged.
        return PreparedImage(
            binary_path=path,
            image_base=0,
            sections=[Section(name=".text", va=0x1000, raw_off=0x400,
                               raw_size=0x2000, vsize=0x2000, is_code=True)],
            arch=None,        # set "x86_64"/"arm64" only if IDA can't detect it itself
        )

    # Only needed if idalib has NO native loader for this format (NSO is the
    # example): do any manual idaapi/ida_segment setup here, called right
    # after idapro.open_database() succeeds, before analysis starts.
    # def post_open(self) -> None: ...

HANDLER = MyFormatHandler()
```

That's the whole contract:

| Method | Required? | What it does |
|---|---|---|
| `sniff(header, path)` | yes | Magic-byte/extension check — does this handler own the file? |
| `prepare(path, workdir)` | yes | Return a `PreparedImage`: the file idalib should open + its section table |
| `post_open()` | no (default no-op) | Manual segment setup for formats with no native IDA loader (see `nso.py`) |
| `make_shard_binary(image, dst, va_start, va_end)` | no (default works) | Override only if zeroing out-of-shard section bytes is wrong for your format (see `nso.py` — never zero a compressed file) |
| `code_range(image)` | no (default works) | Override only if "min/max of `is_code` sections" isn't the right answer |
| `read_bytes(image, va_start, va_end)` | no (default works) | Override if `prepare()` already holds the relevant bytes in memory (NSO) instead of on disk |
| `global_entry_points(image, text_start, text_end)` | no (default: None) | Only override if a per-shard local scan would miss real entry points — NSO needs this because AArch64 leaf functions are only discoverable via BL targets seen elsewhere in the binary, not a local prologue scan |

Look at `formats/pe.py` for the simplest possible handler (pure header parsing, no overrides) and
`formats/nso.py` for the full case (wraps decompression + manual segment setup + every override).

Third-party packages can register a handler too, without touching spectrIDA's source at all, via
the `spectrida.formats` entry-point group:

```toml
# in a separate package's pyproject.toml
[project.entry-points."spectrida.formats"]
myformat = "spectrida_myformat_plugin:HANDLER"
```

Test coverage for the format system lives in `tests/test_formats.py` — pure Python, no
IDA/idalib required, so it runs in CI.

---

[← back to the README](../README.md) 👻
