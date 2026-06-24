"""Format handler discovery.

Built-ins are found by scanning this package's own directory for modules
that expose a module-level ``HANDLER`` instance — drop a new file in here and
it's picked up, no edits to this file or to parallel_analyze.py/shard_worker.py
needed. Third-party formats register the same way from outside the package
via the ``spectrida.formats`` entry-point group in their own pyproject.toml:

    [project.entry-points."spectrida.formats"]
    elf = "spectrida_elf_plugin:HANDLER"

Detection order is sniff-priority: built-ins first (in directory order),
entry-point handlers next, ``GenericHandler`` always last as the catch-all
for anything IDA's native loader already handles on its own.
"""
from __future__ import annotations

import importlib
import pkgutil
from functools import lru_cache
from pathlib import Path

from spectrida.analysis.formats.base import FormatHandler

_SKIP_MODULES = {"base", "registry", "generic"}
_HEADER_BYTES = 0x1000


@lru_cache(maxsize=1)
def _builtin_handlers() -> list[FormatHandler]:
    handlers: list[FormatHandler] = []
    pkg_dir = Path(__file__).parent
    for info in pkgutil.iter_modules([str(pkg_dir)]):
        if info.name in _SKIP_MODULES:
            continue
        mod = importlib.import_module(f"spectrida.analysis.formats.{info.name}")
        handler = getattr(mod, "HANDLER", None)
        if isinstance(handler, FormatHandler):
            handlers.append(handler)
    return handlers


@lru_cache(maxsize=1)
def _entrypoint_handlers() -> list[FormatHandler]:
    handlers: list[FormatHandler] = []
    try:
        from importlib.metadata import entry_points
    except ImportError:
        return handlers
    try:
        eps = entry_points(group="spectrida.formats")
    except TypeError:
        eps = entry_points().get("spectrida.formats", [])  # py3.9 fallback
    for ep in eps:
        try:
            handler = ep.load()
        except Exception:
            continue
        if isinstance(handler, FormatHandler):
            handlers.append(handler)
    return handlers


@lru_cache(maxsize=1)
def _generic_handler() -> FormatHandler:
    from spectrida.analysis.formats.generic import HANDLER
    return HANDLER


def list_handlers() -> list[FormatHandler]:
    """All registered handlers, built-ins first, generic fallback last."""
    return [*_builtin_handlers(), *_entrypoint_handlers(), _generic_handler()]


def detect(path: str) -> FormatHandler:
    """Return the first handler whose sniff() claims this file."""
    with open(path, "rb") as f:
        header = f.read(_HEADER_BYTES)
    for handler in list_handlers():
        try:
            if handler.sniff(header, path):
                return handler
        except Exception:
            continue
    return _generic_handler()
