"""Pluggable binary-format support.

Every format spectrIDA can shard/analyze — PE, NSO, whatever comes next — is a
``FormatHandler`` living in this package (or contributed by a third-party
package via the ``spectrida.formats`` entry-point group). Nothing outside this
package knows what a PE section table or an NSO segment looks like.
"""
from __future__ import annotations

from spectrida.analysis.formats.base import FormatHandler, PreparedImage, Section
from spectrida.analysis.formats.registry import detect, list_handlers

__all__ = ["FormatHandler", "PreparedImage", "Section", "detect", "list_handlers"]
