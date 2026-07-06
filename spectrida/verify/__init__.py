"""SpectrIDA verified decompilation — self-verifying loop.

Lifts named pseudocode into clean compilable C, recompiles it, and checks
against the original function via behavioral (differential emulation).
Only verified-equivalent output is accepted.
"""
