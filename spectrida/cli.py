"""spectrIDA CLI."""
from __future__ import annotations

from pathlib import Path

import typer

app = typer.Typer(add_completion=False, help="Ghost through binaries — parallel IDA analysis + AI naming.")

install_app = typer.Typer(add_completion=False, help="Wire spectrIDA's MCP server into a coding agent.")
app.add_typer(install_app, name="install")


@app.callback(invoke_without_command=True)
def _root(
    ctx: typer.Context,
    demo: bool = typer.Option(False, "--demo", help="Run the TUI on canned data (no IDA/Ollama)."),
    no_onboard: bool = typer.Option(False, "--no-onboard", help="Skip the first-run wizard."),
):
    from spectrida import config
    if not config.onboarded() and not no_onboard:
        from spectrida.onboard import run_onboarding
        run_onboarding()
        if ctx.invoked_subcommand is None:
            demo = True  # first-run bare command → land in the demo
    if ctx.invoked_subcommand is None:
        from spectrida.tui.app import SpectrIDAApp
        SpectrIDAApp(demo=demo).run()


@app.command()
def analyze(
    binary: str = typer.Argument(..., help="Binary to analyze (DLL/EXE/NSO…)."),
    workers: int = typer.Option(None, "-w", "--workers"),
):
    """Run parallel analysis, then open the browser."""
    p = Path(binary).expanduser()
    if not p.exists():
        typer.echo(f"error: not found: {p}", err=True)
        raise typer.Exit(1)
    from spectrida.tui.app import SpectrIDAApp
    SpectrIDAApp(binary=str(p.resolve()), workers=workers).run()


@app.command("open")
def open_(i64: str = typer.Argument(..., help="Path to an .i64 database.")):
    """Open an existing .i64 in the browser."""
    p = Path(i64).expanduser()
    if not p.exists():
        typer.echo(f"error: not found: {p}", err=True)
        raise typer.Exit(1)
    from spectrida.tui.app import SpectrIDAApp
    SpectrIDAApp(i64=str(p.resolve())).run()


@app.command()
def onboard():
    """Re-run the setup wizard, then open the demo."""
    from spectrida.onboard import run_onboarding
    run_onboarding(force=True)
    from spectrida.tui.app import SpectrIDAApp
    SpectrIDAApp(demo=True).run()


@app.command()
def export(
    i64:        str = typer.Argument(..., help="Path to .i64 database."),
    output:     str = typer.Option(None, "-o", "--output", help="Output file (default: <stem>.<fmt>)."),
    fmt:        str = typer.Option("json", "-f", "--format", help="json | csv | idc | symbols"),
    named_only: bool = typer.Option(False, "--named-only", help="Skip sub_* functions."),
):
    """Export all function names + addresses to a file."""
    import asyncio

    from spectrida.api import loading_line, open_i64

    p = Path(i64).expanduser()
    if not p.exists():
        typer.echo(f"error: not found: {p}", err=True); raise typer.Exit(1)

    out = Path(output) if output else p.with_suffix(f".{fmt}")
    typer.echo(loading_line())

    async def _run():
        async with open_i64(str(p)) as db:
            result = await db.export(out, fmt=fmt, named_only=named_only)
            funcs = await db.list_functions()
            n = len(funcs) if not named_only else sum(
                1 for f in funcs if not f["name"].lower().startswith("sub_"))
            typer.echo(f"exported {n:,} functions -> {result}")

    asyncio.run(_run())


@app.command()
def overview(
    i64:     str = typer.Argument(..., help="Path to .i64 database."),
    extra:   list[str] = typer.Option([], "-a", "--addr",
                 help="Extra function addresses to include (hex, repeatable)."),
    sample:  int = typer.Option(120, "-n", "--sample", help="Number of functions to sample."),
):
    """Ask the AI to describe what this binary does."""
    import asyncio

    from spectrida.api import loading_line, open_i64

    p = Path(i64).expanduser()
    if not p.exists():
        typer.echo(f"error: not found: {p}", err=True); raise typer.Exit(1)

    addrs = [int(a, 16) if a.startswith("0x") else int(a, 16) for a in extra]
    typer.echo(loading_line())

    async def _run():
        async with open_i64(str(p)) as db:
            it = await db.overview(sample_size=sample, extra_addresses=addrs or None, stream=True)
            async for tok in it:
                typer.echo(tok, nl=False)
        typer.echo()

    asyncio.run(_run())


@app.command()
def serve():
    """Check Ollama + the model are ready."""
    import asyncio

    from spectrida.config import ollama_model
    from spectrida.core.services import ensure_model_loaded, ensure_ollama, model_present

    async def _check():
        if not await ensure_ollama():
            typer.echo("✗ Ollama not reachable. Install: https://ollama.com/download", err=True)
            raise typer.Exit(1)
        typer.echo("● Ollama up")
        if await model_present():
            await ensure_model_loaded()
            typer.echo(f"● {ollama_model()} ready")
        else:
            typer.echo(f"✗ {ollama_model()} not pulled — ollama pull hf.co/gdfhhjk/spectrida-re-gguf", err=True)

    asyncio.run(_check())


@app.command()
def formats():
    """List registered binary-format handlers (built-in + plugins)."""
    from spectrida.analysis.formats import list_handlers

    for handler in list_handlers():
        typer.echo(f"{handler.name:<10} {handler.__class__.__module__}.{handler.__class__.__qualname__}")


@app.command()
def mcp():
    """Run the MCP server so Claude (or any MCP client) can query indexed
    binaries — search functions, walk callers/callees, pull pseudocode,
    rename, or analyze a fresh binary. Requires the graph populated via
    scripts/populate_graph.py and a [graph] section in config.toml."""
    from spectrida.mcp_server import main as run_mcp
    run_mcp()


@install_app.command("mcp")
def install_mcp():
    """Register spectrIDA's MCP server with Claude Code and/or pi
    automatically — no manual .mcp.json editing, no separate pip step for
    mcp/neo4j. Safe to re-run; restart whichever client(s) you wire up
    afterward (MCP config is read at their startup, not live)."""
    from spectrida.mcp_install import install_mcp as run_install
    run_install()


def main() -> None:
    app()


if __name__ == "__main__":
    main()
