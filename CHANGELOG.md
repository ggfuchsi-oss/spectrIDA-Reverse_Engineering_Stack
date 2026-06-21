# Changelog

## 0.2.3 — the ghost installs its own help

0.2.2 fixed the model-file half of "MCP naming needs manual setup." This closes the other half:
llama-server itself.

- `start_all()` now installs llama-server automatically if it's missing entirely -- `winget
  install -e --id ggml.llamacpp` on Windows, `brew install llama.cpp` on macOS -- the same way
  onboarding already leans on winget for Ollama. No separate llama.cpp download, no hunting
  through GitHub release assets for the right build.
- `llama_exe()` also checks winget's own portable-package install location directly, not just
  `PATH` -- a process that just triggered the install wouldn't see a PATH update without
  restarting, since Windows only broadcasts that to processes that start *after* the change.
- Verified end-to-end on a clean (no manually-configured `llama_exe`) run: auto-install, launch,
  health check, and a real naming call all completed successfully against the winget-installed
  binary.

## 0.2.2 — the ghost stops naming things "sub_*"

Found by actually testing the AI naming path end-to-end (not just demangling) for the first time
this release: `[services] llama_model` had no usable default, and the MCP naming pipeline
(`analyze_binary`/`populate_binary`) would silently no-op without it -- no crash, no warning, just
quietly skipping the one feature you'd actually notice missing.

- `llama_model_path()` now falls back to the GGUF Ollama already has on disk for whichever model
  `[ollama] model` names, via `ollama show --modelfile`. Anyone who's done onboarding's
  `ollama pull hf.co/gdfhhjk/spectrida-re-gguf` step already has the real weights sitting in
  Ollama's blob store -- no reason the MCP path needed a second, manually-pointed copy.
- `llama_exe()` now falls back to `llama-server`/`llama-server.exe` on `PATH` if `[services]
  llama_exe` isn't set.
- Still genuinely manual: llama.cpp itself isn't bundled, so if you don't have its `llama-server`
  binary anywhere reachable, you'll need to grab it yourself. The above just means you no longer
  also have to hunt down and hand-configure a second copy of the model file once you do.

## 0.2.1 — the ghost actually reads Switch binaries now

0.2.0's NSO support ran without errors and *looked* like it worked, but a real benchmark exposed
three real bugs that meant it was barely finding anything:

- **Wrong architecture**: IDA has no native NSO loader, so a raw-opened NSO silently fell back to
  `metapc` (x86) — every NSO shard was scanning real AArch64 instructions with an x86 prologue
  matcher and disassembler. Fixed by detecting Switch == AArch64 explicitly instead of trusting
  IDA's auto-detected processor type for a format it doesn't actually support.
- **Missing LZ4 decompression**: NSO `.text`/`.rodata`/`.data` can be LZ4-compressed in the file;
  the pipeline was opening the raw bytes directly with no decompression and no correct base
  address, so even with the right architecture it was sometimes scanning compressed garbage.
  Added a minimal NSO loader (decompress + `idaapi.mem2base` + `idaapi.add_segm`, ported from the
  load-time logic in reswitched/loaders' `nxo64.py`) used by both the shard workers and the merge
  step.
- **Locally-scoped entry points**: each shard was deriving its own seed functions from a scan of
  *only its own narrow byte window*, so any call whose target lived in a different shard never got
  seeded — most calls, in a binary this size. Fixed with one global prologue+call-target scan over
  the whole (decompressed) `.text` up front; each shard now just filters that list to its own
  address range instead of rediscovering entry points blind.
- Skipped FLIRT signature matching during the merge phase (unneeded here, and the single most
  expensive default analysis pass) — worth a modest ~3%. Tried trimming further at first, but the
  flags that actually moved the needle turned out to be the local-variable/stack-frame analysis
  Hex-Rays depends on to decompile anything; disabling those silently zeroed out pseudocode for
  plenty of functions, so that part was reverted.

Net effect on a 74,790-function Switch binary (Mario Odyssey's `main.nso`), 16 workers: end-to-end
parallel-analysis wall time went from a broken 727-function run to a real 197.6s / 74,790 functions,
with decompilation verified working on every function in both this and the existing PE/x86 path.

## 0.2.0 — the ghost learns to talk back (chapter 2)

- **MCP server** (`spectrida mcp`) — Claude (or any MCP client) can search/read/chain through
  every analyzed binary directly: `search_functions`, `get_function` (pseudocode + full
  disassembly + inline callers/callees, for chaining without extra round trips),
  `get_callees`/`get_callers`/`trace_chain`, `get_full_pseudocode`, `rename_function`.
- **`spectrida install mcp`** — registers the server with Claude Code and pi automatically;
  no manual JSON, no separate `pip install` for the `mcp`/`neo4j` extras.
- **Neo4j-backed function graph** (`scripts/populate_graph.py`, or auto-chained from
  `analyze_binary`) — demangles every mangled name (Itanium *and* MSVC, both via IDA's own
  ABI-detecting demangler — previously only Itanium ever reached it), skips tiny thunks, sends
  only genuinely-stripped functions to the model, and now stores disassembly per function too
  (exact instruction boundaries/operands — the layer pseudocode can't give you).
- **`analyze_binary`** — one tool call takes a never-before-seen binary through the whole
  pipeline (parallel analysis → demangle → AI naming → graph), as a background job polled via
  `poll_analysis`/`list_jobs` so a multi-minute run never blocks the conversation. Reports live
  shard progress via MCP progress notifications.
- **NSO support** for the parallel analyzer — previously PE-only; equal-width parallel sharding
  (no PE-style file-zeroing, idalib's own loader handles decompression per worker).
- **`doctor`/`start_all`/`deindex_binary`** — check or boot llama-server + Neo4j from inside the
  conversation; clear out a bad/stale graph run without touching the `.i64`.
- Fixed: a cancelled `analyze_binary` call no longer orphans the analyzer subprocess (and its
  own shard-worker children); the analyzer no longer inherits the MCP transport's stdin pipe
  (a real hang vector specific to running under an MCP server, not standalone).

## 0.1.0 — first ghost

- Parallel sharded IDA analysis (Capstone recursive descent + idalib merge).
- AI function naming via a local Ollama model, streamed token-by-token.
- Terminal UI: virtualized function browser, syntax-highlighted disasm, decompiler view,
  call-chain explorer, inline rename, command palette.
- First-run onboarding wizard (humorous, skippable) that helps set up Ollama + the model.
- Demo mode (`spectrida --demo`) — runs the whole TUI with no IDA/Ollama.
- Config-driven everything (`~/.spectrida/config.toml` + env vars); no hardcoded paths.
