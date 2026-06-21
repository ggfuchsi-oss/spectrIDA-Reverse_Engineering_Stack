<div align="center">

# 👻 spectrIDA

**Ghost through binaries.**

A local, AI-powered reverse engineering assistant: parallel IDA Pro analysis, AI function
naming, a terminal that doesn't suck, a Neo4j knowledge graph of everything it's ever figured
out, and an MCP server so Claude can search and chain through that graph directly.

</div>

```
spectrida analyze GameAssembly.dll --workers 16
```

```
◈  spectrIDA  ▸  GameAssembly.dll

  ✓ 00  ✓ 01  ✓ 02  ✓ 03  ▸ 04  · 05  · 06  · 07
  ✓ 08  ✓ 09  ✓ 10  ✓ 11  ✓ 12  ✓ 13  ▸ 14  · 15

  14/16 shards  │  141,203 functions found
  ████████████████████████████░░░░  89%  ~4s remaining
```

---

## What it is

IDA Pro's auto-analysis is single-threaded. On a 34 MB il2cpp DLL that's *minutes*. spectrIDA splits
the binary into N shards, runs them in parallel via idalib, merges into one `.i64`, then lets a
fine-tuned 8B model **name every function** — all from one terminal UI with a cyberpunk theme and
exactly the right amount of sarcasm.

That's Chapter 1, and it stands on its own: pure speed, no AI required if you don't want it.

Chapter 2 turns the output into something that outlives the session — a Neo4j graph an MCP client
(Claude, [pi](https://pi.dev), whatever speaks MCP) can actually live in, instead of you
copy-pasting decompiler output into a chat window one function at a time:

```
Binary  ─▶  Parallel IDA Analysis  ─▶  Demangle  ─▶  AI Naming  ─▶  Neo4j Graph  ─▶  MCP Server  ─▶  Claude
              (N idalib shards)       (free, real)   (stripped     (persists,        (search/chain/
                                                       leftovers     forever,          rename, live)
                                                       only)         across sessions)
```

Full rundown, including what's still on the to-do pile, is down in
[Chapter 2](#chapter-2--the-ghost-learns-to-talk-back).

It is not Ghidra. It does one annoying thing (slow analysis + naming) fast, and it's genuinely fun
to use. **199 downloads speak for themselves.**

**No cloud. No telemetry. Runs entirely on your machine.**

---

## Numbers

| task | time |
|------|------|
| Among Us DLL — single-threaded IDA | ~4 hours |
| Among Us DLL — spectrIDA (16 workers) | **67 seconds** |
| 153,649 function binary — full naming pass | overnight |
| Binary overview (what does this thing do?) | ~30 seconds |

**Hardware these were measured on:** AMD Ryzen 7 5800X3D (8C/16T), 32 GB RAM, RTX 4070 12 GB.
Different hardware moves the parallel-analysis numbers (more cores, more shards, faster); the
naming numbers are mostly GPU-bound. The 4-hour/67-second Among Us figures predate Chapter 2 and
aren't independently re-verified in every release — re-run `spectrida analyze` yourself if you
want a number for your own machine and binary, results vary with shard density and binary size.

Numbers actually re-verified during Chapter 2 development, same hardware:

| binary | functions | task | time / result |
|--------|-----------|------|----------------|
| test_small.dll (PE) | 189 | parallel analysis, 4 workers, CLI | **6.4s** |
| test_small.dll (PE) | 164 | full MCP pipeline (analyze + demangle + graph write) | **9.8s** |
| main.nso — Mario Odyssey (NSO), 16 workers | 28,038 seed functions | parallel sharded scan phase | **54.5s** |
| main.nso — Mario Odyssey (NSO), 16 workers | 74,790 total functions | + merge/full-analysis phase | **143.1s** |
| main.nso — Mario Odyssey (NSO), 16 workers | 74,790 total functions | **end-to-end wall time** | **197.6s** |
| main.nso — Mario Odyssey (NSO) | 74,790 | resolved via demangling alone (Itanium ABI, free, no AI) | 67,300 (90.0%) |

That NSO row is the real equivalent of the old Among Us "4 hours → 67 seconds" claim, measured
fresh this release on a 74,790-function Switch binary, no AI naming involved (demangling only —
`populate=False`). The parallel phase (16 cores, ~55s) does the initial sharded discovery; the
merge phase (~143s) is single-threaded by design — one IDA database, one writer — so if you watch
Task Manager during that part and see 15 cores napping, that's not a bug report, that's physics.

Getting an *honest* number here was its own small horror story. The first version of NSO support
ran clean, exited 0, and proudly returned 727 functions for a binary that has roughly 75,000 of
them — not a crash, just spectacularly, confidently wrong, which is somehow worse. Turns out IDA
has no native NSO loader, so the file silently loaded as plain x86 ("metapc") even though the
Switch has been ARM64 since the box launched. Every shard ran an x86 prologue scanner against pure
AArch64 instructions and called whatever it accidentally matched a "function." Fixing the
architecture fixed nothing on its own, because the binary was *also* still LZ4-compressed in
memory — so half of what got scanned was, generously, noise. And even once it was properly
decompressed and flagged AArch64, each shard was only hunting for call targets inside its own tiny
slice of the binary, missing every call that crossed a shard boundary — which in a binary this
size is most of them. Three bugs, one number, and not one of them had the decency to throw an
exception. (We also tried shaving the merge phase down by skipping IDA's stack-frame analysis —
got a beautiful speedup and a database where Hex-Rays politely refused to decompile half of it.
That got reverted fast. Kept the much smaller, much safer FLIRT-signature skip instead, which is
worth a shrug-worthy ~3% and didn't break anything, which by this point felt like a personality
trait worth keeping.)

**On naming accuracy:** it's not Ghidra-grade ground truth, it's an 8B model guessing from
pseudocode. Generic helpers/getters tend to land well; deeply game-specific logic is more of a
coin flip. Rename anything it gets wrong — that's why `rename_function` persists straight back
into the graph.

---

## Features

- **Parallel sharded analysis** — splits into address-space shards, runs N idalib instances,
  merges into one `.i64`. Workers configurable via flag, config, or env var.
- **AI function naming** — fine-tuned Qwen3-8B runs locally via Ollama, streams names
  token-by-token. Press `N`. Watch it think. Name appears.
- **Batch naming** — `B` to name every `sub_*` function in the list. Walk away. Come back.
- **Binary overview** — press `O` or run `spectrida overview file.i64`. Model reads 120
  sampled function names and tells you what the binary does, what its subsystems are, and
  anything security-relevant. Correctly identified a 153k-function IL2CPP runtime in 30 seconds.
- **Call chain explorer** — `C` shows callers and callees. The model uses these as context
  when naming — a function called by `Player$$TakeDamage` gets named better than one in isolation.
- **Decompiler view** — `D` toggles Hex-Rays pseudocode.
- **Export** — dump everything to JSON, CSV, IDA `.idc` script, or a symbols file.
  The `.idc` applies all AI-generated names back into any IDA install in one click.
- **Programmatic API** — `from spectrida.api import open_i64`. Drive everything from scripts,
  notebooks, or Claude Code without touching the TUI.
- **MCP server** — `spectrida install mcp` wires it straight into Claude Code and/or
  [pi](https://pi.dev), no manual JSON editing. Claude can then search/read/chain through a
  Neo4j-backed function graph (name, pseudocode, disassembly, callers/callees) and kick off a
  fresh analysis on a new binary itself — `analyze_binary` runs the whole pipeline (parallel
  analysis → demangle → AI naming → graph) from one tool call, as a background job it polls.
  Works on PE and NSO. See [Chapter 2](#chapter-2--the-ghost-learns-to-talk-back) below.
- **Demo mode** (`spectrida --demo`) — try the whole thing with **zero setup**. No IDA, no Ollama.
- **A first-run wizard** — helps you install Ollama + the model, detects your IDA install
  automatically, then never asks again.

---

## Install

```bash
pip install spectrida
```

Requirements: **IDA Pro 9.x** with idalib · **Python 3.10+** · **Ollama**

```bash
# install Ollama (Windows)
winget install Ollama.Ollama

# pull the model (8.7 GB — go get coffee)
ollama pull hf.co/gdfhhjk/spectrida-re-gguf:latest

# first run — detects your IDA install and sets everything up
spectrida onboard

# or just try the demo right now
spectrida --demo
```

---

## Commands

```bash
# analyze a binary from scratch
spectrida analyze GameAssembly.dll
spectrida analyze GameAssembly.dll --workers 8    # custom worker count

# open an existing .i64 in the browser
spectrida open file.i64

# ask the AI what this binary is
spectrida overview file.i64
spectrida overview file.i64 --addr 0x10001000 --addr 0x10353fd0  # include specific functions

# export function names
spectrida export file.i64 -f idc           # IDA script — apply names to any install
spectrida export file.i64 -f json          # full dump with addresses + sizes
spectrida export file.i64 -f csv           # spreadsheet
spectrida export file.i64 -f symbols       # addr name pairs
spectrida export file.i64 --named-only     # skip sub_* functions

# check Ollama + model status
spectrida serve

# re-run the setup wizard
spectrida onboard
```

---

## TUI keys

| Key | Action |
|-----|--------|
| `N` | Name selected function — AI streams the result live |
| `R` | Rename — pre-filled with the AI suggestion |
| `D` | Toggle decompiled pseudocode (Hex-Rays) |
| `C` | Call chain — callers and callees |
| `B` | Batch-name all `sub_*` functions in the current list |
| `O` | Overview — AI summary of the whole binary |
| `/` | Fuzzy search |
| `?` | Help |
| `Q` | Quit |

---

## Programmatic API

No TUI needed — drive spectrIDA from scripts, Claude Code, notebooks, whatever:

```python
import asyncio
from spectrida.api import open_i64

async def main():
    async with open_i64("GameAssembly.i64") as db:

        # list all 153k functions
        funcs = await db.list_functions()

        # name one function — returns name + reasoning + confidence
        result = await db.name_function(0x10001000)
        print(result["new_name"])     # init_atexit_handler
        print(result["reasoning"])    # allocates array of 3 fn ptrs, calls _atexit...

        # batch name everything (with live progress)
        async def on_progress(done, total, r):
            print(f"  {done}/{total}  {r['old_name']} -> {r['new_name']}")

        await db.batch_name(limit=500, rename=True, progress_cb=on_progress)

        # ask what the binary does
        overview = await db.overview()
        print(overview)

        # export to IDA script
        await db.export("names.idc", fmt="idc", named_only=True)

asyncio.run(main())
```

---

## The model

[`hf.co/gdfhhjk/spectrida-re-gguf`](https://huggingface.co/gdfhhjk/spectrida-re-gguf) — Qwen3-8B
fine-tuned for reverse engineering.

**Trained on:**
- x86/x64 assembly → function name pairs with call-chain context
- Tool call traces from [`jtsylve/ida-mcp`](https://github.com/jtsylve/ida-mcp) — headless IDA with idalib
- Extended context reasoning traces from a codebase context server

**Training approach:** neuron-targeted SFT + GRPO. Only the RE-relevant neurons are tuned —
base Qwen3 knowledge stays intact, you just added a very specific skill on top.

Runs locally via Ollama. GGUF — works on CPU, GPU, or both.

---

## Who is this for

You're reversing something. You have a binary with 150,000 functions. Maybe 2,000 have names from
metadata. The other 148,000 are `sub_XXXXXXXX`. You want to find the network code.
You can't grep for it because nothing has a name yet.

A human RE can name ~50-100 functions per hour if they're fast. At that rate, 150k functions = **3 years**.

spectrIDA names them overnight. Not perfectly — maybe 70% accuracy on generic functions,
much higher on patterns the model recognizes. But now instead of 148k `sub_` functions you have
`network_send_packet`, `serialize_player_state`, `validate_checksum` — and you know where to look.

It doesn't replace a skilled reverse engineer. It does the boring 80% so you can focus on the
interesting 20%. It's the orientation layer.

**Real use cases:**
- Game modding — find the physics system in a 150k-function binary in minutes, not days
- Security research — malware triage, understand a binary's architecture quickly
- CTF — time pressure, need to know what you're looking at immediately
- Anyone who has stared at `sub_140001234` for 20 minutes thinking *there has to be a better way*

---

## Configuration

`~/.spectrida/config.toml`:

```toml
[ida]
idalib = "C:/Program Files/IDA Professional 9.1"
output_dir = "~/.spectrida/output"

[ollama]
base_url = "http://localhost:11434"
model = "spectrida-re"   # any ollama model name works

[pipeline]
workers = 16
```

Env var overrides: `SPECTRIDA_IDALIB` · `SPECTRIDA_MODEL` · `SPECTRIDA_WORKERS` · `SPECTRIDA_OLLAMA_URL`

---

## Chapter 2 — the ghost learns to talk back

Chapter 1 was a faster, funnier IDA. Chapter 2 is spectrIDA as a teammate: a persistent,
queryable knowledge graph of every function it's ever named, and an MCP server so Claude (or
any MCP client — [pi](https://pi.dev) works too) can search and reason through it directly,
instead of you copy-pasting decompiler output into a chat window.

```bash
spectrida install mcp
```

That's it. It registers the server with Claude Code and pi automatically (pulling in `mcp` +
`neo4j` if a bare `pip install spectrida` skipped them), writes their config, and tells you
which restart you owe it.

**What Claude actually gets, once Neo4j is running (`spectrida` config `[graph]` section,
or just point it at a local instance):**

- `search_functions` / `get_function` / `get_callees` / `get_callers` / `trace_chain` — fast,
  cached graph reads. `get_function` returns pseudocode **and** disassembly (exact instruction
  boundaries and operands — the layer pseudocode can't give you, which matters the moment you
  go from "what does this do" to "where exactly would I patch this") plus inline
  callers/callees, so Claude decides whether to chain deeper by looking at whether a callee is
  still `sub_*` right there in the response — no extra round trip just to find out there's
  nothing more to see.
- `get_full_pseudocode` / `rename_function` — live, authoritative reads/writes straight to the
  `.i64` when the cached snippet isn't enough or a name is finally figured out.
- `analyze_binary` — hand it a binary it's never seen (PE or NSO, parallel-sharded either way)
  and it runs the whole pipeline — analyze → demangle (Itanium *and* MSVC) → AI-name the
  genuinely stripped leftovers → push it all into the graph — as one background job you poll,
  so a multi-minute run never blocks the conversation.
- `doctor` / `start_all` — check or boot llama-server + Neo4j without leaving the chat.
  If llama-server itself isn't installed anywhere, `start_all` grabs it via winget (Windows) or
  brew (macOS) first — no separate llama.cpp download/setup needed.

It's not magic — a function that's still `sub_140001234` because nobody's looked at it yet is
still `sub_140001234`. But the graph remembers everything the model *has* figured out, forever,
across sessions, and Claude can walk it like a colleague who already read the codebase instead
of staring at one function at a time.

**Still coming:**

- **Deep context naming** — follow call trees N levels deep, feed the full chain to the model.
  A function 3 hops from `encrypt_block` should know it's in the crypto path.
- **Deobfuscation** — TigressVM pattern detection and handler tracing
- **Actual patching** — the disassembly is in the graph now so an agent *can* plan a byte-level
  patch; turning "here's the exact instruction to change" into "and here's the write" is next.

---

## License

MIT. Do whatever you want with it. If it works, cool.
If it doesn't, blame the GGUF quantization.

Built with spite, coffee, and an RTX 4070.
The model has 199 downloads with zero marketing. Each one adds 0.01% to development speed.
(This is not true. But it's close.) 👻
