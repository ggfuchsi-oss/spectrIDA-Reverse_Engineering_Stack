<div align="center">

# 👻 spectrIDA

**Ghost through binaries.**

Parallel IDA Pro analysis + AI function naming + a terminal that doesn't suck.

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

## What's coming (chapter 2)

- **Deep context naming** — follow call trees N levels deep, feed the full chain to the model.
  A function 3 hops from `encrypt_block` should know it's in the crypto path.
- **Deobfuscation** — TigressVM pattern detection and handler tracing
- **MCP server** — expose spectrIDA as an MCP tool so Claude Code can call it natively

---

## License

MIT. Do whatever you want with it. If it works, cool.
If it doesn't, blame the GGUF quantization.

Built with spite, coffee, and an RTX 4070.
The model has 199 downloads with zero marketing. Each one adds 0.01% to development speed.
(This is not true. But it's close.) 👻
