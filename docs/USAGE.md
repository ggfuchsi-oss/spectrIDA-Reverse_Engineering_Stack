# 🛠 Using spectrIDA

Everything the README skips: every command, every key, the Python API, config, and the model.

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

[← back to the README](../README.md) 👻
