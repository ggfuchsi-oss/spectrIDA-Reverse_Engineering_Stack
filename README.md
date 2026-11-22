<div align="center">

# 👻 spectrIDA

**Ghost through binaries.**

<sub>*Readers see a README. Reversers see more.*</sub>

IDA Pro, but parallel. Functions named by a local AI. A graph that remembers.
And a ghost that runs the code to see what it really does.

**No cloud. No telemetry. Runs entirely on your machine.**

</div>

```
◈  spectrIDA  ▸  GameAssembly.dll

  ✓ 00  ✓ 01  ✓ 02  ✓ 03  ▸ 04  · 05  · 06  · 07
  ✓ 08  ✓ 09  ✓ 10  ✓ 11  ✓ 12  ✓ 13  ▸ 14  · 15

  14/16 shards  │  141,203 functions found
  ████████████████████████████░░░░  89%  ~4s remaining
```

## Why

IDA's auto-analysis is single-threaded. spectrIDA splits the binary into shards, runs them in
parallel through idalib, and merges them back into one `.i64`.

| binary | before | spectrIDA |
|---|---|---|
| Among Us DLL | ~4 hours | **67 s** |
| Mario Odyssey `main.nso` (74,790 functions) | — | **198 s**, 90% named by demangling alone |

Then [a fine-tuned 8B model](https://huggingface.co/gdfhhjk/spectrida-re-gguf) (Qwen3-8B, runs locally) names the `sub_*` leftovers, so 148,000 nameless functions become
`network_send_packet` and friends overnight. Not perfect, but now you know where to look.

<sub>Measured on a Ryzen 7 5800X3D + RTX 4070. Full tables and the bug horror stories: [docs/NUMBERS.md](docs/NUMBERS.md).</sub>

## Try it

```bash
pip install spectrida
spectrida --demo        # zero setup: no IDA, no Ollama
```

The real thing needs **IDA Pro 9.x** (idalib), **Python 3.10+** and **Ollama**:

```bash
ollama pull hf.co/gdfhhjk/spectrida-re-gguf:latest   # 8.7 GB, go get coffee
spectrida onboard                                    # finds your IDA, sets everything up
spectrida analyze GameAssembly.dll --workers 16
```

## Three chapters

| | what it does | how |
|---|---|---|
| **1 · Read** | fast analysis + AI naming in a terminal UI that doesn't suck | `N` name · `B` batch · `O` overview · `C` call chain · `D` pseudocode |
| **2 · Remember** | a Neo4j graph of everything it figured out + an MCP server, so Claude or [pi](https://pi.dev) can search, chain and rename | `spectrida install mcp` |
| **3 · Run** | [phantomrt](phantomrt/): emulate, live-hook or fuzz a function, and stamp what *actually happens* on the graph | `pip install "spectrida[atlas]"` |

Works on **PE**, **ELF** and Switch **NSO**. Adding a format is one file.

## More

- [docs/USAGE.md](docs/USAGE.md): every command, the keys, the Python API, config, the model
- [docs/CHAPTERS.md](docs/CHAPTERS.md): chapters 2 and 3 in full, and who this is for
- [docs/FORMATS.md](docs/FORMATS.md): write your own format handler
- [docs/NUMBERS.md](docs/NUMBERS.md): every measurement, and how we caught our own fake ones

## License

MIT. Do whatever you want with it. If it works, cool. If it doesn't, blame the GGUF quantization.

Built with spite, coffee, and an RTX 4070. 199 downloads with zero marketing. 👻

<!-- the ghost left something behind. not in the docs. in the source tree, next to phantomrt's tests. -->
<sub><code>52 45 56 45 4e 41 4e 43 45 3a 20 62 69 6e 61 72 79 20 2d 3e 20 73 6f 75 72 63 65 2e 20 32 30 32 37</code></sub>
