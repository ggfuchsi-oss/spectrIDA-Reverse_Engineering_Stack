# The chapters, in full

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

## Chapter 3 — the ghost walks through walls

Chapters 1 and 2 read the binary and remember it. But reading a function tells you what it *is*,
never what it *does* when you pull the trigger. Chapter 3 — [**phantomrt**](https://pypi.org/project/phantomrt/) —
pulls the trigger.

```bash
pip install "spectrida[atlas]"
```

It takes a function spectrIDA already named and does one of three haunted things to it:

- **Emulate** it (Unicorn, no OS, any arch) — the only door that works on binaries you *can't*
  launch, like a Switch `.nso` or an Android `.so`.
- **Live-instrument** it (Frida) — attach to the *running* process and watch real args and return
  values, for the functions emulation can only shrug at because they need real state.
- **Fuzz** it — mutated inputs (seeds you bring, or ones it *carves out of the binary itself*),
  catch the crashes, keep the reproducing input.

Then it stamps the verdict onto the same Neo4j node as `dyn_*` properties, so the agent walking
the graph sees the name **and** the behavior in one place. Six new MCP tools —
`emulate_function`, `hunt_crashes`, `live_trace`, `dynamic_overview`, `risk_functions`,
`learn_vm` — all backing the one graph. The reasoning corner is whatever LLM is driving; phantomrt
just makes sure it has real runtime facts to reason with instead of vibes.

```
spectrIDA (names it)  ─▶  phantomrt (runs it)  ─▶  graph (dyn_status / crash / live args)  ─▶  the agent reasons
```

**And, in the spirit of the NSO horror story above:** the first real bug-hunt honestly found
*nothing* — and the reason was more interesting than a crash would have been. Pointed at a
genuinely old, genuinely vulnerable FreeType, blind fuzzing got zero. Coverage-guided fuzzing then
reported a triumphant **64,000 edges** covered — which was a lie, because the binary was PIE and
ASLR was quietly re-randomizing the addresses every run, so "new coverage" was mostly the loader
shuffling the deck. Disable ASLR, honest number drops to a *real* 727 edges, and it plateaus
there — because every seed was a TrueType font, so the fuzzer was trapped inside one parser and
couldn't structurally mutate its way into the CFF/Type1/BDF code where the bugs actually live. The
fix wasn't a smarter mutator, it was better seeds: the agent fetched real OpenType/Type1/BDF
samples, coverage jumped 727 → 4,013 before a single fuzz iteration, and it explored properly.
Still no crash in the budget — which is the honest state of a 3-minute run on one core versus a
job that normally takes hours. The machinery is real. It caught its *own* fake number instead of
reporting it. That's the whole point.

**Honest ghost disclaimer:** phantomrt is `0.1.0`. Alpha. It's a solid dynamic layer, not a magic
bug oracle — it found planted bugs in a toy target instantly, and on real targets it tells you
honestly when it's stuck (`needs_state`), when a crash is only a *candidate* (go verify the
pointer's actually input-controlled), and when it just needs more time and better seeds. Switch
binaries don't run live — Frida needs something it can launch — so there, emulation is the only
door and it'll say `needs_state` a lot. That's honest, not broken.

It's the heavy extra on purpose (`torch`, `unicorn`, `frida`) — the base `pip install spectrida`
pulls none of it. Source lives in [`phantomrt/`](../phantomrt/); its own ghost-flavored README is
[right there](../phantomrt/README.md).

*The static ghost names your functions. This one makes them confess.* 👻

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

[← back to the README](../README.md) 👻
