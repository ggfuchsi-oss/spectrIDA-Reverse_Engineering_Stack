# 📊 Numbers — and how we got honest ones

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

[← back to the README](../README.md) 👻
