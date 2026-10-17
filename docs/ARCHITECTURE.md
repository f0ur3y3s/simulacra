# mscmatch architecture

mscmatch turns a function from an x64 MSVC binary into C source that recompiles to the **same
machine code**. This document describes how the code is organised, how data flows through it,
and why it is built the way it is. The phase plan and acceptance criteria are in
[`CLAUDE.md`](../CLAUDE.md); commands and setup are in the [README](../README.md).

## Status

| Phase | Component | State |
|---|---|---|
| 1 | Harness: compile service, COFF/PE extraction, normalization, scoring | **Done**, acceptance passed |
| 2 | Toolchain fingerprinter | **Done**, acceptance passed on 3 seeds |
| 3 | Data pipeline (vcpkg builds, Ghidra, dataset records) | Started: Ghidra decompiler image + wrapper done |
| 4 | Agent loop + baselines | Not started (`agent/prompts/` is a placeholder) |
| 5 | Fine-tuning | Not started; needs approval after Phase 4 |

Phase 1 results: the round-trip test was exact for 1000/1000 functions at each of `/O2`,
`/O1 /GS-` and `/Od`. The Wine-vs-native equivalence check matched 11,562/11,562 function hashes
across 6 flag sets, against a stock VS 2022 17.14.42 install (cl 19.44.35229, recorded in both
manifests). Throughput was 1.9 compiles/s with 1 worker and 9.7/s with 12.

Phase 2 results: 3 seeds × 40 evaluations (20 held-out binaries, each with and without the
Rich header). The right config ranked first in 100%, 100% and 95% of cases, 117/120 overall
(target ≥ 90%), and in the top three in 100% (target ≥ 98%). The only misses are one Lua
`/Od /GS-` binary, ranked second behind `/GS` both with and without the Rich header.

## The big picture

Everything is built around one loop: **compile → extract → normalize → score**. The fingerprinter,
the acceptance checks and (later) the agent are all clients of that loop.

```
                      ┌───────────────────── toolchain/registry.toml ─────────────────────┐
                      │  id, cl build, SDK, image tag            (one entry per compiler) │
                      └────────────────────────────────┬──────────────────────────────────┘
                                                       │
  C source + context ──► compile.CompileService ──► .obj ──► coff.extract_function ─┐
     (CompileRequest)     │  cache (sqlite+blobs)                                  │
                          │  DockerPool ── docker exec ──► msvc-wine container     ├─► FunctionBlob
                          │  NativeBackend (Windows cl.exe, equivalence check)     │   (bytes + symbolic
                          └────────────────────────────────────────────────────────┘    relocs + unwind)
  target .exe/.dll ─────────────────────────────────► pe.extract_pe_function ─────┘          │
                                                      (rebuilds relocations)                 ▼
                                                                                 disasm.normalize
                                                                                 (iced-x86 → tokens)
                                                                                             │
                                                                         NormalizedFunction ─┤
                                                                                             ▼
                                                                                   score.score(t, c)
                                                                                 exact / score / diff
```

The key design idea is that **objects and linked images are reduced to the same representation**
(`FunctionBlob`) before anything looks at instructions. A candidate always comes from a
`.obj`, where relocations name their targets. A real target usually comes from a linked PE, where
they don't. Once both are blobs, normalization and scoring never need to know which kind of file
a function came from.

## Repository layout

```
docker/msvc-wine/
  Dockerfile              one image per toolchain (debian:trixie + Wine + msvc-wine + pinned MSVC/SDK)
  mscmatch-runner.py      in-container job runner: JSON job on stdin → JSON result on stdout
docker/ghidra/
  Dockerfile              pinned, checksum-verified Ghidra 12.1.2 on a JDK, non-root
  decompile.sh            entrypoint: binary on stdin → analyzeHeadless → JSON on stdout
  scripts/                MscmatchPrepare.java (pre-analysis options), MscmatchDecompile.java
src/mscmatch/
  cli.py                  `mscmatch <cmd>`: thin argparse layer over the library functions
  harness.py              compile → extract → normalize → score helpers used by CLI and checks
  acceptance.py           Phase 1 checks: round-trip, equivalence manifests, bench
  blob.py                 FunctionBlob, relocations, unwind-info decoding (container-agnostic)
  toolchain/              registry.toml, flagsets.toml, loaders, `docker build` arguments
  compile/                types.py (request/result), backend.py (containers, native), cache.py, service.py
  coff/                   parser.py (COFF + /bigobj), extract.py (COMDAT → FunctionBlob)
  pe/                     image.py (PE32+, Rich, imports, exports, pdata, base relocs, load config),
                          extract.py (function bounds + synthesized relocations)
  disasm/                 normalize.py (iced-x86 decoding and token normalization)
  score/                  score.py (weighted edit distance, alignment, diff text, anonymize)
  fingerprint/            rich.py, db.py, heuristics.py, pdb.py, core.py, evalset.py
  data/                   corpus.toml + corpus.py (pinned sources, preprocessing), cparse.py (libclang)
  decomp/                 ghidra.py: GhidraDecompiler (hardened one-shot runs, disk cache)
  agent/ train/ eval/     reserved for Phases 4–5
tests/                    unit tests (no toolchain) + `-m docker` integration tests
datasets/                 gitignored: corpus, fingerprint DB, reports, built eval binaries
```

`harness.py`, `acceptance.py` and `blob.py` are not in the CLAUDE.md layout. They exist because
the compile → score loop and the shared function representation are used by several packages,
and putting them in any one package would create circular imports.

## Components

### Toolchains (`toolchain/`)

`registry.toml` is the only place a compiler version is defined. Each entry has the `cl.exe`
version and build number, the linker version, the SDK version, and the Docker image tag
(`msvc-<cl version>-sdk-<sdk>`). `build_args()` turns an entry into `docker build` arguments.
`mscmatch toolchain build <id>` builds the image, and the Dockerfile's last step fails unless
`cl` reports exactly the registered version. That check matters because the Visual Studio
download manifest moves under us.

Registered now: `vs2022-17.14` (cl 19.44.35229) and `vs2022-17.8` (cl 19.38.33145). Adding 17.8
took one registry entry and one image build, which is what CLAUDE.md requires.

### Compile service (`compile/`)

```
CompileRequest{source, context_header, function_name, toolchain_id, flags, language, timeout}
        │  cache_key = sha256(source, context, toolchain, flags, language, base flags)
        ▼
CompileService.compile ── cache hit? ──► CompileResult{ok, stderr, obj_bytes, elapsed, cached}
        │ miss
        ▼
Backend.run(files, args, output, timeout, outputs)
   ├─ DockerPool: N DockerWorker containers, a queue of idle workers, one job per worker
   └─ NativeBackend: local cl.exe in a temp dir (Windows only)
```

- **Fixed command line.** `cl /nologo /c /Gy /Z7 /Brepro /TC [/FIctx.h] <flags> src.c`.
  `/Z7` avoids mspdbsrv, which does not work under Wine. `/Brepro` removes timestamps.
  `/Gy` puts every function in its own COMDAT. The context header is force-included (`/FI`) so
  line numbers in error messages point at the agent's source.
- **Workers.** Each worker is a long-lived container started with `--network none --memory 2g`.
  Its main process is a persistent `wineserver`, which keeps a warm compile at about 0.4 s. Jobs
  run through `docker exec … mscmatch-runner`. The runner writes files into a fixed directory
  (`/work/job`) so that paths embedded in the object are the same on every worker. It enforces
  the timeout inside the container by killing the process group. The host adds its own timeout
  and restarts a worker if it hangs. Containers carry the label `mscmatch.worker=1`, and
  `mscmatch toolchain prune` removes ones left behind by killed processes.
- **Cache.** A sqlite index maps the key to (ok, stderr, blob hash). Object bytes are stored by
  sha256 under `blobs/`. Timeouts are never cached. The default location is
  `~/.cache/mscmatch` (override with `MSCMATCH_CACHE`).
- **`run_raw`** runs `cl`/`link` with arbitrary arguments and returns any requested extra
  outputs (`.map`, `.pdb`). It is uncached and is used for preprocessing, building test images
  and fingerprint probes.
- **Determinism** is treated as a correctness property. It is tested directly (the same request
  twice gives byte-identical objects), and indirectly by the round-trip and equivalence checks.

### Object extraction (`coff/`)

`parser.py` is a small custom COFF reader. It handles regular and `/bigobj` headers, long section
names, the relocation-overflow case and section-definition aux records (COMDAT selection and
associated section). A custom reader was chosen over `pefile`/`lief` because COMDAT
associativity and in-place addends are exactly what matter here, and those libraries make them
awkward to reach.

`extract.py` finds the function's code section (preferring the COMDAT `.text$mn`) and lifts it
into a `FunctionBlob`:

- Each relocation becomes a `FunctionReloc` with a kind (`rel32`, `abs64`, `abs32`, `rva32`) and a
  classified `RelocTarget`:
  - `IMP` for `__imp_X`
  - `STR` for `??_C@…` and `$SG…`
  - `CONST` for `__real@` / `__xmm@`
  - `DATA` for section symbols and `$` labels
  - `SELF` for references back into the same function
  - `SYM` for everything else

  The addend is read from the instruction bytes, as MSVC stores it in place.
- The associated `.pdata`/`.xdata` sections are decoded into `RuntimeFunction` entries, including
  chained unwind info and exception handlers.

### PE extraction (`pe/`)

`image.py` parses PE32+: sections, the Rich header, imports (including delay-load), exports,
`.pdata`, `DIR64` base relocations and the load config (security cookie, CFG pointers and flags).

A linked image has no relocations, so `extract.py` **rebuilds them** from the instructions:

| Construct in the image | Becomes |
|---|---|
| RIP-relative operand | `rel32` reloc to whatever the address resolves to |
| `call`/`jmp` rel32 leaving the function | `rel32` reloc to the target function |
| `DIR64` base reloc inside an instruction | `abs64` reloc |
| `disp32` with base/index pointing into this function (switch tables) | `rva32` `SELF` reloc (+ one per table entry) |
| indexed `disp32` pointing into a data section (CRT asm tables) | `rva32` to that data |

Target names come from imports, exports, the load config (`__security_cookie`,
`__guard_dispatch_icall_fptr`) and an optional symbol map. Otherwise names are derived from the
address (`sub_<VA>`, `data_<VA>`). Float constants are rebuilt into the same `__real@<hex>` names
the compiler would use, so they match a candidate's tokens exactly.

Function bounds come from `.pdata`, merging chained fragments, and pdata ranges include trailing
jump tables. Leaf functions have no pdata, so control flow is followed to the last terminator,
then extended over any jump tables found on the way. Exports that point at incremental-link
`jmp` thunks are followed through to the real function.

These rules are validated end to end: the same source built as a `.obj` and as a linked DLL
normalizes identically for every exported function, under `/O2`, `/Od`, `/O1 /GS-` and
`/guard:cf` (`tests/test_integration.py`).

### Normalization (`disasm/normalize.py`)

iced-x86 decodes the code in Intel syntax with stable formatter settings (memory sizes always
shown, `0x` hex, signed displacements). `get_constant_offsets()` gives the exact byte offset of
each displacement and immediate, which is how a relocation at byte *N* is tied to the right
operand. The rules, each with a test in `tests/test_normalize.py`:

| Rule | Example output |
|---|---|
| Relocated operand → symbolic token | `call <sym:strlen>`, `call qword ptr [<imp:CreateFileW>]` |
| Strings / anonymous data numbered by first appearance | `lea rcx, [<str:0>]`, `<data:1>` |
| FP / SIMD constants keep their content-derived name | `mulsd xmm0, qword ptr [<const:__real@3ff8…>]` |
| Branch targets inside the function → instruction-index labels | `je L3` |
| Switch tables rendered as data, with entries as labels | `dd L7` |
| References into the table region | `[rdx+rax*4+<tbl:+0x0>]` |
| Trailing `int3` / `nop` padding removed | |
| Unwind info rendered separately; mode `none`, `codes` (default) or `full` | `PDATA L0..L32`, `@0x4 ALLOC_SMALL 0x28` |

Switch tables are found by a single linear pass. MSVC places tables after the code and
references them with an image-relative `disp32`, so the decoder always reaches the reference
before the table.

### Scoring (`score/score.py`)

`score(target, candidate)` returns a `ScoreReport` with `exact`, `distance`, `score`, `diff_text`
and counts of each mismatch kind.

- **Costs (from CLAUDE.md):** mnemonic mismatch 1.0, register-only operand mismatch 0.3, other
  operand mismatch 0.6, insertion/deletion 1.0. A mismatch is register-only when the operands are
  equal after replacing every register name with a placeholder.
- **Score** = `1 - distance / max(len(target), len(candidate))`, clamped to [0, 1]. `exact`
  requires identical instruction streams and, unless disabled, identical unwind info.
- **Label alignment.** Labels are instruction indices, so one extra instruction would shift
  every later branch target. The edit-distance DP therefore treats labels as wildcards. A second
  pass charges an operand mismatch only where a branch's label disagrees *under the computed
  alignment*. This is how objdiff and asm-differ classify the same cases
  (`tests/test_reference_examples.py`).
- **Speed.** The DP trims the common prefix and suffix and memoizes pair costs on interned
  instruction keys. It is plain Python, O(n·m) on the part that differs.
- **`anonymize()`** renames `<sym:…>`/`<const:…>` tokens by order of first appearance. It is used
  when the target has no symbols; imports keep their names.
- **Diff text** is a side-by-side aligned diff with markers (`~` regalloc-only, `!` opcode,
  `|` operand, `-` missing, `+` extra). Long matching runs are collapsed and the total is capped
  for prompt budgets.

### Fingerprinter (`fingerprint/`)

```
binary ─┬─► rich.summarize ────────────┐
        ├─► linker version (opt. hdr) ─┤
        ├─► db.function_hashes ────────┼─► version scores ─► softmax ─► P(toolchain)
        │    (CRT signature matches)   │                                     │
        ├─► pdb.read_compilands ───────┘ (optional; exact builds/flags)      │
        │                                                                    ▼
        └─► user functions (not CRT) ─► heuristics.analyze_flags ─► P(opt), P(GS), extras, runtime
                                                                             │
                                          core._expand: product of choices ──┤
                                                                             ▼
                                         ranked Candidates (toolchain, flags, prior)
                                                                             │
                     anchors (target fn + C) ─► core.confirm: compile each anchor under the top-k,
                                                rank by (exact count, mean score, prior)
```

- **Per-toolchain DB (`db.py`)** is generated, never hand-written. For each registered toolchain
  we link probe programs (EXE/DLL × `/MT`/`/MD`) that reference about 195 CRT functions. From
  them we record:
  - the linker version and build
  - the compiler builds that appear only through prebuilt CRT objects. These must be ignored:
    17.14's static CRT is built with build 33145, which is 17.8's compiler.
  - hashes of every normalized, anonymized CRT function. Matches unique to one toolchain are
    strong version evidence, and work even when the Rich header has been stripped.
- **Version scoring** adds up linker version match, the user compiler build in the Rich header
  (after excluding library builds), Rich linker build match and unique CRT signature matches.
- **Flag heuristics (`heuristics.py`)** run only on "user" functions, meaning those not matched
  as CRT. Each piece of evidence is reported separately:

  | Flag | Evidence |
  |---|---|
  | `/Od` | prologues store argument registers to their home slots |
  | `/O2` vs `/O1` | multi-byte `nop` loop alignment vs `rep movs`/`stos` |
  | `/GS` | functions that read `__security_cookie`. One such function is ambiguous, since a CRT routine missing from the DB can look the same. |
  | `/guard:cf` | calls through the CFG dispatch pointer, or the CF function table flag (`0x400`). Not `0x100`, which the prebuilt CRT sets anyway. |
  | `/Qspectre` | `lfence` |
  | `/arch:*` | VEX/EVEX instructions; weak if only in one function |
  | `/MT` vs `/MD` | imports from CRT DLLs |
  | `/GL` | LTCG prodids in the Rich header |
- **Rich prodids** were mapped empirically from our own builds. For example `0x104` is Utc C,
  `0x105` Utc C++, `0x108` Utc C LTCG and `0x102` the linker.
- **Anchor confirmation** decides what the heuristics cannot. Selection (`select_anchors`) mixes
  random small, simple functions (good for opt level and toolchain) with up to a third that have
  `/GS` buffers, smallest first. Buffers are found with MSVC's documented rule applied to the
  libclang AST (`cparse.gs_buffer_functions`): a local, non-`static` array larger than 4 bytes
  with more than 2 non-pointer elements, or a struct containing one, plus direct callers that may
  inline such a function. Without these anchors, `/GS` and `/GS-` produce identical code for
  almost every function and can't be told apart.
- **Per-address-range assignment (`assign_ranges`)** handles binaries that mix compilers, such
  as prebuilt static libraries. It builds a matrix of every anchor under the best few configs of
  *every* toolchain, so a compiler the global prior all but rules out still competes. Anchors are
  then walked in address order. A range keeps growing while some config still reproduces every
  anchor in it, and a new range starts when none does. Runs of a single anchor are treated as
  noise and folded into their neighbour, and adjacent ranges with the same best config are
  merged. Boundaries fall halfway between neighbouring anchors. Explicit ranges
  (`--ranges 0x1000-0x8000,...`) skip the segmentation and are ranked as given.
- **PDB (`pdb.py`)** reads MSF 7.0 → DBI module list → per-module `S_COMPILE3` (compiler build,
  language) and `S_ENVBLOCK` (command line). If a PDB has command lines, its flags replace the
  heuristics.
- **Evaluation (`evalset.py`)** builds DLLs from a corpus library's preprocessed TUs with random
  `(toolchain, /O*, /GS, runtime)` configs, exporting functions through a generated `.def`. The
  linker `.map` is used only to locate anchor functions; the fingerprinter never sees it. Each
  binary is evaluated with the Rich header intact and stripped (`rich.strip_rich`).
  `--mixed N` builds DLLs instead whose two libraries come from different toolchains (objects
  from one container, linked in the other's). A binary passes when every library's functions
  fall in ranges assigned that library's true config.

### Decompiler (`decomp/`, `docker/ghidra/`)

Pseudo-C comes from Ghidra headless, following the pattern tiresias uses: the same pinned
Ghidra 12.1.2 release with its sha256 checked at build time, a JDK base (Java post-scripts are
compiled at runtime), and an unprivileged user. Like the MSVC runner, it needs no volume mounts.
The binary goes in on stdin and one JSON document comes out on stdout, so it works the same on
Docker Desktop, remote engines and podman.

- **Per call:** `GhidraDecompiler.decompile(data, filename, functions)` starts one container with
  `--network none --cap-drop ALL --security-opt no-new-privileges --read-only` and tmpfs scratch.
  It returns a `DecompResult` holding `DecompiledFunction`s: name, entry offset, the
  decompiler-recovered signature, calling convention, C text and callees. Results are cached on
  disk, keyed by image, file name/contents and requested functions. `decompile_many` runs
  several in parallel.
- **Forced ABI.** The language and compiler spec are forced to `x86:LE:64:default` / `windows`.
  Ghidra's COFF importer otherwise leaves objects with an unknown convention, and arguments in
  rcx/rdx/r8/r9 disappear.
- **Decompiler Parameter ID** (off by default in Ghidra) is enabled by `MscmatchPrepare.java`. It
  carries parameters across calls within one binary and commits calling conventions. Arguments
  passed straight through to an *external* callee still can't be recovered.
- **Cost:** about 6 s per object and about 15 s for a 188-function DLL; JVM startup is most of it.
- **Why Ghidra over radare2:** r2's own decompilers are much weaker. Its good option, r2ghidra,
  embeds Ghidra's decompiler but runs it on r2's lighter analysis, with worse signature, type
  and switch recovery. r2 starts faster, but that only matters for interactive per-call use,
  and the agent gets pseudo-C precomputed. If latency ever matters, the answer is a persistent
  Ghidra process (as tiresias's ghidra-mcp does), not a different engine.

### Corpus and C parsing (`data/`)

- `corpus.toml` pins source archives by sha256: zlib 1.3.1, Lua 5.4.7, lz4 1.10.0, cJSON 1.7.18
  and miniz 3.0.2. Only source is downloaded, never binaries.
- `corpus.py` reads archive members in memory (nothing is extracted to disk) and preprocesses
  each TU **inside the toolchain container** with `/P /EP`. Preprocessed text is the unit of work
  everywhere: Wine and native Windows compile byte-identical input, so header differences cannot
  hide compiler differences. `--runtime md` builds a `/MD` variant, because `/MD` defines `_DLL`
  and changes how CRT declarations expand.
- `cparse.py` parses MSVC-preprocessed C with libclang (`-fms-compatibility`, MSVC target) to
  find function definitions and GS buffers. clang's extent starts *after* a leading `__inline`,
  so the start is widened back to the declaration boundary (`;`, `}`, a preprocessor line or
  `__pragma(...)`).

### Acceptance checks (`acceptance.py`)

- **Round-trip** (Phase 1 gate). For each function emitted in a TU's object: the source is the
  function's own definition, and the context is the rest of the TU with the definition replaced
  by its prototype. Compiling that candidate must reproduce the whole-TU object's code exactly.
- **Equivalence manifest.** sha256 of every function's code bytes, for every corpus TU under every
  flag set, plus the banner of the `cl.exe` that actually ran. `verify-toolchain` requires the
  two manifests to have identical keys, identical hashes, the same corpus hash and the same
  compiler banner.
- **Bench.** Compiles/s at several worker counts with the cache disabled.

## Key decisions and trade-offs

| Decision | Why | Cost |
|---|---|---|
| Wine + msvc-wine in Docker, not Windows VMs | Linux workers are cheap, scale out, and can be cut off from the network | Wine has to be proven equivalent (1.4); `/Zi` doesn't work |
| One image per toolchain, version asserted at build time | A silently updated manifest can't swap compilers | Each image is about 3 GB |
| Persistent wineserver + `docker exec` per job | Warm compile ≈ 0.4 s vs ≈ 1 s cold | `exec` adds about 0.1 s; a persistent pipe would be faster |
| Fixed job directory | Paths in debug info are the same on every worker → reproducible objects and cache keys | One job per container at a time |
| Custom COFF parser | COMDAT associativity and in-place addends are what matter | Has to be maintained |
| Rebuild relocations for PE targets | One normalizer for both sides; validated against linked DLLs | Address-based guesses (strings, tables) can be wrong; mitigated by anonymize and CRT-specific fixes |
| Instruction-index labels + wildcard alignment | Follows CLAUDE.md; avoids cascading penalties | Two-pass approximation, not a joint optimum |
| Preprocessed TUs as the corpus unit | Header-independent; same input on Wine and Windows | `/MT` and `/MD` variants needed |
| Fingerprint DB generated from probes | Adding a toolchain needs no hand-written knowledge | CRT code not in the probes counts as "user" (mitigated by a large probe and weak-evidence rules) |
| Anchors confirm flags | Heuristics can't separate configs that differ only in a few functions | Costs compiles (about 240 per binary) and needs C for the anchors |
| Ghidra one-shot containers, binary over stdin | No mounts; same on every engine; hardened per run | ~3 s JVM startup per call; cached |

## Known limitations

- **`/Zi` under Wine** fails with `C1902`. PDB command-line parsing is therefore only tested
  through the linker's `S_ENVBLOCK`. Compiler builds per compiland are tested from `/Z7` PDBs.
- **Leaf functions in PE targets** are bounded by following control flow. Unusual layouts, such
  as data after the code that isn't a table, could be mis-bounded.
- **Address heuristics.** An indexed `disp32` that happens to fall inside a data section is
  treated as a table reference. A bare RIP target is called a string if its bytes look printable.
  Both can misfire on unusual code.
- **Switch tables in unlinked objects** decompile badly: their `__ImageBase`-relative table
  relocations aren't applied before linking, so Ghidra treats the dispatch as an indirect call.
  Linked images decompile cleanly, so Phase 3 should take pseudo-C from linked builds.
- **Out of scope for now:** C++ (name mangling, EH, templates), LTCG binaries (only flagged), and
  toolsets older than VS 2017.

## Where the next phases plug in

- **Phase 3 (`data/`, `decomp/`):** vcpkg builds run through `CompileService.run_raw` with
  `outputs=` for `/P` files. Per-function records reuse `split_tu` (source and context),
  `normalize` (target) and `cparse` (context reduction). Pseudo-C comes from
  `decomp.GhidraDecompiler`, preferably run on a linked build of each library.
- **Phase 4 (`agent/`, `eval/`):** the agent's `compile(source)` tool is `harness.score_candidate`.
  `try_flags` is the same call with different flags. Hard rules (no `#pragma optimize`,
  `__pragma`, naked functions, byte-emitting intrinsics, signature changes) belong in the harness
  before compiling, not in the prompt. Model backends: the Anthropic API, and the
  OpenAI-compatible llama.cpp server on bazzite (`qwen3.5-9b`). The frontier model to compare
  against is still to be decided.
- **Phase 5 (`train/`):** the GRPO reward is computed from `ScoreReport`. The compile service is
  the reward server, and its cache and worker count set the RL batch throughput.

## Testing

| Suite | Needs | Covers |
|---|---|---|
| `test_coff.py` (+ `coffbuilder.py`) | nothing | COFF/bigobj parsing, COMDAT and pdata extraction, addends, synthetic objects |
| `test_normalize.py` | nothing | one test per normalization rule |
| `test_score.py`, `test_reference_examples.py` | nothing | cost model, alignment, truncation, objdiff-style cases |
| `test_compile_cache.py`, `test_verify.py` | nothing | cache keys and storage, manifest comparison |
| `test_fingerprint.py` (unit part) | nothing | Rich summary, flag parsing, heuristics, anchor selection, GS rule |
| `test_integration.py`, `test_fingerprint.py` (`-m docker`) | both images | determinism, errors, context, obj ≡ PE normalization, toolchain ID with and without Rich, PDB |
| `test_decomp.py` | Ghidra image (`-m docker`) | result parsing, warning stripping, cache, forced Windows ABI, parameter propagation |

`ruff` and `mypy --strict` cover `src/`. The acceptance runs (`roundtrip`, `equiv-manifest` +
`verify-toolchain`, `fingerprint-eval`) are long-running and write reports to `datasets/reports/`.
