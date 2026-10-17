# mscmatch — Matching Decompilation for x64 MSVC Binaries

## What this project is

A system that takes a function from an x64 Windows binary built with MSVC and produces C source
that recompiles to the **same machine code**. An LLM agent iterates in a loop — read asm and
decompiler output, write C, compile with the exact MSVC toolchain, diff against the target,
revise — until the function matches or the turn budget runs out.

The project has four products, built in this order:

1. **Harness** — reproducible MSVC compilation under Wine, per-function extraction, normalized
   diffing and scoring. Everything else depends on it.
2. **Toolchain fingerprinter** — recovers compiler version and flags from an unknown binary.
3. **Agent + training pipeline** — the decompile loop, an evaluation set, baselines, and (only if
   baselines justify it) fine-tuning of a local open-weight model.
4. **Whole-program mode** — ingest a directory of binaries (an installed program) and work
   through it function by function, resumably (Phase 6).

Do not start a later phase until the earlier phase's acceptance criteria pass.

## Ground rules for Claude Code

- Language: **Python 3.12**, managed with **uv**. Type hints everywhere; `ruff` + `mypy --strict`
  on `src/`. Tests with `pytest`.
- Host: Debian Linux. MSVC runs under **msvc-wine** inside Docker. Never assume a Windows host
  except in the one-time equivalence check (Phase 1.4).
- Determinism matters more than speed. Any nondeterminism in compile output is a bug.
- Every component is a CLI subcommand (`mscmatch <cmd>`) plus an importable library function.
- Cache aggressively: compile results keyed by `sha256(source + context + toolchain_id + flags)`.
- Do not download or execute binaries from untrusted sources. Training data comes from building
  open-source code ourselves (vcpkg). Target binaries are supplied by the user.
- When a design decision below is marked **OPEN**, ask before choosing.

## Repository layout

```
mscmatch/
  CLAUDE.md
  pyproject.toml
  docker/
    msvc-wine/Dockerfile        # one image per toolchain version, tagged by cl.exe build
  src/mscmatch/
    toolchain/                  # toolchain registry, version ids, flag sets
    compile/                    # compile service (worker pool, cache, sandbox)
    coff/                       # COFF .obj parsing, COMDAT extraction, relocations
    disasm/                     # iced-x86 disassembly + normalization
    score/                      # diff + scoring
    pe/                         # PE parsing: Rich header, load config, CRT signatures
    fingerprint/                # toolchain/flag recovery for unknown binaries
    decomp/                     # Ghidra headless wrapper (pseudo-C, types)
    data/                       # vcpkg build pipeline, dataset extraction, splits
    agent/                      # agent loop, tools, prompt templates, model backends
    train/                      # SFT / repair / GRPO scripts (Unsloth)
    eval/                       # eval runner + reports
    project/                    # whole-program mode: ingest, library ID, scheduler, state store
  tests/
  datasets/                     # gitignored; built artifacts
```

## Phase 1 — Harness

### 1.1 Toolchain containers

- Dockerfile based on msvc-wine that installs a **pinned** MSVC toolset version plus a pinned
  Windows SDK/UCRT version. Image tag = `msvc-<cl build number>-sdk-<version>`.
- Toolchain registry (`toolchain/registry.toml`): id, cl.exe build number (as reported in Rich
  header prodid/build), SDK version, image tag.
- Start with **one** recent VS 2022 toolset. Adding versions must only require a new registry entry
  and image build.

### 1.2 Compile service

- Input: `CompileRequest{source, context_header, function_name, toolchain_id, flags}`.
- Runs `cl.exe /c /Gy /Z7 /Brepro <flags>` inside the container. Use `/Z7` (not `/Zi`) to avoid
  mspdbsrv under Wine.
- Output: `CompileResult{ok, stderr, obj_bytes, elapsed}`.
- Worker pool of long-lived containers (configurable N); per-job timeout (default 20 s); per-job
  temp dir; no network inside containers.
- Content-addressed cache on disk (sqlite index + blob dir).

### 1.3 COFF extraction + normalization

- Parse the .obj (use `pefile`/`lief` or a small custom COFF parser — prefer whichever handles
  COMDAT sections and relocations correctly; write tests either way).
- `extract_function(obj, name) -> FunctionBlob{code, relocs, pdata, xdata}` — locate the COMDAT
  `.text$mn` section for the (mangled or C) symbol.
- Disassemble with **iced-x86** (Intel syntax).
- Normalization rules (each one unit-tested):
  - Replace every relocated operand with a symbolic token from the relocation's target symbol
    (`<sym:foo>`, `<imp:CreateFileW>`, `<str:N>` for `??_C@` literals, `<data:N>` for anonymous data).
  - Rewrite RIP-relative displacements and call/jmp rel32 targets into those tokens.
  - Rewrite intra-function branch targets as instruction-index labels.
  - Strip trailing `int3`/`nop` padding.
  - Optionally keep or drop `.pdata/.xdata` comparison (flag, default: compare unwind codes only).
- Same normalization must apply to functions extracted from a **linked PE** (Phase 2 targets),
  where relocations are absent: use the PE's base relocation table, import table, and function
  boundaries from `.pdata` to rebuild equivalent tokens.

### 1.4 Wine equivalence check (one-time per toolchain)

- Script that compiles a fixed corpus (≥1,000 functions) and emits a manifest of
  `sha256(COMDAT code)` per function. The user runs the same script on a real Windows machine
  with the same toolset; `mscmatch verify-toolchain a.json b.json` must report 100 % identical.

### 1.5 Scoring

- `score(target, candidate) -> ScoreReport`:
  - `exact: bool` — normalized instruction streams identical.
  - `distance` — weighted edit distance over instruction tokens: mnemonic mismatch = 1.0,
    operand register-only mismatch = 0.3, other operand mismatch = 0.6, insertion/deletion = 1.0.
  - `score = 1 - distance / max(len(target), len(candidate))`, clamped to [0, 1].
  - `diff_text` — side-by-side aligned diff for the agent, truncated to a configurable size,
    with mismatches marked (`~` regalloc-only, `!` opcode, `+`/`-` insert/delete).
- Reference behaviour against objdiff/asm-differ on a handful of hand-checked examples.

### Phase 1 acceptance

- `mscmatch compile` + `mscmatch diff` round-trip: compiling a function's original source with the
  original flags scores `exact=True` for ≥99 % of a 1,000-function sample.
- Equivalence check script exists and passes on the user's Windows machine.
- Throughput reported (compiles/sec at N workers).

## Phase 2 — Toolchain fingerprinter

`mscmatch fingerprint <binary>` outputs ranked candidate `(toolchain_id, flags)` with evidence.

0. **Producer check** — decide whether the image is MSVC output at all before ranking anything:
   Rich header, MSVC-only debug directory entries (`VC_FEATURE`/`POGO`), linker version, CRT
   signature matches, versus GNU ld / lld markers (linker version, GNU/LLVM runtime DLLs, kept
   COFF symbols, DWARF sections, nop padding). When the image is confidently MinGW GCC or
   clang/lld, report that and return no candidates (CLI exit code 3).
1. **Version evidence**
   - Rich header: decode prodid/build entries; map to toolchain registry.
   - PE optional header linker version.
   - Statically linked CRT functions: signature-match against per-toolset signatures we generate
     by building CRT-using test programs with each registered toolchain.
   - If a PDB is supplied: read compiland command lines (exact flags; short-circuits step 2).
2. **Flag evidence** (heuristics, each reported separately):
   - `/GS`: calls to `__security_check_cookie`.
   - `/guard:cf`: `__guard_dispatch_icall`/`__guard_check_icall`, GFIDS in load config.
   - `/Qspectre`: `lfence` after bounds checks.
   - `/arch:AVX*`: VEX-encoded instructions.
   - `/EHsc`: C++ EH handlers in `.xdata`.
   - Optimization level: `/Od` (home-space spills, no reg reuse), `/O1` (`rep stos`, low inlining),
     `/O2` (inlining, unrolling).
   - `/GL` (LTCG) suspicion: internal functions with non-standard register conventions.
     Flag the binary as LTCG and warn that per-function matching will be degraded.
3. **Anchor confirmation**
   - Select 20–50 small, simple functions. Obtain C for them (agent or user-provided), compile
     under each candidate configuration, and rank configurations by exact-match count, then mean
     score.
   - Support per-object differences: candidates may be assigned per address range when Rich header
     entries show multiple compilers (e.g., prebuilt static libs).

### Phase 2 acceptance

- On 20 held-out binaries we built ourselves with known configs (Rich header intact and stripped),
  top-1 config is correct for ≥90 %, top-3 for ≥98 %.

## Phase 3 — Data pipeline

1. Build vcpkg C ports (start with C-only libraries; maintain an allowlist) with each registered
   toolchain × flag set from `toolchain/flagsets.toml` (initially: `/O2`, `/O1`, `/Od`, each with
   `/GS` on/off). Capture `/P` preprocessed output for every TU.
2. Per function, extract a record:
   - `target`: normalized disassembly of its COMDAT
   - `pseudo_c`: Ghidra headless decompilation (run on the .obj)
   - `context`: only the types, globals, macros-expanded prototypes the function references —
     computed with libclang over the `/P` output
   - `source`: the original function **plus any static helpers that were inlined into it**
   - `toolchain_id`, `flags`, `library`, `tu`, `size`
3. Filter: drop functions < 3 instructions, generated code, duplicates (hash of normalized target).
4. Split **by library** into train/val/test. Test set = ~200–500 functions sampled across size
   buckets; never trained on.
5. Repair data generator: apply semantic-preserving perturbations to `source` (reorder independent
   statements, `for`↔`while`, swap signedness/width where valid, split/merge expressions,
   change local declaration order), compile, keep only perturbations that still compile but do
   **not** match. Record `(perturbed, diff) -> source`.
6. Context dropout: for some examples, remove part or all of `context` so the model must declare
   plausible types itself.

Storage: Parquet shards + a manifest; all steps resumable.

## Phase 4 — Agent + baselines

### Agent loop

- Tools exposed to the model:
  - `compile(source)` → errors, or score + diff
  - `get_context(symbol)` → known type/prototype info
  - `try_flags(source, flags)` (only when fingerprint confidence is low)
  - `submit(source)`
- Turn budget (default 12), token budget, and early stop on exact match.
- Final fallback: hand best near-miss (score ≥ 0.9) to a permuter (random source mutations scored
  by the harness) for a bounded time.

### Prompt contents

Toolchain id + flags, normalized target asm, Ghidra pseudo-C, known context, and after turn 1
the previous attempt with its diff. Keep templates in `agent/prompts/` as files, not strings in code.

### Model backends

- Pluggable: Anthropic API, OpenAI-compatible local server (vLLM / llama.cpp server).
- **OPEN**: which frontier model and which local Qwen coder size to baseline. Ask the user.

### Hard rules (enforced by the harness, not the prompt)

Reject, with score 0, any candidate that contains `#pragma optimize`, `__pragma`, `__declspec(naked)`,
byte-emitting intrinsics, or whose exported signature / calling convention differs from the target.

### Phase 4 acceptance

- `mscmatch eval --model <backend>` reports on the test set: compile rate, exact-match rate,
  mean best score, mean turns to match, cost/time per function. Results saved as JSON + a
  Markdown summary.
- Baselines run for one frontier model and one local open model.
- **Stop here and report to the user** before Phase 5. The decision to fine-tune depends on these
  numbers and on whether the target code can be sent to a cloud API.

## Phase 5 — Fine-tuning (only if approved)

Use **Unsloth** with LoRA on a Qwen coder instruct checkpoint (not a base model).

1. **SFT**: single-shot (target + pseudo-C + context) → source.
2. **Repair SFT**: (attempt + diff) → source, from the repair generator.
3. **Expert iteration**: run the SFT model in the agent loop on train-split functions; keep
   trajectories that reach exact match; SFT on those multi-turn trajectories.
4. **GRPO**: reward = `0.1·compiles + 0.6·score + 1.0·exact`, 0 on any hard-rule violation.
   Group size and KL settings in config. The compile service is the reward server; it must handle
   the RL batch throughput.
5. Re-run Phase 4 eval after each stage; keep a results table in `eval/RESULTS.md`.

**OPEN**: whether to also distill from frontier-model trajectories (requires checking the API
provider's terms first). Do not do this without user confirmation.

## Phase 6 — Whole-program mode

Feed in a directory of binaries (an installed program: EXEs plus DLLs) and work through it
function by function, resumably. Depends on Phase 4 (the agent) and uses the Phase 3 dataset for
library identification. Does not depend on Phase 5.

1. **Ingest** — `mscmatch project init <dir> --project <path>`:
   - Find PE files, dedupe by sha256, record version info and the import/export graph between
     them.
   - Producer check and fingerprint every binary (per address range where compilers are mixed).
     Non-MSVC binaries are recorded as skipped; LTCG binaries as degraded.
2. **Inventory and triage** (per binary):
   - Function list (`.pdata`, exports, call targets for leaf functions), call graph, sizes.
   - Skip CRT functions (fingerprint signature DB) and known library code (step 3).
3. **Library identification**:
   - Index the Phase 3 dataset by hash of the anonymized normalized target, per toolchain ×
     flags. An exact, unique hit assigns the function its known source without running the
     agent. Ambiguous hits (several sources, same code) are reported, never guessed.
4. **Scheduler**:
   - Work bottom-up over each call graph (callees before callers, so recovered prototypes and
     types reach the callers), smaller functions first within a level.
   - Early exact matches double as anchors: re-run fingerprint confirmation (and range
     assignment) as they accumulate.
   - Budgets per function, per binary and per project (turns, tokens, cost), with stop rules.
5. **Shared context** per binary: prototypes, struct definitions and globals recovered from
   matched functions plus Ghidra types, versioned, served to the agent by `get_context`.
6. **State**: a sqlite project store holding binaries, functions, attempts (source, score, diff,
   model, cost) and a status per function: `pending`, `library`, `exact`, `near` (best score
   ≥ 0.9), `failed`, `skipped`. Every step is resumable; killing the process loses at most the
   attempts in flight.
7. **CLI**: `project status`, `project step [-n N]`, `project next`, `project run --budget …`,
   `project retry <fn>`, `project show <fn>`, `project export` (a source tree per binary:
   matched functions grouped into TUs by address/link order, placeholders for the rest).

Non-goals: relinking byte-identical whole binaries (data layout, TU boundaries, link order);
C++ until the per-function agent handles it.

### Phase 6 acceptance

- On a held-out multi-binary program we build ourselves: at least 5 MSVC EXEs/DLLs with mixed
  configurations, statically linked vcpkg libraries plus unique code, and one non-MSVC binary.
  - The non-MSVC binary is refused; every MSVC binary (and range) gets its true config top-1.
  - Library identification precision ≥ 99 % (no wrong source ever assigned); recall reported.
  - A run killed and resumed reaches the same final state as an uninterrupted run.
  - Report exact-match rate per binary, functions handled by library ID vs. agent, total cost.
- Then one real MSVC-built open-source program. **OPEN**: which program; ask the user.

## Known hard cases (do not over-optimize for these early)

- LTCG/`/GL` binaries: cross-TU inlining and custom calling conventions.
- Register allocation and stack-slot ordering near-misses — permuter territory.
- C++ (name mangling, EH, templates) — out of scope until C works.
- Toolsets older than VS 2017 may not be installable via msvc-wine; they'd need files copied
  from a Windows install.
