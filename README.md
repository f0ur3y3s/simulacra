# simulacra

Matching decompilation for x64 MSVC binaries. See `CLAUDE.md` for the phase plan and
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for how the code is organised.

## Setup

```sh
uv sync                                  # Python 3.12 env with dev tools
uv run simulacra toolchain build          # builds msvc-19.44.35229-sdk-10.0.26100 (~1 GB download)
uv run simulacra corpus                   # fetch + preprocess the fixed C corpus into datasets/corpus
```

The image build downloads MSVC and the Windows SDK from Microsoft via msvc-wine and accepts the
Visual Studio license on your behalf.

Environment knobs: `SIMULACRA_DOCKER` (docker/podman binary), `DOCKER_HOST` (remote engine),
`SIMULACRA_WORKERS` (pool size), `SIMULACRA_CACHE` (cache dir, default `~/.cache/simulacra`),
`SIMULACRA_NATIVE_CL` (cl.exe for `--backend native`).

On Git Bash for Windows, export `MSYS_NO_PATHCONV=1` or MSYS rewrites `/O2` into a path.

## Commands

| command | purpose |
|---|---|
| `simulacra compile src.c -f func --flags "/O2"` | compile, print normalized disassembly of `func` |
| `simulacra disasm file.obj\|file.dll -f func` | normalized disassembly from an object or linked PE (`--list` to enumerate) |
| `simulacra diff target candidate -f func` | score + aligned diff; each side may be `.c`, `.obj` or a PE (`--anonymize` for stripped targets) |
| `simulacra roundtrip --sample 1000 --flags "/O2"` | Phase 1 acceptance (original source must match) |
| `simulacra equiv-manifest -o wine.json` | hash every corpus function's code (1.4) |
| `simulacra verify-toolchain a.json b.json` | compare two manifests; must be 100 % identical |
| `simulacra bench --workers-list 1,4,8` | compile throughput |

Diff markers: `~` register-only difference, `!` opcode, `|` other operand, `-` missing in
candidate, `+` extra in candidate.

### Fingerprinting (Phase 2)

| command | purpose |
|---|---|
| `simulacra fingerprint-db` | build per-toolchain evidence (CRT signatures, Rich lib builds, linker version) from probe images |
| `simulacra fingerprint target.dll [--pdb x.pdb] [--anchors a.jsonl]` | ranked `(toolchain, flags)` candidates with evidence |
| `simulacra fingerprint-eval -n 20` | Phase 2 acceptance on held-out binaries we build (Rich intact + stripped) |
| `simulacra fingerprint target.dll --anchors a.jsonl --ranges auto` | per-address-range configs for binaries mixing compilers (prebuilt libs) |
| `simulacra fingerprint-eval --mixed 8` | mixed-compiler binaries, scored per library |

Anchors are JSONL lines `{"target": "sub_180001234" | "0x1234" | "export", "function": "name",
"source": "...", "context": "..."}`; each is compiled under the top candidates and the
candidates are re-ranked by exact-match count, then mean score.

Known limits: `/Zi` cannot run under Wine (mspdbsrv), so PDB tests use `/Z7`-built PDBs, which
carry compiler builds per compiland but no command line; PDBs from real Windows `/Zi` builds also
carry the command line (`S_ENVBLOCK`), from which the exact flags are taken.

### Dataset (Phase 3)

| command | purpose |
|---|---|
| `simulacra dataset ports [--libraries zstd,expat]` | fetch, patch, configure and preprocess vcpkg ports (allowlist in `data/vcpkg_ports.toml`) |
| `simulacra dataset build [--libraries …] [--toolchains …] [--flagsets …]` | sources → DLL builds → Ghidra → per-function record shards (resumable) |
| `simulacra dataset finalize` | filters, dedup, library split, test sample, context dropout → `datasets/phase3/final/` |
| `simulacra dataset repair [--max-records N]` | repair examples from perturbed sources that compile but no longer match |
| `simulacra dataset stats` | the final manifest |

### Decompilation

| command | purpose |
|---|---|
| `simulacra decomp --build` | build the `simulacra-ghidra:12.1.2` image (pinned, checksum-verified Ghidra) |
| `simulacra decomp file.obj\|file.dll [-f name ...] [--json]` | Ghidra pseudo-C for some or all functions (cached) |

## Wine equivalence check on Windows (1.4)

On a Windows machine with the same toolset (VS 2022 17.14, cl 19.44.35229) installed, copy the
repo **including `datasets/corpus`** (the preprocessed TUs, so headers don't matter), open an
"x64 Native Tools Command Prompt", then:

```bat
uv sync
uv run simulacra equiv-manifest --backend native -o windows.json
uv run simulacra verify-toolchain wine.json windows.json
```

`wine.json` comes from `uv run simulacra equiv-manifest -o wine.json` on the Linux/Docker side.

## Tests

```sh
uv run pytest -m "not docker"   # unit tests, no toolchain needed
uv run pytest -m docker         # integration tests against the image
uv run ruff check src tests && uv run mypy
```
