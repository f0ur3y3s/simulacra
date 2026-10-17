# mscmatch

Matching decompilation for x64 MSVC binaries. See `CLAUDE.md` for the phase plan and
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for how the code is organised.

## Setup

```sh
uv sync                                  # Python 3.12 env with dev tools
uv run mscmatch toolchain build          # builds msvc-19.44.35229-sdk-10.0.26100 (~1 GB download)
uv run mscmatch corpus                   # fetch + preprocess the fixed C corpus into datasets/corpus
```

The image build downloads MSVC and the Windows SDK from Microsoft via msvc-wine and accepts the
Visual Studio license on your behalf.

Environment knobs: `MSCMATCH_DOCKER` (docker/podman binary), `DOCKER_HOST` (remote engine),
`MSCMATCH_WORKERS` (pool size), `MSCMATCH_CACHE` (cache dir, default `~/.cache/mscmatch`),
`MSCMATCH_NATIVE_CL` (cl.exe for `--backend native`).

On Git Bash for Windows, export `MSYS_NO_PATHCONV=1` or MSYS rewrites `/O2` into a path.

## Commands

| command | purpose |
|---|---|
| `mscmatch compile src.c -f func --flags "/O2"` | compile, print normalized disassembly of `func` |
| `mscmatch disasm file.obj\|file.dll -f func` | normalized disassembly from an object or linked PE (`--list` to enumerate) |
| `mscmatch diff target candidate -f func` | score + aligned diff; each side may be `.c`, `.obj` or a PE (`--anonymize` for stripped targets) |
| `mscmatch roundtrip --sample 1000 --flags "/O2"` | Phase 1 acceptance (original source must match) |
| `mscmatch equiv-manifest -o wine.json` | hash every corpus function's code (1.4) |
| `mscmatch verify-toolchain a.json b.json` | compare two manifests; must be 100 % identical |
| `mscmatch bench --workers-list 1,4,8` | compile throughput |

Diff markers: `~` register-only difference, `!` opcode, `|` other operand, `-` missing in
candidate, `+` extra in candidate.

### Fingerprinting (Phase 2)

| command | purpose |
|---|---|
| `mscmatch fingerprint-db` | build per-toolchain evidence (CRT signatures, Rich lib builds, linker version) from probe images |
| `mscmatch fingerprint target.dll [--pdb x.pdb] [--anchors a.jsonl]` | ranked `(toolchain, flags)` candidates with evidence |
| `mscmatch fingerprint-eval -n 20` | Phase 2 acceptance on held-out binaries we build (Rich intact + stripped) |

Anchors are JSONL lines `{"target": "sub_180001234" | "0x1234" | "export", "function": "name",
"source": "...", "context": "..."}`; each is compiled under the top candidates and the
candidates are re-ranked by exact-match count, then mean score.

Known limits: `/Zi` cannot run under Wine (mspdbsrv), so PDB tests use `/Z7`-built PDBs, which
carry compiler builds per compiland but no command line; PDBs from real Windows `/Zi` builds also
carry the command line (`S_ENVBLOCK`), from which the exact flags are taken.

### Decompilation

| command | purpose |
|---|---|
| `mscmatch decomp --build` | build the `mscmatch-ghidra:12.1.2` image (pinned, checksum-verified Ghidra) |
| `mscmatch decomp file.obj\|file.dll [-f name ...] [--json]` | Ghidra pseudo-C for some or all functions (cached) |

## Wine equivalence check on Windows (1.4)

On a Windows machine with the same toolset (VS 2022 17.14, cl 19.44.35229) installed, copy the
repo **including `datasets/corpus`** (the preprocessed TUs, so headers don't matter), open an
"x64 Native Tools Command Prompt", then:

```bat
uv sync
uv run mscmatch equiv-manifest --backend native -o windows.json
uv run mscmatch verify-toolchain wine.json windows.json
```

`wine.json` comes from `uv run mscmatch equiv-manifest -o wine.json` on the Linux/Docker side.

## Tests

```sh
uv run pytest -m "not docker"   # unit tests, no toolchain needed
uv run pytest -m docker         # integration tests against the image
uv run ruff check src tests && uv run mypy
```
