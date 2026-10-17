"""Phase 3 sources: every library TU preprocessed with `/P` (keeping `#line`), per toolchain.

Each toolchain preprocesses with its own headers (17.8 ships SDK 22621, 17.14 SDK 26100), as a
real build with that toolchain would. Layout under `datasets/phase3/sources/`:

    <toolchain>/<library>/<tu>.i      preprocessed text
    <toolchain>/manifest.json         [{library, tu, path, program}]
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from simulacra.compile import CompileService
from simulacra.data.corpus import DEFAULT_CORPUS_DIR, _library_files, fetch, load_specs
from simulacra.data.cparse import function_definitions

SOURCES_DIR = Path("datasets/phase3/sources")
PREPROCESS = ("/nologo", "/P", "/D_CRT_SECURE_NO_WARNINGS", "/TC")


@dataclass(frozen=True)
class SourceTU:
    toolchain: str
    library: str
    tu: str  # file name within the library, e.g. "adler32.c"
    path: Path
    program: bool  # defines main(): a program, not library code linked into the DLL

    @property
    def id(self) -> str:
        return f"{self.library}/{self.tu}"

    def text(self) -> str:
        return self.path.read_text(encoding="utf-8")


def build_sources(
    service: CompileService,
    toolchains: Iterable[str],
    libraries: Iterable[str] | None = None,
    root: Path = SOURCES_DIR,
    downloads: Path = DEFAULT_CORPUS_DIR / "_downloads",
) -> list[SourceTU]:
    wanted = set(libraries) if libraries else None
    out: list[SourceTU] = []
    for tc in toolchains:
        manifest_path = root / tc / "manifest.json"
        known = {}
        if manifest_path.exists():
            for e in json.loads(manifest_path.read_text(encoding="utf-8")):
                known[(e["library"], e["tu"])] = e
        entries = []
        for spec in load_specs():
            if wanted is not None and spec.name not in wanted:
                continue
            files, tus = _library_files(spec, fetch(spec, downloads))
            lib_dir = root / tc / spec.name
            lib_dir.mkdir(parents=True, exist_ok=True)
            for tu in tus:
                dest = lib_dir / (tu[:-2] + ".i")
                if not dest.exists():
                    args = [*PREPROCESS, *(f"/I{i}" for i in spec.include)]
                    args += [f"/D{d}" for d in spec.defines] + ["/Fipre.i", tu]
                    res = service.run_raw(files, args, "pre.i", tc)
                    if not res.ok:
                        raise RuntimeError(f"preprocessing {spec.name}/{tu} ({tc}):\n{res.stdout}")
                    dest.write_bytes(res.obj.replace(b"\r\n", b"\n"))
                prev = known.get((spec.name, tu))
                program = (
                    bool(prev["program"])
                    if prev
                    else any(
                        d.name == "main" for d in function_definitions(dest.read_text("utf-8"))
                    )
                )
                entries.append(
                    {"library": spec.name, "tu": tu, "path": dest.name, "program": program}
                )
                out.append(SourceTU(tc, spec.name, tu, dest, program))
        merged = {(e["library"], e["tu"]): e for e in [*known.values(), *entries]}
        manifest_path.write_text(json.dumps(list(merged.values()), indent=1), encoding="utf-8")
    return out


def load_sources(toolchain: str, root: Path = SOURCES_DIR) -> list[SourceTU]:
    manifest = json.loads((root / toolchain / "manifest.json").read_text(encoding="utf-8"))
    return [
        SourceTU(
            toolchain,
            e["library"],
            e["tu"],
            root / toolchain / e["library"] / e["path"],
            bool(e["program"]),
        )
        for e in manifest
    ]
