"""Fixed C corpus: fetch pinned source archives, preprocess every TU inside the toolchain.

Layout (under datasets/corpus/):
    _downloads/<archive>            verified source archives
    <library>/<tu>.i                preprocessed translation units (/P /EP)
    manifest.json                   [{library, tu, path}] in a stable order
"""

from __future__ import annotations

import fnmatch
import hashlib
import io
import json
import tarfile
import tomllib
import urllib.request
import zipfile
from collections.abc import Iterable
from dataclasses import dataclass
from importlib import resources
from pathlib import Path, PurePosixPath

from simulacra.compile import CompileService
from simulacra.toolchain import DEFAULT_TOOLCHAIN

DEFAULT_CORPUS_DIR = Path("datasets/corpus")
PREPROCESS_FLAGS = ("/nologo", "/P", "/EP", "/D_CRT_SECURE_NO_WARNINGS", "/TC")


@dataclass(frozen=True)
class LibrarySpec:
    name: str
    url: str
    sha256: str
    root: str
    sources: tuple[str, ...]
    include: tuple[str, ...]
    defines: tuple[str, ...] = ()


@dataclass(frozen=True)
class CorpusTU:
    library: str
    tu: str
    path: Path

    @property
    def id(self) -> str:
        return f"{self.library}/{self.tu}"

    def text(self) -> str:
        return self.path.read_text(encoding="utf-8")


def load_specs() -> list[LibrarySpec]:
    text = resources.files(__package__).joinpath("corpus.toml").read_text(encoding="utf-8")
    out = []
    for e in tomllib.loads(text)["library"]:
        out.append(
            LibrarySpec(
                e["name"],
                e["url"],
                e["sha256"],
                e["root"],
                tuple(e["sources"]),
                tuple(e.get("include", ["."])),
                tuple(e.get("defines", [])),
            )
        )
    return out


def fetch(spec: LibrarySpec, dl_dir: Path) -> bytes:
    dl_dir.mkdir(parents=True, exist_ok=True)
    path = dl_dir / PurePosixPath(spec.url).name
    if not path.exists():
        with urllib.request.urlopen(spec.url, timeout=120) as resp:
            data = resp.read()
        path.write_bytes(data)
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != spec.sha256:
        path.unlink()
        raise RuntimeError(f"{spec.name}: sha256 mismatch ({digest} != {spec.sha256})")
    return data


def _archive_members(name: str, data: bytes) -> dict[str, bytes]:
    """Regular files from a .tar.gz or .zip archive (contents only; nothing is extracted)."""
    out: dict[str, bytes] = {}
    if name.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            for info in z.infolist():
                if not info.is_dir():
                    out[info.filename] = z.read(info)
    else:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as t:
            for m in t.getmembers():
                if m.isfile():
                    f = t.extractfile(m)
                    if f is not None:
                        out[m.name] = f.read()
    return out


def _library_files(spec: LibrarySpec, data: bytes) -> tuple[dict[str, str], list[str]]:
    """(all .c/.h files under root keyed by root-relative path, selected TU paths)."""
    members = _archive_members(PurePosixPath(spec.url).name, data)
    prefix = spec.root.rstrip("/") + "/" if spec.root else ""
    files: dict[str, str] = {}
    for name, content in members.items():
        if not name.startswith(prefix) or not name.endswith((".c", ".h")):
            continue
        rel = name[len(prefix) :]
        files[rel] = content.decode("utf-8", "replace")
    tus = sorted(
        rel
        for rel in files
        if "/" not in rel
        and rel.endswith(".c")
        and any(fnmatch.fnmatch(rel, p) for p in spec.sources)
    )
    return files, tus


def build_corpus(
    service: CompileService,
    out_dir: Path = DEFAULT_CORPUS_DIR,
    toolchain_id: str = DEFAULT_TOOLCHAIN,
    libraries: Iterable[str] | None = None,
    extra_flags: tuple[str, ...] = (),
    downloads: Path | None = None,
) -> list[CorpusTU]:
    """Preprocess every TU. `extra_flags` select a variant, e.g. ("/MD",) defines _DLL."""
    wanted = set(libraries) if libraries else None
    entries: list[CorpusTU] = []
    for spec in load_specs():
        if wanted is not None and spec.name not in wanted:
            continue
        files, tus = _library_files(spec, fetch(spec, downloads or out_dir / "_downloads"))
        lib_dir = out_dir / spec.name
        lib_dir.mkdir(parents=True, exist_ok=True)
        for tu in tus:
            dest = lib_dir / (tu[:-2] + ".i")
            if not dest.exists():
                args = [*PREPROCESS_FLAGS, *extra_flags, *(f"/I{i}" for i in spec.include)]
                args += [f"/D{d}" for d in spec.defines]
                args += ["/Fipre.i", tu]
                out = service.run_raw(files, args, "pre.i", toolchain_id)
                if not out.ok:
                    raise RuntimeError(f"preprocessing {spec.name}/{tu} failed:\n{out.stdout}")
                dest.write_bytes(out.obj.replace(b"\r\n", b"\n"))
            entries.append(CorpusTU(spec.name, tu, dest))
    manifest = [{"library": e.library, "tu": e.tu, "path": e.path.name} for e in entries]
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=1), encoding="utf-8")
    return entries


def load_corpus(corpus_dir: Path = DEFAULT_CORPUS_DIR) -> list[CorpusTU]:
    manifest = json.loads((corpus_dir / "manifest.json").read_text(encoding="utf-8"))
    return [
        CorpusTU(e["library"], e["tu"], corpus_dir / e["library"] / e["path"]) for e in manifest
    ]
