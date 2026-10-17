"""Ghidra headless decompilation (pseudo-C) through the simulacra-ghidra image.

Each call is a one-shot, hardened container: the binary goes in on stdin, one JSON document
comes back on stdout (see docker/ghidra/). Results are cached on disk keyed by the image, the
file name and contents, and the requested function names.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from collections.abc import Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from pathlib import Path

from simulacra.compile.backend import docker_cli
from simulacra.compile.cache import default_cache_dir

GHIDRA_VERSION = "12.1.2"
GHIDRA_IMAGE = f"simulacra-ghidra:{GHIDRA_VERSION}"

# Ghidra parses untrusted input: no network, no capabilities, read-only root, scratch on tmpfs.
HARDENING = (
    "--network", "none",
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges",
    "--read-only",
    "--tmpfs", "/tmp:mode=1777",
    "--tmpfs", "/var/tmp:mode=1777",
    "--tmpfs", "/home/ghidra:uid=10001,gid=10001,mode=0700",
)  # fmt: skip

_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]")
_WARNING = re.compile(r"^\s*/\* WARNING: .*\*/\s*$")


class GhidraError(RuntimeError):
    pass


@dataclass(frozen=True)
class DecompiledFunction:
    name: str
    entry: int  # offset from the image base (0 for objects)
    signature: str
    calling_convention: str
    c: str
    callees: tuple[str, ...] = ()
    error: str = ""

    @property
    def ok(self) -> bool:
        return bool(self.c) and not self.error

    def pseudo_c(self, keep_warnings: bool = False) -> str:
        """Decompiled text, by default without Ghidra's `/* WARNING: ... */` lines."""
        lines = self.c.strip("\n").splitlines()
        if not keep_warnings:
            lines = [ln for ln in lines if not _WARNING.match(ln)]
        return "\n".join(lines).strip("\n") + "\n"


@dataclass
class DecompResult:
    program: str
    format: str
    image_base: int
    functions: list[DecompiledFunction] = field(default_factory=list)
    compiler_spec: str = ""
    cached: bool = False

    def get(self, name: str) -> DecompiledFunction | None:
        for f in self.functions:
            if f.name == name:
                return f
        return None

    def at(self, entry: int) -> DecompiledFunction | None:
        for f in self.functions:
            if f.entry == entry:
                return f
        return None

    def to_json(self) -> str:
        d = asdict(self)
        d.pop("cached")
        return json.dumps(d)


def parse_result(text: str) -> DecompResult:
    d = json.loads(text)
    funcs = [
        DecompiledFunction(
            f["name"],
            int(f["entry"]),
            f.get("signature") or "",
            f.get("calling_convention") or "",
            f.get("c") or "",
            tuple(f.get("callees") or ()),
            f.get("error") or "",
        )
        for f in d["functions"]
    ]
    return DecompResult(
        d["program"], d["format"], int(d["image_base"]), funcs, d.get("compiler_spec", "")
    )


def build_args(image: str = GHIDRA_IMAGE) -> list[str]:
    root = Path(__file__).resolve().parents[3] / "docker" / "ghidra"
    return ["build", "-t", image, "--build-arg", f"GHIDRA_VERSION={GHIDRA_VERSION}", str(root)]


class GhidraDecompiler:
    def __init__(
        self,
        image: str = GHIDRA_IMAGE,
        cache_dir: Path | None = None,
        use_cache: bool = True,
        timeout: float = 900.0,
        memory: str = "4g",
        workers: int = 2,
    ) -> None:
        self.image = image
        self.cache_dir = (cache_dir or default_cache_dir()) / "ghidra"
        self.use_cache = use_cache
        self.timeout = timeout
        self.memory = memory
        self.workers = workers

    def _key(self, data: bytes, filename: str, functions: Sequence[str]) -> str:
        h = hashlib.sha256()
        for part in (self.image, Path(filename).suffix.lower(), *sorted(set(functions))):
            h.update(part.encode() + b"\0")
        h.update(data)
        return h.hexdigest()

    def decompile(self, data: bytes, filename: str, functions: Sequence[str] = ()) -> DecompResult:
        """Decompile `functions` (all non-thunk functions if empty) of one object or image."""
        name = _SAFE_NAME.sub("_", Path(filename).name) or "input.bin"
        key = self._key(data, name, functions)
        path = self.cache_dir / key[:2] / f"{key}.json"
        if self.use_cache and path.exists():
            res = parse_result(path.read_text(encoding="utf-8"))
            res.cached = True
            return res
        cmd = [docker_cli(), "run", "-i", "--rm", *HARDENING, "--memory", self.memory,
               "--label", "simulacra.ghidra=1", self.image, name, *functions]  # fmt: skip
        try:
            proc = subprocess.run(cmd, input=data, capture_output=True, timeout=self.timeout)
        except subprocess.TimeoutExpired as e:
            raise GhidraError(f"ghidra timed out after {self.timeout:.0f}s on {filename}") from e
        if proc.returncode != 0:
            err = proc.stderr.decode("utf-8", "replace")[-4000:]
            raise GhidraError(f"ghidra failed on {filename} (exit {proc.returncode}):\n{err}")
        text = proc.stdout.decode("utf-8")
        res = parse_result(text)
        if self.use_cache:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            tmp.write_text(text, encoding="utf-8")
            tmp.replace(path)
        return res

    def decompile_many(
        self, jobs: Iterable[tuple[bytes, str, Sequence[str]]]
    ) -> list[DecompResult | GhidraError]:
        """Run several decompilations concurrently; failures are returned, not raised."""

        def one(job: tuple[bytes, str, Sequence[str]]) -> DecompResult | GhidraError:
            try:
                return self.decompile(*job)
            except GhidraError as e:
                return e

        with ThreadPoolExecutor(max_workers=self.workers) as ex:
            return list(ex.map(one, jobs))
