"""Compile service: request -> cached result, backed by a worker pool."""

from __future__ import annotations

import os
import threading
from collections.abc import Iterable, Iterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from mscmatch.compile.backend import Backend, DockerPool, NativeBackend, RunOutput
from mscmatch.compile.cache import CompileCache
from mscmatch.compile.types import OBJ_NAME, CompileRequest, CompileResult, clean_diagnostics
from mscmatch.toolchain import DEFAULT_TOOLCHAIN, get_toolchain


def default_workers() -> int:
    env = os.environ.get("MSCMATCH_WORKERS")
    return int(env) if env else max(1, (os.cpu_count() or 2) // 2)


class CompileService:
    """Compiles `CompileRequest`s for one or more toolchains.

    Backends are created lazily per toolchain. `backend="native"` uses a local cl.exe for every
    toolchain id (the caller is responsible for that cl.exe being the right version).
    """

    def __init__(
        self,
        workers: int | None = None,
        cache: CompileCache | bool | None = True,
        backend: str = "docker",
        cache_dir: Path | None = None,
    ) -> None:
        self.workers = workers or default_workers()
        self.backend_kind = backend
        if cache is True:
            self.cache: CompileCache | None = CompileCache(cache_dir)
        elif cache is False or cache is None:
            self.cache = None
        else:
            self.cache = cache
        self._backends: dict[str, Backend] = {}
        self._lock = threading.Lock()

    def _backend(self, toolchain_id: str) -> Backend:
        with self._lock:
            if toolchain_id not in self._backends:
                if self.backend_kind == "native":
                    self._backends[toolchain_id] = NativeBackend()
                else:
                    tc = get_toolchain(toolchain_id)
                    self._backends[toolchain_id] = DockerPool(tc.image, self.workers)
            return self._backends[toolchain_id]

    def compile(self, req: CompileRequest) -> CompileResult:
        tcid = req.toolchain_id or DEFAULT_TOOLCHAIN
        key = req.cache_key(tcid)
        if self.cache is not None:
            hit = self.cache.get(key)
            if hit is not None:
                return hit
        out = self._backend(tcid).run(req.files(), req.cl_args(), OBJ_NAME, req.timeout)
        diag = clean_diagnostics(out.stdout, out.stderr)
        if out.timed_out:
            diag = (diag + f"\n<timeout after {req.timeout:.0f}s>").strip()
        result = CompileResult(out.ok, diag, out.obj, out.elapsed, timed_out=out.timed_out)
        if self.cache is not None:
            self.cache.put(key, result)
        return result

    def run_raw(
        self,
        files: dict[str, str],
        args: list[str],
        output: str,
        toolchain_id: str = DEFAULT_TOOLCHAIN,
        timeout: float = 120.0,
        outputs: tuple[str, ...] = (),
        binary_files: dict[str, bytes] | None = None,
    ) -> RunOutput:
        """Run cl.exe with arbitrary arguments (preprocessing, linking test images). Uncached."""
        return self._backend(toolchain_id).run(files, args, output, timeout, outputs, binary_files)

    def compile_many(self, reqs: Iterable[CompileRequest]) -> Iterator[CompileResult]:
        """Compile concurrently; yields results in request order."""
        with ThreadPoolExecutor(max_workers=self.workers) as ex:
            yield from ex.map(self.compile, reqs)

    def close(self) -> None:
        for b in self._backends.values():
            b.close()
        self._backends.clear()
        if self.cache is not None:
            self.cache.close()

    def __enter__(self) -> CompileService:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def compile_source(
    source: str,
    flags: Iterable[str] = (),
    context_header: str = "",
    toolchain_id: str = DEFAULT_TOOLCHAIN,
    service: CompileService | None = None,
) -> CompileResult:
    """One-shot convenience wrapper."""
    req = CompileRequest(source, context_header, "", toolchain_id, tuple(flags))
    if service is not None:
        return service.compile(req)
    with CompileService(workers=1) as svc:
        return svc.compile(req)
