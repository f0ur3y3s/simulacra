"""Compile backends: a pool of long-lived msvc-wine containers, or a native cl.exe (Windows)."""

from __future__ import annotations

import atexit
import base64
import json
import os
import queue
import shutil
import subprocess
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

RUNNER = "/usr/local/bin/simulacra-runner"
WORKER_LABEL = "simulacra.worker=1"


@dataclass
class RunOutput:
    ok: bool
    returncode: int
    stdout: str
    stderr: str
    obj: bytes
    elapsed: float
    timed_out: bool
    outputs: dict[str, bytes] = field(default_factory=dict)  # extra requested output files


class Backend(Protocol):
    def run(
        self,
        files: dict[str, str],
        args: list[str],
        obj: str,
        timeout: float,
        outputs: tuple[str, ...] = (),
        binary_files: dict[str, bytes] | None = None,
    ) -> RunOutput: ...

    def close(self) -> None: ...


def docker_cli() -> str:
    return os.environ.get("SIMULACRA_DOCKER", "docker")


class DockerWorker:
    """One container with a persistent wineserver; jobs run via `docker exec`."""

    def __init__(self, image: str, name: str, memory: str = "2g") -> None:
        self.image = image
        self.name = name
        self.memory = memory
        self._start()

    def _start(self) -> None:
        subprocess.run([docker_cli(), "rm", "-f", self.name], capture_output=True, check=False)
        cmd = [
            docker_cli(), "run", "-d", "--rm",
            "--network", "none",
            "--memory", self.memory,
            "--label", WORKER_LABEL,
            "--name", self.name,
            self.image,
        ]  # fmt: skip
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            raise RuntimeError(f"failed to start worker {self.name}: {proc.stderr.strip()}")

    def restart(self) -> None:
        self._start()

    def run(
        self,
        files: dict[str, str],
        args: list[str],
        obj: str,
        timeout: float,
        outputs: tuple[str, ...] = (),
        binary_files: dict[str, bytes] | None = None,
    ) -> RunOutput:
        job = json.dumps(
            {
                "files": files,
                "binary_files": {
                    k: base64.b64encode(v).decode("ascii") for k, v in (binary_files or {}).items()
                },
                "args": args,
                "obj": obj,
                "timeout": timeout,
                "outputs": list(outputs),
            }
        )
        start = time.monotonic()
        try:
            proc = subprocess.run(
                [docker_cli(), "exec", "-i", self.name, "python3", RUNNER],
                input=job.encode("utf-8"),
                capture_output=True,
                timeout=timeout + 30,
                check=False,
            )
        except subprocess.TimeoutExpired:
            self.restart()
            return RunOutput(False, -1, "", "worker hung; restarted", b"", timeout, True)
        if proc.returncode != 0:
            err = proc.stderr.decode("utf-8", "replace")
            self.restart()
            return RunOutput(False, proc.returncode, "", f"runner failed: {err}", b"", 0.0, False)
        r = json.loads(proc.stdout)
        obj_bytes = base64.b64decode(r["obj_b64"]) if r["obj_b64"] else b""
        return RunOutput(
            bool(r["ok"]),
            int(r["returncode"]),
            r["stdout"],
            r["stderr"],
            obj_bytes,
            float(r.get("elapsed", time.monotonic() - start)),
            bool(r["timed_out"]),
            {k: base64.b64decode(v) for k, v in r.get("outputs_b64", {}).items() if v},
        )

    def close(self) -> None:
        subprocess.run([docker_cli(), "rm", "-f", self.name], capture_output=True, check=False)


def prune_workers() -> int:
    """Remove worker containers left behind by killed processes. Returns how many."""
    ids = subprocess.run(
        [docker_cli(), "ps", "-aq", "--filter", f"label={WORKER_LABEL}"],
        capture_output=True, text=True, check=False,
    ).stdout.split()  # fmt: skip
    if ids:
        subprocess.run([docker_cli(), "rm", "-f", *ids], capture_output=True, check=False)
    return len(ids)


class DockerPool:
    """N long-lived workers; `run` blocks until one is free. Safe to call from many threads."""

    def __init__(self, image: str, workers: int = 4, memory: str = "2g") -> None:
        tag = uuid.uuid4().hex[:8]
        self._idle: queue.Queue[DockerWorker] = queue.Queue()
        self._all: list[DockerWorker] = []
        lock = threading.Lock()

        def start(i: int) -> None:
            w = DockerWorker(image, f"simulacra-{tag}-{i}", memory)
            with lock:
                self._all.append(w)
            self._idle.put(w)

        threads = [threading.Thread(target=start, args=(i,)) for i in range(workers)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        if not self._all:
            raise RuntimeError("no compile workers could be started")
        atexit.register(self.close)

    @property
    def size(self) -> int:
        return len(self._all)

    def run(
        self,
        files: dict[str, str],
        args: list[str],
        obj: str,
        timeout: float,
        outputs: tuple[str, ...] = (),
        binary_files: dict[str, bytes] | None = None,
    ) -> RunOutput:
        w = self._idle.get()
        try:
            return w.run(files, args, obj, timeout, outputs, binary_files)
        finally:
            self._idle.put(w)

    def close(self) -> None:
        for w in self._all:
            w.close()
        self._all.clear()


class NativeBackend:
    """Runs a local cl.exe (Windows, inside a vcvars64 prompt); used for the equivalence check."""

    def __init__(self, cl: str | None = None) -> None:
        found = cl or os.environ.get("SIMULACRA_NATIVE_CL") or shutil.which("cl")
        if not found:
            raise RuntimeError("cl.exe not found; run from a VS x64 Native Tools prompt")
        self.cl = found

    @property
    def size(self) -> int:
        return os.cpu_count() or 1

    def run(
        self,
        files: dict[str, str],
        args: list[str],
        obj: str,
        timeout: float,
        outputs: tuple[str, ...] = (),
        binary_files: dict[str, bytes] | None = None,
    ) -> RunOutput:
        with tempfile.TemporaryDirectory(prefix="simulacra-") as d:
            for name, text in files.items():
                path = Path(d, name)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text, encoding="utf-8", newline="\n")
            for name, data in (binary_files or {}).items():
                path = Path(d, name)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            start = time.monotonic()
            try:
                proc = subprocess.run(
                    [self.cl, *args], cwd=d, capture_output=True, timeout=timeout, check=False
                )
            except subprocess.TimeoutExpired:
                return RunOutput(False, -1, "", "timeout", b"", timeout, True)
            elapsed = time.monotonic() - start
            obj_path = Path(d, obj)
            data = obj_path.read_bytes() if proc.returncode == 0 and obj_path.exists() else b""
            extra = {
                n: Path(d, n).read_bytes()
                for n in outputs
                if proc.returncode == 0 and Path(d, n).is_file()
            }
            return RunOutput(
                bool(data),
                proc.returncode,
                proc.stdout.decode("utf-8", "replace"),
                proc.stderr.decode("utf-8", "replace"),
                data,
                elapsed,
                False,
                extra,
            )

    def close(self) -> None:
        pass
