"""Content-addressed compile cache: sqlite index + blob directory."""

from __future__ import annotations

import hashlib
import os
import sqlite3
import threading
import time
from pathlib import Path

from simulacra.compile.types import CompileResult

_SCHEMA = """
CREATE TABLE IF NOT EXISTS results (
    key TEXT PRIMARY KEY,
    ok INTEGER NOT NULL,
    stderr TEXT NOT NULL,
    blob TEXT,
    elapsed REAL NOT NULL,
    created REAL NOT NULL
)
"""


def default_cache_dir() -> Path:
    env = os.environ.get("SIMULACRA_CACHE")
    return Path(env) if env else Path.home() / ".cache" / "simulacra"


class CompileCache:
    def __init__(self, root: Path | None = None) -> None:
        self.root = root or default_cache_dir()
        self.blobs = self.root / "blobs"
        self.blobs.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(self.root / "index.sqlite", check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute(_SCHEMA)
        self._db.commit()

    def _blob_path(self, digest: str) -> Path:
        return self.blobs / digest[:2] / digest

    def get(self, key: str) -> CompileResult | None:
        with self._lock:
            row = self._db.execute(
                "SELECT ok, stderr, blob, elapsed FROM results WHERE key = ?", (key,)
            ).fetchone()
        if row is None:
            return None
        ok, stderr, blob, elapsed = row
        obj = b""
        if blob:
            path = self._blob_path(blob)
            if not path.exists():
                return None
            obj = path.read_bytes()
        return CompileResult(bool(ok), stderr, obj, elapsed, cached=True)

    def put(self, key: str, result: CompileResult) -> None:
        if result.timed_out:
            return  # timeouts are environmental, never cache them
        digest = None
        if result.obj_bytes:
            digest = hashlib.sha256(result.obj_bytes).hexdigest()
            path = self._blob_path(digest)
            if not path.exists():
                path.parent.mkdir(exist_ok=True)
                tmp = path.with_suffix(f".tmp{threading.get_ident()}")
                tmp.write_bytes(result.obj_bytes)
                tmp.replace(path)
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO results VALUES (?, ?, ?, ?, ?, ?)",
                (key, int(result.ok), result.stderr, digest, result.elapsed, time.time()),
            )
            self._db.commit()

    def close(self) -> None:
        with self._lock:
            self._db.close()
