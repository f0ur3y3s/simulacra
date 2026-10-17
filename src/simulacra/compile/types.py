from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

# Always passed to cl.exe; /Z7 instead of /Zi avoids mspdbsrv under Wine.
BASE_FLAGS: tuple[str, ...] = ("/nologo", "/c", "/Gy", "/Z7", "/Brepro")

SOURCE_NAME = "src.c"
CONTEXT_NAME = "ctx.h"
OBJ_NAME = "src.obj"


@dataclass(frozen=True)
class CompileRequest:
    source: str
    context_header: str = ""
    function_name: str = ""  # informational; does not affect the object or the cache key
    toolchain_id: str = ""
    flags: tuple[str, ...] = ()
    language: str = "c"  # "c" -> /TC, "cpp" -> /TP
    timeout: float = 20.0

    def cache_key(self, toolchain_id: str) -> str:
        payload = json.dumps(
            {
                "source": self.source,
                "context": self.context_header,
                "toolchain": toolchain_id,
                "flags": list(self.flags),
                "language": self.language,
                "base": list(BASE_FLAGS),
            },
            sort_keys=True,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def cl_args(self) -> list[str]:
        args = [*BASE_FLAGS, "/TC" if self.language == "c" else "/TP"]
        if self.context_header:
            args.append(f"/FI{CONTEXT_NAME}")
        args.extend(self.flags)
        args.append(SOURCE_NAME)
        return args

    def files(self) -> dict[str, str]:
        files = {SOURCE_NAME: self.source}
        if self.context_header:
            files[CONTEXT_NAME] = self.context_header
        return files


@dataclass
class CompileResult:
    ok: bool
    stderr: str  # compiler diagnostics (cl writes them to stdout; both streams merged here)
    obj_bytes: bytes = b""
    elapsed: float = 0.0
    cached: bool = False
    timed_out: bool = False
    extra: dict[str, str] = field(default_factory=dict)


def clean_diagnostics(stdout: str, stderr: str) -> str:
    """Drop cl's echo of the source file name; keep everything else."""
    lines = [ln for ln in stdout.splitlines() if ln.strip() not in (SOURCE_NAME, "")]
    lines += [ln for ln in stderr.splitlines() if ln.strip()]
    return "\n".join(lines)
