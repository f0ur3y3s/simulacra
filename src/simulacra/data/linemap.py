"""Origins and pragma state in MSVC `/P` output (preprocessed text that keeps `#line` markers)."""

from __future__ import annotations

import bisect
import re
from dataclasses import dataclass

_LINE = re.compile(rb'^[ \t]*#line[ \t]+(\d+)[ \t]+"((?:[^"\\]|\\.)*)"', re.M)
_DIRECTIVE = re.compile(rb"^[ \t]*#(?:line|pragma)\b[^\n]*\n?", re.M)
_PACK = re.compile(
    rb"(?:^[ \t]*#pragma[ \t]+pack|__pragma[ \t]*\([ \t]*pack)[ \t]*\(([^)]*)\)", re.M
)

DEFAULT_PACK = 16  # MSVC x64 default; `#pragma pack()` restores it
TOOLCHAIN_ROOT = "/opt/msvc/"


@dataclass(frozen=True)
class LineMap:
    offsets: list[int]  # byte offset where each `#line` region starts
    files: list[str]

    @staticmethod
    def build(raw: bytes) -> LineMap:
        offs, files = [], []
        for m in _LINE.finditer(raw):
            offs.append(m.end())
            files.append(m.group(2).decode("utf-8", "replace").replace("\\\\", "/"))
        return LineMap(offs, files)

    def file_at(self, offset: int) -> str:
        i = bisect.bisect_right(self.offsets, offset) - 1
        return self.files[i] if i >= 0 else ""

    def is_library(self, offset: int) -> bool:
        """Library-owned code is anything not under the toolchain's own tree (MSVC + SDK
        headers live in /opt/msvc inside the container); generated headers count as library."""
        f = self.file_at(offset).replace("\\", "/").lower()
        return bool(f) and TOOLCHAIN_ROOT not in f


@dataclass(frozen=True)
class PackMap:
    """`#pragma pack` value in effect at each offset (None = the compiler default)."""

    offsets: list[int]
    values: list[int | None]

    @staticmethod
    def build(raw: bytes) -> PackMap:
        stack: list[int | None] = []
        current: int | None = None
        offs: list[int] = [0]
        vals: list[int | None] = [None]
        for m in _PACK.finditer(raw):
            args = [
                a.strip() for a in m.group(1).decode("ascii", "replace").split(",") if a.strip()
            ]
            nums = [int(a) for a in args if a.isdigit()]
            if args and args[0] == "push":
                stack.append(current)
                if nums:
                    current = nums[-1]
            elif args and args[0] == "pop":
                current = stack.pop() if stack else None
            elif nums:
                current = nums[-1]
            elif not args:
                current = None
            offs.append(m.end())
            vals.append(None if current == DEFAULT_PACK else current)
        return PackMap(offs, vals)

    def at(self, offset: int) -> int | None:
        return self.values[bisect.bisect_right(self.offsets, offset) - 1]


_LINE_DIRECTIVE = re.compile(rb"^[ \t]*#line\b[^\n]*\n?", re.M)


def strip_directives(text: str) -> str:
    """Context declarations: drop `#line` and `#pragma` lines (pack state is re-applied)."""
    return _DIRECTIVE.sub(b"", text.encode("utf-8")).decode("utf-8")


def strip_line_directives(text: str) -> str:
    """Function sources: drop only `#line`; pragmas inside a body (e.g. `#pragma loop`) can
    change code generation and must stay."""
    return _LINE_DIRECTIVE.sub(b"", text.encode("utf-8")).decode("utf-8")
