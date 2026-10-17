"""libclang helpers over MSVC-preprocessed C (/P /EP output)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import cache

import clang.cindex as ci

CLANG_ARGS = (
    "-x", "c",
    "--target=x86_64-pc-windows-msvc",
    "-fms-extensions",
    "-fms-compatibility",
    "-fms-compatibility-version=19.44",
    "-nostdinc",
    "-w",
)  # fmt: skip

_VIRTUAL_NAME = "src.c"


@dataclass(frozen=True)
class FuncDef:
    name: str
    start: int  # byte offsets into the UTF-8 encoded text
    body_start: int
    end: int
    is_static: bool
    prototyped: bool  # False for K&R-style definitions
    is_inline: bool = False


@cache
def _index() -> ci.Index:
    return ci.Index.create()


def parse(text: str, extra_args: tuple[str, ...] = ()) -> ci.TranslationUnit:
    return _index().parse(
        _VIRTUAL_NAME,
        args=[*CLANG_ARGS, *extra_args],
        unsaved_files=[(_VIRTUAL_NAME, text)],
    )


_INLINE = re.compile(rb"\b(?:inline|__inline|__forceinline)\b")
# Declaration boundaries: statement/body ends, preprocessor lines, __pragma(...) (balanced once).
_BOUNDARY = re.compile(rb"[;}]|^[ \t]*#[^\n]*$|__pragma\s*\((?:[^()]|\([^()]*\))*\)", re.M)


def _decl_start(raw: bytes, extent_start: int) -> int:
    """clang's extent starts after a leading `__inline`; widen to the declaration boundary."""
    cut = 0
    for m in _BOUNDARY.finditer(raw, 0, extent_start):
        cut = m.end()
    while cut < extent_start and raw[cut : cut + 1].isspace():
        cut += 1
    return cut


def function_definitions(text: str) -> list[FuncDef]:
    raw = text.encode("utf-8")
    tu = parse(text)
    out = []
    for c in tu.cursor.get_children():
        if c.kind != ci.CursorKind.FUNCTION_DECL or not c.is_definition():
            continue
        if c.location.file is None or c.location.file.name != _VIRTUAL_NAME:
            continue
        body = [ch for ch in c.get_children() if ch.kind == ci.CursorKind.COMPOUND_STMT]
        if not body:
            continue
        start = _decl_start(raw, c.extent.start.offset)
        body_start = body[0].extent.start.offset
        out.append(
            FuncDef(
                c.spelling,
                start,
                body_start,
                c.extent.end.offset,
                c.storage_class == ci.StorageClass.STATIC,
                c.type.kind == ci.TypeKind.FUNCTIONPROTO,
                bool(_INLINE.search(raw, start, body_start)),
            )
        )
    return out


def _is_gs_buffer_type(t: ci.Type, depth: int = 0) -> bool:
    """MSVC /GS protects arrays larger than 4 bytes with more than two non-pointer elements,
    and structures containing such arrays."""
    t = t.get_canonical()
    if t.kind == ci.TypeKind.CONSTANTARRAY:
        elem = t.get_array_element_type().get_canonical()
        size, count = int(t.get_size()), int(t.get_array_size())
        return size > 4 and count > 2 and elem.kind != ci.TypeKind.POINTER
    if t.kind == ci.TypeKind.RECORD and depth < 3:
        return any(_is_gs_buffer_type(f.type, depth + 1) for f in t.get_fields())
    return False


def gs_buffer_functions(text: str, include_callers: bool = True) -> set[str]:
    """Functions defined in `text` with at least one automatic GS buffer. With
    `include_callers`, also their direct callers in the TU, which inherit the buffer (and the
    cookie) when the callee is inlined."""
    direct: set[str] = set()
    calls: dict[str, set[str]] = {}
    for c in parse(text).cursor.get_children():
        if c.kind != ci.CursorKind.FUNCTION_DECL or not c.is_definition():
            continue
        if c.location.file is None or c.location.file.name != _VIRTUAL_NAME:
            continue
        callees = calls.setdefault(c.spelling, set())
        for d in c.walk_preorder():
            if (
                d.kind == ci.CursorKind.VAR_DECL
                and d.storage_class != ci.StorageClass.STATIC
                and _is_gs_buffer_type(d.type)
            ):
                direct.add(c.spelling)
            elif d.kind == ci.CursorKind.CALL_EXPR and d.spelling:
                callees.add(d.spelling)
    if not include_callers:
        return direct
    return direct | {f for f, cs in calls.items() if cs & direct}
