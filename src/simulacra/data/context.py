"""Reduce a preprocessed TU to what one function needs: context declarations + its source.

For a function `f`:

* **source** is `f`'s definition, preceded by the definitions of TU-defined library functions
  that were inlined into it (called in the C but absent from `f`'s machine code), recursively.
* **context** is every top-level declaration that `source` transitively references (types,
  enum constants, globals with their initializers, prototypes of the functions it calls), in TU
  order and under the `#pragma pack` value each was declared with. Inlined helpers that come
  from toolchain headers (UCRT `__inline` functions) go into the context as full definitions.

Works on MSVC `/P` output; `#line` markers tell library code from toolchain headers.
"""

from __future__ import annotations

import bisect
import re
from collections.abc import Iterable
from dataclasses import dataclass, field

import clang.cindex as ci

from simulacra.data.cparse import _decl_start, parse
from simulacra.data.linemap import LineMap, PackMap, strip_directives, strip_line_directives

_SYM = re.compile(r"<sym:([^>+]+)")
_BLANKS = re.compile(r"\n[ \t]*\n(?:[ \t]*\n)+")
_REF_KINDS = {
    ci.CursorKind.DECL_REF_EXPR,
    ci.CursorKind.MEMBER_REF_EXPR,
    ci.CursorKind.TYPE_REF,
    ci.CursorKind.CALL_EXPR,
}


@dataclass
class _Group:
    """A top-level statement: one or more overlapping top-level cursors (e.g. a typedef and the
    struct it names)."""

    start: int
    end: int  # exclusive, including the trailing `;` for declarations
    cursors: list[ci.Cursor] = field(default_factory=list)
    function_def: ci.Cursor | None = None
    body_start: int = 0
    idx: int = 0


@dataclass
class FunctionSlice:
    function: str
    source: str
    context: str
    inlined: list[str]  # helpers whose definitions went into `source`
    header_inlined: list[str]  # toolchain-header helpers defined in `context`
    library_defined: bool  # `f` itself comes from library files, not toolchain headers
    callee_bodies: list[str] = field(default_factory=list)  # called functions defined in context


class TUIndex:
    """Parse a TU once; slice any of its functions."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.raw = text.encode("utf-8")
        self.lines = LineMap.build(self.raw)
        self.packs = PackMap.build(self.raw)
        self.tu = parse(text)
        self.groups = self._build_groups()
        self.starts = [g.start for g in self.groups]
        self.defs: dict[str, _Group] = {}
        self.protos: dict[str, list[_Group]] = {}
        for g in self.groups:
            for c in g.cursors:
                if c.kind != ci.CursorKind.FUNCTION_DECL:
                    continue
                if c.is_definition():
                    self.defs.setdefault(c.spelling, g)
                elif g.function_def is None:
                    self.protos.setdefault(c.spelling, []).append(g)

    # -- construction ----------------------------------------------------------------------
    def _build_groups(self) -> list[_Group]:
        items: list[tuple[int, int, ci.Cursor]] = []
        for c in self.tu.cursor.get_children():
            if c.location.file is None:
                continue
            s, e = c.extent.start.offset, c.extent.end.offset
            if e <= s:
                continue
            items.append((_decl_start(self.raw, s), e, c))
        items.sort(key=lambda t: (t[0], t[1]))
        groups: list[_Group] = []
        for s, e, c in items:
            if groups and s < groups[-1].end:
                g = groups[-1]
                g.end = max(g.end, e)
                g.cursors.append(c)
            else:
                groups.append(_Group(s, e, [c]))
        for i, g in enumerate(groups):
            g.idx = i
            for c in g.cursors:
                if c.kind == ci.CursorKind.FUNCTION_DECL and c.is_definition():
                    body = [k for k in c.get_children() if k.kind == ci.CursorKind.COMPOUND_STMT]
                    if body:
                        g.function_def = c
                        g.body_start = body[0].extent.start.offset
            if g.function_def is None:
                g.end = self._through_semicolon(g.end)
        return groups

    def _through_semicolon(self, end: int) -> int:
        """Declaration extents stop before their `;`."""
        i = end
        while i < len(self.raw) and self.raw[i : i + 1] in (b" ", b"\t", b"\r", b"\n"):
            i += 1
        return i + 1 if self.raw[i : i + 1] == b";" else end

    def _group_of(self, offset: int) -> _Group | None:
        i = bisect.bisect_right(self.starts, offset) - 1
        if i >= 0 and self.groups[i].start <= offset < self.groups[i].end:
            return self.groups[i]
        return None

    # -- reference walking -------------------------------------------------------------------
    def _refs(self, cursors: Iterable[ci.Cursor], skip_body: bool) -> tuple[set[int], set[str]]:
        """Groups (by index) and function names referenced from `cursors`."""
        groups: set[int] = set()
        funcs: set[str] = set()
        seen_types: set[str] = set()
        stack = list(cursors)
        while stack:
            c = stack.pop()
            if skip_body and c.kind == ci.CursorKind.COMPOUND_STMT:
                continue
            if c.kind in _REF_KINDS:
                ref = c.referenced
                if ref is not None and ref.location.file is not None:
                    if ref.kind == ci.CursorKind.FUNCTION_DECL:
                        funcs.add(ref.spelling)
                    else:
                        g = self._group_of(ref.extent.start.offset)
                        if g is not None:
                            groups.add(g.idx)
            # libclang omits TYPE_REF children for some typedef uses (parameters declared with a
            # typedef that a prior prototype already used), so types are walked as well.
            self._walk_type(c.type, groups, seen_types)
            stack.extend(c.get_children())
        return groups, funcs

    def _walk_type(self, t: ci.Type, groups: set[int], seen: set[str]) -> None:
        if t is None or t.kind == ci.TypeKind.INVALID:
            return
        key = f"{t.kind.value}:{t.spelling}"
        if key in seen:
            return
        seen.add(key)
        k = t.kind
        if k in (ci.TypeKind.TYPEDEF, ci.TypeKind.RECORD, ci.TypeKind.ENUM, ci.TypeKind.ELABORATED):
            d = t.get_declaration()
            if d is not None and d.location.file is not None:
                g = self._group_of(d.extent.start.offset)
                if g is not None:
                    groups.add(g.idx)
                if k == ci.TypeKind.TYPEDEF:
                    self._walk_type(d.underlying_typedef_type, groups, seen)
            if k == ci.TypeKind.ELABORATED:
                self._walk_type(t.get_named_type(), groups, seen)
        elif k == ci.TypeKind.POINTER:
            self._walk_type(t.get_pointee(), groups, seen)
        elif k in (
            ci.TypeKind.CONSTANTARRAY,
            ci.TypeKind.INCOMPLETEARRAY,
            ci.TypeKind.VARIABLEARRAY,
            ci.TypeKind.DEPENDENTSIZEDARRAY,
        ):
            self._walk_type(t.element_type, groups, seen)
        elif k in (ci.TypeKind.FUNCTIONPROTO, ci.TypeKind.FUNCTIONNOPROTO):
            self._walk_type(t.get_result(), groups, seen)
            if k == ci.TypeKind.FUNCTIONPROTO:
                for a in t.argument_types():
                    self._walk_type(a, groups, seen)

    def _callees(self, g: _Group) -> set[str]:
        assert g.function_def is not None
        body = [k for k in g.function_def.get_children() if k.kind == ci.CursorKind.COMPOUND_STMT]
        return self._refs(body, skip_body=False)[1]

    # -- text -------------------------------------------------------------------------------
    def _text(self, start: int, end: int) -> str:
        return self.raw[start:end].decode("utf-8")

    def _prototype(self, name: str, defined_here: bool) -> tuple[int, str, _Group]:
        """(offset, text, group) of the declaration that introduces `name`. With
        `defined_here=False` a TU-local definition is declared as an external function."""
        if name in self.protos:
            g = self.protos[name][0]
            text = self._text(g.start, g.end)
        else:
            g = self.defs[name]
            # Strip first: a `#line` between `)` and `{` would swallow the appended `;`.
            text = strip_directives(self._text(g.start, g.body_start)).rstrip() + ";"
        if not defined_here and name in self.defs:
            text = _drop_storage(text)
        return g.start, text, g

    # -- slicing ----------------------------------------------------------------------------
    def functions(self) -> list[str]:
        return list(self.defs)

    def slice(
        self, name: str, target_symbols: set[str], callee_bodies: str = "none"
    ) -> FunctionSlice:
        """`target_symbols`: names referenced by `name`'s compiled code (`<sym:...>` tokens).

        `callee_bodies` controls functions that are called but not inlined and are defined in
        the TU: "none" declares them, "direct" defines the direct callees in the context,
        "transitive" defines everything reachable. Measured on zlib /O2, "none" reproduces the
        target most often (143/153 vs 113 for "direct"): visible bodies change inlining
        decisions, and the remaining misses come from TU-wide effects (how many callers a
        static callee has) that no per-function context reproduces."""
        root = self.defs[name]
        # 1. Callees defined here but missing from the machine code were inlined.
        inlined: list[str] = []
        header_inlined: list[str] = []
        todo = [name]
        seen = {name}
        while todo:
            fn = todo.pop()
            for callee in sorted(self._callees(self.defs[fn])):
                if callee in seen or callee not in self.defs or callee in target_symbols:
                    continue
                seen.add(callee)
                g = self.defs[callee]
                (inlined if self.lines.is_library(g.start) else header_inlined).append(callee)
                todo.append(callee)

        source_fns = [name, *inlined]
        # 2. Called-but-not-inlined functions whose bodies go into the context.
        bodies: list[str] = []
        if callee_bodies != "none":
            frontier = list(source_fns) + list(header_inlined)
            taken = set(source_fns) | set(header_inlined)
            while frontier:
                fn = frontier.pop()
                for callee in sorted(self._callees(self.defs[fn])):
                    if callee in taken or callee not in self.defs:
                        continue
                    taken.add(callee)
                    bodies.append(callee)
                    if callee_bodies == "transitive":
                        frontier.append(callee)
        context_defs = [*header_inlined, *bodies]
        full_groups: set[int] = set()  # emitted verbatim in the context
        protos: dict[str, None] = {}  # functions needing only a declaration
        for fn in context_defs:
            full_groups.add(self.defs[fn].idx)

        # 3. Close over everything the source (and each emitted declaration) references.
        work = [self.defs[fn].function_def for fn in source_fns]
        work += [self.defs[fn].function_def for fn in context_defs]
        pending: list[ci.Cursor] = [c for c in work if c is not None]
        # Prototypes of everything defined in the source: they carry declared attributes, and
        # a helper may be called (in TU order) before its definition.
        for fn in source_fns:
            if fn in self.protos:
                protos[fn] = None
                pending.extend(self.protos[fn][0].cursors)
        visited_groups: set[int] = set()
        while pending:
            groups, funcs = self._refs(pending, skip_body=False)
            pending = []
            for fn in sorted(funcs):
                if fn in source_fns or fn in context_defs or fn in protos:
                    continue
                protos[fn] = None
                if fn in self.protos:
                    pending.extend(self.protos[fn][0].cursors)
                elif fn in self.defs and (d := self.defs[fn].function_def) is not None:
                    pending.extend(
                        k for k in d.get_children() if k.kind != ci.CursorKind.COMPOUND_STMT
                    )
            for gi in groups - visited_groups:
                visited_groups.add(gi)
                g = self.groups[gi]
                if g.function_def is not None:
                    continue  # a function's definition group: only ever referenced via protos
                full_groups.add(gi)
                pending.extend(g.cursors)
        # 4. Emit in TU order.
        pieces: list[tuple[int, str, int | None]] = []
        for gi in full_groups:
            g = self.groups[gi]
            pieces.append(
                (g.start, strip_directives(self._text(g.start, g.end)), self.packs.at(g.start))
            )
        for fn in protos:
            off, text, g = self._prototype(fn, defined_here=fn in source_fns)
            pieces.append((off, strip_directives(text), self.packs.at(g.start)))
        pieces.sort(key=lambda p: p[0])
        context = _with_packs(pieces)

        src_parts = []
        for fn in sorted(source_fns, key=lambda f: self.defs[f].start):
            g = self.defs[fn]
            src_parts.append(strip_line_directives(self._text(g.start, g.end)))
        source = _tidy("\n\n".join(src_parts)) + "\n"
        return FunctionSlice(
            name,
            source,
            context,
            inlined,
            header_inlined,
            self.lines.is_library(root.start),
            bodies,
        )


def _with_packs(pieces: list[tuple[int, str, int | None]]) -> str:
    out: list[str] = []
    current: int | None = None
    for _off, text, pack in pieces:
        if pack != current:
            if current is not None:
                out.append("#pragma pack(pop)")
            if pack is not None:
                out.append(f"#pragma pack(push, {pack})")
            current = pack
        out.append(text.strip())
    if current is not None:
        out.append("#pragma pack(pop)")
    return _tidy("\n".join(out)) + "\n"


def _tidy(text: str) -> str:
    return _BLANKS.sub("\n\n", text).strip("\n")


_STORAGE = re.compile(r"\b(?:static|__inline|__forceinline|inline)\b\s*")


def _drop_storage(proto: str) -> str:
    """Remove `static`/`inline` from a prototype's declaration specifiers."""
    paren = proto.find("(")
    head, tail = (proto[:paren], proto[paren:]) if paren >= 0 else (proto, "")
    return _STORAGE.sub("", head) + tail


def target_symbols(listing: str) -> set[str]:
    """Names a normalized listing references (`<sym:name>` / `<sym:name+0x8>`)."""
    return set(_SYM.findall(listing))
