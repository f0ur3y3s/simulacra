"""Context slicing over MSVC `/P`-style text (`#line` markers, pack pragmas)."""

from __future__ import annotations

import pytest

from simulacra.compile import CompileRequest, CompileService
from simulacra.data.context import TUIndex, _drop_storage, target_symbols
from simulacra.data.linemap import LineMap, PackMap, strip_directives, strip_line_directives
from simulacra.harness import compile_function, function_from_obj
from simulacra.score import score

TU = """#line 1 "/opt/msvc/kits/10/include/ucrt/stddef.h"
#pragma pack(push, 8)
typedef unsigned __int64 size_t;
#pragma pack(pop)
static __inline int hdr_inline(int x) { return x + 1; }
#line 1 "lib.c"
typedef struct S { int a; size_t n; } S;
#pragma pack(push, 1)
struct P { char c; int i; };
#pragma pack(pop)
enum E { E1 = 3, E2 };
static int table[4] = {1, 2, 3, 4};
int unused_global;
static int helper(int v) { return v * table[v & 3]; }
static int callee(int v);
int user(S *s, struct P *p) { return helper(s->a) + callee(p->i) + E2 + hdr_inline(1); }
static int callee(int v) { return v - 1; }
"""


def test_linemap_origin_and_library_ownership() -> None:
    raw = TU.encode()
    lm = LineMap.build(raw)
    assert not lm.is_library(raw.index(b"size_t;"))
    assert lm.is_library(raw.index(b"int user("))
    assert lm.file_at(raw.index(b"int user(")) == "lib.c"


def test_packmap_push_pop() -> None:
    raw = TU.encode()
    pm = PackMap.build(raw)
    assert pm.at(raw.index(b"typedef unsigned")) == 8
    assert pm.at(raw.index(b"struct P")) == 1
    assert pm.at(raw.index(b"enum E")) is None  # back to the default


def test_strip_helpers() -> None:
    text = '#line 3 "a.c"\nint f(void) {\n#pragma loop(no_vector)\n  return 0;\n}\n'
    assert "#line" not in strip_line_directives(text)
    assert "#pragma loop" in strip_line_directives(text)
    assert "#pragma" not in strip_directives(text)


def test_drop_storage_only_touches_declaration_specifiers() -> None:
    assert _drop_storage("static __inline int f(int a);") == "int f(int a);"
    assert _drop_storage("static int g(int static_count);") == "int g(int static_count);"


def test_slice_user() -> None:
    idx = TUIndex(TU)
    sl = idx.slice("user", target_symbols("call <sym:callee>"))
    assert sl.library_defined
    assert sl.inlined == ["helper"] and sl.header_inlined == ["hdr_inline"]
    # source: inlined helper first (TU order), then the function
    assert sl.source.index("static int helper") < sl.source.index("int user(")
    ctx = sl.context
    assert "typedef unsigned __int64 size_t;" in ctx
    assert "typedef struct S" in ctx and "enum E" in ctx
    assert "static int table[4] = {1, 2, 3, 4};" in ctx
    assert "#pragma pack(push, 1)\nstruct P" in ctx
    assert "static __inline int hdr_inline" in ctx  # header helper defined in the context
    assert "int callee(int v);" in ctx and "static int callee" not in ctx  # declared, not static
    assert "unused_global" not in ctx
    assert "int user(" not in ctx and "helper" not in ctx


def test_target_symbols() -> None:
    assert target_symbols("call <sym:foo>\nmov eax, dword ptr [<sym:bar+0x8>]") == {"foo", "bar"}


@pytest.mark.docker
def test_slice_recompiles_to_target() -> None:
    with CompileService(workers=2, cache=False) as svc:
        res = svc.compile(CompileRequest(TU, flags=("/O2",)))
        assert res.ok, res.stderr
        target = function_from_obj(res.obj_bytes, "user")
        sl = TUIndex(TU).slice("user", target_symbols(target.listing()))
        cand, err = compile_function(svc, sl.source, "user", ("/O2",), sl.context)
        assert cand is not None, err
        assert score(target, cand).exact
        # a static function with no remaining caller still compiles (keep-alive)
        t2 = function_from_obj(res.obj_bytes, "callee")
        s2 = TUIndex(TU).slice("callee", target_symbols(t2.listing()))
        c2, err2 = compile_function(svc, s2.source, "callee", ("/O2",), s2.context)
        assert c2 is not None and score(t2, c2).exact, err2
