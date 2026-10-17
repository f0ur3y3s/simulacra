from __future__ import annotations

import random
from collections.abc import Iterator
from pathlib import Path

import pytest

from mscmatch.compile import CompileService
from mscmatch.disasm import NormalizedFunction, NormInsn
from mscmatch.fingerprint import Anchor, build_db, fingerprint
from mscmatch.fingerprint.core import anchor_category, select_anchors
from mscmatch.fingerprint.heuristics import FunctionFeatures, analyze_flags
from mscmatch.fingerprint.pdb import codegen_flags, read_compilands
from mscmatch.fingerprint.rich import strip_rich, summarize
from mscmatch.pe import parse_pe
from mscmatch.pe.image import RichEntry


def test_rich_summary_groups_compilers_and_linkers() -> None:
    s = summarize(
        [
            RichEntry(0x0105, 33145, 141),
            RichEntry(0x0104, 35207, 16),
            RichEntry(0x0104, 35229, 3),
            RichEntry(0x0102, 35229, 1),
            RichEntry(0x0001, 0, 92),
        ]
    )
    assert s.present and s.linker_builds == [35229] and not s.ltcg
    assert s.compiler_builds(exclude={33145, 35207}) == {35229: 3}
    assert summarize([RichEntry(0x0108, 35229, 1)]).ltcg


def test_codegen_flags_filters_non_codegen_options() -> None:
    cmd = '-c -nologo -O2 -GS- -MD -Gy -Z7 -I"C:\\inc" -DFOO=1 -guard:cf -arch:AVX2 -Fo"x.obj" -TC'
    assert codegen_flags(cmd) == ("/O2", "/GS-", "/MD", "/Gy", "/guard:cf", "/arch:AVX2", "/TC")


def feats(**kw: object) -> FunctionFeatures:
    base: dict[str, object] = dict(
        insns=50, arg_spill=False, has_loop=False, inner_nop=False, rep_string=False,
        gs_cookie=False, cfg_dispatch=False, lfence=0, vex=0, avx2=0, avx512=0,
    )  # fmt: skip
    base.update(kw)
    return FunctionFeatures(**base)  # type: ignore[arg-type]


def test_od_detected_from_argument_homing() -> None:
    fa = analyze_flags([feats(arg_spill=True)] * 8 + [feats()] * 2)
    assert max(fa.opt, key=lambda k: fa.opt[k]) == "/Od"


def test_o2_vs_o1_from_loop_alignment() -> None:
    o2 = analyze_flags([feats(has_loop=True, inner_nop=True)] * 4 + [feats(has_loop=True)] * 4)
    o1 = analyze_flags([feats(has_loop=True, rep_string=True)] * 8)
    assert o2.opt["/O2"] > o2.opt["/O1"]
    assert o1.opt["/O1"] > o1.opt["/O2"]


def test_extras_and_runtime() -> None:
    fa = analyze_flags(
        [feats(gs_cookie=True, cfg_dispatch=True, lfence=3, vex=10, avx2=4)] * 2,
        imports_crt_dll=True,
    )
    assert fa.gs["/GS"] > 0.9 and fa.runtime == "/MD"
    assert fa.extras["/guard:cf"] > 0.9 and fa.extras["/Qspectre"] > 0.5
    assert "/arch:AVX2" in fa.extras


# ---- integration (needs both toolchain images) -----------------------------------------------

SRC = r"""
#include <string.h>
#include <stdio.h>
__declspec(dllexport) int count(const char *s, char c) {
    int n = 0; for (; *s; s++) n += *s == c; return n;
}
__declspec(dllexport) int fmt(char *out, int v) {
    char b[32]; sprintf(b, "%d", v); strcpy(out, b); return (int)strlen(out);
}
__declspec(dllexport) int sum(const int *a, int n) {
    int s = 0; for (int i = 0; i < n; i++) s += a[i] * 3; return s;
}
"""


@pytest.fixture(scope="module")
def svc() -> Iterator[CompileService]:
    with CompileService(workers=2, cache=False) as s:
        yield s


@pytest.mark.docker
def test_fingerprint_identifies_toolchain_with_and_without_rich(
    svc: CompileService, tmp_path: Path
) -> None:
    db = {r.toolchain: r for r in build_db(svc, out_dir=tmp_path)}
    for tc in db:
        out = svc.run_raw(
            {"src.c": SRC},
            ["/nologo", "/O2", "/MT", "/Gy", "/LD", "src.c", "/link", "/Brepro"],
            "src.dll",
            tc,
        )
        assert out.ok, out.stdout
        for blob in (out.obj, strip_rich(out.obj)):
            rep = fingerprint(blob, db)
            assert max(rep.toolchain_probs, key=lambda k: rep.toolchain_probs[k]) == tc
            assert rep.candidates[0].toolchain == tc
            assert rep.flags.runtime == "/MT"
        assert parse_pe(strip_rich(out.obj)).rich == []


@pytest.mark.docker
def test_pdb_compilands_report_compiler_build(svc: CompileService) -> None:
    out = svc.run_raw(
        {"a.c": SRC},
        ["/nologo", "/Z7", "/O1", "/MD", "/LD", "a.c", "/link", "/DEBUG", "/PDB:a.pdb"],
        "a.dll",
        outputs=("a.pdb",),
    )
    assert out.ok, out.stdout
    comps = read_compilands(out.outputs["a.pdb"])
    user = [c for c in comps if c.module.lower().endswith("a.obj")]
    assert user and user[0].backend_build == 35229 and user[0].language == "C"
    linker = [c for c in comps if c.module == "* Linker *"]
    assert linker and "/DEBUG" in linker[0].command  # S_ENVBLOCK parsing


def _nf(*lines: str) -> NormalizedFunction:
    insns = []
    for i, line in enumerate(lines):
        mnem, _, rest = line.partition(" ")
        insns.append(NormInsn(i, mnem, tuple(o.strip() for o in rest.split(",")) if rest else ()))
    return NormalizedFunction("f", insns)


def test_anchor_category() -> None:
    simple = _nf("lea eax, [rcx+rdx]", "ret")
    buf = _nf("sub rsp, 0x68", "lea rcx, [rsp+0x20]", "call <sym:g>", "add rsp, 0x68", "ret")
    gs = _nf("mov rax, qword ptr [<sym:__security_cookie>]", "ret")
    assert anchor_category(simple) == "simple"
    assert anchor_category(buf) == "buffer"
    assert anchor_category(gs) == "buffer"


def test_select_anchors_reserves_buffer_functions() -> None:
    body = ["mov eax, 1"] * 10
    simple = _nf(*body, "ret")
    buf = _nf("sub rsp, 0x68", "lea rcx, [rsp+0x20]", *body, "ret")
    pool = [(Anchor(f"s{i}", "f", ""), simple) for i in range(40)]
    pool += [(Anchor(f"b{i}", "f", ""), buf) for i in range(40)]
    picked = select_anchors(pool, 30, random.Random(0))
    assert len(picked) == 30
    assert sum(a.target.startswith("b") for a in picked) == 10


def test_single_cookie_function_is_ambiguous() -> None:
    fa = analyze_flags([feats(gs_cookie=True)] + [feats()] * 20)
    assert 0.2 < fa.gs["/GS"] < 0.8  # both variants go to anchor confirmation


def test_anchor_category_from_source_arrays() -> None:
    fn = _nf("mov eax, 1", "ret")
    assert (
        anchor_category(fn, "void f(void) { ush next_code[15+1]; next_code[0] = 0; }") == "buffer"
    )
    assert anchor_category(fn, "int f(int *a) { int s = a[3]; return s; }") == "simple"


def test_static_local_arrays_are_not_gs_buffers() -> None:
    fn = _nf("mov eax, 1", "ret")
    assert anchor_category(fn, "void f(void) { static const int t[4] = {1}; }") == "simple"


def test_single_element_arrays_are_not_gs_buffers() -> None:
    fn = _nf("mov eax, 1", "ret")
    assert anchor_category(fn, "int f(void) { unsigned char buf[1]; return g(buf); }") == "simple"
    assert anchor_category(fn, "int f(void) { char buf[2*8]; return g(buf); }") == "buffer"
    assert anchor_category(fn, "int f(int n) { char buf[N]; return g(buf); }") == "buffer"


def test_gs_buffer_functions_follow_msvc_rule() -> None:
    from mscmatch.data.cparse import gs_buffer_functions

    src = """
    struct S { char name[16]; int x; };
    static int leaf(void) { char b[16]; b[0] = 1; return b[0]; }
    int caller(void) { return leaf() + 1; }
    int small(void) { char b[4]; b[0] = 1; return b[0]; }
    int two(void) { int b[2]; b[0] = 1; return b[0]; }
    int ptrs(void) { char *p[8]; p[0] = 0; return p[0] != 0; }
    int st(void) { struct S s; s.x = 1; return s.x; }
    int stat(void) { static char b[64]; return b[0]; }
    """
    assert gs_buffer_functions(src) == {"leaf", "caller", "st"}
    assert gs_buffer_functions(src, include_callers=False) == {"leaf", "st"}
