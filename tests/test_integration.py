"""End-to-end tests against the real toolchain image (pytest -m docker)."""

from __future__ import annotations

import re
from collections.abc import Iterator

import pytest

from simulacra.compile import CompileRequest, CompileService
from simulacra.harness import compile_function, function_from_obj
from simulacra.pe import function_from_pe
from simulacra.score import anonymize, score

pytestmark = pytest.mark.docker

SRC = r"""
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#define EXPORT __declspec(dllexport)
static int counter;
int table[16] = {1, 2, 3};
static int helper(int x) { return x * x + counter; }
EXPORT const char *name_of(int k) {
    switch (k) {
    case 0: return "zero"; case 1: return "one"; case 2: return "two"; case 3: return "three";
    case 4: return "four"; case 5: return "five"; case 7: return "seven"; default: return "many";
    }
}
EXPORT int fmt(char *out, int v) {
    char buf[64]; sprintf(buf, "%d-%d", v, helper(v)); strcpy(out, buf); return ++counter;
}
EXPORT double scale(double x) { return x * 1.5 + 0.25; }
EXPORT int sum(int *a, int n) {
    int s = 0;
    for (int i = 0; i < n; i++) s += a[i] + table[i & 15];
    return s;
}
EXPORT int sw(int k, int v) {
    switch (k) {
    case 0: return helper(v); case 1: return helper(v + 1) * 2; case 2: return helper(v - 3) + 7;
    case 3: return abs(v ^ 5); case 4: return helper(v * 9);
    case 5: return helper(v) - helper(v + 1);
    case 9: return 3; default: return helper(k);
    }
}
EXPORT void *dup(const void *p, size_t n) { void *q = malloc(n); if (q) memcpy(q, p, n); return q; }
EXPORT float lerp(float a, float b, float t) { return a + (b - a) * t; }
"""
EXPORTS = re.findall(r"EXPORT\s+[\w\s\*]+?\b(\w+)\s*\(", SRC)


@pytest.fixture(scope="module")
def svc() -> Iterator[CompileService]:
    with CompileService(workers=2, cache=False) as s:
        yield s


def test_compile_is_deterministic(svc: CompileService) -> None:
    req = CompileRequest(SRC, flags=("/O2",))
    a, b = svc.compile(req), svc.compile(req)
    assert a.ok and b.ok
    assert a.obj_bytes == b.obj_bytes


def test_compile_error_is_reported(svc: CompileService) -> None:
    res = svc.compile(CompileRequest("int f( { return 1; }", flags=("/O2",)))
    assert not res.ok
    assert "error C" in res.stderr


def test_context_header_is_force_included(svc: CompileService) -> None:
    fn, err = compile_function(
        svc, "int f(void) { return K * 2; }", "f", ("/O2",), "#define K 21\n"
    )
    assert fn is not None, err
    assert [i.text for i in fn.insns] == ["mov eax, 0x2a", "ret"]


def test_candidate_variants_score_below_one(svc: CompileService) -> None:
    t, _ = compile_function(svc, "int f(int a, int b) { return a * 3 + b; }", "f", ("/O2",))
    c, _ = compile_function(svc, "int f(int a, int b) { return a * 3 - b; }", "f", ("/O2",))
    assert t is not None and c is not None
    r = score(t, c)
    assert not r.exact and 0 < r.score < 1


@pytest.mark.parametrize("flags", [("/O2",), ("/Od",), ("/O1", "/GS-")])
def test_obj_and_linked_pe_normalize_identically(
    svc: CompileService, flags: tuple[str, ...]
) -> None:
    obj = svc.compile(CompileRequest(SRC, flags=flags))
    assert obj.ok, obj.stderr
    link_args = ["/nologo", "/Gy", "/Z7", "/Brepro", "/MT", *flags, "/LD", "src.c",
                 "/link", "/Brepro", "/INCREMENTAL:NO"]  # fmt: skip
    dll = svc.run_raw({"src.c": SRC}, link_args, "src.dll")
    assert dll.ok, dll.stdout
    for name in EXPORTS:
        a = anonymize(function_from_obj(obj.obj_bytes, name))
        b = anonymize(function_from_pe(dll.obj, name))
        rep = score(a, b)
        assert rep.exact, f"{name}:\n{rep.diff_text}"
