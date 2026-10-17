from __future__ import annotations

import json
from pathlib import Path

import pytest

from simulacra.compile import CompileRequest, CompileService
from simulacra.decomp import GhidraDecompiler, parse_result

SAMPLE = {
    "program": "a.obj",
    "format": "MS Common Object File Format (COFF)",
    "image_base": 0,
    "functions": [
        {
            "name": "f",
            "entry": 16,
            "signature": "int f(int x)",
            "calling_convention": "__fastcall",
            "c": (
                "\n/* WARNING: Removing unreachable block */\n\n"
                "int f(int x)\n\n{\n  return x * 3;\n}\n\n"
            ),
            "callees": ["g"],
            "error": "",
        },
        {"name": "h", "entry": 64, "signature": "", "calling_convention": "",
         "c": "", "callees": [], "error": "timeout"},
    ],
}  # fmt: skip


def test_parse_result_and_lookup() -> None:
    res = parse_result(json.dumps(SAMPLE))
    assert res.format.startswith("MS Common Object")
    f = res.get("f")
    assert f is not None and f.ok and f.callees == ("g",) and res.at(16) is f
    h = res.get("h")
    assert h is not None and not h.ok
    assert res.get("missing") is None


def test_pseudo_c_drops_warnings_by_default() -> None:
    f = parse_result(json.dumps(SAMPLE)).get("f")
    assert f is not None
    assert f.pseudo_c() == "int f(int x)\n\n{\n  return x * 3;\n}\n"
    assert "WARNING" in f.pseudo_c(keep_warnings=True)


def test_round_trip_json() -> None:
    res = parse_result(json.dumps(SAMPLE))
    again = parse_result(res.to_json())
    assert again.functions == res.functions


@pytest.mark.docker
def test_decompile_compiled_object(tmp_path: Path) -> None:
    # f passes x straight through to h; only parameter propagation from h (Decompiler
    # Parameter ID) and the forced Windows x64 ABI give f its argument.
    src = (
        "__declspec(noinline) int h(int y);\n"
        "int f(int x) { return h(x) * 3 + 1; }\n"
        "int h(int y) { return y ^ 0x55; }\n"
        "int k(int a, int b) { return a ^ b; }\n"
    )
    with CompileService(workers=1, cache=False) as svc:
        res = svc.compile(CompileRequest(src, flags=("/O2",)))
    assert res.ok
    dec = GhidraDecompiler(cache_dir=tmp_path)
    out = dec.decompile(res.obj_bytes, "src.obj", ["f"])
    assert out.compiler_spec == "windows"
    assert [fn.name for fn in out.functions] == ["f"]
    f = out.functions[0]
    assert f.ok and "h(" in f.c and "h" in f.callees
    assert f.calling_convention == "__fastcall"
    assert "f(void)" not in f.signature and "param_1" in f.signature
    again = dec.decompile(res.obj_bytes, "src.obj", ["f"])
    assert again.cached and again.functions == out.functions
    every = {fn.name: fn for fn in dec.decompile(res.obj_bytes, "src.obj").functions}
    assert {"f", "h", "k"} <= set(every)
    assert every["k"].signature.count("param_") == 2
