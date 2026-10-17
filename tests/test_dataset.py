from __future__ import annotations

from pathlib import Path
from typing import Any

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from simulacra.data.dataset import finalize
from simulacra.data.records import SCHEMA


def row(i: int, lib: str, **kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": f"{lib}-{i:04d}",
        "library": lib,
        "tu": "a.c",
        "function": f"f{i}",
        "toolchain": "tc",
        "flagset": "O2",
        "flags": ["/O2"],
        "size": 20,
        "target": f"t{i}",
        "target_hash": f"h-{lib}-{i}",
        "target_exact_hash": f"x-{lib}-{i}",
        "pseudo_c": "",
        "context": "",
        "source": "int f(void){return 0;}\n",
        "inlined": [],
        "header_inlined": [],
        "static": False,
        "verified": True,
        "verify_score": 1.0,
        "hard_rule": False,
        "context_mode": "none",
    }
    base.update(kw)
    return base


def write(root: Path, lib: str, rows: list[dict[str, Any]]) -> None:
    path = root / "records" / "tc" / "O2" / f"{lib}.parquet"
    path.parent.mkdir(parents=True, exist_ok=True)
    pq.write_table(pa.Table.from_pylist(rows, schema=SCHEMA), path)


def test_finalize_rules(tmp_path: Path) -> None:
    write(
        tmp_path,
        "zlib",
        [
            row(0, "zlib"),
            row(1, "zlib", size=2),  # too small
            row(2, "zlib", hard_rule=True),
            # duplicate of 3 by exact target: the verified one must win
            row(3, "zlib", verified=False, target_exact_hash="dup"),
            row(4, "zlib", verified=True, target_exact_hash="dup"),
            # same code (anonymized) as a test record -> leakage, dropped from train
            row(5, "zlib", target_hash="shared"),
        ],
    )
    write(tmp_path, "lz4", [row(i, "lz4") for i in range(5)])
    write(
        tmp_path,
        "cjson",
        [row(i, "cjson", size=5 + i) for i in range(10)]
        + [row(50, "cjson", verified=False)]  # unverified never enters the test set
        + [row(51, "cjson", target_hash="shared")],
    )
    man = finalize(tmp_path, seed=1)
    train = pq.read_table(tmp_path / "final" / "train.parquet").to_pylist()
    test = pq.read_table(tmp_path / "final" / "test.parquet").to_pylist()
    val = pq.read_table(tmp_path / "final" / "val.parquet").to_pylist()

    assert {r["id"] for r in val} == {f"lz4-{i:04d}" for i in range(5)}
    assert all(r["verified"] for r in test) and "cjson-0050" not in {r["id"] for r in test}
    train_ids = {r["id"] for r in train}
    assert "zlib-0001" not in train_ids and "zlib-0002" not in train_ids
    assert "zlib-0004" in train_ids and "zlib-0003" not in train_ids
    if "cjson-0051" in {r["id"] for r in test}:
        assert "zlib-0005" not in train_ids
        assert man["dropped"]["leak-train"] == 1
    assert man["dropped"]["too-small"] == 1 and man["dropped"]["hard-rule"] == 1
    assert man["splits"]["test"]["records"] == len(test) <= 400


def test_drop_context_kinds() -> None:
    import random

    from simulacra.data.dataset import drop_context

    ctx = "typedef int A;\ntypedef int B;\nstruct S { A a; B b; };\nint g(int);\nenum E { X, Y };\n"
    kinds = {drop_context(ctx, random.Random(i))[0] for i in range(400)}
    assert kinds == {"none", "partial", "full"}
    for i in range(200):
        kind, out = drop_context(ctx, random.Random(i))
        if kind == "partial":
            assert 0 < len(out) < len(ctx)
        elif kind == "full":
            assert out == ""
        else:
            assert out == ctx


@pytest.mark.docker
def test_build_repairs_keeps_compiling_non_matching(tmp_path: Path) -> None:

    from simulacra.compile import CompileRequest, CompileService
    from simulacra.data.context import TUIndex, target_symbols
    from simulacra.data.dataset import FINAL_SCHEMA
    from simulacra.data.repair import build_repairs
    from simulacra.harness import function_from_obj

    tu = (
        "int f(int *a, int n) {\n    int s;\n    int t;\n    s = 0;\n    t = 1;\n"
        "    for (int i = 0; i < n; i++) {\n        s = s + a[i] * t;\n        t = t ^ s;\n"
        "    }\n    if (s > 10) { t = 2; } else { t = 3; }\n    return s + t * 2;\n}\n"
    )
    with CompileService(workers=2) as svc:
        res = svc.compile(CompileRequest(tu, flags=("/O2",)))
        target = function_from_obj(res.obj_bytes, "f")
        sl = TUIndex(tu).slice("f", target_symbols(target.listing()))
        r = row(
            0,
            "zlib",
            function="f",
            source=sl.source,
            context=sl.context,
            toolchain="vs2022-17.14",
            target=target.listing(with_offsets=False),
        )
        r["context_dropout"], r["model_context"] = "none", sl.context
        (tmp_path / "final").mkdir()
        pq.write_table(
            pa.Table.from_pylist([r], schema=FINAL_SCHEMA), tmp_path / "final" / "train.parquet"
        )
        stats = build_repairs(svc, tmp_path, per_record=3)
    out = pq.read_table(tmp_path / "final" / "repair-train.parquet").to_pylist()
    assert stats["kept"] == len(out) >= 1
    for rep in out:
        assert rep["perturbed"] != rep["source"] and rep["diff"] and rep["score"] < 1.0
