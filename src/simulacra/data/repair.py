"""Repair data (CLAUDE.md Phase 3 step 5): (perturbed source + diff) -> original source.

For verified records of a split, apply semantic-preserving perturbations (`perturb.py`), compile
each under the record's toolchain and flags, and keep those that still compile but no longer
match. The diff is the harness's own aligned diff, exactly what the agent sees after an attempt.
"""

from __future__ import annotations

import hashlib
import random
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pyarrow as pa
import pyarrow.parquet as pq

from simulacra.compile import CompileService
from simulacra.data.perturb import Perturbation, perturbations
from simulacra.data.records import PHASE3_DIR
from simulacra.harness import compile_function
from simulacra.score import score

REPAIR_SCHEMA = pa.schema(
    [
        ("id", pa.string()),
        ("base_id", pa.string()),
        ("library", pa.string()),
        ("function", pa.string()),
        ("toolchain", pa.string()),
        ("flagset", pa.string()),
        ("flags", pa.list_(pa.string())),
        ("kind", pa.string()),
        ("perturbed", pa.string()),
        ("context", pa.string()),
        ("diff", pa.string()),
        ("score", pa.float32()),
        ("source", pa.string()),  # the answer: the record's original source
        ("target", pa.string()),
    ]
)


def build_repairs(
    service: CompileService,
    root: Path = PHASE3_DIR,
    split: str = "train",
    per_record: int = 2,
    max_records: int | None = None,
    seed: int = 0,
    max_diff_lines: int = 120,
) -> Counter[str]:
    rows = [
        r for r in pq.read_table(root / "final" / f"{split}.parquet").to_pylist() if r["verified"]
    ]
    rng = random.Random(seed)
    rng.shuffle(rows)
    if max_records is not None:
        rows = rows[:max_records]
    stats: Counter[str] = Counter()

    jobs: list[tuple[dict[str, Any], Perturbation]] = []
    for r in rows:
        try:
            for p in perturbations(r["source"], r["context"], random.Random(r["id"]), limit=6):
                jobs.append((r, p))
        except Exception:
            stats["perturb-error"] += 1

    def target_of(r: dict[str, Any]) -> Any:
        # Verified: the original source recompiles to exactly the target (and is cached).
        fn, _ = compile_function(
            service, r["source"], r["function"], tuple(r["flags"]), r["context"], r["toolchain"]
        )
        return fn

    def run(job: tuple[dict[str, Any], Perturbation]) -> tuple[str, float, str] | None:
        r, p = job
        cand, _err = compile_function(
            service, p.source, r["function"], tuple(r["flags"]), r["context"], r["toolchain"]
        )
        if cand is None:
            return None
        target = target_of(r)
        if target is None:
            return None
        rep = score(target, cand, max_diff_lines=max_diff_lines)
        if rep.exact:
            return ("exact", 1.0, "")
        return ("changed", rep.score, rep.diff_text)

    with ThreadPoolExecutor(service.workers) as ex:
        results = list(ex.map(run, jobs))

    out: dict[str, list[Any]] = {f.name: [] for f in REPAIR_SCHEMA}
    taken: Counter[str] = Counter()
    for (r, p), res in zip(jobs, results, strict=True):
        if res is None:
            stats["no-compile"] += 1
            continue
        verdict, sc, diff = res
        if verdict == "exact":
            stats["still-matches"] += 1
            continue
        if taken[r["id"]] >= per_record:
            stats["over-quota"] += 1
            continue
        taken[r["id"]] += 1
        stats[f"kept:{p.kind}"] += 1
        values = {
            "id": hashlib.sha1(f"{r['id']}|{p.source}".encode()).hexdigest()[:16],
            "base_id": r["id"],
            "library": r["library"],
            "function": r["function"],
            "toolchain": r["toolchain"],
            "flagset": r["flagset"],
            "flags": list(r["flags"]),
            "kind": p.kind,
            "perturbed": p.source,
            "context": r["context"],
            "diff": diff,
            "score": sc,
            "source": r["source"],
            "target": r["target"],
        }
        for k, v in values.items():
            out[k].append(v)
    stats["records"] = len(rows)
    stats["kept"] = sum(taken.values())
    path = root / "final" / f"repair-{split}.parquet"
    pq.write_table(pa.table(out, schema=REPAIR_SCHEMA), path, compression="zstd")
    return stats
