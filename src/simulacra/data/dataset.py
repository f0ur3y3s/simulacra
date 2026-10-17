"""Phase 3 finalize: filter, dedupe, split by library, sample the test set, write shards.

Input: every `records/<toolchain>/<flagset>/<library>.parquet` shard. Output under
`datasets/phase3/final/`: `train.parquet`, `val.parquet`, `test.parquet`, `manifest.json`.

Rules (CLAUDE.md Phase 3 steps 3-4):
* drop functions under 3 instructions, toolchain-header code (already excluded when records
  are built) and records whose source breaks the hard rules (`__pragma` etc.);
* deduplicate on the exact normalized target, preferring verified records;
* split by library (`splits.toml`); the test set is a size-bucketed sample of *verified* test
  records, the rest of the test libraries is discarded, never trained on;
* leakage guard: drop train/val records whose anonymized target also occurs in the test set;
* context dropout (step 6), train only: `model_context` is the context shown to the model; for
  some records part or all of it is removed so the model must declare plausible types itself.
  `context` stays complete (it is what compiles the reference source).
"""

from __future__ import annotations

import json
import random
import time
import tomllib
from collections import Counter, defaultdict
from importlib import resources
from pathlib import Path
from typing import Any

import pyarrow as pa
import pyarrow.parquet as pq

from simulacra.data.context import TUIndex
from simulacra.data.records import PHASE3_DIR, SCHEMA

MIN_INSNS = 3
DROPOUT_FULL = 0.05
DROPOUT_PARTIAL = 0.15
Row = dict[str, Any]

FINAL_SCHEMA = SCHEMA.append(pa.field("context_dropout", pa.string())).append(
    pa.field("model_context", pa.string())
)


def drop_context(context: str, rng: random.Random) -> tuple[str, str]:
    """(kind, context shown to the model): "none", "partial" (30-70 % of the top-level
    declarations removed) or "full" (empty)."""
    u = rng.random()
    if u < DROPOUT_FULL:
        return "full", ""
    if u >= DROPOUT_FULL + DROPOUT_PARTIAL or not context.strip():
        return "none", context
    try:
        groups = TUIndex(context).groups
    except Exception:
        return "none", context
    if len(groups) < 2:
        return "none", context
    k = max(1, round(len(groups) * rng.uniform(0.3, 0.7)))
    drop = sorted(rng.sample(groups, k), key=lambda g: g.start, reverse=True)
    raw = context.encode("utf-8")
    for g in drop:
        raw = raw[: g.start] + raw[g.end :]
    return "partial", raw.decode("utf-8")


def load_split_config() -> dict[str, Any]:
    text = resources.files(__package__).joinpath("splits.toml").read_text(encoding="utf-8")
    return tomllib.loads(text)


def load_records(root: Path = PHASE3_DIR) -> list[Row]:
    rows: list[Row] = []
    for shard in sorted((root / "records").glob("*/*/*.parquet")):
        rows.extend(pq.read_table(shard).to_pylist())
    return rows


def _bucket(size: int, buckets: list[list[int]]) -> int:
    for i, (lo, hi) in enumerate(buckets):
        if lo <= size < hi:
            return i
    return len(buckets) - 1


def finalize(root: Path = PHASE3_DIR, seed: int = 0) -> dict[str, Any]:
    cfg = load_split_config()
    test_libs = set(cfg["splits"].get("test", []))
    val_libs = set(cfg["splits"].get("val", []))
    buckets: list[list[int]] = cfg["test"]["buckets"]
    test_size: int = cfg["test"]["size"]

    rows = load_records(root)
    dropped: Counter[str] = Counter()
    kept: list[Row] = []
    for r in rows:
        if r["size"] < MIN_INSNS:
            dropped["too-small"] += 1
        elif r["hard_rule"]:
            dropped["hard-rule"] += 1
        else:
            kept.append(r)

    # Deduplicate on the exact target; deterministic preference: verified, then id order.
    kept.sort(key=lambda r: (not r["verified"], r["id"]))
    seen: set[str] = set()
    unique: list[Row] = []
    for r in kept:
        if r["target_exact_hash"] in seen:
            dropped["duplicate"] += 1
            continue
        seen.add(r["target_exact_hash"])
        unique.append(r)

    split_rows: dict[str, list[Row]] = defaultdict(list)
    for r in unique:
        lib = r["library"]
        split_rows["test" if lib in test_libs else "val" if lib in val_libs else "train"].append(r)

    # Test sample: verified only, as even across size buckets as availability allows.
    rng = random.Random(seed)
    by_bucket: dict[int, list[Row]] = defaultdict(list)
    for r in split_rows["test"]:
        if r["verified"]:
            by_bucket[_bucket(r["size"], buckets)].append(r)
    sample: list[Row] = []
    remaining = test_size
    order = sorted(by_bucket, key=lambda b: len(by_bucket[b]))  # smallest buckets first
    for i, b in enumerate(order):
        share = remaining // (len(order) - i)
        pick = rng.sample(by_bucket[b], min(share, len(by_bucket[b])))
        sample.extend(pick)
        remaining -= len(pick)
    dropped["test-unsampled"] = len(split_rows["test"]) - len(sample)
    split_rows["test"] = sorted(sample, key=lambda r: r["id"])

    dropped_kinds: Counter[str] = Counter()
    test_hashes = {r["target_hash"] for r in split_rows["test"]}
    for name in ("train", "val"):
        before = len(split_rows[name])
        split_rows[name] = [r for r in split_rows[name] if r["target_hash"] not in test_hashes]
        dropped[f"leak-{name}"] = before - len(split_rows[name])

    for name in ("train", "val", "test"):
        for r in split_rows[name]:
            if name == "train":
                r["context_dropout"], r["model_context"] = drop_context(
                    r["context"], random.Random(f"{seed}:{r['id']}")
                )
            else:
                r["context_dropout"], r["model_context"] = "none", r["context"]
            if r["context_dropout"] != "none":
                dropped_kinds[r["context_dropout"]] += 1

    out = root / "final"
    out.mkdir(parents=True, exist_ok=True)
    for name in ("train", "val", "test"):
        table = pa.Table.from_pylist(split_rows[name], schema=FINAL_SCHEMA)
        pq.write_table(table, out / f"{name}.parquet", compression="zstd")

    def summary(rs: list[Row]) -> dict[str, Any]:
        return {
            "records": len(rs),
            "verified": sum(r["verified"] for r in rs),
            "libraries": dict(Counter(r["library"] for r in rs)),
            "flagsets": dict(Counter(r["flagset"] for r in rs)),
            "toolchains": dict(Counter(r["toolchain"] for r in rs)),
            "size_buckets": dict(Counter(str(buckets[_bucket(r["size"], buckets)]) for r in rs)),
        }

    verify_rates: dict[str, dict[str, float]] = defaultdict(dict)
    groups: dict[tuple[str, str], list[bool]] = defaultdict(list)
    for r in rows:
        groups[(r["library"], r["flagset"])].append(r["verified"])
    for (lib, fs), v in sorted(groups.items()):
        verify_rates[lib][fs] = round(sum(v) / len(v), 4)

    manifest = {
        "created": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "seed": seed,
        "input_records": len(rows),
        "dropped": dict(dropped),
        "context_dropout": dict(dropped_kinds),
        "splits": {name: summary(split_rows[name]) for name in ("train", "val", "test")},
        "verified_rate_by_library_flagset": verify_rates,
        "config": cfg,
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=1), encoding="utf-8")
    return manifest
