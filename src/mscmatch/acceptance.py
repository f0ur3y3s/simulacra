"""Phase 1 checks: compile/diff round-trip, Wine-vs-Windows equivalence manifests, throughput."""

from __future__ import annotations

import hashlib
import json
import platform
import random
import re
import time
from collections import Counter
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from pathlib import Path

from mscmatch.coff import extract_function, list_functions, parse_coff
from mscmatch.compile import CompileRequest, CompileService
from mscmatch.data.corpus import CorpusTU
from mscmatch.data.cparse import function_definitions
from mscmatch.disasm import normalize
from mscmatch.score import score
from mscmatch.toolchain import DEFAULT_TOOLCHAIN, get_toolchain

# ---------------------------------------------------------------------------------------------
# Round-trip: original source of each function, compiled on its own (rest of the TU as
# context), must reproduce the function's code from the whole-TU compile.


@dataclass(frozen=True)
class RoundtripCase:
    tu: str
    function: str
    source: str
    context: str


@dataclass
class RoundtripOutcome:
    tu: str
    function: str
    compiled: bool
    exact: bool
    score: float
    note: str = ""


@dataclass
class RoundtripReport:
    flags: list[str]
    toolchain: str
    total: int
    exact: int
    compiled: int
    skipped: dict[str, int]
    elapsed: float
    population: int = 0  # eligible functions the sample was drawn from
    failures: list[RoundtripOutcome] = field(default_factory=list)

    @property
    def exact_rate(self) -> float:
        return self.exact / self.total if self.total else 0.0

    def summary(self) -> str:
        return (
            f"round-trip {' '.join(self.flags)} on {self.toolchain}: "
            f"{self.exact}/{self.total} exact ({self.exact_rate:.2%}) "
            f"[sampled from {self.population}], {self.compiled} compiled, "
            f"skipped {dict(self.skipped)}, {self.elapsed:.0f}s"
        )


def split_tu(text: str) -> tuple[list[RoundtripCase], Counter[str]]:
    """Cases for every function defined in the TU: (definition, TU minus body + prototype)."""
    raw = text.encode("utf-8")
    defs = function_definitions(text)
    names = Counter(d.name for d in defs)
    skipped: Counter[str] = Counter()
    cases = []
    for d in defs:
        if names[d.name] > 1:
            skipped["duplicate-name"] += 1
            continue
        if not d.prototyped:
            skipped["k&r"] += 1
            continue
        proto = raw[d.start : d.body_start].rstrip()
        context = raw[: d.start] + proto + b";\n" + raw[d.end :]
        source = raw[d.start : d.end] + b"\n"
        cases.append(RoundtripCase("", d.name, source.decode("utf-8"), context.decode("utf-8")))
    return cases, skipped


def roundtrip(
    service: CompileService,
    corpus: Iterable[CorpusTU],
    flags: tuple[str, ...],
    toolchain_id: str = DEFAULT_TOOLCHAIN,
    sample: int | None = 1000,
    seed: int = 0,
) -> RoundtripReport:
    start = time.monotonic()
    tus = list(corpus)
    targets = list(
        service.compile_many(
            CompileRequest(tu.text(), "", "", toolchain_id, flags, timeout=180) for tu in tus
        )
    )
    skipped: Counter[str] = Counter()
    cases: list[RoundtripCase] = []
    target_objs: dict[str, bytes] = {}
    for tu, res in zip(tus, targets, strict=True):
        if not res.ok:
            skipped["tu-compile-failed"] += 1
            continue
        target_objs[tu.id] = res.obj_bytes
        emitted = set(list_functions(parse_coff(res.obj_bytes)))
        tu_cases, tu_skipped = split_tu(tu.text())
        skipped.update(tu_skipped)
        for c in tu_cases:
            if c.function not in emitted:
                skipped["not-emitted"] += 1  # inlined everywhere / unreferenced static
                continue
            cases.append(RoundtripCase(tu.id, c.function, c.source, c.context))
    population = len(cases)
    if sample is not None and len(cases) > sample:
        cases = random.Random(seed).sample(cases, sample)
        cases.sort(key=lambda c: (c.tu, c.function))

    reqs = [
        CompileRequest(c.source, c.context, c.function, toolchain_id, flags, timeout=180)
        for c in cases
    ]
    outcomes: list[RoundtripOutcome] = []
    for case, res in zip(cases, service.compile_many(reqs), strict=True):
        if not res.ok:
            outcomes.append(
                RoundtripOutcome(case.tu, case.function, False, False, 0.0, res.stderr[:2000])
            )
            continue
        try:
            tfn = normalize(extract_function(target_objs[case.tu], case.function))
            cfn = normalize(extract_function(res.obj_bytes, case.function))
        except Exception as e:
            outcomes.append(RoundtripOutcome(case.tu, case.function, True, False, 0.0, str(e)))
            continue
        rep = score(tfn, cfn, max_diff_lines=60)
        note = "" if rep.exact else rep.diff_text
        outcomes.append(RoundtripOutcome(case.tu, case.function, True, rep.exact, rep.score, note))

    return RoundtripReport(
        flags=list(flags),
        toolchain=toolchain_id,
        total=len(outcomes),
        exact=sum(o.exact for o in outcomes),
        compiled=sum(o.compiled for o in outcomes),
        skipped=dict(skipped),
        elapsed=time.monotonic() - start,
        population=population,
        failures=[o for o in outcomes if not o.exact],
    )


# ---------------------------------------------------------------------------------------------
# Equivalence manifests (1.4): sha256 of every COMDAT function's code bytes.

_BANNER = re.compile(r"Compiler Version (\S+) for (\S+)")


def cl_banner(service: CompileService, toolchain_id: str = DEFAULT_TOOLCHAIN) -> str:
    """'<version> for <arch>' as printed by the cl.exe the backend actually runs."""
    out = service.run_raw({}, [], "none", toolchain_id, timeout=60)
    m = _BANNER.search(out.stdout + out.stderr)
    return f"{m.group(1)} for {m.group(2)}" if m else ""


def equivalence_manifest(
    service: CompileService,
    corpus: Iterable[CorpusTU],
    flagsets: dict[str, tuple[str, ...]],
    toolchain_id: str = DEFAULT_TOOLCHAIN,
) -> dict[str, object]:
    tus = list(corpus)
    functions: dict[str, str] = {}
    errors: dict[str, str] = {}
    for fs_name, flags in flagsets.items():
        reqs = [CompileRequest(tu.text(), "", "", toolchain_id, flags, timeout=180) for tu in tus]
        for tu, res in zip(tus, service.compile_many(reqs), strict=True):
            key_tu = f"{fs_name}:{tu.id}"
            if not res.ok:
                errors[key_tu] = res.stderr[:500]
                continue
            obj = parse_coff(res.obj_bytes)
            for name in list_functions(obj):
                code = extract_function(obj, name).code
                functions[f"{key_tu}:{name}"] = hashlib.sha256(code).hexdigest()
    tc = get_toolchain(toolchain_id)
    return {
        "toolchain": toolchain_id,
        "cl_version": tc.cl_version,
        "cl_banner": cl_banner(service, toolchain_id),
        "backend": service.backend_kind,
        "host": platform.platform(),
        "flagsets": {k: list(v) for k, v in flagsets.items()},
        "corpus": [tu.id for tu in tus],
        "corpus_sha256": hashlib.sha256(
            b"".join(hashlib.sha256(tu.path.read_bytes()).digest() for tu in tus)
        ).hexdigest(),
        "function_count": len(functions),
        "functions": dict(sorted(functions.items())),
        "errors": errors,
    }


@dataclass
class VerifyReport:
    common: int
    identical: int
    only_a: list[str]
    only_b: list[str]
    different: list[str]
    corpus_match: bool
    banner_a: str = ""
    banner_b: str = ""

    @property
    def banner_match(self) -> bool:
        return bool(self.banner_a) and self.banner_a == self.banner_b

    @property
    def ok(self) -> bool:
        return (
            self.corpus_match
            and self.banner_match
            and self.common > 0
            and self.identical == self.common
            and not self.only_a
            and not self.only_b
        )

    def summary(self) -> str:
        pct = self.identical / self.common if self.common else 0.0
        lines = [
            f"{'PASS' if self.ok else 'FAIL'}: "
            f"{self.identical}/{self.common} identical ({pct:.2%})",
            f"only in A: {len(self.only_a)}   only in B: {len(self.only_b)}   "
            f"corpus identical: {self.corpus_match}",
            f"cl A: {self.banner_a or '?'}   cl B: {self.banner_b or '?'}   "
            f"same compiler: {self.banner_match}",
        ]
        lines += [f"  differs: {k}" for k in self.different[:50]]
        lines += [f"  only A: {k}" for k in self.only_a[:20]]
        lines += [f"  only B: {k}" for k in self.only_b[:20]]
        return "\n".join(lines)


def verify_manifests(a_path: Path, b_path: Path) -> VerifyReport:
    a = json.loads(a_path.read_text(encoding="utf-8"))
    b = json.loads(b_path.read_text(encoding="utf-8"))
    fa: dict[str, str] = a["functions"]
    fb: dict[str, str] = b["functions"]
    common = sorted(set(fa) & set(fb))
    different = [k for k in common if fa[k] != fb[k]]
    return VerifyReport(
        common=len(common),
        identical=len(common) - len(different),
        only_a=sorted(set(fa) - set(fb)),
        only_b=sorted(set(fb) - set(fa)),
        different=different,
        corpus_match=a.get("corpus_sha256") == b.get("corpus_sha256"),
        banner_a=str(a.get("cl_banner", "")),
        banner_b=str(b.get("cl_banner", "")),
    )


# ---------------------------------------------------------------------------------------------
# Throughput


def bench(
    worker_counts: Iterable[int],
    corpus: list[CorpusTU],
    flags: tuple[str, ...] = ("/O2",),
    jobs: int = 64,
    toolchain_id: str = DEFAULT_TOOLCHAIN,
) -> list[dict[str, float]]:
    """Compiles/sec with the cache disabled, on single-function sources cut from the corpus."""
    cases: list[RoundtripCase] = []
    for tu in corpus:
        cs, _ = split_tu(tu.text())
        cases.extend(cs)
        if len(cases) >= jobs * 4:
            break
    rng = random.Random(1)
    picked = rng.sample(cases, min(jobs, len(cases)))
    reqs = [CompileRequest(c.source, c.context, c.function, toolchain_id, flags) for c in picked]
    results = []
    for n in worker_counts:
        with CompileService(workers=n, cache=False) as svc:
            list(svc.compile_many(reqs[:n]))  # warm up every worker
            t0 = time.monotonic()
            ok = sum(r.ok for r in svc.compile_many(reqs))
            dt = time.monotonic() - t0
        results.append(
            {
                "workers": n,
                "jobs": len(reqs),
                "ok": ok,
                "seconds": dt,
                "compiles_per_sec": len(reqs) / dt,
            }
        )
    return results


def report_json(obj: object) -> str:
    if hasattr(obj, "__dataclass_fields__"):
        return json.dumps(asdict(obj), indent=2)  # type: ignore[call-overload]
    return json.dumps(obj, indent=2)
