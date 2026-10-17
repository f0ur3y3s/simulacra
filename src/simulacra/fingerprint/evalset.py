"""Phase 2 acceptance: fingerprint held-out binaries we build ourselves with known configs.

Each binary is a DLL linked from one corpus library's preprocessed TUs with a random
(toolchain, /O*, /GS, runtime) configuration, exporting every external function via a .def file.
The linker map is used *only* to locate anchor functions (standing in for a user who says
"the function at this address is this C"); the fingerprinter never sees it.
"""

from __future__ import annotations

import json
import random
import re
import time
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path

from simulacra.acceptance import split_tu
from simulacra.compile import CompileService
from simulacra.data.corpus import CorpusTU, load_corpus
from simulacra.data.cparse import function_definitions, gs_buffer_functions
from simulacra.disasm import NormalizedFunction, normalize
from simulacra.fingerprint.core import Anchor, confirm, fingerprint, select_anchors
from simulacra.fingerprint.db import ToolchainRecord
from simulacra.fingerprint.rich import strip_rich
from simulacra.pe import PEFunctions, extract_pe_function, parse_pe
from simulacra.toolchain import load_registry

EXCLUDE_TUS = {"lua/lua.c", "lua/luac.c"}  # programs with main(), not library code
OPTS = ("/O2", "/O1", "/Od")
GSS = ("/GS", "/GS-")
RUNTIMES = ("/MT", "/MD")
_INLINE_DEF = re.compile(r"^\s*(?:static\s+)?(?:__inline|__forceinline|inline)\b")
_MAP_LINE = re.compile(r"^\s*[0-9a-f]{4}:[0-9a-f]{8}\s+(\S+)\s+([0-9a-f]{16})\s+f\s", re.I)


@dataclass(frozen=True)
class EvalConfig:
    library: str
    toolchain: str
    flags: tuple[str, ...]  # (opt, gs, runtime)

    @property
    def name(self) -> str:
        tag = "".join(f.strip("/").replace("-", "n") for f in self.flags)
        return f"{self.library}-{self.toolchain}-{tag}"


@dataclass
class EvalOutcome:
    binary: str
    variant: str  # rich | stripped
    truth: str
    top: list[str]
    rank: int | None  # 1-based rank of the truth after anchor confirmation
    prior_rank: int | None
    anchors: int
    elapsed: float


@dataclass
class EvalReport:
    outcomes: list[EvalOutcome] = field(default_factory=list)

    def rate(self, k: int, variant: str | None = None) -> float:
        rows = [o for o in self.outcomes if variant is None or o.variant == variant]
        return sum(1 for o in rows if o.rank is not None and o.rank <= k) / max(1, len(rows))

    def summary(self) -> str:
        lines = [
            f"{len(self.outcomes)} evaluations: top-1 {self.rate(1):.1%}, top-3 {self.rate(3):.1%}",
        ]
        for v in ("rich", "stripped"):
            lines.append(f"  {v:8}: top-1 {self.rate(1, v):.1%}, top-3 {self.rate(3, v):.1%}")
        for o in self.outcomes:
            if o.rank != 1:
                lines.append(f"  miss {o.binary} [{o.variant}] rank={o.rank} truth={o.truth}")
                lines += [f"      {i + 1}. {t}" for i, t in enumerate(o.top[:3])]
        return "\n".join(lines)


def _label(toolchain: str, flags: tuple[str, ...]) -> str:
    return f"{toolchain} {' '.join(sorted(flags))}"


def sample_configs(n: int, seed: int, libraries: list[str]) -> list[EvalConfig]:
    rng = random.Random(seed)
    toolchains = sorted(load_registry())
    space = [
        EvalConfig(lib, tc, (o, g, r))
        for lib in libraries
        for tc in toolchains
        for o in OPTS
        for g in GSS
        for r in RUNTIMES
    ]
    return rng.sample(space, min(n, len(space)))


def _exports(tus: list[CorpusTU]) -> list[str]:
    counts: Counter[str] = Counter()
    for tu in tus:
        for d in function_definitions(tu.text()):
            if not d.is_static and not d.is_inline:
                counts[d.name] += 1
    return sorted(n for n, c in counts.items() if c == 1 and n != "main")


def build_binary(
    service: CompileService, cfg: EvalConfig, tus: list[CorpusTU]
) -> tuple[bytes, dict[str, int]]:
    files = {f"{Path(tu.tu).stem}.c": tu.text() for tu in tus}
    files["lib.def"] = "EXPORTS\n" + "".join(f"    {n}\n" for n in _exports(tus))
    args = [
        "/nologo",
        "/Gy",
        "/w",
        *cfg.flags,
        "/LD",
        *sorted(k for k in files if k.endswith(".c")),
        "/Felib.dll",
        "/link",
        "/DEF:lib.def",
        "/MAP:lib.map",
        "/Brepro",
        "/INCREMENTAL:NO",
    ]
    out = service.run_raw(files, args, "lib.dll", cfg.toolchain, timeout=900, outputs=("lib.map",))
    if not out.ok:
        raise RuntimeError(f"building {cfg.name} failed:\n{out.stdout[-3000:]}")
    image = parse_pe(out.obj)
    names: dict[str, int] = {}
    for line in out.outputs["lib.map"].decode("utf-8", "replace").splitlines():
        m = _MAP_LINE.match(line)
        if m:
            names.setdefault(m.group(1), int(m.group(2), 16) - image.image_base)
    return out.obj, names


def pick_anchors(
    data: bytes, names: dict[str, int], tus: list[CorpusTU], count: int, seed: int
) -> list[Anchor]:
    pe = parse_pe(data)
    fx = PEFunctions(pe)
    rva_owners = Counter(names.values())
    pool: list[tuple[Anchor, NormalizedFunction]] = []
    for tu in tus:
        cases, _ = split_tu(tu.text())
        gs_fns = gs_buffer_functions(tu.text())
        for c in cases:
            if _INLINE_DEF.match(c.source):  # header inline helpers are not library code
                continue
            rva = names.get(c.function)
            if rva is None or rva_owners[rva] != 1:  # missing or ICF-folded
                continue
            try:
                fn = normalize(extract_pe_function(pe, hex(rva), index=fx))
            except Exception:
                continue
            anchor = Anchor(hex(rva), c.function, c.source, c.context, tu.id, c.function in gs_fns)
            pool.append((anchor, fn))
    return select_anchors(pool, count, random.Random(seed))


def anchor_pool(data: bytes, names: dict[str, int], tus: list[CorpusTU]) -> list[Anchor]:
    """Every function usable as an anchor (for on-demand refinement)."""
    return pick_anchors(data, names, tus, 10**9, 0)


def run_eval(
    service: CompileService,
    db: dict[str, ToolchainRecord],
    *,
    n: int = 20,
    seed: int = 0,
    anchors: int = 30,
    confirm_top: int = 8,
    corpus_dir: Path = Path("datasets/corpus"),
    out_dir: Path = Path("datasets/fingerprint-eval"),
) -> EvalReport:
    corpora = {
        "/MT": load_corpus(corpus_dir),
        "/MD": load_corpus(corpus_dir.with_name(corpus_dir.name + "-md")),
    }
    libraries = sorted({tu.library for tu in corpora["/MT"]})
    out_dir.mkdir(parents=True, exist_ok=True)
    report = EvalReport()
    for cfg in sample_configs(n, seed, libraries):
        runtime = cfg.flags[2]
        tus = [
            tu for tu in corpora[runtime] if tu.library == cfg.library and tu.id not in EXCLUDE_TUS
        ]
        data, names = build_binary(service, cfg, tus)
        (out_dir / f"{cfg.name}.dll").write_bytes(data)
        truth = _label(cfg.toolchain, cfg.flags)
        for variant, blob in (("rich", data), ("stripped", strip_rich(data))):
            t0 = time.monotonic()
            rep = fingerprint(blob, db)
            # Anchors are compiled from TUs preprocessed for the runtime the binary imports.
            anchor_tus = [
                tu
                for tu in corpora[rep.flags.runtime]
                if tu.library == cfg.library and tu.id not in EXCLUDE_TUS
            ]
            picked = pick_anchors(blob, names, anchor_tus, anchors, seed)
            prior = [_label(c.toolchain, c.flags) for c in rep.candidates]
            ranked = confirm(blob, rep.candidates, picked, service, top=confirm_top)
            labels = [_label(c.toolchain, c.flags) for c in ranked]
            report.outcomes.append(
                EvalOutcome(
                    cfg.name,
                    variant,
                    truth,
                    labels[:5],
                    labels.index(truth) + 1 if truth in labels else None,
                    prior.index(truth) + 1 if truth in prior else None,
                    len(picked),
                    time.monotonic() - t0,
                )
            )
            o = report.outcomes[-1]
            print(
                f"{cfg.name:40} {variant:8} rank={o.rank} prior={o.prior_rank} "
                f"anchors={o.anchors} {o.elapsed:.0f}s",
                flush=True,
            )
    (out_dir / "report.json").write_text(
        json.dumps([asdict(o) for o in report.outcomes], indent=1), encoding="utf-8"
    )
    return report


# ---------------------------------------------------------------------------------------------
# Mixed-compiler binaries (Phase 2.3: per-address-range assignment)

_INCOMPATIBLE = {frozenset({"zlib", "miniz"})}  # miniz re-defines the zlib API


@dataclass
class MixedOutcome:
    binary: str
    variant: str
    truth: dict[str, str]  # library -> config label
    predicted: dict[str, str]  # library -> majority config over its functions
    function_accuracy: float  # share of functions whose range has the right config
    ranges: list[str]

    @property
    def ok(self) -> bool:
        return self.truth == self.predicted


def _compile_objects(
    service: CompileService, cfg: EvalConfig, tus: list[CorpusTU]
) -> dict[str, bytes]:
    files = {f"{cfg.library}_{Path(tu.tu).stem}.c": tu.text() for tu in tus}
    objs = tuple(k[:-2] + ".obj" for k in files)
    args = ["/nologo", "/c", "/Gy", "/w", *cfg.flags, *sorted(files)]
    out = service.run_raw(files, args, objs[0], cfg.toolchain, timeout=900, outputs=objs)
    if not out.ok:
        raise RuntimeError(f"compiling {cfg.name} failed:\n{out.stdout[-3000:]}")
    return out.outputs


def build_mixed_binary(
    service: CompileService, a: EvalConfig, b: EvalConfig, tus: dict[str, list[CorpusTU]]
) -> tuple[bytes, dict[str, int]]:
    """Library `a` plays the prebuilt static library; the image is linked by `b`'s toolchain."""
    objs = {
        **_compile_objects(service, a, tus[a.library]),
        **_compile_objects(service, b, tus[b.library]),
    }
    files = {
        "lib.def": "EXPORTS\n"
        + "".join(f"    {n}\n" for n in _exports(tus[a.library] + tus[b.library]))
    }
    args = [
        "/nologo",
        *sorted(objs),
        "/LD",
        "/Felib.dll",
        "/link",
        "/DEF:lib.def",
        "/MAP:lib.map",
        "/Brepro",
        "/INCREMENTAL:NO",
    ]
    out = service.run_raw(
        files, args, "lib.dll", b.toolchain, timeout=900, outputs=("lib.map",), binary_files=objs
    )
    if not out.ok:
        raise RuntimeError(f"linking {a.name}+{b.name} failed:\n{out.stdout[-3000:]}")
    image = parse_pe(out.obj)
    names: dict[str, int] = {}
    for line in out.outputs["lib.map"].decode("utf-8", "replace").splitlines():
        m = _MAP_LINE.match(line)
        if m:
            names.setdefault(m.group(1), int(m.group(2), 16) - image.image_base)
    return out.obj, names


def run_mixed_eval(
    service: CompileService,
    db: dict[str, ToolchainRecord],
    *,
    n: int = 6,
    seed: int = 0,
    anchors: int = 40,
    corpus_dir: Path = Path("datasets/corpus"),
    out_dir: Path = Path("datasets/fingerprint-eval"),
) -> list[MixedOutcome]:
    from simulacra.fingerprint.core import assign_ranges

    rng = random.Random(seed)
    corpora = {
        "/MT": load_corpus(corpus_dir),
        "/MD": load_corpus(corpus_dir.with_name(corpus_dir.name + "-md")),
    }
    libraries = sorted({tu.library for tu in corpora["/MT"]})
    toolchains = sorted(load_registry())
    outcomes: list[MixedOutcome] = []
    for _ in range(n):
        while True:
            la, lb = rng.sample(libraries, 2)
            if frozenset({la, lb}) not in _INCOMPATIBLE:
                break
        ta, tb = rng.sample(toolchains, 2)
        runtime = rng.choice(RUNTIMES)
        a = EvalConfig(la, ta, (rng.choice(OPTS), rng.choice(GSS), runtime))
        b = EvalConfig(lb, tb, (rng.choice(OPTS), rng.choice(GSS), runtime))
        tus = {
            lib: [tu for tu in corpora[runtime] if tu.library == lib and tu.id not in EXCLUDE_TUS]
            for lib in (la, lb)
        }
        data, names = build_mixed_binary(service, a, b, tus)
        tag = f"mixed-{a.name}+{b.name}"
        (out_dir / f"{tag}.dll").write_bytes(data)
        owner = {
            d.name: lib
            for lib in (la, lb)
            for tu in tus[lib]
            for d in function_definitions(tu.text())
        }
        truth = {la: _label(ta, a.flags), lb: _label(tb, b.flags)}
        for variant, blob in (("rich", data), ("stripped", strip_rich(data))):
            rep = fingerprint(blob, db, limit=400)
            anchor_tus = tus[la] + tus[lb]
            picked = pick_anchors(blob, names, anchor_tus, anchors, seed)
            ranges = assign_ranges(
                blob,
                rep.candidates,
                picked,
                service,
                pool=anchor_pool(blob, names, anchor_tus),
            )
            votes: dict[str, Counter[str]] = {la: Counter(), lb: Counter()}
            right = total = 0
            for fname, rva in names.items():
                lib = owner.get(fname)
                if lib is None:
                    continue
                hit = next((r for r in ranges if r.start <= rva < r.end), None)
                label = _label(hit.best.toolchain, hit.best.flags) if hit else "-"
                votes[lib][label] += 1
                total += 1
                right += label == truth[lib]
            predicted = {lib: v.most_common(1)[0][0] if v else "-" for lib, v in votes.items()}
            o = MixedOutcome(
                tag, variant, truth, predicted, right / max(1, total), [r.render() for r in ranges]
            )
            outcomes.append(o)
            print(
                f"{tag:70} {variant:8} ok={o.ok} fn-acc={o.function_accuracy:.0%} "
                f"ranges={len(ranges)}",
                flush=True,
            )
    (out_dir / "mixed-report.json").write_text(
        json.dumps([asdict(o) for o in outcomes], indent=1), encoding="utf-8"
    )
    return outcomes
