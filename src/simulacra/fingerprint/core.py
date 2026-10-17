"""`fingerprint(binary)`: ranked (toolchain, flags) candidates with evidence."""

from __future__ import annotations

import itertools
import math
import random
import re
from collections import Counter
from dataclasses import dataclass, field

from simulacra.compile import CompileRequest, CompileService
from simulacra.disasm import NormalizedFunction, normalize
from simulacra.fingerprint.db import ToolchainRecord, function_hashes
from simulacra.fingerprint.heuristics import (
    FlagAnalysis,
    FunctionFeatures,
    analyze_flags,
    function_features,
)
from simulacra.fingerprint.pdb import read_compilands
from simulacra.fingerprint.producer import Producer, ProducerVerdict, identify_producer
from simulacra.fingerprint.rich import RichSummary, summarize
from simulacra.harness import function_from_obj
from simulacra.pe import PEFunctions, PEImage, extract_pe_function, parse_pe
from simulacra.score import anonymize, score
from simulacra.toolchain import load_registry

_CRT_DLL_PREFIXES = ("vcruntime", "ucrtbase", "api-ms-win-crt-", "msvcr", "msvcp")


@dataclass
class Candidate:
    toolchain: str
    flags: tuple[str, ...]
    prior: float
    exact: int = 0
    mean_score: float = 0.0
    anchors: int = 0

    def key(self) -> tuple[float, ...]:
        return (self.exact, self.mean_score, self.prior)

    def render(self) -> str:
        a = (
            f"  anchors {self.exact}/{self.anchors} exact, mean {self.mean_score:.3f}"
            if self.anchors
            else ""
        )
        return f"{self.toolchain:14} {' '.join(self.flags):32} prior={self.prior:.3f}{a}"


@dataclass
class Anchor:
    target: str  # PE function: exported name, sub_<VA> or hex RVA
    function: str  # name in `source`
    source: str
    context: str = ""
    group: str = ""
    gs_buffer: bool | None = None  # has a /GS-protected local (see cparse.gs_buffer_functions)


@dataclass
class FingerprintReport:
    rich: RichSummary
    linker_version: tuple[int, int]
    toolchain_probs: dict[str, float]
    version_evidence: list[str]
    flags: FlagAnalysis
    candidates: list[Candidate]
    user_functions: int
    crt_matches: dict[str, int] = field(default_factory=dict)
    pdb_flags: tuple[str, ...] | None = None
    warnings: list[str] = field(default_factory=list)
    producer: ProducerVerdict | None = None

    @property
    def refused(self) -> bool:
        """True when the image is confidently not MSVC output, so nothing can be matched."""
        return self.producer is not None and self.producer.producer in (
            Producer.MINGW_GCC,
            Producer.CLANG,
            Producer.NON_MSVC,
        )

    def render(self, top: int = 10) -> str:
        lines = ["== producer", "  " + self.producer.render()] if self.producer else []
        lines += ["== version evidence", *("  " + e for e in self.version_evidence)]
        lines.append(
            "  toolchain probabilities: "
            + ", ".join(
                f"{k}={v:.3f}"
                for k, v in sorted(self.toolchain_probs.items(), key=lambda kv: -kv[1])
            )
        )
        lines += ["== flag evidence", *("  " + e.render() for e in self.flags.evidence)]
        if self.pdb_flags is not None:
            lines.append(f"  PDB command line flags: {' '.join(self.pdb_flags)}")
        lines += ["== candidates"]
        lines += [f"  {i + 1:2}. {c.render()}" for i, c in enumerate(self.candidates[:top])]
        lines += [f"!! {w}" for w in self.warnings]
        return "\n".join(lines)


def _softmax(scores: dict[str, float]) -> dict[str, float]:
    if not scores:
        return {}
    m = max(scores.values())
    exp = {k: math.exp(v - m) for k, v in scores.items()}
    tot = sum(exp.values())
    return {k: v / tot for k, v in exp.items()}


def _version_scores(
    pe: PEImage,
    rich: RichSummary,
    db: dict[str, ToolchainRecord],
    hashes: dict[int, str],
) -> tuple[dict[str, float], list[str], dict[str, int]]:
    reg = load_registry()
    scores: dict[str, float] = {}
    ev: list[str] = []
    all_sig_owner: dict[str, set[str]] = {}
    for rec in db.values():
        for h in rec.signatures:
            all_sig_owner.setdefault(h, set()).add(rec.toolchain)
    target_hashes = set(hashes.values())
    crt_matches = {}
    for tcid, rec in db.items():
        s = 0.0
        notes = []
        if pe.linker_version == rec.link_version:
            s += 2.0
            notes.append(f"linker {pe.linker_version[0]}.{pe.linker_version[1]} matches")
        if rich.present:
            user = rich.compiler_builds(exclude=set(rec.lib_compiler_builds))
            if rec.cl_build in user:
                s += 5.0
                notes.append(f"Rich: {user[rec.cl_build]} objects from cl build {rec.cl_build}")
            elif rec.cl_build in rich.compilers:
                s += 1.0
            if set(rich.linker_builds) & set(rec.link_builds):
                s += 3.0
                notes.append("Rich linker build matches")
        uniq = sum(1 for h in target_hashes if all_sig_owner.get(h) == {tcid})
        shared = sum(1 for h in target_hashes if tcid in all_sig_owner.get(h, ()))
        crt_matches[tcid] = shared
        s += min(4.0, 0.5 * uniq)
        notes.append(f"CRT signatures: {shared} matched, {uniq} unique to this toolchain")
        scores[tcid] = s
        ev.append(f"{tcid}: score {s:.1f} ({'; '.join(notes)})")
    for tcid in reg:
        if tcid not in db:
            ev.append(f"{tcid}: no fingerprint DB (run `simulacra fingerprint-db`)")
    if rich.present:
        ev.append(
            "Rich compilers: "
            + ", ".join(f"{b}:{sum(v.values())}" for b, v in sorted(rich.compilers.items()))
            + f"; linkers: {rich.linker_builds}"
        )
    else:
        ev.append("Rich header absent or stripped")
    return scores, ev, crt_matches


def _user_features(
    pe: PEImage, fx: PEFunctions, hashes: dict[int, str], db: dict[str, ToolchainRecord]
) -> list[FunctionFeatures]:
    known = set().union(*(set(r.signatures) for r in db.values())) if db else set()
    feats = []
    for rva in sorted(fx.groups):
        if hashes.get(rva) in known:
            continue
        try:
            fn = normalize(extract_pe_function(pe, hex(rva), index=fx))
        except Exception:
            continue
        if len(fn.insns) >= 3:
            feats.append(function_features(fn))
    return feats


def _expand(flags: FlagAnalysis, probs: dict[str, float], limit: int) -> list[Candidate]:
    extra_choices: list[list[tuple[tuple[str, ...], float]]] = []
    for flag, p in flags.extras.items():
        if p >= 0.8:
            extra_choices.append([((flag,), p)])
        elif p <= 0.2:
            extra_choices.append([((), 1 - p)])
        else:
            extra_choices.append([((flag,), p), ((), 1 - p)])
    out = []
    for (tc, pt), (opt, po), (gs, pg) in itertools.product(
        probs.items(), flags.opt.items(), flags.gs.items()
    ):
        for combo in itertools.product(*extra_choices) if extra_choices else [()]:
            extra = tuple(f for fl, _ in combo for f in fl)
            pe = math.prod(p for _, p in combo) if combo else 1.0
            out.append(Candidate(tc, (opt, gs, flags.runtime, *extra), pt * po * pg * pe))
    out.sort(key=lambda c: -c.prior)
    return out[:limit]


def fingerprint(
    data: bytes,
    db: dict[str, ToolchainRecord],
    *,
    pdb: bytes | None = None,
    limit: int = 24,
) -> FingerprintReport:
    pe = parse_pe(data)
    fx = PEFunctions(pe)
    rich = summarize(pe.rich)
    hashes = function_hashes(pe, fx)
    vscores, vev, crt = _version_scores(pe, rich, db, hashes)
    warnings: list[str] = []
    producer = identify_producer(pe, max(crt.values(), default=0))

    pdb_flags = None
    if pdb is not None:
        comps = [c for c in read_compilands(pdb) if c.command]
        if comps:
            cmd_counts = Counter(c.codegen_flags() for c in comps)
            pdb_flags = cmd_counts.most_common(1)[0][0]
            builds = Counter(c.backend_build for c in comps)
            for tcid in vscores:
                if db[tcid].cl_build in builds:
                    vscores[tcid] += 20.0
            vev.append(f"PDB: {len(comps)} compilands, backend builds {dict(builds)}")
            if len(cmd_counts) > 1:
                warnings.append(f"PDB lists {len(cmd_counts)} distinct flag sets across objects")

    probs = _softmax(vscores) if vscores else {}
    imports_dll = any(
        name.split("!")[0].lower().startswith(_CRT_DLL_PREFIXES) or False for name in pe.import_dlls
    )
    feats = _user_features(pe, fx, hashes, db)
    flags = analyze_flags(
        feats,
        guard_flags=pe.load_config.get("GuardFlags", 0),
        imports_crt_dll=imports_dll,
        rich_ltcg=rich.ltcg,
    )
    if rich.present and len(rich.compiler_builds(exclude=_lib_builds(db))) > 1:
        warnings.append("multiple compiler builds in Rich header (prebuilt static libs?)")
    if flags.ltcg_suspected:
        warnings.append("LTCG (/GL) binary: per-function matching will be degraded")

    if pdb_flags is not None:
        best = max(probs, key=lambda k: probs[k]) if probs else ""
        cands = [Candidate(best, pdb_flags, 1.0)]
    else:
        cands = _expand(flags, probs, limit)
    if producer.producer in (Producer.MINGW_GCC, Producer.CLANG, Producer.NON_MSVC):
        warnings.insert(
            0,
            f"not built by MSVC ({producer.producer.value}, p={producer.confidence:.2f}): "
            "simulacra cannot match this image; no candidates",
        )
        cands = []
    elif producer.producer is Producer.UNKNOWN:
        warnings.append("toolchain family unclear; MSVC candidates may not apply")
    return FingerprintReport(
        rich,
        pe.linker_version,
        probs,
        vev,
        flags,
        cands,
        len(feats),
        crt,
        pdb_flags,
        warnings,
        producer,
    )


def _lib_builds(db: dict[str, ToolchainRecord]) -> set[int]:
    return set().union(*(set(r.lib_compiler_builds) for r in db.values())) if db else set()


@dataclass
class AnchorMatrix:
    """Exactness and score of every usable anchor under every candidate configuration."""

    anchors: list[Anchor]  # usable anchors, sorted by target RVA
    rvas: list[int]
    candidates: list[Candidate]
    results: list[list[tuple[bool, float]]]  # [candidate][anchor]

    def rank(self, anchor_idx: list[int]) -> list[Candidate]:
        """Candidates ranked over a subset of anchors (copies, with counts filled in)."""
        out = []
        for ci, c in enumerate(self.candidates):
            rows = [self.results[ci][ai] for ai in anchor_idx]
            out.append(
                Candidate(
                    c.toolchain,
                    c.flags,
                    c.prior,
                    exact=sum(e for e, _ in rows),
                    mean_score=sum(sc for _, sc in rows) / len(rows) if rows else 0.0,
                    anchors=len(rows),
                )
            )
        out.sort(key=lambda c: c.key(), reverse=True)
        return out

    def exact_set(self, ai: int) -> frozenset[int]:
        """Candidates reproducing anchor `ai` exactly, else those tied for its best score."""
        exact = frozenset(ci for ci in range(len(self.candidates)) if self.results[ci][ai][0])
        if exact:
            return exact
        best = max(self.results[ci][ai][1] for ci in range(len(self.candidates)))
        return frozenset(
            ci for ci in range(len(self.candidates)) if self.results[ci][ai][1] >= best - 1e-9
        )


def anchor_matrix(
    data: bytes, candidates: list[Candidate], anchors: list[Anchor], service: CompileService
) -> AnchorMatrix:
    pe = parse_pe(data)
    fx = PEFunctions(pe)
    targets: dict[str, NormalizedFunction] = {}
    rvas: dict[str, int] = {}
    for a in anchors:
        try:
            targets[a.target] = anonymize(normalize(extract_pe_function(pe, a.target, index=fx)))
            rvas[a.target] = fx.resolve(a.target)
        except Exception:
            continue
    usable = sorted((a for a in anchors if a.target in targets), key=lambda a: rvas[a.target])
    reqs = [
        CompileRequest(a.source, a.context, a.function, c.toolchain, c.flags, timeout=120)
        for c in candidates
        for a in usable
    ]
    flat: list[tuple[bool, float]] = []
    for req, res in zip(reqs, service.compile_many(reqs), strict=True):
        if not res.ok:
            flat.append((False, 0.0))
            continue
        try:
            cand = anonymize(function_from_obj(res.obj_bytes, req.function_name))
        except Exception:
            flat.append((False, 0.0))
            continue
        target = targets[usable[len(flat) % len(usable)].target]
        rep = score(target, cand, max_diff_lines=0)
        flat.append((rep.exact, rep.score))
    n = len(usable)
    results = [flat[i * n : (i + 1) * n] for i in range(len(candidates))]
    return AnchorMatrix(usable, [rvas[a.target] for a in usable], list(candidates), results)


def confirm(
    data: bytes,
    candidates: list[Candidate],
    anchors: list[Anchor],
    service: CompileService,
    top: int = 8,
) -> list[Candidate]:
    """Re-rank the top candidates by compiling anchor functions under each configuration."""
    head = candidates[:top]
    m = anchor_matrix(data, head, anchors, service)
    return m.rank(list(range(len(m.anchors)))) + candidates[top:]


@dataclass
class RangeAssignment:
    start: int  # RVA, inclusive
    end: int  # RVA, exclusive
    ranked: list[Candidate]  # best first, counted over this range's anchors
    anchor_names: list[str]

    @property
    def best(self) -> Candidate:
        return self.ranked[0]

    def render(self) -> str:
        return (
            f"[{self.start:#x}, {self.end:#x})  {len(self.anchor_names)} anchors  "
            f"-> {self.best.render()}"
        )


def _range_head(candidates: list[Candidate], per_toolchain: int) -> list[Candidate]:
    """Candidates for range assignment: the best `per_toolchain` of every toolchain, so a
    compiler the global prior all but rules out (a prebuilt library's) still competes."""
    head: list[Candidate] = []
    counts: dict[str, int] = {}
    for c in candidates:
        if counts.get(c.toolchain, 0) < per_toolchain:
            head.append(c)
            counts[c.toolchain] = counts.get(c.toolchain, 0) + 1
    return head


def segment(m: AnchorMatrix, min_anchors: int = 2) -> list[list[int]]:
    """Split anchors (address order) into runs that one configuration explains.

    Greedy: extend the current run while some candidate reproduces every anchor in it; start a
    new run when none does. Runs shorter than `min_anchors` are noise (one odd function) and are
    folded into their predecessor.
    """
    runs: list[list[int]] = []
    current: frozenset[int] = frozenset()
    for ai in range(len(m.anchors)):
        s = m.exact_set(ai)
        if runs and current & s:
            runs[-1].append(ai)
            current &= s
        else:
            runs.append([ai])
            current = s
    merged: list[list[int]] = []
    for run in runs:
        if merged and len(run) < min_anchors:
            merged[-1].extend(run)
        else:
            merged.append(run)
    if len(merged) > 1 and len(merged[0]) < min_anchors:
        merged[1] = merged[0] + merged[1]
        merged.pop(0)
    # Neighbouring runs that ended up with the same best configuration are one range.
    out: list[list[int]] = []
    for run in merged:
        if out and _same_best(m, out[-1], run):
            out[-1].extend(run)
        else:
            out.append(run)
    return out


def _same_best(m: AnchorMatrix, a: list[int], b: list[int]) -> bool:
    ra, rb = m.rank(a)[0], m.rank(b)[0]
    return (ra.toolchain, ra.flags) == (rb.toolchain, rb.flags)


def _tied(ranked: list[Candidate]) -> list[Candidate]:
    """Candidates indistinguishable from the best one on the anchors seen so far."""
    top = ranked[0]
    return [c for c in ranked if c.exact == top.exact and abs(c.mean_score - top.mean_score) < 1e-9]


def _refine(
    data: bytes,
    r: RangeAssignment,
    pool: list[tuple[Anchor, int]],
    used: set[str],
    service: CompileService,
    per_round: int,
    min_anchors: int,
) -> RangeAssignment:
    """Pull extra anchors from inside the range until its best configuration is unique (or the
    pool runs out). GS-buffer anchors go first when the tied configurations differ in /GS."""
    for _ in range(3):
        tied = _tied(r.ranked)
        if len(tied) < 2 and len(r.anchor_names) >= min_anchors:
            return r
        inside = [a for a, rva in pool if r.start <= rva < r.end and a.target not in used]
        if not inside:
            return r
        gs_split = len({("/GS" in c.flags) for c in tied}) > 1
        inside.sort(key=lambda a: (not (gs_split and a.gs_buffer), len(a.source)))
        extra = inside[:per_round]
        used.update(a.target for a in extra)
        contenders = tied if len(tied) > 1 else r.ranked[: max(4, len(tied))]
        m = anchor_matrix(data, contenders, extra, service)
        if not m.anchors:
            return r
        fresh = {(c.toolchain, c.flags): c for c in m.rank(list(range(len(m.anchors))))}
        merged = []
        for c in r.ranked:
            f = fresh.get((c.toolchain, c.flags))
            if f is None:
                # Not re-tested: count the new anchors as unknown (neither exact nor scored).
                merged.append(
                    Candidate(
                        c.toolchain,
                        c.flags,
                        c.prior,
                        c.exact,
                        c.mean_score * c.anchors / (c.anchors + len(m.anchors)),
                        c.anchors + len(m.anchors),
                    )
                )
                continue
            n = c.anchors + f.anchors
            merged.append(
                Candidate(
                    c.toolchain,
                    c.flags,
                    c.prior,
                    c.exact + f.exact,
                    (c.mean_score * c.anchors + f.mean_score * f.anchors) / n,
                    n,
                )
            )
        merged.sort(key=lambda c: c.key(), reverse=True)
        r = RangeAssignment(
            r.start, r.end, merged, r.anchor_names + [a.function for a in m.anchors]
        )
    return r


def assign_ranges(
    data: bytes,
    candidates: list[Candidate],
    anchors: list[Anchor],
    service: CompileService,
    *,
    ranges: list[tuple[int, int]] | None = None,
    per_toolchain: int = 6,
    pool: list[Anchor] | None = None,
    per_round: int = 8,
    min_anchors: int = 8,
) -> list[RangeAssignment]:
    """Per-address-range configurations (CLAUDE.md Phase 2.3: binaries mixing compilers, e.g.
    prebuilt static libraries). With explicit `ranges`, each gets its own ranking; otherwise
    the ranges are found from where the anchors' best configuration changes.

    `pool` holds further anchors that may be compiled on demand. Any range whose best
    configurations still tie, or that has fewer than `min_anchors`, draws more from the pool
    functions inside it."""
    m = anchor_matrix(data, _range_head(candidates, per_toolchain), anchors, service)
    if not m.anchors:
        return []
    names = [a.function for a in m.anchors]
    out: list[RangeAssignment] = []
    if ranges is not None:
        for lo, hi in ranges:
            idx = [i for i, r in enumerate(m.rvas) if lo <= r < hi]
            if idx:
                out.append(RangeAssignment(lo, hi, m.rank(idx), [names[i] for i in idx]))
    else:
        runs = segment(m)
        end_of_image = max(s.rva + max(s.vsize, s.raw_size) for s in parse_pe(data).sections)
        for k, run in enumerate(runs):
            lo = 0 if k == 0 else (m.rvas[runs[k - 1][-1]] + m.rvas[run[0]]) // 2
            hi = (
                end_of_image
                if k == len(runs) - 1
                else (m.rvas[run[-1]] + m.rvas[runs[k + 1][0]]) // 2
            )
            out.append(RangeAssignment(lo, hi, m.rank(run), [names[i] for i in run]))
    if pool:
        fx = PEFunctions(parse_pe(data))
        located: list[tuple[Anchor, int]] = []
        for a in pool:
            try:
                located.append((a, fx.resolve(a.target)))
            except Exception:
                continue
        used = {a.target for a in m.anchors}
        out = [_refine(data, r, located, used, service, per_round, min_anchors) for r in out]
    return out


_STACK_ADDR = re.compile(r"^lea \w+, \[(?:rsp|rbp)\+0x[0-9a-f]+\]$")
_ALLOC = re.compile(r"^sub rsp, (0x[0-9a-f]+)$")


# A local (automatic) array declaration inside a function body: what makes MSVC emit a /GS
# cookie. `static` arrays live in .data and never do.
_LOCAL_ARRAY = re.compile(r"[;{]\s*(?:(?!static\b)\w+\s+)+\**\s*\w+\s*\[([^\]\n]+)\]\s*[;=]")
_CONST_EXPR = re.compile(r"^[\d\s+\-*/()]+$")


def _has_gs_buffer(body: str) -> bool:
    """MSVC only protects arrays of two or more elements; `[1]` scratch bytes never count."""
    for m in _LOCAL_ARRAY.finditer(body):
        size = m.group(1)
        if _CONST_EXPR.match(size):
            try:
                if eval(size, {"__builtins__": {}}) < 2:
                    continue
            except (SyntaxError, ZeroDivisionError):
                pass
        return True
    return False


def anchor_category(fn: NormalizedFunction, source: str = "") -> str:
    """'buffer' for functions with stack arrays (the only code where /GS changes anything),
    else 'simple'. Uses the anchor's source when available, plus the target's code."""
    body = source[source.find("{") :] if source else ""
    if body and _has_gs_buffer(body):
        return "buffer"
    texts = [i.text for i in fn.insns if not i.is_data]
    if any("<sym:__security_cookie>" in t for t in texts):
        return "buffer"
    alloc = max((int(m.group(1), 16) for t in texts if (m := _ALLOC.match(t))), default=0)
    if alloc >= 0x48 and any(_STACK_ADDR.match(t) for t in texts):
        return "buffer"
    return "simple"


def select_anchors(
    pool: list[tuple[Anchor, NormalizedFunction]], count: int, rng: random.Random
) -> list[Anchor]:
    """Mix small simple functions (most informative for opt level / toolchain) with about a
    third that have stack buffers (the only ones that can tell /GS from /GS-)."""

    def category(a: Anchor, fn: NormalizedFunction) -> str:
        if a.gs_buffer is not None:
            return "buffer" if a.gs_buffer else "simple"
        return anchor_category(fn, a.source)

    cats = [(a, fn, category(a, fn)) for a, fn in pool]
    simple = [a for a, fn, c in cats if c == "simple" and 8 <= len(fn.insns) <= 80]
    # GS-relevant functions are rare (often a handful per library): take the smallest ones
    # deterministically rather than leaving them to chance.
    buffer = sorted(
        ((a, fn) for a, fn, c in cats if c == "buffer" and len(fn.insns) <= 400),
        key=lambda t: len(t[1].insns),
    )
    picked = [a for a, _ in buffer[: count // 3]]
    picked += rng.sample(simple, min(len(simple), count - len(picked)))
    return picked
