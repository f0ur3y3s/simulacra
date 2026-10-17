"""`fingerprint(binary)`: ranked (toolchain, flags) candidates with evidence."""

from __future__ import annotations

import itertools
import math
import random
import re
from collections import Counter
from dataclasses import dataclass, field

from mscmatch.compile import CompileRequest, CompileService
from mscmatch.disasm import NormalizedFunction, normalize
from mscmatch.fingerprint.db import ToolchainRecord, function_hashes
from mscmatch.fingerprint.heuristics import (
    FlagAnalysis,
    FunctionFeatures,
    analyze_flags,
    function_features,
)
from mscmatch.fingerprint.pdb import read_compilands
from mscmatch.fingerprint.rich import RichSummary, summarize
from mscmatch.harness import function_from_obj
from mscmatch.pe import PEFunctions, PEImage, extract_pe_function, parse_pe
from mscmatch.score import anonymize, score
from mscmatch.toolchain import load_registry

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

    def render(self, top: int = 10) -> str:
        lines = ["== version evidence", *("  " + e for e in self.version_evidence)]
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
            ev.append(f"{tcid}: no fingerprint DB (run `mscmatch fingerprint-db`)")
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
        name.split("!")[0].lower().startswith(_CRT_DLL_PREFIXES) or False
        for name in _import_dlls(pe)
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
    return FingerprintReport(
        rich, pe.linker_version, probs, vev, flags, cands, len(feats), crt, pdb_flags, warnings
    )


def _lib_builds(db: dict[str, ToolchainRecord]) -> set[int]:
    return set().union(*(set(r.lib_compiler_builds) for r in db.values())) if db else set()


def _import_dlls(pe: PEImage) -> set[str]:
    import struct

    rva, _ = pe.dir(1)
    dlls: set[str] = set()
    pos = rva
    while rva:
        oft, _ts, _fc, name_rva, ft = struct.unpack("<IIIII", pe.read(pos, 20))
        if not (oft or name_rva or ft):
            break
        dlls.add(pe.cstr(name_rva).decode("ascii", "replace"))
        pos += 20
    return dlls


def confirm(
    data: bytes,
    candidates: list[Candidate],
    anchors: list[Anchor],
    service: CompileService,
    top: int = 8,
) -> list[Candidate]:
    """Re-rank the top candidates by compiling anchor functions under each configuration."""
    pe = parse_pe(data)
    fx = PEFunctions(pe)
    targets = {}
    for a in anchors:
        try:
            targets[a.target] = anonymize(normalize(extract_pe_function(pe, a.target, index=fx)))
        except Exception:
            continue
    usable = [a for a in anchors if a.target in targets]
    head = candidates[:top]
    reqs = [
        (c, a, CompileRequest(a.source, a.context, a.function, c.toolchain, c.flags, timeout=120))
        for c in head
        for a in usable
    ]
    results = service.compile_many(r for _, _, r in reqs)
    per: dict[int, list[tuple[bool, float]]] = {id(c): [] for c in head}
    for (c, a, _), res in zip(reqs, results, strict=True):
        if not res.ok:
            per[id(c)].append((False, 0.0))
            continue
        try:
            cand = anonymize(function_from_obj(res.obj_bytes, a.function))
        except Exception:
            per[id(c)].append((False, 0.0))
            continue
        rep = score(targets[a.target], cand, max_diff_lines=0)
        per[id(c)].append((rep.exact, rep.score))
    for c in head:
        rows = per[id(c)]
        c.anchors = len(rows)
        c.exact = sum(e for e, _ in rows)
        c.mean_score = sum(s for _, s in rows) / len(rows) if rows else 0.0
    head.sort(key=lambda c: c.key(), reverse=True)
    return head + candidates[top:]


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
