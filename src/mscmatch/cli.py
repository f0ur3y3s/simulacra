"""`mscmatch <command>` entry point."""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

from mscmatch.toolchain import DEFAULT_TOOLCHAIN

Handler = Callable[[argparse.Namespace], int]
_COMMANDS: dict[str, Handler] = {}


def _flags(ns: argparse.Namespace) -> tuple[str, ...]:
    return tuple(shlex.split(ns.flags, posix=False)) if ns.flags else ()


def _service(ns: argparse.Namespace) -> object:
    from mscmatch.compile import CompileService

    return CompileService(
        workers=getattr(ns, "workers", None),
        cache=not getattr(ns, "no_cache", False),
        backend=getattr(ns, "backend", "docker"),
    )


def _add_compile_opts(p: argparse.ArgumentParser) -> None:
    p.add_argument("--toolchain", default=DEFAULT_TOOLCHAIN)
    p.add_argument("--flags", default="/O2", help='cl flags, e.g. "/O2 /GS-"')
    p.add_argument("--context", type=Path, help="context header (force-included)")
    p.add_argument("--workers", type=int)
    p.add_argument("--backend", choices=["docker", "native"], default="docker")
    p.add_argument("--no-cache", action="store_true")


def cmd_toolchain(ns: argparse.Namespace) -> int:
    from mscmatch.compile.backend import docker_cli
    from mscmatch.toolchain import build_args, get_toolchain, load_registry

    if ns.action == "prune":
        from mscmatch.compile.backend import prune_workers

        print(f"removed {prune_workers()} worker containers")
        return 0
    if ns.action == "list":
        for tc in load_registry().values():
            print(f"{tc.id:16} cl {tc.cl_version}  sdk {tc.sdk_version}  image {tc.image}")
        return 0
    tc = get_toolchain(ns.id or DEFAULT_TOOLCHAIN)
    return subprocess.call([docker_cli(), *build_args(tc)])


def cmd_compile(ns: argparse.Namespace) -> int:
    from mscmatch.compile import CompileRequest, CompileService
    from mscmatch.harness import function_from_obj

    svc = _service(ns)
    assert isinstance(svc, CompileService)
    with svc:
        ctx = ns.context.read_text(encoding="utf-8") if ns.context else ""
        src = ns.source.read_text(encoding="utf-8")
        res = svc.compile(CompileRequest(src, ctx, ns.function or "", ns.toolchain, _flags(ns)))
    if res.stderr:
        print(res.stderr, file=sys.stderr)
    if not res.ok:
        return 1
    if ns.output:
        ns.output.write_bytes(res.obj_bytes)
    print(f"; compiled in {res.elapsed:.2f}s{' (cached)' if res.cached else ''}", file=sys.stderr)
    if ns.function:
        print(function_from_obj(res.obj_bytes, ns.function).listing())
    return 0


def cmd_disasm(ns: argparse.Namespace) -> int:
    from mscmatch.coff import list_functions, parse_coff
    from mscmatch.disasm import UnwindMode
    from mscmatch.harness import load_target

    if ns.list:
        if ns.file.suffix.lower() == ".obj":
            print("\n".join(list_functions(parse_coff(ns.file.read_bytes()))))
        else:
            from mscmatch.pe import list_pe_functions

            for name in list_pe_functions(ns.file.read_bytes()):
                print(name)
        return 0
    fn = load_target(ns.file, ns.function, unwind=UnwindMode(ns.unwind))
    print(fn.listing())
    return 0


def cmd_diff(ns: argparse.Namespace) -> int:
    from mscmatch.compile import CompileService
    from mscmatch.disasm import UnwindMode
    from mscmatch.harness import load_target
    from mscmatch.score import anonymize, score

    svc = _service(ns)
    assert isinstance(svc, CompileService)
    unwind = UnwindMode(ns.unwind)
    ctx = ns.context.read_text(encoding="utf-8") if ns.context else ""
    flags = _flags(ns)
    with svc:
        t = load_target(
            ns.target, ns.target_function or ns.function, service=svc, flags=flags,
            context=ctx, toolchain_id=ns.toolchain, unwind=unwind,
        )  # fmt: skip
        c = load_target(
            ns.candidate, ns.function, service=svc, flags=flags,
            context=ctx, toolchain_id=ns.toolchain, unwind=unwind,
        )  # fmt: skip
    if ns.anonymize:
        t, c = anonymize(t), anonymize(c)
    rep = score(t, c, max_diff_lines=ns.max_lines, compare_unwind=unwind is not UnwindMode.NONE)
    if ns.json:
        print(json.dumps({k: v for k, v in vars(rep).items()}, indent=2))
    else:
        print(rep.diff_text)
        print(rep.summary())
    return 0 if rep.exact else 2


def _parse_flagsets(spec: str | None) -> dict[str, tuple[str, ...]]:
    from mscmatch.toolchain import load_flagsets

    all_sets = load_flagsets()
    if not spec:
        return all_sets
    return {name: all_sets[name] for name in spec.split(",")}


def cmd_corpus(ns: argparse.Namespace) -> int:
    from mscmatch.compile import CompileService
    from mscmatch.data.corpus import build_corpus

    with CompileService(workers=1) as svc:
        libs = ns.libraries.split(",") if ns.libraries else None
        if ns.runtime == "md":
            tus = build_corpus(
                svc,
                ns.dir.with_name(ns.dir.name + "-md"),
                ns.toolchain,
                libs,
                ("/MD",),
                downloads=ns.dir / "_downloads",
            )
        else:
            tus = build_corpus(svc, ns.dir, ns.toolchain, libs)
    print(f"{len(tus)} translation units")
    return 0


def cmd_roundtrip(ns: argparse.Namespace) -> int:
    from mscmatch.acceptance import report_json, roundtrip
    from mscmatch.compile import CompileService
    from mscmatch.data.corpus import load_corpus

    corpus = load_corpus(ns.corpus)
    with CompileService(workers=ns.workers) as svc:
        rep = roundtrip(svc, corpus, _flags(ns), ns.toolchain, ns.sample or None, ns.seed)
    print(rep.summary())
    if ns.output:
        ns.output.write_text(report_json(rep), encoding="utf-8")
    for f in rep.failures[: ns.show]:
        print(f"--- {f.tu}:{f.function} compiled={f.compiled} score={f.score:.3f}")
        print(f.note[:3000])
    return 0 if rep.exact_rate >= ns.threshold else 1


def cmd_equiv_manifest(ns: argparse.Namespace) -> int:
    from mscmatch.acceptance import equivalence_manifest
    from mscmatch.compile import CompileService
    from mscmatch.data.corpus import load_corpus

    corpus = load_corpus(ns.corpus)
    with CompileService(workers=ns.workers, cache=not ns.no_cache, backend=ns.backend) as svc:
        man = equivalence_manifest(svc, corpus, _parse_flagsets(ns.flagsets), ns.toolchain)
    ns.output.write_text(json.dumps(man, indent=1), encoding="utf-8")
    print(f"{man['function_count']} functions, {len(man['errors'])} TU errors -> {ns.output}")  # type: ignore[arg-type]
    return 0 if not man["errors"] else 1


def cmd_verify_toolchain(ns: argparse.Namespace) -> int:
    from mscmatch.acceptance import verify_manifests

    rep = verify_manifests(ns.a, ns.b)
    print(rep.summary())
    return 0 if rep.ok else 1


def cmd_bench(ns: argparse.Namespace) -> int:
    from mscmatch.acceptance import bench
    from mscmatch.data.corpus import load_corpus

    rows = bench([int(x) for x in ns.workers_list.split(",")], load_corpus(ns.corpus),
                 _flags(ns), ns.jobs, ns.toolchain)  # fmt: skip
    for r in rows:
        print(f"workers={r['workers']:3.0f}  jobs={r['jobs']:.0f}  ok={r['ok']:.0f}  "
              f"{r['seconds']:7.1f}s  {r['compiles_per_sec']:6.2f} compiles/s")  # fmt: skip
    if ns.output:
        ns.output.write_text(json.dumps(rows, indent=2), encoding="utf-8")
    return 0


def cmd_fingerprint_db(ns: argparse.Namespace) -> int:
    from mscmatch.compile import CompileService
    from mscmatch.fingerprint import build_db

    with CompileService(workers=2) as svc:
        for rec in build_db(svc, ns.toolchains.split(",") if ns.toolchains else None, ns.dir):
            print(
                f"{rec.toolchain}: linker {rec.link_version}, {len(rec.signatures)} CRT sigs, "
                f"lib builds {rec.lib_compiler_builds}"
            )
    return 0


def cmd_fingerprint(ns: argparse.Namespace) -> int:
    from mscmatch.compile import CompileService
    from mscmatch.fingerprint import Anchor, confirm, fingerprint, load_db

    db = load_db(ns.db)
    if not db:
        print("no fingerprint DB; run `mscmatch fingerprint-db` first", file=sys.stderr)
        return 1
    from mscmatch.fingerprint.core import RangeAssignment, assign_ranges

    data = ns.binary.read_bytes()
    want_ranges = ns.ranges is not None
    rep = fingerprint(
        data, db, pdb=ns.pdb.read_bytes() if ns.pdb else None, limit=400 if want_ranges else 24
    )
    if want_ranges and not ns.anchors:
        print("--ranges needs --anchors", file=sys.stderr)
        return 2
    ranges: list[RangeAssignment] = []
    if ns.anchors:
        anchors = [
            Anchor(**json.loads(line))
            for line in ns.anchors.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        with CompileService(workers=ns.workers) as svc:
            if want_ranges:
                explicit = None if ns.ranges == "auto" else _parse_ranges(ns.ranges)
                ranges = assign_ranges(data, rep.candidates, anchors, svc, ranges=explicit)
            else:
                rep.candidates = confirm(data, rep.candidates, anchors, svc, top=ns.confirm_top)
    if ns.json:
        print(
            json.dumps(
                {
                    "toolchain_probs": rep.toolchain_probs,
                    "candidates": [vars(c) for c in rep.candidates[: ns.top]],
                    "ranges": [
                        {
                            "start": r.start,
                            "end": r.end,
                            "anchors": r.anchor_names,
                            "best": vars(r.best),
                        }
                        for r in ranges
                    ],
                    "evidence": [vars(e) for e in rep.flags.evidence],
                    "version_evidence": rep.version_evidence,
                    "warnings": rep.warnings,
                    "producer": {
                        "family": rep.producer.producer.value if rep.producer else None,
                        "confidence": rep.producer.confidence if rep.producer else None,
                        "evidence": rep.producer.evidence if rep.producer else [],
                    },
                },
                indent=2,
            )
        )
    else:
        print(rep.render(top=0 if ranges else ns.top))
        if ranges:
            print("== ranges")
            for r in ranges:
                print("  " + r.render())
    return 3 if rep.refused else 0


def _parse_ranges(spec: str) -> list[tuple[int, int]]:
    """'0x1000-0x8000,0x8000-0x20000' (RVAs) -> [(start, end), ...]"""
    out = []
    for part in spec.split(","):
        lo, _, hi = part.partition("-")
        out.append((int(lo, 0), int(hi, 0)))
    return out


def cmd_fingerprint_eval(ns: argparse.Namespace) -> int:
    from mscmatch.compile import CompileService
    from mscmatch.fingerprint import load_db
    from mscmatch.fingerprint.evalset import run_eval

    if ns.mixed:
        from mscmatch.fingerprint.evalset import run_mixed_eval

        with CompileService(workers=ns.workers) as svc:
            outs = run_mixed_eval(svc, load_db(ns.db), n=ns.mixed, seed=ns.seed)
        good = sum(o.ok for o in outs)
        acc = sum(o.function_accuracy for o in outs) / max(1, len(outs))
        print(
            f"mixed: {good}/{len(outs)} binaries with every library assigned its config; "
            f"mean function accuracy {acc:.1%}"
        )
        for o in outs:
            if not o.ok:
                print(f"  miss {o.binary} [{o.variant}] truth={o.truth} predicted={o.predicted}")
                for r in o.ranges:
                    print(f"      {r}")
        return 0 if good == len(outs) else 1
    with CompileService(workers=ns.workers) as svc:
        rep = run_eval(svc, load_db(ns.db), n=ns.n, seed=ns.seed, anchors=ns.anchors)
    print(rep.summary())
    ok = rep.rate(1) >= 0.90 and rep.rate(3) >= 0.98
    print("PASS" if ok else "FAIL", "(target: top-1 >= 90%, top-3 >= 98%)")
    return 0 if ok else 1


def cmd_decomp(ns: argparse.Namespace) -> int:
    from mscmatch.compile.backend import docker_cli
    from mscmatch.decomp import GhidraDecompiler, GhidraError
    from mscmatch.decomp.ghidra import build_args

    if ns.build:
        return subprocess.call([docker_cli(), *build_args()])
    if ns.file is None:
        print("decomp: give a file, or --build", file=sys.stderr)
        return 2
    dec = GhidraDecompiler(use_cache=not ns.no_cache)
    try:
        res = dec.decompile(ns.file.read_bytes(), ns.file.name, ns.function or ())
    except GhidraError as e:
        print(e, file=sys.stderr)
        return 1
    if ns.json:
        print(res.to_json())
        return 0
    for f in res.functions:
        print(
            f"// {f.name} @ {f.entry:#x}  {f.signature}"
            + (f"  ERROR: {f.error}" if f.error else "")
        )
        print(f.pseudo_c(keep_warnings=ns.warnings))
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="mscmatch", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("toolchain", help="list or build toolchain images")
    p.add_argument("action", choices=["list", "build", "prune"])
    p.add_argument("id", nargs="?")
    p.set_defaults(fn=cmd_toolchain)

    p = sub.add_parser("compile", help="compile a C file; optionally print one function")
    p.add_argument("source", type=Path)
    p.add_argument("-f", "--function")
    p.add_argument("-o", "--output", type=Path)
    _add_compile_opts(p)
    p.set_defaults(fn=cmd_compile)

    p = sub.add_parser("disasm", help="normalized disassembly of a function in .obj / PE")
    p.add_argument("file", type=Path)
    p.add_argument("-f", "--function", default="")
    p.add_argument("--list", action="store_true", help="list functions instead")
    p.add_argument("--unwind", choices=["none", "codes", "full"], default="codes")
    p.set_defaults(fn=cmd_disasm)

    p = sub.add_parser("diff", help="score candidate against target (.c/.obj/PE each)")
    p.add_argument("target", type=Path)
    p.add_argument("candidate", type=Path)
    p.add_argument("-f", "--function", required=True)
    p.add_argument("--target-function", help="name in target if different (e.g. sub_1400010A0)")
    p.add_argument("--unwind", choices=["none", "codes", "full"], default="codes")
    p.add_argument("--anonymize", action="store_true", help="ignore symbol names")
    p.add_argument("--max-lines", type=int, default=200)
    p.add_argument("--json", action="store_true")
    _add_compile_opts(p)
    p.set_defaults(fn=cmd_diff)

    p = sub.add_parser("corpus", help="fetch + preprocess the fixed C corpus")
    p.add_argument("--dir", type=Path, default=Path("datasets/corpus"))
    p.add_argument("--libraries", help="comma-separated subset")
    p.add_argument("--toolchain", default=DEFAULT_TOOLCHAIN)
    p.add_argument(
        "--runtime",
        choices=["mt", "md"],
        default="mt",
        help="md: preprocess with /MD into <dir>-md",
    )
    p.set_defaults(fn=cmd_corpus)

    p = sub.add_parser("roundtrip", help="Phase 1 acceptance: original source -> exact?")
    p.add_argument("--corpus", type=Path, default=Path("datasets/corpus"))
    p.add_argument("--sample", type=int, default=1000, help="0 = all functions")
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--threshold", type=float, default=0.99)
    p.add_argument("--show", type=int, default=5, help="print this many failures")
    p.add_argument("-o", "--output", type=Path)
    _add_compile_opts(p)
    p.set_defaults(fn=cmd_roundtrip)

    p = sub.add_parser("equiv-manifest", help="hash every corpus function (Wine or native)")
    p.add_argument("--corpus", type=Path, default=Path("datasets/corpus"))
    p.add_argument("--flagsets", help="comma-separated names from flagsets.toml (default all)")
    p.add_argument("-o", "--output", type=Path, required=True)
    _add_compile_opts(p)
    p.set_defaults(fn=cmd_equiv_manifest)

    p = sub.add_parser("verify-toolchain", help="compare two equivalence manifests")
    p.add_argument("a", type=Path)
    p.add_argument("b", type=Path)
    p.set_defaults(fn=cmd_verify_toolchain)

    p = sub.add_parser("bench", help="compile throughput at several worker counts")
    p.add_argument("--corpus", type=Path, default=Path("datasets/corpus"))
    p.add_argument("--workers-list", default="1,2,4,8")
    p.add_argument("--jobs", type=int, default=64)
    p.add_argument("-o", "--output", type=Path)
    _add_compile_opts(p)
    p.set_defaults(fn=cmd_bench)

    p = sub.add_parser("fingerprint-db", help="build per-toolchain fingerprint DB from probes")
    p.add_argument("--toolchains", help="comma-separated ids (default: all registered)")
    p.add_argument("--dir", type=Path, default=Path("datasets/fingerprint"))
    p.set_defaults(fn=cmd_fingerprint_db)

    p = sub.add_parser("fingerprint", help="rank (toolchain, flags) candidates for a binary")
    p.add_argument("binary", type=Path)
    p.add_argument("--db", type=Path, default=Path("datasets/fingerprint"))
    p.add_argument("--pdb", type=Path)
    p.add_argument(
        "--anchors",
        type=Path,
        help="JSONL of {target, function, source, context} to confirm candidates",
    )
    p.add_argument("--confirm-top", type=int, default=8)
    p.add_argument(
        "--ranges",
        metavar="auto|LO-HI,...",
        help="per-address-range configs (mixed compilers); needs --anchors",
    )
    p.add_argument("--top", type=int, default=10)
    p.add_argument("--workers", type=int)
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_fingerprint)

    p = sub.add_parser("fingerprint-eval", help="Phase 2 acceptance on held-out built binaries")
    p.add_argument("-n", type=int, default=20)
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--anchors", type=int, default=30)
    p.add_argument(
        "--mixed",
        type=int,
        default=0,
        help="instead: N mixed-compiler binaries scored per address range",
    )
    p.add_argument("--db", type=Path, default=Path("datasets/fingerprint"))
    p.add_argument("--workers", type=int)
    p.set_defaults(fn=cmd_fingerprint_eval)

    p = sub.add_parser("decomp", help="Ghidra pseudo-C for functions of an .obj or PE")
    p.add_argument("file", type=Path, nargs="?")
    p.add_argument("-f", "--function", action="append", help="repeatable; default: all")
    p.add_argument("--build", action="store_true", help="build the Ghidra image")
    p.add_argument("--warnings", action="store_true", help="keep Ghidra WARNING comments")
    p.add_argument("--no-cache", action="store_true")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_decomp)

    ns = ap.parse_args(argv)
    handler: Handler = ns.fn
    return handler(ns)


if __name__ == "__main__":
    sys.exit(main())
