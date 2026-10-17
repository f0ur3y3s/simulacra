"""Phase 3 builds and per-function records.

For each (toolchain, flag set, library):

* **build**: compile every library TU (compile service, cached) and link them into one DLL
  with `/OPT:NOREF /OPT:NOICF`, so every function keeps its own address, plus a `.map`.
* **records**: one row per library function emitted in its TU's object:
  `target` (normalized COMDAT), `pseudo_c` (Ghidra on the DLL), `context` + `source` (sliced
  from the TU, see `context.py`) and `verified` (does context + source recompile to exactly the
  target). Written as one Parquet shard.

Layout under `datasets/phase3/`:
    builds/<toolchain>/<flagset>/<library>/{lib.dll, lib.map}
    records/<toolchain>/<flagset>/<library>.parquet
"""

from __future__ import annotations

import hashlib
import re
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

from simulacra.coff import list_functions, parse_coff
from simulacra.coff.parser import IMAGE_SYM_CLASS_STATIC
from simulacra.compile import CompileRequest, CompileService
from simulacra.data.context import TUIndex, target_symbols
from simulacra.data.cparse import function_definitions
from simulacra.data.sources import SourceTU, load_sources
from simulacra.decomp import DecompResult, GhidraDecompiler, GhidraError
from simulacra.harness import compile_function, function_from_obj
from simulacra.pe import parse_pe
from simulacra.pe.mapfile import parse_map
from simulacra.score import anonymize, score
from simulacra.toolchain import load_flagsets

PHASE3_DIR = Path("datasets/phase3")
CONTEXT_MODE = "none"
_HARD_RULES = re.compile(r"__pragma|#\s*pragma\s+optimize|__declspec\s*\(\s*naked\s*\)")

SCHEMA = pa.schema(
    [
        ("id", pa.string()),
        ("library", pa.string()),
        ("tu", pa.string()),
        ("function", pa.string()),
        ("toolchain", pa.string()),
        ("flagset", pa.string()),
        ("flags", pa.list_(pa.string())),
        ("size", pa.int32()),
        ("target", pa.string()),
        ("target_hash", pa.string()),  # anonymized listing: same code regardless of names
        ("target_exact_hash", pa.string()),  # listing as is
        ("pseudo_c", pa.string()),
        ("context", pa.string()),
        ("source", pa.string()),
        ("inlined", pa.list_(pa.string())),
        ("header_inlined", pa.list_(pa.string())),
        ("static", pa.bool_()),
        ("verified", pa.bool_()),
        ("verify_score", pa.float32()),
        ("hard_rule", pa.bool_()),
        ("context_mode", pa.string()),
    ]
)


@dataclass
class ShardStats:
    toolchain: str
    flagset: str
    library: str
    records: int = 0
    verified: int = 0
    skipped: Counter[str] = field(default_factory=Counter)
    elapsed: float = 0.0

    def line(self) -> str:
        rate = self.verified / self.records if self.records else 0.0
        return (
            f"{self.toolchain:13} {self.flagset:8} {self.library:8} {self.records:5} records, "
            f"{self.verified:5} verified ({rate:.1%}), skipped {dict(self.skipped)}, "
            f"{self.elapsed:.0f}s"
        )


def export_names(texts: list[str]) -> list[str]:
    """External library functions defined in exactly one TU (what a .def would export)."""
    counts: Counter[str] = Counter()
    for t in texts:
        for d in function_definitions(t):
            if not d.is_static and not d.is_inline and d.name != "main":
                counts[d.name] += 1
    return sorted(n for n, c in counts.items() if c == 1)


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:32]


def _record_id(*parts: str) -> str:
    return hashlib.sha1("|".join(parts).encode()).hexdigest()[:16]


def _is_static(obj: bytes, name: str) -> bool:
    for s in parse_coff(obj).iter_symbols():
        if s.name == name and s.section_number > 0 and s.is_function:
            return s.storage_class == IMAGE_SYM_CLASS_STATIC
    return False


class Phase3Builder:
    def __init__(
        self,
        service: CompileService,
        decompiler: GhidraDecompiler | None = None,
        root: Path = PHASE3_DIR,
        verify_workers: int | None = None,
    ) -> None:
        self.service = service
        self.decompiler = decompiler or GhidraDecompiler()
        self.root = root
        self.verify_workers = verify_workers or service.workers
        self._index: dict[tuple[str, str], TUIndex] = {}

    # -- builds ---------------------------------------------------------------------------
    def _tus(self, toolchain: str, library: str) -> list[SourceTU]:
        return [
            t
            for t in load_sources(toolchain, self.root / "sources")
            if t.library == library and not t.program
        ]

    def _objects(
        self, tus: list[SourceTU], toolchain: str, flags: tuple[str, ...]
    ) -> dict[str, bytes]:
        reqs = [CompileRequest(t.text(), "", "", toolchain, flags, timeout=600) for t in tus]
        objs: dict[str, bytes] = {}
        for tu, res in zip(tus, self.service.compile_many(reqs), strict=True):
            if res.ok:
                objs[tu.tu] = res.obj_bytes
        return objs

    def build(
        self, toolchain: str, flagset: str, library: str
    ) -> tuple[bytes, dict[str, int], dict[str, bytes]]:
        flags = load_flagsets()[flagset]
        tus = self._tus(toolchain, library)
        objs = self._objects(tus, toolchain, flags)
        out_dir = self.root / "builds" / toolchain / flagset / library
        dll_path, map_path = out_dir / "lib.dll", out_dir / "lib.map"
        if not dll_path.exists():
            names = {t.replace("/", "__")[:-2] + ".obj": o for t, o in objs.items()}
            exports = export_names([t.text() for t in tus if t.tu in objs])
            files = {"lib.def": "EXPORTS\n" + "".join(f"    {n}\n" for n in exports)}
            args = [
                "/nologo",
                *sorted(names),
                "/LD",
                "/Felib.dll",
                "/link",
                "/DEF:lib.def",
                "/MAP:lib.map",
                "/OPT:NOREF",
                "/OPT:NOICF",
                "/INCREMENTAL:NO",
                "/Brepro",
            ]
            res = self.service.run_raw(
                files,
                args,
                "lib.dll",
                toolchain,
                timeout=900,
                outputs=("lib.map",),
                binary_files=names,
            )
            if not res.ok:
                raise RuntimeError(
                    f"linking {library} {toolchain} {flagset}:\n{res.stdout[-3000:]}"
                )
            out_dir.mkdir(parents=True, exist_ok=True)
            dll_path.write_bytes(res.obj)
            map_path.write_bytes(res.outputs["lib.map"])
        dll = dll_path.read_bytes()
        names_map = parse_map(map_path.read_text("utf-8", "replace"), parse_pe(dll).image_base)
        return dll, names_map, objs

    # -- records ----------------------------------------------------------------------------
    def _tu_index(self, tu: SourceTU) -> TUIndex:
        key = (tu.toolchain, tu.id)
        if key not in self._index:
            self._index[key] = TUIndex(tu.text())
        return self._index[key]

    def records(
        self, toolchain: str, flagset: str, library: str, force: bool = False
    ) -> ShardStats:
        shard = self.root / "records" / toolchain / flagset / f"{library}.parquet"
        stats = ShardStats(toolchain, flagset, library)
        if shard.exists() and not force:
            table = pq.read_table(shard, columns=["verified"])
            stats.records = table.num_rows
            stats.verified = sum(table.column("verified").to_pylist())
            stats.skipped["cached"] += 1
            return stats
        t0 = time.monotonic()
        flags = load_flagsets()[flagset]
        dll, names_map, objs = self.build(toolchain, flagset, library)
        try:
            pseudo: DecompResult | None = self.decompiler.decompile(
                dll, f"{library}.dll", entries=sorted(set(names_map.values()))
            )
        except GhidraError:
            pseudo = None
            stats.skipped["ghidra-failed"] += 1

        jobs = []
        for tu in self._tus(toolchain, library):
            obj = objs.get(tu.tu)
            if obj is None:
                stats.skipped["tu-compile-failed"] += 1
                continue
            idx = self._tu_index(tu)
            for name in list_functions(parse_coff(obj)):
                if name not in idx.defs:
                    stats.skipped["not-in-tu"] += 1
                    continue
                target = function_from_obj(obj, name)
                listing = target.listing(with_offsets=False)
                sl = idx.slice(name, target_symbols(listing), CONTEXT_MODE)
                if not sl.library_defined:
                    stats.skipped["header-function"] += 1
                    continue
                jobs.append((tu, name, target, listing, sl, _is_static(obj, name)))

        def verify(job: tuple) -> tuple[bool, float]:  # type: ignore[type-arg]
            _tu, name, target, _listing, sl, _static = job
            cand, _err = compile_function(
                self.service, sl.source, name, flags, sl.context, toolchain
            )
            if cand is None:
                return False, 0.0
            rep = score(target, cand, max_diff_lines=0)
            return rep.exact, rep.score

        with ThreadPoolExecutor(self.verify_workers) as ex:
            verdicts = list(ex.map(verify, jobs))

        rows: dict[str, list[object]] = {f.name: [] for f in SCHEMA}
        for (tu, name, target, listing, sl, static), (exact, vscore) in zip(
            jobs, verdicts, strict=True
        ):
            fn_pseudo = ""
            if pseudo is not None and name in names_map:
                d = pseudo.at(names_map[name])
                fn_pseudo = d.pseudo_c() if d is not None and d.ok else ""
            values = {
                "id": _record_id(toolchain, flagset, library, tu.tu, name),
                "library": library,
                "tu": tu.tu,
                "function": name,
                "toolchain": toolchain,
                "flagset": flagset,
                "flags": list(flags),
                "size": len(target.insns),
                "target": listing,
                "target_hash": _sha(anonymize(target).listing(with_offsets=False)),
                "target_exact_hash": _sha(listing),
                "pseudo_c": fn_pseudo,
                "context": sl.context,
                "source": sl.source,
                "inlined": sl.inlined,
                "header_inlined": sl.header_inlined,
                "static": static,
                "verified": exact,
                "verify_score": vscore,
                "hard_rule": bool(_HARD_RULES.search(sl.source)),
                "context_mode": CONTEXT_MODE,
            }
            for k, v in values.items():
                rows[k].append(v)
        shard.parent.mkdir(parents=True, exist_ok=True)
        tmp = shard.with_suffix(".tmp")
        pq.write_table(pa.table(rows, schema=SCHEMA), tmp, compression="zstd")
        tmp.replace(shard)
        stats.records = len(jobs)
        stats.verified = sum(e for e, _ in verdicts)
        stats.elapsed = time.monotonic() - t0
        return stats
