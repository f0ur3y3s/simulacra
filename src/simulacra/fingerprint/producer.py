"""Which toolchain family produced an image: MSVC (matchable) or something we must refuse.

simulacra only matches MSVC output. Programs cross-compiled with MinGW-w64 GCC or clang/lld
(VLC and most of its bundled libraries, for example) would otherwise get a confident-looking
MSVC candidate list from the fingerprinter. Each signal is reported so the verdict can be
checked by hand.
"""

from __future__ import annotations

import itertools
from collections import Counter
from dataclasses import dataclass, field
from enum import StrEnum

from simulacra.pe.image import PEImage

DEBUG_CODEVIEW, DEBUG_VC_FEATURE, DEBUG_POGO, DEBUG_ILTCG = 2, 12, 13, 14

# Runtime DLLs that only the GNU / LLVM toolchains ship.
_GNU_DLLS = ("libgcc_s", "libstdc++", "libwinpthread", "libgomp", "libssp", "libquadmath")
_LLVM_DLLS = ("libc++", "libunwind", "libomp")
_MINGW_SECTIONS = {".CRT", ".tls$", ".idata", ".bss"}


class Producer(StrEnum):
    MSVC = "msvc"
    MINGW_GCC = "mingw-gcc"  # GCC + GNU ld (MinGW-w64)
    CLANG = "clang"  # clang with lld (llvm-mingw or clang-cl + lld-link)
    NON_MSVC = "non-msvc"  # GNU or LLVM, not pinned down further
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ProducerFeatures:
    linker_version: tuple[int, int]
    rich_present: bool
    debug_types: tuple[int, ...]
    coff_symbols: int
    import_dlls: tuple[str, ...]
    section_names: tuple[str, ...]
    padding: dict[int, int]  # byte value -> count, in gaps between functions
    msvc_crt_matches: int  # functions matching a registered toolchain's CRT signatures


@dataclass
class ProducerVerdict:
    producer: Producer
    confidence: float
    scores: dict[str, float]
    evidence: list[str] = field(default_factory=list)

    @property
    def matchable(self) -> bool:
        return self.producer is Producer.MSVC

    def render(self) -> str:
        head = f"producer   {self.producer.value:12} p={self.confidence:.2f}"
        return "\n".join([head, *("    " + e for e in self.evidence)])


def extract_features(pe: PEImage, msvc_crt_matches: int = 0) -> ProducerFeatures:
    return ProducerFeatures(
        pe.linker_version,
        bool(pe.rich),
        tuple(pe.debug_types),
        pe.coff_symbols,
        tuple(d.lower() for d in pe.import_dlls),
        tuple(s.name for s in pe.sections),
        _padding(pe),
        msvc_crt_matches,
    )


def _padding(pe: PEImage, max_gap: int = 32) -> dict[int, int]:
    """Bytes between consecutive unwind-described functions: MSVC and lld pad with int3,
    GNU ld with nop or zero."""
    counts: Counter[int] = Counter()
    entries = sorted(pe.pdata, key=lambda e: e.begin)
    for a, b in itertools.pairwise(entries):
        gap = b.begin - a.end
        if 0 < gap <= max_gap:
            try:
                counts.update(pe.read(a.end, gap))
            except ValueError:
                continue
    return dict(counts)


def classify(f: ProducerFeatures) -> ProducerVerdict:
    msvc = gnu = llvm = 0.0
    ev: list[str] = []
    major, minor = f.linker_version

    if f.rich_present:
        msvc += 6
        ev.append("Rich header present (written only by MSVC link.exe)")
    vc_debug = {DEBUG_VC_FEATURE, DEBUG_POGO, DEBUG_ILTCG} & set(f.debug_types)
    if vc_debug:
        msvc += 4
        ev.append(f"debug directory has MSVC-only entries {sorted(vc_debug)}")
    if f.msvc_crt_matches >= 20:
        msvc += 4
        ev.append(f"{f.msvc_crt_matches} functions match an MSVC CRT")
    elif f.msvc_crt_matches >= 5:
        msvc += 2
        ev.append(f"{f.msvc_crt_matches} functions match an MSVC CRT")

    if major < 6:
        gnu += 6
        ev.append(f"linker version {major}.{minor} (GNU ld style)")
    elif (major, minor) == (14, 0) and not f.rich_present and not vc_debug:
        llvm += 4
        ev.append("linker version 14.0 without Rich/VC debug entries (lld default)")
    elif major >= 14 and minor > 0:
        msvc += 1
        ev.append(f"linker version {major}.{minor}")

    gnu_dlls = [d for d in f.import_dlls if d.startswith(_GNU_DLLS)]
    llvm_dlls = [d for d in f.import_dlls if d.startswith(_LLVM_DLLS)]
    if gnu_dlls:
        gnu += 6
        ev.append(f"imports GNU runtime DLLs {gnu_dlls}")
    if llvm_dlls:
        llvm += 6
        ev.append(f"imports LLVM runtime DLLs {llvm_dlls}")
    if "msvcrt.dll" in f.import_dlls and f.msvc_crt_matches < 5:
        gnu += 1
        llvm += 1
        ev.append("links msvcrt.dll directly (MinGW default runtime)")

    mingw_secs = sorted(
        {s for s in f.section_names for m in _MINGW_SECTIONS if s == m or s.startswith(m)}
    )
    if mingw_secs:
        gnu += 2
        llvm += 2
        ev.append(f"MinGW CRT sections {mingw_secs}")
    long_names = [s for s in f.section_names if s.startswith("/")]
    if long_names:
        gnu += 2
        llvm += 2
        ev.append(f"long section names {long_names[:3]} (DWARF sections via string table)")
    if f.coff_symbols:
        gnu += 2
        llvm += 1
        ev.append(f"{f.coff_symbols} COFF symbols kept (MSVC link never emits them)")

    total = sum(f.padding.values())
    if total >= 16:
        cc = f.padding.get(0xCC, 0) / total
        gnu_pad = (f.padding.get(0x90, 0) + f.padding.get(0x00, 0)) / total
        if cc >= 0.8:
            msvc += 1
            llvm += 1
            ev.append(f"inter-function padding {cc:.0%} int3")
        elif gnu_pad >= 0.8:
            gnu += 2
            ev.append(f"inter-function padding {gnu_pad:.0%} nop/zero")

    scores = {Producer.MSVC.value: msvc, Producer.MINGW_GCC.value: gnu, Producer.CLANG.value: llvm}
    # Stage 1, the decision that matters: MSVC or not.
    other = max(gnu, llvm)
    if max(msvc, other) < 3 or abs(msvc - other) < 2:
        return ProducerVerdict(Producer.UNKNOWN, 0.5, scores, ev)
    if msvc > other:
        return ProducerVerdict(Producer.MSVC, min(0.99, 0.6 + 0.05 * (msvc - other)), scores, ev)
    # Stage 2: which non-MSVC family. Weaker evidence; a tie is still a definite "not MSVC".
    conf = min(0.99, 0.6 + 0.05 * (other - msvc))
    if abs(gnu - llvm) < 2:
        return ProducerVerdict(Producer.NON_MSVC, conf, scores, ev)
    return ProducerVerdict(Producer.MINGW_GCC if gnu > llvm else Producer.CLANG, conf, scores, ev)


def identify_producer(pe: PEImage, msvc_crt_matches: int = 0) -> ProducerVerdict:
    return classify(extract_features(pe, msvc_crt_matches))
