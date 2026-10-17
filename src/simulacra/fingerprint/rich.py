"""Rich header interpretation.

Product ids observed for VS 2015+ toolsets (confirmed against our own builds; see
tests/test_fingerprint.py): the "1900" family is shared by every v14x toolset, the build field
carries the exact compiler/linker build.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from simulacra.pe.image import RichEntry

PRODIDS: dict[int, str] = {
    0x0001: "Import",
    0x0093: "Implib900",
    0x00FF: "Cvtres1400",
    0x0100: "Export1400",
    0x0101: "Implib1400",
    0x0102: "Linker1400",
    0x0103: "Masm1400",
    0x0104: "Utc1900_C",
    0x0105: "Utc1900_CPP",
    0x0106: "Utc1900_CVTCIL_C",
    0x0107: "Utc1900_CVTCIL_CPP",
    0x0108: "Utc1900_LTCG_C",
    0x0109: "Utc1900_LTCG_CPP",
    0x010A: "Utc1900_LTCG_MSIL",
    0x010B: "Utc1900_POGO_I_C",
    0x010C: "Utc1900_POGO_I_CPP",
    0x010D: "Utc1900_POGO_O_C",
    0x010E: "Utc1900_POGO_O_CPP",
}
COMPILER_PRODIDS = {0x0104, 0x0105, 0x0108, 0x0109, 0x010B, 0x010C, 0x010D, 0x010E}
LTCG_PRODIDS = {0x0108, 0x0109, 0x010A}
LINKER_PRODID = 0x0102


@dataclass
class RichSummary:
    present: bool
    linker_builds: list[int] = field(default_factory=list)
    # build -> {prodid name: object count}
    compilers: dict[int, dict[str, int]] = field(default_factory=dict)
    ltcg: bool = False
    entries: list[tuple[str, int, int]] = field(default_factory=list)

    def compiler_builds(self, exclude: set[int] | frozenset[int] = frozenset()) -> dict[int, int]:
        """Compiler build -> object count, excluding builds known to come from prebuilt libs."""
        return {
            b: sum(v.values()) for b, v in self.compilers.items() if b not in exclude and b != 0
        }


def summarize(entries: list[RichEntry]) -> RichSummary:
    if not entries:
        return RichSummary(False)
    comps: dict[int, dict[str, int]] = defaultdict(dict)
    linkers = []
    ltcg = False
    for e in entries:
        name = PRODIDS.get(e.prodid, f"prodid_{e.prodid:#x}")
        if e.prodid == LINKER_PRODID:
            linkers.append(e.build)
        if e.prodid in COMPILER_PRODIDS:
            comps[e.build][name] = comps[e.build].get(name, 0) + e.count
        if e.prodid in LTCG_PRODIDS:
            ltcg = True
    return RichSummary(
        True,
        sorted(set(linkers)),
        dict(comps),
        ltcg,
        [(PRODIDS.get(e.prodid, hex(e.prodid)), e.build, e.count) for e in entries],
    )


def strip_rich(data: bytes) -> bytes:
    """Zero the Rich header (DanS..Rich+key), as a stripping tool would."""
    import struct

    (e_lfanew,) = struct.unpack_from("<I", data, 0x3C)
    end = data.find(b"Rich", 0x80, e_lfanew)
    if end < 0:
        return data
    key = data[end + 4 : end + 8]
    dans = bytes(a ^ b for a, b in zip(b"DanS", key, strict=True))
    start = data.rfind(dans, 0x40, end)
    if start < 0:
        return data
    return data[:start] + b"\0" * (end + 8 - start) + data[end + 8 :]
