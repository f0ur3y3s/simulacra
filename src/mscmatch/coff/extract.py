"""Locate a function's code in a COFF object and lift it into a `FunctionBlob`."""

from __future__ import annotations

import struct

from mscmatch.blob import (
    FunctionBlob,
    FunctionReloc,
    RelocKind,
    RelocTarget,
    RuntimeFunction,
    TargetKind,
    UnwindInfo,
    parse_unwind_header,
)
from mscmatch.coff.parser import (
    REL32_TYPES,
    CoffError,
    CoffObject,
    ComdatSelection,
    Relocation,
    RelocType,
    Section,
    Symbol,
    parse_coff,
)

_CONST_PREFIXES = ("__real@", "__xmm@", "__ymm@", "__zmm@", "__mask@")
_STR_PREFIXES = ("??_C@", "$SG")


def _reloc_kind(rtype: int) -> RelocKind | None:
    if rtype in REL32_TYPES:
        return RelocKind.REL32
    if rtype == RelocType.ADDR64:
        return RelocKind.ABS64
    if rtype == RelocType.ADDR32:
        return RelocKind.ABS32
    if rtype == RelocType.ADDR32NB:
        return RelocKind.RVA32
    return None


def _inplace_addend(sec: Section, r: Relocation) -> int:
    if r.type == RelocType.ADDR64:
        return int(struct.unpack_from("<q", sec.data, r.offset)[0])
    return int(struct.unpack_from("<i", sec.data, r.offset)[0])


def classify_symbol(sym: Symbol, addend: int) -> RelocTarget:
    """Map a relocation target symbol to a token class. Anonymous kinds are keyed by name."""
    name = sym.name
    if name.startswith("__imp_"):
        return RelocTarget(TargetKind.IMP, name[len("__imp_") :], addend)
    if name.startswith(_STR_PREFIXES):
        return RelocTarget(TargetKind.STR, name, addend)
    if name.startswith(_CONST_PREFIXES):
        return RelocTarget(TargetKind.CONST, name, addend)
    if sym.section_aux is not None or name.startswith("$"):
        # Section symbols (.rdata/.data/.bss + offset) and compiler labels.
        return RelocTarget(TargetKind.DATA, name, addend)
    return RelocTarget(TargetKind.SYM, name, addend)


def list_functions(obj: CoffObject) -> list[str]:
    """Names of all functions defined in code sections, in section order."""
    out = []
    for sym in obj.iter_symbols():
        if sym.is_function and sym.section_number > 0 and obj.section(sym.section_number).is_code:
            out.append(sym.name)
    return out


def _find_function(obj: CoffObject, name: str) -> Symbol:
    candidates = [
        s
        for s in obj.iter_symbols()
        if s.name == name and s.section_number > 0 and obj.section(s.section_number).is_code
    ]
    if not candidates:
        raise CoffError(f"function {name!r} not defined in object")
    # Prefer a COMDAT definition (the /Gy case).
    candidates.sort(key=lambda s: not obj.section(s.section_number).is_comdat)
    return candidates[0]


def _function_range(obj: CoffObject, fsym: Symbol) -> tuple[int, int]:
    sec = obj.section(fsym.section_number)
    if sec.is_comdat:
        return 0, len(sec.data)
    # Non-/Gy object: function runs to the next function symbol in the same section.
    starts = sorted(
        s.value
        for s in obj.iter_symbols()
        if s.section_number == fsym.section_number and s.is_function and s.value > fsym.value
    )
    return fsym.value, starts[0] if starts else len(sec.data)


def _resolve_rva_field(
    obj: CoffObject, sec: Section, field_off: int
) -> tuple[Section, int, Symbol] | None:
    """Resolve an ADDR32NB field at `field_off` in `sec` to (target section, offset, symbol)."""
    for r in sec.relocs:
        if r.offset == field_off and r.type == RelocType.ADDR32NB:
            sym = obj.symbol(r.symbol_index)
            addend = _inplace_addend(sec, r)
            if sym.section_number <= 0:
                return None
            return obj.section(sym.section_number), sym.value + addend, sym
    return None


def _parse_unwind(
    obj: CoffObject, xsec: Section, xoff: int, text_secnum: int, base: int, depth: int = 0
) -> UnwindInfo:
    raw = parse_unwind_header(xsec.data, xoff)
    info = raw.info
    if raw.handler_field is not None:
        for r in xsec.relocs:
            if r.offset == raw.handler_field:
                info.handler = classify_symbol(obj.symbol(r.symbol_index), _inplace_addend(xsec, r))
        info.handler_data = xsec.data[raw.end :]
    if raw.chain_field is not None and depth < 8:
        info.chained = _parse_runtime_function(
            obj, xsec, raw.chain_field, text_secnum, base, depth + 1
        )
    return info


def _parse_runtime_function(
    obj: CoffObject, sec: Section, off: int, text_secnum: int, base: int, depth: int = 0
) -> RuntimeFunction | None:
    begin = _resolve_rva_field(obj, sec, off)
    end = _resolve_rva_field(obj, sec, off + 4)
    unwind = _resolve_rva_field(obj, sec, off + 8)
    if begin is None or end is None:
        return None
    b = begin[1] - base if begin[0].number == text_secnum else -1
    e = end[1] - base if end[0].number == text_secnum else -1
    info = None
    if unwind is not None:
        info = _parse_unwind(obj, unwind[0], unwind[1], text_secnum, base, depth)
    return RuntimeFunction(b, e, info)


def _collect_pdata(
    obj: CoffObject, text_secnum: int, start: int, end: int
) -> list[RuntimeFunction]:
    out: list[RuntimeFunction] = []
    for sec in obj.sections:
        if not sec.name.startswith(".pdata"):
            continue
        ssym = obj.section_symbol(sec.number)
        if sec.is_comdat:
            if ssym is None or ssym.section_aux is None:
                continue
            aux = ssym.section_aux
            if aux.selection != ComdatSelection.ASSOCIATIVE or aux.number != text_secnum:
                continue
        for off in range(0, len(sec.data) - 11, 12):
            rf = _parse_runtime_function(obj, sec, off, text_secnum, start)
            if rf is not None and 0 <= rf.begin < end - start:
                out.append(rf)
    out.sort(key=lambda rf: rf.begin)
    return out


def extract_function(obj: CoffObject | bytes, name: str) -> FunctionBlob:
    if isinstance(obj, bytes):
        obj = parse_coff(obj)
    fsym = _find_function(obj, name)
    sec = obj.section(fsym.section_number)
    start, end = _function_range(obj, fsym)
    code = sec.data[start:end]

    relocs: list[FunctionReloc] = []
    for r in sec.relocs:
        if not start <= r.offset < end:
            continue
        kind = _reloc_kind(r.type)
        if kind is None:
            continue
        sym = obj.symbol(r.symbol_index)
        addend = _inplace_addend(sec, r)
        if sym.section_number == fsym.section_number:
            self_off = sym.value + addend - start
            target = RelocTarget(TargetKind.SELF, f"+{self_off:#x}", 0, self_off)
        else:
            target = classify_symbol(sym, addend)
        relocs.append(FunctionReloc(r.offset - start, r.size, kind, target))
    relocs.sort(key=lambda fr: fr.offset)

    pdata = _collect_pdata(obj, fsym.section_number, start, end)
    code_size = max((rf.end for rf in pdata if rf.end > 0), default=None)
    return FunctionBlob(name=name, code=code, relocs=relocs, pdata=pdata, code_size=code_size)
