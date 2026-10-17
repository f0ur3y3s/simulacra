"""Lift a function out of a linked PE image into a `FunctionBlob` with synthesized relocations.

A linked image has no COFF relocations, so they are rebuilt from the instruction stream:
RIP-relative operands and out-of-function branch targets become REL32 relocations, DIR64 base
relocations become ABS64, and image-relative displacements into the function (jump tables)
become RVA32 self references. Targets are named from imports, exports, the load config and an
optional symbol map; otherwise they get address-derived names (sub_XXXX / data_XXXX) that
`score.anonymize` reconciles with real names on the candidate side.
"""

from __future__ import annotations

import bisect
import re
from functools import cache

import iced_x86 as ix

from simulacra.blob import (
    UNW_FLAG_CHAININFO,
    FunctionBlob,
    FunctionReloc,
    RelocKind,
    RelocTarget,
    RuntimeFunction,
    TargetKind,
    UnwindInfo,
    parse_unwind_header,
)
from simulacra.disasm.normalize import NormalizedFunction, UnwindMode, normalize
from simulacra.pe.image import PdataEntry, PEError, PEImage, parse_pe

_SUB_RE = re.compile(r"^(?:sub_|fn_)?(?:0x)?([0-9a-fA-F]+)$")
_SIMD = re.compile(r"\b[xyz]mm\d+\b")
_PRINTABLE = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}


class PEFunctions:
    """Per-image indexes needed for extraction (computed once)."""

    def __init__(self, pe: PEImage, symbols: dict[int, str] | None = None) -> None:
        self.pe = pe
        self.symbols = dict(symbols or {})
        for name, rva in pe.exports.items():
            self.symbols.setdefault(rva, name)
        self.by_name = {v: k for k, v in self.symbols.items()}
        pdata = sorted(pe.pdata, key=lambda e: e.begin)
        self.pdata = pdata
        self.pdata_begins = [e.begin for e in pdata]
        self.groups: dict[int, list[PdataEntry]] = {}
        for e in pdata:
            self.groups.setdefault(self._chain_root(e), []).append(e)
        lc = pe.load_config
        self.load_config_symbols = {
            lc[k] - pe.image_base: v
            for k, v in (
                ("GuardCFCheckFunctionPointer", "__guard_check_icall_fptr"),
                ("GuardCFDispatchFunctionPointer", "__guard_dispatch_icall_fptr"),
            )
            if lc.get(k)
        }
        starts = set(self.groups) | set(self.symbols) | {pe.entry_rva}
        self.starts = sorted(s for s in starts if self._is_exec(s))

    def _is_exec(self, rva: int) -> bool:
        s = self.pe.section_of(rva)
        return s is not None and s.executable

    def _chain_root(self, e: PdataEntry) -> int:
        seen = 0
        cur = e
        while seen < 16:
            try:
                raw = parse_unwind_header(self.pe.read(cur.unwind_rva & ~1, 512), 0)
            except (PEError, IndexError, ValueError):
                return cur.begin
            if not raw.info.flags & UNW_FLAG_CHAININFO or raw.chain_field is None:
                return cur.begin
            b = self.pe.u32((cur.unwind_rva & ~1) + raw.chain_field)
            e2 = self.pe.u32((cur.unwind_rva & ~1) + raw.chain_field + 4)
            u = self.pe.u32((cur.unwind_rva & ~1) + raw.chain_field + 8)
            cur = PdataEntry(b, e2, u)
            seen += 1
        return cur.begin

    def resolve(self, name: str) -> int:
        if name in self.by_name:
            return self._follow_thunks(self.by_name[name])
        m = _SUB_RE.match(name)
        if m:
            v = int(m.group(1), 16)
            return v - self.pe.image_base if v >= self.pe.image_base else v
        raise PEError(f"cannot resolve function {name!r} (not exported / not an address)")

    def _follow_thunks(self, rva: int) -> int:
        """Exports of incrementally linked images point at `jmp rel32` ILT thunks."""
        for _ in range(4):
            head = self.pe.read(rva, 5)
            if head[0] != 0xE9 or rva in self.groups:
                break
            target = rva + 5 + int.from_bytes(head[1:5], "little", signed=True)
            if not self._is_exec(target):
                break
            rva = target
        return rva

    def name_of(self, rva: int) -> str:
        return self.symbols.get(rva, f"sub_{rva + self.pe.image_base:X}")

    def next_start(self, rva: int) -> int:
        i = bisect.bisect_right(self.starts, rva)
        if i < len(self.starts):
            return self.starts[i]
        s = self.pe.section_of(rva)
        return s.rva + s.vsize if s else rva

    # -- target classification --------------------------------------------------------------
    def classify(
        self, target: int, ins_text: str, mem_size: int, table: bool = False
    ) -> RelocTarget:
        """`table`: image-relative table base; never a string or FP constant."""
        pe = self.pe
        if target in pe.imports:
            return RelocTarget(TargetKind.IMP, pe.imports[target].split("!")[-1])
        if target == 0:
            return RelocTarget(TargetKind.SYM, "__ImageBase")
        if target == pe.security_cookie_rva:
            return RelocTarget(TargetKind.SYM, "__security_cookie")
        if target in self.load_config_symbols:
            return RelocTarget(TargetKind.SYM, self.load_config_symbols[target])
        if target in self.symbols:
            return RelocTarget(TargetKind.SYM, self.symbols[target])
        sec = pe.section_of(target)
        if sec is None or sec.executable:
            return RelocTarget(TargetKind.SYM, self.name_of(target))
        if table:
            return RelocTarget(TargetKind.SYM, f"data_{target + pe.image_base:X}")
        if not sec.writable and mem_size in (4, 8, 16, 32) and _SIMD.search(ins_text):
            val = int.from_bytes(pe.read(target, mem_size), "little")
            prefix = {4: "__real@", 8: "__real@", 16: "__xmm@", 32: "__ymm@"}[mem_size]
            return RelocTarget(TargetKind.CONST, f"{prefix}{val:0{mem_size * 2}x}")
        if _looks_like_string(pe, target):
            return RelocTarget(TargetKind.STR, f"str_{target:x}")
        return RelocTarget(TargetKind.SYM, f"data_{target + pe.image_base:X}")


def _looks_like_string(pe: PEImage, rva: int) -> bool:
    raw = pe.read(rva, 256)
    n = raw.find(b"\0")
    if n >= 1 and all(b in _PRINTABLE for b in raw[:n]):
        return True
    # UTF-16LE
    chars = []
    for i in range(0, len(raw) - 1, 2):
        c = raw[i] | (raw[i + 1] << 8)
        if c == 0:
            break
        chars.append(c)
    return len(chars) >= 2 and all(c in _PRINTABLE for c in chars)


@cache
def _formatter() -> ix.Formatter:
    f = ix.Formatter(ix.FormatterSyntax.INTEL)
    f.memory_size_options = ix.MemorySizeOptions.ALWAYS
    return f


_MEM_SIZES = {"byte": 1, "word": 2, "dword": 4, "qword": 8, "xmmword": 16, "ymmword": 32}
_PTR_RE = re.compile(r"\b(byte|word|dword|qword|xmmword|ymmword) ptr\b")


def _mem_size(ins: ix.Instruction) -> int:
    m = _PTR_RE.search(_formatter().format(ins))
    return _MEM_SIZES[m.group(1)] if m else 0


def _function_range(fx: PEFunctions, rva: int) -> tuple[int, list[PdataEntry]]:
    group = fx.groups.get(rva)
    if group:
        return max(e.end for e in group), sorted(group, key=lambda e: e.begin)
    return _leaf_end(fx, rva), []


def _leaf_end(fx: PEFunctions, rva: int) -> int:
    """End of a function without unwind data: follow control flow until the last terminator."""
    limit = fx.next_start(rva)
    code = fx.pe.read(rva, max(0, limit - rva))
    reach = rva  # furthest known intra-function branch target
    for ins in ix.Decoder(64, code, ip=rva):
        if ins.code == ix.Code.INVALID:
            return ins.ip
        fc = ins.flow_control
        if fc in (ix.FlowControl.CONDITIONAL_BRANCH, ix.FlowControl.UNCONDITIONAL_BRANCH):
            t = ins.near_branch_target
            if rva <= t < limit:
                reach = max(reach, t)
        nxt = ins.ip + ins.len
        terminator = fc in (
            ix.FlowControl.RETURN,
            ix.FlowControl.UNCONDITIONAL_BRANCH,
            ix.FlowControl.INTERRUPT,
        )
        if terminator and nxt > reach:
            if fc == ix.FlowControl.INTERRUPT and ins.mnemonic == ix.Mnemonic.INT3:
                return ins.ip
            return nxt
        if fc == ix.FlowControl.INDIRECT_BRANCH and nxt > reach:
            # Table dispatch: the case blocks are only reachable through the table, so the
            # function runs to the next padding run or known start.
            tail = fx.pe.read(nxt, max(0, limit - nxt))
            pad = tail.find(b"\xcc\xcc")
            return nxt + pad if pad >= 0 else limit
    return limit


def _unwind(fx: PEFunctions, unwind_rva: int, base: int, depth: int = 0) -> UnwindInfo | None:
    pe = fx.pe
    try:
        buf = pe.read(unwind_rva, 512)
        raw = parse_unwind_header(buf, 0)
    except (PEError, IndexError, ValueError):
        return None
    info = raw.info
    if raw.handler_field is not None:
        h = pe.u32(unwind_rva + raw.handler_field)
        info.handler = fx.classify(h, "", 0)
        info.handler_data = buf[raw.end : raw.end + 4]
    if raw.chain_field is not None and depth < 8:
        b = pe.u32(unwind_rva + raw.chain_field)
        e = pe.u32(unwind_rva + raw.chain_field + 4)
        u = pe.u32(unwind_rva + raw.chain_field + 8)
        info.chained = RuntimeFunction(b - base, e - base, _unwind(fx, u, base, depth + 1))
    return info


def extract_pe_function(
    pe: PEImage | bytes,
    name: str,
    symbols: dict[int, str] | None = None,
    index: PEFunctions | None = None,
) -> FunctionBlob:
    """Extract by exported/known name, `sub_<VA>` or hex address. Pass `index` when extracting
    many functions from one image."""
    if index is not None:
        fx = index
        pe = fx.pe
    else:
        if isinstance(pe, bytes):
            pe = parse_pe(pe)
        fx = PEFunctions(pe, symbols)
    rva = fx.resolve(name)
    end, group = _function_range(fx, rva)
    # Leaf functions have no pdata bounds; their jump tables may lie past the code end.
    scan_end = end if group else max(end, fx.next_start(rva))
    code = pe.read(rva, scan_end - rva)
    fmt = _formatter()

    relocs: list[FunctionReloc] = []
    tables: set[int] = set()
    data_start = end
    dec = ix.Decoder(64, code, ip=rva)
    for ins in dec:
        if ins.ip >= min(data_start, end):
            break
        co = dec.get_constant_offsets(ins)
        rel = ins.ip - rva
        text = fmt.format(ins)
        disp32 = ins.memory_displacement & 0xFFFFFFFF
        if ins.is_ip_rel_memory_operand and co.has_displacement:
            t = ins.ip_rel_memory_address
            if rva <= t < end:
                target = RelocTarget(TargetKind.SELF, f"+{t - rva:#x}", 0, t - rva)
            else:
                target = fx.classify(t, text, _mem_size(ins))
            relocs.append(FunctionReloc(rel + co.displacement_offset, 4, RelocKind.REL32, target))
        elif (
            co.has_displacement
            and co.displacement_size == 4
            and (ins.memory_base != ix.Register.NONE or ins.memory_index != ix.Register.NONE)
            and ins.ip < disp32 < scan_end
        ):
            tables.add(disp32)
            data_start = min(data_start, disp32)
            relocs.append(
                FunctionReloc(
                    rel + co.displacement_offset,
                    4,
                    RelocKind.RVA32,
                    RelocTarget(TargetKind.SELF, f"+{disp32 - rva:#x}", 0, disp32 - rva),
                )
            )
        elif (
            co.has_displacement
            and co.displacement_size == 4
            and ins.memory_index != ix.Register.NONE
            and (dsec := pe.section_of(disp32)) is not None
            and not dsec.executable
        ):
            # __ImageBase-relative table in a data section (the CRT's asm mem* routines).
            relocs.append(
                FunctionReloc(
                    rel + co.displacement_offset,
                    4,
                    RelocKind.RVA32,
                    fx.classify(disp32, text, 0, table=True),
                )
            )
        fc = ins.flow_control
        if (
            fc in (ix.FlowControl.CALL, ix.FlowControl.UNCONDITIONAL_BRANCH,
                   ix.FlowControl.CONDITIONAL_BRANCH)
            and co.has_immediate
            and not (rva <= ins.near_branch_target < end)
        ):  # fmt: skip
            t = ins.near_branch_target
            relocs.append(
                FunctionReloc(rel + co.immediate_offset, co.immediate_size, RelocKind.REL32,
                              fx.classify(t, text, 0))
            )  # fmt: skip
        if co.has_immediate and co.immediate_size == 8:
            br = ins.ip + co.immediate_offset
            if br in pe.base_relocs:
                va = int.from_bytes(code[br - rva : br - rva + 8], "little")
                relocs.append(
                    FunctionReloc(br - rva, 8, RelocKind.ABS64,
                                  fx.classify(va - pe.image_base, text, 0))
                )  # fmt: skip

    # Jump-table entries (image-relative dwords pointing back into the code); tables without
    # such entries are byte index tables running to the next table or the padding.
    code_end = min(data_start, end)
    final_end = end
    ordered = sorted(tables)
    for k, t in enumerate(ordered):
        pos = t
        while pos + 4 <= scan_end:
            v = pe.u32(pos)
            if not rva <= v < code_end:
                break
            relocs.append(
                FunctionReloc(pos - rva, 4, RelocKind.RVA32,
                              RelocTarget(TargetKind.SELF, f"+{v - rva:#x}", 0, v - rva))
            )  # fmt: skip
            pos += 4
        if pos == t:  # byte table
            pos = ordered[k + 1] if k + 1 < len(ordered) else scan_end
            while pos > t and pe.read(pos - 1, 1)[0] == 0xCC:
                pos -= 1
        final_end = max(final_end, pos)
    if not group:
        end = final_end
    code = code[: end - rva]
    relocs = [r for r in relocs if r.offset < end - rva]

    pdata = [
        RuntimeFunction(e.begin - rva, e.end - rva, _unwind(fx, e.unwind_rva, rva)) for e in group
    ]
    relocs.sort(key=lambda r: r.offset)
    return FunctionBlob(name, code, relocs, pdata, end - rva)


def function_from_pe(
    data: bytes,
    name: str,
    unwind: UnwindMode = UnwindMode.CODES,
    symbols: dict[int, str] | None = None,
) -> NormalizedFunction:
    return normalize(extract_pe_function(data, name, symbols), unwind)


def function_rvas(fx: PEFunctions) -> list[int]:
    """Function starts known from unwind data and symbols (leaf functions only via symbols)."""
    return sorted(r for r in set(fx.groups) | set(fx.symbols) if fx._is_exec(r))


def list_pe_functions(data: bytes) -> list[str]:
    fx = PEFunctions(parse_pe(data))
    return [fx.name_of(rva) for rva in function_rvas(fx)]
