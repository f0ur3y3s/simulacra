"""Disassemble a `FunctionBlob` with iced-x86 and normalize it into comparable tokens.

Normalization rules (each covered by tests/test_normalize.py):
  * relocated operands become symbolic tokens: <sym:foo>, <imp:CreateFileW>, <str:N>, <data:N>,
    <const:__real@...>; N is the order of first appearance within the function
  * RIP-relative displacements and call/jmp rel32 targets are rewritten into those tokens
  * intra-function branch targets become instruction-index labels (L<n>)
  * references into the function's trailing data (jump tables) become <tbl:+off>
  * trailing int3/nop padding is stripped
  * unwind info is rendered separately and compared according to `unwind` mode
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum
from functools import cache

import iced_x86 as ix

from mscmatch.blob import (
    FunctionBlob,
    FunctionReloc,
    RelocKind,
    RelocTarget,
    RuntimeFunction,
    TargetKind,
)


class UnwindMode(StrEnum):
    NONE = "none"
    CODES = "codes"  # header + unwind codes (default)
    FULL = "full"  # also exception handler and handler data


@dataclass(frozen=True)
class NormInsn:
    offset: int
    mnemonic: str
    operands: tuple[str, ...] = ()
    is_data: bool = False

    @property
    def text(self) -> str:
        return f"{self.mnemonic} {', '.join(self.operands)}" if self.operands else self.mnemonic

    @property
    def key(self) -> tuple[str, tuple[str, ...]]:
        return (self.mnemonic, self.operands)


@dataclass
class NormalizedFunction:
    name: str
    insns: list[NormInsn]
    unwind: list[str] = field(default_factory=list)
    code_bytes: int = 0

    def listing(self, with_offsets: bool = True) -> str:
        lines = []
        for i, ins in enumerate(self.insns):
            pre = f"L{i:<4} {ins.offset:5x}  " if with_offsets else f"L{i:<4} "
            lines.append(pre + ins.text)
        if self.unwind:
            lines.append("; unwind")
            lines.extend("; " + u for u in self.unwind)
        return "\n".join(lines)


_PAD_MNEMONICS = {ix.Mnemonic.INT3, ix.Mnemonic.NOP}
_BRANCH_KINDS = {ix.OpKind.NEAR_BRANCH16, ix.OpKind.NEAR_BRANCH32, ix.OpKind.NEAR_BRANCH64}
_IMM_KINDS = {
    ix.OpKind.IMMEDIATE8,
    ix.OpKind.IMMEDIATE16,
    ix.OpKind.IMMEDIATE32,
    ix.OpKind.IMMEDIATE64,
    ix.OpKind.IMMEDIATE8TO16,
    ix.OpKind.IMMEDIATE8TO32,
    ix.OpKind.IMMEDIATE8TO64,
    ix.OpKind.IMMEDIATE32TO64,
}


@cache
def _formatter() -> ix.Formatter:
    f = ix.Formatter(ix.FormatterSyntax.INTEL)
    f.memory_size_options = ix.MemorySizeOptions.ALWAYS
    f.hex_prefix = "0x"
    f.hex_suffix = ""
    f.uppercase_hex = False
    f.space_after_operand_separator = True
    f.show_branch_size = False
    f.rip_relative_addresses = True
    f.signed_memory_displacements = True
    f.signed_immediate_operands = False
    f.branch_leading_zeros = False
    f.leading_zeros = False
    return f


@cache
def register_names() -> frozenset[str]:
    f = _formatter()
    names = set()
    for v in vars(ix.Register).values():
        if isinstance(v, int) and v != ix.Register.NONE:
            try:
                names.add(f.format_register(v))  # type: ignore[arg-type]
            except ValueError:
                continue
    names.discard("")
    return frozenset(names)


@cache
def register_regex() -> re.Pattern[str]:
    alts = sorted(register_names(), key=len, reverse=True)
    return re.compile(r"\b(?:" + "|".join(re.escape(a) for a in alts) + r")\b")


class _TokenNamer:
    """Assigns per-function ordinals to anonymous targets (strings, data)."""

    def __init__(self) -> None:
        self._ords: dict[tuple[str, tuple[str, str, int]], int] = {}

    def ordinal(self, kind: str, key: tuple[str, str, int]) -> int:
        k = (kind, key)
        if k not in self._ords:
            self._ords[k] = sum(1 for kk in self._ords if kk[0] == kind)
        return self._ords[k]


@dataclass
class _Ctx:
    blob: FunctionBlob
    index_of: dict[int, int]  # code offset -> instruction index
    data_start: int
    namer: _TokenNamer

    def self_token(self, off: int) -> str:
        if off in self.index_of:
            return f"L{self.index_of[off]}"
        if off >= self.data_start:
            return f"<tbl:+{off - self.data_start:#x}>"
        return f"<self:{off:#x}>"

    def token(self, t: RelocTarget) -> str:
        if t.kind is TargetKind.SELF:
            assert t.self_offset is not None
            return self.self_token(t.self_offset)
        if t.kind in (TargetKind.STR, TargetKind.DATA):
            return f"<{t.kind.value}:{self.namer.ordinal(t.kind.value, t.key())}>"
        suffix = f"{t.addend:+#x}" if t.addend else ""
        return f"<{t.kind.value}:{t.name}{suffix}>"


def _decode(code: bytes, limit: int) -> list[ix.Instruction]:
    dec = ix.Decoder(64, code[:limit], ip=0)
    return list(dec)


def _find_data_start(blob: FunctionBlob, code_limit: int) -> int:
    """Lowest offset of in-function data (jump/byte tables) referenced from code.

    MSVC emits switch tables after the function body and references them with an ADDR32NB
    displacement, so a linear decode reaches every table reference before the table itself.
    """
    data_start = code_limit
    rva_self = [
        r for r in blob.relocs if r.kind is RelocKind.RVA32 and r.target.self_offset is not None
    ]
    if not rva_self:
        return data_start
    for ins in ix.Decoder(64, blob.code[:code_limit], ip=0):
        if ins.ip >= data_start:
            break
        for r in rva_self:
            off = r.target.self_offset
            if ins.ip <= r.offset < ins.ip + ins.len and off is not None and off > ins.ip:
                data_start = min(data_start, off)
    return data_start


def _relocs_in(blob: FunctionBlob, start: int, end: int) -> list[FunctionReloc]:
    return [r for r in blob.relocs if start <= r.offset < end]


def _render_mem(ins: ix.Instruction, i: int, inner_token: str | None, ctx: _Ctx) -> str:
    f = _formatter()
    text = f.format_operand(ins, i)
    lb = text.find("[")
    prefix = text[:lb] if lb >= 0 else ""
    if ins.is_ip_rel_memory_operand:
        if inner_token is None:
            inner_token = ctx.self_token(ins.ip_rel_memory_address)
        return f"{prefix}[{inner_token}]"
    if inner_token is None:
        return text
    parts = []
    if ins.memory_base != ix.Register.NONE:
        parts.append(f.format_register(ins.memory_base))
    if ins.memory_index != ix.Register.NONE:
        idx = f.format_register(ins.memory_index)
        scale = ins.memory_index_scale
        parts.append(f"{idx}*{scale}" if scale != 1 else idx)
    parts.append(inner_token)
    return f"{prefix}[{'+'.join(parts)}]"


def _render_insn(ins: ix.Instruction, dec: ix.Decoder, ctx: _Ctx) -> NormInsn:
    f = _formatter()
    co = dec.get_constant_offsets(ins)
    disp_tok = imm_tok = None
    for r in _relocs_in(ctx.blob, ins.ip, ins.ip + ins.len):
        rel = r.offset - ins.ip
        tok = ctx.token(r.target)
        if co.has_displacement and rel == co.displacement_offset:
            disp_tok = tok
        elif co.has_immediate and rel == co.immediate_offset:
            imm_tok = tok
        else:
            # Relocation we cannot attribute to an operand; keep it visible.
            disp_tok = disp_tok or tok

    ops: list[str] = []
    for i in range(f.operand_count(ins)):
        instr_op = f.get_instruction_operand(ins, i)
        k = ins.op_kind(instr_op) if instr_op is not None else None
        if k == ix.OpKind.MEMORY:
            ops.append(_render_mem(ins, i, disp_tok, ctx))
        elif k in _BRANCH_KINDS:
            ops.append(imm_tok if imm_tok is not None else ctx.self_token(ins.near_branch_target))
        elif k in _IMM_KINDS and imm_tok is not None:
            ops.append(imm_tok)
        else:
            ops.append(f.format_operand(ins, i))
    return NormInsn(ins.ip, f.format_mnemonic(ins, ix.FormatMnemonicOptions.NONE), tuple(ops))


def _render_data(blob: FunctionBlob, start: int, ctx: _Ctx) -> list[NormInsn]:
    out: list[NormInsn] = []
    code = blob.code
    end = len(code)
    while end > start and code[end - 1] == 0xCC:
        end -= 1
    relocs = {r.offset: r for r in _relocs_in(blob, start, end)}
    off = start
    while off < end:
        r = relocs.get(off)
        if r is not None:
            out.append(NormInsn(off, "dq" if r.size == 8 else "dd", (ctx.token(r.target),), True))
            off += r.size
            continue
        run_end = off
        while run_end < end and run_end not in relocs and run_end - off < 8:
            run_end += 1
        out.append(NormInsn(off, "db", tuple(f"{b:#04x}" for b in code[off:run_end]), True))
        off = run_end
    return out


def _render_unwind(pdata: list[RuntimeFunction], ctx: _Ctx, mode: UnwindMode) -> list[str]:
    if mode is UnwindMode.NONE:
        return []
    lines: list[str] = []
    for rf in pdata:
        end_tok = ctx.self_token(rf.end) if rf.end in ctx.index_of else f"+{rf.end:#x}"
        lines.append(f"PDATA {ctx.self_token(rf.begin)}..{end_tok}")
        info = rf.unwind
        if info is not None:
            lines.extend("  " + s for s in info.render_codes())
            if mode is UnwindMode.FULL and info.handler is not None:
                lines.append(f"  HANDLER {ctx.token(info.handler)} data={info.handler_data.hex()}")
            if info.chained is not None:
                # The parent's unwind codes are listed under its own PDATA entry.
                lines.append(f"  CHAIN {ctx.self_token(info.chained.begin)}")
    return lines


def normalize(blob: FunctionBlob, unwind: UnwindMode = UnwindMode.CODES) -> NormalizedFunction:
    code_limit = len(blob.code)
    if blob.code_size is not None and 0 < blob.code_size < code_limit:
        code_limit = blob.code_size
    data_start = _find_data_start(blob, code_limit)

    insns_raw = _decode(blob.code, data_start)
    # Strip trailing padding from the code region.
    while insns_raw and insns_raw[-1].mnemonic in _PAD_MNEMONICS:
        insns_raw.pop()
    while insns_raw and insns_raw[-1].code == ix.Code.INVALID:
        insns_raw.pop()

    index_of = {ins.ip: i for i, ins in enumerate(insns_raw)}
    ctx = _Ctx(blob, index_of, data_start, _TokenNamer())
    out: list[NormInsn] = []
    dec = ix.Decoder(64, blob.code[:data_start], ip=0)
    for ins in dec:  # re-decode: get_constant_offsets needs the decoder state of each insn
        if len(out) >= len(insns_raw):
            break
        out.append(_render_insn(ins, dec, ctx))
    if data_start < len(blob.code):
        out.extend(_render_data(blob, data_start, ctx))
    code_bytes = insns_raw[-1].ip + insns_raw[-1].len if insns_raw else 0
    return NormalizedFunction(blob.name, out, _render_unwind(blob.pdata, ctx, unwind), code_bytes)
