"""Container-agnostic representation of one extracted function.

Both COFF objects (candidates) and linked PE images (targets) are reduced to a `FunctionBlob`:
raw code bytes plus symbolic relocations and unwind info. Normalization only ever sees this.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import StrEnum


class TargetKind(StrEnum):
    IMP = "imp"  # import thunk / IAT slot (__imp_X)
    SYM = "sym"  # named function or global
    STR = "str"  # string literal (??_C@..., $SG...)
    DATA = "data"  # anonymous data (section-relative, compiler-generated labels)
    CONST = "const"  # FP / SIMD constant pool (__real@, __xmm@, __ymm@...)
    SELF = "self"  # inside this function (jump tables, labels)


class RelocKind(StrEnum):
    REL32 = "rel32"  # RIP-relative disp32 or call/jmp rel32
    ABS64 = "abs64"
    ABS32 = "abs32"
    RVA32 = "rva32"  # image-relative (ADDR32NB)


@dataclass(frozen=True)
class RelocTarget:
    kind: TargetKind
    name: str  # symbol name; for anonymous targets a stable key within the container
    addend: int = 0
    self_offset: int | None = None  # set when kind == SELF: offset within the function

    def key(self) -> tuple[str, str, int]:
        return (self.kind.value, self.name, self.addend)


@dataclass(frozen=True)
class FunctionReloc:
    offset: int  # within the function code
    size: int
    kind: RelocKind
    target: RelocTarget


UNWIND_REGS = (
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
)  # fmt: skip

UNW_FLAG_EHANDLER = 1
UNW_FLAG_UHANDLER = 2
UNW_FLAG_CHAININFO = 4


@dataclass(frozen=True)
class UnwindCode:
    prolog_offset: int
    op: str
    arg: str

    def render(self) -> str:
        return f"@{self.prolog_offset:#x} {self.op} {self.arg}".rstrip()


@dataclass
class UnwindInfo:
    version: int
    flags: int
    prolog_size: int
    frame_register: int
    frame_offset: int
    codes: list[UnwindCode]
    handler: RelocTarget | None = None
    handler_data: bytes = b""
    chained: RuntimeFunction | None = None

    def render_codes(self) -> list[str]:
        frame = (
            f"{UNWIND_REGS[self.frame_register]}+{self.frame_offset * 16:#x}"
            if self.frame_register
            else "none"
        )
        flags = [
            n for b, n in ((1, "EHANDLER"), (2, "UHANDLER"), (4, "CHAININFO")) if self.flags & b
        ]
        head = (
            f"UNWIND v{self.version} flags={'|'.join(flags) or '0'} "
            f"prolog={self.prolog_size:#x} frame={frame}"
        )
        return [head, *(c.render() for c in self.codes)]


@dataclass
class RuntimeFunction:
    begin: int  # offsets within the function (may be outside for chained parents)
    end: int
    unwind: UnwindInfo | None


@dataclass
class FunctionBlob:
    name: str
    code: bytes
    relocs: list[FunctionReloc] = field(default_factory=list)
    pdata: list[RuntimeFunction] = field(default_factory=list)
    # Where the function's code ends according to unwind data (jump tables may follow).
    code_size: int | None = None

    def reloc_at(self, offset: int) -> FunctionReloc | None:
        for r in self.relocs:
            if r.offset == offset:
                return r
        return None


def decode_unwind_codes(version: int, raw: bytes, count: int) -> list[UnwindCode]:
    """Decode UNWIND_CODE slots into human-readable ops (operands in bytes)."""
    slots = [struct.unpack_from("<BB", raw, i * 2) for i in range(count)]
    out: list[UnwindCode] = []
    i = 0

    def slot16(j: int) -> int:
        lo, hi = slots[j]
        return int(lo) | (int(hi) << 8)

    while i < count:
        off, b = slots[i]
        op, info = b & 0xF, b >> 4
        used = 1
        if op == 0:
            out.append(UnwindCode(off, "PUSH_NONVOL", UNWIND_REGS[info]))
        elif op == 1:
            if info == 0:
                size, used = slot16(i + 1) * 8, 2
            else:
                size, used = slot16(i + 1) | (slot16(i + 2) << 16), 3
            out.append(UnwindCode(off, "ALLOC_LARGE", f"{size:#x}"))
        elif op == 2:
            out.append(UnwindCode(off, "ALLOC_SMALL", f"{info * 8 + 8:#x}"))
        elif op == 3:
            out.append(UnwindCode(off, "SET_FPREG", ""))
        elif op == 4:
            out.append(
                UnwindCode(off, "SAVE_NONVOL", f"{UNWIND_REGS[info]},{slot16(i + 1) * 8:#x}")
            )
            used = 2
        elif op == 5:
            disp = slot16(i + 1) | (slot16(i + 2) << 16)
            out.append(UnwindCode(off, "SAVE_NONVOL_FAR", f"{UNWIND_REGS[info]},{disp:#x}"))
            used = 3
        elif op == 6 and version >= 2:
            # UWOP_EPILOG: first slot of a run carries flags in info; offsets are opaque here.
            out.append(UnwindCode(off, "EPILOG", f"{info:#x}"))
        elif op == 7 and version >= 2:
            out.append(UnwindCode(off, "SPARE", f"{info:#x}"))
        elif op == 8:
            out.append(UnwindCode(off, "SAVE_XMM128", f"xmm{info},{slot16(i + 1) * 16:#x}"))
            used = 2
        elif op == 9:
            disp = slot16(i + 1) | (slot16(i + 2) << 16)
            out.append(UnwindCode(off, "SAVE_XMM128_FAR", f"xmm{info},{disp:#x}"))
            used = 3
        elif op == 10:
            out.append(UnwindCode(off, "PUSH_MACHFRAME", str(info)))
        else:
            out.append(UnwindCode(off, f"OP{op}", f"{info:#x}"))
        i += used
    return out


@dataclass(frozen=True)
class RawUnwind:
    """UNWIND_INFO decoded except for the parts that need container-specific resolution."""

    info: UnwindInfo
    handler_field: int | None  # byte offset of the handler RVA field, if any
    chain_field: int | None  # byte offset of the chained RUNTIME_FUNCTION, if any
    end: int


def parse_unwind_header(buf: bytes, off: int) -> RawUnwind:
    vf, prolog, count, frame = struct.unpack_from("<BBBB", buf, off)
    version, flags = vf & 7, vf >> 3
    codes_raw = buf[off + 4 : off + 4 + count * 2]
    info = UnwindInfo(
        version,
        flags,
        prolog,
        frame & 0xF,
        frame >> 4,
        decode_unwind_codes(version, codes_raw, count),
    )
    tail = off + 4 + ((count + 1) & ~1) * 2
    handler_field = chain_field = None
    end = tail
    if flags & UNW_FLAG_CHAININFO:
        chain_field = tail
        end = tail + 12
    elif flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER):
        handler_field = tail
        end = tail + 4
    return RawUnwind(info, handler_field, chain_field, end)
