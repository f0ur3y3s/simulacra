"""Minimal COFF object parser (regular and /bigobj), sufficient for COMDAT function extraction.

Only what MSVC x64 objects need: section headers, raw data, relocations, the symbol table with
section-definition aux records, and the string table.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import IntEnum

IMAGE_FILE_MACHINE_AMD64 = 0x8664

IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_LNK_COMDAT = 0x00001000
IMAGE_SCN_LNK_NRELOC_OVFL = 0x01000000
IMAGE_SCN_MEM_EXECUTE = 0x20000000

IMAGE_SYM_CLASS_EXTERNAL = 2
IMAGE_SYM_CLASS_STATIC = 3
IMAGE_SYM_CLASS_LABEL = 6
IMAGE_SYM_DTYPE_FUNCTION = 2

_BIGOBJ_CLSID = bytes.fromhex("c7a1bad1eebaa94baf20faf66aa4dcb8")


class RelocType(IntEnum):
    ABSOLUTE = 0x0
    ADDR64 = 0x1
    ADDR32 = 0x2
    ADDR32NB = 0x3
    REL32 = 0x4
    REL32_1 = 0x5
    REL32_2 = 0x6
    REL32_3 = 0x7
    REL32_4 = 0x8
    REL32_5 = 0x9
    SECTION = 0xA
    SECREL = 0xB
    SECREL7 = 0xC
    TOKEN = 0xD
    SREL32 = 0xE
    PAIR = 0xF
    SSPAN32 = 0x10


REL32_TYPES = frozenset(
    {
        RelocType.REL32,
        RelocType.REL32_1,
        RelocType.REL32_2,
        RelocType.REL32_3,
        RelocType.REL32_4,
        RelocType.REL32_5,
    }
)


class ComdatSelection(IntEnum):
    NODUPLICATES = 1
    ANY = 2
    SAME_SIZE = 3
    EXACT_MATCH = 4
    ASSOCIATIVE = 5
    LARGEST = 6


class CoffError(ValueError):
    pass


@dataclass(frozen=True)
class Relocation:
    offset: int  # relative to the start of the section's raw data
    symbol_index: int
    type: int

    @property
    def size(self) -> int:
        if self.type == RelocType.ADDR64:
            return 8
        if self.type in (RelocType.SECTION,):
            return 2
        return 4


@dataclass(frozen=True)
class SectionAux:
    length: int
    num_relocs: int
    num_lines: int
    checksum: int
    number: int  # associated section (1-based) for ASSOCIATIVE COMDATs
    selection: int


@dataclass
class Symbol:
    index: int
    name: str
    value: int
    section_number: int  # 1-based; 0 = undefined, -1 = absolute, -2 = debug
    type: int
    storage_class: int
    num_aux: int
    section_aux: SectionAux | None = None

    @property
    def is_function(self) -> bool:
        return (self.type >> 4) == IMAGE_SYM_DTYPE_FUNCTION

    @property
    def is_external(self) -> bool:
        return self.storage_class == IMAGE_SYM_CLASS_EXTERNAL

    @property
    def is_undefined(self) -> bool:
        return self.section_number == 0 and self.storage_class == IMAGE_SYM_CLASS_EXTERNAL


@dataclass
class Section:
    number: int  # 1-based
    name: str
    virtual_size: int
    raw_size: int
    raw_offset: int
    reloc_offset: int
    num_relocs: int
    characteristics: int
    data: bytes = b""
    relocs: list[Relocation] = field(default_factory=list)

    @property
    def is_comdat(self) -> bool:
        return bool(self.characteristics & IMAGE_SCN_LNK_COMDAT)

    @property
    def is_code(self) -> bool:
        return bool(self.characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE))


@dataclass
class CoffObject:
    machine: int
    bigobj: bool
    sections: list[Section]
    symbols: list[Symbol | None]  # indexed by symbol table index; aux slots are None

    def section(self, number: int) -> Section:
        if not 1 <= number <= len(self.sections):
            raise CoffError(f"section number {number} out of range")
        return self.sections[number - 1]

    def symbol(self, index: int) -> Symbol:
        sym = self.symbols[index] if 0 <= index < len(self.symbols) else None
        if sym is None:
            raise CoffError(f"symbol index {index} is not a primary symbol")
        return sym

    def iter_symbols(self) -> list[Symbol]:
        return [s for s in self.symbols if s is not None]

    def section_symbol(self, number: int) -> Symbol | None:
        """The symbol carrying the section-definition aux record for a section."""
        for sym in self.iter_symbols():
            if sym.section_number == number and sym.section_aux is not None:
                return sym
        return None


def parse_coff(data: bytes) -> CoffObject:
    if len(data) < 20:
        raise CoffError("file too small for a COFF header")
    sig1, sig2 = struct.unpack_from("<HH", data, 0)
    bigobj = sig1 == 0 and sig2 == 0xFFFF and data[12:28] == _BIGOBJ_CLSID
    if bigobj:
        (machine,) = struct.unpack_from("<H", data, 6)
        nsects, symtab_off, nsyms = struct.unpack_from("<III", data, 44)
        sect_off = 56
        sym_size = 20
        opt_size = 0
    else:
        machine, nsects16, _ts, symtab_off, nsyms, opt_size, _ch = struct.unpack_from(
            "<HHIIIHH", data, 0
        )
        nsects = nsects16
        sect_off = 20 + opt_size
        sym_size = 18
    if machine != IMAGE_FILE_MACHINE_AMD64:
        raise CoffError(f"unsupported machine 0x{machine:04x} (only AMD64)")

    strtab_off = symtab_off + nsyms * sym_size
    strtab = data[strtab_off:] if strtab_off <= len(data) else b""

    def strtab_name(off: int) -> str:
        end = strtab.find(b"\0", off)
        return strtab[off : end if end >= 0 else len(strtab)].decode("utf-8", "replace")

    sections: list[Section] = []
    for i in range(nsects):
        off = sect_off + i * 40
        raw_name = data[off : off + 8]
        (vsize, _vaddr, raw_size, raw_ptr, reloc_ptr, _lines, nrel, _nlines, chars) = (
            struct.unpack_from("<IIIIIIHHI", data, off + 8)
        )
        name = raw_name.rstrip(b"\0").decode("utf-8", "replace")
        if name.startswith("/"):
            name = strtab_name(int(name[1:]))
        sec = Section(i + 1, name, vsize, raw_size, raw_ptr, reloc_ptr, nrel, chars)
        if raw_size and raw_ptr:
            sec.data = data[raw_ptr : raw_ptr + raw_size]
        count = nrel
        rpos = reloc_ptr
        if chars & IMAGE_SCN_LNK_NRELOC_OVFL and nrel == 0xFFFF:
            (count,) = struct.unpack_from("<I", data, reloc_ptr)
            rpos += 10
            count -= 1
        for r in range(count):
            roff, rsym, rtype = struct.unpack_from("<IIH", data, rpos + r * 10)
            sec.relocs.append(Relocation(roff, rsym, rtype))
        sections.append(sec)

    symbols: list[Symbol | None] = [None] * nsyms
    i = 0
    while i < nsyms:
        off = symtab_off + i * sym_size
        raw_name = data[off : off + 8]
        if bigobj:
            value, secnum, typ, sclass, naux = struct.unpack_from("<IiHBB", data, off + 8)
        else:
            value, secnum16, typ, sclass, naux = struct.unpack_from("<IhHBB", data, off + 8)
            secnum = secnum16
        if raw_name[:4] == b"\0\0\0\0":
            (stroff,) = struct.unpack_from("<I", raw_name, 4)
            name = strtab_name(stroff)
        else:
            name = raw_name.rstrip(b"\0").decode("utf-8", "replace")
        sym = Symbol(i, name, value, secnum, typ, sclass, naux)
        if sclass == IMAGE_SYM_CLASS_STATIC and naux >= 1 and secnum > 0 and value == 0:
            aoff = off + sym_size
            length, nrel, nlin, csum, num_lo, sel = struct.unpack_from("<IHHIHB", data, aoff)
            num = num_lo
            if bigobj:
                (num_hi,) = struct.unpack_from("<H", data, aoff + 16)
                num |= num_hi << 16
            # Only section-name symbols carry this record; labels like $LN5 have naux == 0.
            if 0 < secnum <= len(sections) and name == sections[secnum - 1].name:
                sym.section_aux = SectionAux(length, nrel, nlin, csum, num, sel)
        symbols[i] = sym
        i += 1 + naux
    return CoffObject(machine, bigobj, sections, symbols)
