"""PE32+ image parsing: sections, Rich header, imports, exports, pdata, base relocs, load config."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from functools import cached_property

IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_WRITE = 0x80000000

DIR_EXPORT, DIR_IMPORT, DIR_EXCEPTION, DIR_BASERELOC = 0, 1, 3, 5
DIR_DEBUG, DIR_LOAD_CONFIG, DIR_IAT, DIR_DELAY_IMPORT = 6, 10, 12, 13


class PEError(ValueError):
    pass


@dataclass(frozen=True)
class PESection:
    name: str
    rva: int
    vsize: int
    raw_offset: int
    raw_size: int
    characteristics: int

    @property
    def executable(self) -> bool:
        return bool(self.characteristics & IMAGE_SCN_MEM_EXECUTE)

    @property
    def writable(self) -> bool:
        return bool(self.characteristics & IMAGE_SCN_MEM_WRITE)

    def contains(self, rva: int) -> bool:
        return self.rva <= rva < self.rva + max(self.vsize, self.raw_size)


@dataclass(frozen=True)
class RichEntry:
    prodid: int
    build: int
    count: int


@dataclass(frozen=True)
class PdataEntry:
    begin: int
    end: int
    unwind_rva: int


@dataclass
class PEImage:
    data: bytes
    image_base: int
    entry_rva: int
    linker_version: tuple[int, int]
    timestamp: int
    sections: list[PESection]
    dirs: list[tuple[int, int]]
    rich: list[RichEntry] = field(default_factory=list)
    coff_symbols: int = 0  # COFF symbol count in the file header (MSVC link never keeps any)

    # -- address helpers -------------------------------------------------------------------
    def section_of(self, rva: int) -> PESection | None:
        for s in self.sections:
            if s.contains(rva):
                return s
        return None

    def read(self, rva: int, size: int) -> bytes:
        s = self.section_of(rva)
        if s is None:
            raise PEError(f"rva {rva:#x} not in any section")
        off = rva - s.rva
        out = self.data[s.raw_offset + off : s.raw_offset + min(off + size, s.raw_size)]
        return out + b"\0" * (size - len(out))  # virtual (bss) tail reads as zero

    def u32(self, rva: int) -> int:
        return int(struct.unpack("<I", self.read(rva, 4))[0])

    def u64(self, rva: int) -> int:
        return int(struct.unpack("<Q", self.read(rva, 8))[0])

    def cstr(self, rva: int, limit: int = 4096) -> bytes:
        s = self.section_of(rva)
        if s is None:
            return b""
        off = s.raw_offset + rva - s.rva
        end = self.data.find(b"\0", off, off + limit)
        return self.data[off : end if end >= 0 else off]

    def dir(self, idx: int) -> tuple[int, int]:
        return self.dirs[idx] if idx < len(self.dirs) else (0, 0)

    # -- tables ------------------------------------------------------------------------------
    @cached_property
    def imports(self) -> dict[int, str]:
        """IAT slot RVA -> imported function name (or 'dll!#ordinal')."""
        out: dict[int, str] = {}
        rva, _size = self.dir(DIR_IMPORT)
        if rva:
            pos = rva
            while True:
                oft, _ts, _fc, name_rva, ft = struct.unpack("<IIIII", self.read(pos, 20))
                if not (oft or name_rva or ft):
                    break
                self._walk_thunks(out, oft or ft, ft, name_rva)
                pos += 20
        drva, _dsize = self.dir(DIR_DELAY_IMPORT)
        if drva:
            pos = drva
            while True:
                fields = struct.unpack("<IIIIIIII", self.read(pos, 32))
                _attrs, name_rva, _hmod, iat, int_rva = fields[:5]
                if not name_rva:
                    break
                self._walk_thunks(out, int_rva, iat, name_rva)
                pos += 32
        return out

    def _walk_thunks(self, out: dict[int, str], lookup: int, iat: int, dll_rva: int) -> None:
        dll = self.cstr(dll_rva).decode("ascii", "replace")
        i = 0
        while True:
            entry = self.u64(lookup + i * 8)
            if entry == 0:
                break
            if entry >> 63:
                out[iat + i * 8] = f"{dll}!#{entry & 0xFFFF}"
            else:
                out[iat + i * 8] = self.cstr((entry & 0x7FFFFFFF) + 2).decode("ascii", "replace")
            i += 1
            if i > 100000:
                raise PEError("runaway import thunk table")

    @cached_property
    def import_dlls(self) -> list[str]:
        """Names of directly imported DLLs, in table order."""
        rva, _size = self.dir(DIR_IMPORT)
        out: list[str] = []
        pos = rva
        while rva:
            oft, _ts, _fc, name_rva, ft = struct.unpack("<IIIII", self.read(pos, 20))
            if not (oft or name_rva or ft):
                break
            out.append(self.cstr(name_rva).decode("ascii", "replace"))
            pos += 20
        return out

    @cached_property
    def debug_types(self) -> list[int]:
        """IMAGE_DEBUG_DIRECTORY entry types (2 CODEVIEW, 12 VC_FEATURE, 13 POGO, 16 REPRO...)."""
        rva, size = self.dir(DIR_DEBUG)
        if not rva:
            return []
        raw = self.read(rva, size)
        return [int(struct.unpack_from("<I", raw, off + 12)[0]) for off in range(0, size - 27, 28)]

    @cached_property
    def exports(self) -> dict[str, int]:
        rva, _size = self.dir(DIR_EXPORT)
        if not rva:
            return {}
        (_c, _ts, _maj, _min, _name, _base, _nfuncs, nnames, funcs, names, ords) = struct.unpack(
            "<IIHHIIIIIII", self.read(rva, 40)
        )
        out: dict[str, int] = {}
        for i in range(nnames):
            name = self.cstr(self.u32(names + i * 4)).decode("ascii", "replace")
            ordinal = struct.unpack("<H", self.read(ords + i * 2, 2))[0]
            out[name] = self.u32(funcs + ordinal * 4)
        return out

    @cached_property
    def pdata(self) -> list[PdataEntry]:
        rva, size = self.dir(DIR_EXCEPTION)
        if not rva:
            return []
        raw = self.read(rva, size)
        return [
            PdataEntry(*struct.unpack_from("<III", raw, off)) for off in range(0, size - 11, 12)
        ]

    @cached_property
    def base_relocs(self) -> set[int]:
        """RVAs patched by DIR64 base relocations."""
        out: set[int] = set()
        rva, size = self.dir(DIR_BASERELOC)
        pos, end = rva, rva + size
        while rva and pos < end:
            page, block = struct.unpack("<II", self.read(pos, 8))
            if block < 8:
                break
            entries = self.read(pos + 8, block - 8)
            for (e,) in struct.iter_unpack("<H", entries):
                if e >> 12 == 10:  # IMAGE_REL_BASED_DIR64
                    out.add(page + (e & 0xFFF))
            pos += block
        return out

    @cached_property
    def load_config(self) -> dict[str, int]:
        rva, size = self.dir(DIR_LOAD_CONFIG)
        if not rva:
            return {}
        raw = self.read(rva, max(size, 4))
        (lc_size,) = struct.unpack_from("<I", raw, 0)
        raw = self.read(rva, lc_size)
        fields = {
            "SecurityCookie": 0x58,
            "GuardCFCheckFunctionPointer": 0x70,
            "GuardCFDispatchFunctionPointer": 0x78,
            "GuardCFFunctionTable": 0x80,
            "GuardCFFunctionCount": 0x88,
            "GuardFlags": 0x90,
        }
        out: dict[str, int] = {"Size": lc_size}
        for k, off in fields.items():
            if off + 8 <= lc_size:
                size_ = 4 if k == "GuardFlags" else 8
                out[k] = int.from_bytes(raw[off : off + size_], "little")
        return out

    @cached_property
    def security_cookie_rva(self) -> int | None:
        va = self.load_config.get("SecurityCookie")
        return va - self.image_base if va else None


def _parse_rich(data: bytes, e_lfanew: int) -> list[RichEntry]:
    end = data.find(b"Rich", 0x80, e_lfanew)
    if end < 0:
        return []
    key = data[end + 4 : end + 8]
    kint = int.from_bytes(key, "little")
    pos = end - 4
    words: list[int] = []
    while pos >= 0x40:
        w = int.from_bytes(data[pos : pos + 4], "little") ^ kint
        if w == 0x536E6144:  # "DanS"
            break
        words.append(w)
        pos -= 4
    else:
        return []
    words.reverse()
    # words: 3 padding dwords, then (comp.id, count) pairs
    out = []
    for i in range(3, len(words) - 1, 2):
        compid, count = words[i], words[i + 1]
        out.append(RichEntry(compid >> 16, compid & 0xFFFF, count))
    return out


def parse_pe(data: bytes) -> PEImage:
    if data[:2] != b"MZ":
        raise PEError("not an MZ image")
    (e_lfanew,) = struct.unpack_from("<I", data, 0x3C)
    if data[e_lfanew : e_lfanew + 4] != b"PE\0\0":
        raise PEError("missing PE signature")
    coff = e_lfanew + 4
    machine, nsects, ts, symtab, nsyms, opt_size, _ch = struct.unpack_from("<HHIIIHH", data, coff)
    if machine != 0x8664:
        raise PEError(f"unsupported machine {machine:#x}")
    opt = coff + 20
    magic, lmaj, lmin = struct.unpack_from("<HBB", data, opt)
    if magic != 0x20B:
        raise PEError("not PE32+")
    (entry,) = struct.unpack_from("<I", data, opt + 16)
    (image_base,) = struct.unpack_from("<Q", data, opt + 24)
    (ndirs,) = struct.unpack_from("<I", data, opt + 108)
    dirs = [struct.unpack_from("<II", data, opt + 112 + i * 8) for i in range(min(ndirs, 16))]
    sections = []
    sect = opt + opt_size
    for i in range(nsects):
        off = sect + i * 40
        name = data[off : off + 8].rstrip(b"\0").decode("ascii", "replace")
        vsize, rva, raw_size, raw_off = struct.unpack_from("<IIII", data, off + 8)
        (chars,) = struct.unpack_from("<I", data, off + 36)
        sections.append(PESection(name, rva, vsize, raw_off, raw_size, chars))
    return PEImage(
        data, image_base, entry, (lmaj, lmin), ts, sections,
        [(int(a), int(b)) for a, b in dirs], _parse_rich(data, e_lfanew),
        int(nsyms) if symtab else 0,
    )  # fmt: skip
