"""Tiny COFF writer for tests: enough to exercise COMDAT, relocations, pdata/xdata, bigobj."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

COMDAT_TEXT = 0x60501020
RDATA = 0x40301040
PDATA = 0x40301040


@dataclass
class _Sec:
    name: str
    data: bytes
    chars: int
    relocs: list[tuple[int, str, int]] = field(default_factory=list)  # (offset, symbol, type)
    comdat_sel: int = 0
    assoc: str | None = None


@dataclass
class _Sym:
    name: str
    section: str | None  # None = undefined
    value: int = 0
    type: int = 0
    sclass: int = 2


class CoffBuilder:
    def __init__(self) -> None:
        self.secs: list[_Sec] = []
        self.syms: list[_Sym] = []

    def section(
        self,
        name: str,
        data: bytes,
        chars: int = COMDAT_TEXT,
        relocs: list[tuple[int, str, int]] | None = None,
        comdat_sel: int = 2,
        assoc: str | None = None,
        key: str | None = None,
    ) -> str:
        key = key or f"{name}#{len(self.secs)}"
        s = _Sec(name, data, chars, relocs or [], comdat_sel, assoc)
        s.name = name
        self.secs.append(s)
        self._keys = getattr(self, "_keys", [])
        self._keys.append(key)
        return key

    def symbol(self, name: str, section: str | None, value: int = 0, function: bool = False,
               static: bool = False) -> None:  # fmt: skip
        self.syms.append(_Sym(name, section, value, 0x20 if function else 0, 3 if static else 2))

    def build(self, bigobj: bool = False) -> bytes:
        keys: list[str] = self._keys
        secnum = {k: i + 1 for i, k in enumerate(keys)}
        sym_size = 20 if bigobj else 18
        # Symbol table: per section a section symbol + aux, then user symbols.
        table: list[bytes] = []
        index: dict[str, int] = {}
        strtab = bytearray(4)

        def name_field(n: str) -> bytes:
            raw = n.encode()
            if len(raw) <= 8:
                return raw.ljust(8, b"\0")
            off = len(strtab)
            strtab.extend(raw + b"\0")
            return b"\0\0\0\0" + struct.pack("<I", off)

        def sym(n: str, value: int, sec: int, typ: int, sclass: int, naux: int) -> bytes:
            fmt = "<IiHBB" if bigobj else "<IhHBB"
            return name_field(n) + struct.pack(fmt, value, sec, typ, sclass, naux)

        for k, s in zip(keys, self.secs, strict=True):
            index[k] = len(table)
            table.append(sym(s.name, 0, secnum[k], 0, 3, 1))
            assoc = secnum[s.assoc] if s.assoc else 0
            sel = 5 if s.assoc else s.comdat_sel
            aux = struct.pack("<IHHIHB", len(s.data), len(s.relocs), 0, 0, assoc & 0xFFFF, sel)
            aux += struct.pack("<H", assoc >> 16) if bigobj else b""
            table.append(aux.ljust(sym_size, b"\0"))
        for s_ in self.syms:
            index[s_.name] = len(table)
            sec = secnum[s_.section] if s_.section else 0
            table.append(sym(s_.name, s_.value, sec, s_.type, s_.sclass, 0))

        nsects = len(self.secs)
        hdr_size = 56 if bigobj else 20
        pos = hdr_size + 40 * nsects
        sec_hdrs = b""
        body = b""
        for s in self.secs:
            raw_ptr = pos + len(body)
            body += s.data
            rel_ptr = pos + len(body) if s.relocs else 0
            for off, target, typ in s.relocs:
                body += struct.pack("<IIH", off, index[target], typ)
            sec_hdrs += name_field(s.name)[:8] if len(s.name) <= 8 else self._long(s.name, strtab)
            sec_hdrs += struct.pack(
                "<IIIIIIHHI", 0, 0, len(s.data), raw_ptr, rel_ptr, 0, len(s.relocs), 0, s.chars
            )
        symtab_off = pos + len(body)
        nsyms = len(table)
        if bigobj:
            clsid = bytes.fromhex("c7a1bad1eebaa94baf20faf66aa4dcb8")
            header = struct.pack("<HHHHI", 0, 0xFFFF, 2, 0x8664, 0) + clsid
            header += b"\0" * 16 + struct.pack("<III", nsects, symtab_off, nsyms)
        else:
            header = struct.pack("<HHIIIHH", 0x8664, nsects, 0, symtab_off, nsyms, 0, 0)
        struct.pack_into("<I", strtab, 0, len(strtab))
        return header + sec_hdrs + body + b"".join(table) + bytes(strtab)

    @staticmethod
    def _long(name: str, strtab: bytearray) -> bytes:
        off = len(strtab)
        strtab.extend(name.encode() + b"\0")
        return f"/{off}".encode().ljust(8, b"\0")
