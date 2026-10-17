"""Minimal PDB (MSF 7.0) reader: per-compiland compiler build and command line.

Only what fingerprinting needs: the DBI module list, and from each module symbol stream the
S_COMPILE3 (compiler version, language) and S_ENVBLOCK (cwd / cl / cmd) records.
"""

from __future__ import annotations

import re
import shlex
import struct
from dataclasses import dataclass, field

MSF_MAGIC = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0"
S_COMPILE3 = 0x113C
S_ENVBLOCK = 0x113D
DBI_STREAM = 3

# Flags that change code generation; everything else (includes, defines, output paths) is not
# part of a toolchain configuration.
_CODEGEN = re.compile(
    r"^/(O[12dsxtyib]\d?|Oi-?|Oy-?|GS-?|Gy-?|Gw-?|GL-?|GF-?|Gs\d*|Gd|Gr|Gz|Gv|"
    r"guard:.+|Qspectre.*|Qpar-?|arch:.+|fp:.+|M[TD]d?|J|Zp\d*|volatile:.+|"
    r"EH.*|RTC.*|sdl-?|Zc:.+|std:.+|Ob\d|TC|TP|Tc|Tp)$"
)


class PDBError(ValueError):
    pass


@dataclass
class Compiland:
    module: str
    obj: str
    language: str = ""
    frontend_build: int = 0
    backend_build: int = 0
    version: str = ""
    env: dict[str, str] = field(default_factory=dict)

    @property
    def command(self) -> str:
        return self.env.get("cmd", "")

    def codegen_flags(self) -> tuple[str, ...]:
        return codegen_flags(self.command)


def codegen_flags(cmd: str) -> tuple[str, ...]:
    out = []
    for tok in shlex.split(cmd, posix=False):
        if tok[:1] in "-/":
            flag = "/" + tok[1:]
            if _CODEGEN.match(flag):
                out.append(flag)
    return tuple(out)


class _MSF:
    def __init__(self, data: bytes) -> None:
        if not data.startswith(MSF_MAGIC):
            raise PDBError("not an MSF 7.0 PDB")
        self.data = data
        bs, _fpm, _nblocks, dir_bytes, _unk, map_addr = struct.unpack_from("<IIIIII", data, 32)
        self.bs = bs
        ndir_blocks = (dir_bytes + bs - 1) // bs
        dir_block_ids = struct.unpack_from(f"<{ndir_blocks}I", data, map_addr * bs)
        directory = b"".join(self._block(b) for b in dir_block_ids)[:dir_bytes]
        (nstreams,) = struct.unpack_from("<I", directory, 0)
        sizes = struct.unpack_from(f"<{nstreams}I", directory, 4)
        pos = 4 + 4 * nstreams
        self.streams: list[list[int]] = []
        self.sizes: list[int] = []
        for size in sizes:
            if size == 0xFFFFFFFF:
                self.streams.append([])
                self.sizes.append(0)
                continue
            n = (size + bs - 1) // bs
            self.streams.append(list(struct.unpack_from(f"<{n}I", directory, pos)))
            self.sizes.append(size)
            pos += 4 * n

    def _block(self, idx: int) -> bytes:
        return self.data[idx * self.bs : (idx + 1) * self.bs]

    def stream(self, idx: int) -> bytes:
        if idx >= len(self.streams):
            raise PDBError(f"stream {idx} out of range")
        return b"".join(self._block(b) for b in self.streams[idx])[: self.sizes[idx]]


def _cstr(buf: bytes, pos: int) -> tuple[str, int]:
    end = buf.index(b"\0", pos)
    return buf[pos:end].decode("utf-8", "replace"), end + 1


def read_compilands(data: bytes) -> list[Compiland]:
    msf = _MSF(data)
    dbi = msf.stream(DBI_STREAM)
    if len(dbi) < 64:
        raise PDBError("DBI stream missing")
    (mod_size,) = struct.unpack_from("<i", dbi, 24)
    mods = dbi[64 : 64 + mod_size]
    out: list[Compiland] = []
    pos = 0
    while pos + 64 <= len(mods):
        sym_stream, sym_bytes = struct.unpack_from("<HI", mods, pos + 34)
        module, p2 = _cstr(mods, pos + 64)
        obj, p3 = _cstr(mods, p2)
        pos = (p3 + 3) & ~3
        c = Compiland(module, obj)
        if sym_stream != 0xFFFF and sym_bytes:
            _parse_symbols(msf.stream(sym_stream)[:sym_bytes], c)
        out.append(c)
    return out


def _parse_symbols(buf: bytes, c: Compiland) -> None:
    pos = 4  # CV_SIGNATURE_C13
    while pos + 4 <= len(buf):
        reclen, kind = struct.unpack_from("<HH", buf, pos)
        body = buf[pos + 4 : pos + 2 + reclen]
        if kind == S_COMPILE3 and len(body) >= 22:
            flags = struct.unpack_from("<I", body, 0)[0]
            fe = struct.unpack_from("<HHHH", body, 6)
            be = struct.unpack_from("<HHHH", body, 14)
            c.language = {0: "C", 1: "C++"}.get(flags & 0xFF, str(flags & 0xFF))
            c.frontend_build, c.backend_build = fe[2], be[2]
            c.version = body[22:].split(b"\0", 1)[0].decode("utf-8", "replace")
        elif kind == S_ENVBLOCK and body:
            items = body[1:].split(b"\0")
            strs = [s.decode("utf-8", "replace") for s in items]
            for k, v in zip(strs[0::2], strs[1::2], strict=False):
                if k:
                    c.env[k] = v
        if reclen < 2:
            break
        pos += 2 + reclen
