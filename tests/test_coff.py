import struct

import pytest

from mscmatch.blob import RelocKind, TargetKind
from mscmatch.coff import CoffError, extract_function, list_functions, parse_coff
from tests.coffbuilder import PDATA, RDATA, CoffBuilder

REL32, ADDR32NB, ADDR64 = 4, 3, 1

# sub rsp,28h ; call foo ; lea rcx,[rip+str] ; add rsp,28h ; ret
CODE = bytes.fromhex("4883ec28e800000000488d0d000000004883c428c3")
# UNWIND_INFO v1: prolog 4, 1 code: @4 ALLOC_SMALL 0x28 (info=4)
XDATA = bytes([0x01, 0x04, 0x01, 0x00, 0x04, 0x42, 0x00, 0x00])


def build(bigobj: bool = False) -> bytes:
    b = CoffBuilder()
    text = b.section(".text$mn", CODE, relocs=[(5, "foo", REL32), (12, "??_C@_03abc@", REL32)])
    rdata = b.section(".rdata", b"abc\0", chars=RDATA, comdat_sel=2)
    xdata = b.section(".xdata", XDATA, chars=RDATA, assoc=text)
    b.section(
        ".pdata",
        b"\0" * 12,
        chars=PDATA,
        assoc=text,
        relocs=[(0, "f", ADDR32NB), (4, "f", ADDR32NB), (8, "$unwind$f", ADDR32NB)],
    )
    # pdata end field carries the in-place addend (function length).
    b.symbol("f", text, function=True)
    b.symbol("foo", None, function=True)
    b.symbol("??_C@_03abc@", rdata)
    b.symbol("$unwind$f", xdata, static=True)
    raw = bytearray(b.build(bigobj))
    obj = parse_coff(bytes(raw))
    pdata = next(s for s in obj.sections if s.name == ".pdata")
    struct.pack_into("<I", raw, pdata.raw_offset + 4, len(CODE))
    return bytes(raw)


@pytest.mark.parametrize("bigobj", [False, True])
def test_parse_sections_symbols_relocs(bigobj: bool) -> None:
    obj = parse_coff(build(bigobj))
    assert obj.bigobj is bigobj
    assert [s.name for s in obj.sections] == [".text$mn", ".rdata", ".xdata", ".pdata"]
    text = obj.sections[0]
    assert text.is_comdat and text.is_code
    assert [(r.offset, r.type) for r in text.relocs] == [(5, REL32), (12, REL32)]
    ssym = obj.section_symbol(3)
    assert ssym is not None and ssym.section_aux is not None
    assert ssym.section_aux.selection == 5 and ssym.section_aux.number == 1
    assert list_functions(obj) == ["f"]


@pytest.mark.parametrize("bigobj", [False, True])
def test_extract_function(bigobj: bool) -> None:
    blob = extract_function(build(bigobj), "f")
    assert blob.code == CODE
    kinds = [(r.offset, r.kind, r.target.kind, r.target.name) for r in blob.relocs]
    assert kinds == [
        (5, RelocKind.REL32, TargetKind.SYM, "foo"),
        (12, RelocKind.REL32, TargetKind.STR, "??_C@_03abc@"),
    ]
    assert len(blob.pdata) == 1
    rf = blob.pdata[0]
    assert (rf.begin, rf.end) == (0, len(CODE))
    assert rf.unwind is not None
    assert [c.render() for c in rf.unwind.codes] == ["@0x4 ALLOC_SMALL 0x28"]
    assert blob.code_size == len(CODE)


def test_missing_function() -> None:
    with pytest.raises(CoffError):
        extract_function(build(), "nope")


def test_rejects_non_amd64() -> None:
    raw = bytearray(build())
    struct.pack_into("<H", raw, 0, 0x14C)
    with pytest.raises(CoffError):
        parse_coff(bytes(raw))


def test_inplace_addend_and_abs64() -> None:
    code = bytes.fromhex("48b81000000000000000c3")  # mov rax, imm64 (addend 0x10) ; ret
    b = CoffBuilder()
    text = b.section(".text$mn", code, relocs=[(2, "tbl", ADDR64)])
    data = b.section(".data", b"\0" * 32, chars=0xC0300040)
    b.symbol("g", text, function=True)
    b.symbol("tbl", data)
    blob = extract_function(b.build(), "g")
    (r,) = blob.relocs
    assert r.kind is RelocKind.ABS64 and r.size == 8
    assert r.target.name == "tbl" and r.target.addend == 0x10
