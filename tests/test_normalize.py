"""One test per normalization rule (CLAUDE.md 1.3)."""

from mscmatch.blob import (
    FunctionBlob,
    FunctionReloc,
    RelocKind,
    RelocTarget,
    RuntimeFunction,
    TargetKind,
    UnwindCode,
    UnwindInfo,
)
from mscmatch.disasm import UnwindMode, normalize


def rel(off: int, kind: TargetKind, name: str, addend: int = 0) -> FunctionReloc:
    return FunctionReloc(off, 4, RelocKind.REL32, RelocTarget(kind, name, addend))


def selfref(off: int, target: int, kind: RelocKind = RelocKind.RVA32) -> FunctionReloc:
    return FunctionReloc(off, 4, kind, RelocTarget(TargetKind.SELF, f"+{target:#x}", 0, target))


def texts(blob: FunctionBlob, mode: UnwindMode = UnwindMode.CODES) -> list[str]:
    return [i.text for i in normalize(blob, mode).insns]


def test_call_rel32_becomes_sym_token() -> None:
    blob = FunctionBlob("f", bytes.fromhex("e800000000c3"), [rel(1, TargetKind.SYM, "foo")])
    assert texts(blob) == ["call <sym:foo>", "ret"]


def test_sym_addend_is_kept() -> None:
    code = bytes.fromhex("8b0500000000c3")  # mov eax,[rip+X]
    blob = FunctionBlob("f", code, [rel(2, TargetKind.SYM, "arr", 8)])
    assert texts(blob) == ["mov eax, dword ptr [<sym:arr+0x8>]", "ret"]


def test_import_call_becomes_imp_token() -> None:
    code = bytes.fromhex("ff1500000000c3")  # call [rip+X]
    blob = FunctionBlob("f", code, [rel(2, TargetKind.IMP, "CreateFileW")])
    assert texts(blob) == ["call qword ptr [<imp:CreateFileW>]", "ret"]


def test_string_literals_numbered_by_first_appearance() -> None:
    lea = "488d0d00000000"  # lea rcx,[rip+X]
    code = bytes.fromhex(lea * 3 + "c3")
    blob = FunctionBlob(
        "f",
        code,
        [
            rel(3, TargetKind.STR, "??_C@b"),
            rel(10, TargetKind.STR, "??_C@a"),
            rel(17, TargetKind.STR, "??_C@b"),
        ],
    )
    assert texts(blob)[:3] == ["lea rcx, [<str:0>]", "lea rcx, [<str:1>]", "lea rcx, [<str:0>]"]


def test_anonymous_data_numbered_and_distinguished_by_addend() -> None:
    lea = "488d0d00000000"
    blob = FunctionBlob(
        "f",
        bytes.fromhex(lea * 2 + "c3"),
        [rel(3, TargetKind.DATA, ".rdata", 0x10), rel(10, TargetKind.DATA, ".rdata", 0x20)],
    )
    assert texts(blob)[:2] == ["lea rcx, [<data:0>]", "lea rcx, [<data:1>]"]


def test_fp_constant_keeps_name() -> None:
    code = bytes.fromhex("f20f590500000000c3")  # mulsd xmm0,[rip+X]
    blob = FunctionBlob("f", code, [rel(4, TargetKind.CONST, "__real@3ff8000000000000")])
    assert texts(blob)[0] == "mulsd xmm0, qword ptr [<const:__real@3ff8000000000000>]"


def test_rip_relative_without_relocation_is_self_reference() -> None:
    code = bytes.fromhex("488d0500000000c3")  # lea rax,[rip+0] -> offset 7 = the ret
    assert texts(FunctionBlob("f", code))[0] == "lea rax, [L1]"


def test_intra_function_branches_become_labels() -> None:
    # 0: test ecx,ecx ; 2: je 7 ; 4: mov eax,1 ... use simpler: je +1 ; inc eax ; ret
    code = bytes.fromhex("85c97402ffc0c3")
    assert texts(FunctionBlob("f", code)) == ["test ecx, ecx", "je L3", "inc eax", "ret"]


def test_trailing_int3_and_nop_padding_stripped() -> None:
    code = bytes.fromhex("c3cccccc900f1f00")
    assert texts(FunctionBlob("f", code)) == ["ret"]


def test_abs64_immediate_token() -> None:
    code = bytes.fromhex("48b80000000000000000c3")
    blob = FunctionBlob(
        "f", code, [FunctionReloc(2, 8, RelocKind.ABS64, RelocTarget(TargetKind.SYM, "g"))]
    )
    assert texts(blob)[0] == "mov rax, <sym:g>"


def test_jump_table_rendered_as_data() -> None:
    # 0: lea rdx,[__ImageBase] ; 7: mov ecx,[rdx+rax*4+TABLE] ; e: add rcx,rdx ; 11: jmp rcx
    # 13: mov eax,1 (b801000000) ; 18: ret ; 19: mov eax,2 ; 1e: ret ; 1f: int3 ; 20: table
    code = bytes.fromhex(
        "488d1500000000" "8b8c8200000000" "4803ca" "ffe1"
        "b801000000" "c3" "b802000000" "c3" "cc"
        "00000000" "00000000"
    )  # fmt: skip
    relocs = [
        rel(3, TargetKind.SYM, "__ImageBase"),
        selfref(0x0A, 0x20),
        selfref(0x20, 0x13),
        selfref(0x24, 0x19),
    ]
    out = texts(FunctionBlob("f", code, relocs))
    assert out == [
        "lea rdx, [<sym:__ImageBase>]",
        "mov ecx, dword ptr [rdx+rax*4+<tbl:+0x0>]",
        "add rcx, rdx",
        "jmp rcx",
        "mov eax, 1",
        "ret",
        "mov eax, 2",
        "ret",
        "dd L4",
        "dd L6",
    ]


def _unwind_blob() -> FunctionBlob:
    info = UnwindInfo(1, 1, 4, 0, 0, [UnwindCode(4, "ALLOC_SMALL", "0x28")])
    info.handler = RelocTarget(TargetKind.SYM, "__GSHandlerCheck")
    info.handler_data = b"\x20\0\0\0"
    code = bytes.fromhex("4883ec284883c428c3")
    return FunctionBlob("f", code, [], [RuntimeFunction(0, 9, info)], 9)


def test_unwind_modes() -> None:
    blob = _unwind_blob()
    assert normalize(blob, UnwindMode.NONE).unwind == []
    codes = normalize(blob, UnwindMode.CODES).unwind
    assert codes == [
        "PDATA L0..+0x9",
        "  UNWIND v1 flags=EHANDLER prolog=0x4 frame=none",
        "  @0x4 ALLOC_SMALL 0x28",
    ]
    full = normalize(blob, UnwindMode.FULL).unwind
    assert full[-1] == "  HANDLER <sym:__GSHandlerCheck> data=20000000"


def test_listing_is_stable() -> None:
    fn = normalize(FunctionBlob("f", bytes.fromhex("31c0c3")))
    assert fn.listing(with_offsets=False) == "L0    xor eax, eax\nL1    ret"
