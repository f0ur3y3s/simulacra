"""Hand-checked scoring examples, cross-referenced with how objdiff / asm-differ classify them.

objdiff and asm-differ both diff relocation-aware instruction streams: relocation targets are
compared by symbol, not by encoded displacement; branch targets inside the function are compared
after alignment; register-only differences are reported separately from other argument changes
(asm-differ prints them as `r`, objdiff as an argument mismatch with the same opcode). The cases
below were worked by hand from MSVC /O2 output and assert the same classification here.
"""

import pytest

from simulacra.disasm import NormalizedFunction, NormInsn
from simulacra.score import score


def fn(*lines: str) -> NormalizedFunction:
    out = []
    for i, line in enumerate(lines):
        mnem, _, rest = line.partition(" ")
        out.append(NormInsn(i, mnem, tuple(o.strip() for o in rest.split(",")) if rest else ()))
    return NormalizedFunction("f", out)


def test_swapped_operand_registers_is_regalloc() -> None:
    # `a*3+b` vs `b+a*3`: MSVC picks lea with swapped base/index -> regalloc-only (asm-differ 'r')
    t = fn("lea eax, [rdx+rcx*2]", "ret")
    c = fn("lea eax, [rcx+rdx*2]", "ret")
    r = score(t, c)
    assert r.marks.get("~") == 1 and r.distance == pytest.approx(0.3)


def test_different_call_target_is_argument_mismatch() -> None:
    # objdiff: same opcode, relocation to a different symbol -> argument mismatch
    t = fn("sub rsp, 0x28", "call <sym:foo>", "add rsp, 0x28", "ret")
    c = fn("sub rsp, 0x28", "call <sym:bar>", "add rsp, 0x28", "ret")
    r = score(t, c)
    assert r.marks.get("|") == 1 and r.distance == pytest.approx(0.6)


def test_condition_flip_is_opcode_mismatch() -> None:
    # `if (a < b)` vs `if (a <= b)`: jl vs jle -> opcode mismatch in both tools
    t = fn("cmp ecx, edx", "jl L4", "xor eax, eax", "ret", "mov eax, 1", "ret")
    c = fn("cmp ecx, edx", "jle L4", "xor eax, eax", "ret", "mov eax, 1", "ret")
    r = score(t, c)
    assert r.marks.get("!") == 1 and r.distance == pytest.approx(1.0)


def test_extra_spill_shifts_labels_without_cascading() -> None:
    # One extra instruction before a loop. asm-differ/objdiff align the streams and do not flag
    # every later branch; neither do we.
    t = fn("xor eax, eax", "add eax, dword ptr [rcx]", "add rcx, 4", "dec edx", "jne L1", "ret")
    c = fn(
        "mov qword ptr [rsp+8], rbx",
        "xor eax, eax",
        "add eax, dword ptr [rcx]",
        "add rcx, 4",
        "dec edx",
        "jne L2",
        "ret",
    )
    r = score(t, c)
    assert r.marks.get("+") == 1 and r.distance == pytest.approx(1.0)
    assert r.score == pytest.approx(1 - 1 / 7)


def test_stack_offset_change_is_operand_not_regalloc() -> None:
    # different local layout: [rsp+0x20] vs [rsp+0x28] is a non-register argument change
    r = score(fn("mov dword ptr [rsp+0x20], ecx"), fn("mov dword ptr [rsp+0x28], ecx"))
    assert r.marks.get("|") == 1
