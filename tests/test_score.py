import pytest

from mscmatch.disasm import NormalizedFunction, NormInsn
from mscmatch.score import anonymize, score


def fn(*lines: str, unwind: list[str] | None = None) -> NormalizedFunction:
    insns = []
    for i, line in enumerate(lines):
        mnem, _, rest = line.partition(" ")
        ops = tuple(o.strip() for o in rest.split(",")) if rest else ()
        insns.append(NormInsn(i, mnem, ops))
    return NormalizedFunction("f", insns, unwind or [])


def test_identical_is_exact() -> None:
    a = fn("mov eax, ecx", "ret")
    r = score(a, fn("mov eax, ecx", "ret"))
    assert r.exact and r.score == 1.0 and r.distance == 0


def test_regalloc_only_mismatch() -> None:
    r = score(fn("mov eax, ecx", "add eax, 1", "ret"), fn("mov edx, ecx", "add eax, 1", "ret"))
    assert not r.exact
    assert r.distance == pytest.approx(0.3)
    assert r.score == pytest.approx(1 - 0.3 / 3)
    assert "~" in r.marks


def test_memory_operand_register_only() -> None:
    r = score(fn("mov eax, dword ptr [rcx+8]"), fn("mov eax, dword ptr [rdx+8]"))
    assert r.distance == pytest.approx(0.3)


def test_other_operand_mismatch() -> None:
    r = score(fn("mov eax, dword ptr [rcx+8]"), fn("mov eax, dword ptr [rcx+0x10]"))
    assert r.distance == pytest.approx(0.6)
    assert "|" in r.marks


def test_opcode_mismatch() -> None:
    r = score(fn("add eax, 1", "ret"), fn("sub eax, 1", "ret"))
    assert r.distance == pytest.approx(1.0)
    assert r.marks.get("!") == 1


def test_insertion_and_label_shift_not_double_charged() -> None:
    target = fn("test ecx, ecx", "je L3", "inc eax", "ret")
    cand = fn("test ecx, ecx", "je L4", "nop", "inc eax", "ret")
    r = score(target, cand)
    # one insertion; the branch label is consistent under the alignment
    assert r.distance == pytest.approx(1.0)
    assert r.marks.get("+") == 1


def test_wrong_branch_target_is_charged() -> None:
    target = fn("je L2", "inc eax", "ret")
    cand = fn("je L1", "inc eax", "ret")
    r = score(target, cand)
    assert r.distance == pytest.approx(0.6)


def test_score_clamped_and_normalized() -> None:
    r = score(fn("ret"), fn("push rbx", "pop rbx", "xor eax, eax", "ret"))
    assert r.distance == pytest.approx(3.0)
    assert r.score == pytest.approx(1 - 3 / 4)
    r2 = score(fn("ret"), fn("int3", "int3"))
    assert r2.score == 0.0


def test_unwind_difference_breaks_exactness() -> None:
    a = fn("ret", unwind=["PDATA L0..+0x1", "  @0x4 ALLOC_SMALL 0x28"])
    b = fn("ret", unwind=["PDATA L0..+0x1", "  @0x4 ALLOC_SMALL 0x38"])
    r = score(a, b)
    assert not r.exact and not r.unwind_match
    assert "unwind info differs" in r.diff_text
    assert score(a, b, compare_unwind=False).exact


def test_diff_text_markers_and_truncation() -> None:
    t = fn(*[f"mov eax, {i}" for i in range(100)])
    c = fn(*[f"mov eax, {i}" if i % 2 else f"mov ecx, {i}" for i in range(100)])
    r = score(t, c, max_diff_lines=10)
    assert "diff truncated" in r.diff_text
    assert r.diff_text.splitlines()[2].startswith("~ ")


def test_anonymize_symbols_but_not_imports() -> None:
    a = anonymize(
        fn("call <sym:foo>", "call <sym:bar>", "call <sym:foo>", "call qword ptr [<imp:Sleep>]")
    )
    assert [i.text for i in a.insns] == [
        "call <sym:#0>",
        "call <sym:#1>",
        "call <sym:#0>",
        "call qword ptr [<imp:Sleep>]",
    ]
