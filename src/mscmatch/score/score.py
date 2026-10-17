"""Score a candidate function against a target: exactness, weighted edit distance, aligned diff.

Costs (per CLAUDE.md 1.5): mnemonic mismatch 1.0, register-only operand mismatch 0.3,
other operand mismatch 0.6, insertion/deletion 1.0.

Branch labels are instruction indices, so one inserted instruction would shift every later
label. The alignment therefore treats label operands as wildcards; afterwards each aligned
pair whose labels disagree *under the alignment* is charged as an operand mismatch.
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field
from enum import StrEnum

from mscmatch.disasm.normalize import NormalizedFunction, NormInsn, register_regex

COST_MNEMONIC = 1.0
COST_REG = 0.3
COST_OPERAND = 0.6
COST_INDEL = 1.0

_LABEL = re.compile(r"^L(\d+)$")
_TOKEN = re.compile(r"<(sym|const|data|str):([^>]*)>")


class Mark(StrEnum):
    EQUAL = " "
    REG = "~"
    OPCODE = "!"
    OPERAND = "|"
    INSERT = "+"  # present only in candidate
    DELETE = "-"  # present only in target


@dataclass
class ScoreReport:
    exact: bool
    distance: float
    score: float
    diff_text: str
    target_len: int
    candidate_len: int
    unwind_match: bool = True
    marks: dict[str, int] = field(default_factory=dict)

    def summary(self) -> str:
        m = ", ".join(f"{k!r}:{v}" for k, v in sorted(self.marks.items()) if k != " ")
        return (
            f"exact={self.exact} score={self.score:.4f} distance={self.distance:.2f} "
            f"len={self.target_len}/{self.candidate_len} "
            f"unwind={'ok' if self.unwind_match else 'DIFF'}" + (f" [{m}]" if m else "")
        )


def _regnorm(op: str) -> str:
    return register_regex().sub("R", op)


def _wild(op: str) -> str:
    return "L*" if _LABEL.match(op) else op


def _insn_cost(a: NormInsn, b: NormInsn, wildcard_labels: bool) -> tuple[float, Mark]:
    if a.key == b.key:
        return 0.0, Mark.EQUAL
    if a.mnemonic != b.mnemonic:
        return COST_MNEMONIC, Mark.OPCODE
    if len(a.operands) != len(b.operands):
        return COST_OPERAND, Mark.OPERAND
    reg_only = True
    any_diff = False
    for x, y in zip(a.operands, b.operands, strict=True):
        if wildcard_labels:
            x, y = _wild(x), _wild(y)
        if x == y:
            continue
        any_diff = True
        if _regnorm(x) != _regnorm(y):
            reg_only = False
    if not any_diff:
        return 0.0, Mark.EQUAL
    return (COST_REG, Mark.REG) if reg_only else (COST_OPERAND, Mark.OPERAND)


def _align(
    t: list[NormInsn], c: list[NormInsn]
) -> list[tuple[int | None, int | None, float, Mark]]:
    """Weighted edit-distance alignment (labels wildcarded). Returns (ti, ci, cost, mark)."""
    # Trim common prefix/suffix (strict equality) to keep the DP small.
    pre = 0
    while pre < len(t) and pre < len(c) and t[pre].key == c[pre].key:
        pre += 1
    suf = 0
    while (
        suf < len(t) - pre
        and suf < len(c) - pre
        and t[len(t) - 1 - suf].key == c[len(c) - 1 - suf].key
    ):
        suf += 1
    tm, cm = t[pre : len(t) - suf], c[pre : len(c) - suf]
    n, m = len(tm), len(cm)

    # Intern instruction keys so the inner loop compares ints and memoizes pair costs.
    ids: dict[tuple[str, tuple[str, ...]], int] = {}
    tid = [ids.setdefault(x.key, len(ids)) for x in tm]
    cid = [ids.setdefault(x.key, len(ids)) for x in cm]
    rep = {ids[x.key]: x for x in (*tm, *cm)}
    memo: dict[tuple[int, int], float] = {}

    def sub(i: int, j: int) -> float:
        a, b = tid[i], cid[j]
        if a == b:
            return 0.0
        k = (a, b)
        v = memo.get(k)
        if v is None:
            v = _insn_cost(rep[a], rep[b], True)[0]
            memo[k] = v
        return v

    prev = [j * COST_INDEL for j in range(m + 1)]
    back: list[bytearray] = [bytearray(m + 1)]  # 0 diag, 1 up (delete), 2 left (insert)
    back[0][1:] = b"\x02" * m
    for i in range(1, n + 1):
        cur = [i * COST_INDEL] + [0.0] * m
        bk = bytearray(m + 1)
        bk[0] = 1
        for j in range(1, m + 1):
            d = prev[j - 1] + sub(i - 1, j - 1)
            u = prev[j] + COST_INDEL
            le = cur[j - 1] + COST_INDEL
            if d <= u and d <= le:
                cur[j], bk[j] = d, 0
            elif u <= le:
                cur[j], bk[j] = u, 1
            else:
                cur[j], bk[j] = le, 2
        back.append(bk)
        prev = cur

    path: list[tuple[int | None, int | None]] = []
    i, j = n, m
    while i > 0 or j > 0:
        mv = back[i][j] if i > 0 and j > 0 else (1 if i > 0 else 2)
        if mv == 0:
            path.append((i - 1, j - 1))
            i, j = i - 1, j - 1
        elif mv == 1:
            path.append((i - 1, None))
            i -= 1
        else:
            path.append((None, j - 1))
            j -= 1
    path.reverse()

    full: list[tuple[int | None, int | None]] = [(k, k) for k in range(pre)]
    full += [(None if a is None else a + pre, None if b is None else b + pre) for a, b in path]
    full += [(len(t) - suf + k, len(c) - suf + k) for k in range(suf)]

    # Second pass: charge label disagreements under the computed alignment.
    t2c = {a: b for a, b in full if a is not None and b is not None}
    out: list[tuple[int | None, int | None, float, Mark]] = []
    for a, b in full:
        if a is None:
            out.append((None, b, COST_INDEL, Mark.INSERT))
            continue
        if b is None:
            out.append((a, None, COST_INDEL, Mark.DELETE))
            continue
        ta, cb = t[a], c[b]
        cost, mark = _insn_cost(ta, cb, True)
        if mark is Mark.EQUAL and ta.key != cb.key:
            labels_ok = all(
                x == y
                or (
                    (mx := _LABEL.match(x)) is not None
                    and (my := _LABEL.match(y)) is not None
                    and t2c.get(int(mx.group(1))) == int(my.group(1))
                )
                for x, y in zip(ta.operands, cb.operands, strict=True)
            )
            if not labels_ok:
                cost, mark = COST_OPERAND, Mark.OPERAND
        out.append((a, b, cost, mark))
    return out


def anonymize(fn: NormalizedFunction) -> NormalizedFunction:
    """Rename <sym:..>/<const:..> tokens by first appearance (for targets without symbols)."""
    seen: dict[tuple[str, str], int] = {}

    def repl(m: re.Match[str]) -> str:
        kind, name = m.group(1), m.group(2)
        if kind in ("data", "str"):
            return m.group(0)
        k = (kind, name)
        if k not in seen:
            seen[k] = sum(1 for kk in seen if kk[0] == kind)
        return f"<{kind}:#{seen[k]}>"

    insns = [
        NormInsn(i.offset, i.mnemonic, tuple(_TOKEN.sub(repl, o) for o in i.operands), i.is_data)
        for i in fn.insns
    ]
    unwind = [_TOKEN.sub(repl, u) for u in fn.unwind]
    return NormalizedFunction(fn.name, insns, unwind, fn.code_bytes)


def _render_diff(
    t: list[NormInsn],
    c: list[NormInsn],
    rows: list[tuple[int | None, int | None, float, Mark]],
    max_lines: int,
    context: int,
    width: int,
) -> list[str]:
    lines: list[str] = []
    interesting = [k for k, r in enumerate(rows) if r[3] is not Mark.EQUAL]
    keep: set[int] = set()
    for k in interesting:
        keep.update(range(max(0, k - context), min(len(rows), k + context + 1)))
    if not interesting:
        keep = set(range(min(len(rows), max_lines)))
    skipped = 0
    for k, (a, b, _cost, mark) in enumerate(rows):
        if k not in keep:
            skipped += 1
            continue
        if skipped:
            lines.append(f"      ... {skipped} matching ...")
            skipped = 0
        left = f"L{a:<4} {t[a].text}" if a is not None else ""
        right = f"L{b:<4} {c[b].text}" if b is not None else ""
        lines.append(f"{mark.value} {left[:width]:<{width}} | {right[:width]}")
    if skipped:
        lines.append(f"      ... {skipped} matching ...")
    if len(lines) > max_lines:
        hidden = len(lines) - max_lines
        lines = [*lines[:max_lines], f"... diff truncated ({hidden} more lines) ..."]
    return lines


def score(
    target: NormalizedFunction,
    candidate: NormalizedFunction,
    *,
    max_diff_lines: int = 200,
    context: int = 3,
    width: int = 48,
    compare_unwind: bool = True,
) -> ScoreReport:
    t, c = target.insns, candidate.insns
    rows = _align(t, c)
    distance = sum(r[2] for r in rows)

    unwind_match = True
    unwind_lines: list[str] = []
    if compare_unwind and target.unwind != candidate.unwind:
        unwind_match = False
        sm = difflib.SequenceMatcher(a=target.unwind, b=candidate.unwind, autojunk=False)
        for op, a0, a1, b0, b1 in sm.get_opcodes():
            if op == "equal":
                continue
            distance += max(a1 - a0, b1 - b0) * COST_INDEL * 0.5
            unwind_lines += [f"- {x}" for x in target.unwind[a0:a1]]
            unwind_lines += [f"+ {x}" for x in candidate.unwind[b0:b1]]

    denom = max(len(t), len(c), 1)
    sc = min(1.0, max(0.0, 1.0 - distance / denom))
    exact = [x.key for x in t] == [x.key for x in c] and unwind_match
    marks: dict[str, int] = {}
    for r in rows:
        marks[r[3].value] = marks.get(r[3].value, 0) + 1

    lines = [
        f"target: {len(t)} insns   candidate: {len(c)} insns   score {sc:.4f}"
        + ("   EXACT" if exact else ""),
        "legend: ~ regalloc-only  ! opcode  | operand  "
        "- missing in candidate  + extra in candidate",
    ]
    if not exact:
        lines += _render_diff(t, c, rows, max_diff_lines, context, width)
    if unwind_lines:
        lines += ["unwind info differs:", *unwind_lines[:40]]
    if exact:
        sc = 1.0
    return ScoreReport(exact, distance, sc, "\n".join(lines), len(t), len(c), unwind_match, marks)
