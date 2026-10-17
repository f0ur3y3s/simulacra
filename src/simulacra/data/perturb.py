"""Semantic-preserving source perturbations for the repair dataset (CLAUDE.md Phase 3 step 5).

Each transform rewrites one site of a function's source using the libclang AST of
`context + source`. They are chosen to keep the program's meaning; whether the *code* changes is
decided afterwards by compiling (only perturbations that compile but no longer match are kept).
"""

from __future__ import annotations

import itertools
import random
from collections.abc import Callable, Iterator
from dataclasses import dataclass

import clang.cindex as ci

from simulacra.data.cparse import parse

K = ci.CursorKind
_INT_TYPES = {
    "int",
    "unsigned int",
    "long",
    "unsigned long",
    "short",
    "unsigned short",
    "char",
    "unsigned char",
    "signed char",
    "__int64",
    "unsigned __int64",
    "long long",
    "unsigned long long",
}
_SIDE_EFFECT_KINDS = {K.CALL_EXPR, K.COMPOUND_ASSIGNMENT_OPERATOR}


@dataclass(frozen=True)
class Edit:
    start: int  # byte offsets into the source (not the combined text)
    end: int
    text: str


@dataclass(frozen=True)
class Perturbation:
    kind: str
    source: str


class _Ctx:
    def __init__(self, context: str, source: str) -> None:
        self.prefix = context.rstrip("\n") + "\n"
        self.src = source.encode("utf-8")
        self.base = len(self.prefix.encode("utf-8"))
        self.tu = parse(self.prefix + source)
        self.combined = (self.prefix + source).encode("utf-8")

    def in_source(self, c: ci.Cursor) -> bool:
        return c.extent.start.file is not None and c.extent.start.offset >= self.base

    def text(self, c: ci.Cursor) -> str:
        return self.combined[c.extent.start.offset : c.extent.end.offset].decode("utf-8")

    def span(self, c: ci.Cursor) -> tuple[int, int]:
        return c.extent.start.offset - self.base, c.extent.end.offset - self.base

    def cursors(self) -> Iterator[ci.Cursor]:
        for c in self.tu.cursor.walk_preorder():
            if self.in_source(c):
                yield c


def _children(c: ci.Cursor) -> list[ci.Cursor]:
    return list(c.get_children())


def _names(c: ci.Cursor) -> set[str]:
    return {d.spelling for d in c.walk_preorder() if d.kind == K.DECL_REF_EXPR}


def _pure(c: ci.Cursor) -> bool:
    """No calls, assignments or increments anywhere inside."""
    for d in c.walk_preorder():
        if d.kind in _SIDE_EFFECT_KINDS:
            return False
        if d.kind == K.UNARY_OPERATOR and _op(d) in ("++", "--"):
            return False
        if d.kind == K.BINARY_OPERATOR and _op(d) == "=":
            return False
    return True


def _op(c: ci.Cursor) -> str:
    """Operator token of a unary/binary operator cursor."""
    toks = [t.spelling for t in c.get_tokens()]
    kids = _children(c)
    if c.kind == K.UNARY_OPERATOR:
        return (
            toks[0]
            if toks and toks[0] in ("++", "--", "-", "!", "~", "*", "&")
            else (toks[-1] if toks else "")
        )
    if len(kids) == 2:
        n_left = len(list(kids[0].get_tokens()))
        return toks[n_left] if n_left < len(toks) else ""
    return ""


def _semicolon_end(ctx: _Ctx, c: ci.Cursor) -> int:
    """Source offset just after the statement's trailing `;` (extents exclude it)."""
    _, end = ctx.span(c)
    i = end
    while i < len(ctx.src) and ctx.src[i : i + 1] in (b" ", b"\t", b"\n", b"\r"):
        i += 1
    return i + 1 if ctx.src[i : i + 1] == b";" else end


def _stmt_text(ctx: _Ctx, c: ci.Cursor) -> tuple[int, int, str]:
    s, _ = ctx.span(c)
    e = _semicolon_end(ctx, c) if c.kind not in (K.COMPOUND_STMT,) else ctx.span(c)[1]
    return s, e, ctx.src[s:e].decode("utf-8")


# -- transforms -------------------------------------------------------------------------------


def t_swap_decls(ctx: _Ctx) -> Iterator[list[Edit]]:
    """Swap adjacent declarations when the second does not use what the first declares."""
    for c in ctx.cursors():
        if c.kind != K.COMPOUND_STMT:
            continue
        kids = _children(c)
        for a, b in itertools.pairwise(kids):
            if a.kind != K.DECL_STMT or b.kind != K.DECL_STMT:
                continue
            declared = {d.spelling for d in a.get_children()}
            if declared & _names(b) or not (_pure(a) and _pure(b)):
                continue
            yield _swap(ctx, a, b)


def t_swap_assignments(ctx: _Ctx) -> Iterator[list[Edit]]:
    """Swap adjacent `x = e1; y = e2;` with no shared variables and no side effects in e1/e2."""
    for c in ctx.cursors():
        if c.kind != K.COMPOUND_STMT:
            continue
        kids = _children(c)
        for a, b in itertools.pairwise(kids):
            if not (_is_simple_assign(a) and _is_simple_assign(b)):
                continue
            if _names(a) & _names(b):
                continue
            yield _swap(ctx, a, b)


def _is_simple_assign(c: ci.Cursor) -> bool:
    if c.kind != K.BINARY_OPERATOR or _op(c) != "=":
        return False
    lhs, rhs = _children(c)
    return lhs.kind == K.DECL_REF_EXPR and _pure(rhs)


def _swap(ctx: _Ctx, a: ci.Cursor, b: ci.Cursor) -> list[Edit]:
    sa, ea, ta = _stmt_text(ctx, a)
    sb, eb, tb = _stmt_text(ctx, b)
    gap = ctx.src[ea:sb].decode("utf-8")
    return [Edit(sa, eb, tb + gap + ta)]


def t_for_to_while(ctx: _Ctx) -> Iterator[list[Edit]]:
    for c in ctx.cursors():
        if c.kind != K.FOR_STMT:
            continue
        if any(d.kind == K.CONTINUE_STMT for d in c.walk_preorder()):
            continue  # `continue` would skip the moved increment
        toks = [t.spelling for t in c.get_tokens()]
        # for ( init ; cond ; inc ) body -- recover the three header parts from the tokens
        try:
            lp = toks.index("(")
        except ValueError:
            continue
        depth = 0
        parts: list[str] = []
        cur: list[str] = []
        i = lp + 1
        while i < len(toks):
            t = toks[i]
            if t == "(":
                depth += 1
            elif t == ")":
                if depth == 0:
                    break
                depth -= 1
            if t == ";" and depth == 0:
                parts.append(" ".join(cur))
                cur = []
            else:
                cur.append(t)
            i += 1
        parts.append(" ".join(cur))
        if len(parts) != 3:
            continue
        init, cond, inc = parts
        body = _children(c)[-1]
        s, e = ctx.span(c)
        bs, be = ctx.span(body)
        body_text = ctx.src[bs:be].decode("utf-8")
        if body.kind == K.COMPOUND_STMT:
            inner = body_text[1:-1]
            new_body = "{" + inner + (f"    {inc};\n" if inc else "") + "}"
        else:
            new_body = "{ " + body_text + (";" if not body_text.rstrip().endswith(";") else "")
            new_body += (f" {inc};" if inc else "") + " }"
        head = f"{init};" if init else ""
        text = "{ " + head + f" while ({cond or '1'}) " + new_body + " }"
        yield [Edit(s, e, text)]


def t_while_to_for(ctx: _Ctx) -> Iterator[list[Edit]]:
    for c in ctx.cursors():
        if c.kind != K.WHILE_STMT:
            continue
        cond, body = _children(c)[0], _children(c)[-1]
        s, e = ctx.span(c)
        bs, be = ctx.span(body)
        yield [Edit(s, e, f"for (; {ctx.text(cond)}; ) " + ctx.src[bs:be].decode("utf-8"))]


def t_compound_assign(ctx: _Ctx) -> Iterator[list[Edit]]:
    """`a = a op b` -> `a op= b` and back, for a plain variable `a`."""
    for c in ctx.cursors():
        if c.kind == K.BINARY_OPERATOR and _op(c) == "=":
            lhs, rhs = _children(c)
            if lhs.kind != K.DECL_REF_EXPR or rhs.kind != K.BINARY_OPERATOR:
                continue
            op = _op(rhs)
            rl, rr = _children(rhs)
            inner = rl
            while inner.kind == K.UNEXPOSED_EXPR and _children(inner):
                inner = _children(inner)[0]
            if op in ("+", "-", "*", "|", "&", "^", "<<", ">>") and inner.spelling == lhs.spelling:
                s, e = ctx.span(c)
                yield [Edit(s, e, f"{lhs.spelling} {op}= {ctx.text(rr)}")]
        elif c.kind == K.COMPOUND_ASSIGNMENT_OPERATOR:
            lhs, rhs = _children(c)
            if lhs.kind != K.DECL_REF_EXPR:
                continue
            op = _op(c)
            if not op.endswith("=") or len(op) < 2:
                continue
            s, e = ctx.span(c)
            yield [Edit(s, e, f"{lhs.spelling} = {lhs.spelling} {op[:-1]} ({ctx.text(rhs)})")]


_STMT_OWNERS = {K.COMPOUND_STMT, K.WHILE_STMT, K.FOR_STMT, K.DO_STMT, K.IF_STMT}


def t_incdec(ctx: _Ctx) -> Iterator[list[Edit]]:
    """`x++;` / `++x;` used as a whole statement -> `x += 1;`."""
    for owner in ctx.cursors():
        if owner.kind not in _STMT_OWNERS:
            continue
        kids = _children(owner)
        # Statement positions: every child of a block; the body (last child) of a loop or if.
        stmts = kids if owner.kind == K.COMPOUND_STMT else kids[-1:]
        if owner.kind == K.IF_STMT and len(kids) == 3:
            stmts = kids[1:]
        for c in stmts:
            if c.kind != K.UNARY_OPERATOR:
                continue
            op = _op(c)
            kid = _children(c)[0] if _children(c) else None
            if op in ("++", "--") and kid is not None and kid.kind == K.DECL_REF_EXPR:
                st, en = ctx.span(c)
                yield [Edit(st, en, f"{kid.spelling} {op[0]}= 1")]


def t_invert_if(ctx: _Ctx) -> Iterator[list[Edit]]:
    for c in ctx.cursors():
        if c.kind != K.IF_STMT:
            continue
        kids = _children(c)
        if len(kids) != 3:
            continue
        cond, then_s, else_s = kids
        if else_s.kind == K.IF_STMT:
            continue  # leave else-if chains alone
        s = ctx.span(c)[0]
        then_t = ctx.src[ctx.span(then_s)[0] : _end_of(ctx, then_s)].decode("utf-8")
        else_t = ctx.src[ctx.span(else_s)[0] : _end_of(ctx, else_s)].decode("utf-8")
        end = _end_of(ctx, else_s)
        yield [Edit(s, end, f"if (!({ctx.text(cond)})) {_braced(else_t)} else {_braced(then_t)}")]


def _end_of(ctx: _Ctx, stmt: ci.Cursor) -> int:
    return ctx.span(stmt)[1] if stmt.kind == K.COMPOUND_STMT else _semicolon_end(ctx, stmt)


def _braced(text: str) -> str:
    t = text.strip()
    return t if t.startswith("{") else "{ " + t + " }"


def t_split_return(ctx: _Ctx) -> Iterator[list[Edit]]:
    """`return A op B;` -> `{ T t = B; return A op t; }` for integer B without side effects."""
    for c in ctx.cursors():
        if c.kind != K.RETURN_STMT or not _children(c):
            continue
        expr = _children(c)[0]
        while expr.kind == K.UNEXPOSED_EXPR and _children(expr):
            expr = _children(expr)[0]
        if expr.kind != K.BINARY_OPERATOR or not _pure(expr):
            continue
        op = _op(expr)
        if op not in ("+", "-", "*", "|", "&", "^"):
            continue
        a, b = _children(expr)
        btype = b.type.get_canonical().spelling
        if btype not in _INT_TYPES:
            continue
        s = ctx.span(c)[0]
        e = _semicolon_end(ctx, c)
        yield [Edit(s, e, f"{{ {btype} __t = {ctx.text(b)}; return {ctx.text(a)} {op} __t; }}")]


TRANSFORMS: dict[str, Callable[[_Ctx], Iterator[list[Edit]]]] = {
    "swap_decls": t_swap_decls,
    "swap_assignments": t_swap_assignments,
    "for_to_while": t_for_to_while,
    "while_to_for": t_while_to_for,
    "compound_assign": t_compound_assign,
    "incdec": t_incdec,
    "invert_if": t_invert_if,
    "split_return": t_split_return,
}


def apply(source: str, edits: list[Edit]) -> str:
    raw = source.encode("utf-8")
    for ed in sorted(edits, key=lambda e: e.start, reverse=True):
        raw = raw[: ed.start] + ed.text.encode("utf-8") + raw[ed.end :]
    return raw.decode("utf-8")


def perturbations(
    source: str, context: str, rng: random.Random, limit: int = 6
) -> list[Perturbation]:
    """Up to `limit` distinct single-site perturbations, spread over transform kinds."""
    ctx = _Ctx(context, source)
    out: list[Perturbation] = []
    seen = {source}
    kinds = list(TRANSFORMS)
    rng.shuffle(kinds)
    for kind in kinds:
        sites = list(TRANSFORMS[kind](ctx))
        rng.shuffle(sites)
        for edits in sites[:2]:
            new = apply(source, edits)
            if new not in seen:
                seen.add(new)
                out.append(Perturbation(kind, new))
        if len(out) >= limit:
            break
    return out[:limit]
