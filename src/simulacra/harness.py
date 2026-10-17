"""High-level helpers tying compile -> extract -> normalize -> score together."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from simulacra.coff import extract_function, list_functions, parse_coff
from simulacra.compile import CompileRequest, CompileService
from simulacra.disasm import NormalizedFunction, UnwindMode, normalize
from simulacra.score import ScoreReport, anonymize, score
from simulacra.toolchain import DEFAULT_TOOLCHAIN

PE_SUFFIXES = {".exe", ".dll", ".sys", ".efi"}


class HarnessError(RuntimeError):
    pass


@dataclass
class CandidateResult:
    compiled: bool
    errors: str
    function: NormalizedFunction | None = None
    report: ScoreReport | None = None


def function_from_obj(
    obj: bytes, name: str, unwind: UnwindMode = UnwindMode.CODES
) -> NormalizedFunction:
    return normalize(extract_function(parse_coff(obj), name), unwind)


def compile_function(
    service: CompileService,
    source: str,
    name: str,
    flags: tuple[str, ...],
    context: str = "",
    toolchain_id: str = DEFAULT_TOOLCHAIN,
    unwind: UnwindMode = UnwindMode.CODES,
) -> tuple[NormalizedFunction | None, str]:
    res = service.compile(CompileRequest(source, context, name, toolchain_id, flags))
    if not res.ok:
        return None, res.stderr
    if name not in list_functions(parse_coff(res.obj_bytes)):
        # A static function with no caller in the candidate TU is never emitted; reference it.
        retry = service.compile(
            CompileRequest(keep_alive(source, name), context, name, toolchain_id, flags)
        )
        if retry.ok:
            res = retry
    try:
        return function_from_obj(res.obj_bytes, name, unwind), res.stderr
    except Exception as e:  # function missing from the object, malformed object, ...
        names = ", ".join(list_functions(parse_coff(res.obj_bytes))[:20])
        return None, f"{res.stderr}\n{e} (functions in object: {names})".strip()


def keep_alive(source: str, name: str) -> str:
    """`source` plus a file-scope reference that forces `name` to be emitted. It adds a data
    relocation elsewhere in the object; the function's own code is unaffected."""
    return f"{source.rstrip()}\n\nvoid *const __simulacra_keep_{name} = (void *)&{name};\n"


def load_target(
    path: Path,
    name: str,
    *,
    service: CompileService | None = None,
    flags: tuple[str, ...] = (),
    context: str = "",
    toolchain_id: str = DEFAULT_TOOLCHAIN,
    unwind: UnwindMode = UnwindMode.CODES,
) -> NormalizedFunction:
    """Load a function from a .obj, a linked PE image, or a C source (compiled with `flags`)."""
    suffix = path.suffix.lower()
    if suffix == ".obj":
        return function_from_obj(path.read_bytes(), name, unwind)
    if suffix in PE_SUFFIXES:
        from simulacra.pe import function_from_pe

        return function_from_pe(path.read_bytes(), name, unwind)
    if service is None:
        raise HarnessError("compiling a source target needs a CompileService")
    fn, err = compile_function(
        service, path.read_text(encoding="utf-8"), name, flags, context, toolchain_id, unwind
    )
    if fn is None:
        raise HarnessError(f"failed to build {path}:\n{err}")
    return fn


def score_candidate(
    service: CompileService,
    target: NormalizedFunction,
    source: str,
    name: str,
    flags: tuple[str, ...],
    context: str = "",
    toolchain_id: str = DEFAULT_TOOLCHAIN,
    anonymize_symbols: bool = False,
    max_diff_lines: int = 200,
) -> CandidateResult:
    fn, err = compile_function(service, source, name, flags, context, toolchain_id)
    if fn is None:
        return CandidateResult(False, err)
    t, c = (anonymize(target), anonymize(fn)) if anonymize_symbols else (target, fn)
    return CandidateResult(True, err, fn, score(t, c, max_diff_lines=max_diff_lines))
