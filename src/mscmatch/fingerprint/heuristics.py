"""Flag evidence from code shape (CLAUDE.md Phase 2, step 2). Each heuristic reports separately."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field

from mscmatch.disasm import NormalizedFunction

_ARG_SPILL = re.compile(
    r"^(?:mov (?:qword|dword|word|byte) ptr \[rsp\+(?:0x8|0x10|0x18|0x20)\], "
    r"(?:rcx|ecx|cx|cl|rdx|edx|dx|dl|r8|r8d|r8w|r8b|r9|r9d|r9w|r9b)"
    r"|movs[sd] (?:qword|dword) ptr \[rsp\+(?:0x8|0x10|0x18|0x20)\], xmm[0-3])$"
)
_LABEL = re.compile(r"^L(\d+)$")
_YMM_INT = re.compile(r"^vp")


@dataclass
class FunctionFeatures:
    insns: int
    arg_spill: bool  # /Od homes register arguments in the prologue
    has_loop: bool
    inner_nop: bool  # multi-byte nop inside the body (loop alignment, /O2)
    rep_string: bool  # rep movs/stos (/O1 favours these)
    gs_cookie: bool
    cfg_dispatch: bool
    lfence: int
    vex: int
    avx2: int
    avx512: int


def function_features(fn: NormalizedFunction) -> FunctionFeatures:
    code = [i for i in fn.insns if not i.is_data]
    texts = [i.text for i in code]
    arg_spill = any(_ARG_SPILL.match(t) for t in texts[:6])
    has_loop = False
    for idx, ins in enumerate(code):
        for op in ins.operands:
            m = _LABEL.match(op)
            if m and ins.mnemonic.startswith("j") and int(m.group(1)) <= idx:
                has_loop = True
    inner_nop = any(i.mnemonic == "nop" and i.operands for i in code[:-1])
    rep_string = any(i.mnemonic.startswith("rep") for i in code)
    joined = "\n".join(texts)
    vex = sum(1 for i in code if i.mnemonic.startswith("v"))
    avx2 = sum(
        1 for i in code if _YMM_INT.match(i.mnemonic) and any("ymm" in o for o in i.operands)
    )
    avx512 = sum(1 for i in code if any("zmm" in o or o.startswith("k") for o in i.operands))
    return FunctionFeatures(
        insns=len(code),
        arg_spill=arg_spill,
        has_loop=has_loop,
        inner_nop=inner_nop,
        rep_string=rep_string,
        gs_cookie="<sym:__security_cookie>" in joined,
        cfg_dispatch="__guard_dispatch_icall_fptr" in joined
        or "__guard_check_icall_fptr" in joined,
        lfence=sum(1 for i in code if i.mnemonic == "lfence"),
        vex=vex,
        avx2=avx2,
        avx512=avx512,
    )


@dataclass
class FlagEvidence:
    name: str
    value: str
    confidence: float  # 0..1 that `value` is right
    detail: str

    def render(self) -> str:
        return f"{self.name:10} {self.value:12} p={self.confidence:.2f}  {self.detail}"


@dataclass
class FlagAnalysis:
    evidence: list[FlagEvidence] = field(default_factory=list)
    opt: dict[str, float] = field(default_factory=dict)  # /O2 /O1 /Od -> probability
    gs: dict[str, float] = field(default_factory=dict)
    extras: dict[str, float] = field(default_factory=dict)  # flag -> probability present
    runtime: str = "/MT"
    ltcg_suspected: bool = False


def _sigmoid(x: float) -> float:
    return 1.0 / (1.0 + math.exp(-x))


def analyze_flags(
    user_fns: list[FunctionFeatures],
    *,
    guard_flags: int = 0,
    imports_crt_dll: bool = False,
    rich_ltcg: bool = False,
) -> FlagAnalysis:
    fa = FlagAnalysis()
    n = max(1, len(user_fns))
    spill = sum(f.arg_spill for f in user_fns) / n
    loops = [f for f in user_fns if f.has_loop]
    nop_frac = sum(f.inner_nop for f in loops) / max(1, len(loops))
    rep_frac = sum(f.rep_string for f in user_fns) / n

    p_od = _sigmoid((spill - 0.25) * 25)
    # /O2 aligns loop heads with multi-byte nops; /O1 optimizes for size and does not.
    o2_logit = (nop_frac - 0.08) * 30 - rep_frac * 20 if loops else 0.0
    p_o2 = (1 - p_od) * _sigmoid(o2_logit)
    p_o1 = (1 - p_od) - p_o2
    fa.opt = {"/O2": p_o2, "/O1": p_o1, "/Od": p_od}
    fa.evidence.append(
        FlagEvidence(
            "opt",
            max(fa.opt, key=lambda k: fa.opt[k]),
            max(fa.opt.values()),
            f"arg-spill {spill:.0%} of {len(user_fns)} fns; aligned loops "
            f"{nop_frac:.0%} of {len(loops)}; rep-string {rep_frac:.0%}",
        )
    )

    gs_n = sum(f.gs_cookie for f in user_fns)
    big = sum(1 for f in user_fns if f.insns >= 40)
    # One cookie-checking function can be a CRT routine missing from the signature DB, so it
    # is ambiguous; several are conclusive. With none, /GS- grows likelier with more code.
    if gs_n >= 2:
        p_gs = 0.98
    elif gs_n == 1:
        p_gs = 0.6
    else:
        p_gs = max(0.15, 0.6 - 0.02 * big)
    fa.gs = {"/GS": p_gs, "/GS-": 1 - p_gs}
    fa.evidence.append(
        FlagEvidence(
            "/GS",
            "/GS" if p_gs >= 0.5 else "/GS-",
            max(p_gs, 1 - p_gs),
            f"{gs_n} user functions check __security_cookie ({big} non-trivial)",
        )
    )

    cfg_n = sum(f.cfg_dispatch for f in user_fns)
    # The prebuilt CRT is CFG-instrumented, so CF_INSTRUMENTED (0x100) is set regardless; the
    # function table (0x400) is only emitted when linking with /guard:cf.
    table = bool(guard_flags & 0x400)
    p_cfg = 0.97 if cfg_n else (0.6 if table else 0.03)
    fa.extras["/guard:cf"] = p_cfg
    fa.evidence.append(
        FlagEvidence(
            "/guard:cf",
            "on" if p_cfg >= 0.5 else "off",
            max(p_cfg, 1 - p_cfg),
            f"{cfg_n} user fns call through guard dispatch; GuardFlags={guard_flags:#x}",
        )
    )

    lf = sum(f.lfence for f in user_fns)
    p_sp = 0.9 if lf >= 2 else (0.5 if lf == 1 else 0.03)
    fa.extras["/Qspectre"] = p_sp
    fa.evidence.append(
        FlagEvidence(
            "/Qspectre",
            "on" if p_sp >= 0.5 else "off",
            max(p_sp, 1 - p_sp),
            f"{lf} lfence in user code",
        )
    )

    vex = sum(f.vex for f in user_fns)
    avx2 = sum(f.avx2 for f in user_fns)
    avx512 = sum(f.avx512 for f in user_fns)
    vex_fns = sum(1 for f in user_fns if f.vex)
    arch = "/arch:AVX512" if avx512 else "/arch:AVX2" if avx2 else "/arch:AVX" if vex else ""
    # Hand-written CRT routines missing from the signature DB also use VEX; one such function
    # is weak evidence, so offer both variants and let anchors decide.
    p_arch = 0.9 if vex_fns >= max(2, 0.05 * n) else 0.5
    if arch:
        fa.extras[arch] = p_arch
    fa.evidence.append(
        FlagEvidence(
            "/arch",
            arch or "default(SSE2)",
            p_arch if arch else 0.95,
            f"VEX insns {vex} in {vex_fns} fns, AVX2 int ymm {avx2}, AVX-512 {avx512}",
        )
    )

    fa.runtime = "/MD" if imports_crt_dll else "/MT"
    fa.evidence.append(
        FlagEvidence(
            "runtime",
            fa.runtime,
            0.95,
            "imports CRT DLLs" if imports_crt_dll else "no CRT DLL imports",
        )
    )
    fa.ltcg_suspected = rich_ltcg
    if rich_ltcg:
        fa.evidence.append(
            FlagEvidence(
                "/GL",
                "LTCG",
                0.95,
                "Rich header has LTCG compiler entries: per-function matching degraded",
            )
        )
    return fa
