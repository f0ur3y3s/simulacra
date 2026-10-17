"""Per-toolchain fingerprint database, generated from probe images we build ourselves.

For each registered toolchain we link small C programs against the static and dynamic CRT and
record (a) the Rich header builds that come from prebuilt libraries rather than from cl.exe,
(b) the linker version and (c) hashes of every normalized CRT function. A target binary is then
compared against every toolchain's record.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from pathlib import Path

from simulacra.compile import CompileService
from simulacra.disasm import UnwindMode, normalize
from simulacra.pe import PEFunctions, PEImage, extract_pe_function, function_rvas, parse_pe
from simulacra.score import anonymize
from simulacra.toolchain import Toolchain, get_toolchain, load_registry

DEFAULT_DB_DIR = Path("datasets/fingerprint")
MIN_SIG_INSNS = 6

# CRT entry points referenced by the probes so the static CRT links them in.
PROBE_CRT_FUNCTIONS = (
    "memcpy",
    "memmove",
    "memset",
    "memcmp",
    "memchr",
    "strlen",
    "strnlen",
    "strcmp",
    "strncmp",
    "strcpy",
    "strncpy",
    "strcat",
    "strncat",
    "strchr",
    "strrchr",
    "strstr",
    "strtok",
    "strspn",
    "strcspn",
    "strpbrk",
    "strerror",
    "strtol",
    "strtoul",
    "strtoll",
    "strtoull",
    "strtod",
    "strtof",
    "atoi",
    "atol",
    "atoll",
    "atof",
    "qsort",
    "bsearch",
    "malloc",
    "calloc",
    "realloc",
    "free",
    "abs",
    "labs",
    "llabs",
    "div",
    "ldiv",
    "rand",
    "srand",
    "printf",
    "fprintf",
    "sprintf",
    "snprintf",
    "vsnprintf",
    "vsprintf",
    "vfprintf",
    "vprintf",
    "sscanf",
    "fscanf",
    "scanf",
    "fopen",
    "fclose",
    "fread",
    "fwrite",
    "fseek",
    "ftell",
    "fflush",
    "fgets",
    "fputs",
    "fputc",
    "fgetc",
    "getc",
    "putc",
    "puts",
    "getchar",
    "putchar",
    "ungetc",
    "remove",
    "rename",
    "tmpfile",
    "setvbuf",
    "feof",
    "ferror",
    "clearerr",
    "perror",
    "exit",
    "atexit",
    "getenv",
    "system",
    "time",
    "clock",
    "difftime",
    "mktime",
    "localtime",
    "gmtime",
    "strftime",
    "isalpha",
    "isdigit",
    "isspace",
    "isupper",
    "islower",
    "isalnum",
    "isxdigit",
    "ispunct",
    "iscntrl",
    "isprint",
    "isgraph",
    "toupper",
    "tolower",
    "sin",
    "cos",
    "tan",
    "asin",
    "acos",
    "atan",
    "atan2",
    "sinh",
    "cosh",
    "tanh",
    "exp",
    "log",
    "log10",
    "log2",
    "pow",
    "sqrt",
    "ceil",
    "floor",
    "fabs",
    "fmod",
    "frexp",
    "ldexp",
    "modf",
    "round",
    "lround",
    "trunc",
    "fmin",
    "fmax",
    "hypot",
    "cbrt",
    "expm1",
    "log1p",
    "exp2",
    "longjmp",
    "signal",
    "raise",
    "wcslen",
    "wcscpy",
    "wcscmp",
    "wcsncmp",
    "wcschr",
    "mbstowcs",
    "wcstombs",
    "mbtowc",
    "wctomb",
    "_strdup",
    "localeconv",
    "setlocale",
    "fgetpos",
    "fsetpos",
    "rewind",
    "freopen",
    "vsscanf",
    "_stricmp",
    "_strnicmp",
    "_wcsicmp",
    "_snprintf",
    "_vsnprintf",
    "_itoa",
    "_ltoa",
    "_ultoa",
    "_atoi64",
    "_strtoi64",
    "_strtoui64",
    "_fseeki64",
    "_ftelli64",
    "_fileno",
    "_isatty",
    "_open",
    "_close",
    "_read",
    "_write",
    "_lseek",
    "_access",
    "_getcwd",
    "_chdir",
    "_mkdir",
    "_rmdir",
    "_unlink",
    "_stat64",
    "_fstat64",
    "_beginthreadex",
    "_endthreadex",
    "_errno",
    "_aligned_malloc",
    "_aligned_free",
    "_msize",
    "_expand",
    "_set_invalid_parameter_handler",
    "_wfopen",
    "_wcsdup",
)

PROBE_C = r"""
#define _CRT_SECURE_NO_WARNINGS
#include <ctype.h>
#include <direct.h>
#include <errno.h>
#include <io.h>
#include <locale.h>
#include <malloc.h>
#include <math.h>
#include <process.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <wchar.h>
/* Take the address of many CRT entry points so the static CRT links them in. */
int probe_refs(int i) {
    const void *volatile refs[] = {
    %REFS%
    };
    return refs[i % (sizeof refs / sizeof refs[0])] != 0;
}
int probe_entry(int argc, char **argv) {
    char buf[64];
    snprintf(buf, sizeof buf, "%d:%s:%g", argc, argc > 0 ? argv[0] : "", argc * 0.5);
    return (int)strlen(buf) + atoi(buf) + probe_refs(argc);
}
"""
PROBE_C = PROBE_C.replace(
    "%REFS%", ",\n        ".join(f"(const void *){n}" for n in PROBE_CRT_FUNCTIONS)
)
PROBE_EXE = PROBE_C + "int main(int argc, char **argv) { return probe_entry(argc, argv); }\n"
PROBE_DLL = PROBE_C + "__declspec(dllexport) int probe_export(int x) { return x + 1; }\n"
PROBES: dict[str, tuple[str, list[str], str]] = {
    "exe_mt": (PROBE_EXE, ["/MT"], "probe.exe"),
    "exe_md": (PROBE_EXE, ["/MD"], "probe.exe"),
    "dll_mt": (PROBE_DLL, ["/MT", "/LD"], "probe.dll"),
    "dll_md": (PROBE_DLL, ["/MD", "/LD"], "probe.dll"),
}


@dataclass
class ToolchainRecord:
    toolchain: str
    cl_build: int
    link_version: tuple[int, int]
    link_builds: list[int]
    lib_compiler_builds: list[int]  # compiler builds present only via prebuilt CRT objects
    signatures: dict[str, list[str]] = field(default_factory=dict)  # hash -> probe names

    @staticmethod
    def from_json(d: dict[str, object]) -> ToolchainRecord:
        lv = d["link_version"]
        assert isinstance(lv, list)
        return ToolchainRecord(
            str(d["toolchain"]),
            int(d["cl_build"]),  # type: ignore[call-overload]
            (int(lv[0]), int(lv[1])),
            list(d["link_builds"]),  # type: ignore[call-overload]
            list(d["lib_compiler_builds"]),  # type: ignore[call-overload]
            dict(d["signatures"]),  # type: ignore[call-overload]
        )


def function_hashes(pe: PEImage, index: PEFunctions | None = None) -> dict[int, str]:
    """RVA -> hash of the anonymized normalized listing, for functions long enough to matter."""
    fx = index or PEFunctions(pe)
    out: dict[int, str] = {}
    for rva in function_rvas(fx):
        try:
            fn = normalize(extract_pe_function(pe, hex(rva), index=fx), UnwindMode.NONE)
        except Exception:
            continue
        if len(fn.insns) < MIN_SIG_INSNS:
            continue
        text = anonymize(fn).listing(with_offsets=False)
        out[rva] = hashlib.sha256(text.encode()).hexdigest()[:24]
    return out


def build_record(service: CompileService, tc: Toolchain) -> ToolchainRecord:
    from simulacra.fingerprint.rich import COMPILER_PRODIDS, LINKER_PRODID

    sigs: dict[str, list[str]] = {}
    link_builds: set[int] = set()
    lib_builds: set[int] = set()
    link_version = (0, 0)
    for name, (src, flags, out_name) in PROBES.items():
        args = ["/nologo", "/O2", "/Gy", *flags, "probe.c", f"/Fe{out_name}", "/link", "/Brepro"]
        out = service.run_raw({"probe.c": src}, args, out_name, tc.id)
        if not out.ok:
            raise RuntimeError(f"probe {name} failed for {tc.id}:\n{out.stdout}{out.stderr}")
        pe = parse_pe(out.obj)
        link_version = pe.linker_version
        for e in pe.rich:
            if e.prodid == LINKER_PRODID:
                link_builds.add(e.build)
            elif e.prodid in COMPILER_PRODIDS and e.build != tc.cl_build:
                lib_builds.add(e.build)
        for h in function_hashes(pe).values():
            sigs.setdefault(h, [])
            if name not in sigs[h]:
                sigs[h].append(name)
    return ToolchainRecord(
        tc.id, tc.cl_build, link_version, sorted(link_builds), sorted(lib_builds), sigs
    )


def build_db(
    service: CompileService, toolchains: Iterable[str] | None = None, out_dir: Path = DEFAULT_DB_DIR
) -> list[ToolchainRecord]:
    out_dir.mkdir(parents=True, exist_ok=True)
    ids = list(toolchains) if toolchains else list(load_registry())
    records = []
    for tcid in ids:
        rec = build_record(service, get_toolchain(tcid))
        (out_dir / f"{tcid}.json").write_text(json.dumps(asdict(rec)), encoding="utf-8")
        records.append(rec)
    return records


def load_db(db_dir: Path = DEFAULT_DB_DIR) -> dict[str, ToolchainRecord]:
    out = {}
    for p in sorted(db_dir.glob("*.json")):
        rec = ToolchainRecord.from_json(json.loads(p.read_text(encoding="utf-8")))
        out[rec.toolchain] = rec
    return out
