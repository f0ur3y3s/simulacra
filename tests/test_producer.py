"""Producer identification: refuse what simulacra cannot match (MinGW GCC, clang/lld)."""

from __future__ import annotations

import subprocess

import pytest

from simulacra.compile import CompileService
from simulacra.fingerprint.producer import (
    Producer,
    ProducerFeatures,
    classify,
    identify_producer,
)
from simulacra.fingerprint.rich import strip_rich
from simulacra.pe import parse_pe


def feats(**kw: object) -> ProducerFeatures:
    base: dict[str, object] = dict(
        linker_version=(14, 44),
        rich_present=True,
        debug_types=(13, 16),
        coff_symbols=0,
        import_dlls=("kernel32.dll",),
        section_names=(".text", ".rdata", ".data", ".pdata"),
        padding={0xCC: 100},
        msvc_crt_matches=300,
    )
    base.update(kw)
    return ProducerFeatures(**base)  # type: ignore[arg-type]


def test_msvc_with_and_without_rich() -> None:
    assert classify(feats()).producer is Producer.MSVC
    stripped = classify(feats(rich_present=False))
    assert stripped.producer is Producer.MSVC and stripped.matchable


def test_mingw_gcc() -> None:
    v = classify(
        feats(
            linker_version=(2, 44),
            rich_present=False,
            debug_types=(),
            coff_symbols=1500,
            import_dlls=("kernel32.dll", "msvcrt.dll"),
            section_names=(".text", ".data", ".rdata", ".pdata", ".bss", ".idata", "/4"),
            padding={0x90: 80, 0x00: 20},
            msvc_crt_matches=0,
        )
    )
    assert v.producer is Producer.MINGW_GCC and not v.matchable


def test_clang_lld() -> None:
    v = classify(
        feats(
            linker_version=(14, 0),
            rich_present=False,
            debug_types=(),
            coff_symbols=600,
            import_dlls=("kernel32.dll", "msvcrt.dll"),
            section_names=(".text", ".data", ".rdata", ".pdata", "/4", "/18"),
            padding={0xCC: 50},
            msvc_crt_matches=0,
        )
    )
    assert v.producer is Producer.CLANG


def test_gnu_runtime_dll_is_decisive() -> None:
    v = classify(
        feats(
            rich_present=False,
            debug_types=(),
            msvc_crt_matches=0,
            import_dlls=("libstdc++-6.dll", "libgcc_s_seh-1.dll"),
        )
    )
    assert not v.matchable


def test_no_evidence_is_unknown() -> None:
    v = classify(
        feats(
            linker_version=(9, 0),
            rich_present=False,
            debug_types=(),
            padding={},
            msvc_crt_matches=0,
        )
    )
    assert v.producer is Producer.UNKNOWN


# ---- real images ------------------------------------------------------------------------------

FIXTURE_IMAGE = "simulacra-mingw-fixtures"
SRC = b"""
#include <stdio.h>
int count(const char *s, char c) { int n = 0; for (; *s; s++) n += *s == c; return n; }
int main(int argc, char **argv) { printf("%d", count(argv[0], 47)); return 0; }
"""


def _fixture(tool: str, out: str, *args: str) -> bytes:
    r = subprocess.run(
        ["docker", "run", "-i", "--rm", "--network", "none", FIXTURE_IMAGE, tool, out, *args],
        input=SRC,
        capture_output=True,
        check=False,
    )
    if r.returncode != 0:
        pytest.skip(f"{FIXTURE_IMAGE} unavailable: {r.stderr.decode()[-300:]}")
    return r.stdout


@pytest.mark.docker
@pytest.mark.parametrize(
    ("tool", "out", "args", "expected"),
    [
        ("gcc", "a.exe", (), Producer.MINGW_GCC),
        ("gcc", "a.dll", ("-shared",), Producer.MINGW_GCC),
        ("clang", "a.exe", (), Producer.CLANG),
        ("clang", "a.dll", ("-shared",), Producer.CLANG),
    ],
)
def test_real_non_msvc_images(
    tool: str, out: str, args: tuple[str, ...], expected: Producer
) -> None:
    pe = parse_pe(_fixture(tool, out, *args))
    v = identify_producer(pe)
    assert v.producer is expected, v.evidence


@pytest.mark.docker
def test_real_msvc_image_with_and_without_rich() -> None:
    with CompileService(workers=1, cache=False) as svc:
        res = svc.run_raw(
            {"a.c": SRC.decode()},
            ["/nologo", "/O2", "/MT", "a.c", "/link", "/Brepro"],
            "a.exe",
        )
    assert res.ok, res.stdout
    for data in (res.obj, strip_rich(res.obj)):
        assert identify_producer(parse_pe(data)).producer is Producer.MSVC
