from __future__ import annotations

import json
from pathlib import Path

import pytest

from simulacra.compile import CompileService
from simulacra.data.vcpkg import _common_prefix, evaluate, shlex_quote

PORTFILE = """
if(VCPKG_TARGET_IS_WINDOWS)
    set(PATCHES win-only.patch)
endif()
vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO example/demo
    REF "v${VERSION}"
    SHA512 ABCDEF0123
    HEAD_REF main
    PATCHES
        common.patch
        ${PATCHES}
)
file(COPY "${CMAKE_CURRENT_LIST_DIR}/CMakeLists.txt" DESTINATION "${SOURCE_PATH}")
string(COMPARE EQUAL "${VCPKG_LIBRARY_LINKAGE}" "static" DEMO_STATIC)
vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}/build/cmake"
    OPTIONS
        -DDEMO_STATIC=${DEMO_STATIC}
        -DDEMO_TESTS=OFF
)
vcpkg_cmake_install()
vcpkg_some_future_helper(FOO bar)
file(READ "${CURRENT_PACKAGES_DIR}/include/demo.h" header)
"""


def test_common_prefix_and_quote() -> None:
    assert _common_prefix(["demo-1.0/a.c", "demo-1.0/sub/b.c"]) == "demo-1.0/"
    assert _common_prefix(["a.c", "demo/b.c"]) == ""
    assert shlex_quote("-DX=it's") == "'-DX=it'\"'\"'s'"


@pytest.mark.docker
def test_evaluate_synthetic_port(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    port = repo / "ports" / "demo"
    port.mkdir(parents=True)
    (port / "portfile.cmake").write_text(PORTFILE)
    (port / "vcpkg.json").write_text(json.dumps({"name": "demo", "version": "2.1.0"}))
    for helpers in ("scripts/cmake", "ports/vcpkg-cmake", "ports/vcpkg-cmake-config"):
        (repo / helpers).mkdir(parents=True, exist_ok=True)
    (repo / "scripts/cmake/vcpkg_some_future_helper.cmake").write_text(
        "function(vcpkg_some_future_helper)\n  message(FATAL_ERROR boom)\nendfunction()\n"
    )
    (repo / "ports/vcpkg-cmake/vcpkg_cmake_install.cmake").write_text(
        "function(vcpkg_cmake_install)\nendfunction()\n"
    )
    with CompileService(workers=1, cache=False) as svc:
        r = evaluate(svc, repo, "demo", "vs2022-17.14")
    assert (r.version, r.repo, r.ref, r.sha512) == ("2.1.0", "example/demo", "v2.1.0", "abcdef0123")
    assert r.patches == ["common.patch", "win-only.patch"]
    assert r.cmake_subdir == "build/cmake"
    assert r.options == ["-DDEMO_STATIC=1", "-DDEMO_TESTS=OFF"]
    assert r.copies == [("CMakeLists.txt", "")]
