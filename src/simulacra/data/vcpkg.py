"""vcpkg ports as a pinned source catalog for Phase 3 (see vcpkg_ports.toml).

Per port and toolchain:
  1. evaluate `portfile.cmake` with `cmake -P` inside the container, every vcpkg helper stubbed
     to record its arguments (x64-windows-static, default features);
  2. download the source, verify vcpkg's SHA512 pin, extract, apply the port's patches and copy
     the files the port adds;
  3. in the container: CMake configure (Ninja, Windows, cl) and preprocess every C TU listed in
     compile_commands.json with exactly its own defines and include paths (`/P`, keeping #line);
  4. write the TUs into the Phase 3 sources tree like any other library.
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import shutil
import subprocess
import tarfile
import tomllib
import urllib.request
import zipfile
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path, PurePosixPath

from simulacra.compile import CompileService
from simulacra.data.cparse import function_definitions
from simulacra.data.sources import SOURCES_DIR

VCPKG_DIR = Path("datasets/vcpkg")
MAX_FILE = 8 * 1024 * 1024
_SKIP_DIRS = {".git", ".github", ".gitlab", "doc", "docs"}


@dataclass
class PortRecipe:
    port: str
    version: str
    repo: str = ""  # GitHub owner/name
    ref: str = ""
    urls: list[str] = field(default_factory=list)
    filename: str = ""
    sha512: str = ""
    patches: list[str] = field(default_factory=list)
    copies: list[tuple[str, str]] = field(default_factory=list)  # (port file, dest under source)
    cmake_subdir: str = ""
    options: list[str] = field(default_factory=list)
    log: str = ""


def load_allowlist() -> tuple[dict[str, str], list[dict[str, object]]]:
    text = resources.files(__package__).joinpath("vcpkg_ports.toml").read_text(encoding="utf-8")
    cfg = tomllib.loads(text)
    return cfg["vcpkg"], cfg["port"]


# -- catalog ------------------------------------------------------------------------------------


def checkout(ports: list[str], root: Path = VCPKG_DIR) -> Path:
    """Sparse clone of vcpkg at the pinned commit, with the requested ports and the helpers."""
    meta, _ = load_allowlist()
    repo = root / "repo"
    if not (repo / ".git").exists():
        root.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            [
                "git",
                "clone",
                "-q",
                "--filter=blob:none",
                "--sparse",
                "--no-checkout",
                meta["repo"],
                str(repo),
            ],
            check=True,
        )
    head = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True, check=False
    ).stdout.strip()
    if head != meta["commit"]:
        subprocess.run(
            ["git", "-C", str(repo), "fetch", "-q", "--depth", "1", "origin", meta["commit"]],
            check=True,
        )
        subprocess.run(["git", "-C", str(repo), "checkout", "-q", meta["commit"]], check=True)
    paths = [
        "scripts/cmake",
        "ports/vcpkg-cmake",
        "ports/vcpkg-cmake-config",
        *(f"ports/{p}" for p in ports),
    ]
    subprocess.run(["git", "-C", str(repo), "sparse-checkout", "set", *paths], check=True)
    return repo


def _helper_names(repo: Path) -> list[str]:
    names: set[str] = set()
    pat = re.compile(r"^\s*(?:function|macro)\(\s*((?:z_)?vcpkg_\w+)", re.M | re.I)
    for d in ("scripts/cmake", "ports/vcpkg-cmake", "ports/vcpkg-cmake-config"):
        for f in (repo / d).glob("*.cmake"):
            names.update(
                m.lower() for m in pat.findall(f.read_text(encoding="utf-8", errors="replace"))
            )
    return sorted(names)


_RECORDED = {
    "vcpkg_from_github",
    "vcpkg_from_gitlab",
    "vcpkg_download_distfile",
    "vcpkg_extract_source_archive",
    "vcpkg_extract_source_archive_ex",
    "vcpkg_cmake_configure",
    "vcpkg_configure_cmake",
    "vcpkg_check_features",
    "vcpkg_find_acquire_program",
}

_PRELUDE = r"""
cmake_minimum_required(VERSION 3.20)
set(PORT "@PORT@")
set(VERSION "@VERSION@")
set(TARGET_TRIPLET x64-windows-static)
set(VCPKG_TARGET_IS_WINDOWS 1)
set(VCPKG_TARGET_ARCHITECTURE x64)
set(VCPKG_LIBRARY_LINKAGE static)
set(VCPKG_CRT_LINKAGE static)
set(VCPKG_CMAKE_SYSTEM_NAME "")
set(VCPKG_BUILD_TYPE "")
set(FEATURES core)
set(CURRENT_PORT_DIR "${CMAKE_CURRENT_LIST_DIR}")
set(CURRENT_PACKAGES_DIR "/nonexistent/packages")
set(CURRENT_INSTALLED_DIR "/nonexistent/installed")
set(CURRENT_BUILDTREES_DIR "/nonexistent/buildtrees")
set(DOWNLOADS "/nonexistent/downloads")
function(simulacra_emit tag)
  string(REPLACE "\n" " " body "${ARGN}")
  message("SIMULACRA|${tag}|${body}")
endfunction()
function(simulacra_args fn)
  cmake_parse_arguments(PARSE_ARGV 1 A ""
    "OUT_SOURCE_PATH;SOURCE_PATH;REPO;REF;SHA512;FILENAME;ARCHIVE;GITLAB_URL;HEAD_REF"
    "PATCHES;URLS;OPTIONS;OPTIONS_RELEASE")
  foreach(k REPO REF SHA512 FILENAME ARCHIVE GITLAB_URL SOURCE_PATH)
    if(DEFINED A_${k})
      simulacra_emit("${fn}.${k}" "${A_${k}}")
    endif()
  endforeach()
  foreach(k PATCHES URLS OPTIONS OPTIONS_RELEASE)
    foreach(v IN LISTS A_${k})
      simulacra_emit("${fn}.${k}" "${v}")
    endforeach()
  endforeach()
  if(DEFINED A_OUT_SOURCE_PATH)
    set(${A_OUT_SOURCE_PATH} "@SRC@" PARENT_SCOPE)
  endif()
endfunction()
function(vcpkg_from_github)
  simulacra_args(github ${ARGN})
  cmake_parse_arguments(PARSE_ARGV 0 A "" "OUT_SOURCE_PATH" "")
  set(${A_OUT_SOURCE_PATH} "@SRC@" PARENT_SCOPE)
endfunction()
function(vcpkg_from_gitlab)
  simulacra_args(gitlab ${ARGN})
  cmake_parse_arguments(PARSE_ARGV 0 A "" "OUT_SOURCE_PATH" "")
  set(${A_OUT_SOURCE_PATH} "@SRC@" PARENT_SCOPE)
endfunction()
function(vcpkg_download_distfile out)
  simulacra_args(distfile ${ARGN})
  set(${out} "@ARCHIVE@" PARENT_SCOPE)
endfunction()
function(vcpkg_extract_source_archive)
  if(ARGC GREATER 0 AND NOT ARGV0 MATCHES "^(OUT_SOURCE_PATH|ARCHIVE)$")
    set(${ARGV0} "@SRC@" PARENT_SCOPE)
    list(REMOVE_AT ARGV 0)
  endif()
  simulacra_args(extract ${ARGV})
  cmake_parse_arguments(PARSE_ARGV 0 A "" "OUT_SOURCE_PATH" "")
  if(DEFINED A_OUT_SOURCE_PATH)
    set(${A_OUT_SOURCE_PATH} "@SRC@" PARENT_SCOPE)
  endif()
endfunction()
function(vcpkg_extract_source_archive_ex)
  simulacra_args(extract ${ARGN})
  cmake_parse_arguments(PARSE_ARGV 0 A "" "OUT_SOURCE_PATH" "")
  set(${A_OUT_SOURCE_PATH} "@SRC@" PARENT_SCOPE)
endfunction()
function(vcpkg_cmake_configure)
  simulacra_args(configure ${ARGN})
endfunction()
function(vcpkg_configure_cmake)
  simulacra_args(configure ${ARGN})
endfunction()
function(vcpkg_check_features)
  cmake_parse_arguments(PARSE_ARGV 0 A "" "OUT_FEATURE_OPTIONS;PREFIX" "")
  if(DEFINED A_OUT_FEATURE_OPTIONS)
    set(${A_OUT_FEATURE_OPTIONS} "" PARENT_SCOPE)
  endif()
endfunction()
function(vcpkg_find_acquire_program var)
  set(${var} "${var}-NOTFOUND" PARENT_SCOPE)
endfunction()
function(file mode)
  if(mode STREQUAL "COPY" OR mode STREQUAL "INSTALL")
    cmake_parse_arguments(PARSE_ARGV 1 A "" "DESTINATION" "")
    if(A_DESTINATION MATCHES "@SRC@")
      foreach(f IN LISTS A_UNPARSED_ARGUMENTS)
        simulacra_emit("copy" "${f}=>${A_DESTINATION}")
      endforeach()
    endif()
  endif()
endfunction()
function(configure_file)
endfunction()
@STUBS@
include("${CMAKE_CURRENT_LIST_DIR}/portfile.cmake")
"""


def _version(port_dir: Path) -> str:
    meta = json.loads((port_dir / "vcpkg.json").read_text(encoding="utf-8"))
    for k in ("version", "version-semver", "version-date", "version-string"):
        if k in meta:
            return str(meta[k])
    return ""


def evaluate(service: CompileService, repo: Path, port: str, toolchain: str) -> PortRecipe:
    port_dir = repo / "ports" / port
    version = _version(port_dir)
    stubs = "\n".join(
        f"function({n})\nendfunction()" for n in _helper_names(repo) if n not in _RECORDED
    )
    prelude = (
        _PRELUDE.replace("@PORT@", port).replace("@VERSION@", version).replace("@STUBS@", stubs)
    )
    files = {
        f"port/{p.name}": p.read_text(encoding="utf-8", errors="replace")
        for p in port_dir.iterdir()
        if p.is_file()
    }
    files["port/simulacra-prelude.cmake"] = prelude
    out = service.run_raw(
        files,
        [],
        "",
        toolchain,
        timeout=120,
        exec_argv=["cmake", "-P", "port/simulacra-prelude.cmake"],
    )
    recipe = PortRecipe(port, version, log=out.stdout + out.stderr)
    for line in (out.stdout + out.stderr).splitlines():
        if not line.startswith("SIMULACRA|"):
            continue
        _, tag, value = line.split("|", 2)
        value = value.strip()
        fn, _, key = tag.partition(".")
        if tag == "copy":
            src, _, dest = value.partition("=>")
            recipe.copies.append(
                (
                    src.replace("${CMAKE_CURRENT_LIST_DIR}", "").split("/")[-1],
                    dest.replace("@SRC@", "").strip("/"),
                )
            )
        elif key == "REPO" and fn in ("github", "gitlab"):
            recipe.repo = value
        elif key == "REF":
            recipe.ref = value
        elif key == "SHA512" and fn in ("github", "gitlab", "distfile"):
            recipe.sha512 = value.lower()
        elif key == "URLS":
            recipe.urls.append(value)
        elif key == "FILENAME":
            recipe.filename = value
        elif key == "PATCHES":
            if value:
                recipe.patches.append(value)
        elif fn == "configure" and key == "SOURCE_PATH":
            recipe.cmake_subdir = value.replace("@SRC@", "").strip("/")
        elif fn == "configure" and key in ("OPTIONS", "OPTIONS_RELEASE"):
            if value and "@" not in value:
                recipe.options.append(value)
    if not (recipe.repo or recipe.urls) or not recipe.sha512:
        raise RuntimeError(f"{port}: portfile gave no source archive\n{recipe.log[-2000:]}")
    return recipe


# -- sources ------------------------------------------------------------------------------------


def fetch_source(recipe: PortRecipe, repo: Path, root: Path = VCPKG_DIR) -> Path:
    """Download (verified), extract and patch the port's source; returns the source root."""
    dest = root / "src" / f"{recipe.port}-{recipe.version}"
    if (dest / ".simulacra-ready").exists():
        return dest
    downloads = root / "downloads"
    downloads.mkdir(parents=True, exist_ok=True)
    if recipe.repo:
        urls = [f"https://github.com/{recipe.repo}/archive/{recipe.ref}.tar.gz"]
        name = f"{recipe.port}-{recipe.ref.replace('/', '_')}.tar.gz"
    else:
        urls = recipe.urls
        name = recipe.filename or PurePosixPath(urls[0]).name
    archive = downloads / name
    if not archive.exists():
        last: Exception | None = None
        for url in urls:
            try:
                with urllib.request.urlopen(url, timeout=300) as resp:
                    archive.write_bytes(resp.read())
                break
            except Exception as e:
                last = e
        else:
            raise RuntimeError(f"{recipe.port}: download failed: {last}")
    digest = hashlib.sha512(archive.read_bytes()).hexdigest()
    if digest != recipe.sha512:
        archive.unlink()
        raise RuntimeError(f"{recipe.port}: SHA512 mismatch for {name}")

    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    data = archive.read_bytes()
    if name.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            members = [m for m in z.namelist() if not m.endswith("/")]
            prefix = _common_prefix(members)
            for m in members:
                rel = m[len(prefix) :]
                if rel and ".." not in PurePosixPath(rel).parts:
                    (dest / rel).parent.mkdir(parents=True, exist_ok=True)
                    (dest / rel).write_bytes(z.read(m))
    else:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as t:
            infos = [ti for ti in t.getmembers() if ti.isfile()]
            prefix = _common_prefix([ti.name for ti in infos])
            for ti in infos:
                rel = ti.name[len(prefix) :]
                if not rel or ".." in PurePosixPath(rel).parts or ti.name.startswith("/"):
                    continue
                f = t.extractfile(ti)
                if f is not None:
                    (dest / rel).parent.mkdir(parents=True, exist_ok=True)
                    (dest / rel).write_bytes(f.read())
    port_dir = repo / "ports" / recipe.port
    for patch in recipe.patches:
        res = subprocess.run(
            [
                "git",
                "apply",
                "--ignore-whitespace",
                "--whitespace=nowarn",
                str((port_dir / patch).resolve()),
            ],
            cwd=dest,
            capture_output=True,
            text=True,
            check=False,
        )
        if res.returncode != 0:
            raise RuntimeError(f"{recipe.port}: patch {patch} failed: {res.stderr[-500:]}")
    for src, rel in recipe.copies:
        if (port_dir / src).is_file():
            target = dest / rel / src if rel else dest / src
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(port_dir / src, target)
    (dest / ".simulacra-ready").write_text(json.dumps(recipe.__dict__, indent=1), encoding="utf-8")
    return dest


def _common_prefix(names: list[str]) -> str:
    tops = {n.split("/", 1)[0] for n in names}
    return f"{tops.pop()}/" if len(tops) == 1 and all("/" in n for n in names) else ""


_PP_SCRIPT = r"""
import json, os, shlex, subprocess, sys
CL = "/opt/msvc/bin/x64/cl"
JOB = os.getcwd()
cc = json.load(open("build/compile_commands.json"))
os.makedirs("out", exist_ok=True)
seen, results = set(), []
src_root = os.path.abspath("src")
for e in cc:
    path = os.path.abspath(os.path.join(e.get("directory", "."), e["file"]))
    if not path.endswith(".c") or path in seen or not path.startswith(src_root + "/"):
        continue
    seen.add(path)
    toks = e["arguments"] if "arguments" in e else shlex.split(e["command"])
    keep, i = [], 1
    while i < len(toks):
        t = toks[i]
        low = t.lower()
        if low[:2] in ("-d", "/d", "-i", "/i", "-u", "/u") and len(t) > 2 and t[1] in "DIUdiu":
            keep.append(t)
        elif low in ("-d", "/d", "-i", "/i") and i + 1 < len(toks):
            keep += [t, toks[i + 1]]; i += 1
        elif low.startswith(("/fi", "-fi")) and not low.startswith(("/fo", "-fo")) and len(t) > 3:
            keep.append(t)
        elif low.startswith(("/std:", "-std:", "/zc:", "-zc:", "/j", "-j")):
            keep.append(t)
        i += 1
    rel = os.path.relpath(path, src_root).replace(os.sep, "/")
    out = "out/" + rel.replace("/", "__")[:-2] + ".i"
    dest = os.path.join(JOB, out)
    r = subprocess.run([CL, "/nologo", "/P", "/TC", *keep, "/Fi" + dest, path],
                       capture_output=True, text=True, cwd=e.get("directory", "."))
    results.append({"tu": rel, "out": out, "ok": r.returncode == 0 and os.path.exists(dest),
                    "flags": keep, "log": (r.stdout + r.stderr)[-400:]})
json.dump(results, open("out/pp.json", "w"), indent=1)
"""


def configure_and_preprocess(
    service: CompileService, recipe: PortRecipe, src: Path, toolchain: str
) -> dict[str, bytes]:
    binary: dict[str, bytes] = {}
    for p in src.rglob("*"):
        if not p.is_file() or p.name == ".simulacra-ready":
            continue
        rel = p.relative_to(src)
        if any(part in _SKIP_DIRS for part in rel.parts[:-1]) or p.stat().st_size > MAX_FILE:
            continue
        binary[f"src/{rel.as_posix()}"] = p.read_bytes()
    subdir = f"src/{recipe.cmake_subdir}" if recipe.cmake_subdir else "src"
    opts = " ".join(shlex_quote(o) for o in recipe.options)
    script = (
        "set -e\n"
        f"cmake -G Ninja -S {subdir} -B build -DCMAKE_SYSTEM_NAME=Windows "
        "-DCMAKE_C_COMPILER=cl -DCMAKE_CXX_COMPILER=cl -DCMAKE_BUILD_TYPE=Release "
        "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DBUILD_SHARED_LIBS=OFF "
        "-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded -DBUILD_TESTING=OFF "
        # /Zi needs mspdbsrv, which does not work under Wine: embed debug info (/Z7), also for
        # projects whose cmake_minimum_required predates CMP0141, and try-compile as Release.
        "-DCMAKE_POLICY_DEFAULT_CMP0141=NEW -DCMAKE_MSVC_DEBUG_INFORMATION_FORMAT=Embedded "
        "'-DCMAKE_C_FLAGS_DEBUG=/Z7 /Ob0 /Od /RTC1' '-DCMAKE_CXX_FLAGS_DEBUG=/Z7 /Ob0 /Od /RTC1' "
        "-DCMAKE_TRY_COMPILE_CONFIGURATION=Release "
        f"{opts} > configure.log 2>&1 || {{ tail -60 configure.log; exit 1; }}\n"
        "python3 pp.py\n"
    )
    out = service.run_raw(
        {"run.sh": script, "pp.py": _PP_SCRIPT},
        [],
        "",
        toolchain,
        timeout=1800,
        binary_files=binary,
        exec_argv=["sh", "run.sh"],
        output_globs=("out/*.i", "out/pp.json", "configure.log"),
    )
    if not out.ok:
        raise RuntimeError(f"{recipe.port} ({toolchain}) configure failed:\n{out.stdout[-3000:]}")
    return out.outputs


def shlex_quote(s: str) -> str:
    return "'" + s.replace("'", "'\"'\"'") + "'"


def add_port_sources(
    service: CompileService,
    ports: list[str] | None,
    toolchains: list[str],
    root: Path = SOURCES_DIR,
) -> dict[str, str]:
    """Prepare sources for allowlisted ports; returns port -> status line."""
    _, allow = load_allowlist()
    names = [str(p["name"]) for p in allow if ports is None or p["name"] in ports]
    repo = checkout(names)
    status: dict[str, str] = {}
    for port in names:
        for tc in toolchains:
            lib_dir = root / tc / port
            manifest_path = root / tc / "manifest.json"
            try:
                recipe = evaluate(service, repo, port, tc)
                src = fetch_source(recipe, repo)
                outputs = configure_and_preprocess(service, recipe, src, tc)
            except Exception as e:
                status[f"{port}/{tc}"] = f"FAILED: {str(e)[:300]}"
                continue
            pp = json.loads(outputs["out/pp.json"])
            lib_dir.mkdir(parents=True, exist_ok=True)
            entries = []
            for item in pp:
                if not item["ok"] or item["out"] not in outputs:
                    continue
                text = outputs[item["out"]].replace(b"\r\n", b"\n")
                dest = lib_dir / PurePosixPath(item["out"]).name
                dest.write_bytes(text)
                program = any(
                    d.name == "main" for d in function_definitions(text.decode("utf-8", "replace"))
                )
                entries.append(
                    {"library": port, "tu": item["tu"], "path": dest.name, "program": program}
                )
            known = (
                json.loads(manifest_path.read_text(encoding="utf-8"))
                if manifest_path.exists()
                else []
            )
            known = [e for e in known if e["library"] != port] + entries
            manifest_path.parent.mkdir(parents=True, exist_ok=True)
            manifest_path.write_text(json.dumps(known, indent=1), encoding="utf-8")
            failed = sum(1 for i in pp if not i["ok"])
            status[f"{port}/{tc}"] = (
                f"{len(entries)} TUs ({failed} failed to preprocess), v{recipe.version}"
            )
    return status
