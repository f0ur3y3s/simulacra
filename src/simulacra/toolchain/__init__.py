"""Toolchain registry: which MSVC builds we can run, and how to find their images."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from functools import cache
from importlib import resources
from pathlib import Path

DEFAULT_TOOLCHAIN = "vs2022-17.14"


@dataclass(frozen=True)
class Toolchain:
    id: str
    vs_major: int
    msvc_version_arg: str
    cl_version: str
    cl_build: int
    link_version: str
    sdk_version: str
    image: str


def _registry_text() -> str:
    return resources.files(__package__).joinpath("registry.toml").read_text(encoding="utf-8")


@cache
def load_registry() -> dict[str, Toolchain]:
    data = tomllib.loads(_registry_text())
    out: dict[str, Toolchain] = {}
    for entry in data.get("toolchain", []):
        tc = Toolchain(**entry)
        if tc.id in out:
            raise ValueError(f"duplicate toolchain id {tc.id!r}")
        out[tc.id] = tc
    return out


def get_toolchain(toolchain_id: str) -> Toolchain:
    reg = load_registry()
    if toolchain_id not in reg:
        raise KeyError(f"unknown toolchain {toolchain_id!r}; known: {', '.join(sorted(reg))}")
    return reg[toolchain_id]


@cache
def load_flagsets() -> dict[str, tuple[str, ...]]:
    text = resources.files(__package__).joinpath("flagsets.toml").read_text(encoding="utf-8")
    return {k: tuple(v) for k, v in tomllib.loads(text)["flagsets"].items()}


def dockerfile_dir() -> Path:
    return Path(__file__).resolve().parents[3] / "docker" / "msvc-wine"


def build_args(tc: Toolchain) -> list[str]:
    """`docker build` arguments that produce the image for `tc`."""
    return [
        "build",
        "-t",
        tc.image,
        "--build-arg",
        f"VS_MAJOR={tc.vs_major}",
        "--build-arg",
        f"MSVC_VERSION={tc.msvc_version_arg}",
        "--build-arg",
        f"SDK_VERSION={tc.sdk_version}",
        "--build-arg",
        f"EXPECT_CL={tc.cl_version}",
        str(dockerfile_dir()),
    ]
