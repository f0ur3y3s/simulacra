# Test fixture toolchains: MinGW-w64 GCC and clang/lld targeting x86_64 Windows.
#
# Not a matching target. These build the non-MSVC PE images that tests/test_producer.py uses
# to check that the fingerprinter refuses binaries it cannot match.
#
#   docker build -t simulacra-mingw-fixtures docker/mingw

FROM debian:trixie-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc-mingw-w64-x86-64 g++-mingw-w64-x86-64 clang lld python3 \
    && apt-get clean -y && rm -rf /var/lib/apt/lists/*

# `build <tool> <out> <args...>`: source on stdin as src.c, image bytes on stdout.
RUN printf '%s\n' \
    '#!/bin/sh' \
    'set -eu' \
    'tool="$1"; out="$2"; shift 2' \
    'd="$(mktemp -d)"; cd "$d"' \
    'cat > src.c' \
    'case "$tool" in' \
    '  gcc)   x86_64-w64-mingw32-gcc -O2 "$@" -o "$out" src.c >&2 ;;' \
    '  clang) clang --target=x86_64-w64-windows-gnu -fuse-ld=lld -O2 "$@" -o "$out" src.c >&2 ;;' \
    '  *) echo "unknown tool $tool" >&2; exit 2 ;;' \
    'esac' \
    'cat "$out"' > /usr/local/bin/build \
    && chmod 0755 /usr/local/bin/build

WORKDIR /work
ENTRYPOINT ["/usr/local/bin/build"]
