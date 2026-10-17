#!/bin/sh
# decompile <file name> [function names...]  (binary on stdin, JSON on stdout)
#
# Imports the binary into a throwaway project, runs auto-analysis, then SimulacraDecompile.java
# writes one JSON document with every requested function (all if none named). Ghidra's own log
# goes to stderr so stdout carries only the JSON.
#
# Everything simulacra handles is MSVC x64, so the language and compiler spec are forced: the
# COFF importer otherwise leaves objects without the Windows x64 ABI, and arguments passed in
# rcx/rdx/r8/r9 vanish from the pseudo-C.
set -eu
name="${1:?usage: decompile <file name> [functions...]}"
shift
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir "$work/in" "$work/proj"
cat > "$work/in/$name"
printf '%s\n' "$@" > "$work/functions.txt"

if ! "$GHIDRA_HOME/support/analyzeHeadless" "$work/proj" p \
        -import "$work/in/$name" \
        -processor x86:LE:64:default -cspec windows \
        -scriptPath /opt/simulacra-scripts \
        -preScript SimulacraPrepare.java \
        -postScript SimulacraDecompile.java "$work/out.json" "$work/functions.txt" \
        -deleteProject -max-cpu 2 >"$work/log" 2>&1 \
   || [ ! -s "$work/out.json" ]; then
    tail -40 "$work/log" >&2
    exit 1
fi
cat "$work/out.json"
