#!/bin/sh
# decompile  (tar on stdin, JSON on stdout)
#
# stdin is a tar holding `binary/<file name>` (the object or image) and `functions.txt` (one
# function name or "@<hex rva>" entry point per line; no names = every function). A tar keeps
# the request off the command line, whose length is limited on Windows hosts.
#
# Imports the binary into a throwaway project, runs auto-analysis, then SimulacraDecompile.java
# writes one JSON document with the requested functions. Ghidra's own log goes to stderr so
# stdout carries only the JSON.
#
# Everything simulacra handles is MSVC x64, so the language and compiler spec are forced: the
# COFF importer otherwise leaves objects without the Windows x64 ABI, and arguments passed in
# rcx/rdx/r8/r9 vanish from the pseudo-C.
set -eu
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir "$work/in" "$work/proj"
tar -x -C "$work/in" -f -
binary="$(find "$work/in/binary" -type f | head -n 1)"
[ -n "$binary" ] || { echo "no binary/ member in the input tar" >&2; exit 2; }
touch "$work/in/functions.txt"

if ! "$GHIDRA_HOME/support/analyzeHeadless" "$work/proj" p \
        -import "$binary" \
        -processor x86:LE:64:default -cspec windows \
        -scriptPath /opt/simulacra-scripts \
        -preScript SimulacraPrepare.java \
        -postScript SimulacraDecompile.java "$work/out.json" "$work/in/functions.txt" \
        -deleteProject -max-cpu 2 >"$work/log" 2>&1 \
   || [ ! -s "$work/out.json" ]; then
    tail -40 "$work/log" >&2
    exit 1
fi
cat "$work/out.json"
