#!/bin/bash

set -euo pipefail

SCRIPTS_DIR="$(dirname $(realpath ${BASH_SOURCE[0]}))"
MAZE_DIR="$(dirname "$SCRIPTS_DIR")"

msg() {
    echo -e "[+] ${1-}" >&2
}

hurt() {
    echo -e "[-] ${1-}" >&2
}

die() {
    echo -e "[!] ${1-}" >&2
    exit 1
}

usage() {
    cat <<EOF
[!] Usage: $(basename "${BASH_SOURCE[0]}") [-h] [-v]

    Compile Maze.c into x86, amd64, and aarch64 binaries.

    Available options:

    -h, --help      Print this help and exit
    -v, --verbose   Print script debug info
EOF
}

parse_params() {
    while :; do
        case "${1-}" in
        -h | --help) usage; exit ;;
        -v | --verbose) set -x ;;
        -?*) die "Unknown option: $1\n$(usage)" ;;
        *) break ;;
        esac
        shift
    done
}

main() {
    parse_params $@

    CC="$MAZE_DIR/installed/cxx-common/installed/x64-linux-rel/bin/clang"
    CXX="$MAZE_DIR/installed/cxx-common/installed/x64-linux-rel/bin/clang++"

    msg "Compiling maze.x86..."
    "$CC" "$MAZE_DIR/Maze.c" -o "$MAZE_DIR/bin/maze.x86" -target i386-linux-gnu

    msg "Compiling maze.amd64..."
    "$CC" "$MAZE_DIR/Maze.c" -o "$MAZE_DIR/bin/maze.amd64" -target x86_64-linux-gnu

    msg "Compiling maze.aarch64..."
    CC=aarch64-linux-gnu-gcc
    "$CC" "$MAZE_DIR/Maze.c" -o "$MAZE_DIR/bin/maze.aarch64" #-target aarch64-linux-gnu
}

main $@
