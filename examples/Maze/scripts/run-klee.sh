#!/usr/bin/env bash

set -euo pipefail

SCRIPTS_DIR="$(dirname $(realpath ${BASH_SOURCE[0]}))"
MAZE_DIR="$(dirname "$SCRIPTS_DIR")"

msg() {
    echo -e "[+] ${1-}" >&2
}

die() {
    echo -e "[!] ${1-}" >&2
    exit 1
}

usage() {
    cat <<EOF
[!] Usage: $(basename "${BASH_SOURCE[0]}") [-h] [-v] program_bitcode [args...]

    Run the given program bitcode with KLEE.

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
    TARGET_BC="$(realpath "$1")"
    shift

    msg "Running ${TARGET_BC} with KLEE..."
    ${MAZE_DIR}/installed/klee/usr/bin/klee \
        --simplify-sym-indices \
        --solver-backend=z3 \
        --solver-optimize-divides \
        --use-forked-solver \
        --use-independent-solver \
        --write-cov \
        --write-paths \
        --write-sym-paths \
        --write-test-info \
        --external-calls=all \
        --suppress-external-warnings \
        --posix-runtime \
        --libc=none \
        "${TARGET_BC}" $@

    OUT_DIR="$(readlink -f "$(dirname "${TARGET_BC}")/klee-last")"
    msg "Output directory: ${OUT_DIR}"
}

main $@
