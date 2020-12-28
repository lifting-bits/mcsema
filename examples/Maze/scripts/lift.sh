#!/usr/bin/env bash
# Copyright (c) 2017 Trail of Bits, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -euo pipefail

SCRIPTS_DIR="$(dirname $(realpath ${BASH_SOURCE[0]}))"
MAZE_DIR="$(dirname "$SCRIPTS_DIR")"
LLVM_VER=10

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
[!] Usage: $(basename "${BASH_SOURCE[0]}") [-h] [-v] [--llvm LLVM_version]

    Lift the CFG files to LLVM bitcode.

    Available options:

    -h, --help      Print this help and exit
    -v, --verbose   Print script debug info
    --llvm          Specify LLVM version (9 or 10, default: 10)
EOF
}

parse_params() {
    while :; do
        case "${1-}" in
        -h | --help) usage; exit ;;
        -v | --verbose) set -x ;;
        --llvm)
            LLVM_VER="${2-}"
            if [ "$LLVM_VER" != "9" -a "$LLVM_VER" != "10" ]; then
                die "Invalid LLVM version: $LLVM_VER\n$(usage)"
            fi
            shift
            ;;
        -?*) die "Unknown option: $1\n$(usage)" ;;
        *) break ;;
        esac
        shift
    done

    export MCSEMA_LIFT="mcsema-lift-${LLVM_VER}.0"
    if ! command -v "${MCSEMA_LIFT}" >/dev/null 2>&1; then
        die "[!] Cannot find ${MCSEMA_LIFT}"
    fi
}

lift() {
    CFG="$1"
    BC="$MAZE_DIR/bc/$(basename "$CFG" | sed 's/\.cfg$/\.bc/')"
    ARCH="$(basename "$CFG" | sed -e 's/\.cfg$//' -e 's/^maze\.//')"

    set +e
    msg "Lifting $CFG..."
    "$MCSEMA_LIFT" \
        --os linux \
        --arch "$ARCH" \
        --explicit_args \
        --cfg "$CFG" \
        --output "$BC"
    if [ $? -ne 0 ] ; then
        hurt "Failed to lift $CFG"
    else
        msg "Bitcode saved to $BC"
    fi
    set -e
}

main() {
    parse_params $@
    mkdir -p "${MAZE_DIR}/bc"
    lift "${MAZE_DIR}/cfg/maze.x86.cfg"
    lift "${MAZE_DIR}/cfg/maze.amd64.cfg"
    lift "${MAZE_DIR}/cfg/maze.aarch64.cfg"
}

main $@
