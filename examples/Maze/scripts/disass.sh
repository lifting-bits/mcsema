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
DISASSEMBLER=/opt/idapro-7.5/idat64

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
[!] Usage: $(basename "${BASH_SOURCE[0]}") [-h] [-v] [--disassembler path]

    Disassemble the binaries into CFG files.

    Available options:

    -h, --help      Print this help and exit
    -v, --verbose   Print script debug info
    --disassembler  Specify the backend disassembler
EOF
}

parse_params() {
    while :; do
        case "${1-}" in
        -h | --help) usage; exit ;;
        -v | --verbose) set -x ;;
        --disassembler)
            DISASSEMBLER="$(realpath -m "${2-}")"
            shift ;;
        -?*) die "Unknown option: $1\n$(usage)" ;;
        *) break ;;
        esac
        shift
    done

    if [ ! -f "$DISASSEMBLER" ]; then
        die "Disassembler '${DISASSEMBLER}' does not exist"
    fi
    msg "Use disassembler ${DISASSEMBLER}"
}

disassemble() {
    BIN="$1"
    CFG="${MAZE_DIR}/cfg/$(basename "$BIN").cfg"
    ARCH="$(basename "$BIN" | sed 's/^maze\.//')"
    if file "$BIN" | grep ' pie ' >/dev/null 2>&1; then
        PIE_FLAG='--pie-mode'
    else
        PIE_FLAG=''
    fi

    set +e
    msg "Disassembling $BIN..."
    mcsema-disass \
        --os linux \
        --arch "$ARCH" \
        --disassembler "$DISASSEMBLER" \
        --entrypoint main \
        $PIE_FLAG \
        --log_file "$BIN.log" \
        --binary "$BIN" \
        --output "$CFG"
    if [ $? -ne 0 ] ; then
        hurt "Failed to disassemble $BIN"
    else
        msg "CFG saved to $CFG"
    fi
    set -e
}

main() {
    parse_params $@
    disassemble "${MAZE_DIR}/bin/maze.x86"
    disassemble "${MAZE_DIR}/bin/maze.amd64"
    disassemble "${MAZE_DIR}/bin/maze.aarch64"
}

main $@
