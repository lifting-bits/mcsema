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

SCRIPTS_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
MAZE_DIR=$( cd "$( dirname "${SCRIPTS_DIR}" )" && pwd )
KLEE_WS_DIR=$(pwd)

mkdir -p "${MAZE_DIR}/bc"

LIB_ARGS=
if [[ -f "${KLEE_WS_DIR}/libc.bc" ]] ; then
  LIB_ARGS="--library ${KLEE_WS_DIR}/libc.bc"
else
  printf "WARNING: Could not find klee-uclibc\n"
fi

mcsema-lift-3.9 \
    --os linux \
    --arch x86 \
    --cfg "${MAZE_DIR}/cfg/maze.x86.cfg" \
    --output "${MAZE_DIR}/bc/maze.x86.bc" \
    --explicit_args \
    ${LIB_ARGS}

mcsema-lift-3.9 \
    --os linux \
    --arch amd64 \
    --cfg "${MAZE_DIR}/cfg/maze.amd64.cfg" \
    --output "${MAZE_DIR}/bc/maze.amd64.bc" \
    --explicit_args \
    ${LIB_ARGS}

mcsema-lift-3.9 \
    --os linux \
    --arch aarch64 \
    --cfg "${MAZE_DIR}/cfg/maze.aarch64.cfg" \
    --output "${MAZE_DIR}/bc/maze.aarch64.bc" \
    --explicit_args \
    ${LIB_ARGS}

