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
IDA_DIR=/opt/ida-6.9/

mcsema-disass \
    --os linux \
    --arch x86 \
    --disassembler "${IDA_DIR}/idal" \
    --log_file /tmp/log \
    --entrypoint main \
    --output "${MAZE_DIR}/cfg/maze.x86.cfg" \
    --binary "${MAZE_DIR}/bin/maze.x86"

mcsema-disass \
    --os linux \
    --arch amd64 \
    --disassembler "${IDA_DIR}/idal64" \
    --log_file /tmp/log \
    --entrypoint main \
    --output "${MAZE_DIR}/cfg/maze.amd64.cfg" \
    --binary "${MAZE_DIR}/bin/maze.amd64"


mcsema-disass \
    --os linux \
    --arch aarch64 \
    --disassembler "${IDA_DIR}/idal64" \
    --log_file /tmp/log \
    --entrypoint main \
    --output "${MAZE_DIR}/cfg/maze.aarch64.cfg" \
    --binary "${MAZE_DIR}/bin/maze.aarch64"
