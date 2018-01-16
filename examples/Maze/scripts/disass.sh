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

MCSEMA_EXAMPLES_MAZE_SCRIPTS_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
MCSEMA_EXAMPLES_MAZE_DIR=$( cd "$( dirname "${MCSEMA_EXAMPLES_MAZE_SCRIPTS_DIR}" )" && pwd )
MCSEMA_EXAMPLES_DIR=$( cd "$( dirname "${MCSEMA_EXAMPLES_MAZE_DIR}" )" && pwd )
MCSEMA_DIR=$( cd "$( dirname "${MCSEMA_EXAMPLES_DIR}" )" && pwd )
DISASSEMBLER=/opt/ida-6.9/idal64

function Disassemble {

  printf "[+] Disassembling ${MCSEMA_EXAMPLES_MAZE_DIR}/bin/maze.amd64\n"
  mcsema-disass \
      --os linux \
      --arch amd64 \
      --disassembler "${DISASSEMBLER}" \
      --log_file /tmp/log \
      --entrypoint main \
      --output "${MCSEMA_EXAMPLES_MAZE_DIR}/cfg/maze.amd64.cfg" \
      --binary "${MCSEMA_EXAMPLES_MAZE_DIR}/bin/maze.amd64" \
      --log_file /tmp/log.amd64

  if [[ $? -ne 0 ]] ; then
    printf "[x] Error disassembling ${MCSEMA_EXAMPLES_MAZE_DIR}/bin/maze.amd64\n"
    return 1
  else
    printf " i  Saved CFG to ${MCSEMA_EXAMPLES_MAZE_DIR}/cfg/maze.amd64.cfg\n"
  fi

  printf "[+] Disassembling ${MCSEMA_EXAMPLES_MAZE_DIR}/bin/maze.aarch64\n"
  mcsema-disass \
      --os linux \
      --arch aarch64 \
      --disassembler "${DISASSEMBLER}" \
      --log_file /tmp/log \
      --entrypoint main \
      --output "${MCSEMA_EXAMPLES_MAZE_DIR}/cfg/maze.aarch64.cfg" \
      --binary "${MCSEMA_EXAMPLES_MAZE_DIR}/bin/maze.aarch64" \
      --log_file /tmp/log.aarch64

  if [[ $? -ne 0 ]] ; then
    printf "[x] Error disassembling ${MCSEMA_EXAMPLES_MAZE_DIR}/bin/maze.aarch64\n"
    return 1
  else
    printf " i  Saved CFG to ${MCSEMA_EXAMPLES_MAZE_DIR}/cfg/maze.aarch64.cfg\n"
  fi

  return 0
}

function main {
  while [[ $# -gt 0 ]] ; do
    key="$1"

    case $key in

      # Change the default installation prefix.
      --disassembler)
        DISASSEMBLER=$(python -c "import os; import sys; sys.stdout.write(os.path.abspath('${2}'))")
        printf "[+] New disassembler path is ${DISASSEMBLER}\n"
        shift # past argument
      ;;

      *)
        # unknown option
        printf "[x] Unknown option: ${key}\n"
        return 1
      ;;
    esac

    shift # past argument or value
  done

  if [[ ! -f "${DISASSEMBLER}" ]] ; then
    printf "[x] Disassembler ${DISASSEMBLER} does not exist. Please specify it manually using --disassembler.\n"
    return 1
  fi

  Disassemble
  return $?
}

main $@
exit $?
