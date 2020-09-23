#!/usr/bin/env python
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

import argparse
import collections
import itertools
import os
import subprocess
import sys
import traceback

try:
  from shlex import quote
except:
  from pipes import quote

def execute(args, command_args):
  """Execute IDA Pro as a subprocess, passing this file in as a batch-mode
  script for IDA to run. This forwards along arguments passed to `mcsema-disass`
  down into the IDA script. `command_args` contains unparsed arguments passed
  to `mcsema-disass`. This script may handle extra arguments."""

  ida_disass_path = os.path.abspath(__file__)
  ida_dir = os.path.dirname(ida_disass_path)
  ida_get_cfg_path = os.path.join(ida_dir, "get_cfg.py")

  env = {}
  env["IDALOG"] = os.devnull
  env["TVHEADLESS"] = "1"
  env["HOME"] = os.path.expanduser('~')
  env["IDA_PATH"] = os.path.dirname(args.disassembler)
  env["PYTHONPATH"] = os.path.dirname(ida_dir)
  if "SystemRoot" in os.environ:
    env["SystemRoot"] = os.environ["SystemRoot"]

  script_cmd = []
  script_cmd.append(ida_get_cfg_path)
  script_cmd.append("--output")
  script_cmd.append(args.output)
  script_cmd.append("--log_file")
  script_cmd.append(args.log_file)
  script_cmd.append("--arch")
  script_cmd.append(args.arch)
  script_cmd.append("--os")
  script_cmd.append(args.os)
  if args.rebase:
    script_cmd.append("--rebase")
    script_cmd.append(str(args.rebase))
  if args.entrypoint is not None and len(args.entrypoint):
    script_cmd.append("--entrypoint")
    script_cmd.append(args.entrypoint)
  script_cmd.extend(command_args)  # Extra, script-specific arguments.

  cmd = []
  cmd.append(quote(args.disassembler))  # Path to IDA.
  cmd.append("-B")  # Batch mode.
  cmd.append("-S\"{}\"".format(" ".join(script_cmd)))
  cmd.append(quote(args.binary))

  try:
    with open(os.devnull, "w") as devnull:
      return subprocess.check_call(
          " ".join(cmd),
          env=env, 
          stdin=None, 
          stdout=devnull,  # Necessary.
          stderr=sys.stderr,  # For enabling `--log_file /dev/stderr`.
          shell=True,  # Necessary.
          cwd=os.path.dirname(__file__))

  except:
    sys.stderr.write(traceback.format_exc())
    return 1
