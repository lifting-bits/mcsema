#!/usr/bin/env python
# Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved.

import argparse
import collections
import itertools
import os
import subprocess
import sys
import traceback

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
  script_cmd.append("--entrypoint")
  script_cmd.append(args.entrypoint)
  script_cmd.extend(command_args)  # Extra, script-specific arguments.

  cmd = []
  cmd.append(r'"{}"'.format(args.disassembler))  # Path to IDA.
  cmd.append("-B")  # Batch mode.
  cmd.append("-S\"{}\"".format(" ".join(script_cmd)))
  cmd.append(args.binary)

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

  except subprocess.CalledProcessError as e:
    sys.stderr.write(traceback.format_exc())
    return 1
