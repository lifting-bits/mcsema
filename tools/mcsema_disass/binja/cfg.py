# Copyright (c) 2018 Trail of Bits, Inc.
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

# System import
import argparse
import os

# Definitions
EXT_MAP = {}
EXT_DATA_MAP = {}

RECOVER_OPTS = {
  'stack_vars': False
}

# Internal Imports
import functions
import CFG_pb2
import util
import vars
import log


# Entrypoint for CFG recovery
def get_cfg(args, fixed_args):

  # Parse any additional args
  parser = argparse.ArgumentParser()

  parser.add_argument(
      '--recover-stack-vars',
      help='Flag to enable stack variable recovery',
      default=False,
      action='store_true')

  parser.add_argument(
      "--std-defs",
      action='append',
      type=str,
      default=[],
      help="std_defs file: definitions and calling conventions of imported functions and data")

  extra_args = parser.parse_args(fixed_args)

  if extra_args.recover_stack_vars:
    RECOVER_OPTS['stack_vars'] = True

  # Setup logger
  log.init(args.log_file)

  # Load the binary in binja
  log.debug('Loading binary in BinaryNinja')
  bv = util.load_binary(args.binary)

  # Parse defs files
  log.debug('Loading definitions files')
  util.parse_defs_files(bv, args.os, extra_args.std_defs)

  # Recover cfg
  log.debug('Starting recivery')
  log.push()
  pb_mod = CFG_pb2.Module()
  pb_mod.name = os.path.basename(bv.file.filename)

  log.debug('Recovering Functions')
  functions.recover_functions(bv, pb_mod, args.entrypoint)

  log.debug('Recovering Globals')
  vars.recover_globals(bv, pb_mod)

  log.debug('Processing Segments')
  util.recover_sections(bv, pb_mod)

  log.debug('Recovering Externals')
  util.recover_externals(bv, pb_mod)
  log.pop()

  # Save cfg
  log.debug('Saving to file: %s', args.output)
  with open(args.output, 'wb') as f:
    f.write(pb_mod.SerializeToString())

  return 0
