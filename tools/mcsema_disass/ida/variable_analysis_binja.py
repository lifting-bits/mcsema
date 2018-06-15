#!/usr/bin/env python

# Copyright (c) 2018 Trail of Bits, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import sys
import collections
import argparse
import pprint
from collections import namedtuple
import binaryninja as binja
import mcsema_disass.ida.CFG_pb2

# Debug logging utilities
_DEBUG = False
_DEBUG_FILE = None
_DEBUG_PREFIX = ""

def DEBUG_INIT(file, flag):
  global _DEBUG
  global _DEBUG_FILE
  _DEBUG = flag
  _DEBUG_FILE = file
  
def DEBUG_PUSH():
  global _DEBUG_PREFIX
  _DEBUG_PREFIX += "  "

def DEBUG_POP():
  global _DEBUG_PREFIX
  _DEBUG_PREFIX = _DEBUG_PREFIX[:-2]

def DEBUG(s):
  if _DEBUG:
    _DEBUG_FILE.write("{}{}\n".format(_DEBUG_PREFIX, str(s)))

def convert_signed32(num):
  num = num & 0xFFFFFFFF
  return (num ^ 0x80000000) - 0x80000000
  
def is_valid_addr(bv, addr):
  return bv.get_segment_at(addr) is not None
  
def is_invalid_addr(bv, addr):
  return bv.get_segment_at(addr) is None
  
def get_section_at(bv, addr):
  if is_invalid_addr(bv, addr):
    return None

  for sec in bv.sections.values():
    if sec.start <= addr < sec.end:
      return sec
  return None

def is_executable(bv, addr):
  seg = bv.get_segment_at(addr)
  return seg is not None and seg.executable

def is_readable(bv, addr):
  seg = bv.get_segment_at(addr)
  return seg is not None and seg.writable

def is_writeable(bv, addr):
  seg = bv.get_segment_at(addr)
  return seg is not None and seg.readable

def is_ELF(bv):
  return bv.view_type == 'ELF'

def is_PE(bv):
  return bv.view_type == 'PE'

VARIABLES_TO_RECOVER = dict()

Type = namedtuple('Type', ['name', 'size', 'type_offset', 'tag'])

def _create_variable_entry(name, addr, size=0, offset=0):
  return dict(name=name, offset=offset, type=Type(None, None, None, None), size=size, addr=addr, is_global=True)

def handle_store(bv, func, insn):
  i = 0
  operands = binja.MediumLevelILInstruction.ILOperations[insn.operation]
  for operand in operands:
    name, operand_type = operand
    if operand_type == "int":
      value = insn.operands[i]
      DEBUG("{} {:x}".format(func.name, convert_signed32(value)))
      addr = convert_signed32(value)
      VARIABLES_TO_RECOVER[addr] = _create_variable_entry("recovered_global_{:x}".format(addr), addr)


def handle_function(bv, func):
  if func is None:
    return
  
  # Don't process the external functions
  if func.symbol.type == binja.SymbolType.ImportedFunctionSymbol:
    return

  DEBUG("{:x} {}".format(func.start, func.name))
  for block in func.medium_level_il.basic_blocks:
    for insn in block:
      DEBUG("{:x} {} {}".format(insn.address, str(insn), insn.operation))
      DEBUG("{:x} {} {}".format(insn.address, str(insn.ssa_form), insn.ssa_form.operation))
      DEBUG("{}".format(bv.get_data_var_at(insn.address)))
      if insn.operation ==  binja.MediumLevelILOperation.MLIL_STORE:
         # handle destination operand
         value = insn.dest
         handle_store(bv, func, value)
      elif insn.operation ==  binja.MediumLevelILOperation.MLIL_LOAD:
        value = insn.src
        handle_store(bv, func, value)

def identify_data_variable(bv):
  DEBUG("Looking for data variables {}".format(len(bv.sections)))
  DEBUG_PUSH()
  
  for seg in bv.sections.values():
    addr = seg.start
    DEBUG("Processing section {:x}".format(seg.start))
    if is_executable(bv, addr):
      continue

    var = addr
    next_var = None
    while True:
      DEBUG("Variable at {:x} ".format(var))
      VARIABLES_TO_RECOVER[var] = 0
      next_var = bv.get_next_data_var_after(var)
      if next_var == var:
        break
      size = next_var - var
      dv = bv.get_data_var_at(var)
      VARIABLES_TO_RECOVER[var] = _create_variable_entry("recovered_global_{:x}".format(var), convert_signed32(var), size)
      var = next_var

    size = next_var - var
    VARIABLES_TO_RECOVER[var] = _create_variable_entry("recovered_global_{:x}".format(var), convert_signed32(var), size)
  DEBUG_POP()

def main(binfile, outfile):
  bv = binja.BinaryViewType.get_view_of_file(binfile)
  bv.update_analysis_and_wait()
  
  DEBUG("Analysis file {} loaded...".format(binfile))
  DEBUG("Entry points {:x} {}".format(bv.entry_point, bv.entry_function.name))
  
  entry_func = bv.entry_function
  identify_data_variable(bv)
  
  for func in bv.functions:
    handle_function(bv, func)
    
  updateCFG(outfile)
  DEBUG("Number of global variables recovered with Naive approach {}".format(len(VARIABLES_TO_RECOVER)))

def updateCFG(outfile):
  M = mcsema_disass.ida.CFG_pb2.Module()
  M.name = "GlobalVariables".format('utf-8')

  for key in sorted(VARIABLES_TO_RECOVER.iterkeys()):
    entry = VARIABLES_TO_RECOVER[key]
    var = M.global_vars.add()
    var.ea = key
    var.name = entry['name']
    var.size = entry['size']
    
  with open(outfile, "w") as outf:
    outf.write(M.SerializeToString())
  
if __name__ == '__main__':
  parser = argparse.ArgumentParser()
  parser.add_argument("--log_file", type=argparse.FileType('w'),
                      default=sys.stderr,
                      help='Name of the log file. Default is stderr.')
    
  parser.add_argument('--out',
                      help='Name of the output proto buffer file.',
                      required=True)
    
  parser.add_argument('--binary',
                      help='Name of the binary image.',
                      required=True)
  
  args = parser.parse_args(sys.argv[1:])
  
  if args.log_file:
    DEBUG_INIT(args.log_file, True)
    DEBUG("Debugging is enabled.")
  
  BINARY_FILE = args.binary
  main(args.binary, args.out)