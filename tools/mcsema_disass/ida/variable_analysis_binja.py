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
from Queue import Queue
from collections import namedtuple
import binaryninja as binja
import mcsema_disass.ida.CFG_pb2

from binja_var_recovery.util import *
from binja_var_recovery.il_instructions import *

VARIABLES_TO_RECOVER = dict()

POSSIBLE_MEMORY_STATE = dict()

RECOVERED = set()
TO_RECOVER = Queue()

def queue_func(addr):
  if addr not in RECOVERED:
    TO_RECOVER.put(addr)

def identify_byte(var, function):
  if isinstance(var, binja.SSAVariable):
    possible_values = function[1].get_ssa_var_possible_values(var)
    size = function[function.get_ssa_var_definition(var)].size
  else:
    possible_values = var.possible_values
    size = var.size

  if (possible_values.type == binja.RegisterValueType.UnsignedRangeValue):
    value_range = possible_values.ranges[0]
    start = value_range.start
    end = value_range.end
    step = value_range.step

    for i in range(size):
      if (start, end, step) == (0, (0xff << (8 * i)), (1 << (8 * i))):
        return value_range

def _create_variable_entry(name, addr, size=0):
  return dict(name=name, size=size, addr=addr, is_global=True, refs=set())

def recover_instruction(bv, func, insn):
  if insn is None:
    return

  if not is_executable(bv, insn.address):
    return

  mlil_insn = ILInstruction(bv, func, insn)
  operation_name = "{}".format(insn.operation.name)
  if hasattr(mlil_insn, operation_name):
    getattr(mlil_insn, operation_name)(insn)
  else:
    DEBUG("Instruction operation {} is not supported!".format(operation_name))

def recover_function(bv, addr, is_entry=False):
  """ Process the function and collect the function which should be visited next
  """
  func = bv.get_function_at(addr)
  if func is None:
    return

  if func.symbol.type == binja.SymbolType.ImportedFunctionSymbol:
    DEBUG("Skipping external function '{}'".format(func.symbol.name))
    return

  DEBUG("Recovering function {} at {:x}".format(func.symbol.name, addr))
  
  index = 0
  DEBUG("{:x} {}".format(func.start, func.name))
  size = len(func.medium_level_il.ssa_form)

  DEBUG_PUSH()
  while index < size:
    insn = func.medium_level_il.ssa_form[index]
    DEBUG("{} : {:x} {} operation {} ".format(index+1, insn.address, insn, insn.operation.name))
    DEBUG_PUSH()
    recover_instruction(bv, func, insn)
    DEBUG_POP()
    if insn.operation == binja.MediumLevelILOperation.MLIL_CALL_SSA:
      dest = insn.dest
      if dest.operation == binja.MediumLevelILOperation.MLIL_CONST_PTR:
        called_function = bv.get_function_at(dest.constant)
        DEBUG("{} : {}".format(index+1, called_function))
        if called_function is not None:
          queue_func(called_function.start)
    index += 1
  DEBUG_POP()
  #func_obj.print_ssa_variables()

def identify_data_variable(bv):
  """ Recover the data variables from the segments identified by binja; The size of
      variables may not be correct and safe to recover.
  """
  if bv is None:
    return

  DEBUG("Looking for data variables {}".format(len(bv.sections)))  
  DEBUG_PUSH()
  
  for seg in bv.sections.values():
    addr = seg.start
    if is_executable(bv, addr):
      continue

    var = addr
    next_var = None
    while True:
      next_var = bv.get_next_data_var_after(var)
      if next_var == var:
        break

      size = next_var - var
      dv = bv.get_data_var_at(var)
      #DEBUG("Global Variable address {:x} and type {}".format(var, type(dv)))
      VARIABLE_ALIAS_SET.add(var, next_var)
      for ref in bv.get_code_refs(var):
        llil = ref.function.get_low_level_il_at(ref.address)
      var = next_var

    size = next_var - var
    if dv is not None:
      VARIABLE_ALIAS_SET.add(var, next_var)
  DEBUG_POP()

# main function
def main(args):
  """ Function which recover the variables from the medium-level IL instructions;
      1) Get the data variables and populate the list with possible sizes and references; The data variables
         recovered may not be having the correct size which should get fixed at later point 
  """
  bv = binja.BinaryViewType.get_view_of_file(args.binary)
  bv.update_analysis_and_wait()
  
  DEBUG("Analysis file {} loaded...".format(args.binary))
  
  entry_symbol = bv.get_symbols_by_name(args.entrypoint)[0]
  DEBUG("Entry points {:x} {}".format(entry_symbol.address, entry_symbol.name))

  # Get all the data variables from the data segments
  identify_data_variable(bv)

  # Create function objects and collect its references
  for func in bv.functions:
    create_function(bv, func)

  entry_addr = entry_symbol.address
  recover_function(bv, entry_addr, is_entry=True)

  # Recover any discovered functions until there are none left
  while not TO_RECOVER.empty():
    addr = TO_RECOVER.get()

    if addr in RECOVERED:
      continue
    RECOVERED.add(addr)

    recover_function(bv, addr)
    DEBUG_FLUSH()

  updateCFG(args.out)
  DEBUG("Number of global variables passed as params {}".format(VARIABLE_ALIAS_SET))
  DEBUG("SSA Variable value set {}".format(pprint.pformat(SSA_VARIABLE_VALUESET)))
  #DEBUG("Possible memory state {}".format(pprint.pformat(POSSIBLE_MEMORY_STATE)))


def updateCFG(outfile):
  """ Update the CFG file with the recovered global variables
  """
  M = mcsema_disass.ida.CFG_pb2.Module()
  M.name = "GlobalVariables".format('utf-8')

  blacklist_file = "blacklist.txt"
  BLACKLIST_VECTOR = dict()

  with open(blacklist_file, "r") as bfile:
    lines = bfile.readlines()
    for l in lines:
      ea = long(l, 16)
      BLACKLIST_VECTOR[ea] = 1

  for key in sorted(VARIABLE_ALIAS_SET.ALIAS_SET.iterkeys()):
    if key not in BLACKLIST_VECTOR.keys():
      value = VARIABLE_ALIAS_SET.ALIAS_SET[key]
      size = value - key
      var = M.global_vars.add()
      var.ea = key
      var.name = "global_var_{:x}".format(key)
      var.size = size #entry['size'] This is dummy size since it does not get used by get_cfg in IDA
    
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

  parser.add_argument('--entrypoint',
                      help='Name of the entry point function.',
                      required=True)
  
  args = parser.parse_args(sys.argv[1:])
  
  if args.log_file:
    INIT_DEBUG_FILE(args.log_file)
    DEBUG("Debugging is enabled.")
  
  BINARY_FILE = args.binary
  main(args)