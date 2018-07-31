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

from binja_var_recovery.util import *
from binja_var_recovery.il_instructions import *

"""
   step 1 : Generate the points-to set for the global variables
            a) Set of possible values for variables
            b) Set of possible values in a memory location
            c) Set of possible values in the register passed as arguments
"""

VARIABLES_TO_RECOVER = dict()

POSSIBLE_MEMORY_STATE = dict()

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

INSTRUCTIONS_TO_VARIABLE = dict()
FUNCTION_TO_SSA_VARIABLE = dict()

def get_ssa_def(mlil, var):
  """ Gets the IL that defines var in the SSA form of mlil """
  try:
    return mlil[mlil.get_ssa_var_definition(var)]
  except IndexError:
    return None

def gather_defs(mlil, defs):
  if mlil is None:
    return

  defs.add(mlil.address)
  op = mlil.operation

  if op == binja.MediumLevelILOperation.MLIL_CONST:
    return

  if op in [binja.MediumLevelILOperation.MLIL_VAR_SSA_FIELD, binja.MediumLevelILOperation.MLIL_VAR_SSA]:
    gather_defs(get_ssa_def(mlil.function, mlil.src), defs)

  if op == binja.MediumLevelILOperation.MLIL_VAR_PHI:
    for var in mlil.src:
      gather_defs(get_ssa_def(mlil.function, var), defs)

  if hasattr(mlil, 'src') and isinstance(mlil.src, binja.MediumLevelILInstruction):
    gather_defs(mlil.src, defs)

""" Collects the ssa variables used in the instruction
"""
def collect_variables(bv, instr):
  variables = []

  for operand in instr.prefix_operands:
    if isinstance(operand, binja.SSAVariable):
      variables.append(operand)
    elif isinstance(operand, list):
      for element in operand:
        if isinstance(element, binja.SSAVariable):
          variables.append(element)
        elif isinstance(element, binja.MediumLevelILInstruction):
          variables += collect_variables(bv, element)

  return variables


def _create_variable_entry(name, addr, size=0):
  return dict(name=name, size=size, addr=addr, is_global=True, refs=set())

def handle_instruction_ssa(bv, func, insn):
  if insn is None or  not is_executable(bv, insn.address):
    return

  INSTRUCTIONS_TO_VARIABLE[insn.address] = collect_variables(bv, insn)
  DEBUG("{:x} : {} operation name {}".format(insn.address, str(insn), insn.operation.name))
  DEBUG("{:x} : {} operation name {}".format(insn.address, str(insn.ssa_form), insn.ssa_form.operation.name))
  DEBUG("Collected variable at insn {:x} : {}".format(insn.address, pprint.pformat(INSTRUCTIONS_TO_VARIABLE[insn.address])))

  # Remove the check for variable reference. It does not check
  # if any global variable is getting referenced at insn
  dv = bv.get_data_var_at(insn.address)
  if dv is not None:
    DEBUG("Insn refer to variable at {}".format(bv.get_data_var_at(insn.address)))

  if insn.operation ==  binja.MediumLevelILOperation.MLIL_STORE_SSA:
    # handle destination operand
    handle_store(bv, func, insn)

  elif insn.operation ==  binja.MediumLevelILOperation.MLIL_LOAD_SSA:
    value = insn.src
    handle_load(bv, func, value)

  elif insn.operation == binja.MediumLevelILOperation.MLIL_SET_VAR_SSA:
    vars_written = insn.vars_written
    DEBUG("Operation MLIL_SET_VAR insn : {} vars: {} possible values {}".format(insn, pprint.pformat(vars_written), insn.src.value))
    for var in vars_written:
      result = func.medium_level_il.get_ssa_var_uses(var)
      for instr in result:
        DEBUG("Operation MLIL_SET_VAR var written uses : {} ".format(func.medium_level_il[instr]))

    vars_read = insn.vars_read
    for var in vars_read:
      if isinstance(var, binja.mediumlevelil.SSAVariable):
        DEBUG("Operation MLIL_SET_VAR insn : {} vars: {} possible values {}".format(insn, var, insn.src.possible_values))
        result = func.medium_level_il.get_ssa_var_uses(var)
        for instr in result:
          DEBUG("Operation MLIL_SET_VAR var read uses : {} ".format(func.medium_level_il[instr]))


def handle_function(bv, func):
  if func is None:
    return
  
  # Don't process the external functions
  if func.symbol.type == binja.SymbolType.ImportedFunctionSymbol:
    return

  DEBUG("{:x} {}".format(func.start, func.name))

  handle_function_refernces(bv, func)

  dump_mlil_ssa(bv, func)
  dump_llil_ssa(bv, func)
  bb = func.medium_level_il.basic_blocks
  bb_visited = list()
  bb_to_visit = set()

  if len(bb) == 0:
    DEBUG("Function {} does not have basic blocks".format(func.name))
    return

  DEBUG_PUSH()
  for block in bb:
    DEBUG("Processing basic block at {:x}".format(func.medium_level_il[block.start].address))
    DEBUG_PUSH()
    for insn in block:
      #handle_instruction(bv, func, insn)
      handle_instruction_ssa(bv, func, insn.ssa_form)

    DEBUG_POP()
    bb_visited.append(block)
  DEBUG_POP()

"""
    1) Get the list of functions and the entry functions
    2) Walk through the list of functions and get the list of possible arguments getting passed
    3) Remove the function from list and perform analysis again
"""

def recover_instruction(bv, func, insn, to_visit):
  if insn is None or not is_executable(bv, insn.address):
    return

  #DEBUG("{:x} : {} operation name {}".format(insn.address, str(insn), insn.operation.name))
  mlil_insn = ILInstruction(bv, func, insn)
  mlil_insn.process_instruction()

def recover_function(bv, func, to_visit):
  """ Process the function and collect the function which should be visited next
  """
  if func is None:
    return
  
  index = 0
  DEBUG("{:x} {}".format(func.start, func.name))
  size = len(func.medium_level_il.ssa_form)

  func_obj = Function(bv, func)
  if func_obj is None:
    return

  FUNCTION_OBJECTS[func.start] = func_obj
  func_obj.collect_parameters()
  DEBUG_PUSH()
  while index < size:
    insn = func.medium_level_il.ssa_form[index]
    DEBUG("{} : {:x} {} operation {} ".format(index+1, insn.address, insn, insn.operation.name))
    recover_instruction(bv, func, insn, to_visit)
    if insn.operation == binja.LowLevelILOperation.LLIL_CALL_SSA:
      dest = insn.dest
      if dest.operation == binja.LowLevelILOperation.LLIL_CONST_PTR:
        called_function = bv.get_function_at(dest.constant)
        DEBUG("{} : {}".format(index+1, called_function))
        if called_function is not None:
          to_visit.append(called_function.start)
    index += 1
  DEBUG_POP()

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
      VARIABLES_TO_RECOVER[var] = _create_variable_entry("global_var_{:x}".format(var), convert_signed32(var), size)
      for ref in bv.get_code_refs(var):
        #DEBUG("Data reference at {} {:x}".format(ref.function, ref.address))
        llil = ref.function.get_low_level_il_at(ref.address)
        VARIABLES_TO_RECOVER[var]["refs"].add(ref)

      var = next_var

    size = next_var - var
    if dv is not None:
      VARIABLES_TO_RECOVER[var] = _create_variable_entry("recovered_global_{:x}".format(var), convert_signed32(var), size)
  DEBUG_POP()

# main function
def main(binfile, outfile):
  """ Function which recover the variables from the medium-level IL instructions;
      1) Get the data variables and populate the list with possible sizes and references; The data variables
         recovered may not be having the correct size which should get fixed at later point 
  """
  bv = binja.BinaryViewType.get_view_of_file(binfile)
  bv.update_analysis_and_wait()
  
  DEBUG("Analysis file {} loaded...".format(binfile))
  DEBUG("Entry points {:x} {}".format(bv.entry_point, bv.entry_function.name))
  
  identify_data_variable(bv)
  entry_func = bv.entry_function
  
  to_visit = list()
  visited = set()
  
  recover_function(bv, entry_func, to_visit)
  visited.add(entry_func.start)
  
  for func in bv.functions:
    if func.start in visited:
      continue
    
    to_visit.append(func.start)
    while len(to_visit) > 0:
      func_addr = to_visit.pop(0)
      visit_func = bv.get_function_at(func_addr)
      recover_function(bv, visit_func, to_visit)
      visited.add(func_addr)
    
  updateCFG(outfile)
  DEBUG("Number of global variables recovered with Naive approach {}".format(len(VARIABLES_TO_RECOVER)))
  DEBUG("Number of global variables passed as params {}".format(len(VARIABLE_AS_PARAMS)))
  DEBUG("Possible memory state {}".format(pprint.pformat(POSSIBLE_MEMORY_STATE)))


def updateCFG(outfile):
  """ Update the CFG file with the recovered global variables
  """
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
    INIT_DEBUG_FILE(args.log_file)
    DEBUG("Debugging is enabled.")
  
  BINARY_FILE = args.binary
  main(args.binary, args.out)