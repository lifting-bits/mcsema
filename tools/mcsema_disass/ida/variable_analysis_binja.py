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

from z3 import (UGT, ULT, And, Array, BitVec, BitVecSort, Concat, Extract, LShR, Not, Or, Solver, ZeroExt, simplify, unsat)

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

"""
   step 1 : Generate the points-to set for the global variables
            a) Set of possible values for variables
            b) Set of possible values in a memory location
            c) Set of possible values in the register passed as arguments
"""

def create_BitVec(ssa_var, size):
  return BitVec('{}#{}'.format(ssa_var.var.name, ssa_var.version), size * 8 if size else 1)

def identify_byte(var, function):
  if isinstance(var, binja.SSAVariable):
    possible_values = function[1].get_ssa_var_possible_values(var)
    size = function[function.get_ssa_var_definition(var)].size
  else:
    possible_values = var.possible_values
    size = var.size

  #DEBUG("identify_byte {} {}".format(possible_values, len(possible_values.ranges)))
  if (possible_values.type == binja.RegisterValueType.UnsignedRangeValue):
    value_range = possible_values.ranges[0]
    start = value_range.start
    end = value_range.end
    step = value_range.step

    for i in range(size):
      if (start, end, step) == (0, (0xff << (8 * i)), (1 << (8 * i))):
        return value_range


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
POSSIBLE_MEMORY_STATE = dict()

"""
    Gather the definition of variables in the use-def chain; Find all addresses in the way
"""

"""
    Data Structure to gather information about the list of variables an instruction is using 
"""
INSTRUCTIONS_TO_VARIABLE = dict()
FUNCTION_PARAMETERS = dict()

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

Type = namedtuple('Type', ['name', 'size', 'type_offset', 'tag'])

def _create_variable_entry(name, addr, size=0, offset=0):
  return dict(name=name, offset=offset, type=Type(None, None, None, None), size=size, addr=addr, is_global=True)

class MLILVisitor(object):
  """ Class functions to visit medium IL"""
  def __init__(self):
    super(MLILVisitor, self).__init__()

  def visit(self, expr):
    method_name = 'visit_{}'.format(expr.operation.name)
    DEBUG("visit {}".format(method_name))
    if hasattr(self, method_name):
      value = getattr(self, method_name)(expr)
    else:
      value = None
    return value

class VariableModeler(MLILVisitor):
  def __init__(self, var, address_size):
    super(VariableModeler, self).__init__()
    self.address_size = address_size
    self.var = var
    self.function = var.function
    self.visited = set()
    self.to_visit = list()


  def model_variable(self):
    var_def = self.function.get_ssa_var_definition(self.var.src)
    DEBUG("model_variable {} {} {}".format(self.var.src, self.function, var_def))
    self.to_visit.append(var_def)

    while self.to_visit:
      idx = self.to_visit.pop()
      if idx is not None:
        DEBUG("visit {}".format(self.function[idx]))
        self.visit(self.function[idx])

  def visit_MLIL_CONST(self, expr):
    return expr.constant

  def visit_MLIL_VAR(self, expr):
    pass

  def visit_MLIL_SET_VAR(self, expr):
    DEBUG("visit_MLIL_SET_VAR : {}".format(expr))
    src = self.visit(expr.src)
    pass

  def visit_MLIL_LOAD(self, expr):
    pass

  def visit_MLIL_STORE(self, expr):
    pass

  def visit_MLIL_SET_VAR_SSA(self, expr):
    DEBUG("visit_MLIL_SET_VAR_SSA : {}".format(expr))
    src = self.visit(expr.src)
    pass

  def visit_MLIL_VAR_SSA(self, expr):
    if expr.src not in self.visited:
      DEBUG("visit_MLIL_VAR_SSA : {}".format(expr))
      var_def = expr.function.get_ssa_var_definition(expr.src)
      if var_def is not None:
        self.to_visit.append(var_def)

    src = create_BitVec(expr.src, expr.size)
    DEBUG("visit_MLIL_VAR_SSA : {}".format(src))
    value_range = identify_byte(expr, self.function)
    DEBUG("visit_MLIL_VAR_SSA  value_range : {}".format(value_range))

    #return src

class ILInstruction(object):
  def __init__(self, bv, insn_il):
    self.insn = insn_il

def dump_ssa_form(bv, func):
  if func is None:
    return

  index = 0
  size = len(func.medium_level_il.ssa_form)
  DEBUG("Dump the ssa form of function {} for analysis; size {}".format(func.name, size))

  while index < size:
    insn = func.medium_level_il.ssa_form[index]
    DEBUG("{} : {:x} {}".format(index+1, insn.address, insn))
    index += 1


def handle_store(bv, func, insn):
  index = 0
  src_value = 0
  dest_addr = 0
  insn_src = insn.src
  insn_dest = insn.dest

  # Handle the instruction src to check what value is getting written in the
  operands = binja.MediumLevelILInstruction.ILOperations[insn_src.operation]
  for operand in operands:
    name, operand_type = operand
    if operand_type == "int":
      value = insn_src.operands[index]
      addr = convert_signed32(value)
      DEBUG("handle_store: src operand value {:x} @ {}".format(addr, func.name))
      dv = bv.get_data_var_at(addr)
      if dv is not None:
        DEBUG("Source operand referring to variable at {:x}".format(addr))

      src_value = addr
    elif operand_type == "expr":
      value = insn_src.operands[index]
      DEBUG("handle_store: evalue expr {} @ {}".format(value, func.name))
    index += 1

  index = 0
  operands = binja.MediumLevelILInstruction.ILOperations[insn_dest.operation]
  for operand in operands:
    name, operand_type = operand
    if operand_type == "int":
      value = insn_dest.operands[index]
      DEBUG("{} {:x}".format(func.name, convert_signed32(value)))
      addr = convert_signed32(value)
      dest_addr = addr
      dv = bv.get_data_var_at(addr)
      if dv is not None:
        VARIABLES_TO_RECOVER[addr] = _create_variable_entry("recovered_global_{:x}".format(addr), addr)
    index += 1

  if dest_addr != 0:
    if dest_addr in POSSIBLE_MEMORY_STATE.keys():
      possible_value = POSSIBLE_MEMORY_STATE[dest_addr]
      possible_value.add(src_value)
    else:
      possible_value = set()
      possible_value.add(src_value)
      POSSIBLE_MEMORY_STATE[dest_addr] = possible_value

def handle_load(bv, func, insn):
  i = 0
  operands = binja.MediumLevelILInstruction.ILOperations[insn.operation]
  for operand in operands:
    name, operand_type = operand
    if operand_type == "int":
      value = insn.operands[i]
      DEBUG("{} {:x}".format(func.name, convert_signed32(value)))
      addr = convert_signed32(value)
      dv = bv.get_data_var_at(addr)
      if dv is not None:
        VARIABLES_TO_RECOVER[addr] = _create_variable_entry("recovered_global_{:x}".format(addr), addr)

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

   #elif insn.operation == binja.MediumLevelILOperation.MLIL

    #ssa_defs = set()
    #gather_defs(insn, ssa_defs)
    #DEBUG("Gather defs {}".format(pprint.pformat(ssa_defs)))

def handle_instruction(bv, func, insn):
  DEBUG("{:x} : {} operation name {}".format(insn.address, str(insn), insn.operation.name))
  DEBUG("{:x} : {} operation name {}".format(insn.address, str(insn.ssa_form), insn.ssa_form.operation.name))

  if insn is None:
    return

  # Remove the check for variable reference. It does not check
  # if any global variable is getting referenced at insn
  #dv = bv.get_data_var_at(insn.address)
  #if dv is not None:
  #  DEBUG("Insn refer to variable at {}".format(bv.get_data_var_at(insn.address)))

  if insn.operation ==  binja.MediumLevelILOperation.MLIL_STORE:
    # handle destination operand
    value = insn.dest
    handle_store(bv, func, value)

  elif insn.operation ==  binja.MediumLevelILOperation.MLIL_LOAD:
    value = insn.src
    handle_store(bv, func, value)

  elif insn.operation == binja.MediumLevelILOperation.MLIL_SET_VAR:
    vars_written = insn.vars_written
    DEBUG("Operation MLIL_SET_VAR insn : {} vars: {} possible values {}".format(insn, pprint.pformat(vars_written), insn.src.value))
    for var in vars_written:
      result = func.medium_level_il.get_var_definitions(var)
      for instr in result:
        DEBUG("Operation MLIL_SET_VAR var definitions : {} ".format(func.medium_level_il[instr]))

def handle_function_refernces(bv, func):
  """ Find refernces of the function and get the parameters 
      and calculate possible values
  """
  if func is None:
    return

  for ref in bv.get_code_refs(func.start):
    DEBUG("Function {} is getting referenced at {:x}".format(func.name, ref.address))
    param1 = func.get_parameter_at(ref.address, None, 0)
    param2 = func.get_parameter_at(ref.address, None, 1)
    DEBUG("param1 {} param2 {}".format(param1, param2))

    rdi = func.get_reg_value_at(ref.address, 'rdi')
    DEBUG("Register rdi {}".format(rdi))


def handle_function(bv, func):
  if func is None:
    return
  
  # Don't process the external functions
  if func.symbol.type == binja.SymbolType.ImportedFunctionSymbol:
    return

  DEBUG("{:x} {}".format(func.start, func.name))

  handle_function_refernces(bv, func)

  dump_ssa_form(bv, func)
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

def get_instruction_at_addr(bv, func, addr):
  for bb in func.low_level_il.basic_blocks:
    for insn in bb:
      if insn.address == addr:
        if insn.medium_level_il != None:
          return insn.medium_level_il.ssa_form

def identify_data_variable(bv):
  DEBUG("Looking for data variables {}".format(len(bv.sections)))
  DEBUG_PUSH()
  
  for seg in bv.sections.values():
    addr = seg.start
    if is_executable(bv, addr):
      continue

    var = addr
    next_var = None
    while True:
      VARIABLES_TO_RECOVER[var] = 0
      next_var = bv.get_next_data_var_after(var)
      if next_var == var:
        break

      size = next_var - var
      dv = bv.get_data_var_at(var)
      if dv is not None:
        DEBUG("Global Variable address {:x} type {} auto discovered {}".format(var, type(dv), dv))
        VARIABLES_TO_RECOVER[var] = _create_variable_entry("global_var_{:x}".format(var), convert_signed32(var), size)
        for ref in bv.get_code_refs(var):
          DEBUG("Data reference at {} {:x}".format(ref.function, ref.address))
          DEBUG("Instructions : {}".format(get_instruction_at_addr(bv, ref.function, ref.address)))
        var = next_var

    size = next_var - var
    if dv is not None:
      VARIABLES_TO_RECOVER[var] = _create_variable_entry("recovered_global_{:x}".format(var), convert_signed32(var), size)
  DEBUG_POP()

"""
    1) Get the list of functions and the entry functions
    2) Walk through the list of functions and get the list of possible arguments getting passed
    3) Remove the function from list and perform analysis again
"""

def collect_functions_arguments(bv, func):
  if func is None:
    return

  num_params = len(func.parameter_vars)
  start_addr = func.start
  if start_addr in FUNCTION_PARAMETERS.keys():
    func_params = FUNCTION_PARAMETERS[start_addr]
  else:
    func_params = list()

  DEBUG("Number of possible parameter in the functions {} {}".format(func.name, num_params))

  for ref in bv.get_code_refs(start_addr):
    ref_function = ref.function
    insn_mlil = ref_function.get_low_level_il_at(ref.address).medium_level_il
    insn_mlil_ssa = insn_mlil.ssa_form if insn_mlil is not None else None
    if insn_mlil_ssa is None:
      continue 

    DEBUG("Function referred : {} {}".format(ref_function, insn_mlil.ssa_form if insn_mlil is not None else insn_mlil))
    num_params = len(insn_mlil_ssa.params) if insn_mlil_ssa.params is not None else 0
    for index in range(num_params):
      if insn_mlil_ssa is not None:
        param = insn_mlil_ssa.params[index]
        DEBUG("param {} : {} {}".format(index, param, param.operation))

        possible_values = param.possible_values
        DEBUG("param possible values {}".format(possible_values))

        if len(func_params) > index:
          value_set = func_params[index]
          value_set.add(param)
          func_params[index] = value_set
        else:
          value_set = set()
          value_set.add(param)
          func_params.append(value_set)
        
        if possible_values.type != binja.RegisterValueType.UndeterminedValue:
          continue

        model = VariableModeler(param, bv.address_size)
        model.model_variable()

    FUNCTION_PARAMETERS[start_addr] = func_params

def main(binfile, outfile):
  bv = binja.BinaryViewType.get_view_of_file(binfile)
  bv.update_analysis_and_wait()
  
  DEBUG("Analysis file {} loaded...".format(binfile))
  DEBUG("Entry points {:x} {}".format(bv.entry_point, bv.entry_function.name))
  
  entry_func = bv.entry_function
  #identify_data_variable(bv)
  
  for func in bv.functions:
    collect_functions_arguments(bv, func)
  
  DEBUG("Function arguments {} ".format(pprint.pformat(FUNCTION_PARAMETERS)))
  for func in bv.functions:
    handle_function(bv, func)
    
  updateCFG(outfile)
  DEBUG("Number of global variables recovered with Naive approach {}".format(len(VARIABLES_TO_RECOVER)))
  DEBUG("Possible memory state {}".format(pprint.pformat(POSSIBLE_MEMORY_STATE)))

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