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

import re
import io
import collections
import struct
from binaryninja import *
from binja_var_recovery.util import *

VARIABLE_ANALYSIS_SET = collections.defaultdict()

class Values(object):
  def __init__(self, addr, src):
    self.address = addr
    self.src = src

  def __str__(self):
    return "<{:x}, {:x}>".format(self.address, self.src)

  def __repr__(self):
    return "<{:x}, {:x}>".format(self.address, self.src)

class SymbolicValue(object):
  def __init__(self, comment, offset):
    self.comment = comment
    self.offset = offset

  def __str__(self):
    return "<{}, {:x}>".format(self.comment, self.offset)

  def __repr__(self):
    return "<{}, {:x}>".format(self.comment, self.offset)

def is_subset(s1, s2):
  for item in s2:
    if item not in s1:
      return False
  return True

def is_long(bv, addr):
  return isinstance(addr, long)

def is_values(bv, obj):
  return isinstance(obj, Values)
  
def is_sym_values(bv, obj):
  return isinstance(obj, SymbolicValue)

def is_mlil(bv, insn):
  return isinstance(insn, MediumLevelILInstruction)
  
def is_llil(bv, insn):
  return isinstance(insn, LowLevelILInstruction)
  
def is_reg_ssa(bv, reg):
  return isinstance(reg, SSARegister)

def is_call(bv, insn):
  return insn.operation == LowLevelILOperation.LLIL_CALL or \
    insn.operation == LowLevelILOperation.LLIL_CALL_STACK_ADJUST or \
    insn.operation == LowLevelILOperation.LLIL_CALL_SSA 

def is_load(bv, insn):
  return insn.operation == LowLevelILOperation.LLIL_LOAD_SSA or \
    insn.operation == LowLevelILOperation.LLIL_LOAD
    
def is_store(bv, insn):
  return insn.operation == LowLevelILOperation.LLIL_STORE_SSA or \
    insn.operation == LowLevelILOperation.LLIL_STORE
    
def is_constant(bv, insn):
  if is_mlil(bv, insn):
    return insn.operation == MediumLevelILOperation.MLIL_CONST or \
      insn.operation == MediumLevelILOperation.MLIL_CONST_PTR
  elif is_llil(bv, insn):
    return insn.operation == LowLevelILOperation.LLIL_CONST or \
      insn.operation == LowLevelILOperation.LLIL_CONST_PTR
      
def is_register(bv, insn):
  if is_mlil(bv, insn):
    return insn.operation == MediumLevelILOperation.MLIL_REG or \
      insn.operation == MediumLevelILOperation.MLIL_REG_SSA
  elif is_llil(bv, insn):
    return insn.operation == LowLevelILOperation.LLIL_REG or \
      insn.operation == LowLevelILOperation.LLIL_REG_SSA
    
def is_address(bv, insn):
  if insn.operation == LowLevelILOperation.LLIL_SET_REG or \
    insn.operation == LowLevelILOperation.LLIL_SET_REG_SSA:
    return is_constant(bv, insn.src)
  return False
  
def call_target(bv, insn):
  if is_llil(bv, insn) and is_constant(bv, insn.dest):
    return insn.dest.constant
  else:
    return None

def is_stack_op(bv, expr):
  for opnd in expr.operands:
    if isinstance(opnd, SSARegister):
      if repr(opnd.reg) in ["rsp", "rbp"]:
        return True
    
    if is_llil(bv, opnd) and is_register(bv, opnd):
        reg_name = repr(opnd.src.reg)
        if reg_name in ["rsp", "rbp"]:
          return True

  return False

def get_variable_size(bv, insn):
  if insn.operation == MediumLevelILOperation.MLIL_STORE_SSA or \
    insn.operation == MediumLevelILOperation.MLIL_LOAD_SSA:
    return insn.size
  elif insn.operation == MediumLevelILOperation.MLIL_SET_VAR_SSA:
    return get_variable_size(bv, insn.src)
  elif insn.operation == MediumLevelILOperation.MLIL_IF:
    return get_variable_size(bv, insn.condition)
  return insn.size

def get_memory_version(bv, insn):
  """ Get the version of the ssa memory for the `MediumLevelILInstruction`. For 
      the `LowLevelILInstruction` it finds out if the insn is memory operation
  """
  if is_mlil(bv, insn):
    if insn.ssa_memory_version > 0:
      return insn.ssa_memory_version
    elif "mem#0" in str(insn):
      return 0
  elif is_llil(bv, insn):
    if "mem#" in str(insn):
      return 1

def get_address(bv, insn):
  for token in insn.tokens:
    if token.type == InstructionTextTokenType.PossibleAddressToken:
      return token.value

def analyse_variable_size(bv, variable):
  if variable in VARIABLE_ANALYSIS_SET.keys():
    return VARIABLE_ANALYSIS_SET[variable]

  dv = bv.get_data_var_at(variable)
  prev_dv = bv.get_previous_data_var_before(variable)

  dv_refs = list()
  dv_func_set = set()
    
  for ref in bv.get_code_refs(variable):
    dv_func_set.add(ref.function.start)
    llil = ref.function.get_low_level_il_at(ref.address)
    if llil:
      DEBUG("VariableAnalysis: {:x} - {:x} {}".format(variable, ref.address, llil.ssa_form))
      dv_refs.append(llil.ssa_form)

  for ins in dv_refs:
    if get_memory_version(bv, ins) is None:
      VARIABLE_ANALYSIS_SET[variable] = None
      return None
    
    if is_call(bv, ins):
      VARIABLE_ANALYSIS_SET[variable] = None
      return None
  
    if get_address(bv, ins) != variable:
      VARIABLE_ANALYSIS_SET[variable] = None
      return None

  prev_dv_refs = list()
  prev_dv_func_set = set()
  if prev_dv != None:
    for ref in bv.get_code_refs(prev_dv):
      prev_dv_func_set.add(ref.function.start)
      llil = ref.function.get_low_level_il_at(ref.address)
      prev_dv_refs.append(llil)

    for ins in prev_dv_refs: 
      if is_call(bv, ins) or is_address(bv, ins):
        VARIABLE_ANALYSIS_SET[variable] = None
        return None

    if is_subset(prev_dv_func_set, dv_func_set):
      VARIABLE_ANALYSIS_SET[variable] = None
      return None

  VARIABLE_ANALYSIS_SET[variable] = bv.address_size
  return bv.address_size

def analyse_variable_refs(bv, insn, variable):
  dv_refs = list()
  dv_func_set = set()
  dv = bv.get_data_var_at(variable)
  prev_dv = bv.get_previous_data_var_before(variable)
  
  for ref in bv.get_code_refs(variable):
    dv_func_set.add(ref.function.start)
    llil = ref.function.get_low_level_il_at(ref.address)
    if llil:
      DEBUG("AddressAnalysis: {:x} - {:x} {}".format(variable, ref.address, llil.ssa_form))
      dv_refs.append(llil.ssa_form)
  
  prev_dv_refs = list()
  prev_dv_func_set = set()
  if prev_dv != None:
    for ref in bv.get_code_refs(prev_dv):
      prev_dv_func_set.add(ref.function.start)
      llil = ref.function.get_low_level_il_at(ref.address)
      prev_dv_refs.append(llil)
      
    if is_subset(prev_dv_func_set, dv_func_set):
      return False
  
    for ins in dv_refs:
      if is_address(bv, ins) and \
        get_address(bv, ins) == variable:
        return True

  return False
  
def analyze_reference(bv, variable):
  dv_refs = list()
  dv_func_set = set()
  dv = bv.get_data_var_at(variable)
  prev_dv = bv.get_previous_data_var_before(variable)
  
  for ref in bv.get_code_refs(variable):
    dv_func_set.add(ref.function.start)
    llil = ref.function.get_low_level_il_at(ref.address)
    DEBUG("AddressAnalysis: {:x} - {:x} {}".format(variable, ref.address, llil.ssa_form))
    dv_refs.append(llil)
  
  prev_dv_refs = list()
  prev_dv_func_set = set()
  if prev_dv != None:
    for ref in bv.get_code_refs(prev_dv):
      prev_dv_func_set.add(ref.function.start)
      llil = ref.function.get_low_level_il_at(ref.address)
      prev_dv_refs.append(llil)
      
    if is_subset(prev_dv_func_set, dv_func_set):
      return None
  
    if len(prev_dv_refs) == 0:
      return prev_dv

  return variable
