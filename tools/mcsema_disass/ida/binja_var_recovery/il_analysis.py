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

LOPS = LowLevelILOperation
MOPS = MediumLevelILOperation

VariableSet = set()

class Value(object):
  def __init__(self, bv, addr, base = None):
    self.bv = bv
    self.address = addr
    self._has_xrefs = has_xrefs(bv, addr)
    self._base = base if base else addr

  @property
  def base_address(self):
    return self._base

  @property
  def size(self):
    if self.address > self._base:
      return self.address - self._base
    else:
      return self._base - self.address

  def __str__(self):
    return "<{:x} - {:x}>".format(self.address, self._base)

  def __repr__(self):
    return "<{:x} - {:x}>".format(self.address, self._base)

  def __sub__(self, other):
    if self._has_xrefs:
      return Value(self.bv, self.address - other.address, self._base)
    else:
      return Value(self.bv, self.address - other.address, other._base)

  def __add__(self, other):
    if self._has_xrefs:
      return Value(self.bv, self.address + other.address, self._base)
    else:
      return Value(self.bv, self.address + other.address, other._base)

  def __lshift__(self, other):
    if isinstance(other, Value):
      return Value(self.bv, self.address << other.address, self._base)
    else:
      return self
  
  def __rshift__(self, other):
    if isinstance(other, Value):
      return Value(self.bv, self.address >> other.address, self._base)
    else:
      return self

  def __hash__(self):
    return hash(self.__repr__())

  def __eq__(self, other):
    if isinstance(self, Value):
      return (self.__repr__() == other.__repr__())
    else:
      return False

  def __ne__(self, other):
    return not self.__eq__(self)

class SymbolicValue(Value):
  def __init__(self, bv, sym_value, offset=0):
    super(SymbolicValue, self).__init__(bv, 0)
    self.sym_value = sym_value
    self.offset = offset

  @property
  def base_address(self):
    return 0

  @property
  def size(self):
    return 0

  def __str__(self):
    return "<{}, {}>".format(self.sym_value, self.offset)

  def __repr__(self):
    return "<{} {}>".format(self.sym_value, self.offset)

  def __add__(self, other):
    if isinstance(other, Value):
      return SymbolicValue(self.bv, self.sym_value,  self.offset + other.address)
    else:
      return SymbolicValue(self.bv, self.sym_value  + " + " + other.sym_value, other.offset)

  def __sub__(self, other):
    if isinstance(other, Value):
      return SymbolicValue(self.bv, self.sym_value,  self.offset - other.address)
    else:
      return SymbolicValue(self.bv, self.sym_value + " - " + other.sym_value, other.offset)

  def __lshift__(self, other):
    if isinstance(other, Value):
      return SymbolicValue(self.bv, self.sym_value + " << " + "{}".format(hex(other.address)), self.offset)
    else:
      return self

  def __rshift__(self, other):
    if isinstance(other, Value):
      return SymbolicValue(self.bv, self.sym_value + " >> " + "{}".format(hex(other.address)), self.offset)
    else:
      return self

  def __hash__(self):
    return hash(self.__repr__())

  def __eq__(self, other):
    if isinstance(self, SymbolicValue):
      return (self.__repr__() == other.__repr__())
    else:
      return False

  def __ne__(self, other):
    return not self.__eq__(self)

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
  if is_llil(bv, insn):
    return insn.operation == LOPS.LLIL_CALL or \
      insn.operation == LOPS.LLIL_CALL_STACK_ADJUST or \
      insn.operation == LOPS.LLIL_CALL_SSA
  return False

def is_load(bv, insn):
  return insn.operation == LOPS.LLIL_LOAD_SSA or \
    insn.operation == LOPS.LLIL_LOAD
    
def is_store(bv, insn):
  return insn.operation == LOPS.LLIL_STORE_SSA or \
    insn.operation == LOPS.LLIL_STORE
    
def is_constant(bv, insn):
  """ Check if the operand is constant"""
  if is_mlil(bv, insn):
    return insn.operation == MOPS.MLIL_CONST or \
      insn.operation == MOPS.MLIL_CONST_PTR
  elif is_llil(bv, insn):
    return insn.operation == LOPS.LLIL_CONST or \
      insn.operation == LOPS.LLIL_CONST_PTR

def ssa_reg_name(ssa_reg):
  return "{}#{}".format(ssa_reg.reg, ssa_reg.version)

def global_reg_name(func, ssa_reg):
  return "{}_{}".format(func.name, ssa_reg_name(ssa_reg))

def get_constant(bv, insn):
  """ Get the constant value of the operand """
  return insn.constant
      
def is_register(bv, insn):
  if is_mlil(bv, insn):
    return insn.operation == MOPS.MLIL_REG or \
      insn.operation == MOPS.MLIL_REG_SSA
  elif is_llil(bv, insn):
    return insn.operation == LOPS.LLIL_REG or \
      insn.operation == LOPS.LLIL_REG_SSA
    
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

def call_params(bv, insn):
  if is_llil(bv, insn):
    for op in insn.operands:
      if op.operation == LOPS.LLIL_CALL_PARAM:
        return op.src
  return None

def get_call_params(bv, insn):
  for pparam in call_params(bv, insn):
    yield pparam

def get_call_output(bv, insn):
  if is_llil(bv, insn):
    for op in insn.operands:
      if op.operation == LOPS.LLIL_CALL_OUTPUT_SSA:
        for reg in op.dest:
          yield reg

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

def is_arith_op(bv, insn):
  postfix = insn.postfix_operands
  DEBUG("insn {} ->postfix {}".format(insn, postfix))

def get_exec_sections(bv):
  for k in bv.sections:
    v = bv.sections[k]
    if bv.is_offset_executable(v.start):
      yield v

def dw(bv, addr, end):
  if end - addr < 4:
    return None
  return struct.unpack('<L', bv.read(addr, 4))[0]

def qw(bv, addr, end):
  if end - addr < 8:
    return None
  return struct.unpack('<Q', bv.read(addr, 8))[0]

def dw_data(data, offset, length):
  if length - offset < 4:
    return None
  return struct.unpack('<L', data[offset:offset+4])[0]

def qw_data(data, offset, length):
  if length - offset < 8:
    return None
  return struct.unpack('<Q', data[offset:offset+8])[0]

def search_riprel_data(addr, start, data):
  datalen = len(data)
  x64 = 0
  offset = 0

  while offset < datalen:
    cur_addr = start + offset
    opcode = data[offset]

    # 5 byte instruction
    operand_idx = offset + 1
    opend = start + operand_idx + 4
    reladdr = (addr - opend) & 0xffffffff

    if (reladdr == dw_data(data, operand_idx, datalen)
      and (opcode == '\xe8' or opcode == '\xe9')
      and reladdr != 0):
      yield cur_addr

    # 6 byte instruction
    operand_idx = offset + 2
    opend = start + operand_idx + 4
    reladdr = (addr - opend) & 0xffffffff

    if (reladdr == dw_data(data, operand_idx, datalen)
      and offset != x64
      and data[offset+1] != '\xe8'
      and data[offset+1] != '\xe9'
      and reladdr != 0):
      yield cur_addr

    # 7 byte instruction
    operand_idx = offset + 3
    opend = start + operand_idx + 4
    reladdr = (addr - opend) & 0xffffffff

    if (reladdr == dw_data(data, operand_idx, datalen)
      and data[offset] == '\x48'
      and reladdr != 0):
      # 64 bit register
      x64 = offset + 1
      yield cur_addr

    # 10 byte instruction
    operand_idx = offset + 2
    opend = start + operand_idx + 8
    reladdr = (addr - opend) & 0xffffffff

    if (addr == qw_data(data, operand_idx, datalen)
      and data[offset] == '\x48'
      and ord(data[offset+1])&0xF8 == 0xb8):
      # 64 bit register
      x64 = offset + 1
      yield cur_addr

    offset += 1

def xrefs(bv, addr):
  for s in get_exec_sections(bv):
    length = s.end - s.start
    data = bv.read(s.start, length)

    for x in search_riprel_data(addr, s.start, data):
      yield(x)

def find_xrefs(bv, addr):
  DEBUG("[-] searching for reference to {:08X}".format(addr))
  refs = []

  for x in xrefs(bv, addr):
    refs.append(x)
    DEBUG("xrefs {:x}".format(x))

  if (len(refs) == 0):
    DEBUG("could not find references to {:08X}".format(addr))
  return refs

def has_xrefs(bv, addr):
  code_xrefs = bv.get_code_refs(addr)
  data_xrefs = bv.get_data_refs(addr)
  if len(code_xrefs) or len(data_xrefs):
    return True
  return False

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

def has_memory_xrefs(bv, addr):
  if addr in VariableSet:
    return True

  if not is_data_variable_section(bv, addr):
      return False

  # if there is any reference to data section return false
  # Not handling such cases
  for ref in bv.get_data_refs(addr):
    return False

  dv_refs = list()
  dv_func_set = set()
  dv = bv.get_data_var_at(addr)
  prev_dv = bv.get_previous_data_var_before(addr)

  for ref in bv.get_code_refs(addr):
    dv_func_set.add(ref.function.start)
    llil = ref.function.get_low_level_il_at(ref.address)
    if llil:
      DEBUG("VariableAnalysis: {:x} - {:x} {}".format(addr, ref.address, llil.ssa_form))
      dv_refs.append(llil.ssa_form)

  for ins in dv_refs:
    if get_memory_version(bv, ins) is None:
      return False
    
    if is_call(bv, ins):
      return False
  
    if get_address(bv, ins) != addr:
      return False

  prev_dv_refs = list()
  prev_dv_func_set = set()
  if prev_dv != None:
    for ref in bv.get_code_refs(prev_dv):
      prev_dv_func_set.add(ref.function.start)
      llil = ref.function.get_low_level_il_at(ref.address)
      prev_dv_refs.append(llil)

    for ins in prev_dv_refs: 
      if ins and (is_call(bv, ins) or is_address(bv, ins)):
        return False

    if is_subset(prev_dv_func_set, dv_func_set):
      return False

  VariableSet.add(addr)
  return True

def has_address_xrefs(bv, insn, addr):
  if addr in VariableSet:
    return True

  if not is_data_variable_section(bv, addr):
    return False

  # if there is any reference to data section return True
  # Assuming this will be the start address of the synbol
  for ref in bv.get_data_refs(addr):
    VariableSet.add(addr)
    return True

  dv_refs = list()
  dv_func_set = set()
  dv = bv.get_data_var_at(addr)
  prev_dv = bv.get_previous_data_var_before(addr)
  
  for ref in bv.get_code_refs(addr):
    dv_func_set.add(ref.function.start)
    llil = ref.function.get_low_level_il_at(ref.address)
    if llil:
      DEBUG("AddressAnalysis: {:x} - {:x} {}".format(addr, ref.address, llil.ssa_form))
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
        get_address(bv, ins) == addr:
        VariableSet.add(addr)
        return True

  return False