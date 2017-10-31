#!/usr/bin/env python

# Copyright (c) 2017 Trail of Bits, Inc.
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

import idautils
import idaapi
import idc
import sys
import os
import argparse
import struct
import traceback
import collections
import itertools
import pprint

# Bring in utility libraries.
from util import *
from table import *
from flow import *
from refs import *
from segment import *

OPND_WRITE_FLAGS = {
  0: idaapi.CF_CHG1,
  1: idaapi.CF_CHG2,
  2: idaapi.CF_CHG3,
  3: idaapi.CF_CHG4,
  4: idaapi.CF_CHG5,
  5: idaapi.CF_CHG6,
}

OPND_READ_FLAGS = {
  0: idaapi.CF_USE1,
  1: idaapi.CF_USE2,
  2: idaapi.CF_USE3,
  3: idaapi.CF_USE4,
  4: idaapi.CF_USE5,
  5: idaapi.CF_USE6,
}

OPND_DTYPE_STR = {
  0:'dt_byte',
  1:'dt_word',
  2:'dt_dword',
  3:'dt_float',
  4:'dt_double',
  5:'dt_tbyte',
  6:'dt_packreal',
  7:'dt_qword',
  8:'dt_byte16',
  9:'dt_code',
  10:'dt_void',
  11:'dt_fword',
  12:'dt_bitfild',
  13:'dt_string',
  14:'dt_unicode',
  15:'dt_3byte',
  16:'dt_ldbl',
  17:'dt_byte32',
  18:'dt_byte64'
}

OPND_DTYPE_TO_SIZE = {
  idaapi.dt_byte: 1,
  idaapi.dt_word: 2,
  idaapi.dt_dword: 4,
  idaapi.dt_float: 4,
  idaapi.dt_double: 8,
  idaapi.dt_qword: 8,
  idaapi.dt_byte16: 16,
  idaapi.dt_fword: 6,
  idaapi.dt_3byte: 3,
  idaapi.dt_byte32: 32,
  idaapi.dt_byte64: 64,
}

def get_native_size():
  info = idaapi.get_inf_structure()
  if info.is_64bit():
    return 8
  elif info.is_32bit():
    return 4
  else:
    return 2
    
def get_register_name(reg_id, size=None):
  if size is None:
    size = get_native_size()
  return idaapi.get_reg_name(reg_id, size)

def get_register_info(reg_name):
  ri = idaapi.reg_info_t()
  success = idaapi.parse_reg_name(reg_name, ri)
  return ri

class Operand(object):
  def __init__(self, opnd, ea, insn, write, read):
    self._operand = opnd
    self._ea = ea
    self._read = read
    self._write= write
    self._insn = insn
    self._type = opnd.type
    self._index_id = None
    self._base_id = None
    self._displ = None
    self._scale = None
        
    if self._type in (idaapi.o_displ, idaapi.o_phrase):
      specflag1 = self.op_t.specflag1
      specflag2 = self.op_t.specflag2
      scale = 1 << ((specflag2 & 0xC0) >> 6)
      offset = self.op_t.addr
            
      if specflag1 == 0:
        index = None
        base_ = self.op_t.reg
      elif specflag1 == 1:
        index = (specflag2 & 0x38) >> 3
        base_ = (specflag2 & 0x07) >> 0
                
        if self.op_t.reg == 0xC:
          if base_ & 4:
            base_ += 8
          if index & 4:
            index += 8
                        
      self._scale = scale
      self._index_id = index
      self._base_id = base_
      self._displ = offset
               
  def _get_datatype_size(dtype):
    return OPND_DTYPE_TO_SIZE.get(dtype,0)
            
  def _get_datatypestr_from_dtyp(dt_dtyp):
    return OPND_DTYPE_STR.get(dt_dtyp,"")
    
  @property
  def op_t(self):
    return self._operand
    
  @property
  def value(self):
    return idc.GetOperandValue(self._ea, self.index)
    
  @property
  def size(self):
    return _get_datatype_size(self._operand.dtyp)
    
  @property
  def text(self):
    return idc.GetOpnd(self._ea, self.index)
    
  @property
  def dtype(self):
    return _get_datatypestr_from_dtyp(self._operand.dtyp)
        
  @property
  def index(self):
    return self._operand.n
    
  @property
  def type(self):
    return self._type
    
  @property
  def is_read(self):
    return self._read
    
  @property
  def is_write(self):
    return self._write
    
  @property
  def is_void(self):
    return self._type == idaapi.o_void
    
  @property
  def is_reg(self):
    return self._type ==  idaapi.o_reg
    
  @property
  def is_mem(self):
    return self._type == idaapi.o_mem 
    
  @property
  def is_phrase(self):
    return self._type == idaapi.o_phrase
    
  @property
  def is_displ(self):
    return self._type == idaapi.o_displ

  @property
  def is_imm(self):
    return self._type == idaapi.o_imm

  @property
  def is_far(self):
    return self._type == idaapi.o_far

  @property
  def is_near(self):
    return self._type == idaapi.o_near

  @property
  def is_special(self):
    return self._type >= idaapi.o_idpspec0
    
  @property
  def has_phrase(self):
    return self._type in (idaapi.o_phrase, idaapi.o_displ)
    
  @property
  def reg_id(self):
    """ID of the register used in the operand."""
    return self._operand.reg
    
  @property
  def reg(self):
    """Name of the register used in the operand."""
    if self.has_phrase:
      size = get_native_size()
    return get_register_name(self.reg_id, size)

    if self.type.is_reg:
      return get_register_name(self.reg_id, self.size)

  @property
  def regs(self):
    if self.has_phrase:
      return set(reg for reg in (self.base, self.index) if reg)
    elif self.type.is_reg:
      return {get_register_name(self.reg_id, self.size)}
    else:
      return set()
    
  @property
  def base_reg(self):
    if self._base_id is None:
      return None
    return get_register_name(self._base_id)
    
  @property
  def index_reg(self):
    if self._index_id is None:
      return None
    return get_register_name(self._index_id)
    
  @property
  def scale(self):
    return self._scale
    
  @property
  def displ(self):
    return self._displ
    
    
class Instruction(object):
  '''
    Instruction objects
  '''
  def __init__(self, ea):
    self._ea = ea
    self._insn, _ = decode_instruction(ea)
    self._operands = self._make_operands()
        
  def _is_operand_write_to(self, index):
    return (self.feature & OPND_WRITE_FLAGS[index])
    
  def _is_operand_read_from(self, index):
    return (self.feature & OPND_READ_FLAGS[index])
    
  def _make_operands(self):
    operands = []
    for index, opnd in enumerate(self._insn.Operands):
      if opnd.type == idaapi.o_void:
        break
      operands.append(Operand(opnd,
                              self._ea,
                              insn=self._insn,
                              write=self._is_operand_write_to(index),
                              read=self._is_operand_read_from(index))) 
            
    return operands

  @property
  def feature(self):
    return self._insn.get_canon_feature()
    
  @property
  def opearnds(self):
    return self._operands
    
  @property
  def mnemonic(self):
    return self._insn.get_canon_mnem()
    
    


def _signed_from_unsigned64(val):
  if val & 0x8000000000000000:
    return -0x10000000000000000 + val
  return val

def _signed_from_unsigned32(val):
  if val & 0x80000000:
    return -0x100000000 + val
  return val

def _mark_function_args_ms64(referers, dereferences, func_var_data):
  for reg in ["rcx", "rdx", "r8", "r9"]:
    _mark_func_arg(reg, referers, dereferences, func_var_data)

def _mark_function_args_sysv64(referers, dereferences, func_var_data):
  for reg in ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]:
    _mark_func_arg(reg, referers, dereferences, func_var_data)

def _mark_function_args_x86(referers, dereferences, func_var_data):
  pass #TODO. urgh.

def _translate_reg_32(reg):
  return reg

def _translate_reg_64(reg):
  return {"edi":"rdi",
          "esi":"rsi",
          "eax":"rax",
          "ebx":"rbx",
          "ecx":"rcx",
          "edx":"rdx",
          "ebp":"rbp",
          "esp":"rsp"}.get(reg, reg)

if idaapi.get_inf_structure().is_64bit():
  _signed_from_unsigned = _signed_from_unsigned64
  _base_ptr = "rbp"
  _stack_ptr = "rsp"
  _trashed_regs = ["rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"]
  _mark_args = _mark_function_args_sysv64
  _translate_reg = _translate_reg_64
elif idaapi.get_inf_structure().is_32bit():
  _signed_from_unsigned = _signed_from_unsigned32
  _base_ptr = "ebp"
  _stack_ptr = "esp"
  _trashed_regs = ["eax", "ecx", "edx"]
  _mark_args = _mark_function_args_x86
  _translate_reg = _translate_reg_32

_base_ptr_format = "[{}+".format(_base_ptr)
_stack_ptr_format = "[{}+".format(_stack_ptr)

def floor_key(d, key):
  L1 = list(k for k in d if k <= key)
  if len(L1):
    return max(L1)

def _get_flags_from_bits(flag):
  '''
  Translates the flag field in structures (and elsewhere?) into a human readable
  string that is compatible with pasting into IDA or something.
  Returns an empty string if supplied with -1.
  '''
  if -1 == flag:
    return ""

  cls = {
    'MASK':1536,
    1536:'FF_CODE',
    1024:'FF_DATA',
    512:'FF_TAIL',
    0:'FF_UNK',
  }

  comm = {
    'MASK':1046528,
    2048:'FF_COMM',
    4096:'FF_REF',
    8192:'FF_LINE',
    16384:'FF_NAME',
    32768:'FF_LABL',
    65536:'FF_FLOW',
    524288:'FF_VAR',
    49152:'FF_ANYNAME',
  }

  _0type = {
    'MASK':15728640,
    1048576:'FF_0NUMH',
    2097152:'FF_0NUMD',
    3145728:'FF_0CHAR',
    4194304:'FF_0SEG',
    5242880:'FF_0OFF',
    6291456:'FF_0NUMB',
    7340032:'FF_0NUMO',
    8388608:'FF_0ENUM',
    9437184:'FF_0FOP',
    10485760:'FF_0STRO',
    11534336:'FF_0STK',
  }
  _1type = {
    'MASK':251658240,
    16777216:'FF_1NUMH',
    33554432:'FF_1NUMD',
    50331648:'FF_1CHAR',
    67108864:'FF_1SEG',
    83886080:'FF_1OFF',
    100663296:'FF_1NUMB',
    117440512:'FF_1NUMO',
    134217728:'FF_1ENUM',
    150994944:'FF_1FOP',
    167772160:'FF_1STRO',
    184549376:'FF_1STK',
  }
  datatype = {
    'MASK':4026531840,
    0:'FF_BYTE',
    268435456:'FF_WORD',
    536870912:'FF_DWRD',
    805306368:'FF_QWRD',
    1073741824:'FF_TBYT',
    1342177280:'FF_ASCI',
    1610612736:'FF_STRU',
    1879048192:'FF_OWRD',
    2147483648:'FF_FLOAT',
    2415919104:'FF_DOUBLE',
    2684354560:'FF_PACKREAL',
    2952790016:'FF_ALIGN',
  }

  flags = set()
  flags.add(cls[cls['MASK']&flag])

  for category in [comm, _0type, _1type, datatype]:
    #the ida docs define, for example, a FF_0VOID = 0 constant in with the rest
    #  of the 0type constants, but I _think_ that just means
    #  the field is unused, rather than being specific data
    val = category.get(category['MASK']&flag, None)
    if val:
      flags.add(val)
  return flags

def _process_lea_instruction(inst_ea, func_variable):
  insn = Instruction(inst_ea)
  for opnd in insn.opearnds:
    if opnd.has_phrase:
      DEBUG("Operand is Phrase {}".format(opnd.text))
      base_ = _translate_reg(opnd.base_reg) if opnd.base_reg else None
      index_ = _translate_reg(opnd.index_reg) if opnd.index_reg else None
      offset = _signed_from_unsigned(idc.GetOperandValue(inst_ea, opnd.index))
      if len(func_variable["stackArgs"].keys()) == 0:
        return
    
      target_on_stack = base_ if base_ == _stack_ptr or base_ == _base_ptr else None
      if target_on_stack == _base_ptr:
        start_ = floor_key(func_variable["stackArgs"].keys(), offset)
        func_variable["stackArgs"].pop(start_, None)
  
def _process_instruction(inst_ea, func_variable):
  insn = Instruction(inst_ea)
  for opnd in insn.opearnds:
    if opnd.has_phrase:
      DEBUG("Operand is Phrase {}".format(opnd.text))
      base_ = _translate_reg(opnd.base_reg) if opnd.base_reg else None
      index_ = _translate_reg(opnd.index_reg) if opnd.index_reg else None
      offset = _signed_from_unsigned(idc.GetOperandValue(inst_ea, opnd.index))
      if len(func_variable["stackArgs"].keys()) == 0:
        return
    
      if opnd.is_write:
        target_on_stack = base_ if base_ == _stack_ptr or base_ == _base_ptr else None
        if target_on_stack == _base_ptr:
          DEBUG("Operand is write base {0}, index {1}, offset {2} {3}".format(base_, index_, offset, func_variable["stackArgs"].keys()))
          start_ = floor_key(func_variable["stackArgs"].keys(), offset)
          if start_:
            end_ = start_ + func_variable["stackArgs"][start_]["size"]
            DEBUG("Start {0}, end {1}, keys {2}".format(start_, end_, func_variable["stackArgs"].keys()))
            if offset in range(start_, end_):
              var_offset = offset - start_
              func_variable["stackArgs"][start_]["writes"].append({"ea" :inst_ea, "offset" :var_offset})
              func_variable["stackArgs"][start_]["safe"] = True
        else:
          for key in func_variable["stackArgs"].keys():
            if func_variable["stackArgs"][key]["name"] in opnd.text:
              func_variable["stackArgs"][key]["safe"] = False
              func_variable["stackArgs"].pop(key, None)
              break
            
      elif opnd.is_read:
        read_on_stack = base_ if base_ == _stack_ptr or base_ == _base_ptr else None
        if read_on_stack == _base_ptr:
          DEBUG("Operand is read base {0}, index {1}, offset {2}".format(base_, index_, offset)) 
          start_ = floor_key(func_variable["stackArgs"].keys(), offset)
          if start_:
            end_ = start_ + func_variable["stackArgs"][start_]["size"]
            DEBUG("Start {0}, end {1}, keys {2}".format(start_, end_, func_variable["stackArgs"].keys()))
            if offset in range(start_, end_):
              var_offset = offset - start_
              func_variable["stackArgs"][start_]["reads"].append({"ea" :inst_ea, "offset" :var_offset})
              func_variable["stackArgs"][start_]["safe"] = True
        else:
          for key in func_variable["stackArgs"].keys():
            if func_variable["stackArgs"][key]["name"] in opnd.text:
              func_variable["stackArgs"][key]["safe"] = False
              func_variable["stackArgs"].pop(key, None)
              break
      else:
        read_on_stack = base_ if base_ == _stack_ptr or base_ == _base_ptr else None
        if read_on_stack:
          DEBUG("Operand is write base referent {0}, index {1}, offset {2:x}".format(base_, index_, offset))
          start_ = floor_key(func_variable["stackArgs"].keys(), offset)
          if start_:
            end_ = start_ + func_variable["stackArgs"][start_]["size"]
            if offset in range(start_, end_):
              var_offset = offset - start_
              func_variable["stackArgs"][start_]["flags"].add("LOCAL_REFERER")
              func_variable["stackArgs"][start_]["referent"].append({"ea" :inst_ea, "offset" :var_offset})

  
def _process_basic_block(f_ea, block_ea, func_variable):

  inst_eas, succ_eas = analyse_block(f_ea, block_ea, True)
  for inst_ea in inst_eas:
    _funcs = {"lea":_process_lea_instruction
              }
    func = _funcs.get(idc.GetMnem(inst_ea), None)
    if func:
      func(inst_ea, func_variable)
    else:
      _process_instruction(inst_ea, func_variable)


RECOVER_DEBUG_FL = [
    # stack variable tick and times_per_thread is causing
    # problem while lifting Apache ATD's;
    "status_handler" 
    ]

def build_stack_args(f):
  stackArgs = dict()
  name = idc.Name(f)
  end = idc.GetFunctionAttr(f, idc.FUNCATTR_END)
  _locals = idc.GetFunctionAttr(f, idc.FUNCATTR_FRSIZE)
  _uses_bp = 0 != (idc.GetFunctionFlags(f) & idc.FUNC_FRAME)
  frame = idc.GetFrame(f)
  if frame is None:
    return stackArgs

  func_type = idc.GetType(f)
  if (func_type is not None) and ("(" in func_type):
    args = func_type[ func_type.index('(')+1: func_type.rindex(')') ]
    args_list = [ x.strip() for x in args.split(',')]
    if "..." in args_list:
      return stackArgs

  if name in RECOVER_DEBUG_FL:
    return stackArgs

  #grab the offset of the stored frame pointer, so that
  #we can correlate offsets correctly in referent code
  # e.g., EBP+(-0x4) will match up to the -0x4 offset
  delta = idc.GetMemberOffset(frame, " s")
  if -1 == delta:
    #indicates that it wasn't found. Unsure exactly what to do
    # in that case, punting for now
    delta = 0

  offset = idc.GetFirstMember(frame)
  while -1 != _signed_from_unsigned(offset):
    memberName = idc.GetMemberName(frame, offset)
    if memberName is None:
      # gaps in stack usage are fine, but generate trash output
      # gaps also could indicate a buffer that IDA doesn't recognize
      offset = idc.GetStrucNextOff(frame, offset)
      continue
    if (memberName == " r" or memberName == " s"):
      #the return pointer and start pointer, who cares
      offset = idc.GetStrucNextOff(frame, offset)
      continue
    memberSize = idc.GetMemberSize(frame, offset)
    if offset >= delta:
      offset = idc.GetStrucNextOff(frame, offset)
      continue
    memberFlag = idc.GetMemberFlag(frame, offset)
    #TODO: handle the case where a struct is encountered (FF_STRU flag)
    flag_str = _get_flags_from_bits(memberFlag)
    stackArgs[offset-delta] = {"name":memberName,
                               "size":memberSize,
                               "flags":flag_str,
                               "writes":list(),
                               "referent":list(),
                               "reads":list(),
                               "safe": False}
    offset = idc.GetStrucNextOff(frame, offset)

  return stackArgs

def collect_function_vars(f, blockset):
  stackArgs = dict()
  name = idc.Name(f)
  start = idc.GetFunctionAttr(f, idc.FUNCATTR_START)
  end = idc.GetFunctionAttr(f, idc.FUNCATTR_END)
  _locals = idc.GetFunctionAttr(f, idc.FUNCATTR_FRSIZE)
  _uses_bp = 0 != (idc.GetFunctionFlags(f) & idc.FUNC_FRAME)
  
  DEBUG_PUSH()
  stackArgs = build_stack_args(f)
  processed_blocks = set()
  while len(blockset) > 0:
    block_ea = blockset.pop()
    if block_ea in processed_blocks:
      DEBUG("ERROR: Attempting to add same block twice: {0:x}".format(block_ea))
      continue

    processed_blocks.add(block_ea)
    _process_basic_block(f, block_ea, {"name":name, "stackArgs": stackArgs, "uses_bp":_uses_bp})

  DEBUG_POP()
  
  return stackArgs
