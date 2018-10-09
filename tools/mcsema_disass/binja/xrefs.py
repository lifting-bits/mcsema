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

import binaryninja as binja
from binaryninja.enums import LowLevelILOperation
import logging

import CFG_pb2
import util
from debug import *

log = logging.getLogger(util.LOGNAME)


class XRef(object):
  IMMEDIATE = 0
  MEMORY = 1
  DISPLACEMENT = 2
  CONTROLFLOW = 3

  TYPE_TO_CFG = {
    IMMEDIATE  : CFG_pb2.CodeReference.ImmediateOperand,
    MEMORY     : CFG_pb2.CodeReference.MemoryOperand,
    DISPLACEMENT : CFG_pb2.CodeReference.MemoryDisplacementOperand,
    CONTROLFLOW  : CFG_pb2.CodeReference.ControlFlowOperand
  }

  def __init__(self, addr, reftype, mask=0):
    self.addr = addr
    self.type = reftype
    self.mask = mask

  @property
  def cfg_type(self):
    return self.TYPE_TO_CFG[self.type]

  def __repr__(self):
    return '<XREF: 0x{:x} {}>'.format(self.addr, CFG_pb2.CodeReference.OperandType.Name(self.cfg_type))

  def __eq__(self, other):
    if not isinstance(other, XRef):
      return NotImplemented
    return self.addr == other.addr and \
         self.type == other.type

  def __hash__(self):
    return hash((self.addr, self.type))

_NO_XREFS = set()

_IGNORED_XREF_OP_TYPES = (LowLevelILOperation.LLIL_JUMP,
                          LowLevelILOperation.LLIL_JUMP_TO,
                          LowLevelILOperation.LLIL_UNIMPL,
                          LowLevelILOperation.LLIL_UNIMPL_MEM)


_CONST_XREF_OP_TYPES = [LowLevelILOperation.LLIL_CONST_PTR]

_LOAD_STORE_OP_TYPES = (LowLevelILOperation.LLIL_LOAD,
                        LowLevelILOperation.LLIL_STORE)

_CONST_OR_CONST_PTR_TYPES = (binja.RegisterValueType.ConstantValue,
                             binja.RegisterValueType.ConstantPointerValue)

_AARCH64_ADRP_XREFS = {}

def _get_aarch64_partial_xref(bv, func, il, dis):
  """" Figure out the final destination referenced by an ADRP+ADD instruction
  combination on AArch64."""

  if func.arch.name != 'aarch64':
    return None

  if il.address in _AARCH64_ADRP_XREFS:
    return _AARCH64_ADRP_XREFS[il.address]

  if not dis.startswith('adrp '):
    return None

  next_address = il.address + bv.get_instruction_length(il.address)
  next_dis = bv.get_disassembly(next_address)
  if not next_dis.startswith('add '):
    return None

  next_il = func.get_low_level_il_at(next_address)
  value = next_il.get_reg_value_after(next_il.dest)

  if value.type not in _CONST_OR_CONST_PTR_TYPES:
    return None

  _AARCH64_ADRP_XREFS[il.address] = XRef(value.value, XRef.DISPLACEMENT, mask=-4096L)
  _AARCH64_ADRP_XREFS[next_address] = XRef(value.value, XRef.IMMEDIATE, mask=4095)

  return _AARCH64_ADRP_XREFS[il.address]


def get_xrefs(bv, func, il):
  global _LAST_UNUSED_REFS

  refs = set()
  dis = bv.get_disassembly(il.address)

  # TODO(pag): This is an ugly hack for the ADRP instruction on AArch64.
  ref = _get_aarch64_partial_xref(bv, func, il, dis)
  if ref is not None:
    refs.add(ref)
  else:
    reftype = XRef.IMMEDIATE

    # PC-relative displacement for AArch64's `adr` instruction.
    if func.arch.name == 'aarch64' and dis.startswith('adr '):
      reftype = XRef.DISPLACEMENT

    _fill_xrefs_internal(bv, il, refs, reftype)

    # TODO(pag): Another ugly hack to deal with a specific flavor of jump
    #            table that McSema doesn't handle very well. The specific form
    #            is:
    #
    #    .text:00000000004009AC ADRP            X1, #asc_400E5C@PAGE ; "\b"
    #    .text:00000000004009B0 ADD             X1, X1, #asc_400E5C@PAGEOFF ; "\b"
    #    .text:00000000004009B4 LDR             W0, [X1,W0,UXTW#2]
    #    .text:00000000004009B8 ADR             X1, loc_4009C4   <-- point to a block
    #    .text:00000000004009BC ADD             X0, X1, W0,SXTW#2
    #    .text:00000000004009C0 BR              X0
    #
    #            We don't have good ways of referencing basic blocks, so if we
    #            left the reference from `4009B8` to `4009C4`, then that would
    #            be computed in terms of the location in memory of the copied
    #            `.text` segment in the lifted binary.
    #
    #            We could handle this via a jump-offset table with offset of
    #            `4009B8`, but we don't yet support this variant of jump table
    #            in jmptable.py.
    if dis.startswith('adr ') and len(refs):
      ref = refs.pop()
      if util.is_code(bv, ref.addr) and not bv.get_function_at(ref.addr):
        DEBUG("WARNING: Omitting reference to non-function code address {:x}".format(ref.addr))
      else:
        refs.add(ref)  # Add it back in.

  return refs


def _fill_xrefs_internal(bv, il, refs, reftype=XRef.IMMEDIATE, parent=None):
  """ Recursively gather xrefs in an IL instruction

  Args:
    bv (binja.BinaryView)
    il (binja.LowLevelILInstruction)
    reftype (int)
    parent (binja.LowLevelILInstruction)

  Returns:
    set[XRef]
  """
  global _NO_XREFS, _IGNORED_XREF_OP_TYPES, _CONST_XREF_OF_TYPES
  global _LOAD_STORE_OP_TYPES

  if not isinstance(il, binja.LowLevelILInstruction):
    return _NO_XREFS

  # Update reftype using il information
  op = il.operation

  # Detect a tail call target
  # This is the only instance where a LLIL_JUMP is considered
  if util.is_jump_tail_call(bv, il):
    target = util.get_jump_tail_call_target(bv, il)
    DEBUG('Tail call from {:x} to {:x}'.format(il.address, target.start))
    return _fill_xrefs_internal(bv, il.dest, refs, XRef.CONTROLFLOW, il)

  # Some instruction types are ignored
  if op in _IGNORED_XREF_OP_TYPES:
    return _NO_XREFS

  elif op == LowLevelILOperation.LLIL_CALL:
    # Any xref in here will be a control flow target
    reftype = XRef.CONTROLFLOW

  elif op in _LOAD_STORE_OP_TYPES:

    # Choose the correct operand to look at
    mem_il = il.src if op == LowLevelILOperation.LLIL_LOAD else il.dest

    # Loading from memory
    # Check if we're using a displacement in this
    if mem_il.operation in _CONST_XREF_OP_TYPES:
      # No displacement
      reftype = XRef.MEMORY
    else:
      reftype = XRef.DISPLACEMENT

    # In a load/store, only the operand that references memory gets the new reftype
    # The other operand(s) start at the default (immediate) again
    _fill_xrefs_internal(bv, mem_il, refs, reftype, il)
    for oper in il.operands:
      if oper != mem_il:
        _fill_xrefs_internal(bv, oper, refs)

  elif op in _CONST_XREF_OP_TYPES:
    # Hit a value, if this is a reference we can save the xref
    if util.is_valid_addr(bv, il.constant):
      # A displacement might be incorrectly classified as an immediate at this point
      if reftype == XRef.IMMEDIATE and parent is not None:
        # There's some other expression including this value
        # look at the disassembly to figure out if this is actually a displacement
        dis = bv.get_disassembly(il.address)
        if '[' in dis and ']' in dis:
          # Fix the reftype depending on how this value is used
          if parent.operation == LowLevelILOperation.LLIL_SET_REG:
            reftype = XRef.MEMORY
          else:
            reftype = XRef.DISPLACEMENT

      refs.add(XRef(il.constant, reftype))

  # Continue searching operands for xrefs
  for oper in il.operands:
    _fill_xrefs_internal(bv, oper, refs, reftype, il)
