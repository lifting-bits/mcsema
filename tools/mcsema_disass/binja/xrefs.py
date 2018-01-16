import binaryninja as binja
from binaryninja.enums import LowLevelILOperation
import logging

import CFG_pb2
import util

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

  def __init__(self, addr, reftype):
    self.addr = addr
    self.type = reftype

  @property
  def cfg_type(self):
    return self.TYPE_TO_CFG[self.type]

  def __repr__(self):
    return '<XREF: 0x{:x} {}>'.format(self.addr, CFG_pb2.CodeReference.OperandType.Name(self.cfg_type))


_NO_XREFS = tuple()

_IGNORED_XREF_OP_TYPES = (LowLevelILOperation.LLIL_JUMP,
                          LowLevelILOperation.LLIL_JUMP_TO,
                          LowLevelILOperation.LLIL_UNIMPL,
                          LowLevelILOperation.LLIL_UNIMPL_MEM)


_CONST_XREF_OP_TYPES = (LowLevelILOperation.LLIL_CONST,
                        LowLevelILOperation.LLIL_CONST_PTR)

_LOAD_STORE_OP_TYPES = (LowLevelILOperation.LLIL_LOAD,
                        LowLevelILOperation.LLIL_STORE)

def get_xrefs(bv, il, reftype=XRef.IMMEDIATE, parent=None):
  """ Recursively gather xrefs in an IL instruction

  Args:
    bv (binja.BinaryView)
    il (binja.LowLevelILInstruction)
    reftype

  Returns:
    tuple[XRef]
  """
  global _NO_XREFS, _IGNORED_XREF_OP_TYPES, _CONST_XREF_OF_TYPES
  global _LOAD_STORE_OP_TYPES

  if not isinstance(il, binja.LowLevelILInstruction):
    return _NO_XREFS

  refs = []

  # There's some other expression including this value
  # look at the disassembly to figure out if this is actually a displacement
  dis = bv.get_disassembly(il.address)

  # # ADRP instruction on AArch64.
  # if dis.startswith('adrp '):
  #   print hex(il.address), dis, il.dest


  # Update reftype using il information
  op = il.operation

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

  elif op in _CONST_XREF_OP_TYPES:
    # Hit a value, if this is a reference we can save the xref
    if util.is_valid_addr(bv, il.constant):
      # A displacement might be incorrectly classified as an immediate at this point
      if reftype == XRef.IMMEDIATE:  
        if '[' in dis and ']' in dis:
          # Fix the reftype depending on how this value is used
          if parent and parent.operation == LowLevelILOperation.LLIL_SET_REG:
            reftype = XRef.MEMORY
          else:
            reftype = XRef.DISPLACEMENT

      refs.append(XRef(il.constant, reftype))

  # Continue searching operands for xrefs
  for oper in il.operands:
    refs.extend(get_xrefs(bv, oper, reftype, il))

  return tuple(refs)
