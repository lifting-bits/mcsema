# Copyright (c) 2019s Trail of Bits, Inc.
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

from enum import Enum

import binaryninja as bn
from binaryninja.enums import LowLevelILOperation

from functions import RECOVERED, TO_RECOVER
from jmptable import JMP_TABLES
from cfg import RECOVER_OPTS
import CFG_pb2
import util
import log

_BYTE_WIDTH_NAME = {4: "dword", 8: "qword"}

_NO_XREFS = set()

_IGNORED_XREF_OP_TYPES = (LowLevelILOperation.LLIL_JUMP,
                          LowLevelILOperation.LLIL_JUMP_TO,
                          LowLevelILOperation.LLIL_UNIMPL)


_CONST_OR_CONST_PTR_TYPES = (bn.RegisterValueType.ConstantValue,
                             bn.RegisterValueType.ConstantPointerValue)

_AARCH64_ADRP_XREFS = {}


class XRef(object):
  class Type(Enum):
    IMMEDIATE = 0
    MEMORY = 1
    DISPLACEMENT = 2
    CONTROLFLOW = 3

    def type_to_cfg(typ):
      return {
        XRef.Type.IMMEDIATE: CFG_pb2.CodeReference.ImmediateOperand,
        XRef.Type.MEMORY: CFG_pb2.CodeReference.MemoryOperand,
        XRef.Type.DISPLACEMENT: CFG_pb2.CodeReference.MemoryDisplacementOperand,
        XRef.Type.CONTROLFLOW: CFG_pb2.CodeReference.ControlFlowOperand
      }[typ]

  def __init__(self, addr, reftype, mask=0):
    self.addr = addr
    self.type = reftype
    self.mask = mask

  @property
  def cfg_type(self):
    return XRef.Type.type_to_cfg(self.type)

  def __repr__(self):
    return '<XREF: 0x{:x} {}>'.format(self.addr, CFG_pb2.CodeReference.OperandType.Name(self.cfg_type))

  def __eq__(self, other):
    if not isinstance(other, XRef):
      return NotImplemented
    return self.addr == other.addr and \
        self.type == other.type

  def __hash__(self):
    return hash((self.addr, self.type))


def cfg_to_name(cfg):
  return {
    CFG_pb2.CodeReference.ImmediateOperand: "imm",
    CFG_pb2.CodeReference.MemoryOperand: "mem",
    CFG_pb2.CodeReference.MemoryDisplacementOperand: "disp",
    CFG_pb2.CodeReference.ControlFlowOperand: "flow",
    CFG_pb2.CodeReference.OffsetTable: "ofst",
  }[cfg]


def add_xref(bv, pb_inst, target, mask, optype):
  xref = pb_inst.xrefs.add()
  xref.ea = target
  xref.operand_type = optype

  debug_mask = ""
  if mask:
    xref.mask = mask
    debug_mask = " & {:x}".format(mask)

  sym_name = util.find_symbol_name(bv, target)
  if len(sym_name) > 0:
    xref.name = sym_name

  if util.is_code(bv, target):
    xref.target_type = CFG_pb2.CodeReference.CodeTarget
    debug_type = "code"
  else:
    xref.target_type = CFG_pb2.CodeReference.DataTarget
    debug_type = "data"

  if util.is_external_ref(bv, target):
    xref.location = CFG_pb2.CodeReference.External
    debug_loc = "external"
  else:
    xref.location = CFG_pb2.CodeReference.Internal
    debug_loc = "internal"

  if RECOVER_OPTS["manual_recursive_descent"]:
    if bv.get_function_at(target) is not None:
      if target not in RECOVERED:
        TO_RECOVER.put(target)

  debug_op = cfg_to_name(optype)

  return "({} {} {} {:x}{} {})".format(
      debug_type, debug_op, debug_loc, target, debug_mask, sym_name)


def get_xrefs(bv, func, all_il, address):
  # Aarch64 has addition checks surrounding normal xrefs stuff...bypass that for non-Aarch64 binaries
  if func.arch.name == 'aarch64':
    return _get_aarch64_xrefs(bv, func, all_il, address)

  return _get_xrefs(bv, all_il, address)


def _get_xrefs(bv, all_il, address, reftype=XRef.Type.IMMEDIATE):
  """ Gathers xrefs in a Lifted IL instruction

  Args:
    bv (bn.BinaryView)
    il (bn.LowLevelILInstruction)
    reftype (XRef.Type)

  Returns:
    set[XRef]
  """
  global _NO_XREFS, _IGNORED_XREF_OP_TYPES

  refs = set()

  if not util.xref_in_all_il(all_il):
    return refs

  # Detect a tail call target
  # This is the only instance where a LLIL_JUMP is considered
  if util.is_jump_tail_call(bv, all_il):
    target = util.get_jump_tail_call_target(bv, all_il)
    if target is not None:
      log.debug('Tail call from {:x} to {:x}'.format(address, target.start))
      refs.add(XRef(target.start, XRef.Type.CONTROLFLOW))
      return refs

  for il in all_il:
    if util.xref_in_il(il):
      _get_xref_for_lifted_il(bv, il, refs, reftype)

  return refs


def _get_xref_for_lifted_il(bv, lifted_il, refs, reftype, parent=None):
  """ Recursively gather xrefs in an IL instruction

  Args:
    bv (bn.BinaryView)
    il (bn.LowLevelILInstruction)
    reftype (int)
    parent (bn.LowLevelILInstruction)

  Returns:
    set[XRef]
  """

  # Update reftype using il information
  try:
    op = lifted_il.operation
  except:
    return

  if op == LowLevelILOperation.LLIL_CALL:
    # Any xref in here will be a control flow target
    reftype = XRef.Type.CONTROLFLOW

  elif op is LowLevelILOperation.LLIL_LOAD or op is LowLevelILOperation.LLIL_STORE:
    # Choose the correct operand to look at
    mem_il = lifted_il.src if op == LowLevelILOperation.LLIL_LOAD else lifted_il.dest

    # Loading from memory
    # Check if we're using a displacement in this
    if mem_il.operation is LowLevelILOperation.LLIL_CONST_PTR:
      # No displacement
      reftype = XRef.Type.MEMORY
    else:
      reftype = XRef.Type.DISPLACEMENT

    # In a load/store, only the operand that references memory gets the new reftype
    # The other operand(s) start at the default (immediate) again
    _get_xref_for_lifted_il(bv, mem_il, refs, reftype, lifted_il)
    for oper in lifted_il.operands:
      if oper != mem_il:
        _get_xref_for_lifted_il(bv, oper, refs, reftype, lifted_il)

  elif op is LowLevelILOperation.LLIL_CONST_PTR:
    # Hit a value, if this is a reference we can save the xref
    if util.is_valid_addr(bv, lifted_il.constant):
      # A displacement might be incorrectly classified as an immediate at this point
      if reftype == XRef.Type.IMMEDIATE and parent is not None:
        # Fix the reftype depending on how this value is used
        if parent.operation == LowLevelILOperation.LLIL_ADD:
          reftype = XRef.Type.DISPLACEMENT
        else:
          reftype = XRef.Type.MEMORY

      refs.add(XRef(lifted_il.constant, reftype))

  # Recurse through the entire instruction tree
  for oper in lifted_il.operands:
    _get_xref_for_lifted_il(bv, oper, refs, reftype, lifted_il)


def _get_aarch64_xrefs(bv, func, il, address):
  refs = set()
  dis = bv.get_disassembly(il.address)

  # TODO(pag): This is an ugly hack for the ADRP instruction on AArch64.
  if _resolve_aarch64_adrp_xref(bv, func, il, dis, refs):
    return refs

  # Assume it's an immediate unless there's a PC-relative displacement (`adr` instruction).
  reftype = XRef.Type.IMMEDIATE
  if dis.startswith('adr '):
    reftype = XRef.Type.DISPLACEMENT

  refs = _get_xrefs(bv, il, address, reftype)

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
      log.debug("WARNING: Omitting reference to non-function code address {:x}".format(ref.addr))
    else:
      refs.add(ref)  # Add it back in.

  return refs


def _resolve_aarch64_adrp_xref(bv, func, il, dis, refs):
  """" Figure out the final destination referenced by an ADRP+ADD instruction
  combination on AArch64."""

  if il.address in _AARCH64_ADRP_XREFS:
    refs.add(_AARCH64_ADRP_XREFS[il.address])
    return True

  if not dis.startswith('adrp '):
    return False

  next_address = il.address + bv.get_instruction_length(il.address)
  next_dis = bv.get_disassembly(next_address)
  if not next_dis.startswith('add '):
    return False

  next_il = func.get_low_level_il_at(next_address)
  value = next_il.get_reg_value_after(next_il.dest)

  if value.type not in _CONST_OR_CONST_PTR_TYPES:
    return False

  _AARCH64_ADRP_XREFS[il.address] = XRef(value.value, XRef.Type.DISPLACEMENT, mask=-4096L)
  _AARCH64_ADRP_XREFS[next_address] = XRef(value.value, XRef.Type.IMMEDIATE, mask=4095)

  refs.add(_AARCH64_ADRP_XREFS[il.address])
  return True


def recover_section_cross_references(bv, pb_seg, real_sect, sect_start, sect_end):
  """ Find references to other code/data in this section

  Args:
    bv (bn.BinaryView)
    pb_seg (CFG_pb2.Segment)
    real_sect (bn.binaryview.Section)
    sect_start (int)
    sect_end (int)
  """
  entry_width = util.clamp(real_sect.align, 4, bv.address_size)
  read_val = {4: util.read_dword,
              8: util.read_qword}[entry_width]

  log.debug("Recovering references in [{:x}, {:x}) of section {}".format(
      sect_start, sect_end, real_sect.name))

  log.push()
  for addr in xrange(sect_start, sect_end, entry_width):
    xref = read_val(bv, addr)

    if not util.is_valid_addr(bv, xref):
      continue

    # Skip this xref if it's a jmp table entry
    if any(xref in tbl.targets for tbl in JMP_TABLES):
      continue

    width_name = _BYTE_WIDTH_NAME.get(entry_width, "{}-byte".format(entry_width))
    log.debug("Adding {} reference from {:x} to {:x}".format(width_name, addr, xref))

    pb_ref = pb_seg.xrefs.add()
    pb_ref.ea = addr
    pb_ref.width = entry_width
    pb_ref.target_ea = xref
    pb_ref.target_name = util.find_symbol_name(bv, xref)
    pb_ref.target_is_code = util.is_code(bv, xref)

    if util.is_tls_section(bv, addr):
      pb_ref.target_fixup_kind = CFG_pb2.DataReference.OffsetFromThreadBase
    else:
      pb_ref.target_fixup_kind = CFG_pb2.DataReference.Absolute

  log.pop()
