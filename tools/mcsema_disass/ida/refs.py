# Copyright (c) 2017, Trail of Bits
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
# Redistributions of source code must retain the above copyright notice, this
# list of conditions and the following disclaimer.
#
# Redistributions in binary form must reproduce the above copyright notice, this
# list of conditions and the following disclaimer in the documentation and/or
# other materials provided with the distribution.
#
# Neither the name of Trail of Bits nor the names of its
# contributors may be used to endorse or promote products derived from
# this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
# ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from util import *

class Reference(object):
  __slots__ = ('offset', 'addr', 'symbol', 'type')

  INVALID = 0
  IMMEDIATE = 1
  DISPLACEMENT = 2
  MEMORY = 3
  CODE = 4

  TYPE_TO_STR = {
    INVALID: "(null)",
    IMMEDIATE: "imm",
    DISPLACEMENT: "disp",
    MEMORY: "mem",
    CODE: "code",
  }

  def __init__(self, addr, offset):
    self.offset = offset
    self.addr = addr
    self.symbol = ""
    self.type = self.INVALID

  def __str__(self):
    return "({} {} {})".format(
      is_code(self.addr) and "code" or "data",
      self.TYPE_TO_STR[self.type],
      self.symbol or "0x{:x}".format(self.addr))

# Tries to get the name of a symbol.
def get_symbol_name(from_ea, ea=None):
  if ea is None:
    ea = from_ea

  flags = idc.GetFlags(ea)
  if idaapi.has_dummy_name(flags):
    return ""

  name = ""
  try:
    name = name or idc.GetTrueNameEx(from_ea, ea)
  except:
    pass

  try:
    name = name or idc.GetFunctionName(ea)
  except:
    pass

  return name

# Try to recognize an operand as a reference candidate when a target fixup
# is not available.
def _get_ref_candidate(op, all_refs):
  ref = None
  if idc.o_imm == op.type:
    if op.value in all_refs:
      ref = Reference(op.value, op.offb)
      return ref

  elif op.type in (idc.o_displ, idc.o_mem, idc.o_near):
    if op.addr in all_refs:
      ref = Reference(op.addr, op.offb)
      return ref

  return ref

_REFS = {}

def memop_is_actually_displacement(I):
  """IDA will unhelpfully decode something like `jmp ds:off_48A5F0[rax*8]`
  and tell us that this is an `o_mem` rather than an `o_displ`. We really want
  to recognize it as an `o_displ` because the memory reference is a displacement
  and not an absolute address."""
  asm = idc.GetDisasm(I.ea)
  return "[" in asm and ("+" in asm or "*" in asm)

# Get a list of references from an instruction.
def get_instruction_references(arg, binary_is_pie=False):
  I = arg
  if isinstance(arg, (int, long)):
    I, _ = decode_instruction(arg)

  if I.ea in _REFS:
    return _REFS[I.ea]

  offset_to_ref = {}
  all_refs = set()
  for ea in xrange(I.ea, I.ea + I.size):
    targ = idc.GetFixupTgtOff(ea)
    if targ != idc.BADADDR and targ != -1:
      all_refs.add(targ)
      ref = Reference(targ, ea - I.ea)
      offset_to_ref[ref.offset] = ref

  all_refs.update(long(x) for x in idautils.DataRefsFrom(I.ea))
  all_refs.update(long(x) for x in idautils.CodeRefsFrom(I.ea, 0))
  all_refs.update(long(x) for x in idautils.CodeRefsFrom(I.ea, 1))

  refs = []
  for i, op in enumerate(I.Operands):
    if not op.type:
      continue

    op_ea = I.ea + op.offb
    if op.offb in offset_to_ref:
      ref = offset_to_ref[op.offb]
    else:
      ref = _get_ref_candidate(op, all_refs)

    if not ref:
      continue

    # Immediate constant, may be the absolute address of a data reference.
    if idc.o_imm == op.type:
      seg_begin = idaapi.getseg(ref.addr)
      seg_end = idaapi.getseg(ref.addr + idc.ItemSize(ref.addr) - 1)

      # If the immediate constant is not within a segment, or crosses
      # two segments then don't treat it as a reference.
      if not seg_begin or not seg_end or seg_begin.startEA != seg_end.startEA:
        idaapi.del_dref(op_ea, op.value)
        idaapi.del_cref(op_ea, op.value, False)
        continue

      # If this is a PIE-mode, 64-bit binary, then most likely the immediate
      # operand is not a data ref. 
      if seg_begin.use64() and binary_is_pie:
        idaapi.del_dref(op_ea, op.value)
        idaapi.del_cref(op_ea, op.value, False)
        continue

      ref.type = Reference.IMMEDIATE
      ref.symbol = get_symbol_name(op_ea, ref.addr)

    # Displacement within a memory operand, excluding PC-relative
    # displacements when those are memory references.
    elif idc.o_displ == op.type:
      assert ref.addr == op.addr
      ref.type = Reference.DISPLACEMENT
      ref.symbol = get_symbol_name(op_ea, ref.addr)

    # Absolute memory reference, and PC-relative memory reference. These
    # are references that IDA can recognize statically.
    elif idc.o_mem == op.type:
      assert ref.addr == op.addr
      if memop_is_actually_displacement(I):
        ref.type = Reference.DISPLACEMENT
      else:
        ref.type = Reference.MEMORY
      ref.symbol = get_symbol_name(op_ea, ref.addr)

    # Code reference.
    elif idc.o_near == op.type:
      assert ref.addr == op.addr
      ref.type = Reference.CODE
      ref.symbol = get_symbol_name(op_ea, ref.addr)

    refs.append(ref)

  for ref in refs:
    assert ref.addr != idc.BADADDR
  
  _REFS[I.ea] = refs

  return refs
