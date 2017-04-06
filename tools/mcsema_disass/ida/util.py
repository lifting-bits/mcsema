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

import collections
import idaapi
import idautils
import idc
import itertools
import struct

DEBUG = (lambda *args: None)

# Maps instruction EAs to a pair of decoded inst, and the bytes of the inst.
_INSTRUCTION_CACHE = {}

_PREFIX_ITYPES = (idaapi.NN_lock, idaapi.NN_rep,
                  idaapi.NN_repe, idaapi.NN_repne)

PERSONALITY_NORMAL = 0
PERSONALITY_DIRECT_JUMP = 1
PERSONALITY_INDIRECT_JUMP = 2
PERSONALITY_DIRECT_CALL = 3
PERSONALITY_INDIRECT_CALL = 4
PERSONALITY_RETURN = 5
PERSONALITY_SYSTEM_CALL = 6
PERSONALITY_SYSTEM_RETURN = 7
PERSONALITY_CONDITIONAL_BRANCH = 8
PERSONALITY_TERMINATOR = 9

_PERSONALITIES = collections.defaultdict(int)
_PERSONALITIES.update({
  idaapi.NN_call: PERSONALITY_DIRECT_CALL,
  idaapi.NN_callfi: PERSONALITY_INDIRECT_CALL,
  idaapi.NN_callni: PERSONALITY_INDIRECT_CALL,

  idaapi.NN_retf: PERSONALITY_RETURN,
  idaapi.NN_retfd: PERSONALITY_RETURN,
  idaapi.NN_retfq: PERSONALITY_RETURN,
  idaapi.NN_retfw: PERSONALITY_RETURN,
  idaapi.NN_retn: PERSONALITY_RETURN,
  idaapi.NN_retnd: PERSONALITY_RETURN,
  idaapi.NN_retnq: PERSONALITY_RETURN,
  idaapi.NN_retnw: PERSONALITY_RETURN,

  idaapi.NN_jmp: PERSONALITY_DIRECT_JUMP,
  idaapi.NN_jmpshort: PERSONALITY_DIRECT_JUMP,
  idaapi.NN_jmpfi: PERSONALITY_INDIRECT_JUMP,
  idaapi.NN_jmpni: PERSONALITY_INDIRECT_JUMP,

  idaapi.NN_int: PERSONALITY_SYSTEM_CALL,
  idaapi.NN_into: PERSONALITY_SYSTEM_CALL,
  idaapi.NN_int3: PERSONALITY_SYSTEM_CALL,
  idaapi.NN_bound: PERSONALITY_SYSTEM_CALL,
  idaapi.NN_syscall: PERSONALITY_SYSTEM_CALL,
  idaapi.NN_sysenter: PERSONALITY_SYSTEM_CALL,

  idaapi.NN_iretw: PERSONALITY_SYSTEM_RETURN,
  idaapi.NN_iret: PERSONALITY_SYSTEM_RETURN,
  idaapi.NN_iretd: PERSONALITY_SYSTEM_RETURN,
  idaapi.NN_iretq: PERSONALITY_SYSTEM_RETURN,
  idaapi.NN_sysret: PERSONALITY_SYSTEM_RETURN,
  idaapi.NN_sysexit: PERSONALITY_SYSTEM_RETURN,

  idaapi.NN_hlt: PERSONALITY_TERMINATOR,
  idaapi.NN_ud2: PERSONALITY_TERMINATOR,
  idaapi.NN_icebp: PERSONALITY_TERMINATOR,

  idaapi.NN_ja: PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_jae: PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_jb: PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_jbe: PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_jc: PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_jcxz: PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_je: PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_jecxz: PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_jg: PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_jge: PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_jl: PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_jle: PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_jna: PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_jnae: PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_jnb: PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_jnbe: PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_jnc: PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_jne: PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_jng: PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_jnge: PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_jnl: PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_jnle: PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_jno: PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_jnp: PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_jns: PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_jnz: PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_jo: PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_jp: PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_jpe: PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_jpo: PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_jrcxz: PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_js: PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_jz: PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_xbegin: PERSONALITY_CONDITIONAL_BRANCH,

  idaapi.NN_loopw: PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_loop: PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_loopd: PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_loopq: PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_loopwe: PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_loope: PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_loopde: PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_loopqe: PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_loopwne: PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_loopne: PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_loopdne: PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.NN_loopqne: PERSONALITY_CONDITIONAL_BRANCH,
})


# Python 2.7's xrange doesn't work with `long`s.
def xrange(begin, end=None, step=1):
  if end:
    return iter(itertools.count(begin, step).next, end)
  else:
    return iter(itertools.count().next, begin)

def instruction_personality(arg):
  if isinstance(arg, (int, long)):
    arg, _ = decode_instruction(arg)
  return _PERSONALITIES[arg.itype]

def is_conditional_jump(arg):
  return instruction_personality(arg) == PERSONALITY_CONDITIONAL_BRANCH

def is_unconditional_jump(arg):
  return instruction_personality(arg) in (PERSONALITY_DIRECT_JUMP, PERSONALITY_INDIRECT_JUMP)

def is_direct_jump(arg):
  return instruction_personality(arg) == PERSONALITY_DIRECT_JUMP

def is_indirect_jump(arg):
  return instruction_personality(arg) == PERSONALITY_INDIRECT_JUMP

def is_function_call(arg):
  return instruction_personality(arg) in (PERSONALITY_DIRECT_CALL, PERSONALITY_INDIRECT_CALL)

def is_direct_function_call(arg):
  return instruction_personality(arg) == PERSONALITY_DIRECT_CALL

def is_return(arg):
  return instruction_personality(arg) == PERSONALITY_RETURN

def is_control_flow(arg):
  return instruction_personality(arg) != PERSONALITY_NORMAL

def instruction_ends_block(arg):
  return instruction_personality(arg) in (PERSONALITY_CONDITIONAL_BRANCH,
                                          PERSONALITY_DIRECT_JUMP,
                                          PERSONALITY_INDIRECT_JUMP,
                                          PERSONALITY_RETURN,
                                          PERSONALITY_TERMINATOR,
                                          PERSONALITY_SYSTEM_RETURN) 

_NOT_CODE_EAS = set()

# Returns `True` if `ea` belongs to some code segment.
def is_code(ea):
  global _NOT_CODE_EAS
  return ea not in _NOT_CODE_EAS and idc.isCode(idc.GetFlags(ea))

# Mark an address as containing code.
def mark_as_code(ea):
  if not is_code(ea):
    idc.MakeCode(ea)
    idaapi.autoWait()

def mark_as_not_code(ea):
  global _NOT_CODE_EAS, _INSTRUCTION_CACHE

  if ea in _INSTRUCTION_CACHE:
    del _INSTRUCTION_CACHE[ea]

  _NOT_CODE_EAS.add(ea)

def read_bytes_slowly(start, end):
  bytestr = ""
  for i in xrange(start, end):
    if idc.hasValue(idc.GetFlags(i)):
      bt = idc.Byte(i)
      bytestr += chr(bt)
    else:
      #virtual size may be bigger than size on disk
      #pad with nulls
      #DEBUG("Failed on {0:x}".format(i))
      bytestr += "\x00"
  return bytestr

def read_byte(ea):
  byte = read_bytes_slowly(ea, ea + 1)
  byte = ord(byte) 
  return byte

def read_dword(ea):
  bytestr = read_bytes_slowly(ea, ea + 4)
  dword = struct.unpack("<L", bytestr)[0]
  return dword

def read_qword(ea):
  bytestr = read_bytes_slowly(ea, ea + 8)
  qword = struct.unpack("<Q", bytestr)[0]
  return qword

_BAD_INSTRUCTION = (None, "")

def decode_instruction(ea):
  """Read the bytes of an x86/amd64 instruction. This handles things like
  combining the bytes of an instruction with its prefix. IDA Pro sometimes
  treats these as separate."""
  global _INSTRUCTION_CACHE, _NOT_CODE_EAS, _BAD_INSTRUCTION, _PREFIX_ITYPES

  if ea in _NOT_CODE_EAS:
    return _BAD_INSTRUCTION

  if ea in _INSTRUCTION_CACHE:
    return _INSTRUCTION_CACHE[ea]

  decoded_inst = idautils.DecodeInstruction(ea)
  if not decoded_inst:
    _INSTRUCTION_CACHE[ea] = _BAD_INSTRUCTION
    return _BAD_INSTRUCTION

  assert decoded_inst.ea == ea
  end_ea = ea + decoded_inst.size

  decoded_bytes = read_bytes_slowly(ea, end_ea)

  # We've got an instruction with a prefix, but the prefix is treated as
  # independent.
  if 1 == decoded_inst.size and decoded_inst.itype in _PREFIX_ITYPES:
    decoded_inst, extra_bytes = decode_instruction(end_ea)
    decoded_bytes += extra_bytes

  _INSTRUCTION_CACHE[ea] = (decoded_inst, decoded_bytes)
  return decoded_inst, decoded_bytes

_NOT_EXTERNAL_SEGMENTS = set([idc.BADADDR])
_EXTERNAL_SEGMENTS = set()

def is_external_segment(ea):
  """Returns `True` if the segment containing `ea` looks to be solely containing
  external references."""
  global _NOT_EXTERNAL_SEGMENTS

  base_ea = idc.SegStart(ea)
  if base_ea in _NOT_EXTERNAL_SEGMENTS:
    return False

  if base_ea in _EXTERNAL_SEGMENTS:
    return True

  ext_types = []
  seg_name = idc.SegName(base_ea).lower()
  if ".got" in seg_name or ".plt" in seg_name:
    _EXTERNAL_SEGMENTS.add(base_ea)
    return True

  segtype = idc.GetSegmentAttr(base_ea, idc.SEGATTR_TYPE)
  if segtype == idc.SEG_XTRN:
    _EXTERNAL_SEGMENTS.add(base_ea)
    return True

  _NOT_EXTERNAL_SEGMENTS.add(base_ea)
  return False

def is_internal_code(ea):
  if is_external_segment(ea):
    return False
  
  if is_code(ea):
    return True

  # find stray 0x90 (NOP) bytes in .text that IDA 
  # thinks are data items
  if read_byte(ea) == 0x90:
    seg = idc.SegStart(ea)
    segtype = idc.GetSegmentAttr(seg, idc.SEGATTR_TYPE)
    if segtype == idc.SEG_CODE:
      mark_as_code(ea)
      return True

  return False

def is_block_or_instruction_head(ea):
  """Returns `True` if `ea` looks like it's the beginning of an actual
  instruction."""
  global _INSTRUCTION_CACHE
  if ea in _INSTRUCTION_CACHE:
    return True
  return is_internal_code(ea) and idc.ItemHead(ea) == ea

def get_address_size_in_bits():
  """Returns the available address size."""
  if (idaapi.ph.flag & idaapi.PR_USE64) != 0:
    return 64
  else:
    return 32

def get_address_size_in_bytes():
  return get_address_size_in_bits() / 8

# Tries to get the name of a symbol.
def get_symbol_name(from_ea, ea=None, allow_dummy=False):
  if ea is None:
    ea = from_ea

  flags = idc.GetFlags(ea)
  if not allow_dummy and idaapi.has_dummy_name(flags):
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

def get_function_bounds(ea):
  """Get the bounds of the function containing `ea`. We want to discover jump
  table targets that are missed by IDA, and it's possible that they aren't
  marked as being part of the current function, and perhaps are after the
  assumed range of the current function. Ideally they will fall before the
  beginning of the next function, though.

  We need to be pretty careful with the case that one function tail-calls
  another. IDA will sometimes treat the end of the tail-called function
  (e.g. a thunk) as if it is the end of the caller. For this reason, we start
  with loose bounds using the prev/next functions, then try to narrow with
  the bounds of the function containing `ea`.

  TODO(pag): Handle discontinuous regions (e.g. because of function chunks).
             It may be worth to return an object here that can we queried
             for membership using the `__in__` method.
  """
  seg_start, seg_end = idc.SegStart(ea), idc.SegEnd(ea)
  min_ea = seg_start
  max_ea = seg_end

  if idc.BADADDR == min_ea or not is_code(ea):
    return ea, ea

  # Get an upper bound using the next function.
  next_func_ea = idc.NextFunction(ea)
  if next_func_ea != idc.BADADDR:
    max_ea = min(next_func_ea, max_ea)

  # Get a lower bound using the previous function.
  prev_func_ea = idc.PrevFunction(ea)
  if prev_func_ea != idc.BADADDR:
    min_ea = max(min_ea, prev_func_ea)
    prev_func = idaapi.get_func(prev_func_ea)
    if prev_func and prev_func.endEA < ea:
      min_ea = max(min_ea, prev_func.endEA)

  # Try to tighten the bounds using the function containing `ea`.
  func = idaapi.get_func(ea)
  if func:
    min_ea = max(min_ea, func.startEA)
    max_ea = min(max_ea, func.endEA)

  return min_ea, max_ea

def is_noreturn_function(ea):
  """Returns `True` if the function at `ea` is a no-return function."""
  flags = idc.GetFunctionFlags(ea)
  return 0 < flags and (flags & idaapi.FUNC_NORET)

def remove_all_refs(ea):
  """Remove all references to something."""
  dref_eas = list(idautils.DataRefsFrom(ea))
  cref_eas0 = list(idautils.CodeRefsFrom(ea, False))
  cref_eas1 = list(idautils.CodeRefsFrom(ea, True))

  for ref_ea in dref_eas:
    idaapi.del_dref(ea, ref_ea)

  for ref_ea in cref_eas0:
    idaapi.del_cref(ea, ref_ea, False)

  for ref_ea in cref_eas1:
    idaapi.del_cref(ea, ref_ea, True)

def is_thunk(ea):
  """Returns true if some address is a known to IDA to be a thunk."""
  flags = idc.GetFunctionFlags(ea)
  return 0 < flags and 0 != (flags & idaapi.FUNC_THUNK)

_IDA_WEIRD_BAD_REF = 0xff00000000000000
_IGNORE_DREF = (lambda x: [_IDA_WEIRD_BAD_REF])
_IGNORE_CREF = (lambda x, y: [_IDA_WEIRD_BAD_REF])

def _reference_checker(ea, dref_finder=_IGNORE_DREF, cref_finder=_IGNORE_CREF):
  """Looks for references to/from `ea`, and does some sanity checks on what
  IDA returns."""
  global _IDA_WEIRD_BAD_REF
  for ref in dref_finder(ea):
    if ref == idc.BADADDR or ref >= _IDA_WEIRD_BAD_REF:
      continue
    return True

  for ref in cref_finder(ea, True):
    if ref == idc.BADADDR or ref >= _IDA_WEIRD_BAD_REF:
      continue
    return True

  for ref in cref_finder(ea, False):
    if ref == idc.BADADDR or ref >= _IDA_WEIRD_BAD_REF:
      continue
    return True

  return False

def is_referenced(ea):
  """Returns `True` if the data at `ea` is referenced by something else."""
  return _reference_checker(ea, idautils.DataRefsTo, idautils.CodeRefsTo)

def is_reference(ea):
  """Returns `True` if the `ea` references something else."""
  return _reference_checker(ea, idautils.DataRefsFrom, idautils.CodeRefsFrom)

def has_flow_to_code(ea):
  """Returns `True` if there are and control flows to the instruction at 
  `ea`."""
  return _reference_checker(ea, cref_finder=idautils.CodeRefsTo)

def get_reference_target(ea):
  global _IDA_WEIRD_BAD_REF
  for ref in idautils.DataRefsFrom(ea):
    if ref == idc.BADADDR or ref >= _IDA_WEIRD_BAD_REF:
      continue
    return ref

  for ref in idautils.CodeRefsFrom(ea, True):
    if ref == idc.BADADDR or ref >= _IDA_WEIRD_BAD_REF:
      continue
    return ref

  for ref in idautils.CodeRefsFrom(ea, False):
    if ref == idc.BADADDR or ref >= _IDA_WEIRD_BAD_REF:
      continue
    return ref

  return idc.BADADDR