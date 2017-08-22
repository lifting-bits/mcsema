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

import collections
import idaapi
import idautils
import idc
import itertools
import struct
import inspect

_DEBUG_FILE = None
_DEBUG_PREFIX = ""
_INFO = idaapi.get_inf_structure()


IS_ARM = "ARM" in _INFO.procName

# True if we are running on an ELF file.
IS_ELF = (idaapi.f_ELF == _INFO.filetype) or \
         (idc.GetLongPrm(idc.INF_FILETYPE) == idc.FT_ELF)

# True if this is a Windows PE file.
IS_PE = idaapi.f_PE == _INFO.filetype

if IS_ARM:
  from arm_util import *
else:
  from x86_util import *

def INIT_DEBUG_FILE(file):
  global _DEBUG_FILE
  _DEBUG_FILE = file

def DEBUG_PUSH():
  global _DEBUG_PREFIX
  _DEBUG_PREFIX += "  "

def DEBUG_POP():
  global _DEBUG_PREFIX
  _DEBUG_PREFIX = _DEBUG_PREFIX[:-2]

def DEBUG(s):
  global _DEBUG_FILE
  if _DEBUG_FILE:
    _DEBUG_FILE.write("{}{}\n".format(_DEBUG_PREFIX, str(s)))

# Python 2.7's xrange doesn't work with `long`s.
def xrange(begin, end=None, step=1):
  if end:
    return iter(itertools.count(begin, step).next, end)
  else:
    return iter(itertools.count().next, begin)

_NOT_INST_EAS = set()

# Returns `True` if `ea` belongs to some code segment.
#
# TODO(pag): This functon is extra aggressive, in that it doesn't strictly
#            trust the `idc.isCode`. I have observed cases where data in
#            `.bss` is treated as code and I am not sure why. Perhaps adding
#            a reference to the data did this.
#
#            I think it has something to do with ELF thunks, e.g. entries in
#            the `.plt` section. When I made this function stricter,
#            `mcsema-lift` would report issues where it needed to add tail-calls
#            to externals.
def is_code(ea):
  if is_invalid_ea(ea):
    return False

  seg_ea = idc.SegStart(ea)
  seg_type = idc.GetSegmentAttr(seg_ea, idc.SEGATTR_TYPE)
  return seg_type == idc.SEG_CODE

# Mark an address as containing code.
def try_mark_as_code(ea):
  return False

  if not is_code(ea):
    seg_ea = idc.SegStart(ea)
    if is_code(seg_ea):
      idc.MakeCode(ea)
      idaapi.autoWait()
      return True
  return False

def mark_as_not_code(ea):
  global _NOT_INST_EAS
  _NOT_INST_EAS.add(ea)

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

def instruction_personality(arg):
  global PERSONALITIES
  if isinstance(arg, (int, long)):
    arg, _ = decode_instruction(arg)
  p = PERSONALITIES[arg.itype]

  return fixup_personality(arg, p)

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

def is_invalid_ea(ea):
  """Returns `True` if `ea` is not valid, i.e. it doesn't point into any
  valid segment."""
  if idc.BADADDR == ea:
    return True

  try:
    idc.GetSegmentAttr(idc.SegStart(ea), idc.SEGATTR_TYPE)
    return False  # If we get here, then it must be a valid ea!
  except:
    return True

_BAD_INSTRUCTION = (None, "")

def decode_instruction(ea):
  """Read the bytes of an x86/amd64 instruction. This handles things like
  combining the bytes of an instruction with its prefix. IDA Pro sometimes
  treats these as separate."""
  global _NOT_INST_EAS, _BAD_INSTRUCTION, PREFIX_ITYPES

  if ea in _NOT_INST_EAS:
    return _BAD_INSTRUCTION

  decoded_inst = idautils.DecodeInstruction(ea)
  if not decoded_inst:
    _NOT_INST_EAS.add(ea)
    return _BAD_INSTRUCTION

  assert decoded_inst.ea == ea
  end_ea = ea + decoded_inst.size

  decoded_bytes = read_bytes_slowly(ea, end_ea)

  # We've got an instruction with a prefix, but the prefix is treated as
  # independent.
  if 1 == decoded_inst.size and decoded_inst.itype in PREFIX_ITYPES:
    decoded_inst, extra_bytes = decode_instruction(end_ea)
    decoded_bytes += extra_bytes

  return decoded_inst, decoded_bytes

_NOT_EXTERNAL_SEGMENTS = set([idc.BADADDR])
_EXTERNAL_SEGMENTS = set()

def is_external_segment_by_flags(ea):
  try:
    seg_ea = idc.SegStart(ea)
    seg_type = idc.GetSegmentAttr(seg_ea, idc.SEGATTR_TYPE)
    if seg_type == idc.SEG_XTRN:
      _EXTERNAL_SEGMENTS.add(seg_ea)
      return True
    else:
      return False
  except:
    return False

def is_external_segment(ea):
  """Returns `True` if the segment containing `ea` looks to be solely containing
  external references."""
  global _NOT_EXTERNAL_SEGMENTS

  seg_ea = idc.SegStart(ea)
  if seg_ea in _NOT_EXTERNAL_SEGMENTS:
    return False

  if seg_ea in _EXTERNAL_SEGMENTS:
    return True

  if is_external_segment_by_flags(ea):
    _EXTERNAL_SEGMENTS.add(seg_ea)
    return True

  ext_types = []
  seg_name = idc.SegName(seg_ea).lower()
  
  if IS_ELF:
    if ".got" in seg_name or ".plt" in seg_name:
      _EXTERNAL_SEGMENTS.add(seg_ea)
      return True

  elif IS_PE:
    if ".idata" == seg_name:  # Import table.
      _EXTERNAL_SEGMENTS.add(seg_ea)
      return True

  _NOT_EXTERNAL_SEGMENTS.add(seg_ea)
  return False

def is_internal_code(ea):
  if is_invalid_ea(ea):
    return False

  if is_external_segment(ea):
    return False
  
  if is_code(ea):
    return True

  # find stray 0x90 (NOP) bytes in .text that IDA 
  # thinks are data items.
  flags = idc.GetFlags(ea)
  if idaapi.isAlign(flags):
    if not try_mark_as_code(ea):
      return False
    return True

  return False

def is_block_or_instruction_head(ea):
  """Returns `True` if `ea` looks like it's the beginning of an actual
  instruction."""
  return is_internal_code(ea) and idc.ItemHead(ea) == ea

def get_address_size_in_bits():
  """Returns the available address size."""
  global _INFO
  if _INFO.is_64bit():
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

  if is_invalid_ea(min_ea) or not is_code(ea):
    return ea, ea

  # Get an upper bound using the next function.
  next_func_ea = idc.NextFunction(ea)
  if not is_invalid_ea(next_func_ea):
    max_ea = min(next_func_ea, max_ea)

  # Get a lower bound using the previous function.
  prev_func_ea = idc.PrevFunction(ea)
  if not is_invalid_ea(prev_func_ea):
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
  return 0 < flags and \
         (flags & idaapi.FUNC_NORET) and \
         "cxa_throw" not in get_symbol_name(ea)

def remove_all_refs(ea):
  """Remove all references to something."""
  assert False
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

_IGNORE_DREF = (lambda x: [idc.BADADDR])
_IGNORE_CREF = (lambda x, y: [idc.BADADDR])

def _reference_checker(ea, dref_finder=_IGNORE_DREF, cref_finder=_IGNORE_CREF):
  """Looks for references to/from `ea`, and does some sanity checks on what
  IDA returns."""
  for ref_ea in dref_finder(ea):
    if not is_invalid_ea(ref_ea):
      return True

  for ref_ea in cref_finder(ea, True):
    if not is_invalid_ea(ref_ea):
      return True

  for ref_ea in cref_finder(ea, False):
    if not is_invalid_ea(ref_ea):
      return True
      
  return False

def is_referenced(ea):
  """Returns `True` if the data at `ea` is referenced by something else."""
  return _reference_checker(ea, idautils.DataRefsTo, idautils.CodeRefsTo)

def is_referenced_by(ea, by_ea):
  for ref_ea in idautils.DataRefsTo(ea):
    if ref_ea == by_ea:
      return True

  for ref_ea in idautils.CodeRefsTo(ea, True):
    if ref_ea == by_ea:
      return True

  for ref_ea in idautils.CodeRefsTo(ea, False):
    if ref_ea == by_ea:
      return True

  return False

def is_runtime_external_data_reference(ea):
  """This can happen in ELF binaries, where you'll have somehting like
  `stdout@@GLIBC_2.2.5` in the `.bss` section, where at runtime the
  linker will fill in the slot with a pointer to the real `stdout`.

  IDA discovers this type of reference, but it has no real way to
  cross-reference it to anything, because the target address will
  only exist at runtime."""
  comment = idc.GetCommentEx(ea, 0)
  if comment and "Copy of shared data" in comment:
    return True
  else:
    return False

def is_reference(ea):
  """Returns `True` if the `ea` references something else."""
  if is_invalid_ea(ea):
    return False

  for target in idautils.XrefsFrom(ea):
    if ea == target.frm and not is_invalid_ea(target.to):
      return True

  return is_runtime_external_data_reference(ea)

def is_data_reference(ea):
  """Returns `True` if the `ea` references something else."""
  if is_invalid_ea(ea):
    return False

  for target_ea in idautils.DataRefsFrom(ea):
    if not is_invalid_ea(target_ea):
      return True

  return is_runtime_external_data_reference(ea)

def has_flow_to_code(ea):
  """Returns `True` if there are and control flows to the instruction at 
  `ea`."""
  return _reference_checker(ea, cref_finder=idautils.CodeRefsTo)

def get_reference_target(ea):
  for ref_ea in idautils.DataRefsFrom(ea):
    if not is_invalid_ea(ref_ea):
      return ref_ea

  for ref_ea in idautils.CodeRefsFrom(ea, True):
    if not is_invalid_ea(ref_ea):
      return ref_ea

  for ref_ea in idautils.CodeRefsFrom(ea, False):
    if not is_invalid_ea(ref_ea):
      return ref_ea

  # This is kind of funny, but it works with how we understand external
  # variable references from the CFG production and LLVM side. Really,
  # we need a unique location for every reference (internal and external).
  # For external references, the location itself is not super important, it's
  # used for identification in the LLVM side of things.
  #
  # When creating cross-references, we need that ability to identify the
  # "target" of the cross-reference, and again, that can be anything so long
  # as other parts of the code agree on the target.
  if is_runtime_external_data_reference(ea):
    return ea

  return idc.BADADDR

def is_head(ea):
  return idc.isHead(idc.GetFlags(ea))

# Make the data at `ea` into a head.
def make_head(ea):
  flags = idc.GetFlags(ea)
  if not idc.isHead(flags):
    idc.SetFlags(ea, flags | idc.FF_DATA)
    idaapi.autoWait()
    return is_head(ea)
  return True
