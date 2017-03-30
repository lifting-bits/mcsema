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



# Returns `True` if `ea` belongs to some code segment.
def is_code(ea):
  return idc.isCode(idc.GetFlags(ea))

# Mark an address as containing code.
def mark_as_code(ea):
  if not is_code(ea):
    idc.MakeCode(ea)
    idaapi.autoWait()

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


def decode_instruction(ea):
  """Read the bytes of an x86/amd64 instruction. This handles things like
  combining the bytes of an instruction with its prefix. IDA Pro sometimes
  treats these as separate."""
  global _INSTRUCTION_CACHE
  if ea in _INSTRUCTION_CACHE:
    return _INSTRUCTION_CACHE[ea]

  global _PREFIX_ITYPES

  decoded_inst = idautils.DecodeInstruction(ea)
  if not decoded_inst:
    _INSTRUCTION_CACHE[ea] = (None, "")
    return (None, "")

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

# def instruction_is_referenced(ea):
#   """Returns `True` if it appears that there's a non-fall-through reference
#   to the instruction at `ea`."""
#   global POSSIBLE_CODE_REFS
#   if len(tuple(idautils.CodeRefsTo(ea, False))):
#     return True
#   if len(tuple(idautils.DataRefsTo(ea))):
#     return True
#   return ea in POSSIBLE_CODE_REFS

def is_internal_code(ea):
  pf = idc.GetFlags(ea)
  if idc.isCode(pf) and not idc.isData(pf):
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

def is_external_segment(ea):
  """Returns `True` if the segment containing `ea` looks to be solely containing
  external references."""
  ext_types = []
  seg_name = idc.SegName(ea).lower()
  if ".got" in seg_name or ".plt" in seg_name:
    return True

  seg = idc.SegStart(ea)
  if seg == idc.BADADDR:
    DEBUG("WARNING: Could not get segment addr for: {0:x}".format(ea))
    return False

  segtype = idc.GetSegmentAttr(seg, idc.SEGATTR_TYPE)
  if segtype == idc.SEG_XTRN:
    return True

  return False

def get_address_size_in_bits():
  """Returns the available address size."""
  if (idaapi.ph.flag & idaapi.PR_USE64) != 0:
    return 64
  else:
    return 32


def get_address_size_in_bytes():
  return get_address_size_in_bits() / 8