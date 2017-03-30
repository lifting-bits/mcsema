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

# def instruction_is_referenced(ea):
#   """Returns `True` if it appears that there's a non-fall-through reference
#   to the instruction at `ea`."""
#   global POSSIBLE_CODE_REFS
#   if len(tuple(idautils.CodeRefsTo(ea, False))):
#     return True
#   if len(tuple(idautils.DataRefsTo(ea))):
#     return True
#   return ea in POSSIBLE_CODE_REFS

# Addresses of the first instruction in a function.
_FUNC_HEAD_EAS = set()

# Addresses of the first instruction in a block.
_BLOCK_HEAD_EAS = set()

# Set of initially discovered block entrypoint addresses for each function
# as discovered by IDA's initial auto-analysis.
_DEFAULT_BLOCK_HEAD_EAS = {}

# Addresses of instructions that terminate a basic block.
_TERMINATOR_EAS = set()

# Mark an address as being the beginning of a function.
def try_mark_as_function(address):
  global _FUNC_HEAD_EAS, _BLOCK_HEAD_EAS
  
  _FUNC_HEAD_EAS.add(address)
  _BLOCK_HEAD_EAS.add(address)

  if not idaapi.add_func(address, idc.BADADDR):
    return False
  idaapi.autoWait()
  return True

def find_linear_terminator(ea, max_num=256):
  """Find the terminating instruction of a basic block, without actually
  associating the instructions with the block. This scans linearly until
  we find something that is definitely a basic block terminator. This does
  not consider the case of intermediate blocks."""
  global _BLOCK_HEAD_EAS, _TERMINATOR_EAS

  prev_term = None
  term_ea = ea
  for i in xrange(max_num):
    term_inst, inst_bytes = decode_instruction(ea)
    if not term_inst:
      # TODO(pag): Log that we couldn't decode.
      term_inst = prev_term
      break

    term_ea = ea
    prev_term = term_inst
    if ea in _TERMINATOR_EAS or instruction_ends_block(term_inst):
      break

    ea += len(inst_bytes)

    # The next instruction was already processed as part of some other scan.
    if ea in _BLOCK_HEAD_EAS:
      break

  if term_inst:
    _TERMINATOR_EAS.add(term_ea)

  return term_inst

def get_direct_branch_target(arg):
  """Tries to 'force' get the target of a direct or conditional branch.
  IDA can't always get code refs for flows from an instruction that appears
  inside another instruction (and so even seen by IDA in the first place)."""
  if not isinstance(arg, (int, long)):
    branch_inst_ea = arg.ea
  else:
    branch_inst_ea = arg
  try:
    branch_flows = tuple(idautils.CodeRefsFrom(branch_inst_ea, False))
    return branch_flows[0]
  except:
    decoded_inst, _ = decode_instruction(branch_inst_ea)
    target_ea = decoded_inst.Op1.addr
    #log.warning("Determined target of {:08x} to be {:08x}".format(
    #    branch_inst_ea, target_ea))
    return target_ea

def is_noreturn_function(ea):
  """Returns true if the function at `ea` is a no-return function."""
  flags = idc.GetFunctionFlags(ea)
  return 0 < flags and (flags & idaapi.FUNC_NORET)

def get_static_successors(inst):
  """Returns the statically known successors of an instruction."""
  branch_flows = tuple(idautils.CodeRefsFrom(inst.ea, False))
  next_ea = inst.ea + inst.size
  # Direct function call. The successor will be the fall-through instruction
  # unless the target of the function call looks like a `noreturn` function.
  if is_direct_function_call(inst):
    if not is_noreturn_function(get_direct_branch_target(inst.ea)):
      yield next_ea  # Not recognised as a `noreturn` function.

  if is_function_call(inst):  # Indirect function call, system call.
    yield next_ea

  elif is_conditional_jump(inst):
    yield next_ea
    yield get_direct_branch_target(inst.ea)

  elif is_direct_jump(inst):
    yield get_direct_branch_target(inst.ea)

  elif is_indirect_jump(inst):
    #TODO(pag): Augment with better switch table analysis.
    si = idaapi.get_switch_info_ex(inst.ea)
    if si:
      for case_ea in idautils.CodeRefsFrom(inst.ea, True):
        yield case_ea

  elif not is_control_flow(inst):
    yield next_ea

  else:
    # TODO(pag): Log this.
    #log.debug("No static successors of {:08x}".format(inst.ea))
    pass

def analyse_block(func_ea, ea):
  """Find the instructions of a basic block."""
  global _BLOCK_HEAD_EAS, _TERMINATOR_EAS, _FUNC_HEAD_EAS
  assert is_code(ea)

  inst_eas = []
  insts = []
  seen = set()

  next_ea = ea
  while is_code(next_ea) and next_ea not in seen:
    seen.add(next_ea)
    inst, _ = decode_instruction(next_ea)
    if not inst:
      break

    inst_eas.append(next_ea)
    insts.append(inst)

    if next_ea in _TERMINATOR_EAS or instruction_ends_block(inst):
      break

    next_ea = inst.ea + inst.size
    if next_ea in _BLOCK_HEAD_EAS:
      break

  successors = []
  if inst_eas:
    _TERMINATOR_EAS.add(inst_eas[-1])
    successors = get_static_successors(insts[-1])
    successors = [succ for succ in successors if is_code(succ)]
  
  return (ea, inst_eas, set(successors))

def find_default_block_heads(sub_ea):
  """Pre-process a function by finding all the recognized block head EAs
  before we dig deeper into individual blocks."""
  global _BLOCK_HEAD_EAS, _FUNC_HEAD_EAS, _DEFAULT_BLOCK_HEAD_EAS

  if sub_ea in _DEFAULT_BLOCK_HEAD_EAS:
    return _DEFAULT_BLOCK_HEAD_EAS[sub_ea]

  _FUNC_HEAD_EAS.add(sub_ea)
  heads = set([sub_ea])

  f = idaapi.get_func(sub_ea)
  if f:
    for b in idaapi.FlowChart(f):
      _BLOCK_HEAD_EAS.add(b.startEA)
      heads.add(b.startEA)

    for chunk_start_ea, chunk_end_ea in idautils.Chunks(sub_ea):
      _BLOCK_HEAD_EAS.add(chunk_start_ea)
      heads.add(chunk_start_ea)

  _DEFAULT_BLOCK_HEAD_EAS[sub_ea] = heads

  return heads

_FUNCTION_BLOCK_HEAD_EAS = {}

def analyse_subroutine(sub_ea):
  """Goes through the basic blocks of an identified function. Returns a set
  of basic block heads in the function, as well as block terminator
  instructions."""
  global _BLOCK_HEAD_EAS, _FUNC_HEAD_EAS, _FUNCTION_BLOCK_HEAD_EAS

  if sub_ea in _FUNCTION_BLOCK_HEAD_EAS:
    return _FUNCTION_BLOCK_HEAD_EAS[sub_ea]

  #log.info("Analysing subroutine {} at {:08x}".format(sub.name, sub.ea))
  block_head_eas = find_default_block_heads(sub_ea)
  term_insts = set()

  # Iteratively scan for block heads. This will do linear sweeps looking for
  # block terminators. These linear sweeps do not consider flows incoming
  # flows from existing blocks that logically split a block into two.
  found_block_eas = set()
  seen_blocks = set()
  while len(block_head_eas):
    block_head_ea = block_head_eas.pop()
    if block_head_ea in seen_blocks:
      continue

    was_seen_before = block_head_ea in _BLOCK_HEAD_EAS
    is_func_entry = block_head_ea in _FUNC_HEAD_EAS

    seen_blocks.add(block_head_ea)

    if not is_code(block_head_ea):
      #log.error("Block head at {:08x} is not code.".format(block_head_ea))
      continue

    found_block_eas.add(block_head_ea)
    _BLOCK_HEAD_EAS.add(block_head_ea)

    # Try to make sure that analysis will terminate if we accidentally
    # walk through a noreturn call.
    if block_head_ea != sub_ea and is_func_entry:
      found_block_eas.remove(block_head_ea)
      continue

    #log.debug("Found block head at {:08x}".format(block_head_ea))
    term_inst = find_linear_terminator(block_head_ea)
    if not term_inst:
      #log.error("Block at {:08x} has no terminator!".format(block_head_ea))
      found_block_eas.remove(block_head_ea)
      continue
    
    elif term_inst.ea != sub_ea and term_inst.ea in _FUNC_HEAD_EAS:
      found_block_eas.remove(block_head_ea)
      continue

    term_insts.add(term_inst)
    #log.debug("Linear terminator of {:08x} is {:08x}".format(
    #    block_head_ea, term_inst.ea))

    for succ_ea in get_static_successors(term_inst):
      if succ_ea not in _FUNC_HEAD_EAS or succ_ea == sub_ea:
        block_head_eas.add(succ_ea)

  #log.debug("Subroutine {:08x} has {} blocks".format(sub.ea, len(blocks)))

  # Analyse the blocks
  ret = found_block_eas, term_insts
  _FUNCTION_BLOCK_HEAD_EAS[sub_ea] = ret
  return ret
