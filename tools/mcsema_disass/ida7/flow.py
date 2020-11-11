# Copyright (c) 2020 Trail of Bits, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from table import *
from exception import *
from refs import *

# Addresses of the first instruction in a function.
_FUNC_HEAD_EAS = set()

# Addresses of the first instruction in a block.
_BLOCK_HEAD_EAS = set()

# Set of initially discovered block entrypoint addresses for each function
# as discovered by IDA's initial auto-analysis.
_DEFAULT_BLOCK_HEAD_EAS = {}

# Addresses of instructions that terminate a basic block.
_TERMINATOR_EAS = set()

# Instruction bytes that are used for alignment. In this case, an x86 NOP.
_ALIGNMENT_BYTES = set([0x90])

# Maps subroutine addresses to sets of block that are not targeted by any
# flows. We use this as an opportunistic way of handling jump tables that
# IDA does not understand. They are not handled directly as jump tables,
# rather they get handled as code cross-references.
_MISSING_FLOWS = collections.defaultdict(set)

# Mark an address as being the beginning of a function.
def try_mark_as_function(address):
  global _FUNC_HEAD_EAS, _BLOCK_HEAD_EAS
  
  _FUNC_HEAD_EAS.add(address)
  _BLOCK_HEAD_EAS.add(address)

  if not idaapi.add_func(address, idc.BADADDR):
    return False

  idaapi.auto_wait()
  return True


def is_start_of_function(ea):
  """Returns `True` if `ea` is the start of a function."""
  global _FUNC_HEAD_EAS

  if ea in _FUNC_HEAD_EAS:
    return True

  if not is_code(ea):
    return False

  func = ida_funcs.get_func(ea)
  if not func:
    return False

  return ea == func.start_ea

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
    if ea in _BLOCK_HEAD_EAS or \
       has_our_dref_to(ea) or \
       is_jump_table_target(ea):
      break

  if term_inst:
    _TERMINATOR_EAS.add(term_ea)

  return term_inst, inst_bytes


def get_direct_branch_target(arg):
  """Tries to 'force' get the target of a direct or conditional branch.
  IDA can't always get code refs for flows from an instruction that appears
  inside another instruction (and so even seen by IDA in the first place)."""
  global INT_TYPES

  if not isinstance(arg, INT_TYPES):
    branch_inst_ea = arg.ea
  else:
    branch_inst_ea = arg
  try:
    branch_flows = tuple(idautils.CodeRefsFrom(branch_inst_ea, False))
    return branch_flows[0]
  except:
    decoded_inst, _ = decode_instruction(branch_inst_ea)
    target_ea = decoded_inst.Op1.addr
    if not target_ea:
      for i, op in enumerate(decoded_inst.ops):
        if op.addr != 0:
          target_ea = op.addr
    return target_ea

def is_noreturn_inst(arg):
  """Returns `True` if the instruction `arg`, or at `arg`, will terminate
  control flow."""
  global INT_TYPES
  inst = arg
  if isinstance(arg, INT_TYPES):
    inst, _ = decode_instruction(arg)

  if is_direct_function_call(inst) or is_direct_jump(inst):
    called_ea = get_direct_branch_target(inst.ea)
    return is_noreturn_function(called_ea)

  return is_terminator(inst)

def get_static_successors(sub_ea, term_inst, delayed_inst, binary_is_pie):
  """Returns the statically known successors of an instruction."""

  # delayed_inst will be term_inst if there is no delay slot
  #
  # NOTE(pag): It is possible that there is an apparently single instruction
  #            block containing a `set` in SPARC (`sethi+or`), and so we
  #            want to use `term_inst.size` (8 in this case) to find `next_ea`
  #            if `term_inst` and `delayed_inst` match.
  global _FUNC_HEAD_EAS

  next_ea = term_inst.ea + term_inst.size
  if term_inst.ea != delayed_inst.ea:
    next_ea = delayed_inst.ea + fixup_delayed_instr_size(delayed_inst)

  # Direct function call. The successor will be the fall-through instruction
  # unless the target of the function call looks like a `noreturn` function.
  if is_direct_function_call(term_inst):
    if not is_noreturn_function(get_direct_branch_target(term_inst.ea)):
      yield fixup_function_return_address(term_inst, next_ea)  # Not recognised as a `noreturn` function.

  if is_function_call(term_inst):  # Indirect function call, system call.
    yield fixup_function_return_address(term_inst, next_ea)

  elif is_conditional_jump(term_inst):
    yield next_ea
    yield get_direct_branch_target(term_inst.ea)

  elif is_direct_jump(term_inst):
    yield get_direct_branch_target(term_inst.ea)

  elif is_indirect_jump(term_inst):
    table = get_jump_table(term_inst, binary_is_pie)
    target_eas = set(idautils.CodeRefsFrom(term_inst.ea, True))

    # Over the course of execution, `idautils.CodeRefsFrom` might change to
    # include delayed instructions.
    if delayed_inst.ea in target_eas:
      target_eas.remove(delayed_inst.ea)

    if table:
      for target_ea in table.entries.values():
        target_eas.add(target_ea)

    # Opportunistically add more flows to this instruction if it seems like
    # there are any blocks in the function with no predecessors.
    if not len(target_eas) and sub_ea in _MISSING_FLOWS:
      missing_flows = _MISSING_FLOWS[sub_ea]
      for target_ea in missing_flows:
        if not has_flow_to_code(target_ea):
          DEBUG("Assuming that jump at {:x} targets block {:x} with missing flow.")
          idc.add_cref(term_inst.ea, target_ea, idc.XREF_USER | idc.fl_JN)
          target_eas.add(target_ea)

    # If the jump table is not recovered add the next_ea as
    # the successor eas and throw a warning to look into later
    if len(target_eas) == 0:
      DEBUG("WARNING: No table entries for indirect jump at {:x}; Adding next_ea {:x} as successor." \
            .format(term_inst.ea, next_ea))
      yield next_ea
    else:
      for target_ea in target_eas:
        yield target_ea

  elif not is_control_flow(term_inst):
    if not is_noreturn_inst(term_inst) \
      and next_ea not in _FUNC_HEAD_EAS:
      yield next_ea

_BAD_BLOCK = (tuple(), set())

def analyse_block(func_ea, ea, binary_is_pie=False):
  """Find the instructions of a basic block."""
  global _BLOCK_HEAD_EAS, _TERMINATOR_EAS, _FUNC_HEAD_EAS
  
  if not is_code(ea):
    DEBUG("ERROR: Block at {:x} in function {:x} is not code".format(ea, func_ea))
    return _BAD_BLOCK

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
    if next_ea in _BLOCK_HEAD_EAS or \
       has_our_dref_to(next_ea) or \
       is_jump_table_target(next_ea):
      break

  successors = []
  if inst_eas:
    delayed_inst, delayed_ea = get_delayed_instruction(insts[-1])
    successors = get_static_successors(func_ea, insts[-1], delayed_inst, binary_is_pie)
    _TERMINATOR_EAS.add(inst_eas[-1])
    successors = [succ for succ in successors if is_code(succ)]
    if delayed_ea not in inst_eas:
      inst_eas.append(delayed_ea)
  
  return (inst_eas, set(successors))

def find_default_block_heads(sub_ea):
  """Pre-process a function by finding all the recognized block head EAs
  before we dig deeper into individual blocks."""
  global _BLOCK_HEAD_EAS, _FUNC_HEAD_EAS, _DEFAULT_BLOCK_HEAD_EAS
  global _ALIGNMENT_BYTES

  if sub_ea in _DEFAULT_BLOCK_HEAD_EAS:
    return _DEFAULT_BLOCK_HEAD_EAS[sub_ea]

  _FUNC_HEAD_EAS.add(sub_ea)
  heads = set([sub_ea])

  min_ea, max_ea = get_function_bounds(sub_ea)

  DEBUG("Default block heads for function {:x} with loose bounds [{:x}, {:x})".format(
      sub_ea, min_ea, max_ea))

  f = idaapi.get_func(sub_ea)
  if f:
    for b in idaapi.FlowChart(f):
      if min_ea <= b.start_ea < max_ea:
        _BLOCK_HEAD_EAS.add(b.start_ea)
        heads.add(b.start_ea)
        DEBUG("  block [{:x}, {:x})".format(b.start_ea, b.end_ea))

    for chunk_start_ea, chunk_end_ea in idautils.Chunks(sub_ea):
      _BLOCK_HEAD_EAS.add(chunk_start_ea)
      heads.add(chunk_start_ea)
      DEBUG("  chunk [{:x}, {:x})".format(chunk_start_ea, chunk_end_ea))

    for eh_start_ea, eh_end_ea in get_exception_chunks(sub_ea):
      _BLOCK_HEAD_EAS.update([eh_start_ea, eh_end_ea])
      heads.update([eh_start_ea, eh_end_ea])
      DEBUG("  exception chunks [{:x}, {:x})".format(eh_start_ea, eh_end_ea))

  # Look for possibly good jump table target candidates. We will use this
  # information in `get_static_successors` when we come across an indirect
  # jump with no known targets (i.e. not a jump table). In that case, we
  # assert that the untargeted code (if still not targeted) are candidate
  # targets for the instruction.
  if max_ea:
    ea = sub_ea
    while min_ea <= ea < max_ea and ea != idc.BADADDR:
      if ea not in _BLOCK_HEAD_EAS and \
         16 < idaapi.get_alignment(ea) and \
         read_byte(ea) not in _ALIGNMENT_BYTES and \
         not has_flow_to_code(ea):

        if is_data_reference(ea):
          DEBUG("  {:x} in function {:x} looks like an embedded jump table entry".format(
              ea, sub_ea))
        else:
          DEBUG("  block {:x} of function {:x} is not targeted by any flows!".format(
              ea, sub_ea))

          _MISSING_FLOWS[sub_ea].add(ea)
      ea = idc.next_head(ea, max_ea)


  _DEFAULT_BLOCK_HEAD_EAS[sub_ea] = heads

  return heads

_FUNCTION_BLOCK_HEAD_EAS = {}

def analyse_subroutine(sub_ea, binary_is_pie):
  """Goes through the basic blocks of an identified function. Returns a set
  of basic block heads in the function, as well as block terminator
  instructions."""
  global _BLOCK_HEAD_EAS, _FUNC_HEAD_EAS, _FUNCTION_BLOCK_HEAD_EAS

  if sub_ea in _FUNCTION_BLOCK_HEAD_EAS:
    return _FUNCTION_BLOCK_HEAD_EAS[sub_ea]

  sub_name = get_symbol_name(sub_ea, allow_dummy=True)
  DEBUG("Analysing subroutine {} at {:x}".format(sub_name, sub_ea))
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

    # The exception handling blocks are not identified as code with tight checks
    if not is_code(block_head_ea): #is_code_by_flags(block_head_ea):
      DEBUG("  Block head at {:08x} is not code.".format(block_head_ea))
      found_block_eas.discard(block_head_ea)
      continue

    found_block_eas.add(block_head_ea)
    _BLOCK_HEAD_EAS.add(block_head_ea)

    # Try to make sure that analysis will terminate if we accidentally
    # walk through a noreturn call.
    if block_head_ea != sub_ea and is_func_entry:
      found_block_eas.remove(block_head_ea)
      continue

    #DEBUG("Found block head at {:08x}".format(block_head_ea))
    term_inst, inst_bytes = find_linear_terminator(block_head_ea)
    if not term_inst:
      DEBUG("  Block at {:x} has no terminator!".format(block_head_ea))
      found_block_eas.remove(block_head_ea)
      continue
    
    elif term_inst.ea != sub_ea and term_inst.ea in _FUNC_HEAD_EAS:
      found_block_eas.remove(block_head_ea)
      continue

    term_insts.add(term_inst)

    # Check the instruction next to term_instr for recovery, if it has missing flow
    # IDA heuristics misses the landing pad and exception blocks in some cases; Linear
    # scan identifies the missing blocks and recover them
    delayed_inst, delayed_ea = get_delayed_instruction(term_inst)
    next_ea = delayed_inst.ea + delayed_inst.size
    if next_ea not in _FUNC_HEAD_EAS and next_ea not in _BLOCK_HEAD_EAS:
      block_head_eas.add(next_ea)

    #DEBUG("Linear terminator of {:08x} is {:08x}".format(
    #    block_head_ea, term_inst.ea))

    for succ_ea in get_static_successors(sub_ea, term_inst, delayed_inst, binary_is_pie):
      if succ_ea not in _FUNC_HEAD_EAS or succ_ea == sub_ea:
        block_head_eas.add(succ_ea)

  DEBUG("Subroutine {} at {:x} has {} blocks".format(
      sub_name, sub_ea, len(found_block_eas)))

  # Analyse the blocks
  ret = found_block_eas, term_insts
  _FUNCTION_BLOCK_HEAD_EAS[sub_ea] = ret
  return ret
