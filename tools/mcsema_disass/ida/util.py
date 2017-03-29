# Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved.

import idc
import idaapi
import idautils
import collections

DEBUG = (lambda *args: None)

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

_INSTRUCTION_CACHE = {}

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
  decoded_bytes = "".join(chr(idc.Byte(byte_ea)) for byte_ea in range(ea, end_ea))

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

_BLOCK_HEAD_EAS = set()
_TERMINATOR_EAS = set()

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

# Set of function entrypoints.
_FUNC_HEAD_EAS = set()
_DEFAULT_HEADS = {}

def find_default_block_heads(sub_ea):
  """Pre-process a function by finding all the recognized block head EAs
  before we dig deeper into individual blocks."""
  global _BLOCK_HEAD_EAS, _FUNC_HEAD_EAS, _DEFAULT_HEADS

  if sub_ea in _DEFAULT_HEADS:
    return _DEFAULT_HEADS[sub_ea]

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

  _DEFAULT_HEADS[sub_ea] = heads

  return heads

def analyse_subroutine(sub_ea):
  """Goes through the basic blocks of an identified function. Returns a set
  of basic block heads in the function, as well as block terminator
  instructions."""
  global _BLOCK_HEAD_EAS, _FUNC_HEAD_EAS

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
  return found_block_eas, term_insts

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
  
  refs = tuple(refs)
  _REFS[I.ea] = refs

  return refs

# Mark an address as containing code.
def mark_as_code(address):
  if not idc.isCode(idc.GetFlags(address)):
    idc.MakeCode(address)
    idaapi.autoWait()

# Returns `True` if `address` belongs to some code segment.
def is_code(address):
  return idc.isCode(idc.GetFlags(address))

# Mark an address as being the beginning of a function.
def try_mark_as_function(address):
  global _FUNC_HEAD_EAS, _BLOCK_HEAD_EAS
  
  _FUNC_HEAD_EAS.add(address)
  _BLOCK_HEAD_EAS.add(address)

  if not idaapi.add_func(address, idc.BADADDR):
    return False
  idaapi.autoWait()
  return True
