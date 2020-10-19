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

import collections
import idaapi
import idautils
import idc

# Maps instruction EAs to a pair of decoded inst, and the bytes of the inst.
PREFIX_ITYPES = tuple()

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

PERSONALITIES = collections.defaultdict(int)
PERSONALITIES.update({
  idaapi.ARM_bl: PERSONALITY_DIRECT_CALL,
  idaapi.ARM_blr: PERSONALITY_INDIRECT_CALL,

  idaapi.ARM_ret: PERSONALITY_RETURN,

  idaapi.ARM_b: PERSONALITY_DIRECT_JUMP,
  idaapi.ARM_br: PERSONALITY_INDIRECT_JUMP,

  idaapi.ARM_svc: PERSONALITY_SYSTEM_CALL,
  idaapi.ARM_hvc: PERSONALITY_SYSTEM_CALL,
  idaapi.ARM_smc: PERSONALITY_SYSTEM_CALL,

  idaapi.ARM_hlt: PERSONALITY_TERMINATOR,

  idaapi.ARM_cbnz: PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.ARM_cbz: PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.ARM_tbnz: PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.ARM_tbz: PERSONALITY_CONDITIONAL_BRANCH,
})

def fixup_personality(inst, p):
  """For things like b.le, IDA will give us the `ARM_b` opcode, and we need
  to figure out if it's actually conditional. This is stored in the `segpref`
  field, and `0xe` is the unconditional version."""
  if inst.itype == idaapi.ARM_b:
    if 0 <= inst.segpref <= 0xf and inst.segpref != 0xe:
      return PERSONALITY_CONDITIONAL_BRANCH
  return p

def has_delayed_slot(inst):
  return False

def fixup_delayed_instr_size(inst):
  return 4  # All isntructions are four bytes.

def fixup_instr_as_nop(inst):
  return False

def fixup_function_return_address(inst, next_ea):
  return next_ea


_BAD_ARM_REF_OFF = (idc.BADADDR, 0, 0)
_INVALID_THUNK_ADDR = (False, idc.BADADDR)


def is_ELF_thunk_by_structure(ea):
  """Try to manually identify an ELF thunk by its structure."""
  from util import decode_instruction, is_direct_jump, is_indirect_jump
  from util import is_invalid_ea, get_reference_target
  global _INVALID_THUNK_ADDR
  inst = None
  
  for i in range(4):  # 1 is good enough for x86, 4 for aarch64.
    inst, _ = decode_instruction(ea)
    if not inst:
      break
    # elif is_direct_jump(inst):
    #   ea = get_direct_branch_target(inst)
    #   inst = None
    if is_indirect_jump(inst) or is_direct_jump(inst):
      target_ea = get_reference_target(inst.ea)
      if not is_invalid_ea(target_ea):
        seg_name = idc.get_segm_name(target_ea).lower()
        if ".got" in seg_name or ".plt" in seg_name:
          target_ea = get_reference_target(target_ea)
          seg_name = idc.get_segm_name(target_ea).lower()

        if "extern" == seg_name:
          return True, target_ea

    ea = inst.ea + inst.size

  return _INVALID_THUNK_ADDR

_ARM_REF_CANDIDATES = set()

def _get_arm_ref_candidate(mask, op_val, op_str, all_refs):
  global _BAD_ARM_REF_OFF, _ARM_REF_CANDIDATES

  try:
    op_name = op_str.split("@")[0][1:]  # `#asc_400E5C@PAGE` -> `asc_400E5C`.
    op_name = op_name.split("#")[-1]
    op_name = op_name.split("+")[0]
    op_name = op_name.split("(")[-1]
    ref_ea = idc.get_name_ea_simple(op_name)

    #if (ref_ea & mask) == op_val:
    return ref_ea, mask, 0
  except:
    pass

  # NOTE(pag): We deal with candidates because it's possible that this
  #            instruction will have multiple references. In the case of
  #            `@PAGE`-based offsets, it's problematic when the wrong base
  #            is matched, because it really throws off the C++ side of things
  #            because the arrangement of the lifted data being on the same
  #            page is not guaranteed.
  _ARM_REF_CANDIDATES.clear()
  for ref_ea in all_refs:
    if (ref_ea & mask) == op_val:
      _ARM_REF_CANDIDATES.add(ref_ea)
      return ref_ea, mask, 0

  if len(_ARM_REF_CANDIDATES):
    for candidate_ea in _ARM_REF_CANDIDATES:
      if candidate_ea == op_val:
        return candidate_ea, mask, 0

    return _ARM_REF_CANDIDATES.pop(), mask, 0

  return _BAD_ARM_REF_OFF

# Try to handle `@PAGE` and `@PAGEOFF` references, resolving them to their
# 'intended' address.
#
# TODO(pag): There must be a better way than just string searching :-/
def try_get_ref_addr(inst, op, op_val, all_refs, _NOT_A_REF):
  global _BAD_ARM_REF_OFF

  from util import is_invalid_ea

  #if op.type not in (idc.o_imm, idc.o_displ):
    # This is a reference type that the other ref tracking code
    # can handle, return defaults
  #  return op_val, 0, 0

  op_str = idc.print_operand(inst.ea, op.n)

  if '@PAGEOFF' in op_str:
    return _get_arm_ref_candidate(4095, op_val, op_str, all_refs)

  elif '@PAGE' in op_str:
    return _get_arm_ref_candidate(-4096, op_val, op_str, all_refs)

  elif not is_invalid_ea(op_val) and inst.get_canon_mnem().lower() == "adr":
    return op_val, 0, 0

  return _BAD_ARM_REF_OFF


def recover_preserved_regs(M, F, inst, xrefs, preserved_reg_sets):
  return False

def recover_deferred_preserved_regs(M):
  return

def recover_function_spec_from_arch(E):
  return
