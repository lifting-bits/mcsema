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
PREFIX_ITYPES = (idaapi.NN_lock, idaapi.NN_rep,
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

PERSONALITIES = collections.defaultdict(int)
PERSONALITIES.update({
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

def fixup_personality(inst, p):
  return p

def has_delayed_slot(inst):
  return False

def fixup_delayed_instr_size(inst):
  return inst.size

def fixup_instr_as_nop(inst):
  return False

def fixup_function_return_address(inst, next_ea):
  return next_ea

_INVALID_THUNK_ADDR = (False, idc.BADADDR)

def is_ELF_thunk_by_structure(ea):
  """Try to manually identify an ELF thunk by its structure."""
  from util import decode_instruction, is_direct_jump, is_indirect_jump
  from util import is_invalid_ea, get_reference_target
  
  global _INVALID_THUNK_ADDR
  
  seg_name = idc.get_segm_name(ea).lower()  
  if ".plt" not in seg_name:
    return _INVALID_THUNK_ADDR

  inst, _ = decode_instruction(ea)
  if not inst or not (is_indirect_jump(inst) or is_direct_jump(inst)):
    return _INVALID_THUNK_ADDR

  target_ea = get_reference_target(inst.ea)
  if is_invalid_ea(target_ea):
    return _INVALID_THUNK_ADDR

  seg_name = idc.get_segm_name(target_ea).lower()
  if ".got" in seg_name or ".plt" in seg_name:
    target_ea = get_reference_target(target_ea)
    seg_name = idc.get_segm_name(target_ea).lower()

  if "extern" == seg_name:
    return True, target_ea

  return _INVALID_THUNK_ADDR

def try_get_ref_addr(inst, op, op_val, all_refs, _NOT_A_REF):
  return op_val, 0, 0

def recover_preserved_regs(M, F, inst, xrefs, preserved_reg_sets):
  return False

def recover_deferred_preserved_regs(M):
  return

if idaapi.get_inf_structure().is_64bit():
  def return_values():
    return {
      "register": "RAX",
      "type": "L"
    }

  def return_address():
    return {
      "memory": {
        "register": "RSP",
        "offset": 0
      },
      "type": "L"
    }

  def return_stack_pointer():
    return {
      "register": "RSP",
      "offset": 8,
      "type": "L"
    }

elif idaapi.get_inf_structure().is_32bit():
  def return_values():
    return {
      "register": "EAX",
      "type": "I"
    }

  def return_address():
    return {
      "memory": {
        "register": "ESP",
        "offset": 0
      },
      "type": "I"
    }

  def return_stack_pointer():
    return {
      "register": "ESP",
      "offset": 4,
      "type": "I"
    }

def recover_value_spec(V, spec):
  """Recovers the default value specification."""
  V.type = spec["type"]

  if "name" in spec and len(spec["name"]):
    V.name = spec["name"]

  if "register" in spec:
    V.register = spec["register"]
  elif "memory" in spec:
    mem_spec = spec["memory"]
    V.memory.register = mem_spec["register"]
    if mem_spec["offset"]:
      V.memory.offset = mem_spec["offset"]

def recover_function_spec_from_arch(E):
  """ recover the basic information about the function spec"""
  D = E.decl
  if E.argument_count >= 8:
    D.is_noreturn = E.no_return
    D.is_variadic = (E.argument_count >= 8)
    D.calling_convention = 0
    if D.is_noreturn == False:
      V = D.return_values.add()
      recover_value_spec(V, return_values())
    recover_value_spec(D.return_address, return_address())
    recover_value_spec(D.return_stack_pointer, return_stack_pointer())
