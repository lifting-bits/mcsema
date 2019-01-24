# Copyright (c) 2019 Trail of Bits, Inc.
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

from binaryninja.enums import (
  LowLevelILOperation, MediumLevelILOperation, RegisterValueType
)

import binaryninja as binja

JMP_TABLES = []

import util
import log


class JMPTable(object):
  """ Simple container for jump table info """
  def __init__(self, bv, rel_base, targets, rel_off=0):
    self.rel_off = rel_off
    self.base_addr = rel_base
    self.targets = targets


def search_ssa_mlil_displ(il, ptr=False, _neg=False):
  """ Searches for a MLIL_CONST[_PTR] as a child of an ADD or SUB

  Args:
    il (binja.LowLevelILInstruction): Instruction to parse
    ptr (bool): Searches for CONST_PTR instead of CONST if True
    _neg (bool): Used internally to negate the final output if needed

  Returns:
    int: located value
  """
  # The il may be inside a MLIL_LOAD
  if il.operation == MediumLevelILOperation.MLIL_LOAD:
    return search_ssa_mlil_displ(il.src, ptr, _neg)

  # Continue left/right for ADD/SUB only
  elif il.operation in [MediumLevelILOperation.MLIL_ADD, MediumLevelILOperation.MLIL_SUB]:
    _neg = (il.operation == MediumLevelILOperation.MLIL_SUB)
    return (search_ssa_mlil_displ(il.left, ptr, _neg) or
            search_ssa_mlil_displ(il.right, ptr, _neg))

  # Terminate when we find a constant
  const_type = MediumLevelILOperation.MLIL_CONST_PTR if ptr else MediumLevelILOperation.MLIL_CONST
  if il.operation == const_type:
    return il.constant * (-1 if _neg else 1)

  # DEBUG('Reached end of expr: {}'.format(il))


def get_jmptable(bv, il):
  """ Gathers jump table information (if any) being referenced at the given il

  Args:
    bv (binja.BinaryView)
    il (binja.LowLevelILInstruction)

  Returns:
    JMPTable: Jump table info if found, None otherwise
  """
  func = il.function.source_function
  mlil_func = func.medium_level_il
  llil_func = func.low_level_il

  llil_inst_idx = llil_func.get_instruction_start(il.address)
  mlil_inst_idx = llil_func.get_medium_level_il_instruction_index(llil_inst_idx)

  try:
    targets = [e.to_value for e in il.dest.possible_values.table]
  except:
    """ If there is no targets, it's not a form of jump """
    return None

  # Should be able to find table info now
  tbl = None

  # Jumping to a register
  if il.dest.operation == LowLevelILOperation.LLIL_REG:
    # This is likely a relative offset table
    ssa_mlil_func = func.medium_level_il.ssa_form

    # Get the SSA MLIL instruction at this jump
    llil_inst_idx = llil_func.get_instruction_start(il.address)
    mlil_inst_idx = llil_func.get_medium_level_il_instruction_index(llil_inst_idx)
    ssa_mlil_inst_idx = func.medium_level_il.get_ssa_instruction_index(mlil_inst_idx)

    # Get the SSA MLIL variable that holds jump targets
    jmp_var = ssa_mlil_func[ssa_mlil_inst_idx].vars_read[0]

    # Find where this variable is defined
    ssa_mlil_jmp_var_def = ssa_mlil_func[ssa_mlil_func.get_ssa_var_definition(jmp_var)]

    # Possible jump table info here, try parsing it
    base = search_ssa_mlil_displ(ssa_mlil_jmp_var_def.src, ptr=True)
    offset = 0

    # If parsing worked, identify table type and return

    # Most common case:
     # 2. add table entry to table_base
     # 1. load from table_base + offset

    # 2:
    if ssa_mlil_jmp_var_def.src.operation is binja.MediumLevelILOperation.MLIL_ADD and \
       binja.MediumLevelILOperation.MLIL_CONST_PTR in [ssa_mlil_jmp_var_def.src.left.operation, ssa_mlil_jmp_var_def.src.right.operation]:

      offset_base = ssa_mlil_jmp_var_def.src.address

      add_pointer = None
      left_add_pointer = False

      if ssa_mlil_jmp_var_def.src.left.operation is binja.MediumLevelILOperation.MLIL_CONST_PTR:
        add_pointer = ssa_mlil_jmp_var_def.src.left.constant
        left_add_pointer = True
      if ssa_mlil_jmp_var_def.src.right.operation is binja.MediumLevelILOperation.MLIL_CONST_PTR:
        add_pointer = ssa_mlil_jmp_var_def.src.right.constant

      # 1:
      if left_add_pointer:  # Parse right
        is_load, load_pointer = check_if_load_from_table(ssa_mlil_jmp_var_def.src.right, ssa_mlil_func)
      else:  # Parse right
        is_load, load_pointer = check_if_load_from_table(ssa_mlil_jmp_var_def.src.left, ssa_mlil_func)

      if not is_load or load_pointer != add_pointer:
        return None

      base = load_pointer
      offset = offset_base - base

      tbl = JMPTable(bv, base, targets, offset)

  # Full jump expression
  else:
    # Parse out the base address
    base = util.search_displ_base(il.dest)
    if base is not None:
      tbl = JMPTable(bv, base, targets)

  if tbl is not None:
    log.debug("Found jump table at {:x} with offset {:x}".format(tbl.base_addr, tbl.rel_off))
  return tbl


def check_if_load_from_table(ssa_var, func):
  # This is what we're looking for
  if ssa_var.operation is binja.MediumLevelILOperation.MLIL_LOAD_SSA:
    if ssa_var.src.left.operation is binja.MediumLevelILOperation.MLIL_CONST_PTR:
      return (True, ssa_var.src.left.constant)
    elif ssa_var.src.right.operation is binja.MediumLevelILOperation.MLIL_CONST_PTR:
      return (True, ssa_var.src.right.constant)
    else:
      return (False, 0)

  # Filter through some instruction types
  elif ssa_var.operation in [binja.MediumLevelILOperation.MLIL_SX, binja.MediumLevelILOperation.MLIL_ZX]:
    return check_if_load_from_table(ssa_var.src, func)

  # If it is a variable, find the definition
  elif ssa_var.operation in [binja.MediumLevelILOperation.MLIL_VAR_SSA, binja.MediumLevelILOperation.MLIL_VAR_SSA_FIELD]:
    # Get the variable is definition, will except if it is the original definition
    try:
      ssa_def = func[func.get_ssa_var_definition(ssa_var.src)]
    except AttributeError:
      return (False, 0)

    return check_if_load_from_table(ssa_def.src, func)

  # It's not what we're looking for and it's not in what we can ignore
  else:
    return (False, 0)
