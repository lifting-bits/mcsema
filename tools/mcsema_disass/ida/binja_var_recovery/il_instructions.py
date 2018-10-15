# Copyright (c) 2018 Trail of Bits, Inc.
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

import pprint
import collections
from binaryninja import *
from binja_var_recovery.util import *
from binja_var_recovery.il_analysis import *
from binja_var_recovery.il_variable import *
from binja_var_recovery.il_function import *

def get_opd_1(expr):
  return expr.src

def get_opd_2(expr):
  return expr.dest, expr.src

class ILInstruction(object):
  def __init__(self, bv, func, insn_il):
    self.insn = insn_il
    self.address = insn_il.address
    self.bv = bv
    self.function = func
    self.f_handler = FUNCTION_OBJECTS[func.start]
    self.ssa_variables = collections.defaultdict(set)

  def get_ssa_var_values(self, ssa_var):
    if isinstance(ssa_var, binja.SSAVariable):
      value_set = set()
      p_value = self.function.medium_level_il.get_ssa_var_value(ssa_var)
      if p_value.type in [ binja.RegisterValueType.ConstantValue,
                          binja.RegisterValueType.ConstantPointerValue ]:
        value_set.add(p_value.value)

      elif p_value.type == binja.RegisterValueType.EntryValue:
        values = self.f_handler.get_param_register(p_value.reg)
        value_set.update(values)
      else:
        values = self.backward_analysis(ssa_var)
        value_set.update(values)
      return value_set
    else:
      return None

  def get_ssa_var_possible_values(self, ssa_var):
    value_set = set()
    if isinstance(ssa_var, binja.SSAVariable):
      p_value = self.insn.get_ssa_var_possible_values(ssa_var)
      if p_value.type == binja.RegisterValueType.EntryValue:
        value_set = self.func_obj.get_entry_register(p_value.reg)
      elif p_value.type != binja.RegisterValueType.UndeterminedValue:
        pass
      else:
        values = self.backward_analysis(ssa_var)
        value_set.update(values)
    return value_set

  def evaluate_expression(self, expr):
    expr_value_set = set()
    if expr is None:
      return
    operation_name = "{}".format(expr.operation.name.lower())
    if hasattr(self, operation_name):
      ssa_values = getattr(self, operation_name)(expr)
    else:
      DEBUG("Instruction operation {} is not supported!".format(operation_name))
      ssa_values = set()

    expr_value_set.update(ssa_values)
    return expr_value_set

  def forward_analysis(self, ssa_var):
    # Collect all the alias ssa variables associated
    indices = set()
    vars_uses = self.function.medium_level_il.get_ssa_var_uses(ssa_var)
    for index in vars_uses:
      insn = self.function.medium_level_il[index].ssa_form
      if insn is None:
        continue

      if insn.operation == binja.MediumLevelILOperation.MLIL_SET_VAR_SSA or \
        insn.operation == binja.MediumLevelILOperation.MLIL_SET_VAR_SSA_FIELD or \
        insn.operation == binja.MediumLevelILOperation.MLIL_VAR_PHI :
        indices.add(index)
        vars_written = insn.vars_written
        for ssa_var in vars_written:
          indices.update(self.forward_analysis(ssa_var))

    return sorted(indices)

  def backward_analysis(self, ssa_var):
    var_handler = SSAVariable(self.bv, ssa_var, self.bv.address_size, self.function)
    set_comments(self.bv, self.insn.address, "test backward analysis 1 : {}".format(var_handler.variable_name()))
    return var_handler.backward_analysis(self.insn)

  def get_memory_version(self, insn):
    version = insn.ssa_memory_version
    if version > 0:
      return version
    elif "mem#0" in str(insn):
      return 0
    else:
      return None

  def get_variable_addr(self, expr):
    if expr is None:
      return None

    for token in expr.tokens:
      if token.type == binja.InstructionTextTokenType.PossibleAddressToken:
        if is_data_variable(self.bv, token.value):
          return token.value
    return None

  def get_variable_size(self, expr):
    if expr.operation == binja.MediumLevelILOperation.MLIL_STORE_SSA or \
      expr.operation == binja.MediumLevelILOperation.MLIL_LOAD_SSA:
      return expr.size

    elif expr.operation == binja.MediumLevelILOperation.MLIL_SET_VAR_SSA:
      return self.get_variable_size(expr.src)

    elif expr.operation == binja.MediumLevelILOperation.MLIL_IF:
      return self.get_variable_size(expr.condition)

    return expr.size

  def mlil_const(self, expr):
    value_set = set([expr.constant])
    return value_set

  def mlil_const_ptr(self, expr):
    value_set = set([expr.constant])
    return value_set

  def mlil_var_ssa(self, expr):
    if isinstance(expr.src, binja.SSAVariable):
      if str(expr.src) not in self.f_handler.ssa_variables.keys():
        ssa_value = self.get_ssa_var_values(expr.src)
        self.f_handler.ssa_variables[str(expr.src)] = ssa_value
        return ssa_value
      else:
        return self.f_handler.ssa_variables[str(expr.src)]
    else:
      return set()

  def mlil_var_ssa_field(self, expr):
    if isinstance(expr.src, binja.SSAVariable):
      if str(expr.src) not in self.f_handler.ssa_variables.keys():
        ssa_value = self.get_ssa_var_values(expr.src)
        self.f_handler.ssa_variables[str(expr.src)] = ssa_value
        return ssa_value
      else:
        return self.f_handler.ssa_variables[str(expr.src)]
    else:
      return set()

  def mlil_set_var_ssa(self, expr):
    src_value_set = set()
    idest, isrc = get_opd_2(expr)

    if len(expr.vars_written) > 1:
      DEBUG("Warning! vars_written > 1 for operation MLIL_SET_VAR_SSA")

    for var in expr.vars_read:
      if isinstance(var, binja.SSAVariable):
        if str(var) not in self.f_handler.ssa_variables.keys():
          ssa_value = self.get_ssa_var_values(var)
          self.f_handler.ssa_variables[str(var)] = ssa_value

    if is_constant(self.bv, isrc):
      set_comments(self.bv, self.insn.address, "isrc : {:x}".format(isrc.constant))
      src_value_set.add(isrc.constant)
    else:
      src_value_set = self.evaluate_expression(isrc)

    for var in expr.vars_written:
      self.f_handler.ssa_variables[str(var)].update(src_value_set)
      DEBUG("mlil_set_var_ssa, vars_written : {} {}".format(var, src_value_set))
      set_comments(self.bv, self.insn.address, "vars_written : {} {}".format(var, src_value_set))

  def mlil_set_var_aliased(self, expr):
    src_value_set = set()
    idest, isrc = get_opd_2(expr)

    if len(expr.vars_written) > 1:
      DEBUG("Warning! vars_written > 1 for operation MLIL_SET_VAR_SSA")

    for var in expr.vars_read:
      if isinstance(var, binja.SSAVariable):
        if str(var) not in self.f_handler.ssa_variables.keys():
          ssa_value = self.get_ssa_var_values(var)
          self.f_handler.ssa_variables[str(var)] = ssa_value

    if is_constant(self.bv, isrc):
      set_comments(self.bv, self.insn.address, "isrc : {:x}".format(isrc.constant))
      src_value_set.add(isrc.constant)
    else:
      src_value_set = self.evaluate_expression(isrc)

    for var in expr.vars_written:
      self.f_handler.ssa_variables[str(var)].update(src_value_set)
      DEBUG("mlil_set_var_ssa, vars_written : {} {}".format(var, src_value_set))
      set_comments(self.bv, self.insn.address, "vars_written : {} {}".format(var, src_value_set))


  def mlil_set_var_ssa_field(self, expr):
    src_value_set = set()
    idest, isrc = get_opd_2(expr)

    for var in expr.vars_read:
      if isinstance(var, binja.SSAVariable):
        if str(var) not in self.f_handler.ssa_variables.keys():
          ssa_value = self.get_ssa_var_values(var)
          self.f_handler.ssa_variables[str(var)] = ssa_value

    if len(expr.vars_written) > 1:
      DEBUG("Warning! vars_written > 1 for operation MLIL_SET_VAR_SSA_FIELD")

    # Check if the variable is assigned a constant value. Not preserving the bitfields 
    # not update during assignments
    if is_constant(self.bv, isrc):
      set_comments(self.bv, self.insn.address, "isrc : {:x}".format(isrc.constant))
      src_value_set.add(isrc.constant)
    else:
      src_value_set = self.evaluate_expression(isrc)

    for var in expr.vars_written:
      self.f_handler.ssa_variables[str(var)].update(src_value_set)
      set_comments(self.bv, self.insn.address, "vars_written : {} {}".format(var, src_value_set))

  def mlil_address_of(self, expr):
    expr_value = set()
    expr_value.add("<undetermined>")
    return expr_value

  def mlil_if(self, expr):
    if self.get_memory_version(expr) is not None:
      cond = expr.condition
      # Handle both direct and indirect memory accesses
      var = self.get_variable_addr(cond)
      if var is None:
        DEBUG("Warning! return expr is None expr {}".format(cond))
      #else:
      #  VARIABLE_ALIAS_SET[var].add(var)

  def mlil_goto(self, expr):
    pass

  def mlil_nop(self, expr):
    pass

  def mlil_sx(self, expr):
    return self.evaluate_expression(expr.src)

  def mlil_zx(self, expr):
    return self.evaluate_expression(expr.src)

  def mlil_ret(self, expr):
    value_set = set()
    isrc_list = expr.src
    for isrc in isrc_list:
      expr_values = self.evaluate_expression(isrc)
      value_set.update(expr_values)
    return value_set  

  def mlil_noret(self, expr):
    return set()

  def mlil_store_ssa(self, expr):
    idest, isrc = get_opd_2(expr)

    if is_constant(self.bv, idest):
      dest_memory = idest.constant
      if is_data_variable(self.bv, dest_memory):
        if analyse_variable_size(self.bv, self.insn, dest_memory) is not None:
          MEMORY_REFS[dest_memory] = isrc.size

    else:
      dest_memory_set = self.evaluate_expression(idest)
      set_comments(self.bv, self.insn.address, "expression : {} {}".format(idest, dest_memory_set))

  def mlil_load_ssa(self, expr):
    src_value_set = set()
    isrc = get_opd_1(expr)

    if is_constant(self.bv, isrc):
      src_memory = isrc.constant
      if is_data_variable(self.bv, src_memory):
        if analyse_variable_size(self.bv, self.insn, src_memory) is not None:
          DEBUG("Found variable memory {:x} size {:x}".format(src_memory, isrc.size))
          MEMORY_REFS[src_memory] = isrc.size
    else:
      memory_set = self.evaluate_expression(isrc)
      DEBUG("mlil_load_ssa expression : {} {}".format(isrc, memory_set))
      set_comments(self.bv, self.insn.address, "expression : {} {}".format(isrc, memory_set))

    src_value_set.add("<undetermined>")
    return src_value_set

  def mlil_add(self, expr):
    """ Handle the ssa operation - mlil_add
        The expression could be of following format : (mem + expr), (expr + expr), (expr, mem)
        1) Get the values of ssa variables read in the expression
        2) Check if there is a reference to the constant value
        3) Compute the possible global variable access
    """
    expr_value_set = set()
    left_values = set()
    right_values = set()
    vars_read = expr.vars_read
    for var in vars_read:
      if isinstance(var, binja.SSAVariable):
        if str(var) not in self.f_handler.ssa_variables.keys():
          ssa_value = self.get_ssa_var_values(var)
          self.f_handler.ssa_variables[str(var)] = ssa_value
        DEBUG("mlil_add ssa variable {} -> {}".format(str(var), self.f_handler.ssa_variables[str(var)]))

    # Handle left operand
    if is_constant(self.bv, expr.left):
      left_values.add(expr.left.constant)
      if is_data_variable(self.bv, expr.left.constant):
        if analyse_variable_refs(self.bv, expr, expr.left.constant):
          ADDRESS_REFS[expr.left.constant] = 0

    else:
      left_values = self.evaluate_expression(expr.left)

    if is_constant(self.bv, expr.right):
      right_values.add(expr.right.constant)
      if is_data_variable(self.bv, expr.right.constant):
        if analyse_variable_refs(self.bv, expr, expr.right.constant):
          ADDRESS_REFS[expr.right.constant] = 0
    else:
      right_values = self.evaluate_expression(expr.right)

    for lvalue in left_values:
      for rvalue in right_values:
        DEBUG("mlil_add rvalue {} {} lvalue {} {}".format(rvalue, type(rvalue), lvalue, type(lvalue)))
        if not isinstance(lvalue, str) and not isinstance(rvalue, str):
          if is_data_variable(self.bv, lvalue):
            build_alias_set(self.bv, lvalue + rvalue, lvalue)
          if is_data_variable(self.bv, rvalue):
            build_alias_set(self.bv, lvalue + rvalue, rvalue)
          expr_value_set.add(lvalue + rvalue)
        else:
          expr_value_set.add("<undetermined>")

    DEBUG("mlil_add expr_value_set {}".format(expr_value_set))
    return expr_value_set

  def mlil_var_phi(self, expr):
    src_value_set = set()
    src_value_set.add("<undetermined>")
    return src_value_set

  def mlil_lsl(self, expr):
    expr_value_set = set()
    left_values = set()
    right_values = set()
    return expr_value_set

# Low Level IL analysis to determine the possible values of the variables
  def _unarry_op(self, expr):
    src_vset = set()
    if is_constant(self.bv, expr):
      src_vset.add(expr.constant)
    else:
      src_vset = self.evaluate_expression(expr)
    return src_vset

  def llil_reg_ssa(self, expr):
    if str(expr.src) in self.f_handler.ssa_variables.keys():
      return self.f_handler.ssa_variables[str(expr.src)]
    return set([])

  def llil_goto(self, expr):
    pass

  def llil_sx(self, expr):
    return self._unarry_op(expr.src)

  def llil_zx(self, expr):
    return self._unarry_op(expr.src)

  def llil_sub(self, expr):
    return set([])

  def llil_lsl(self, expr):
    expr_vset = set()
    lvset = set()
    rvset = set()
    # Handle left operand
    if is_constant(self.bv, expr.left):
      ileft = expr.left
      if is_data_variable(self.bv, ileft.constant):
        lvset.add(Values(ileft.constant, ileft.constant))
        ADDRESS_REFS[ileft.constant] = 0
      else:
        lvset.add(ileft.constant)
    else:
      lvset = self.evaluate_expression(expr.left)

    if is_constant(self.bv, expr.right):
      iright = expr.right
      if is_data_variable(self.bv, iright.constant):
        rvset.add(Values(iright.constant, iright.constant))
        ADDRESS_REFS[iright.constant] = 0
      else:
        rvset.add(iright.constant)
    else:
      rvset = self.evaluate_expression(expr.right)

    for lvalue in lvset:
      for rvalue in rvset:
        if is_values(self.bv, lvalue) and is_long(self.bv, rvalue):
          new_addr = lvalue.address << rvalue
          add_to_aliasset(self.bv, new_addr, lvalue.src)
          expr_vset.add(Values(new_addr, lvalue.src))
        elif is_long(self.bv, lvalue) and is_long(self.bv, rvalue):
          new_val = lvalue << rvalue
          expr_vset.add(new_val)
        elif is_long(self.bv, lvalue):
          expr_vset.add("<symbolic> + {:x}".format(lvalue))
        elif is_long(self.bv, rvalue):
          expr_vset.add("<symbolic> + {}".format(rvalue))

    DEBUG("llil_lsl expr_vset {}".format(expr_vset))
    return expr_vset

  def llil_add(self, expr):
    expr_vset = set()
    lvset = set()
    rvset = set()

    if is_constant(self.bv, expr.left):
      ileft = expr.left
      if is_data_variable(self.bv, ileft.constant):
        lvset.add(Values(ileft.constant, ileft.constant))
        ADDRESS_REFS[ileft.constant] = 0
      else:
        lvset.add(ileft.constant)  

    else:
      lvset = self.evaluate_expression(expr.left)

    if is_constant(self.bv, expr.right):
      iright = expr.right
      if is_data_variable(self.bv, iright.constant):
        rvset.add(Values(iright.constant, iright.constant))
        ADDRESS_REFS[iright.constant] = 0
      else:
        rvset.add(iright.constant)
    else:
      rvset = self.evaluate_expression(expr.right)

    for lvalue in lvset:
      for rvalue in rvset:
        if is_values(self.bv, lvalue) and is_long(self.bv, rvalue):
          add_to_aliasset(self.bv, lvalue.address + rvalue, lvalue.src)
          expr_vset.add(Values(lvalue.address + rvalue, lvalue.src))
        elif is_long(self.bv, lvalue) and is_long(self.bv, rvalue):
          add_to_aliasset(self.bv, lvalue + rvalue, lvalue)
          expr_vset.add(lvalue + rvalue)
        elif is_long(self.bv, rvalue) and is_sym_values(self.bv, lvalue):
          expr_vset.add(SymbolicValue(lvalue.comment + " add", lvalue.offset + rvalue))
        elif is_long(self.bv, lvalue):
          expr_vset.add("<symbolic> + {:x}".format(lvalue))
        elif is_long(self.bv, rvalue):
          expr_vset.add("<symbolic> + {:x}".format(rvalue))

    DEBUG("llil_add expr_vset {}".format(expr_vset))
    return expr_vset

  def llil_store_ssa(self, expr):
    idest, isrc = get_opd_2(expr)

    # if the store operation happening on stack; ignore it
    if is_stack_op(self.bv, idest):
      return

    if is_constant(self.bv, idest):
      dest_memory = idest.constant
      if is_data_variable(self.bv, dest_memory):
        if analyse_variable_size(self.bv, dest_memory) is not None:
          MEMORY_REFS[dest_memory] = isrc.size
          add_to_aliasset(self.bv, dest_memory+isrc.size, dest_memory)

    else:
      dest_memset = self.evaluate_expression(idest)
      sz = isrc.size
      for item in dest_memset:
        if is_values(self.bv, item):
          add_to_aliasset(self.bv, item.address+sz, item.src)

  def llil_load_ssa(self, expr):
    src_vset = set()
    isrc = get_opd_1(expr)

    # if the load operation is happening on stack ignore it
    if is_stack_op(self.bv, isrc):
      src_vset.add(SymbolicValue("stack load", 0))
      return src_vset

    if is_constant(self.bv, isrc):
      src_memory = isrc.constant
      if is_data_variable(self.bv, src_memory):
        if analyse_variable_size(self.bv, src_memory) is not None:
          MEMORY_REFS[src_memory] = isrc.size
          add_to_aliasset(self.bv, src_memory+isrc.size, src_memory)
    else:
      src_memset = self.evaluate_expression(isrc)
      sz = isrc.size
      for item in src_memset:
        if is_values(self.bv, item):
          add_to_aliasset(self.bv, item.address+sz, item.src)

    src_vset.add(SymbolicValue("load", 0))
    return src_vset

  def llil_set_reg_ssa(self, expr):
    src_vset = set()
    idest, isrc = get_opd_2(expr)
    if not is_reg_ssa(self.bv, idest):
      return

    if str(idest) in self.f_handler.ssa_variables.keys():
      return self.f_handler.ssa_variables[str(idest)]

    if is_constant(self.bv, isrc):
      if is_data_variable(self.bv, isrc.constant):
        addr_ref = analyze_reference(self.bv, isrc.constant)
        if addr_ref is not None:
          ADDRESS_REFS[addr_ref] = 0
          add_to_aliasset(self.bv, isrc.constant, addr_ref)
          src_vset.add(Values(isrc.constant, addr_ref))
        else:
          src_vset.add(Values(isrc.constant, isrc.constant))
      else:
        src_vset.add(isrc.constant)
    else:
      src_vset = self.evaluate_expression(isrc)

    self.f_handler.ssa_variables[str(idest)] = src_vset
    DEBUG("{} -> {}".format(str(idest), src_vset))
    return src_vset

  def llil_reg_phi(self, expr):
    expr_vset = set()
    idest, isrc = get_opd_2(expr)
    for reg in isrc:
      if str(reg) in self.f_handler.ssa_variables.keys():
        expr_vset.update(self.f_handler.ssa_variables[str(reg)])
      else:
        expr_vset.add(str(reg))
    return expr_vset

  def llil_noret(self, expr):
    DEBUG("llil_noret not supported for the analysis")

  def llil_unimpl_mem(self, expr):
    DEBUG("llil_unimpl_mem not supported for the analysis")
