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

    if ssa_values:
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

  def get_ssa_reg_values(self, ssa_reg):
    ssa_reg_name = global_reg_name(self.function, ssa_reg)
    if ssa_reg_name in SSAVariableSet.keys():
      ssa_values = SSAVariableSet[ssa_reg_name]
      #DEBUG("get_ssa_reg_values {} -> {}".format(ssa_reg_name, ssa_values))
      return ssa_values
    else:
      var_handler = SSARegister(self.bv, ssa_reg, self.function)
      ssa_values = var_handler.backward_analysis(self.insn)
      #DEBUG("get_ssa_reg_values {} -> {}".format(ssa_reg_name, ssa_values))
      return ssa_values

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

# Low Level IL analysis to determine the possible values of the variables
  def _unarry_op(self, expr):
    """ Handle the unarry operand; if the operand is const, check if
        it has the xrefs or not
    """
    src_vset = set()
    if is_constant(self.bv, expr):
      value = get_constant(self.bv, expr)
      src_vset.add(Value(self.bv, value))
    else:
      src_vset = self.evaluate_expression(expr)
    return src_vset

  def llil_const(self, expr):
    value = get_constant(self.bv, expr)
    return set([Value(self.bv, value)])

  def llil_const_ptr(self, expr):
    value = get_constant(self.bv, expr)
    return set([Value(self.bv, value)])

  def llil_reg_ssa(self, expr):
    ssa_reg = expr.src
    ssa_values = self.get_ssa_reg_values(ssa_reg)
    return ssa_values

  def llil_reg_ssa_partial(self, expr):
    ssa_full_reg = expr.full_reg
    ssa_values = self.get_ssa_reg_values(ssa_full_reg)
    return ssa_values

  def llil_set_reg_ssa(self, expr):
    idest, isrc = get_opd_2(expr)
    name = global_reg_name(self.function, expr.dest)
    ssa_values = set()

    if name in SSAVariableSet.keys():
      return SSAVariableSet[name]

    if is_constant(self.bv, isrc):
      value = get_constant(self.bv, isrc)
      ssa_values.add(Value(self.bv, value))
      if has_xrefs(self.bv, value) and \
        has_address_xrefs(self.bv, expr, value):
        ADDRESS_REFS[value] = 0
    else:
      ssa_values = self.evaluate_expression(isrc)

    SSAVariableSet[name] = ssa_values
    DEBUG("{} -> {}".format(name, ssa_values))
    return ssa_values

  def llil_goto(self, expr):
    pass

  def llil_sx(self, expr):
    return self._unarry_op(expr.src)

  def llil_zx(self, expr):
    return self._unarry_op(expr.src)

  def llil_jump(self, expr):
    idest = expr.dest
    ssa_values = self.evaluate_expression(idest)

  def llil_lsl(self, expr):
    expr_vset = set()
    lvset = set()
    rvset = set()

    # Handle left operand
    ileft = expr.left
    if is_constant(self.bv, ileft):
      value = get_constant(self.bv, ileft)
      if has_xrefs(self.bv, value) and \
        has_address_xrefs(self.bv, expr, value):
        lvset.add(Values(value, value))
        ADDRESS_REFS[value] = 0
      else:
        lvset.add(value)
    else:
      lvset = self.evaluate_expression(expr.left)

    iright = expr.right
    if is_constant(self.bv, iright):
      value = get_constant(self.bv, iright)
      if has_xrefs(self.bv, value) and \
        has_address_xrefs(self.bv, expr, value):
        rvset.add(Values(value, value))
        ADDRESS_REFS[value] = 0
      else:
        rvset.add(value)
    else:
      rvset = self.evaluate_expression(expr.right)

    DEBUG("llil_lsl expr_vset {}".format(expr_vset))
    return expr_vset

  def llil_sub(self, expr):
    lvset = set()
    rvset = set()

    lvset = self.evaluate_expression(expr.left)
    if is_constant(self.bv, expr.right):
      iright = expr.right
      rvset.add(Value(self.bv, iright.constant))
    else:
      rvset = self.evaluate_expression(expr.right)

    ssa_values = set([l - r for l in lvset for r in rvset])
    DEBUG("llil_sub {}".format(ssa_values))
    return ssa_values

  def llil_add(self, expr):
    lvset = set()
    rvset = set()

    if is_constant(self.bv, expr.left):
      ileft = expr.left
      value = get_constant(self.bv, ileft)
      lvset.add(Value(self.bv, value))
      if has_xrefs(self.bv, value) and \
        has_address_xrefs(self.bv, expr, value):
        ADDRESS_REFS[ileft.constant] = 0
    else:
      lvset = self.evaluate_expression(expr.left)
      
    if is_constant(self.bv, expr.right):
      iright = expr.right
      value = get_constant(self.bv, iright)
      rvset.add(Value(self.bv, value))
      if has_xrefs(self.bv, value) and \
        has_address_xrefs(self.bv, expr, value):
        ADDRESS_REFS[iright.constant] = 0
    else:
      rvset = self.evaluate_expression(expr.right)

    ssa_values = set([l + r for l in lvset for r in rvset])
    DEBUG("llil_add {}".format(ssa_values))
    return ssa_values

  def llil_store_ssa(self, expr):
    DEBUG("llil_store_ssa {}".format(expr))
    idest, isrc = get_opd_2(expr)

    sz = isrc.size
    if is_constant(self.bv, idest):
      dest_memory = get_constant(self.bv, idest)
      dest_memset = set([Value(self.bv, dest_memory)])
      if has_xrefs(self.bv, dest_memory) and \
        has_memory_xrefs(self.bv, dest_memory):
        MEMORY_REFS[dest_memory] = sz
    else:
      dest_memset = self.evaluate_expression(idest)

    for item in dest_memset:
      if isinstance(item, Value):
        set_variables(self.bv, item.base_address, item.size + sz)

    DEBUG("llil_store_ssa {}".format(dest_memset))

  def llil_load_ssa(self, expr):
    DEBUG("llil_load_ssa {}".format(expr))
    isrc = get_opd_1(expr)

    sz = isrc.size
    if is_constant(self.bv, isrc):
      src_memory = get_constant(self.bv, isrc)
      src_memset = set([Value(self.bv, src_memory)])
      if has_xrefs(self.bv, src_memory) and \
        has_memory_xrefs(self.bv, src_memory):
        MEMORY_REFS[src_memory] = sz
    else:
      src_memset = self.evaluate_expression(isrc)

    for item in src_memset:
      if isinstance(item, Value):
        set_variables(self.bv, item.base_address, item.size + sz)

    ssa_values = set([SymbolicValue(self.bv, "memory load {}".format(src_memset))])
    return ssa_values

  def llil_cmp_e(self, expr):
    lvset = self.evaluate_expression(expr.left)
    rvset = self.evaluate_expression(expr.right)
    DEBUG("llil_cmp_e {} left {}, right {}".format(expr, lvset, rvset))

  def llil_cmp_ne(self, expr):
    lvset = self.evaluate_expression(expr.left)
    rvset = self.evaluate_expression(expr.right)
    DEBUG("llil_cmp_ne {} left {}, right {}".format(expr, lvset, rvset))

  def llil_if(self, expr):
    cond = self.evaluate_expression(expr.condition)
    DEBUG("llil_if {} -> {}".format(expr.condition, cond))

  ssa_variable_set = set()
  def llil_reg_phi(self, expr):
    idest, isrc = get_opd_2(expr)
    reg_name = global_reg_name(self.function, idest)
    if reg_name in SSAVariableSet.keys():
      return SSAVariableSet[reg_name]

    ssa_values = set()
    for ssa_reg in isrc:
      if str(ssa_reg) not in SSARegister.ssa_variable_set:
        ILInstruction.ssa_variable_set.add(str(ssa_reg))
        reg_handler = SSARegister(self.bv, ssa_reg, self.function)
        ssa_values.update(reg_handler.backward_analysis(self.insn))
        ILInstruction.ssa_variable_set.remove(str(ssa_reg))

    SSAVariableSet[reg_name] = ssa_values
    DEBUG("llil_reg_phi ssa values {} -> {}".format(reg_name, ssa_values))
    return ssa_values

  def llil_call_ssa(self, expr):
    DEBUG("Analyze low level IL llil_call_ssa")
    call_parameters = call_params(self.bv, expr)
    if call_parameters != None:
      for param in call_parameters:
        ssa_values = self.get_ssa_reg_values(param.src)
        DEBUG("param {} -> {}".format(param.src, ssa_values))

    target = call_target(self.bv, expr)
    try:
      sym_value = FUNCTION_OBJECTS[target].get_return_set()
    except KeyError:
      sym_value = set([SymbolicValue(self.bv, "Return {}".format(hex(target) if isinstance(target, long) else target), 0)])
    for out in get_call_output(self.bv, expr):
      SSAVariableSet[global_reg_name(self.function, out)].update(sym_value)

  def llil_tailcall_ssa(self, expr):
    DEBUG("Analyze low level IL llil_tailcall_ssa")
    call_parameters = call_params(self.bv, expr)
    if call_parameters != None:
      for param in call_parameters:
        ssa_values = self.get_ssa_reg_values(param.src)
        DEBUG("param {} -> {}".format(param.src, ssa_values))

  def llil_ret(self, expr):
    ssa_values = self.evaluate_expression(expr.dest)
    DEBUG("llil_ret ssa values {} {}".format(expr.dest, ssa_values))
    return ssa_values

  def llil_noret(self, expr):
    DEBUG("llil_noret not supported for the analysis")

  def llil_unimpl_mem(self, expr):
    DEBUG("llil_unimpl_mem not supported for the analysis")
