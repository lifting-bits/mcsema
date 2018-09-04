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
from operator import or_
import binaryninja as binja
from binja_var_recovery.util import *
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
      DEBUG("Calling operation {}".format(operation_name))
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
      #set_comments(self.bv, self.insn.address, "forward analysis index : {} {}".format(index, insn.operation.name))
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

  def is_memory_operation(self, expr):
    if expr.operation != binja.MediumLevelILOperation.MLIL_CALL_SSA and \
      self.get_memory_version(expr) != None:
      return True
    return False

  def variable_size_heuristic(self, insn, variable):
    dv = self.bv.get_data_var_at(variable)
    prev_dv = self.bv.get_previous_data_var_before(variable)

    dv_refs = list()
    dv_func_set = set()
    for ref in self.bv.get_code_refs(variable):
      llil = ref.function.get_low_level_il_at(ref.address)
      if llil is None:
        continue

      mlil = llil.medium_level_il
      if mlil is not None:
        dv_refs.append(mlil.ssa_form)
        dv_func_set.add(ref.function.start)

    # Check if there is a reference by address to the data variable
    for ins in dv_refs:
      if self.get_memory_version(ins) is None:
        DEBUG("variable_size_heuristic return {}".format(ins))
        return None

    prev_dv_func_set = set()

    if prev_dv != None:
      for ref in self.bv.get_code_refs(prev_dv):
        llil = ref.function.get_low_level_il_at(ref.address)
        if llil is None:
          continue

        mlil = llil.medium_level_il
        if mlil is not None:
          prev_dv_func_set.add(ref.function.start)

      if sorted(prev_dv_func_set) >= sorted(dv_func_set):
        return None

    DEBUG("Variable into alias set 1 @ {:x}".format(variable, self.bv.address_size))
    DEBUG("Variable into alias set 2 @ {:x}".format(variable + self.get_variable_size(insn), self.bv.address_size))
    return self.get_variable_size(insn)

  def analyse_memory(self):
    """ Heauristic analysis of direct memory operations
    """
    if self.insn is None:
      return

    if self.insn.operation == binja.MediumLevelILOperation.MLIL_CALL_SSA:
      return

    if self.is_memory_operation(self.insn):
      var_addr = self.get_variable_addr(self.insn)
      if var_addr != None:
        self.variable_size_heuristic(self.insn, var_addr)

  def mlil_const(self, expr):
    return expr.constant

  def mlil_const_ptr(self, expr):
    return expr.constant

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

    if isrc.operation == binja.MediumLevelILOperation.MLIL_CONST or \
      isrc.operation == binja.MediumLevelILOperation.MLIL_CONST_PTR:
      set_comments(self.bv, self.insn.address, "isrc : {:x}".format(isrc.constant))
      src_value_set.add(Values(isrc.constant, DIRECT_ADDRESS_META))
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
    if isrc.operation == binja.MediumLevelILOperation.MLIL_CONST or \
      isrc.operation == binja.MediumLevelILOperation.MLIL_CONST_PTR:
      set_comments(self.bv, self.insn.address, "isrc : {:x}".format(isrc.constant))
      src_value_set.add(Values(isrc.constant, DIRECT_ADDRESS_META))
    else:
      src_value_set = self.evaluate_expression(isrc)

    for var in expr.vars_written:
      self.f_handler.ssa_variables[str(var)].update(src_value_set)
      set_comments(self.bv, self.insn.address, "vars_written : {} {}".format(var, src_value_set))

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

  def mlil_ret(self, expr):
    value_set = set()
    isrc_list = expr.src
    for isrc in isrc_list:
      if isrc.operation == binja.MediumLevelILOperation.MLIL_CONST or \
        isrc.operation == binja.MediumLevelILOperation.MLIL_CONST_PTR:
        value_set.add(Values(isrc.constant, "d"))
      else:
        expr_values = self.evaluate_expression(isrc)
        value_set.update(expr_values)
    
    DEBUG("mlil_ret expr {}  value_set {} ".format(expr, value_set))
    return value_set  

  def mlil_noret(self, expr):
    return set()

  def mlil_store_ssa(self, expr):
    idest, isrc = get_opd_2(expr)
    if idest.operation == binja.MediumLevelILOperation.MLIL_CONST or \
      idest.operation == binja.MediumLevelILOperation.MLIL_CONST_PTR:
      dest_memory = idest.constant
      if is_data_variable(self.bv, dest_memory):
        if self.variable_size_heuristic(self.insn, dest_memory) is not None:
          DEBUG("Found variable memory {:x}".format(dest_memory))
          MEMORY_REFS[dest_memory] = expr.size

    else:
      dest_memory_set = self.evaluate_expression(idest)
      set_comments(self.bv, self.insn.address, "expression : {} {}".format(idest, dest_memory_set))

  def mlil_load_ssa(self, expr):
    src_value_set = set()
    isrc = get_opd_1(expr)
    if isrc.operation == binja.MediumLevelILOperation.MLIL_CONST or \
      isrc.operation == binja.MediumLevelILOperation.MLIL_CONST_PTR:
      src_memory = isrc.constant
      if is_data_variable(self.bv, src_memory):
        if self.variable_size_heuristic(self.insn, src_memory) is not None:
          DEBUG("Found variable memory {:x}".format(src_memory))
          MEMORY_REFS[src_memory] = expr.size
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
    vars_read = expr.vars_read
    for var in vars_read:
      if isinstance(var, binja.SSAVariable):
        if str(var) not in self.f_handler.ssa_variables.keys():
          ssa_value = self.get_ssa_var_values(var)
          self.f_handler.ssa_variables[str(var)] = ssa_value
        DEBUG("mlil_add ssa variable {} -> {}".format(str(var), self.f_handler.ssa_variables[str(var)]))

    # Handle left operand
    if expr.left.operation == binja.MediumLevelILOperation.MLIL_CONST or \
      expr.left.operation == binja.MediumLevelILOperation.MLIL_CONST_PTR:
      left_values = expr.left.constant
      if is_data_variable(self.bv, left_values):
        ADDRESS_REFS[left_values] = 0

    else:
      left_values = self.evaluate_expression(expr.left)

    # Handle right operand
    if expr.right.operation == binja.MediumLevelILOperation.MLIL_CONST or \
      expr.right.operation == binja.MediumLevelILOperation.MLIL_CONST_PTR:
      right_values = expr.right.constant
      if is_data_variable(self.bv, right_values):
        ADDRESS_REFS[right_values] = 0
    else:
      right_values = self.evaluate_expression(expr.right)

    if isinstance(left_values, long):
      if is_data_variable(self.bv, left_values):
        if "<undetermined>" not in right_values and len(right_values) > 0:
          max_size = max(right_values)
          DEBUG("mlil_add Found memory with size {:x} -> {}".format(left_values, max_size))
          expr_value_set.add(left_values + max_size)
        else:
          expr_value_set.add("<undetermined>")

    elif isinstance(right_values, long):
      if is_data_variable(self.bv, right_values):
        if "<undetermined>" not in left_values and len(left_values) > 0:
          max_size = max(left_values)
          DEBUG("mlil_add Found memory with size {:x} -> {}".format(right_values, max_size))
          expr_value_set.add(right_values + max_size)
        else:
          expr_value_set.add("<undetermined>")
    else:
      pass

    DEBUG("mlil_add expr_value_set {}".format(expr_value_set))
    return expr_value_set

  def mlil_var_phi(self, expr):
    src_value_set = set()
    src_value_set.add("<undetermined>")
    return src_value_set

  def MLIL_CALL_SSA(self, expr):
    if isinstance(expr.params, binja.MediumLevelILInstruction):
      DEBUG("Warning! unhandled MLIL_CALL_SSA {}".format(expr))
      return

    values_set = set()
    idest = expr.dest
    called_function = None
    called_function_object = None

    if idest.operation == binja.MediumLevelILOperation.MLIL_CONST_PTR or idest.operation == binja.MediumLevelILOperation.MLIL_CONST:
      called_function = self.bv.get_function_at(idest.constant)
      if called_function is None:
        return

      try:
        called_function_object = FUNCTION_OBJECTS[called_function.start]
      except KeyError:
        called_function_object = None

      if called_function != None and called_function.can_return:
        if called_function.symbol.type == binja.SymbolType.ImportedFunctionSymbol:
          DEBUG("Skipping external function '{}'".format(called_function.symbol.name))
          values_set.update(["<ReturnValueExternal {:x}>".format(called_function.symbol.address)])
        else:
          DEBUG("Warning! handle function '{}'".format(called_function.symbol.name))
          values_set.update(["<ReturnValueInternal {:x}>".format(called_function.symbol.address)])

      for index in range(len(expr.params)):
        parameter = expr.params[index]
        p_value = parameter.possible_values

        try:
          reg_name = PARAM_REGISTERS_INDEX[index]
        except KeyError:
          reg_name = None

        if p_value.type == binja.RegisterValueType.ConstantPointerValue:
          if is_data_variable(self.bv, p_value.value):
            VARIABLE_ALIAS_SET[p_value.value] = p_value.value + 8
            if called_function_object:
              called_function_object.update_register(reg_name, p_value.value)

        elif p_value.type == binja.RegisterValueType.ConstantValue:
          if is_data_variable(self.bv, p_value.value):
            VARIABLE_ALIAS_SET[p_value.value] = p_value.value + 8
            if called_function_object:
              called_function_object.update_register(reg_name, p_value.value)

        elif p_value.type != binja.RegisterValueType.UndeterminedValue:
          if called_function_object:
            called_function_object.update_register(reg_name, p_value)
        else:
          ssa_var = SSAVariable(self.bv, parameter.src, self.bv.address_size, self.function)
          ssa_value = ssa_var.get_values()
          if called_function_object:
            called_function_object.update_register(reg_name, ssa_value)

          DEBUG("param values  {}".format(ssa_value))

      ssa_vars_output = expr.output.vars_written
      if len(ssa_vars_output) > 0:
        for ssa_var in ssa_vars_output:
          var_name, ssa_value = self.get_ssa_var_possible_values(ssa_var)
          values_set.update(ssa_value)
          self.func_obj.add_ssa_variables(var_name, values_set, self.insn)
          DEBUG("{} -> {}".format(var_name, values_set))