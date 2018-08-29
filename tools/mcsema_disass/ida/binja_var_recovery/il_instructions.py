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
      p_value = self.function.medium_level_il.get_ssa_var_value(ssa_var)
      return p_value
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
        var = SSAVariable(self.bv, ssa_var, self.bv.address_size, self.function)
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

  def has_memory_version(self, insn):
    if insn.ssa_memory_version > 0:
      return True

    mem0_insn = self.function.medium_level_il.get_ssa_memory_uses(0)
    if insn in mem0_insn:
      return True

    return False

  def has_memory_operation(self, insn):
    if insn is None:
      return False

    for token in insn.tokens:
      if token.type == binja.InstructionTextTokenType.RegisterToken:
        return True
    return False

  def get_variable_addr(self, expr):
    if expr is None:
      return None

    for token in expr.tokens:
      if token.type == binja.InstructionTextTokenType.PossibleAddressToken:
        if is_data_variable(self.bv, token.value):
          return token.value
    return None

  def get_variable_size(self, expr):
    operands = binja.MediumLevelILInstruction.ILOperations[expr.operation]
    index = 0
    for operand in operands:
      name, operand_type = operand
      if operand_type == "int":
        return self.bv.address_size
      elif operand_type == "float":
        return self.bv.address_size
      elif operand_type == "expr":
        opd = expr.operands[index]
        if opd.operation == binja.MediumLevelILOperation.MLIL_STORE_SSA or \
          opd.operation == binja.MediumLevelILOperation.MLIL_LOAD_SSA:
          return opd.size
        else:
          return self.get_variable_size(opd)
      index += 1
    return expr.size

  def is_memory_operation(self, expr):
    if expr is None:
      return False

    if expr.operation == binja.MediumLevelILOperation.MLIL_CALL_SSA:
      return False

    for token in expr.tokens:
      if token.type == binja.InstructionTextTokenType.RegisterToken:
        return True
    return False

  def memory_heauristic_analysis(self, insn, variable):
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
    for insn in dv_refs:
      if not self.is_memory_operation(insn):
        return

    if prev_dv is None:
      return

    prev_dv_func_set = set()
    for ref in self.bv.get_code_refs(prev_dv):
      llil = ref.function.get_low_level_il_at(ref.address)
      if llil is None:
        continue

      mlil = llil.medium_level_il
      if mlil is not None:
        prev_dv_func_set.add(ref.function.start)

    if prev_dv_func_set == dv_func_set:
      return
  
    VARIABLE_ALIAS_SET[variable].add(variable + self.get_variable_size(insn))
    VARIABLE_ALIAS_SET[variable + self.get_variable_size(insn)].add(variable)
    DEBUG("Size of the variable @ {:x} {}".format(variable, self.bv.address_size))

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
        self.memory_heauristic_analysis(self.insn, var_addr)

  def mlil_const(self, expr):
    return expr.constant

  def mlil_const_ptr(self, expr):
    return expr.constant

  def mlil_var_ssa(self, expr):
    pass

  def mlil_set_var_ssa(self, expr):
    variable_values = set()
    src_value_set = set()
    isrc = expr.src
    idest = expr.dest
    vars_read = self.insn.vars_read
    vars_written = self.insn.vars_written

    for var in vars_read:
      if isinstance(var, binja.SSAVariable):
        ssa_value = self.backward_analysis(var)
        set_comments(self.bv, self.insn.address, "test backward analysis : {} {}".format(var, ssa_value))

    if len(vars_written) > 1:
      DEBUG("Warning! vars_written > 1 for operation MLIL_SET_VAR_SSA")

    if isrc.operation == binja.MediumLevelILOperation.MLIL_CONST or \
      isrc.operation == binja.MediumLevelILOperation.MLIL_CONST_PTR:
      set_comments(self.bv, self.insn.address, "isrc : {:x}".format(isrc.constant))
      src_value_set.add(isrc.constant)
      #for var in vars_written:
      #  self.forward_analysis(var)

    elif isrc.operation == binja.MediumLevelILOperation.MLIL_VAR_SSA or \
      isrc.operation == binja.MediumLevelILOperation.MLIL_VAR_SSA_FIELD:
      if isrc.src in self.f_handler.ssa_variables.keys():
        ssa_value = self.f_handler.ssa_variables[isrc.src]
        src_value_set.update(ssa_value)
      else:
        ssa_value = self.get_ssa_var_values(isrc.src)
        if ssa_value != None:
          src_value_set.add(ssa_value)

    elif isrc.operation == binja.MediumLevelILOperation.MLIL_ZX:
      src = isrc.src
      if src.operation == binja.MediumLevelILOperation.MLIL_VAR_SSA or \
        src.operation == binja.MediumLevelILOperation.MLIL_VAR_SSA_FIELD:
        if src.src in self.f_handler.ssa_variables.keys():
          ssa_value = self.f_handler.ssa_variables[src.src]
          src_value_set.update(ssa_value)
        else:
          ssa_value = self.get_ssa_var_values(src.src)
          if ssa_value != None:
            src_value_set.add(ssa_value)

    elif isrc.operation == binja.MediumLevelILOperation.MLIL_LSL:
      ssa_value = self.evaluate_expression(isrc)
      src_value_set.update(ssa_value)

    else:
      set_comments(self.bv, self.insn.address, "isrc operation {}".format(isrc.operation.name))
      for var in vars_read:
        ssa_value = self.get_ssa_var_values(var)
        if ssa_value != None:
          ssa_value = self.backward_analysis(var)
          set_comments(self.bv, self.insn.address, "vars_read : {} {}".format(var, ssa_value))

    for var in vars_written:
      self.f_handler.ssa_variables[var].update(src_value_set)
      set_comments(self.bv, self.insn.address, "vars_written : {} {}".format(var, src_value_set))

  def mlil_set_var_ssa_field(self, expr):
    variable_values = set()
    src_value_set = set()
    isrc = expr.src
    idest = expr.dest
    vars_read = self.insn.vars_read
    vars_written = self.insn.vars_written
    
    for var in vars_read:
      ssa_value = self.backward_analysis(var)
      set_comments(self.bv, self.insn.address, "test backward analysis : {} {}".format(var, ssa_value))
    
    if len(vars_written) > 1:
      DEBUG("Warning! vars_written > 1 for operation MLIL_SET_VAR_SSA_FIELD")
    
    # Check if the variable is assigned a constant value. Not preserving the bitfields 
    # not update during assignments
    if isrc.operation == binja.MediumLevelILOperation.MLIL_CONST or \
      isrc.operation == binja.MediumLevelILOperation.MLIL_CONST_PTR:
      set_comments(self.bv, self.insn.address, "isrc : {:x}".format(isrc.constant))
      src_value_set.add(isrc.constant)
      #for var in vars_written:
      #  indices = self.forward_analysis(var)
      # set_comments(self.bv, self.insn.address, "forward analysis index : {}".format(indices))

    else:
      for var in vars_read:
        ssa_value = self.get_ssa_var_values(var)
        if ssa_value != None:
          src_value_set.add(ssa_value)
          ssa_value = self.backward_analysis(var)
          set_comments(self.bv, self.insn.address, "vars_read : {} {}".format(var, ssa_value))
    
    for var in vars_written:
      self.f_handler.ssa_variables[var].update(src_value_set)
      set_comments(self.bv, self.insn.address, "vars_written : {} {}".format(var, src_value_set))
  
  def mlil_load_ssa(self, expr):
    pass

  def mlil_if(self, expr):
    if self.has_memory_version(expr) is True:
      cond = expr.condition
      # Handle both direct and indirect memory accesses
      var = self.get_variable_addr(cond)
      if var is None:
        DEBUG("Warning! return expr is None expr {}".format(cond))
      else:
        VARIABLE_ALIAS_SET[var].add(var)

  def mlil_goto(self, expr):
    pass

  def mlil_ret(self, expr):
    value_set = set()
    isrc_list = expr.src
    for isrc in isrc_list:
      if isrc.operation == binja.MediumLevelILOperation.MLIL_VAR_SSA:
        ssa_var = isrc.src
        ssa_value = self.get_ssa_var_values(ssa_var)
        if ssa_value.type == binja.RegisterValueType.ConstantValue or \
          ssa_value.type == binja.RegisterValueType.ConstantPointerValue:
          value_set.add(ssa_value.value)
        else:
          value_set.add(str(ssa_value))
          
      elif isrc.operation == binja.MediumLevelILOperation.MLIL_CONST or \
        isrc.operation == binja.MediumLevelILOperation.MLIL_CONST_PTR:
        value_set.add(isrc.constant)
        
      else:
        expr_values = self.evaluate_expression(isrc)
        value_set.update(expr_values)
    
    DEBUG("mlil_ret expr {}  value_set {} ".format(expr, value_set))
    return value_set  

  def mlil_noret(self, expr):
    return set()

  def MLIL_STORE_SSA(self, expr):
    DEBUG("MLIL_STORE_SSA {}".format(expr))
    # handle the expr destination
    if isinstance(expr.dest, binja.MediumLevelILInstruction):
      idest = expr.dest
      DEBUG("MLIL_STORE_SSA idest {} type {}".format(idest, idest.operation.name))
      if idest.operation == binja.MediumLevelILOperation.MLIL_VAR_SSA:
        ssa_var = idest.src
        possible_values = idest.get_ssa_var_possible_values(ssa_var)
        if possible_values.type == binja.RegisterValueType.ConstantPointerValue:
          value = possible_values.value
          DEBUG("MLIL_STORE_SSA {}".format(value))
        else:
          DEBUG("MLIL_STORE_SSA {}".format(possible_values))
      elif idest.operation == binja.MediumLevelILOperation.MLIL_CONST_PTR:
        value = idest.constant
        size = expr.size
        DEBUG("MLIL_STORE_SSA {:x} size {}".format(value, size))
        VARIABLE_ALIAS_SET[value] = value + size
      elif idest.operation == binja.MediumLevelILOperation.MLIL_CONST_PTR:
        pass

    if isinstance(expr.src, binja.MediumLevelILInstruction):
      isrc = expr.src
      DEBUG("MLIL_STORE_SSA isrc {} type {}".format(isrc, isrc.operation.name))
      if isrc.operation == binja.MediumLevelILOperation.MLIL_CONST_PTR or \
        isrc.operation == binja.MediumLevelILOperation.MLIL_CONST:
        value = isrc.constant
        size = expr.size
        DEBUG("MLIL_STORE_SSA {:x} size {}".format(value, size))
        if is_data_variable(self.bv, value):
          VARIABLE_ALIAS_SET[value] = value + size
      else:
        operation_name = "{}".format(isrc.operation.name)
        if hasattr(self, operation_name):
          getattr(self, operation_name)(isrc)

  def MLIL_LOAD_SSA(self, expr):
    DEBUG("MLIL_LOAD_SSA {}".format(expr))
    # handle the expr source
    if isinstance(expr.src, binja.MediumLevelILInstruction):
      isrc = expr.src
      op = isrc.operation
      if op == binja.MediumLevelILOperation.MLIL_VAR_SSA:
        ssa_var = isrc.src
        possible_values = isrc.get_ssa_var_possible_values(ssa_var)
        if possible_values.type == binja.RegisterValueType.ConstantPointerValue:
          value = possible_values.value
          DEBUG("MLIL_LOAD_SSA {}".format(value))
        else:
          DEBUG("MLIL_LOAD_SSA {}".format(possible_values))

      elif op == binja.MediumLevelILOperation.MLIL_CONST_PTR:
        value = isrc.constant
        size = isrc.size
        DEBUG("MLIL_LOAD_SSA {} size {}".format(value, size))

    #operation_name = "{}".format(expr.dest.operation.name)
    #if hasattr(self, operation_name):
    #  getattr(self, operation_name)(expr.dest)

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