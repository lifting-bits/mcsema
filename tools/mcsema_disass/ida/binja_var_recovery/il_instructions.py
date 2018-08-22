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
    self.func_obj = FUNCTION_OBJECTS[func.start]
    self.ssa_variables = collections.defaultdict(set)

  def get_ssa_var_possible_values(self, ssa_var):
    if ssa_var is None:
      return None

    var_name = "{}#{}".format(ssa_var.var.name, ssa_var.version)
    p_value = self.insn.get_ssa_var_possible_values(ssa_var)
    if p_value.type == binja.RegisterValueType.EntryValue:
      value_set = self.func_obj.get_entry_register(p_value.reg)
      if value_set is None:
        self.ssa_variables[var_name].add(p_value)
      else:
        self.ssa_variables[var_name].update(value_set)
    elif p_value.type != binja.RegisterValueType.UndeterminedValue:
      self.ssa_variables[var_name].add(p_value)
    else:
      var = SSAVariable(self.bv, ssa_var, self.bv.address_size, self.function)
      self.ssa_variables[var_name].update(var.get_values())

    return var_name, self.ssa_variables[var_name]

  def MLIL_IF(self, expr):
    pass

  def MLIL_GOTO(self, expr):
    pass

  def MLIL_SET_VAR_SSA(self, expr):
    if isinstance(expr.dest, binja.SSAVariable):
      var_name, value_set = self.get_ssa_var_possible_values(expr.dest)
      self.func_obj.add_ssa_variables(var_name, value_set, self.insn)
      DEBUG("{} -> {}".format(var_name, value_set))
    else:
      DEBUG("MLIL_SET_VAR_SSA {}".format(expr))

  def MLIL_SET_VAR_ALIASED(self, expr):
    if isinstance(expr.dest, binja.SSAVariable):
      var_name, value_set = self.get_ssa_var_possible_values(expr.dest)
      self.func_obj.add_ssa_variables(var_name, value_set, self.insn)
      DEBUG("{} -> {}".format(var_name, value_set))
    else:
      DEBUG("MLIL_SET_VAR_ALIASED {}".format(expr))

  def MLIL_VAR_SSA(self, expr):
    DEBUG("MLIL_VAR_SSA {}".format(expr))
    if isinstance(expr.src, binja.SSAVariable):
      var_name, value_set = self.get_ssa_var_possible_values(expr.src)
      self.func_obj.add_ssa_variables(var_name, value_set, self.insn)
      for entry in value_set:
        DEBUG("MLIL_VAR_SSA {}".format(entry))

  def MLIL_CONST(self, expr):
    DEBUG("MLIL_CONST {}".format(expr))
    return expr.constant

  def MLIL_CONST_PTR(self, expr):
    DEBUG("MLIL_CONST_PTR {}".format(expr))
    return expr.constant

  def MLIL_RET(self, expr):
    DEBUG("MLIL_RET {}".format(expr))
    isrc = expr.src
    for item in isrc:
      if item.operation == binja.MediumLevelILOperation.MLIL_VAR_SSA:
        ssa_var = item.src
        possible_value = expr.get_ssa_var_possible_values(ssa_var)
        DEBUG("Expr {} {}".format(item, possible_value))
        if possible_value.type == binja.RegisterValueType.EntryValue:
          value_set = self.func_obj.get_entry_register(possible_value.reg)
          DEBUG("value_set {} ".format(pprint.pformat(value_set)))
          self.func_obj.return_set.update(value_set)
          
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
        VARIABLE_ALIAS_SET.add(value, value + size)
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
          VARIABLE_ALIAS_SET.add(value, value + size)
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
            VARIABLE_ALIAS_SET.add(p_value.value, p_value.value + 8)
            if called_function_object:
              called_function_object.update_register(reg_name, p_value.value)

        elif p_value.type == binja.RegisterValueType.ConstantValue:
          if is_data_variable(self.bv, p_value.value):
            VARIABLE_ALIAS_SET.add(p_value.value, p_value.value + 8)
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