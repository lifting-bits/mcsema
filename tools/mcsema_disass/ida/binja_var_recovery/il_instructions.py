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
    possible_value = self.insn.get_ssa_var_possible_values(ssa_var)
    if possible_value.type == binja.RegisterValueType.EntryValue:
      value_set = self.func_obj.get_entry_register(possible_value.reg)
      if value_set is None:
        self.ssa_variables[var_name].add(possible_value)
      else:
        self.ssa_variables[var_name].update(value_set)
    elif possible_value.type != binja.RegisterValueType.UndeterminedValue:
      self.ssa_variables[var_name].add(possible_value)
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

    values = set()
    idest = expr.dest
    for index in range(len(expr.params)):
      parameter = expr.params[index]
      possible_value = parameter.possible_values

      if possible_value.type == binja.RegisterValueType.ConstantPointerValue:
        if is_data_variable(self.bv, possible_value.value):
          VARIABLE_ALIAS_SET.add(possible_value.value, possible_value.value + 8)

      elif possible_value.type == binja.RegisterValueType.ConstantValue:
        if is_data_variable(self.bv, possible_value.value):
          VARIABLE_ALIAS_SET.add(possible_value.value, possible_value.value + 8)
    
      elif possible_value.type != binja.RegisterValueType.UndeterminedValue:
        DEBUG("param values  {}".format(possible_value))

      else:
        ssa_var = SSAVariable(self.bv, parameter.src, self.bv.address_size, self.function)
        ssa_value = ssa_var.get_values()
        DEBUG("param values  {}".format(ssa_value))

    if idest.operation == binja.MediumLevelILOperation.MLIL_CONST_PTR or \
      idest.operation == binja.MediumLevelILOperation.MLIL_CONST:
      called_function = self.bv.get_function_at(idest.constant)
      if called_function != None and called_function.can_return:
        if called_function.symbol.type == binja.SymbolType.ImportedFunctionSymbol:
          DEBUG("Skipping external function '{}'".format(called_function.symbol.name))
          values.update(["<ReturnValueExternal {:x}>".format(called_function.symbol.address)])
        else:
          DEBUG("Warning! handle function '{}'".format(called_function.symbol.name))
          values.update(["<ReturnValueInternal {:x}>".format(called_function.symbol.address)])
          #DEBUG_PUSH()
          #if called_function.symbol.address != self.function.start:
          #  func_obj = FUNCTION_OBJECTS[called_function.symbol.address]
          #  func_obj.recover_instructions()
          #  values.update(func_obj.return_set)
          #DEBUG_POP()

      ssa_vars_output = expr.output.vars_written
      if len(ssa_vars_output) > 0:
        for ssa_var in ssa_vars_output:
          var_name, ssa_value = self.get_ssa_var_possible_values(ssa_var)
          values.update(ssa_value)
          self.func_obj.add_ssa_variables(var_name, values, self.insn)
          DEBUG("{} -> {}".format(var_name, values))


  def process_instruction(self):
    var_name = None
    insn_op = self.insn.operation
    if insn_op == binja.MediumLevelILOperation.MLIL_SET_VAR_SSA:
      if isinstance(self.insn.dest, binja.SSAVariable):
        ssa_var = self.insn.dest
        possible_values = self.insn.get_ssa_var_possible_values(ssa_var)
        if possible_values.type != binja.RegisterValueType.UndeterminedValue:
          var_name = "{}#{}".format(ssa_var.var.name, ssa_var.version)
          self.ssa_variables[var_name].append(possible_values) 
        else:
          var = SSAVariable(self.bv, self.insn.dest, self.bv.address_size, self.function)
          var_name = "{}#{}".format(ssa_var.var.name, ssa_var.version)
          self.ssa_variables[var_name].append(var.get_values())
        self.func_obj.add_ssa_variables(var_name, self.ssa_variables[var_name], self.insn)

    elif insn_op ==  binja.MediumLevelILOperation.MLIL_STORE_SSA:
      insn_dest = self.insn.dest
      insn_src = self.insn.src
      self.handle_store()
    elif insn_op ==  binja.MediumLevelILOperation.MLIL_LOAD_SSA:
      value = self.insn.src
      self.handle_load()

    elif insn_op == binja.MediumLevelILOperation.MLIL_VAR_PHI:
      insn_src = self.insn.src
      for ssa_var in insn_src:
        possible_value = self.insn.get_ssa_var_possible_values(ssa_var)
        if possible_value.type == binja.RegisterValueType.UndeterminedValue:
          var = SSAVariable(self.bv, ssa_var, self.bv.address_size, self.function)
          value_set = var.get_values()
          var_name = "{}#{}".format(ssa_var.var.name, ssa_var.version)
          self.ssa_variables[var_name].append(value_set)
        else:
          var_name = "{}#{}".format(ssa_var.var.name, ssa_var.version)
          self.ssa_variables[var_name].append(possible_value)
        self.func_obj.add_ssa_variables(var_name, self.ssa_variables[var_name], self.insn)

    elif insn_op  == binja.MediumLevelILOperation.MLIL_SET_VAR_ALIASED:
      if isinstance(self.insn.dest, binja.SSAVariable):
        ssa_var = self.insn.dest
        possible_values = self.insn.get_ssa_var_possible_values(ssa_var)
        if possible_values.type != binja.RegisterValueType.UndeterminedValue:
          var_name = "{}#{}".format(ssa_var.var.name, ssa_var.version)
          self.ssa_variables[var_name].append(possible_values) 
        else:
          var = SSAVariable(self.bv, self.insn.dest, self.bv.address_size, self.function)
          var_name = "{}#{}".format(ssa_var.var.name, ssa_var.version)
          self.ssa_variables[var_name].append(var.get_values())
        self.func_obj.add_ssa_variables(var_name, self.ssa_variables[var_name], self.insn)

      elif isinstance(self.insn.src, binja.MediumLevelILInstruction):
        var = SSAVariable(self.bv, self.insn.src, self.bv.address_size)
        value = var.get_values()
  
  def handle_store(self):
    index = 0
    src_value = 0
    dest_addr = 0
    insn_src = self.insn.src
    insn_dest = self.insn.dest

    # Handle the instruction src to check what value is getting written in the
    operands = binja.MediumLevelILInstruction.ILOperations[insn_src.operation]
    for operand in operands:
      name, operand_type = operand
      if operand_type == "int":
        value = insn_src.operands[index]
        addr = convert_signed32(value)
        DEBUG("handle_store: src operand value {:x} @ {}".format(addr, self.function.name))
        dv = self.bv.get_data_var_at(addr)
        if dv is not None:
          DEBUG("Source operand referring to variable at {:x}".format(addr))

        src_value = addr
      elif operand_type == "expr":
        value = insn_src.operands[index]
        DEBUG("handle_store: evalue expr {} @ {}".format(value, self.function.name))
      index += 1

    index = 0
    operands = binja.MediumLevelILInstruction.ILOperations[insn_dest.operation]
    for operand in operands:
      name, operand_type = operand
      DEBUG("dest operand type {}".format(operand_type))
      if operand_type == "int":
        value = insn_dest.operands[index]
        DEBUG("{} {:x}".format(self.function.name, convert_signed32(value)))
        addr = convert_signed32(value)
        dest_addr = addr
        dv = self.bv.get_data_var_at(addr)
        #if dv is not None:
        #  VARIABLES_TO_RECOVER[addr] = _create_variable_entry("recovered_global_{:x}".format(addr), addr)
      elif operand_type == "expr":
        value = insn_dest.operands[index]
        DEBUG("handle_store: evalue expr {} @ {}".format(value, self.function.name))
      elif operand_type == "var_ssa":
        value = insn_dest.operands[index]
        possible_value = self.insn.get_ssa_var_possible_values(value)
        ssa_var = SSAVariable(insn_dest.operands[index], self.bv.address_size, self.function)
        ssa_var.get_values()
        DEBUG("handle_store: ssa variable {} @ {}".format(possible_value, self.function.name))
      index += 1

  def handle_load(self):
    index = 0
    isrc = self.insn.src
    idest = self.insn.dest

    operands = binja.MediumLevelILInstruction.ILOperations[isrc.operation]
    for operand in operands:
      name, operand_type = operand
      if operand_type == "int":
        value = isrc.operands[index]
        DEBUG("{} {:x}".format(self.function.name, convert_signed32(value)))
        addr = convert_signed32(value)
        dv = bv.get_data_var_at(addr)
      elif operand_type == "expr":
        value = isrc.operands[index]
        DEBUG("handle_load: evalue expr {} @ {}".format(value, self.function.name))
      index += 1
