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
import binaryninja as binja
from binja_var_recovery.util import *

FUNCTION_OBJECTS = dict()
VARIABLE_AS_PARAMS = dict()

class ILVisitor(object):
  """ Class functions to visit medium-level IL"""
  def __init__(self):
    super(ILVisitor, self).__init__()

  def visit(self, expr):
    method_name = 'visit_{}'.format(expr.operation.name)
    DEBUG("calling... {}".format(method_name))
    if hasattr(self, method_name):
      value = getattr(self, method_name)(expr)
    else:
      value = None
    return value

  def visit_MLIL_CONST(self, expr):
    DEBUG("visit_MLIL_CONST : {}".format(expr))
    return expr.constant

  def visit_MLIL_CONST_PTR(self, expr):
    DEBUG("visit_MLIL_CONST_PTR : {}".format(expr))
    return expr.constant

  def visit_MLIL_VAR(self, expr):
    pass

  def visit_MLIL_ZX(self, expr):
    src = self.visit(expr.src)
    DEBUG("visit_MLIL_ZX : {}".format(src))
    return src

  def visit_MLIL_SET_VAR(self, expr):
    DEBUG("visit_MLIL_SET_VAR : {}".format(expr))
    src = self.visit(expr.src)
    pass

  def visit_MLIL_LOAD(self, expr):
    pass

  def visit_MLIL_STORE(self, expr):
    pass

  def visit_MLIL_SET_VAR_SSA(self, expr):
    pass

  def visit_MLIL_VAR_SSA(self, expr):
    pass

class SSAVariable(ILVisitor):
  def __init__(self, var, address_size, func=None):
    super(SSAVariable, self).__init__()
    self.address_size = address_size
    self.var = var
    if isinstance(var, binja.MediumLevelILInstruction):
      self.function = var.function
    else:
      self.function = func.medium_level_il.ssa_form
    self.visited = set()
    self.to_visit = list()
    self.value_set = set()

  def get_values(self):
    if isinstance(self.var, binja.MediumLevelILInstruction):
      var_def = self.function.get_ssa_var_definition(self.var.src)
    else:
      var_def = self.function.get_ssa_var_definition(self.var)
    
    self.to_visit.append(var_def)
    while self.to_visit:
      idx = self.to_visit.pop()
      if idx is not None:
        DEBUG("visit {}".format(self.function[idx]))
        self.visit(self.function[idx])

    return self.value_set

  def visit_MLIL_SET_VAR_ALIASED(self, expr):
    DEBUG("visit_MLIL_SET_VAR_ALIASED: {}".format(expr))
    src = self.visit(expr.src)
    return src

  def visit_MLIL_SET_VAR_SSA(self, expr):
    ssa_var = expr.dest
    if isinstance(ssa_var, binja.SSAVariable):
      possible_value = expr.get_ssa_var_possible_values(ssa_var)
      if possible_value.type != binja.RegisterValueType.UndeterminedValue:
        self.value_set.add(possible_value)
        DEBUG("visit_MLIL_SET_VAR_SSA: possible values {}".format(possible_value))
      else:
        src = self.visit(expr.src)
    else:
      DEBUG("visit_MLIL_SET_VAR_SSA: Warning! The dest is not ssa variable")

    return self.value_set

  def visit_MLIL_VAR_SSA(self, expr):
    """ Get the possible value of the ssa variable
    """
    ssa_var = expr.src
    if isinstance(ssa_var, binja.SSAVariable):
      possible_value = expr.get_ssa_var_possible_values(ssa_var)
      
      if possible_value.type == binja.RegisterValueType.EntryValue:
        func = expr.function
        DEBUG("Variable name register {} {:x}".format(possible_value.reg, func.current_address))
        self.value_set.add(possible_value)
        return self.value_set

      elif possible_value.type == binja.RegisterValueType.ConstantValue:
        DEBUG("Variable constant value {:x}".format(possible_value.value))
        self.value_set.add(possible_value)
        return self.value_set

      elif possible_value.type == binja.RegisterValueType.UndeterminedValue:
        DEBUG("Undetermined value {} {}".format(possible_value, ssa_var.var.name))
        if ssa_var.var.name == "__return_addr":
          self.value_set.add(ssa_var)
          return self.value_set

    if expr.src not in self.visited:
      var_def = expr.function.get_ssa_var_definition(expr.src)
      if var_def is not None:
        self.to_visit.append(var_def)

  def visit_MLIL_LOAD_SSA(self, expr):
    """ Resolve the SSA Variable performing memory load
    """
    DEBUG("visit_MLIL_LOAD_SSA {}".format(expr))
    isrc = expr.src
    operands = binja.MediumLevelILInstruction.ILOperations[isrc.operation]


class Function(object):
  """ The function objects
  """
  def __init__(self, bv, func):
    self.bv = bv
    self.func = func
    self.start_addr = func.start
    self.params = list()
    self.ssa_variables = collections.defaultdict(list)

  def collect_parameters(self):
    if self.func is None:
      return

    num_params = len(self.func.parameter_vars)
    for ref in self.bv.get_code_refs(self.start_addr):
      ref_function = ref.function
      insn_il = ref_function.get_low_level_il_at(ref.address).medium_level_il
      insn_il_ssa = insn_il.ssa_form if insn_il is not None else None
      if insn_il_ssa is None:
        continue
      
      DEBUG("Function referred : {} {}".format(ref_function, insn_il_ssa))
      if not hasattr(insn_il_ssa, "params"):
        continue

      if isinstance(insn_il_ssa.params, binja.MediumLevelILInstruction):
        continue

      num_params = len(insn_il_ssa.params) if insn_il_ssa is not None else 0
      for index in range(num_params):
        if insn_il_ssa is not None:
          param = insn_il_ssa.params[index]
          possible_value = param.possible_values
          DEBUG("param {} : {} {} possible_values {}".format(index, param, param.operation, possible_value))
          
          if possible_value.type != binja.RegisterValueType.UndeterminedValue:
            param_value = str(possible_value)
          else:
            ssa_var = SSAVariable(param, self.bv.address_size)
            value_set = ssa_var.get_values()
            DEBUG("param value_set  {}".format(value_set))
            param_value = param
          
          if len(self.params) > index:
            value_set = self.params[index]
            value_set.add(param_value)
            self.params[index] = value_set
          else:
            value_set = set()
            value_set.add(param_value)
            self.params.append(value_set)

      DEBUG("collect_parameters {}".format(pprint.pformat(self.params)))
      # Collect the const ptr from the passed variables
      for args in self.params:
        DEBUG("parameter  {}".format(pprint.pformat(args)))
        for item in args:
          DEBUG("parameter 1  {}".format(pprint.pformat(item)))
          if isinstance(item, binja.PossibleValueSet):
            if item.type == binja.RegisterValueType.ConstantPointerValue:
              VARIABLE_AS_PARAMS[item.value] = 1

  def add_ssa_variables(self, var, value_set):
    try:
      self.ssa_variables[var].append(value_set)
    except KeyError:
      DEBUG("Variable Key is not found {}".format(var))
    DEBUG("add_ssa_variables {}".format(pprint.pformat(self.ssa_variables)))

  def print_ssa_variables(self):
    if len(self.ssa_variables) == 0:
      return
    
    DEBUG("SSA Variables in the function {}".format(pprint.pformat(self.ssa_variables)))

class ILInstruction(object):
  def __init__(self, bv, func, insn_il):
    self.insn = insn_il
    self.address = insn_il.address
    self.bv = bv
    self.function = func
    self.ssa_variables = collections.defaultdict(list)
    
  def process_instruction(self):
    insn_op = self.insn.operation
    if insn_op == binja.MediumLevelILOperation.MLIL_SET_VAR_SSA:
      if isinstance(self.insn.dest, binja.SSAVariable):
        ssa_var = self.insn.dest
        possible_values = self.insn.get_ssa_var_possible_values(ssa_var)
        if possible_values.type != binja.RegisterValueType.UndeterminedValue:
          var_name = "{}#{}".format(ssa_var.var.name, ssa_var.version)
          self.ssa_variables[var_name].append(possible_values) 
        else:
          var = SSAVariable(self.insn.dest, self.bv.address_size, self.function)
          var_name = "{}#{}".format(ssa_var.var.name, ssa_var.version)
          self.ssa_variables[var_name].append(var.get_values())

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
        DEBUG("VAR_PHI {} {}".format(ssa_var, possible_value))
        if possible_value.type == binja.RegisterValueType.UndeterminedValue:
          var = SSAVariable(ssa_var, self.bv.address_size, self.function)
          value_set = var.get_values()
          var_name = "{}#{}".format(ssa_var.var.name, ssa_var.version)
          self.ssa_variables[var_name].append(value_set)
        else:
          var_name = "{}#{}".format(ssa_var.var.name, ssa_var.version)
          self.ssa_variables[var_name].append(possible_value) 

    elif insn_op  == binja.MediumLevelILOperation.MLIL_SET_VAR_ALIASED:
      DEBUG("MLIL_SET_VAR_ALIASED {} {}".format(type(self.insn.src), self.insn.dest))
      if isinstance(self.insn.dest, binja.SSAVariable):
        ssa_var = self.insn.dest
        possible_values = self.insn.get_ssa_var_possible_values(ssa_var)
        if possible_values.type != binja.RegisterValueType.UndeterminedValue:
          var_name = "{}#{}".format(ssa_var.var.name, ssa_var.version)
          self.ssa_variables[var_name].append(possible_values) 
        else:
          var = SSAVariable(self.insn.dest, self.bv.address_size, self.function)
          var_name = "{}#{}".format(ssa_var.var.name, ssa_var.version)
          self.ssa_variables[var_name].append(var.get_values())

      elif isinstance(self.insn.src, binja.MediumLevelILInstruction):
        var = SSAVariable(self.insn.src, self.bv.address_size)
        value = var.get_values()

    DEBUG("process_instruction {}".format(pprint.pformat(self.ssa_variables)))
  
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
