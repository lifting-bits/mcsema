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
import binaryninja as binja
from binja_var_recovery.util import *

FUNCTION_OBJECTS = collections.defaultdict()

class VariableAliasSet(object):
  def __init__(self):
    self.ALIAS_SET = collections.defaultdict(int)
    
  def add(self, start_addr, alias_addr):
    try:
      value = self.ALIAS_SET[start_addr]
      if value < alias_addr:
        self.ALIAS_SET[start_addr] =  alias_addr
    except KeyError:
      index = None
      for k, v in self.ALIAS_SET:
        if start_addr > k:
          break
        index = k
    
      if index:
        value = self.ALIAS_SET[index]
        if value < alias_addr:
          self.ALIAS_SET[start_addr] =  alias_addr

  def __repr__(self):
    string = "{ "
    for k in sorted(self.ALIAS_SET.keys()):
      size = self.ALIAS_SET[k] - k
      if size > 0:
        string += "({:x} {})".format(k, self.ALIAS_SET[k] - k)
    string += " }"
    return string

VARIABLE_ALIAS_SET = collections.defaultdict(set)

DATA_VARIABLES_SET = VariableAliasSet()

SSA_VARIABLE_VALUESET = collections.defaultdict(dict)

class ILVisitor(object):
  """ Class functions to visit medium-level IL"""
  def __init__(self):
    super(ILVisitor, self).__init__()

  def visit(self, expr):
    method_name = 'visit_{}'.format(expr.operation.name.lower())
    if hasattr(self, method_name):
      value = getattr(self, method_name)(expr)
    else:
      DEBUG("Warning! method `{}` not found.".format(method_name))
      value = set()
    return value

""" SSA variable class provides support for backward analysis and
    get the value set for the ssa variables
"""
class SSAVariable(ILVisitor):
  def __init__(self, bv, var, address_size, func=None):
    super(SSAVariable, self).__init__()
    self.address_size = address_size
    self.bv = bv
    self.var = var
    self.function = func
    self.func_start = func.start
    self.f_handler = FUNCTION_OBJECTS[func.start]
    self.visited = set()
    self.to_visit = list()
    self.comments = ""
    self.insn = None

  def variable_name(self):
    return "{}#{}".format(self.var.var.name, self.var.version)

  def has_data_variable(self, values):
    for item in values:
      if is_data_variable(item):
        return True
    return False

  def backward_analysis(self, insn):
    var_def = self.function.medium_level_il.ssa_form.get_ssa_var_definition(self.var)
    self.to_visit.append(var_def)
    values_set = set()

    self.insn = insn
    set_comments(self.bv, insn.address, "test backward analysis 2 : {}".format(var_def))
    while self.to_visit:
      idx = self.to_visit.pop()
      if idx is not None:
        DEBUG("visit {}".format(self.function.medium_level_il.ssa_form[idx]))
        ssa_value = self.visit(self.function.medium_level_il.ssa_form[idx])
        values_set.update(ssa_value)

    set_comments(self.bv, insn.address, "test backward analysis 3 : {}".format(self.comments))
    return values_set

  def visit_mlil_const(self, expr):
    values = set()
    values.add(expr.constant)
    return values

  def visit_mlil_const_ptr(self, expr):
    values = set()
    values.add(expr.constant)
    return values

  def visit_mlil_var_ssa(self, expr):
    """ Get the possible value of the ssa variable
    """
    self.comments += " inside function visit_mlil_var_ssa {}; ".format(expr)
    values_set = set()
    vars_read = expr.vars_read
    vars_written = expr.vars_written
    # Abort with exception if vars_written > 0
    if len(vars_written) > 0:
      sys.exit("Error! visit_mlil_var_ssa vars_written is not 0")

    for ssa_var in vars_read:
      p_value = self.function.medium_level_il.ssa_form.get_ssa_var_value(ssa_var)
      if p_value.type == binja.RegisterValueType.ConstantValue or \
        p_value.type == binja.RegisterValueType.ConstantPointerValue:
        values_set.add(p_value.value)
      elif p_value.type == binja.RegisterValueType.EntryValue:
        ssa_value = self.f_handler.get_param_register(p_value.reg)
        values_set.update(ssa_value)
      else:
        var_handler = SSAVariable(self.bv, ssa_var,  self.bv.address_size, self.function)
        ssa_value = var_handler.backward_analysis(self.insn)
        values_set.update(ssa_value)

    return values_set

  def visit_mlil_var_ssa_field(self, expr):
    """ Get the possible value of the ssa variable
    """
    self.comments += " inside function visit_mlil_var_ssa_field {};".format(expr)
    values_set = set()
    vars_read = expr.vars_read
    vars_written = expr.vars_written

    # Abort with exception if vars_written > 0
    if len(vars_written) > 0:
      sys.exit("Error! visit_mlil_var_ssa vars_written is not 0")

    for ssa_var in vars_read:
      p_value = self.function.medium_level_il.ssa_form.get_ssa_var_value(ssa_var)
      if p_value.type == binja.RegisterValueType.ConstantValue or \
        p_value.type == binja.RegisterValueType.ConstantPointerValue:
        values_set.add(p_value.value)
      elif p_value.type == binja.RegisterValueType.EntryValue:
        ssa_value = self.f_handler.get_param_register(p_value.reg)
        values_set.update(ssa_value)
      elif p_value.type != binja.RegisterValueType.UndeterminedValue:
        values_set.add(str(p_value))  
      else:
        var_handler = SSAVariable(self.bv, ssa_var,  self.bv.address_size, self.function)
        ssa_value = var_handler.backward_analysis(self.insn)
        values_set.update(ssa_value)

    return values_set

  def visit_mlil_set_var_ssa(self, expr):
    values_set = set()
    vars_written = expr.vars_written
    # Abort with exception if vars_written > 1
    if len(vars_written) > 1:
      sys.exit("Error! visit_mlil_set_var_ssa vars_written is not 1")
      
    isrc = expr.src
    if isrc.operation == binja.MediumLevelILOperation.MLIL_CONST or \
      isrc.operation == binja.MediumLevelILOperation.MLIL_CONST_PTR:
      values_set.add(isrc.constant)

    else:
      values = self.visit(isrc)
      if values is not None:
        values_set.update(values)

    return values_set

  def visit_mlil_set_var_ssa_field(self, expr):
    self.comments += " inside function visit_mlil_set_var_ssa_field {}; ".format(expr)
    values_set = set()
    vars_written = expr.vars_written
    
    # Abort with exception if vars_written > 1
    if len(vars_written) > 1:
      sys.exit("Error! visit_mlil_set_var_ssa_field vars_written is not 1")
      
    isrc = expr.src
    if isrc.operation == binja.MediumLevelILOperation.MLIL_CONST or \
      isrc.operation == binja.MediumLevelILOperation.MLIL_CONST_PTR:
      values_set.add(isrc.constant)

    else:
      values = self.visit(isrc)
      values_set.update(values)

    return values_set

  def visit_mlil_zx(self, expr):
    self.comments += " inside function visit_mlil_zx; "
    isrc = expr.src
    return self.visit(isrc)

  def visit_mlil_sx(self, expr):
    self.comments += " inside function visit_mlil_sx; "
    isrc = expr.src
    return self.visit(isrc)

  def visit_mlil_lsl(self, expr):
    self.comments += " inside function visit_mlil_lsl; "
    right_op = 0 
    value_set = set()
    left_value_set = set()
    
    i_left = expr.left
    i_right = expr.right
    if i_right.operation == binja.MediumLevelILOperation.MLIL_CONST or \
      i_right.operation == binja.MediumLevelILOperation.MLIL_CONST_PTR:
      self.comments += "lsl right operand {}; ".format(i_right.constant)
      right_op = i_right.constant
    else:
      ssa_values = self.visit(i_left)
      if len(ssa_values) > 0:
        right_op = max(ssa_values)

    left_value_set = self.visit(i_left)
    for item in left_value_set:
      value_set.add(item << right_op)

    return value_set

  def visit_mlil_lsr(self, expr):
    self.comments += " inside function visit_mlil_lsr; "
    right_op = 0 
    value_set = set()
    left_value_set = set()

    i_left = expr.left
    i_right = expr.right
    if i_right.operation == binja.MediumLevelILOperation.MLIL_CONST or \
      i_right.operation == binja.MediumLevelILOperation.MLIL_CONST_PTR:
      self.comments += "lsl right operand {}; ".format(i_right.constant)
      right_op = i_right.constant
    else:
      ssa_values = self.visit(i_left)
      if len(ssa_values) > 0:
        right_op = min(ssa_values)

    left_value_set = self.visit(i_left)
    for item in left_value_set:
      value_set.add(item << right_op)

    return value_set

  def visit_mlil_add(self, expr):
    self.comments += " inside function visit_mlil_add; "
    value_set = set()
    left_value_set = set()
    right_value_set = set()
    
    i_left = expr.left
    i_right = expr.right
    if i_left.operation == binja.MediumLevelILOperation.MLIL_CONST or \
      i_left.operation == binja.MediumLevelILOperation.MLIL_CONST_PTR:
      left_value_set.add(i_left.constant)
      self.comments += "mlil_add left operand {}; ".format(i_left.constant)
      
    else: 
      left_value_set = self.visit(i_left)
      
    if i_right.operation == binja.MediumLevelILOperation.MLIL_CONST or \
      i_right.operation == binja.MediumLevelILOperation.MLIL_CONST_PTR:
      right_value_set.add(i_right.constant)
      self.comments += "mlil_add right operand {}; ".format(i_right.constant)
      
    else:
      right_value_set = self.visit(i_right)
      
    if len(right_value_set) > 0:
      max_offset = max(right_value_set)
    else:
      max_offset = 0
    
    for item in left_value_set:
      value_set.add(item + max_offset) 
      
    return value_set

  def visit_MLIL_LOAD_SSA(self, expr):
    """ Resolve the SSA Variable performing memory load
    """
    values_set = set()
    isrc = expr.src
    if isrc.operation == binja.MediumLevelILOperation.MLIL_CONST_PTR or \
      isrc.operation == binja.MediumLevelILOperation.MLIL_CONST:
      memory = isrc.constant
    else:
      memory = self.visit(isrc)
      DEBUG("visit_MLIL_LOAD_SSA {} {} operations {}".format(expr.src, memory, isrc.operation))
    return values_set

  def visit_MLIL_ADD(self, expr):
    """ Resolve the SSA variable used in the addition expression
    """
    values_set = set()
    left = self.visit(expr.left)
    right = self.visit(expr.right)
    expr_str = ""
    for item in left:
      expr_str += str(item)
    expr_str += " + "
    for item in right:
      expr_str += str(item)

    values_set.add(expr_str)
    DEBUG("visit_MLIL_ADD values {} ".format(values_set))
    return values_set

  def visit_MLIL_VAR_PHI(self, expr):
    """ Resolve the MLIL_VAR_PHI operation
        Handling VAR_PHI causing the circular dependency; Disable it if the variable value is undef
    """
    DEBUG("visit_MLIL_VAR_PHI expr {} ".format(expr.src))
    values_set = set()
    for ssa_var in expr.src:
      possible_value = expr.get_ssa_var_possible_values(ssa_var)

      if possible_value.type != binja.RegisterValueType.UndeterminedValue:
        values_set.add(possible_value)
      else:
        values_set.add(ssa_var)
        #var_def = expr.function.get_ssa_var_definition(ssa_var)
        #if var_def is not None:
        #self.to_visit.append(var_def)
    return values_set

  def visit_MLIL_CALL_SSA(self, expr):
    """ Resolve the SSA variables referring to the function calls
    """
    values = set()
    idest = expr.dest
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

    return values
