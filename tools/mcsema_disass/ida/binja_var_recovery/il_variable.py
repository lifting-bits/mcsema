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
import binaryninja as bn
from binja_var_recovery.util import *
from binja_var_recovery.il_analysis import *

FUNCTION_OBJECTS = collections.defaultdict()

VARIABLE_ALIAS_SET = collections.defaultdict(set)

SSAVariableSet = collections.defaultdict(set)

class ILVisitor(object):
  """ Class functions to visit low-level IL"""
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
class SSARegister(ILVisitor):
  def __init__(self, bv, reg, func=None):
    super(SSARegister, self).__init__()
    self.bv = bv
    self.reg = reg
    self.function = func
    self.func_start = func.start
    self.visited = set()
    self.to_visit = list()
    self.insn = None

  @property
  def version(self):
    return self.reg.version

  @property
  def name(self):
    return "{}#{}".format(self.reg.reg.name, self.reg.version)

  @property
  def global_name(self):
    return "{}_{}#{}".format(self.function.name, self.reg.reg.name, self.reg.version)

  @staticmethod
  def version(self, ssa_reg):
    return ssa_reg.version

  @staticmethod
  def name(self, ssa_reg):
    return "{}#{}".format(ssa_reg.reg.name, self.version(self, ssa_reg))

  @staticmethod
  def global_name(self, ssa_reg):
    return "{}_{}#{}".format(self.function.name, ssa_reg.reg.name, self.version(self, ssa_reg))

  def backward_analysis(self, insn):
    var_def = self.function.low_level_il.ssa_form.get_ssa_reg_definition(self.reg)
    if var_def:
      self.to_visit.append(var_def)
    ssa_values = set()
     
    if len(self.to_visit):
      self.insn = insn
      while self.to_visit:
        idx = self.to_visit.pop()
        if idx is not None:
          ssa_values.update(self.visit(self.function.low_level_il.ssa_form[idx]))
    else:
      ssa_values = set([SymbolicValue(self.bv, self.global_name(self, self.reg))])

    return ssa_values

  def visit_llil_const(self, expr):
    value = get_constant(self.bv, expr)
    return set([Value(self.bv, value)])

  def visit_llil_const_ptr(self, expr):
    value = get_constant(self.bv, expr)
    return set([Value(self.bv, value)])

  def visit_llil_reg_ssa(self, expr):
    #DEBUG("visit_llil_reg_ssa {}".format(expr))
    if self.version(self, expr.src) == 0:
      return set([SymbolicValue(self.bv, self.global_name(self, expr.src))])
  
    if self.global_name(self, expr.src) in SSAVariableSet.keys():
      return SSAVariableSet[self.global_name(self, expr.src)]
  
    reg_handler = SSARegister(self.bv, expr.src, self.function)
    ssa_values = reg_handler.backward_analysis(self.insn)
    return ssa_values

  def visit_llil_reg_ssa_partial(self, expr):
    full_reg = expr.full_reg
    full_reg_name = self.global_name(self, full_reg)
    if full_reg_name in SSAVariableSet.keys():
      return SSAVariableSet[full_reg_name]

    reg_handler = SSARegister(self.bv, full_reg, self.function)
    ssa_values = reg_handler.backward_analysis(self.insn)
    return ssa_values

  def visit_llil_set_reg_ssa(self, expr):
    #DEBUG("visit_llil_set_reg_ssa {}".format(expr))
    ssa_reg = expr.dest
    ssa_reg_name = self.global_name(self, ssa_reg)
    if ssa_reg_name in SSAVariableSet.keys():
      return SSAVariableSet[ssa_reg_name]
  
    ssa_values = self.visit(expr.src)
    SSAVariableSet[ssa_reg_name] = ssa_values
    return ssa_values

  def visit_llil_set_reg_ssa_partial(self, expr):
    #DEBUG("visit_llil_set_reg_ssa_partial {}".format(expr))
    ssa_values = self.visit(expr.src)
    return ssa_values

  def visit_llil_zx(self, expr):
    isrc = expr.src
    return self.visit(isrc)

  def visit_llil_sx(self, expr):
    isrc = expr.src
    return self.visit(isrc)

  def visit_llil_lsl(self, expr):
    ssa_values_left = self.visit(expr.left)
    ssa_values_right = self.visit(expr.right)
    ssa_values = set([l << r for l in ssa_values_left for r in ssa_values_right])
    DEBUG("visit_llil_lsl values {} ".format(ssa_values))
    return ssa_values

  def visit_llil_lsr(self, expr):
    ssa_values_left = self.visit(expr.left)
    ssa_values_right = self.visit(expr.right)
    ssa_values = set([l >> r for l in ssa_values_left for r in ssa_values_right])
    DEBUG("visit_llil_lsr values {} ".format(ssa_values))
    return ssa_values

  def visit_llil_load_ssa(self, expr):
    DEBUG("visit_llil_load_ssa {}".format(expr))
    isrc = expr.src
    memory = self.visit(isrc)
    return set([SymbolicValue(self.bv, "memory load ({})".format(memory))])

  def visit_llil_add(self, expr):
    """ Resolve the SSA variable used in the addition expression
    """
    left = self.visit(expr.left)
    right = self.visit(expr.right)
    values = set([l + r for l in left for r in right])
    DEBUG("visit_llil_add values {} ".format(values))
    return values

  def visit_llil_sub(self, expr):
    """ Resolve the SSA variable used in the addition expression
    """
    left = self.visit(expr.left)
    right = self.visit(expr.right)
    values = set([l - r for l in left for r in right])
    DEBUG("visit_llil_sub values {} ".format(values))
    return values

  ssa_variable_set = set()
  def visit_llil_reg_phi(self, expr):
    values_set = set()
    for ssa_reg in expr.src:
      if str(ssa_reg) not in SSARegister.ssa_variable_set:
        SSARegister.ssa_variable_set.add(str(ssa_reg))
        reg_handler = SSARegister(self.bv, ssa_reg, self.function)
        values_set.update(reg_handler.backward_analysis(self.insn))
        SSARegister.ssa_variable_set.remove(str(ssa_reg))
    return values_set

  def visit_llil_call_ssa(self, expr):
    def global_varname(bv, func, ssa_var):
      return "{}_{}#{}".format(func.name, ssa_var.reg.name, ssa_var.version)
  
    target = call_target(self.bv, expr)
    try:
      sym_value = FUNCTION_OBJECTS[target].get_return_set()
    except KeyError:
      sym_value = set([SymbolicValue(self.bv, "Return {}".format(hex(target) if isinstance(target, long) else target), 0)])
    for out in get_call_output(self.bv, expr):
      SSAVariableSet[global_reg_name(self.function, out)].update(sym_value)
    return sym_value