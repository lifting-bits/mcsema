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
from binja_var_recovery.il_variable import *

PARAM_REGISTERS = {
  "rdi" : 0,
  "rsi" : 1,
  "rdx" : 2,
  "rcx" : 3,
  "r8"  : 4,
  "r9"  : 5
  }

SYMBOLIC_VALUE = {
  "rdi" : 0xFFFFFFFFFFFFFFFF,
  "rsi" : 0xFFFFFFFFFFFFFFFF,
  "rdx" : 0xFFFFFFFFFFFFFFFF,
  "rcx" : 0xFFFFFFFFFFFFFFFF,
  "r8"  : 0xFFFFFFFFFFFFFFFF,
  "r9"  : 0xFFFFFFFFFFFFFFFF,
  }

class Function(object):
  """ The function objects
  """
  def __init__(self, bv, func):
    self.bv = bv
    self.func = func
    self.start_addr = func.start
    self.params = list()
    self.ssa_variables = collections.defaultdict(list)
    self.num_params = 0

  def add_ssa_variables(self, var_name, value, insn):
    if var_name in self.ssa_variables.keys():
      variable = self.ssa_variables[var_name]
      variable["value"].append(value)
      variable["insn_def"] = insn
    else:
      variable = dict(value=list(), insn_def=insn)
      variable["value"].append(value)
      self.ssa_variables[var_name] = variable

  def set_params_count(self):
    if self.func is None:
      return

    for ref in self.bv.get_code_refs(self.start_addr):
      ref_function = ref.function
      insn_il = ref_function.get_low_level_il_at(ref.address).medium_level_il
      insn_il_ssa = insn_il.ssa_form if insn_il is not None else None
      if (insn_il_ssa is None or not hasattr(insn_il_ssa, "params")):
        continue
      if isinstance(insn_il_ssa.params, binja.MediumLevelILInstruction):
        continue
      self.num_params = len(insn_il_ssa.params) if len(insn_il_ssa.params) > self.num_params else self.num_params

  def collect_parameters(self):
    if self.func is None:
      return

    DEBUG_PUSH()
    self.params = [set() for i in range(self.num_params)]
    for ref in self.bv.get_code_refs(self.start_addr):
      ref_function = ref.function
      insn_il = ref_function.get_low_level_il_at(ref.address).medium_level_il
      if insn_il is None or \
        insn_il.ssa_form is None:
        continue
      
      insn_il_ssa = insn_il.ssa_form
      DEBUG("Function referred : {} {} num params {}".format(ref_function, insn_il_ssa, self.num_params))
      if not hasattr(insn_il_ssa, "params"):
        continue

      if isinstance(insn_il_ssa.params, binja.MediumLevelILInstruction):
        continue

      for index in range(len(insn_il_ssa.params)):
        parameter = insn_il_ssa.params[index]
        if parameter.operation in [binja.MediumLevelILOperation.MLIL_CONST, binja.MediumLevelILOperation.MLIL_CONST_PTR]:
          possible_value = parameter.possible_values
        else:
          possible_value = parameter.get_ssa_var_possible_values(parameter.src)
        value_set = self.params[index]
    
        if possible_value.type != binja.RegisterValueType.UndeterminedValue:
          value_set.add(possible_value)
        else:
          ssa_var = SSAVariable(parameter.src, self.bv.address_size, ref_function)
          ssa_value = ssa_var.get_values()
          DEBUG("param value_set  {}".format(ssa_value))
          for item in ssa_value:
            value_set.add(item)

    DEBUG_POP() 
    #DEBUG("collect_parameters {}".format(pprint.pformat(self.params)))
    for args in self.params:
      for item in args:
        if isinstance(item, binja.PossibleValueSet):
          if (item.type == binja.RegisterValueType.ConstantPointerValue \
            or item.type == binja.RegisterValueType.ConstantValue) \
            and is_data_variable(self.bv, item.value):
            DEBUG("Data Variable at address {:x}".format(item.value))
            VARIABLE_ALIAS_SET.add(item.value, item.value + 8)

  def print_ssa_variables(self):
    DEBUG("SSA Variables in the function {}".format(pprint.pformat(self.ssa_variables)))

  def get_entry_register(self, register):
    if register is None:
      return
  
    try:
      value_set = self.params[PARAM_REGISTERS[register]]
      return value_set
    except KeyError:
      return None

def create_function(bv, func):
  if func.symbol.type == binja.SymbolType.ImportedFunctionSymbol:
    return

  DEBUG("Processing... {:x} {}".format(func.start, func.name))
  func_obj = Function(bv, func)
  if func_obj is None:
    return

  FUNCTION_OBJECTS[func.start] = func_obj
  func_obj.set_params_count()
  func_obj.collect_parameters()
