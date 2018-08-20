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
from Queue import Queue
import binaryninja as binja
from binja_var_recovery.util import *
from binja_var_recovery.il_variable import *
from binja_var_recovery.il_instructions import *

PARAM_REGISTERS = {
  "rdi" : 0,
  "rsi" : 1,
  "rdx" : 2,
  "rcx" : 3,
  "r8"  : 4,
  "r9"  : 5
  }

PARAM_REGISTERS_INDEX = {
  0 : "rdi",
  1 : "rsi",
  2 : "rdx",
  3 : "rcx",
  4 : "r8",
  5 : "r9"
  }

SYMBOLIC_VALUE = {
  "rdi" : 0xFFFFFFFFFFFFFFFF,
  "rsi" : 0xFFFFFFFFFFFFFFFF,
  "rdx" : 0xFFFFFFFFFFFFFFFF,
  "rcx" : 0xFFFFFFFFFFFFFFFF,
  "r8"  : 0xFFFFFFFFFFFFFFFF,
  "r9"  : 0xFFFFFFFFFFFFFFFF,
  }

RECOVERED = set()
TO_RECOVER = Queue()

def queue_func(addr):
  if addr not in RECOVERED:
    TO_RECOVER.put(addr)

class Function(object):
  """ The function objects
  """
  def __init__(self, bv, func):
    self.bv = bv
    self.func = func
    self.start_addr = func.start
    self.params = list()
    self.ssa_variables = collections.defaultdict(set)
    self.num_params = 0
    self.return_set = set()
    self.regs = collections.defaultdict(set)

  def init_registers(self):
    self.regs["rax"].add(-1)
    self.regs["rbx"].add(-1)
    self.regs["rcx"].add(-1)
    self.regs["rdx"].add(-1)
    self.regs["rdi"].add(-1)
    self.regs["rsi"].add(-1)

    self.regs["r8"].add(-1)
    self.regs["r9"].add(-1)
    self.regs["r10"].add(-1)
    self.regs["r11"].add(-1)
    self.regs["r12"].add(-1)
    self.regs["r13"].add(-1)
    self.regs["r14"].add(-1)

    self.regs["fsbase"].add(-1)
    self.regs["gsbase"].add(-1)

  def add_ssa_variables(self, var_name, value, insn):
    if var_name in self.ssa_variables.keys():
      variable = self.ssa_variables[var_name]
      variable["value"].append(value)
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
          p_value = parameter.possible_values
        else:
          p_value = parameter.get_ssa_var_possible_values(parameter.src)
        value_set = self.params[index]

        if p_value.type in [binja.RegisterValueType.ConstantValue, binja.RegisterValueType.ConstantPointerValue]:
          value_set.add(p_value.value)
        elif p_value.type == binja.RegisterValueType.EntryValue:
          reg_value = self.regs[p_value.reg]
          value_set.update(reg_value)
        elif p_value.type != binja.RegisterValueType.UndeterminedValue:
          value_set.add(p_value)
        else:
          ssa_var = SSAVariable(self.bv, parameter.src, self.bv.address_size, ref_function)
          ssa_value = ssa_var.get_values()
          DEBUG("param value_set  {}".format(ssa_value))
          for item in ssa_value:
            value_set.add(item)

    DEBUG_POP()

    if len(self.params) == 0:
      return

    DEBUG("collect_parameters {}".format(pprint.pformat(self.params)))
    for args in self.params:
      for item in args:
        if isinstance(item, binja.PossibleValueSet):
          if (item.type == binja.RegisterValueType.ConstantPointerValue \
            or item.type == binja.RegisterValueType.ConstantValue):
            if is_data_variable(self.bv, item.value):
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
      return set()
    except IndexError:
      return set()

  def print_parameters(self):
    size = len(self.params)
    for index in range(size):
      try:
        DEBUG("{} : {}".format(PARAM_REGISTERS_INDEX[index], pprint.pformat(self.params[index])))
      except KeyError:
        pass

  def recover_instructions(self):
    index = 0
    DEBUG("{:x} {}".format(self.func.start, self.func.name))
    size = len(self.func.medium_level_il.ssa_form)
      
    DEBUG_PUSH()
    while index < size:
      insn = self.func.medium_level_il.ssa_form[index]
      DEBUG("{} : {:x} {} operation {} ".format(index+1, insn.address, insn, insn.operation.name))
      if not is_executable(self.bv, insn.address):
        index += 1
        continue

      DEBUG_PUSH()
      mlil_insn = ILInstruction(self.bv, self.func, insn)
      operation_name = "{}".format(insn.operation.name)
      if hasattr(mlil_insn, operation_name):
        getattr(mlil_insn, operation_name)(insn)
      else:
        DEBUG("Instruction operation {} is not supported!".format(operation_name))
      DEBUG_POP()

      if insn.operation == binja.MediumLevelILOperation.MLIL_CALL_SSA:
        dest = insn.dest
        if dest.operation == binja.MediumLevelILOperation.MLIL_CONST_PTR:
          called_function = self.bv.get_function_at(dest.constant)
          if called_function is not None:
            queue_func(called_function.start)
      index += 1
    DEBUG_POP()

def create_function(bv, func):
  if func.symbol.type == binja.SymbolType.ImportedFunctionSymbol:
    return

  DEBUG("Processing... {:x} {}".format(func.start, func.name))
  func_obj = Function(bv, func)
  if func_obj is None:
    return

  FUNCTION_OBJECTS[func.start] = func_obj
  func_obj.init_registers()
  func_obj.set_params_count()
  func_obj.collect_parameters()
