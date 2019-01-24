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
from binaryninja import *
from binja_var_recovery.util import *
from binja_var_recovery.il_variable import *
from binja_var_recovery.il_instructions import *

RECOVERED = set()
TO_RECOVER = Queue()

def queue_func(addr):
  if addr not in RECOVERED:
    TO_RECOVER.put(addr)
    return True
  else:
    return False

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
    self.return_set = set([SymbolicValue(self.bv, "Return {}".format(hex(func.start)), 0)])
    self.regs = collections.defaultdict(set)

  def get_return_set(self):
    return self.return_set

  def update_register(self, reg_name, value):
    if reg_name is None:
      return
    try:
      if isinstance(value, set):
        self.regs[reg_name].update(value)
      else:
        self.regs[reg_name].add(value)
    except KeyError:
      pass

  def add_ssa_variables(self, var_name, value, insn):
    if var_name in self.ssa_variables.keys():
      variable = self.ssa_variables[var_name]
      variable["value"].append(value)
    else:
      variable = dict(value=list(), insn_def=insn)
      variable["value"].append(value)
      self.ssa_variables[var_name] = variable

  def set_params_count(self):
    """ Set the number of function parameters
    """
    if self.func is None:
      return

    for ref in self.bv.get_code_refs(self.start_addr):
      ref_function = ref.function
      insn_il = ref_function.get_low_level_il_at(ref.address).medium_level_il
      insn_il_ssa = insn_il.ssa_form if insn_il is not None else None
      if (insn_il_ssa is None or not hasattr(insn_il_ssa, "params")):
        continue
      if isinstance(insn_il_ssa.params, MediumLevelILInstruction):
        continue
      self.num_params = len(insn_il_ssa.params) if len(insn_il_ssa.params) > self.num_params else self.num_params

  def collect_parameters(self):
    def global_varname(bv, func, ssa_var):
      return "{}_{}#{}".format(func.name, ssa_var.reg.name, ssa_var.version)

    DEBUG_PUSH()
    self.params = [set() for i in range(self.num_params)]
    for ref in self.bv.get_code_refs(self.start_addr):
      ref_function = ref.function
      insn_il = ref_function.get_low_level_il_at(ref.address)
      if not is_call(self.bv, insn_il):
        continue

      DEBUG("Function referred : {} {}".format(ref_function, insn_il.ssa_form))
      for pparam in get_call_params(self.bv, insn_il.ssa_form):
        ssa_reg = pparam.src
        var_handler = SSARegister(self.bv, ssa_reg, ref_function)
        ssa_values = var_handler.backward_analysis(insn_il)
        DEBUG("{} -> {}".format(global_varname(self.bv, ref_function, ssa_reg), ssa_values))
        SSAVariableSet[global_varname(self.bv, ref_function, ssa_reg)].update(ssa_values)
        target = call_target(self.bv, insn_il)
        if isinstance(target, long):
          func = self.bv.get_function_at(target)
          if func:
            variable_name = "{}_{}#0".format(func.name, ssa_reg.reg.name)
            SSAVariableSet[variable_name].update(ssa_values)
            DEBUG("{} -> {}".format(variable_name, ssa_values))
    DEBUG_POP()

  def collect_returnset(self):
    index = 0
    size = len(self.func.low_level_il.ssa_form)
    DEBUG_PUSH()
    while index < size:
      insn = self.func.low_level_il.ssa_form[index]
      if not is_executable(self.bv, insn.address):
        index += 1
        continue

      if insn.operation == LowLevelILOperation.LLIL_RET:
        llil_insn = ILInstruction(self.bv, self.func, insn)
        operation_name = "{}".format(insn.operation.name.lower())
        if hasattr(llil_insn, operation_name):
          self.return_set = getattr(llil_insn, operation_name)(insn)
        DEBUG("Function returnset {} {}".format(self.return_set, insn.operation.name))
      index += 1
    DEBUG_POP()
    pass

  def get_param_register(self, reg_name):
    try:
      index = PARAM_REGISTERS[reg_name.lower()]
      return self.params[index]
    except KeyError:
      return set()
    except IndexError:
      return set()

  def get_entry_register(self, register):
    if register is None:
      return

    try:
      value_set = self.regs[register]
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

  def recover_mlil(self):
    """ It creates the instruction objects and process them for the variable
        analysis.
    """
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
      operation_name = "{}".format(insn.operation.name.lower())
      if hasattr(mlil_insn, operation_name):
        getattr(mlil_insn, operation_name)(insn)
      else:
        DEBUG("Instruction operation {} is not supported!".format(operation_name))
      DEBUG_POP()

      if insn.operation == MediumLevelILOperation.MLIL_CALL_SSA:
        dest = insn.dest
        if dest.operation == MediumLevelILOperation.MLIL_CONST_PTR:
          called_function = self.bv.get_function_at(dest.constant)
          if called_function is not None:
            queue_func(called_function.start)
      index += 1
    DEBUG_POP()
    
  def recover_llil(self):
    index = 0
    DEBUG("{:x} {}".format(self.func.start, self.func.name))
    size = len(self.func.low_level_il.ssa_form)
      
    DEBUG_PUSH()
    while index < size:
      insn = self.func.low_level_il.ssa_form[index]
      DEBUG("{} : {:x} {} operation {} ".format(index+1, insn.address, insn, insn.operation.name))
      if not is_executable(self.bv, insn.address):
        index += 1
        continue

      DEBUG_PUSH()
      llil_insn = ILInstruction(self.bv, self.func, insn)
      operation_name = "{}".format(insn.operation.name.lower())
      if hasattr(llil_insn, operation_name):
        getattr(llil_insn, operation_name)(insn)
      else:
        DEBUG("Instruction operation {} is not supported!".format(operation_name))
      DEBUG_POP()
      
      if is_call(self.bv, insn):
        target = call_target(self.bv, insn)
        if target is not None:
          queue_func(target)
      index += 1
    DEBUG_POP()

def recover_function(bv, addr, is_entry=False):
  """ Process the function and collect the function which should be visited next
  """
  func = bv.get_function_at(addr)
  if func is None:
    return

  if func.symbol.type == SymbolType.ImportedFunctionSymbol:
    DEBUG("Skipping external function '{}'".format(func.symbol.name))
    return

  DEBUG("Recovering function {} at {:x}".format(func.symbol.name, addr))

  if func.start not in FUNCTION_OBJECTS.keys():
    return None

  f_handle = FUNCTION_OBJECTS[func.start]

  f_handle.collect_parameters()
  f_handle.collect_returnset()
  f_handle.recover_llil()

def create_function(bv, func):
  if func.symbol.type == SymbolType.ImportedFunctionSymbol:
    return

  DEBUG("Processing... {:x} {}".format(func.start, func.name))
  f_handler = Function(bv, func)
  if f_handler is None:
    return

  FUNCTION_OBJECTS[func.start] = f_handler
  f_handler.set_params_count()
