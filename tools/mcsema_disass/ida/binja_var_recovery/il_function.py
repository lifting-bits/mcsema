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
    self.return_set = set()
    self.regs = collections.defaultdict(set)

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
      if isinstance(insn_il_ssa.params, binja.MediumLevelILInstruction):
        continue
      self.num_params = len(insn_il_ssa.params) if len(insn_il_ssa.params) > self.num_params else self.num_params

  def collect_parameters(self):
    """ Traverse through the references of the function and recover the function
        parameters. It is the possible values of the entry registers. If the parameters
        can't be resolved it gets assigned '<undetermined>' as value
    """
    def called_function(bv, insn):
      if insn.operation == binja.MediumLevelILOperation.MLIL_CALL_SSA:
        dest = insn.dest
        if dest.operation == binja.MediumLevelILOperation.MLIL_CONST_PTR:
          called_function = self.bv.get_function_at(dest.constant)
          if called_function is not None:
            return called_function.start

    if self.func is None:
      return

    DEBUG_PUSH()
    self.params = [set() for i in range(self.num_params)]
    for ref in self.bv.get_code_refs(self.start_addr):
      ref_function = ref.function
      insn_il = ref_function.get_low_level_il_at(ref.address).medium_level_il
      if (insn_il is None) or (insn_il.ssa_form is None):
        continue

      insn_il_ssa = insn_il.ssa_form
      if called_function(self.bv, insn_il_ssa) != self.start_addr:
        continue

      DEBUG("Function referred : {} {} num params {}".format(ref_function, insn_il_ssa, self.num_params))
      if not hasattr(insn_il_ssa, "params"):
        continue

      if isinstance(insn_il_ssa.params, binja.MediumLevelILInstruction):
        continue

      for index in range(len(insn_il_ssa.params)):
        parameter = insn_il_ssa.params[index]

        if parameter.operation in [ binja.MediumLevelILOperation.MLIL_CONST,
                                   binja.MediumLevelILOperation.MLIL_CONST_PTR ]:
          p_value = parameter.possible_values
        else:
          p_value = parameter.get_ssa_var_possible_values(parameter.src)

        value_set = self.params[index]

        if p_value.type in [ binja.RegisterValueType.ConstantValue,
                            binja.RegisterValueType.ConstantPointerValue ]:
          value_set.add(p_value.value)
          # build the alias set from the constant value
          add_to_aliasset(self.bv, p_value.value, p_value.value)
        else:
          value_set.add("<undetermined>")
    DEBUG_POP()

  def get_param_register(self, reg_name):
    try:
      index = PARAM_REGISTERS[reg_name.lower()]
      return self.params[index]
    except KeyError:
      return set()
    except IndexError:
      return set()

  def print_ssa_variables(self):
    DEBUG("SSA Variables in the function {}".format(pprint.pformat(self.ssa_variables)))

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

      if insn.operation == binja.MediumLevelILOperation.MLIL_CALL_SSA:
        dest = insn.dest
        if dest.operation == binja.MediumLevelILOperation.MLIL_CONST_PTR:
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
      mlil_insn = ILInstruction(self.bv, self.func, insn)
      operation_name = "{}".format(insn.operation.name.lower())
      if hasattr(mlil_insn, operation_name):
        getattr(mlil_insn, operation_name)(insn)
      else:
        DEBUG("Instruction operation {} is not supported!".format(operation_name))
      DEBUG_POP()
      
      if is_call(self.bv, insn):
        target = call_target(self.bv, insn)
        if target is not None:
          queue_func(target)
          DEBUG("Call target {:x}".format(target))

      index += 1
    DEBUG_POP()

def recover_function(bv, addr, is_entry=False):
  """ Process the function and collect the function which should be visited next
  """
  func = bv.get_function_at(addr)
  if func is None:
    return

  if func.symbol.type == binja.SymbolType.ImportedFunctionSymbol:
    DEBUG("Skipping external function '{}'".format(func.symbol.name))
    return

  DEBUG("Recovering function {} at {:x}".format(func.symbol.name, addr))

  if func.start not in FUNCTION_OBJECTS.keys():
    return None

  f_handle = FUNCTION_OBJECTS[func.start]

  f_handle.collect_parameters()
  f_handle.print_parameters()
  #f_handle.recover_mlil()
  f_handle.recover_llil()

def create_function(bv, func):
  if func.symbol.type == binja.SymbolType.ImportedFunctionSymbol:
    return

  DEBUG("Processing... {:x} {}".format(func.start, func.name))
  f_handler = Function(bv, func)
  if f_handler is None:
    return

  FUNCTION_OBJECTS[func.start] = f_handler
  f_handler.set_params_count()
