#!/usr/bin/env python

# Copyright (c) 2018 Trail of Bits, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import sys
import collections
import argparse
import pprint
from collections import namedtuple
try:
  import manticore
  MANTICORE_FLAG = True
except ImportError:
  MANTICORE_FLAG = False

import binaryninja as binja
import mcsema_disass.ida.CFG_pb2
from binja_var_recovery.util import *
from binja_var_recovery.il_function import *

VARIABLES_TO_RECOVER = dict()

DATA_VARIABLE_XREFS = collections.defaultdict(set)

def identify_exported_symbols(bv):
  syms = sorted(bv.symbols.values(), key=lambda s: s.address)
  for i, sym in enumerate(syms):
    sect = get_section_at(bv, sym.address)
    if sect is None:
      continue

    if sym.type == binja.SymbolType.DataSymbol and \
      is_data_variable(bv, sym.address) and \
      not is_executable(bv, sym.address) and \
      not is_section_external(bv, sect):
      VARIABLE_ALIAS_SET[sym.address].add(sym.address + bv.address_size)
      EXPORTED_REFS[sym.address] = sym.address
  DEBUG('Number of exported global variables {}'.format(len(VARIABLE_ALIAS_SET)))

def identify_data_variable(bv):
  """ Recover the data variables from the segments identified by binja; The size of
      variables may not be correct and safe to recover.
  """
  if bv is None:
    return

  DEBUG("Looking for data variables {}".format(len(bv.sections)))  
  DEBUG_PUSH()
  
  for seg in bv.sections.values():
    addr = seg.start
    if is_executable(bv, addr):
      continue

    var = addr
    next_var = None
    while True:
      next_var = bv.get_next_data_var_after(var)
      if next_var == var:
        break

      size = next_var - var
      if not is_data_variable(bv, var):
        var = next_var  
        continue
    
      dv = bv.get_data_var_at(var)
      DATA_VARIABLES_SET.add(var, next_var)
      for ref in bv.get_code_refs(var):
        llil = ref.function.get_low_level_il_at(ref.address)
        if llil is not None:
          mlil = llil.medium_level_il
          if mlil:
            DATA_VARIABLE_XREFS[mlil.address].update({var, mlil})
      var = next_var

    size = next_var - var
    if dv is not None:
      DATA_VARIABLES_SET.add(var, next_var)
  DEBUG_POP()

def manticore_install(bv, args):
  def print_regs(func_name, cpu):
    _debug_str = "{} RDI {:x}, RSI {:x}, RAX {:x}, RBX {:x}, RCX {:x}, RDX {:x}, R8 {:x}, R9 {:x}, R10 {:x}, R11 {:x}, R12 {:x}, R13 {:x}, R14 {:x}, R15 {:x}".format( \
                func_name, cpu.RDI, cpu.RSI, cpu.RAX, cpu.RBX, cpu.RCX, cpu.RDX, cpu.R8, cpu.R9, cpu.R10, cpu.R11, cpu.R12, cpu.R13, cpu.R14, cpu.R15)
    DEBUG(_debug_str)

  m = manticore.Manticore(args.binary)
  for func in bv.functions:
    hook_pc = func.start
    @m.hook(hook_pc)
    def hook(state):
      cpu = state.cpu
      func_addr = cpu.RIP
      func = bv.get_function_at(func_addr)
      print_regs(func.name, cpu)

  m.run()

# main function
def main(args):
  """ Function which recover the variables from the medium-level IL instructions;
      1) Get the data variables and populate the list with possible sizes and references; The data variables
         recovered may not be having the correct size which should get fixed at later point 
  """
  bv = binja.BinaryViewType.get_view_of_file(args.binary)
  bv.update_analysis_and_wait()
  
  DEBUG("Analysis file {} loaded...".format(args.binary))
  DEBUG("Number of functions {}".format(len(bv.functions)))
  
  entry_symbol = bv.get_symbols_by_name(args.entrypoint)[0]
  DEBUG("Entry points {:x} {} {} ".format(entry_symbol.address, entry_symbol.name, len(bv.functions)))

  # recover the exported symbols from the binary
  identify_exported_symbols(bv)
  # Get all the data variables from the data segments
  identify_data_variable(bv)

  # Create function objects and collect its references
  for func in bv.functions:
    create_function(bv, func)

  #if MANTICORE_FLAG:
  #  manticore_install(bv, args)

  entry_addr = entry_symbol.address
  recover_function(bv, entry_addr, is_entry=True)

  # Recover any discovered functions until there are none left
  while not TO_RECOVER.empty():
    addr = TO_RECOVER.get()
    if addr not in RECOVERED:
      RECOVERED.add(addr)
      recover_function(bv, addr)
      bv.remove_function(bv.get_function_at(addr))

      if TO_RECOVER.qsize() == 0 and len(bv.functions) > 0:
        queue_func(bv.functions[0].start)

  updateCFG(bv, args.out)
  DEBUG("Global variables recovered {}".format(VARIABLE_ALIAS_SET))
  DEBUG("Data variables from binja {}".format(DATA_VARIABLES_SET))

def get_variable_size(bv, next_var, var):
  sec = get_section_at(bv, var)
  if sec.end > next_var:
    return next_var - var
  else:
    return sec.end - var

def generate_variable_list(bv):
  """ Generate the list of variables from the recovered memory refs,
      address refs and the list of exported symbols. It also calculate
      the size of the variables.
  """
  g_variables = collections.defaultdict()
  for ref in EXPORTED_REFS.keys():
    g_variables[ref] = 0

  for ref in ADDRESS_REFS.keys():
    g_variables[ref] = 0

  for ref in MEMORY_REFS.keys():
    size = MEMORY_REFS[ref]
    g_variables[ref] = size
    next_ref = ref + size
    next_ref = next_ref if next_ref % 4 else (next_ref/4 + 1)*4

  variable_list = sorted(g_variables.iterkeys())
  for index, addr in enumerate(variable_list):
    try:
      size = get_variable_size(bv, variable_list[index+1], addr)
    except IndexError:
      sec = get_section_at(bv, addr)
      size = get_variable_size(bv, sec.end, addr)
    g_variables[addr] = size

  return g_variables

def updateCFG(bv, outfile):
  """ Update the CFG file with the recovered global variables
  """
  M = mcsema_disass.ida.CFG_pb2.Module()
  M.name = "GlobalVariables".format('utf-8')

  g_variables = generate_variable_list(bv)
  for key in sorted(g_variables.iterkeys()):
    var = M.global_vars.add()
    var.ea = key
    var.name = "global_var_{:x}".format(key)
    var.size = g_variables[key]

  with open(outfile, "w") as outf:
    outf.write(M.SerializeToString())

if __name__ == '__main__':
  parser = argparse.ArgumentParser()
  parser.add_argument("--log_file", type=argparse.FileType('w'),
                      default=sys.stderr,
                      help='Name of the log file. Default is stderr.')
    
  parser.add_argument('--out',
                      help='Name of the output proto buffer file.',
                      required=True)
    
  parser.add_argument('--binary',
                      help='Name of the binary image.',
                      required=True)

  parser.add_argument('--entrypoint',
                      help='Name of the entry point function.',
                      required=True)
  
  args = parser.parse_args(sys.argv[1:])
  
  if args.log_file:
    INIT_DEBUG_FILE(args.log_file)
    DEBUG("Debugging is enabled.")
  
  BINARY_FILE = args.binary
  main(args)