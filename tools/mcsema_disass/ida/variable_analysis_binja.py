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
from binaryninja import *
import mcsema_disass.ida.CFG_pb2
from binja_var_recovery.util import *
from binja_var_recovery.il_function import *

def is_exported_symbol(bv, sym):
  if sym.type == SymbolType.DataSymbol and \
    is_data_variable(bv, sym.address):
    return True
  return False

def get_symbols(bv):
  for syms in bv.symbols.values():
    if isinstance(syms, Symbol):
      yield (syms)
    else:
      for entry in syms:
        yield (entry)

def identify_exported_symbols(bv):
  syms = sorted(get_symbols(bv), key=lambda s: s.address)
  for i, sym in enumerate(syms):
    sect = get_section_at(bv, sym.address)
    if sect is None:
      continue

    if is_exported_symbol(bv, sym) and \
      not is_section_external(bv, sect):
      EXPORTED_REFS[sym.address] = sym.address

# main function
def main(args):
  """ Function which recover the variables from the medium-level IL instructions;
      1) Get the data variables and populate the list with possible sizes and references; The data variables
         recovered may not be having the correct size which should get fixed at later point 
  """
  bv = BinaryViewType.get_view_of_file(args.binary)
  bv.add_analysis_option("linearsweep")
  bv.update_analysis_and_wait()
  process_binary(bv, args.binary)
  
  DEBUG("Analysis file {} loaded...".format(args.binary))
  DEBUG("Number of functions {}".format(len(bv.functions)))
  
  entry_symbol = bv.get_symbols_by_name(args.entrypoint)[0]
  DEBUG("Entry points {:x} {} {} ".format(entry_symbol.address, entry_symbol.name, len(bv.functions)))

  # recover the exported symbols from the binary
  identify_exported_symbols(bv)

  # Create function objects and collect its references
  for func in bv.functions:
    create_function(bv, func)

  entry_addr = entry_symbol.address
  recover_function(bv, entry_addr, is_entry=True)

  # Recover any discovered functions until there are none left
  while not TO_RECOVER.empty():
    addr = TO_RECOVER.get()
    if addr not in RECOVERED:
      RECOVERED.add(addr)
      DEBUG("STAT -> Recovering {} out of {} functions...".format(len(RECOVERED), len(bv.functions)))
      recover_function(bv, addr)
  
    if TO_RECOVER.empty() and (len(bv.functions) > 0):
      for func in bv.functions:
        if func.start not in RECOVERED: 
          queue_func(func.start)
          break

  DEBUG("Number of functions {} {}".format(len(bv.functions), TO_RECOVER.qsize()))
  updateCFG(bv, args.out)
  print_variables(bv)

def get_variable_size(bv, next_var, var):
  sec = get_section_at(bv, var)
  if sec is None:
    return 0
  if sec.end > next_var:
    return next_var - var
  else:
    return sec.end - var

def generate_variable_list(bv):
  g_variables = collections.defaultdict()
  for ref, size in get_dynamic_symbol(bv):
    g_variables[ref] = size

  for ref, size in get_memory_refs(bv):
    DEBUG("Memory ref : {:x} size {:x}".format(ref, size))
    g_variables[ref] = size
    
  for ref, size in get_address_refs(bv):
    DEBUG("Address ref : {:x} size 0".format(ref))
    g_variables[ref] = size

  variable_list = sorted(g_variables.iterkeys())
  for index, addr in enumerate(variable_list):
    try:
      size = get_variable_size(bv, variable_list[index+1], addr)
    except IndexError:
      sec = get_section_at(bv, addr)
      if sec is None:
        continue
      size = get_variable_size(bv, sec.end, addr)
    g_variables[addr] = size

  DEBUG("Number of global symbols {}".format(len(g_variables)))
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

  main(args)
