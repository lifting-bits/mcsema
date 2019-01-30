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

import re
import io
import collections
import struct

try:
  from elftools.elf.elffile import ELFFile
  from elftools.elf.sections import SymbolTableSection
except ImportError:
  print "Install pyelf tools"

_DEBUG_FILE = None
_DEBUG_PREFIX = ""

def INIT_DEBUG_FILE(file):
  global _DEBUG_FILE
  _DEBUG_FILE = file

def DEBUG_PUSH():
  global _DEBUG_PREFIX
  _DEBUG_PREFIX += "  "

def DEBUG_POP():
  global _DEBUG_PREFIX
  _DEBUG_PREFIX = _DEBUG_PREFIX[:-2]

def DEBUG(s):
  global _DEBUG_FILE
  if _DEBUG_FILE:
    _DEBUG_FILE.write("{}{}\n".format(_DEBUG_PREFIX, str(s)))

dynamic_symbols = collections.defaultdict()

MEMORY_REFS = collections.defaultdict()

ADDRESS_REFS = collections.defaultdict()

EXPORTED_REFS = collections.defaultdict()

VARIABLE_SET_REFS = collections.defaultdict()

def set_comments(bv, addr, str):
  functions = bv.get_functions_containing(addr)
  if functions is None:
    return

  for func in functions:
    old_str = func.get_comment_at(addr)
    new_str = old_str + " ; " + str
    func.set_comment_at(addr, new_str)

def convert_signed32(num):
  num = num & 0xFFFFFFFF
  return (num ^ 0x80000000) - 0x80000000

def is_valid_addr(bv, addr):
  return bv.get_segment_at(addr) is not None
  
def is_invalid_addr(bv, addr):
  return bv.get_segment_at(addr) is None
  
def get_section_at(bv, addr):
  if is_invalid_addr(bv, addr):
    return None

  for sec in bv.sections.values():
    if sec.start <= addr < sec.end:
      return sec
  return None

def is_executable(bv, addr):
  seg = bv.get_segment_at(addr)
  return seg is not None and seg.executable

def is_readable(bv, addr):
  seg = bv.get_segment_at(addr)
  return seg is not None and seg.writable

def is_writeable(bv, addr):
  seg = bv.get_segment_at(addr)
  return seg is not None and seg.readable

def is_ELF(bv):
  return bv.view_type == 'ELF'

def is_PE(bv):
  return bv.view_type == 'PE'

def is_data_variable_section(bv, addr):
  seg = bv.get_segment_at(addr)
  if seg == None:
    return False

  sect = get_section_at(bv, addr)
  if sect is not None and is_ELF(bv):
    if re.search(r'\.(init|fini|got|plt)', sect.name):
      return False

  return (seg.executable == False)

def is_data_variable(bv, addr):
  seg = bv.get_segment_at(addr)
  if seg == None:
    return False

  sect = get_section_at(bv, addr)
  if sect is not None and is_ELF(bv):
    if re.search(r'\.(init|fini|got|plt)', sect.name):
      return False

  if is_dynamic_range_lookup(bv, addr):
    return False

  return (seg.executable == False)

# Caching results of is_section_external
_EXT_SECTIONS = set()
_INT_SECTIONS = set()

def is_section_external(bv, sect):
  if sect.start in _EXT_SECTIONS:
    return True

  if sect.start in _INT_SECTIONS:
    return False

  if is_ELF(bv):
    if re.search(r'\.(got|plt)', sect.name):
      _EXT_SECTIONS.add(sect.start)
      return True

  _INT_SECTIONS.add(sect.start)
  return False

def is_dynamic_range_lookup(bv, addr):
  for sym in sorted(dynamic_symbols.keys()):
    if sym <= addr < sym + dynamic_symbols[sym]:
      return True
  return False

def process_binary(bv, binfile):
  with open(binfile, 'rb') as f:
    elffile = ELFFile(f)
    symbol_tables = [s for s in elffile.iter_sections() if isinstance(s, SymbolTableSection)]

    for section in symbol_tables:
      if not isinstance(section, SymbolTableSection):
        continue

      if section['sh_entsize'] == 0:
        continue

      for nsym, symbol in enumerate(section.iter_symbols()):
        sym_addr = symbol['st_value']
        sym_size = symbol['st_size']
        if is_data_variable_section(bv, sym_addr):
          dynamic_symbols[sym_addr] = sym_size

def set_variables(bv, addr, size):
  if not is_data_variable(bv, addr):
    return
  try:
    curr_size = VARIABLE_SET_REFS[addr]
    if size > curr_size:
      VARIABLE_SET_REFS[addr] = size
  except KeyError:
    VARIABLE_SET_REFS[addr] = size

def print_variables(bv):
  g_variables = collections.defaultdict()
  for key in VARIABLE_SET_REFS.keys():
    size = VARIABLE_SET_REFS[key]
    g_variables[key] = size

  DEBUG("Variables set")
  for addr in g_variables.keys():
    DEBUG("{:x} -> {:x}".format(addr, g_variables[addr]))

def get_dynamic_symbol(bv):
  sym_table = sorted(dynamic_symbols.keys())
  for sym in sym_table:
    size = dynamic_symbols[sym]
    yield (sym, size)
    yield (sym +size, 0)
    
def get_memory_refs(bv):
  memory_refs = sorted(MEMORY_REFS.keys())
  for ref in memory_refs:
    size = MEMORY_REFS[ref]
    if is_dynamic_range_lookup(bv, ref):
      continue
    yield (ref, size)
    
def get_address_refs(bv):
  xrefs = sorted(ADDRESS_REFS.keys())
  for ref in xrefs:
    if is_dynamic_range_lookup(bv, ref):
      continue
    yield (ref, 0)
