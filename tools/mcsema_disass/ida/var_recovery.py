#!/usr/bin/env python

import os
import sys
import argparse
import pprint

from collections import defaultdict, OrderedDict
from collections import namedtuple
from enum import Enum

try:
  from elftools.elf.elffile import ELFFile
  from elftools.common.py3compat import itervalues
  from elftools.dwarf.descriptions import (describe_DWARF_expr, set_global_machine_arch, describe_CFI_instructions)
  from elftools.dwarf.descriptions import describe_attr_value, describe_reg_name
  from elftools.dwarf.locationlists import LocationEntry
  from elftools.common.py3compat import maxint, bytes2str, byte2int, int2byte
  from elftools.dwarf.callframe import  instruction_name, CIE, FDE, ZERO
except ImportError:
  print "Install pyelf tools"

import CFG_pb2

DWARF_OPERATIONS = defaultdict(lambda: (lambda *args: None))
SYMBOL_BLACKLIST = defaultdict(lambda: (lambda *args: None))

BINARY_FILE = ""

Type = namedtuple('Type', ['name', 'size', 'type_offset', 'tag'])

GLOBAL_VARIABLES = OrderedDict()

TYPES_MAP = OrderedDict()

EH_FRAMES = OrderedDict()

BASE_TYPES = [
  'DW_TAG_base_type',
  'DW_TAG_structure_type',
  'DW_TAG_union_type',
  'DW_TAG_enumeration_type',
]

INDIRECT_TYPES = [
  'DW_TAG_typedef',
  'DW_TAG_const_type',
  'DW_TAG_volatile_type',
  'DW_TAG_restrict_type',
  'DW_TAG_subroutine_type',
]

POINTER_TYPES = {
  'DW_TAG_pointer_type' : '*',
}

ARRAY_TYPES = {
  'DW_TAG_array_type',
}

TYPE_ENUM = {
  'DW_TAG_unknown_type': 0,
  'DW_TAG_base_type': 1,
  'DW_TAG_structure_type' : 2,
  'DW_TAG_union_type': 3,
  'DW_TAG_pointer_type': 4,
  'DW_TAG_array_type': 5,
}

_DEBUG = False
_DEBUG_FILE = None
_DEBUG_PREFIX = ""

def DEBUG_INIT(file, flag):
  global _DEBUG
  global _DEBUG_FILE
  _DEBUG = flag
  _DEBUG_FILE = file
  
def DEBUG_PUSH():
  global _DEBUG_PREFIX
  _DEBUG_PREFIX += "  "

def DEBUG_POP():
  global _DEBUG_PREFIX
  _DEBUG_PREFIX = _DEBUG_PREFIX[:-2]

def DEBUG(s):
  if _DEBUG:
    _DEBUG_FILE.write("{}{}\n".format(_DEBUG_PREFIX, str(s)))

'''
    DIE attributes utilities 
'''
def get_name(die):
  if 'DW_AT_name' in die.attributes:
    return die.attributes['DW_AT_name'].value
  else:
    return 'UNKNOWN'

def get_size(die):
  if 'DW_AT_byte_size' in die.attributes:
    return die.attributes['DW_AT_byte_size'].value
  else:
    return -1
    
def get_location(die):
  if 'DW_AT_location' in die.attributes:
    return die.attributes['DW_AT_location'].value
  else:
    return None
    
def get_types(die):
  if 'DW_AT_type' in die.attributes:
    offset = die.attributes['DW_AT_type'].value + die.cu.cu_offset
    if offset in TYPES_MAP:
      return (TYPES_MAP[offset], TYPES_MAP[offset].size, TYPES_MAP[offset].type_offset)

  return (Type(None, None, None, None), -1, -1)

def _create_variable_entry(name, offset):
  return dict(name=name, offset=offset, type=Type(None, None, None, None), size=0, addr=0, is_global=False)

def process_types(dwarf, typemap):
  def process_direct_types(die):
    if die.tag in BASE_TYPES:
      name = get_name(die)
      size = get_size(die)
      if die.offset not in typemap :
        typemap[die.offset] = Type(name=name, size=size, type_offset=die.offset, tag=TYPE_ENUM.get(die.tag))
      DEBUG("<{0:x}> {1}".format(die.offset, typemap.get(die.offset)))

  def process_pointer_types(die):
    if die.tag in POINTER_TYPES:
      if 'DW_AT_type' in die.attributes:
        offset = die.attributes['DW_AT_type'].value + die.cu.cu_offset
        indirect = POINTER_TYPES[die.tag]
        name = (typemap[offset].name if offset in typemap else 'UNKNOWN') + indirect
        type_offset = typemap[offset].type_offset if offset in typemap else -1 
      else:
        name = 'void*'
        type_offset = 0
      if die.offset not in typemap:
        typemap[die.offset] = Type(name=name, size=die.cu['address_size'], type_offset=type_offset, tag=TYPE_ENUM.get(die.tag))
      DEBUG("<{0:x}> {1}".format(die.offset, typemap.get(die.offset)))
    
  def process_indirect_types(die):
    if die.tag in INDIRECT_TYPES:
      if 'DW_AT_type' in die.attributes:
        offset = die.attributes['DW_AT_type'].value + die.cu.cu_offset
        if offset in typemap:
          size = typemap[offset].size
          name = typemap[offset].name
          type_offset =  typemap[offset].type_offset
          tag = typemap[offset].tag if offset in typemap else 0
          if die.offset not in typemap:
            typemap[die.offset] = Type(name=name, size=size, type_offset=type_offset, tag=tag)
          else:
            tag = 0
            type_offset = 0
            name = get_name(die)
          if die.offset not in typemap:
            typemap[die.offset] = Type(name=name, size=-1, type_offset=type_offset, tag=tag)
        DEBUG("<{0:x}> {1}".format(die.offset, typemap.get(die.offset)))
            
  def process_array_types(die):
    if die.tag in ARRAY_TYPES:
      if 'DW_AT_type' in die.attributes:
        offset = die.attributes['DW_AT_type'].value + die.cu.cu_offset
        if offset in typemap:
          name = typemap[offset].name if offset in typemap else 'UNKNOWN'
          type_offset = typemap[offset].type_offset if offset in typemap else 0
          size = typemap[offset].size if offset in typemap else 0
          # get sub range to get the array size
          for child_die in die.iter_children():
            if child_die.tag == 'DW_TAG_subrange_type':
              if 'DW_AT_upper_bound' in child_die.attributes:
                index = child_die.attributes['DW_AT_upper_bound'].value
                if type(index) is int:
                  index = index +1
                  size = size*index
                  break
          typemap[die.offset] = Type(name=name, size=size, type_offset=type_offset, tag=TYPE_ENUM.get(die.tag))
          DEBUG("<{0:x}> {1}".format(die.offset, typemap.get(die.offset)))
            
  build_typemap(dwarf, process_direct_types)
  build_typemap(dwarf, process_indirect_types)
  build_typemap(dwarf, process_pointer_types)
  build_typemap(dwarf, process_array_types)
  build_typemap(dwarf, process_indirect_types)
  build_typemap(dwarf, process_array_types)
    
def _process_dies(die, fn):
  fn(die)
  for child in die.iter_children():
    _process_dies(child, fn)

def build_typemap(dwarf, fn):
  for CU in dwarf.iter_CUs():
    top = CU.get_top_DIE()
    _process_dies(top, fn)
    
def _process_frames_info(dwarf, cfi_entries, eh_frames):
  for entry in cfi_entries:
    if isinstance(entry, CIE):
      pass
    elif isinstance(entry, FDE):
      pc = entry['initial_location']
      if pc not in eh_frames:
        eh_frames[pc] = entry
    else:
      continue
  
def process_frames(dwarf, eh_frames):
  if dwarf.has_EH_CFI():
    _process_frames_info(dwarf, dwarf.EH_CFI_entries(), eh_frames)

def _create_global_var_entry(memory_ref, var_name):
  return dict(addrs=set(), size=-1, name=var_name, type=None, safe=True)

VARIABLE_STAT = {"type1": 0, "type2": 0}

def address_lookup(g_ref, global_var_array):
  for value, gvar in GLOBAL_VARIABLES.iteritems():
    if ((gvar['type'].tag == 1) or (gvar['type'].tag == 4)):
      if gvar['addr'] == g_ref.address:
        address = gvar['addr']
        size = gvar['size']
        if address not in global_var_array:
          global_var_array[address] = _create_global_var_entry(address, g_ref.var.name)
          global_var_array[address]['size'] = size
          global_var_array[address]['type'] = g_ref.var.ida_type
          for ref in g_ref.var.ref_eas:
            global_var_array[address]['addrs'].add((ref.inst_addr, ref.offset)) 
          VARIABLE_STAT["type1"] = VARIABLE_STAT["type1"] + 1
          return None
    elif (gvar['type'].tag == 5) or (gvar['type'].tag == 2):
      base_address = gvar['addr']
      size = gvar['size']
      name = "recovered_global_{:0x}".format(base_address)
      if g_ref.address in xrange(base_address, base_address + size):
        if base_address not in global_var_array:
          global_var_array[base_address] = _create_global_var_entry(base_address, name)
          global_var_array[base_address]['size'] = size
          global_var_array[base_address]['type'] = g_ref.var.ida_type
          offset = g_ref.address - base_address
          for ref in g_ref.var.ref_eas:
            global_var_array[base_address]['addrs'].add((ref.inst_addr, offset))
          VARIABLE_STAT["type2"] = VARIABLE_STAT["type2"] + 1
          return None
  return None

 
def _print_die(die, section_offset):
  DEBUG("Processing DIE: {}".format(str(die)))
  for attr in itervalues(die.attributes):
    if attr.name == 'DW_AT_name' :
      variable_name = attr.value
      name = attr.name
      if isinstance(name, int):
        name = 'Unknown AT value: %x' % name
      DEBUG('    <%x>   %-18s: %s' % (attr.offset, name, describe_attr_value(attr, die, section_offset)))

def _process_variable_tag(die, section_offset, M, global_var_data):
  if die.tag != 'DW_TAG_variable':
    return
  name = get_name(die)
  if 'DW_AT_location' in die.attributes:
    attr = die.attributes['DW_AT_location']
    if attr.form not in ('DW_FORM_data4', 'DW_FORM_data8', 'DW_FORM_sec_offset'):
      loc_expr = "{}".format(describe_DWARF_expr(attr.value, die.cu.structs)).split(':')
      if loc_expr[0][1:] == 'DW_OP_addr':
        memory_ref = int(loc_expr[1][:-1][1:], 16)
        if memory_ref not in  global_var_data:
          global_var_data[memory_ref] = _create_variable_entry(name, die.offset)
          global_var_data[memory_ref]['is_global'] = True
          global_var_data[memory_ref]['addr'] = memory_ref
          (type, size, offset) = get_types(die)
          global_var_data[memory_ref]['type'] = type
          global_var_data[memory_ref]['size'] = size
          DEBUG("{}".format(pprint.pformat(global_var_data[memory_ref])))  # DEBUG_ENABLE
   
def _full_reg_name(regnum):
  regname = describe_reg_name(regnum, None, False)
  if regname:
    return 'r%s (%s)' % (regnum, regname)
  else:
    return 'r%s' % regnum
  
"""
  Process subprogram tag and recover the local variables
"""  
def _process_subprogram_tag(die, section_offset, M, global_var_data):
  if die.tag != 'DW_TAG_subprogram':
    return

  F = M.funcs.add()
  F.ea = 0
  F.name = get_name(die)
  F.is_entrypoint = 0
  has_frame = False
  frame_regname = ""
  
  if 'DW_AT_frame_base' in die.attributes:
    frame_attr = die.attributes['DW_AT_frame_base']
    has_frame = True
    loc_expr = "{}".format(describe_DWARF_expr(frame_attr.value, die.cu.structs)).split(' ')
    if loc_expr[0][1:][:-1] == "DW_OP_call_frame_cfa":
      lowpc_attr = die.attributes['DW_AT_low_pc']
      #DEBUG("loc_expr {0} {1:x}".format(loc_expr, lowpc_attr.value))
      frame = EH_FRAMES[lowpc_attr.value] if lowpc_attr.value in EH_FRAMES else None
      if frame:
        DEBUG("{0:x}, {1}".format(frame['initial_location'], frame))
        for instr in frame.instructions:
          name = instruction_name(instr.opcode)
          if name == 'DW_CFA_def_cfa_register':
            frame_regname =  describe_reg_name(instr.args[0], None, False)

  for child in die.iter_children():
    if child.tag != 'DW_TAG_variable':
      continue
  
    stackvar = F.stack_vars.add()
    stackvar.name = get_name(child)
    stackvar.sp_offset = 0
    stackvar.has_frame = has_frame
    stackvar.reg_name = frame_regname
    (type, size, offset) = get_types(child)
    stackvar.size = size if size > 0 else 0
    
    if 'DW_AT_location' in child.attributes:
      attr = child.attributes['DW_AT_location']
      if attr.form not in ('DW_FORM_data4', 'DW_FORM_data8', 'DW_FORM_sec_offset'):
        loc_expr = "{}".format(describe_DWARF_expr(attr.value, child.cu.structs)).split(' ')
        if loc_expr[0][1:][:-1] == 'DW_OP_fbreg':
          offset = int(loc_expr[1][:-1])
          stackvar.sp_offset = offset
          
DWARF_OPERATIONS = {
  #'DW_TAG_compile_unit': _process_compile_unit_tag,
  'DW_TAG_variable' : _process_variable_tag,
  'DW_TAG_subprogram' : _process_subprogram_tag,
}

class CUnit(object):
  def __init__(self, die, cu_len, cu_offset, global_offset = 0):
    self._die = die
    self._length = cu_len
    self._offset = cu_offset
    self._section_offset = global_offset
    self._global_variable = dict()
        
  def _process_child(self, child_die, M, global_var_data):
    for child in child_die.iter_children():
      func_ = DWARF_OPERATIONS.get(child.tag)
      if func_:
        func_(child, self._section_offset, M, global_var_data)
        continue
      self._process_child(child, M, global_var_data)
        
  def decode_control_unit(self, M, global_var_data):
    for child in self._die.iter_children():
      func_ = DWARF_OPERATIONS.get(child.tag)
      if func_:
        func_(child, self._section_offset, M, global_var_data)
        continue
      self._process_child(child, M, global_var_data)
      

def process_dwarf_info(in_file, out_file):
  '''
    Main function processing the dwarf informations from debug sections
  '''
  DEBUG('Processing file: {0}'.format(in_file))
    
  with open(in_file, 'rb') as f:
    f_elf = ELFFile(f)    
    if not f_elf.has_dwarf_info():
      DEBUG("{0} has no debug informations!".format(file))
      return False
        
    M = CFG_pb2.Module()
    M.name = "GlobalVariable".format('utf-8')
    
    set_global_machine_arch(f_elf.get_machine_arch())
    dwarf_info = f_elf.get_dwarf_info()
    process_types(dwarf_info, TYPES_MAP)    
    process_frames(dwarf_info, EH_FRAMES)
    section_offset = dwarf_info.debug_info_sec.global_offset
    
    # Iterate through all the compile units
    for CU in dwarf_info.iter_CUs():
      DEBUG('Found a compile unit at offset {0}, length {1}'.format(CU.cu_offset, CU['unit_length']))
      top_DIE = CU.get_top_DIE()
      c_unit = CUnit(top_DIE, CU['unit_length'], CU.cu_offset, section_offset)
      c_unit.decode_control_unit(M, GLOBAL_VARIABLES)
        
    for key, value in GLOBAL_VARIABLES.iteritems():
      if value["size"] > 0:
        gvar = M.global_vars.add()
        gvar.name = value["name"]
        gvar.ea = value["addr"]
        gvar.size = value["size"]
      else:
        DEBUG("Look for {}".format(pprint.pformat(value)))
        
    #for func in M.funcs:
    #  DEBUG("Function name {}".format(func.name))
    #  for sv in func.stackvars:
    #    DEBUG_PUSH()
    #    DEBUG("{} : {}, ".format(sv.name, sv.sp_offset))
    #    DEBUG_POP()
        
            
    with open(out_file, "w") as outf:
      outf.write(M.SerializeToString())
     
  DEBUG("Global Vars\n")
  DEBUG('Number of Global Vars: {0}'.format(len(GLOBAL_VARIABLES)))
  DEBUG("{}".format(pprint.pformat(GLOBAL_VARIABLES)))
  DEBUG("End Global Vars\n")

def is_global_variable_reference(global_var, address):
  for key in sorted(global_var.iterkeys()):
    entry = global_var[key]
    start = key
    end = start + entry['size']
    if (start <= address) and (end > address):
      return True
  return False

def add_global_variable_entry(M, ds):
  for g in M.global_vars:
    start = g.address
    end = start + g.var.size
    if (ds.base_address >= start) and (ds.base_address < end):
      symbol = g.symbols.add()
      symbol.base_address = ds.base_address
      symbol.symbol_name = ds.symbol_name
      symbol.symbol_size = ds.symbol_size

def updateCFG(in_file, out_file):
  global_var_array = dict()
    
  M = CFG_pb2.Module()
  with open(in_file, 'rb') as inf:
    M.ParseFromString(inf.read())
    GV = list(M.global_vars)
    DEBUG('Number of Global Variables recovered from dwarf: {0}'.format(len(GLOBAL_VARIABLES)))
    for g in GV:
      gvar = address_lookup(g, global_var_array)
      if gvar is None:
        DEBUG("Global Vars {} {}".format(str(g.var.name), hex(g.address)))
        M.global_vars.remove(g)
             
    for key in sorted(global_var_array.iterkeys()):
      entry = global_var_array[key]
      var = M.global_vars.add()
      var.address = key
      var.var.name = entry['name']
      var.var.size = entry['size']
      var.var.ida_type = entry['type']
      for i in entry["addrs"]:
        r = var.var.ref_eas.add()
        r.inst_addr = i[0]
        r.offset = i[1]
                
    for data in M.internal_data:
      for ds in data.symbols:
        symbol = ds.symbol_name.split("_")
        if (symbol[0] == 'data') and (is_global_variable_reference(global_var_array, long(symbol[1], 16)) is True):
          ds.symbol_name = "recovered_global_{0:x}".format(long(symbol[1], 16))
          add_global_variable_entry(M, ds)
                        
    with open(out_file, "w") as outf:
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
    
  args = parser.parse_args(sys.argv[1:])
    
  if args.log_file:
      DEBUG_INIT(args.log_file, True)
      DEBUG("Debugging is enabled.")
        
  BINARY_FILE = args.binary
  process_dwarf_info(args.binary, args.out)
    