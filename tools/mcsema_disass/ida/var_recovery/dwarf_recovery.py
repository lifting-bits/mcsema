#!/usr/bin/env python

import sys
import argparse
import pprint

from collections import defaultdict
from collections import namedtuple
from enum import Enum

from elftools.elf.elffile import ELFFile
from elftools.common.py3compat import itervalues
from elftools.dwarf.descriptions import (describe_DWARF_expr, set_global_machine_arch)
from elftools.dwarf.descriptions import describe_attr_value
from elftools.dwarf.locationlists import LocationEntry
from elftools.common.py3compat import maxint, bytes2str

import mcsema_disass.ida.CFG_pb2 as CFG_pb2

DWARF_OPERATIONS = defaultdict(lambda: (lambda *args: None))

Type = namedtuple('Type', ['name', 'size', 'type_offset', 'tag'])

GLOBAL_VARIABLES = dict()

TYPES_MAP = dict()

BASE_TYPES = [
    'DW_TAG_base_type',
    'DW_TAG_structure_type',
    'DW_TAG_union_type',
]

INDIRECT_TYPES = [
    'DW_TAG_typedef',
    'DW_TAG_const_type',
    'DW_TAG_volatile_type',
    'DW_TAG_restrict_type',
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
_DEBUG_FILE = sys.stderr

def DEBUG(s):
    if _DEBUG:
        _DEBUG_FILE.write("{}\n".format(str(s)))

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
        DEBUG("{}".format(die.attributes))
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
            if die.offset not in typemap:
                typemap[die.offset] = Type(name=name, size=size, type_offset=die.offset, tag=TYPE_ENUM.get(die.tag))
            DEBUG("<{0:x}> {1}".format(die.offset, typemap.get(die.offset)))

    def process_pointer_types(die):
        if die.tag in POINTER_TYPES:
            if 'DW_AT_type' in die.attributes:
                offset = die.attributes['DW_AT_type'].value + die.cu.cu_offset
                indirect = POINTER_TYPES[die.tag]
                name = (typemap[offset].name if offset in typemap else 'UNKNOWN') + indirect
                type_offset = typemap[offset].type_offset if offset in typemap else 0 
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
                        typemap[die.offset] = Type(name=name, size=die.cu['address_size'], type_offset=type_offset, tag=tag)
            DEBUG("<{0:x}> {1}".format(die.offset, typemap.get(die.offset)))
            
    def process_array_types(die):
        if die.tag in ARRAY_TYPES:
            if 'DW_AT_type' in die.attributes:
                offset = die.attributes['DW_AT_type'].value + die.cu.cu_offset
                name = typemap[offset].name if offset in typemap else 'UNKNOWN'
                type_offset = typemap[offset].type_offset if offset in typemap else 0
                size = typemap[offset].size if offset in typemap else 0
                # get sub range to get the array size
                for child_die in die.iter_children():
                    if child_die.tag == 'DW_TAG_subrange_type':
                        if 'DW_AT_upper_bound' in child_die.attributes:
                            size = size*child_die.attributes['DW_AT_upper_bound'].value
                            break
                if die.offset not in typemap:
                    typemap[die.offset] = Type(name=name, size=size, type_offset=type_offset, tag=TYPE_ENUM.get(die.tag))
            DEBUG("<{0:x}> {1}".format(die.offset, typemap.get(die.offset)))
            
    build_typemap(dwarf, process_direct_types)
    build_typemap(dwarf, process_indirect_types)
    build_typemap(dwarf, process_pointer_types)
    build_typemap(dwarf, process_array_types)
    

    
def _process_dies(die, fn):
    fn(die)
    for child in die.iter_children():
        _process_dies(child, fn)

def build_typemap(dwarf, fn):
    for CU in dwarf.iter_CUs():
        top = CU.get_top_DIE()
        _process_dies(top, fn)

def address_lookup(memory_ref):
    gvar = GLOBAL_VARIABLES.get(memory_ref)
    if gvar:
        if (gvar['type'].tag == 1 or gvar['type'].tag == 4):
            DEBUG("Found {}".format(pprint.pformat(gvar)))
            return True
    return False
    
def _print_die(die, section_offset):
    DEBUG("Processing DIE: {}".format(str(die)))
    for attr in itervalues(die.attributes):
        if attr.name == 'DW_AT_name' :
            variable_name = attr.value
        name = attr.name
        if isinstance(name, int):
            name = 'Unknown AT value: %x' % name
        DEBUG('    <%x>   %-18s: %s' % (attr.offset, name, describe_attr_value(attr, die, section_offset)))

def _process_variable_tag(die, section_offset, global_var_data):
    if die.tag != 'DW_TAG_variable':
        return
    name = get_name(die)
    if 'DW_AT_location' in die.attributes:
        attr = die.attributes['DW_AT_location']
        if attr.form not in ('DW_FORM_data4', 'DW_FORM_data8', 'DW_FORM_sec_offset'):
            loc_expr = "{}".format(describe_DWARF_expr(attr.value, die.cu.structs)).split(':')
            if loc_expr[0][1:] == 'DW_OP_addr':
                #_print_die(die, section_offset)   # DEBUG_ENABLE
                memory_ref = int(loc_expr[1][:-1][1:], 16)
                if memory_ref not in  global_var_data:
                    global_var_data[memory_ref] = _create_variable_entry(name, die.offset)
                    global_var_data[memory_ref]['is_global'] = True
                    global_var_data[memory_ref]['addr'] = memory_ref
                    (type, size, offset) = get_types(die)
                    global_var_data[memory_ref]['type'] = type
                    global_var_data[memory_ref]['size'] = size
                    DEBUG("{}".format(pprint.pformat(global_var_data[memory_ref])))  # DEBUG_ENABLE
    
DWARF_OPERATIONS = {
    #'DW_TAG_compile_unit': _process_compile_unit_tag,
    'DW_TAG_variable' : _process_variable_tag
}

class CUnit(object):
    def __init__(self, die, cu_len, cu_offset, global_offset = 0):
        self._die = die
        self._length = cu_len
        self._offset = cu_offset
        self._section_offset = global_offset
        self._global_variable = dict()
        
    def _process_child(self, child_die, global_var_data):
        for child in child_die.iter_children():
            func_ = DWARF_OPERATIONS.get(child.tag)
            if func_:
                func_(child, self._section_offset, global_var_data)
                continue
            self._process_child(child, global_var_data)
        
    def decode_control_unit(self, global_var_data):
        for child in self._die.iter_children():
            func_ = DWARF_OPERATIONS.get(child.tag)
            if func_:
                func_(child, self._section_offset, global_var_data)
                continue
            self._process_child(child, global_var_data)

def process_dwarf_info(file):
    '''
        Main function processing the dwarf informations from debug sections
    '''
    DEBUG('Processing file: {0}'.format(file))
    
    with open(file, 'rb') as f:
        f_elf = ELFFile(f)
        
        if not f_elf.has_dwarf_info():
            DEBUG("{0} has no debug informations!".format(file))
            return
        
        dwarf_info = f_elf.get_dwarf_info()
        process_types(dwarf_info, TYPES_MAP)
        
        section_offset = dwarf_info.debug_info_sec.global_offset
        
        # Iterate through all the compile units
        for CU in dwarf_info.iter_CUs():
            DEBUG('Found a compile unit at offset {0}, length {1}'.format(CU.cu_offset, CU['unit_length']))
            top_DIE = CU.get_top_DIE()
            c_unit = CUnit(top_DIE, CU['unit_length'], CU.cu_offset, section_offset)
            c_unit.decode_control_unit(GLOBAL_VARIABLES)
    
    DEBUG('Number of Global Vars: {0}'.format(len(GLOBAL_VARIABLES)))
    DEBUG("Type Definitions:")
    DEBUG("{}".format(pprint.pformat(TYPES_MAP)))
    DEBUG("End Type Definitions:")
    
    DEBUG("Global Vars\n")
    DEBUG('Number of Global Vars: {0}'.format(len(GLOBAL_VARIABLES)))
    DEBUG("{}".format(pprint.pformat(GLOBAL_VARIABLES)))
    DEBUG("End Global Vars\n")
    
def updateCFG(in_file, out_file):
    M = CFG_pb2.Module()
    with open(in_file, 'rb') as inf:
        M.ParseFromString(inf.read())
        GV = list(M.global_vars)
        DEBUG("Number of Global Variables in CFG : {}".format(len(GV)))
        DEBUG('Number of Global Variables recovered from dwarf: {0}'.format(len(GLOBAL_VARIABLES)))
        for g in GV:
            if address_lookup(g.address) is False:
                DEBUG("Global Vars {} {}".format(str(g.var.name), hex(g.address)))
                M.global_vars.remove(g)
                
    with open(out_file, "w") as outf:
        outf.write(M.SerializeToString())

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    
        
    parser.add_argument("--log_file", type=argparse.FileType('w'),
                        default=sys.stderr,
                        help='Name of the log file. Default is stderr.')
    
    parser.add_argument('--cfg',
                        help='Name of the CFG file.',
                        required=True)
    
    parser.add_argument('--binary',
                        help='Name of the binary image.',
                        required=True)
    
    args = parser.parse_args(sys.argv[1:])
    
    if args.log_file:
        _DEBUG = True
        _DEBUG_FILE = args.log_file
        DEBUG("Debugging is enabled.")
        
    process_dwarf_info(args.binary)
    updateCFG(args.cfg, args.cfg)