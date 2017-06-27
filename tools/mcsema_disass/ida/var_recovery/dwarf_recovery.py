#!/usr/bin/env python

import sys
import argparse
import collections

from elftools.elf.elffile import ELFFile
from elftools.common.py3compat import itervalues
from elftools.dwarf.descriptions import (describe_DWARF_expr, set_global_machine_arch)
from elftools.dwarf.descriptions import describe_attr_value
from elftools.dwarf.locationlists import LocationEntry
from elftools.common.py3compat import maxint, bytes2str

import mcsema_disass.ida.CFG_pb2 as CFG_pb2

_DEBUG_FILE = sys.stderr

DWARF_OPERATIONS = collections.defaultdict(lambda: (lambda *args: None))
DWARF_CU = set()
STRUCT_TYPES_TAG = dict()
BASE_TYPES_TAG = dict()
GLOBAL_VARIABLES = dict()

def DEBUG(s):
    _DEBUG_FILE.write("{}\n".format(str(s)))
    
def show_loclist(loclist, dwarfinfo, indent):
    """ 
        Display a location list nicely, decoding the DWARF expressions
        contained within.
    """
    d = []
    for loc_entity in loclist:
        if isinstance(loc_entity, LocationEntry):
            d.append('%s <<%s>>' % (
                loc_entity,
                describe_DWARF_expr(loc_entity.loc_expr, dwarfinfo.structs)))
        else:
            d.append(str(loc_entity))
    return '\n'.join(indent + s for s in d)

def _print_die(DIE, section_offset):
    for attr in itervalues(DIE.attributes):
        if attr.name == 'DW_AT_name' :
            variable_name = attr.value
        name = attr.name
        if isinstance(name, int):
            name = 'Unknown AT value: %x' % name
        DEBUG('    <%x>   %-18s: %s' % (attr.offset, name, describe_attr_value(attr, DIE, section_offset)))
        

def _create_type_entry(offset, type_name, type_size):
    return dict(name=type_name, offset=offset, size=type_size)

def _create_variable_entry(var_name, offset):
    return dict(name=var_name, offset=offset, type=0, size=0, addr=0, is_global=False)

def _process_compile_unit_tag(CU, DIE, section_offset):
    return

def _process_structure_tag(CU, DIE, section_offset):
    if DIE.tag != 'DW_TAG_structure_type':
        return
    DEBUG("Processing structure type TAG")
    _print_die(DIE, section_offset)
    offset = DIE.offset
    name = "Unknown"
    size = 0
    for attr in itervalues(DIE.attributes):
        if attr.name == 'DW_AT_name':
            name = attr.value
        if attr.name == 'DW_AT_byte_size':
            size = attr.value
    if offset not in STRUCT_TYPES_TAG:
        STRUCT_TYPES_TAG[offset] = _create_type_entry(offset, name, size)
        
def _process_array_type_tag(CU, DIE, section_offset):
    pass
    
def _process_base_type_tag(CU, DIE, section_offset):
    pass    

def _process_variable_tag(CU, DIE, section_offset):
    if DIE.tag != 'DW_TAG_variable':
        return
    DEBUG("Processing variable TAG")
    _print_die(DIE, section_offset)
    offset = DIE.offset
    variable_name = "Unknown"
    if 'DW_AT_name' in DIE.attributes:
        variable_name = DIE.attributes['DW_AT_name'].value

    if variable_name not in CU._global_variable :
        CU._global_variable[variable_name] = _create_variable_entry(variable_name, offset)
    
    for attr in itervalues(DIE.attributes):
        if attr.name == 'DW_AT_type':
            type_offset = attr.value
            CU._global_variable[variable_name]['type'] = type_offset
            if type_offset in STRUCT_TYPES_TAG:
                size = STRUCT_TYPES_TAG[type_offset]['size']
                CU._global_variable[variable_name]['size'] = size
                
        if attr.name == 'DW_AT_location' and attr.form not in ('DW_FORM_data4', 'DW_FORM_data8', 'DW_FORM_sec_offset'):
            loc_expr = "{}".format(describe_DWARF_expr(attr.value, DIE.cu.structs)).split(':')
            # How to find if the variable is global
            # take help of extra descriptions
            if loc_expr[0][1:] == 'DW_OP_addr':
                CU._global_variable[variable_name]['addr'] = int(loc_expr[1][:-1][1:], 16)
                CU._global_variable[variable_name]['is_global'] = True
    
DWARF_OPERATIONS = {
    'DW_TAG_compile_unit': _process_compile_unit_tag,
    'DW_TAG_base_type': _process_base_type_tag,
    'DW_TAG_structure_type' : _process_structure_tag,
    'DW_TAG_array_type' : _process_array_type_tag,
    'DW_TAG_variable' : _process_variable_tag
}

class CUnit(object):
    def __init__(self, die, cu_len, cu_offset, global_offset = 0):
        self._die = die
        self._length = cu_len
        self._offset = cu_offset
        self._section_offset = global_offset
        self._global_variable = dict()
        self._types = dict()
        
    def _process_child(self, child_die, indent_level):
        indent = indent_level + '  '
        for child in child_die.iter_children():
            func_ = DWARF_OPERATIONS.get(child.tag)
            if func_:
                func_(self, child, self._section_offset)
                continue
            self._process_child(child, indent)
        
    def decode_control_unit(self, indent_level='    '):
        indent = indent_level + '  '
        for child in self._die.iter_children():
            func_ = DWARF_OPERATIONS.get(child.tag)
            if func_:
                func_(self, child, self._section_offset)
                continue
            self._process_child(child, indent)

    def print_control_unit(self):
        DEBUG("Type dictionary {}".format(self._types))
        DEBUG("Variable recovered {}".format(self._global_variable))

def resolve_variable_types():
    for cu in DWARF_CU:
        for name, variable  in cu._global_variable.iteritems():
            type_offset = variable['type']
            if type_offset in STRUCT_TYPES_TAG:
                size = STRUCT_TYPES_TAG[type_offset]['size']
                cu._global_variable[name]['size'] = size
                DEBUG("{0} {1}".format(name, variable))

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
        section_offset = dwarf_info.debug_info_sec.global_offset
        
        # Iterate through all the compile units
        for CU in dwarf_info.iter_CUs():
            DEBUG('Found a compile unit at offset {0}, length {1}'.format(CU.cu_offset, CU['unit_length']))
            top_DIE = CU.get_top_DIE()
            c_unit = CUnit(top_DIE, CU['unit_length'], CU.cu_offset, section_offset)
            DWARF_CU.add(c_unit)
            DEBUG('    Top DIE with tag= {} name={}'.format(top_DIE.tag, top_DIE.get_full_path()))
            c_unit.decode_control_unit()
            c_unit.print_control_unit()
    
    resolve_variable_types()
    DEBUG('Number of control units : {0}'.format(len(DWARF_CU)))

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
        _DEBUG_FILE = args.log_file
        DEBUG("Debugging is enabled.")
    
    process_dwarf_info(args.binary)