#!/usr/bin/env python

import sys
import argparse
import collections
from binaryninja import *

_DEBUG = True
_DEBUG_FILE = sys.stderr

def DEBUG(s):
    global _DEBUG, _DEBUG_FILE
    if _DEBUG:
        _DEBUG_FILE.write("{}\n".format(str(s)))
    
def _normalize_global_var_name(value):
    return "recovered_global_{0:x}".format(value)

def _create_global_var_entry(memory_ref, var_name):
    return dict(reads=set(), writes=set(), addrs=set(), size=-1, name=var_name, offset=memory_ref, data="\x00", safe=True)

def _process_add(bview, instr, global_var_data):
    pass

def _process_reg(bview, instr, global_var_data):
    # Possible LEA instruction loading memory address to a register
    if type(instr.src) is not LowLevelILOperation:
        return
    
    if (instr.src.operation == LowLevelILOperation.LLIL_CONST and
        instr.dest.operation == LowLevelILOperation.LLIL_REG):
        var_name = _normalize_global_var_name(instr.src.value)
        memory_ref = hex(instr.src.value)
        if memory_ref not in global_var_data:
            global_var_data[memory_ref] = _create_global_var_entry(memory_ref, var_name)
            global_var_data[memory_ref]["addrs"].add(hex(instr.address))
            global_var_data[memory_ref]["safe"] = False
            global_var_data[memory_ref]["size"] = instr.src.size

def _process_load(bview, instr, global_var_data):
    # check if memory reference is of type LLIL_CONST
    if (instr.src.operation == LowLevelILOperation.LLIL_CONST):
        var_name = _normalize_global_var_name(instr.src.value)
        memory_ref = hex(instr.src.value)
        if memory_ref not in global_var_data:
            global_var_data[memory_ref] = _create_global_var_entry(memory_ref, var_name)
            global_var_data[memory_ref]["reads"].add(hex(instr.address))
            global_var_data[memory_ref]["size"] = instr.src.size
            global_var_data[memory_ref]["data"] = bview.read(instr.src.value, instr.src.size)

def _process_store(bview, instr, global_var_data):
    # check if memory reference is of type LLIL_CONST
    if (instr.dest.operation == LowLevelILOperation.LLIL_CONST):
        var_name = _normalize_global_var_name(instr.dest.value)
        memory_ref = hex(instr.dest.value)
        if memory_ref not in global_var_data:
            global_var_data[memory_ref] = _create_global_var_entry(memory_ref, var_name)
            global_var_data[memory_ref]["writes"].add(hex(instr.address))
            global_var_data[memory_ref]["size"] = instr.dest.size
            global_var_data[memory_ref]["data"] = bview.read(instr.dest.value, instr.dest.size)

def _process_call(bview, instr, global_var_data):
    pass

LLIL_OPERATIONS = collections.defaultdict(lambda: (lambda *args: None))

LLIL_OPERATIONS = {
    LowLevelILOperation.LLIL_ADD : _process_add,
    LowLevelILOperation.LLIL_REG : _process_reg,
    LowLevelILOperation.LLIL_LOAD : _process_load,
    LowLevelILOperation.LLIL_STORE : _process_store,
    LowLevelILOperation.LLIL_CALL : _process_call
}

def _process_instruction(bview, instr, global_var_data):
    func_ = LLIL_OPERATIONS.get(instr.operation)
    if func_ :
        func_(bview, instr, global_var_data)
    
def _process_basic_block(bview, F, BB, visited_bb, global_var_data):
    visited_bb.add(BB)
    for instr in BB:
        _process_instruction(bview, instr, global_var_data)
        
def _find_local_references(bview, F, global_var_data):
    visited_bb = set()
    for BB in F.low_level_il.basic_blocks:
        _process_basic_block(bview, F, BB, visited_bb, global_var_data)

        
def collect_function_vars(bview, F, global_var_data):
    _find_local_references(bview, F, global_var_data)
        
def collect_variables(binary):
    global_variables = dict()
    bview = BinaryViewType["ELF"].open(binary)
    bview.update_analysis_and_wait()
    funcs = bview.functions
    
    for fn in funcs:
        DEBUG("Analysis function: {0} {1:x}".format(fn.symbol.name, fn.start))
        collect_function_vars(bview, fn, global_variables)
        
    return {"functions":funcs, "globals":global_variables}

def recoverVariables(binary):
    variable_data = collect_variables(binary)
    
    DEBUG("Global Vars:")
    for gvar in variable_data["globals"]:
        DEBUG("{0} : {1}".format(gvar, variable_data["globals"][gvar]))
    DEBUG("End Global Vars")
        
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    
    parser.add_argument("--log_file", type=argparse.FileType('w'),
                        default=sys.stderr,
                        help='Name of the log file. Default is stderr.')
    
    parser.add_argument('--arch',
                        help='Name of the architecture.',
                        required=True)
    
    parser.add_argument('--binary',
                        help='Name of the binary image.',
                        required=True)
    
    args = parser.parse_args(sys.argv[1:])
    
    if args.log_file:
        _DEBUG = True
        _DEBUG_FILE = args.log_file
        DEBUG("Debugging is enabled.")
    
    recoverVariables(args.binary)
