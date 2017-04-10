#!/usr/bin/env python

# Copyright (c) 2017, Trail of Bits
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
# Redistributions of source code must retain the above copyright notice, this
# list of conditions and the following disclaimer.
#
# Redistributions in binary form must reproduce the above copyright notice, this
# list of conditions and the following disclaimer in the documentation and/or
# other materials provided with the distribution.
#
# Neither the name of Trail of Bits nor the names of its
# contributors may be used to endorse or promote products derived from
# this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
# ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


##
## Instructions:
## 1) Install python-protobuf for your IDAPython installation. This probably means
## downloading it from https://protobuf.googlecode.com/files/protobuf-2.5.0.tar.gz
## and manually running setup.py
## 2) This script should be run via IDA's batch mode. See the output 
## of --help for more details on the command line options.
##

import idautils
import idaapi
import idc
import sys
from os import path
import os
import argparse
import struct
#import syslog
import traceback
import collections
import itertools

# Bring in utility libraries.
from util import *
from table import *
from flow import *
from refs import *
from segment import *

#hack for IDAPython to see google protobuf lib
if os.path.isdir('/usr/lib/python2.7/dist-packages'):
    sys.path.append('/usr/lib/python2.7/dist-packages')

if os.path.isdir('/usr/local/lib/python2.7/dist-packages'):
    sys.path.append('/usr/local/lib/python2.7/dist-packages')

tools_disass_ida_dir = os.path.dirname(__file__)
tools_disass_dir = os.path.dirname(tools_disass_ida_dir)

# Note: The bootstrap file will copy CFG_pb2.py into this dir!!
import CFG_pb2

EXTERNAL_FUNCS_TO_RECOVER = {}
EXTERNAL_VARS_TO_RECOVER = {}

RECOVERED_EAS = set()
ACCESSED_VIA_JMP = set()

# Map of external functions names to a tuple containing information like the
# number of arguments and calling convention of the function.
EMAP = {}

# Map of external variable names to their sizes, in bytes.
EMAP_DATA = {}

# `True` if we are getting the CFG of a position independent executable. This
# affects heuristics like trying to turn immediate operands in instructions
# into references into the data.
PIE_MODE = False

# Name of the operating system that runs the program being lifted. E.g. if
# we're lifting an ELF then this will typically be `linux`.
OS_NAME = ""

# Set of substrings that can be found inside of symbol names that are usually
# signs that the symbol is external. For example, `stderr@@GLIBC_2.2.5` is
# really the external `stderr`, so we want to be able to chop out the `@@...`
# part to resolve the "true" name,
EXTERNAL_NAMES = ("@@GLIBC_",)

def is_ELF_program():
    """Returns `True` if the type of the program being recovered is an ELF."""
    return idc.GetLongPrm(idc.INF_FILETYPE) == idc.FT_ELF

# Returns `True` if this is an ELF binary (as opposed to an ELF object file).
def is_linked_ELF_program():
    return idc.GetLongPrm(idc.INF_FILETYPE) == idc.FT_ELF and \
        idc.BeginEA() not in [0xffffffffL, 0xffffffffffffffffL]

def is_ELF_got_pointer(ea):
    """Returns `True` if this is a pointer to a pointer stored in the
    `.got` section of an ELF binary. For example, `__gmon_start___ptr` is
    a pointer in the `.got` that will be fixed up to contain the address of
    the external function `__gmon_start__`. We don't want to treat
    `__gmon_start___ptr` as external because it is really a sort of local
    variable that will will resolve with a data cross-reference."""
    seg_name = idc.SegName(ea).lower()
    if ".got" not in seg_name:
        return False

    name = get_symbol_name(ea)
    if not name.endswith("_ptr"):
        return False

    target_ea = get_reference_target(ea)
    target_name = get_true_external_name(get_symbol_name(target_ea))

    if target_name not in name:
        return False

    return is_referenced_by(target_ea, ea)

def is_ELF_got_pointer_to_external(ea):
    """Similar to `is_ELF_got_pointer`, but requires that the eventual target
    of the pointer is an external."""
    if not is_ELF_got_pointer(ea):
        return False

    target_ea = get_reference_target(ea)
    return is_external_segment(target_ea)

_FIXED_EXTERNAL_NAMES = {}

def get_true_external_name(fn):
    """Tries to get the 'true' name of `fn`. This removes things like
    ELF-versioning from symbols."""
    if not fn:
        return ""

    orig_fn = fn
    if fn in _FIXED_EXTERNAL_NAMES:
        return _FIXED_EXTERNAL_NAMES[orig_fn]

    if fn in EMAP:
        return fn

    if fn in EMAP_DATA:
        return fn

    # TODO(pag): Is this a macOS or Windows thing?
    if not is_linked_ELF_program() and fn[0] == '_':
        return fn[1:]

    if fn.endswith("_0"):
        newfn = fn[:-2]
        if newfn in EMAP:
            return newfn

    # Go and strip off things like the `@@GLIBC_*` symbol suffixes.
    for en in EXTERNAL_NAMES:
        if en in fn:
            fn = fn[:fn.find(en)]
            break

    # In some cases we'll have something like a reference to `stderr_ptr` in
    # the `.got` section, and that will have a pointer that is the actual
    # external `stderr`.
    ea = idc.LocByName(orig_fn)
    if is_ELF_got_pointer_to_external(ea):
        name = get_symbol_name(get_reference_target(ea))
        if name:
            fn = handleExternalRef(name)

    # DEBUG("True name of {} at {:x} is {}".format(orig_fn, ea, fn))
    _FIXED_EXTERNAL_NAMES[orig_fn] = fn
    return fn

# Set of symbols that IDA identifies as being "weak" symbols. In ELF binaries,
# a weak symbol is kind of an optional linking thing. For example, the 
# `__gmon_start__` function is referenced as a weak symbol. This function is
# used for gcov-based profiling. If gcov is available, then this symbol will
# be resolved to a real function, but if not, it will be NULL and programs
# will detect it as such. An example use of a weak symbol in C would be:
#
#       extern void __gmon_start__(void) __attribute__((weak));
#       ...
#       if (__gmon_start__) {
#           __gmon_start__();
#       }
WEAK_SYMS = set()

def parse_os_defs_file(df):
    """Parse the file containing external function and variable
    specifications."""
    global OS_NAME, WEAK_SYMS, EMAP, EMAP_DATA
    is_linux = OS_NAME == "linux"
    for l in df.readlines():
        #skip comments / empty lines
        l = l.strip()
        if not l or l[0] == "#":
            continue

        if l.startswith('DATA:'):
            # process as data
            (marker, symname, dsize) = l.split()
            if 'PTR' in dsize:
                dsize = get_address_size_in_bytes()
            EMAP_DATA[symname] = int(dsize)

            # Sometimes there will be things like `__gmon_start___ptr` which
            # is really a pointer to the implementation of `__gmon_start__`.
            if is_linux:
                ptr_name = "{}_ptr".format(symname)
                if idc.LocByName(symname):
                    _FIXED_EXTERNAL_NAMES[ptr_name] = symname

        else:
            fname = args = conv = ret = sign = None
            line_args = l.split()
            if len(line_args) == 2:
                fname, conv = line_args
                if conv == "MCSEMA":
                    DEBUG("Found mcsema internal function: {}".format(fname))
                    realconv = CFG_pb2.ExternalFunction.McsemaCall
                    EMAP[fname] = (1, realconv, 'N', None)
                    continue
                else:
                    raise Exception("Unknown calling convention:"+str(conv))

            if len(line_args) == 4:
                (fname, args, conv, ret) = line_args
            elif len(line_args) == 5:
                (fname, args, conv, ret, sign) = line_args

            if conv == "C":
                realconv = CFG_pb2.ExternalFunction.CallerCleanup
            elif conv == "E":
                realconv = CFG_pb2.ExternalFunction.CalleeCleanup
            elif conv == "F":
                realconv = CFG_pb2.ExternalFunction.FastCall
            else:
                raise Exception("Unknown calling convention:"+str(l))

            if ret not in ['Y', 'N']:
                raise Exception("Unknown return type:"+ret)

            ea = idc.LocByName(fname)
            if ea != idc.BADADDR \
            and ea < 0xff00000000000000 \
            and not is_external_segment(ea) \
            and not is_thunk(ea):
                DEBUG("Not treating {} as external, it is defined at {:x}".format(
                    fname, ea))
                continue

            EMAP[fname] = (int(args), realconv, ret, sign)

            # Sometimes there will be things like `__imp___gmon_start__` which
            # is really the implementation of `__gmon_start__`, where that is
            # a weak symbol.
            if is_linux:
                global _FIXED_EXTERNAL_NAMES
                imp_name = "__imp_{}".format(fname)

                if idc.LocByName(imp_name):
                    _FIXED_EXTERNAL_NAMES[imp_name] = fname
                    WEAK_SYMS.add(fname)
                    WEAK_SYMS.add(imp_name)

                ptr_name = "{}_ptr".format(fname)
                if idc.LocByName(ptr_name):
                    _FIXED_EXTERNAL_NAMES[ptr_name] = fname

    df.close()

def is_external_reference(ea):
    """Returns `True` if `ea` references external data."""

    # TODO(pag): Use `is_ELF_got_pointer_to_external`?
    return is_external_segment(ea) \
        or ea in EXTERNAL_VARS_TO_RECOVER \
        or ea in EXTERNAL_FUNCS_TO_RECOVER

def get_function_name(ea):
    """Return name of a function, as IDA sees it. This includes allowing
    dummy names, e.g. `sub_abc123`."""
    return get_symbol_name(ea, ea, allow_dummy=True)

def handleExternalRef(fn):
    # Don't mangle symbols for fully linked ELFs... yet
    in_a_map = fn in EMAP or fn in EMAP_DATA
    if not is_linked_ELF_program():
        if fn.startswith("__imp_"):
            fn = fn[6:]

        if fn.endswith("_0"):
            fn = fn[:-2]

        # name could have been modified by the above tests
        in_a_map = fn in EMAP or fn in EMAP_DATA

        if fn.startswith("_") and not in_a_map:
            fn = fn[1:]

        if fn.startswith("@") and not in_a_map:
            fn = fn[1:]

        if is_ELF_program() and '@' in fn:
            fn = fn[:fn.find('@')]

    fixfn = get_true_external_name(fn)
    return fixfn

_ELF_THUNKS = {}
_NOT_ELF_THUNKS = set()
_INVALID_THUNK = (False, None)

def is_ELF_thunk_by_structure(ea):
    """Try to manually identify an ELF thunk by its structure. The structure
    of this kind of thunk is usually something like:
        
            .plt:00041F10 _qsort          proc near               
            .plt:00041F10                 jmp     cs:off_31F388
            .plt:00041F10 _qsort          endp

    With:

        .got.plt:0031F388 off_31F388      dq offset qsort
    """
    global _INVALID_THUNK

    if ".plt" not in idc.SegName(ea).lower():
        return _INVALID_THUNK

    inst, _ = decode_instruction(ea)
    if not inst or not is_indirect_jump(inst):
        return _INVALID_THUNK

    # TODO(pag): Use `get_reference_target`?
    real_ext_ref = get_reference_target(inst.ea)
    for got_plt_ea in idautils.CodeRefsFrom(ea, 0):
        if is_external_segment(got_plt_ea):
            real_ext_ref = got_plt_ea
            break

    if real_ext_ref is None:
        return _INVALID_THUNK

    for dref in idautils.DataRefsFrom(ea):
        if ".got" in idc.SegName(dref).lower():
            # this is an external call after all
            for extref in idautils.DataRefsFrom(dref):
                if is_external_segment(extref):
                    real_ext_ref = extref

    if real_ext_ref is None:
        return _INVALID_THUNK
    
    return True, handleExternalRef(get_function_name(real_ext_ref))

def is_thunk_by_flags(ea):
    """Try to identify a thunk based off of the IDA flags. This isn't actually
    specific to ELFs.

    IDA seems to have a kind of thunk-propagation. So if one thunk calls
    another thunk, then the former thing is treated as a thunk. The former
    thing will not actually follow the 'structured' form matched above, so
    we'll try to recursively match to the 'final' referenced thunk."""
    global _INVALID_THUNK

    if not is_thunk(ea):
        return _INVALID_THUNK
    
    ea_name = get_function_name(ea)
    inst, _ = decode_instruction(ea)
    if not inst:
        DEBUG("{} at {:x} is a thunk with no code??".format(ea_name, ea))
        return _INVALID_THUNK

    # Recursively find thunk-to-thunks.
    if is_direct_jump(inst) or is_direct_function_call(inst):
        targ_ea = get_direct_branch_target(inst)
        targ_is_thunk, targ_thunk_name = is_thunk(targ_ea)
        if targ_is_thunk:
            DEBUG("Found thunk-to-thunk {:x} -> {:x}: {} to {}".format(
                ea, targ_ea, ea_name, targ_thunk_name))
            return True, targ_thunk_name
        
        DEBUG("ERROR? targ_ea={:x} is not thunk".format(targ_ea))

    if not is_external_reference(ea):
        return _INVALID_THUNK

    return True, handleExternalRef(ea_name)

def try_get_thunk_name(ea):
    """Try to figure out if a function is actually a thunk, i.e. a function
    that represents a 'local' definition for an external function. Thunks work
    by having the local function jump through a function pointer that is
    resolved at runtime."""
    global _ELF_THUNKS, _NOT_ELF_THUNKS, _INVALID_THUNK

    if ea in _ELF_THUNKS:
        return _ELF_THUNKS[ea]

    if ea in _NOT_ELF_THUNKS:
        _NOT_ELF_THUNKS.add(ea)
        return _INVALID_THUNK

    # Try two approaches to detecting whether or not
    # something is a thunk.
    is_thunk = False
    if is_ELF_program():
        is_thunk, name = is_ELF_thunk_by_structure(ea)

    if not is_thunk:
        is_thunk, name = is_thunk_by_flags(ea)
    
    if not is_thunk:
        _NOT_ELF_THUNKS.add(ea)
        return _INVALID_THUNK
    else:
        _ELF_THUNKS[ea] = (is_thunk, name)
        return is_thunk, name

def is_start_of_function(ea):
    """Returns `True` if `ea` is the start of a function."""
    return is_code(ea) and ea == idc.LocByName(idc.GetFunctionName(ea))

_REFERENCE_OPERAND_TYPE = {
    Reference.IMMEDIATE: CFG_pb2.CodeReference.ImmediateOperand,
    Reference.DISPLACEMENT: CFG_pb2.CodeReference.MemoryDisplacementOperand,
    Reference.MEMORY: CFG_pb2.CodeReference.MemoryOperand,
    Reference.CODE: CFG_pb2.CodeReference.ControlFlowOperand,
}

def reference_target_type(ref):
    """Sometimes code references into the GOT would be treated as data
    references. We fall back onto our external maps as an oracle for
    what the type should really be. This has happened with `pcre_free`
    references from Apache."""
    if is_external_reference(ref.addr):
        if ref.addr in EXTERNAL_VARS_TO_RECOVER:
            return CFG_pb2.CodeReference.DataTarget
        elif ref.addr in EXTERNAL_FUNCS_TO_RECOVER:
            return CFG_pb2.CodeReference.CodeTarget

    if is_code(ref.addr):
        return CFG_pb2.CodeReference.CodeTarget
    else:
        return CFG_pb2.CodeReference.DataTarget

def reference_operand_type(ref):
    global _REFERENCE_OPERAND_TYPE
    return _REFERENCE_OPERAND_TYPE[ref.type]

def reference_location(ref):
    if is_external_reference(ref.addr):
        return CFG_pb2.CodeReference.External
    else:
        return CFG_pb2.CodeReference.Internal

def referenced_name(ref):
    if ref.addr in EXTERNAL_VARS_TO_RECOVER:
        return EXTERNAL_VARS_TO_RECOVER[ref.addr]
    elif ref.addr in EXTERNAL_FUNCS_TO_RECOVER:
        return EXTERNAL_FUNCS_TO_RECOVER[ref.addr]
    else:
        return get_true_external_name(ref.symbol)

_TARGET_NAME = {
    CFG_pb2.CodeReference.CodeTarget: "code",
    CFG_pb2.CodeReference.DataTarget: "data",
}

_OPERAND_NAME = {
    CFG_pb2.CodeReference.ImmediateOperand: "imm",
    CFG_pb2.CodeReference.MemoryDisplacementOperand: "disp",
    CFG_pb2.CodeReference.MemoryOperand: "mem",
    CFG_pb2.CodeReference.ControlFlowOperand: "flow",
}

_LOCATION_NAME = {
    CFG_pb2.CodeReference.External: "external",
    CFG_pb2.CodeReference.Internal: "internal",
}

def format_instruction_reference(ref):
    """Returns a string representation of a cross reference contained
    in an instruction."""
    return "({} {} {} {:x} {})".format(
        _TARGET_NAME[ref.target_type],
        _OPERAND_NAME[ref.operand_type],
        _LOCATION_NAME[ref.location],
        ref.address,
        ref.HasField('name') and ref.name or "")

def recover_instruction_references(I, inst, addr):
    """Add the memory/code reference information from this instruction
    into the CFG format. The LLVM side of things needs to be able to
    match instruction operands to references to internal/external
    code/data.

    The `get_instruction_references` gives us an accurate picture of the
    references as they are, but in practice we want a higher-level perspective
    that resolves things like thunks to their true external representations.

    Note: References are a kind of gotcha that need special explaining. We kind
    of 'devirtualize' references. An example of this is:
        
        extern:00000000002010A8                 extrn stderr@@GLIBC_2_2_5

        extern:00000000002010D8 ; struct _IO_FILE *stderr
        extern:00000000002010D8                 extrn stderr
                            |                   ; DATA XREF: .got:stderr_ptr
                            `-------------------------------.
                                                            |                       
          .got:0000000000200FF0 stderr_ptr      dq offset stderr
                                  |             ; DATA XREF: main+12
                                  `-------------------------------.
                                                                  | 
         .text:0000000000000932                 mov     rax, cs:stderr_ptr
         .text:0000000000000939                 mov     rdi, [rax]      ; stream
                                    ...
         .text:0000000000000949                 call    _fprintf
    
    So above we see that the `mov` instruction is dereferencing `stderr_ptr`,
    and from there it's getting the address of `stderr`. Then it dereferences
    that, which is the value of `stderr, getting us the address of the `FILE *`.
    That is passed at the first argument to `fprintf`.

    Now, what we see in the `mcseam-disass` log is a bit different.

            Variable at 200ff0 is the external stderr
            Variable at 2010a8 is the external stderr
            Variable at 2010d8 is the external stderr
                            ...
            I: 932 (data mem external 200ff0 stderr)

    So even though the `mov` instruction uses `stderr_ptr` and an extra level
    of indirection, we devirtualize that to `stderr`. But, how could this work?
    It seems like it's removing a layer of indirection. The answer is on the
    LLVM side of things.

    On the LLVM side, `stderr` is a global variable:

            @stderr = external global %struct._IO_FILE*, align 8

    And the corresponding call is:

        %4 = load %struct._IO_FILE*, %struct._IO_FILE** @stderr, align 8
        %5 = call i32 (...) @fprintf(%struct._IO_FILE* %4, i8* ...)

    So now we see that by declaring the global variable `stderr` on the LLVM
    side, we regain this extra level of indirection because all global variables
    are really pointers to their type (i.e. `%struct._IO_FILE**`), thus we
    preserve the intent of the original assembly.
    """
    DEBUG_PUSH()
    debug_info = ["I: {:x}".format(addr)]
    refs = get_instruction_references(inst, PIE_MODE)
    for ref in refs:

        target_type = reference_target_type(ref)
        location = reference_location(ref)

        # Don't add code flows that go to internal code.
        if ref.type == Reference.CODE \
        and CFG_pb2.CodeReference.CodeTarget == target_type \
        and CFG_pb2.CodeReference.Internal == location:
            continue

        addrs = set()
        R = I.xrefs.add()
        R.address = ref.addr
        R.operand_type = reference_operand_type(ref)
        R.target_type = target_type
        R.location = location
        name = referenced_name(ref)
        if name:
            R.name = name.format('utf-8')
        
        debug_info.append(format_instruction_reference(R))

    DEBUG_POP()
    DEBUG(" ".join(debug_info))

def recover_instruction(M, B, ea):
    """Recover an instruction, adding it to its parent block in the CFG."""
    inst, inst_bytes = decode_instruction(ea)

    I = B.instructions.add()
    I.ea = ea  # May not be `inst.ea` because of prefix coalescing.
    I.bytes = inst_bytes
    recover_instruction_references(I, inst, ea)

    if is_noreturn_inst(inst):
        I.local_noreturn = True

    table = get_jump_table(inst, PIE_MODE)
    if table:
        I.jump_table_addr = table.table_ea
        I.offset_base_addr = table.offset

def recover_basic_block(M, F, block_ea):
    """Add in a basic block to a specific function in the CFG."""
    inst_eas, succ_eas = analyse_block(
        F.ea, block_ea, PIE_MODE)

    DEBUG("BB: {:x} in func {:x} with {} insts".format(
        block_ea, F.ea, len(inst_eas)))
    
    B = F.blocks.add()
    B.ea = block_ea
    B.successor_eas.extend(succ_eas)

    DEBUG_PUSH()
    for inst_ea in inst_eas:
        recover_instruction(M, B, inst_ea)

    DEBUG_PUSH()
    if len(succ_eas) > 0:
        DEBUG("Successors: {}".format(", ".join("{0:x}".format(i) for i in succ_eas)))
    else:
        DEBUG("No successors")
    DEBUG_POP()
    DEBUG_POP()

def analyze_jump_table_targets(inst, new_eas, new_func_eas):
    """Function recovery is an iterative process. Sometimes we'll find things
    in the entries of the jump table that we need to go mark as code to be
    added into the CFG."""
    table = get_jump_table(inst, PIE_MODE)
    if not table:
        return

    for entry_addr, entry_target in table.entries.items():
        if is_start_of_function(entry_target):
            DEBUG("  Jump table {:x} entry at {:x} references function at {:x}".format(
                table.table_ea, entry_addr, entry_target))
            new_func_eas.add(entry_target)
        else:
            DEBUG("  Jump table {:x} entry at {:x} references block at {:x}".format(
                table.table_ea, entry_addr, entry_target))
            new_eas.add(entry_target)

_RECOVERED_FUNCS = set()

def recover_function(M, func_ea, new_func_eas, entrypoints):
    """Decode a function and store it, all of its basic blocks, and all of
    their instructions into the CFG file."""
    global _RECOVERED_FUNCS
    if func_ea in _RECOVERED_FUNCS:
        return

    _RECOVERED_FUNCS.add(func_ea)

    if not is_start_of_function(func_ea):
        DEBUG("{:x} is not a function! Not recovering.".format(func_ea))
        return

    DEBUG("Recovering {:x}".format(func_ea))
    DEBUG_PUSH()
    F = M.funcs.add()
    F.ea = func_ea
    F.is_entrypoint = (func_ea in entrypoints)
    name = get_symbol_name(func_ea)
    if name:
        F.name = name.format('utf-8')

    blockset, term_insts = analyse_subroutine(func_ea, PIE_MODE)

    for term_inst in term_insts:
        if get_jump_table(term_inst, PIE_MODE):
            DEBUG("Terminator inst {:x} in func {:x} is a jump table".format(
                term_inst.ea, func_ea))
            analyze_jump_table_targets(term_inst, blockset, new_func_eas)
    
    processed_blocks = set()
    while len(blockset) > 0:
        block_ea = blockset.pop()
        if block_ea in processed_blocks:
            DEBUG("ERROR: Attempting to add same block twice: {0:x}".format(block_ea))
            continue

        processed_blocks.add(block_ea)
        recover_basic_block(M, F, block_ea)

    DEBUG_POP()

def find_default_function_heads():
    """Loop through every function, to discover the heads of all blocks that
    IDA recognizes. This will populate some global sets in `flow.py` that
    will help distinguish block heads."""
    
    func_heads = set()
    for seg_ea in idautils.Segments():
        seg_type = idc.GetSegmentAttr(seg_ea, idc.SEGATTR_TYPE)
        if seg_type != idc.SEG_CODE:
            continue
        for func_ea in idautils.Functions(seg_ea, idc.SegEnd(seg_ea)):
            if is_code(func_ea):
                func_heads.add(func_ea)
    return func_heads

def recover_segment_variables(M, S, seg_ea, seg_end_ea):
    """Look for named locations pointing into the data of this segment, and
    add them to the protobuf."""
    for ea, name in idautils.Names():
        if ea < seg_ea or ea >= seg_end_ea:
            continue

        if is_external_reference(ea):
            continue

        # Only add named internal variables if they are referenced.   
        if is_referenced(ea):
            DEBUG("Variable {} at {:x}".format(name, ea))
            V = S.vars.add()
            V.ea = ea
            V.name = name.format('utf-8')

def recover_segment_cross_references(M, S, seg_ea, seg_end_ea):
    """Goes through the segment and identifies fixups that need to be
    handled by the LLVM side of things."""

    # Go through and look for the fixups. We start at `seg_ea - 1` because we
    # always try to find the *next* fixup/heads, and if there's one right at
    # the beginning of the segment then we don't want to jump to the second one.
    ea = seg_ea - 1
    while ea < seg_end_ea:
        ea = min(idc.GetNextFixupEA(ea), idc.NextHead(ea, seg_end_ea))
        if ea < seg_ea:
            continue
        elif ea >= seg_end_ea:
            break

        # We don't want to fill the jump table bytes with their actual
        # code cross-references. This is because we can't get the address
        # of a basic block. Our goal is thus to preserve the original values,
        # and implement the switch in terms of those original values on the
        # LLVM side of things.
        if is_jump_table_entry(ea):
            continue

        if not is_reference(ea):
            continue

        # Note: it's possible that `ea == target_ea`. This happens with
        #       external references to things like `stderr`, where there's 
        #       an internal slot, whose value is filled in at runtime. 
        target_ea = get_reference_target(ea)
        
        if target_ea == idc.BADADDR or 0 > target_ea or 0xff00000000000000 <= target_ea:
            DEBUG("ERROR: Reference at {:x} is not a reference.".format(ea))
            continue

        # Probably `idc.BADADDR`, or some really small number.
        elif not idc.GetFlags(target_ea):
            continue

        elif (ea % 4) != 0:
            DEBUG("ERROR: Unaligned reference at {:x} to {:x}".format(ea, target_ea))
        
        else:
            X = S.xrefs.add()
            X.ea = ea
            X.width = min(max(idc.ItemSize(ea), 4), 8)
            X.target_ea = target_ea
            target_name = get_symbol_name(target_ea)
            if is_runtime_external_data_reference(ea):
                X.target_name = get_true_external_name(target_name)
            else:
                X.target_name = target_name
            X.target_is_code = is_code(target_ea)
            DEBUG("{}-byte reference at {:x} to {:x} ({})".format(
                X.width, ea, target_ea, X.target_name))

def recover_segment(M, seg_ea):
    """Recover the data and cross-references from a segment. The data of a
    segment is stored verbatim within the protobuf, and accompanied by a
    series of variable and cross-reference entries."""

    seg_name = idc.SegName(seg_ea)
    seg_end_ea = idc.SegEnd(seg_ea)
    DEBUG("Recovering segment {} [{:x}, {:x})".format(
        seg_name, seg_ea, seg_end_ea))
    seg_size = seg_end_ea - seg_ea
    seg = idaapi.getseg(seg_ea)

    S = M.segments.add()
    S.ea = seg_ea
    S.data = read_bytes_slowly(seg_ea, seg_end_ea)
    S.read_only = (seg.perm & idaapi.SEGPERM_WRITE) == 0
    S.is_external = is_external_segment(seg_ea)
    S.name = seg_name.format('utf-8')

    # Don't look for fixups in the code segment. These are all handled as
    # `CodeReference`s and stored in the `Instruction`s themselves. We also
    # don't want to mark jump table entries embedded in the code section
    # either (see comment below), so this captures that case as well.
    seg_type = idc.GetSegmentAttr(seg_ea, idc.SEGATTR_TYPE)
    if seg_type == idc.SEG_CODE:
        S.read_only = True  # Force this even if it's not true.
        return  # Don't process xrefs or variables.

    DEBUG_PUSH()
    recover_segment_cross_references(M, S, seg_ea, seg_end_ea)
    recover_segment_variables(M, S, seg_ea, seg_end_ea)
    DEBUG_POP()

def recover_segments(M):
    """Recover all non-external segments into the CFG module."""
    for seg_ea in idautils.Segments():
        if not is_external_segment(seg_ea):
            recover_segment(M, seg_ea)

def recover_external_functions(M):
    """Recover the named external functions (e.g. `printf`) that are referenced
    within this binary."""
    global EXTERNAL_FUNCS_TO_RECOVER, WEAK_SYMS, EMAP

    for ea, name in EXTERNAL_FUNCS_TO_RECOVER.items():
        DEBUG("Recovering extern function {} at {:x}".format(name, ea))
        args, conv, ret, sign = EMAP[name]
        E = M.external_funcs.add()
        E.name = name.format('utf-8')
        E.ea = ea
        E.argument_count = args
        E.cc = conv
        E.is_weak = idaapi.is_weak_name(ea) or (name in WEAK_SYMS)
        E.has_return = ret == 'N'

        # TODO(pag): This should probably reflect whether or not the function
        #            actually returns something, rather than simply does not
        #            return (e.g. `abort`).
        E.no_return = (not E.has_return)

def recover_external_variables(M):
    """Reover the named external variables (e.g. `stdout`) that are referenced
    within this binary."""
    global EXTERNAL_VARS_TO_RECOVER, WEAK_SYMS

    for ea, name in EXTERNAL_VARS_TO_RECOVER.items():
        DEBUG("Recovering extern variable {} at {:x}".format(name, ea))
        EV = M.external_vars.add()
        EV.ea = ea
        EV.name = name.format('utf-8')
        EV.is_weak = idaapi.is_weak_name(ea) or (name in WEAK_SYMS)
        if name in EMAP_DATA:
            EV.size = EMAP_DATA[name]
        else:
            EV.size = idc.ItemSize(ea)

def recover_external_symbols(M):
    recover_external_functions(M)
    recover_external_variables(M)

def try_identify_as_external_function(ea):
    """Try to identify a function as being an external function."""
    global EXTERNAL_FUNCS_TO_RECOVER, EMAP

    if ea in EXTERNAL_FUNCS_TO_RECOVER:
        return True

    # First, check if it's a thunk. Some thunks are not location in exported
    # sections. Sometimes there are thunk-to-thunks, where there's a function
    # whose only instruction is a direct jump to the real thunk.
    is_thunk, thunk_name = try_get_thunk_name(ea)
    name = None
    if is_thunk:
        name = get_true_external_name(thunk_name)

    elif is_external_segment(ea):
        name = get_true_external_name(get_function_name(ea))

    else:
        return False

    if name not in EMAP:
        return False

    DEBUG("Function at {:x} is the external function {}".format(ea, name))
    EXTERNAL_FUNCS_TO_RECOVER[ea] = name
    return True

def identify_external_symbols():
    """Try to identify external functions and variables."""
    # Go try to find external variables.
    for ea, name in idautils.Names():
        if try_identify_as_external_function(ea) or is_code(ea):
            continue

        elif is_external_reference(ea) or is_runtime_external_data_reference(ea):
            extern_name = get_true_external_name(name)
            if extern_name in EMAP_DATA:
                DEBUG("Variable at {:x} is the external {}".format(ea, extern_name))
                EXTERNAL_VARS_TO_RECOVER[ea] = extern_name

            # Corner case, there is an external reference in the `.got` section
            # into internal data. This was observed in one binary where
            # `fec_scheme_str_ptr` was an entry in the `.got`, but pointed into the
            # `.data` section.
            elif is_ELF_got_pointer(ea):
                target_ea = get_reference_target(ea)
                if not is_external_segment(target_ea):
                    global _FIXED_EXTERNAL_NAMES  # Hack :-(
                    _FIXED_EXTERNAL_NAMES[name] = get_symbol_name(target_ea)

def identify_program_entrypoints(func_eas):
    """Identify all entrypoints into the program. This is pretty much any
    externally visible function."""
    entrypoints = set()
    for index, ordinal, ea, name in idautils.Entries():
        assert ea != idc.BADADDR
        if not is_internal_code(ea) or is_external_reference(ea):
            DEBUG("Export {0} at {1} does not point to code; skipping".format(name, hex(ea)))
            continue
        func_eas.add(ea)
        entrypoints.add(ea)
        
    return entrypoints

def recover_module():
    global EMAP
    global EXTERNAL_FUNCS_TO_RECOVER

    M = CFG_pb2.Module()
    M.name = idc.GetInputFile().format('utf-8')
    DEBUG("Recovering module {}".format(M.name))

    process_segments(PIE_MODE)
    func_eas = find_default_function_heads()

    recovered_fns = 0

    identify_external_symbols()
    entrypoints = identify_program_entrypoints(func_eas)

    # Process and recover functions. 
    while len(func_eas) > 0:
        func_ea = func_eas.pop()
        if func_ea in RECOVERED_EAS or func_ea in EXTERNAL_FUNCS_TO_RECOVER:
            continue

        RECOVERED_EAS.add(func_ea)

        if try_identify_as_external_function(func_ea):
            DEBUG("ERROR: External function {:x} not previously identified".format(func_ea))
            continue

        if not is_internal_code(func_ea):
            DEBUG("ERROR: Function EA not code: {:x}".format(func_ea))
            continue

        if is_external_segment(func_ea):
            continue

        recover_function(M, func_ea, func_eas, entrypoints)
        recovered_fns += 1

    if recovered_fns == 0:
        DEBUG("COULD NOT RECOVER ANY FUNCTIONS")
        return

    recover_segments(M)
    recover_external_symbols(M)

    DEBUG("Recovered {0} functions.".format(recovered_fns))
    return M

def parseTypeString(typestr, ea):

    if "__stdcall" in typestr:
        conv = CFG_pb2.ExternalFunction.CalleeCleanup
    elif "__cdecl" in typestr:
        conv = CFG_pb2.ExternalFunction.CallerCleanup
    elif "__fastcall" in typestr:
        conv = CFG_pb2.ExternalFunction.FastCall
    elif "__usercall" in typestr:
        # do not handle this for now
        return (0, CFG_pb2.ExternalFunction.CalleeCleanup, "N")
    else:
        raise Exception("Could not parse function type:"+typestr)

    fn = idaapi.get_func(ea)
    if fn is None:
        raise Exception("Could not get function args for: {0:x}".format(ea))
    args = fn.argsize / 4

    ret = 'N'

    return args, conv, ret

def getAllExports():
    entrypoints = idautils.Entries()
    to_recover = set()
    # recover every entry point
    for ep_tuple in entrypoints:
        (index, ordinal, ea, name) = ep_tuple
        to_recover.add(name)

    return to_recover 

if __name__ == "__main__":

    parser = argparse.ArgumentParser()

    parser.add_argument("--log_file", type=argparse.FileType('w'),
        default=sys.stderr,
        help="Log to a specific file. Default is stderr.")

    parser.add_argument(
        '--arch',
        help='Name of the architecture. Valid names are x86, amd64.',
        required=True)

    parser.add_argument(
        '--os',
        help='Name of the operating system. Valid names are linux, windows.',
        required=True)

    parser.add_argument(
        "--output", type=argparse.FileType('wb'), default=None,
        help="The output control flow graph recovered from this file",
        required=True)

    parser.add_argument("--std-defs", action='append', type=str,
        default=[],
        help="std_defs file: definitions and calling conventions of imported functions and data")
    
    parser.add_argument("-e", "--exports-to-lift", type=argparse.FileType('r'),
        default=None,
        help="A file containing a exported functions to lift, one per line. If not specified, all exports will be lifted.")

    parser.add_argument("--exports-are-apis", action="store_true",
        default=False,
        help="Exported functions are defined in std_defs. Useful when lifting DLLs")
    
    parser.add_argument("-z", "--syms", type=argparse.FileType('r'), default=None,
        help="File containing <name> <address> pairs of symbols to pre-define.")

    parser.add_argument("--pie-mode", action="store_true", default=False,
        help="Assume all immediate values are constants (useful for ELFs built with -fPIE")

    args = parser.parse_args(args=idc.ARGV[1:])

    if args.log_file != os.devnull:
        INIT_DEBUG_FILE(args.log_file)
        DEBUG("Debugging is enabled.")

    addr_size = {"x86": 32, "amd64": 64}.get(args.arch, 0)
    if addr_size != get_address_size_in_bits():
        DEBUG("Arch {} address size does not match IDA's available bitness {}! Did you mean to use idal64?".format(
            args.arch, get_address_size_in_bits()))
        idc.Exit(-1)

    if args.pie_mode:
        DEBUG("Using PIE mode.")
        PIE_MODE = True

    EMAP = {}
    EMAP_DATA = {}

    # Try to find the defs file or this OS
    OS_NAME = args.os
    os_defs_file = os.path.join(tools_disass_dir, "defs", "{}.txt".format(args.os))
    if os.path.isfile(os_defs_file):
        args.std_defs.insert(0, os_defs_file)

    # Load in all defs files, include custom ones
    for defsfile in args.std_defs:
        with open(defsfile, "r") as df:
            DEBUG("Loading Standard Definitions file: {0}".format(defsfile))
            parse_os_defs_file(df)

    # for batch mode: ensure IDA is done processing
    DEBUG("Using Batch mode.")
    analysis_flags = idc.GetShortPrm(idc.INF_START_AF)
    analysis_flags &= ~idc.AF_IMMOFF
    # turn off "automatically make offset" heuristic
    idc.SetShortPrm(idc.INF_START_AF, analysis_flags)
    idaapi.autoWait()

    DEBUG("Starting analysis")
    try:
        # Pre-define a bunch of symbol names and their addresses. Useful when reading
        # a core dump.
        if args.syms:
            for line in args.syms:
                name, ea_str = line.strip().split(" ")
                ea = int(ea_str, base=16)
                if not is_internal_code(ea):
                    mark_as_code(ea)
                try_mark_as_function(ea)
                idc.MakeName(ea, name)

        M = recover_module()

        DEBUG("Saving to: {0}".format(args.output.name))
        args.output.write(M.SerializeToString())
        args.output.close()

    except Exception as e:
        DEBUG(str(e))
        DEBUG(traceback.format_exc())
    
    idc.Exit(0)
