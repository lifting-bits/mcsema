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

EXTERNALS = set()
DATA_SEGMENTS = {}

EXTERNAL_FUNCS_TO_RECOVER = set()
EXTERNAL_VARS_TO_RECOVER = set()

RECOVERED_EAS = set()
ACCESSED_VIA_JMP = set()

EMAP = {}
EMAP_DATA = {}

PIE_MODE = False

EXTERNAL_NAMES = [
        "@@GLIBC_",\
        ]

EXTERNAL_DATA_COMMENTS = [
        "Copy of shared data",
        ]

def hasExternalDataComment(ea):
    cmt = idc.GetCommentEx(ea, 0)
    return cmt in EXTERNAL_DATA_COMMENTS

def isElf():
    return idc.GetLongPrm(idc.INF_FILETYPE) == idc.FT_ELF

# Returns `True` if this is an ELF binary (as opposed to an ELF object file).
def isLinkedElf():
    return idc.GetLongPrm(idc.INF_FILETYPE) == idc.FT_ELF and \
        idc.BeginEA() not in [0xffffffffL, 0xffffffffffffffffL]

def IsString(ea):
    return idc.isASCII(idaapi.getFlags(ea))

def IsStruct(ea):
    return idc.isStruct(idaapi.getFlags(ea))

_FIXED_EXTERNAL_NAMES = {}

def fixExternalName(fn):
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
    if not isLinkedElf() and fn[0] == '_':
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
    if isLinkedElf():
        ea = idc.LocByName(fn)
        if not is_code(ea) and ".got" in idc.SegName(ea).lower():
            for extref in idautils.DataRefsFrom(ea):
                name = get_symbol_name(extref, extref)
                if name:
                    fn = handleExternalRef(name) 

    _FIXED_EXTERNAL_NAMES[orig_fn] = fn
    return fn

def nameInMap(themap, fn):
    return fixExternalName(fn) in themap

def getFromEMAP(fname):
    fixname = fixExternalName(fname)
    return EMAP[fixname]

def isExternalReference(ea):
    # see if this is in an internal or external code ref
    if is_external_segment(ea):
        return True

    if isLinkedElf():
        fn = getFunctionName(ea)
        for extsign in EXTERNAL_NAMES:
            if extsign in fn:
                DEBUG("Assuming external reference because: {} in {}".format(extsign, fn))
                return True

        if isExternalData(fn):
            if hasExternalDataComment(ea):
                return True
            else:
                DEBUG("WARNING: May have missed external data ref {} at {:x}".format(fn, ea))

    return False

def getFunctionName(ea):
    return idc.GetTrueNameEx(ea,ea)

_REFERENCE_OPERAND_TYPE = {
    Reference.IMMEDIATE: CFG_pb2.CodeReference.ImmediateOperand,
    Reference.DISPLACEMENT: CFG_pb2.CodeReference.MemoryDisplacementOperand,
    Reference.MEMORY: CFG_pb2.CodeReference.MemoryOperand,
    Reference.CODE: CFG_pb2.CodeReference.ControlFlowOperand,
}

def reference_target_type(ref):
    global EMAP, EMAP_DATA

    # Sometimes code references into the GOT would be treated as data
    # references. We fall back onto our external maps as an oracle for
    # what the type should really be. This has happened with `pcre_free`
    # references from Apache.
    if ref.symbol and reference_location(ref) == CFG_pb2.CodeReference.External:
        if nameInMap(EMAP, ref.symbol):
            return CFG_pb2.CodeReference.CodeTarget
        elif nameInMap(EMAP_DATA, ref.symbol):
            return CFG_pb2.CodeReference.DataTarget

    if is_code(ref.addr):
        return CFG_pb2.CodeReference.CodeTarget
    else:
        return CFG_pb2.CodeReference.DataTarget

def reference_operand_type(ref):
    global _REFERENCE_OPERAND_TYPE
    return _REFERENCE_OPERAND_TYPE[ref.type]

def reference_location(ref):
    if ref.symbol:
        fixed_name = fixExternalName(ref.symbol)
        if nameInMap(EMAP, fixed_name):
            return CFG_pb2.CodeReference.External
        elif nameInMap(EMAP_DATA, fixed_name):
            return CFG_pb2.CodeReference.External

    if isExternalReference(ref.addr):
        return CFG_pb2.CodeReference.External
    else:
        return CFG_pb2.CodeReference.Internal

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

def debug_ref_string(ref):
    return "({} {} {} {:x} {})".format(
        _TARGET_NAME[ref.target_type],
        _OPERAND_NAME[ref.operand_type],
        _LOCATION_NAME[ref.location],
        ref.address,
        ref.HasField('name') and ref.name or "")

MISSING_FUNCS = set()

def handleExternalRef(fn):
    # Don't mangle symbols for fully linked ELFs... yet
    in_a_map = fn in EMAP or fn in EMAP_DATA
    if not isLinkedElf():
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

        if isElf() and '@' in fn:
            fn = fn[:fn.find('@')]

    fixfn = fixExternalName(fn)

    EXTERNALS.add(fixfn)
    return fixfn

def isInData(start_ea, end_ea):
    for (start,end) in DATA_SEGMENTS.values():
        if start_ea >= start and start_ea < end:
            DEBUG("Data Range: {0:x} <= {1:x} < {2:x}".format(start, start_ea, end))
            DEBUG("Data Range: {:x} - {:x}".format(start_ea, end_ea))
            if end_ea <= end:
                return True
            else:
                DEBUG("{0:x} NOT <= {1:x}".format(end_ea, end))
                DEBUG("{0:x}-{1:x} overlaps with: {2:x}-{3:x}".format(start_ea, end_ea, start, end))
                raise Exception("Overlapping data segments!")
        else:
            if end_ea > start and end_ea <= end:
                DEBUG("Overlaps with: {0:x}-{1:x}".format(start, end))
                raise Exception("Overlapping data segments!")

    return False

def isExternalData(fn):
    indata = fn in EMAP_DATA
    incode = fn in EMAP

    if indata and not incode:
        return True
    elif indata and incode:
        raise Exception("Symbol "+fn+" defined as both code and data!")
    else:
        return False

def updateWithJmpTableTargets(inst, new_eas, new_func_eas):
    """Function recovery is an iterative process. Sometimes we'll find things
    in the entries of the jump table that we need to go mark as code to be
    added into the CFG."""
    table = get_jump_table(inst, PIE_MODE)
    if not table:
        return

    for entry_addr, entry_target in table.entries.items():
        if isStartOfFunction(entry_target):
            DEBUG("  Jump table {:x} entry at {:x} references function at {:x}".format(
                table.table_ea, entry_addr, entry_target))
            new_func_eas.add(entry_target)
        else:
            DEBUG("  Jump table {:x} entry at {:x} references block at {:x}".format(
                table.table_ea, entry_addr, entry_target))
            new_eas.add(entry_target)

_ELF_THUNKS = {}
_NOT_ELF_THUNKS = set()
_INVALID_THUNK = (False, None)

def isElfThunkByStructureImpl(ea):
    """Try to manually identify an ELF thunk by its structure."""
    global _INVALID_THUNK

    inst, _ = decode_instruction(ea)
    if not inst or not is_indirect_jump(inst):
        return _INVALID_THUNK

    real_ext_ref = None
    for cref in idautils.CodeRefsFrom(ea, 0):
        if isExternalReference(cref):
            real_ext_ref = cref
            break

    if real_ext_ref is None:
        for dref in idautils.DataRefsFrom(ea):
            if idc.SegName(dref).lower() in ".got.plt":
                # this is an external call after all
                for extref in idautils.DataRefsFrom(dref):
                    if isExternalReference(extref):
                        real_ext_ref = extref

    if real_ext_ref is not None:
        return True, handleExternalRef(getFunctionName(real_ext_ref))

    return _INVALID_THUNK

def isThunkByFlags(ea):
    """Try to identify an ELF thunk based off of the IDA flags.

    IDA seems to have a kind of thunk-propagation. So if one thunk calls
    another thunk, then the former thing is treated as a thunk. The former
    thing will not actually follow the 'structured' form matched above, so
    we'll try to recursively match to the 'final' referenced thunk."""
    global _ELF_THUNKS, _INVALID_THUNK

    if not is_thunk(ea):
        return _INVALID_THUNK
    
    ea_name = getFunctionName(ea)
    inst, _ = decode_instruction(ea)
    if not inst:
        DEBUG("{} at {:x} is a thunk with no code??".format(ea_name, ea))
        return _INVALID_THUNK

    # Recursively find thunk-to-thunks.
    if is_direct_jump(inst) or is_direct_function_call(inst):
        targ_ea = get_direct_branch_target(inst)
        targ_is_thunk, targ_thunk_name = isElfThunk(targ_ea)
        if targ_is_thunk:
            DEBUG("Found thunk-to-thunk {:x} -> {:x}: {} to {}".format(
                ea, targ_ea, ea_name, targ_thunk_name))
            return True, targ_thunk_name
        
        DEBUG("ERROR? targ_ea={:x} is not thunk".format(targ_ea))

    if not isExternalReference(ea):
        return _INVALID_THUNK

    return True, handleExternalRef(ea_name)

def isElfThunk(ea):
    """Try to figure out if a function is actually an ELF thunk, i.e. a function
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
    is_thunk, name = isElfThunkByStructureImpl(ea)
    if not is_thunk:
        is_thunk, name = isThunkByFlags(ea)
    
    if not is_thunk:
        _NOT_ELF_THUNKS.add(ea)
        return _INVALID_THUNK
    else:
        _ELF_THUNKS[ea] = (is_thunk, name)
        return is_thunk, name

WEAK_SYMS = set()
OS_NAME = ""

def parseDefsFile(df):
    global OS_NAME, WEAK_SYMS
    emap = {}
    emap_data = {}
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
            emap_data[symname] = int(dsize)

        else:
            fname = args = conv = ret = sign = None
            line_args = l.split()
            if len(line_args) == 2:
                fname, conv = line_args
                if conv == "MCSEMA":
                    DEBUG("Found mcsema internal function: {}".format(fname))
                    realconv = CFG_pb2.ExternalFunction.McsemaCall
                    emap[fname] = (1, realconv, 'N', None)
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
            if ea != idc.BADADDR and ea < 0xff00000000000000 \
            and not is_external_segment(ea) and not is_thunk(ea):
                DEBUG("Not treating {} as external, it is defined at {:x}".format(
                    fname, ea))
                continue

            emap[fname] = (int(args), realconv, ret, sign)

            if is_linux:
                imp_name = "__imp_{}".format(fname)
                emap[imp_name] = emap[fname]
                WEAK_SYMS.add(imp_name)

    df.close()

    return emap, emap_data

# def processExternalFunction(M, fn):
#     global WEAK_SYMS

#     args, conv, ret, sign = getFromEMAP(fn)
#     ea = idc.LocByName(fn)
#     is_weak = idaapi.is_weak_name(ea) or fn in WEAK_SYMS

#     DEBUG("Program will reference external{}: {}".format(" (weak)" if is_weak else "", fn))
#     extfn = M.external_funcs.add()
#     extfn.symbol_name = fn
#     extfn.calling_convention = conv
#     extfn.argument_count = args
#     extfn.is_weak = is_weak
#     if ret == 'N':
#         extfn.has_return = True
#         extfn.no_return = False
#     else:
#         extfn.has_return = False
#         extfn.no_return = True

# def processExternalData(M, dt):
#     data_size = EMAP_DATA[dt]
#     ea = idc.LocByName(dt)
#     is_weak = idaapi.is_weak_name(ea)
    
#     DEBUG("Program will reference external{}: {}".format(" (weak)" if is_weak else "", dt))

#     extdt = M.external_data.add()
#     extdt.symbol_name = dt
#     extdt.data_size = data_size
#     extdt.is_weak = is_weak

# def processExternals(M):
#     for fn in EXTERNALS:
#         fixedn = fixExternalName(fn)
#         if nameInMap(EMAP, fixedn):
#             processExternalFunction(M, fixedn)
#         elif nameInMap(EMAP_DATA, fixedn):
#             processExternalData(M, fixedn)
#         else:
#             DEBUG("UNKNOWN API: {0}".format(fixedn))


# class Segment(object):

#     SEGMENTS = {}

#     @classmethod
#     def get(cls, ea):
#         base_ea = idc.SegStart(ea)
#         if base_ea == idc.BADADDR:
#             DEBUG("ERROR: Can't get segment for {:x}".format(ea))
#             return None

#         if base_ea not cls.SEGMENTS:
#             segtype = idc.GetSegmentAttr(seg, idc.SEGATTR_TYPE)
#             can_exec = (segtype == idc.SEG_CODE)

#         return cls.SEGMENTS[base_ea]

#     def __init__(self, base_ea, limit_ea, can_write, can_exec):
#         self.base_ea = base_ea
#         self.limit_ea = limit_ea
#         self.can_write = can_write
#         self.can_exec = can_exec


# def handleDataRelocation(M, dref, new_eas):
#     dref_size = idc.ItemSize(dref)
#     if not isInData(dref, dref+dref_size):
#         addDataSegment(dref, dref+dref_size)
#         return dref + populateDataSegment(M, dref, dref+dref_size, new_eas)
#     else:
#         return dref

# def relocationSize(reloc_type):
    
#     reloc_type = reloc_type & idc.FIXUP_MASK
#     size_map = {
#         idc.FIXUP_OFF8 : 1,
#         idc.FIXUP_BYTE : 1,
#         idc.FIXUP_OFF16 : 2,
#         idc.FIXUP_SEG16 : 2,
#         idc.FIXUP_PTR32 : 4,
#         idc.FIXUP_OFF32 : 4,
#         idc.FIXUP_PTR48 : 8,
#         idc.FIXUP_HI8 : 1,
#         idc.FIXUP_HI16 : 2,
#         idc.FIXUP_LOW8 : 1,
#         idc.FIXUP_LOW16 : 2,
#         12: 8,}

#     reloc_size = size_map.get(reloc_type, -1)
#     return reloc_size


# def resolveRelocation(ea):
#     rtype = idc.GetFixupTgtType(ea) 

#     relocSize = -1
#     relocVal = -1

#     if get_address_size_in_bits() == 64:
#         if rtype == -1:
#             raise Exception("No relocation type at ea: {:x}".format(ea))

#         DEBUG("rtype : {0:x}, {1:x}, {2:x}".format(rtype, idc.GetFixupTgtOff(ea), idc.GetFixupTgtDispl(ea)))
#         relocVal = idc.GetFixupTgtDispl(ea) +  idc.GetFixupTgtOff(ea)
#     else:
#         if rtype == idc.FIXUP_OFF32:
#             relocVal = read_dword(ea)
#         elif rtype == -1:
#             raise Exception("No relocation type at ea: {:x}".format(ea))
#         else:
#             relocVal = idc.GetFixupTgtOff(ea)

#     relocSize = relocationSize(rtype)
#     return relocVal, relocSize

# def insertRelocatedSymbol(M, D, reloc_dest, offset, seg_offset, new_eas, itemsize=-1):
#     pf = idc.GetFlags(reloc_dest)

#     DS = D.symbols.add()
#     DS.base_address = offset+seg_offset

#     itemsize = int(itemsize)
#     if itemsize == -1:
#         itemsize = int(idc.ItemSize(offset))

#     DEBUG("Offset: {0:x}, seg_offset: {1:x} => {2:x}".format(offset, seg_offset, reloc_dest))
#     DEBUG("Reloc Base Address: {0:x}".format(DS.base_address))
#     DEBUG("Reloc size: {0:x}".format(itemsize))

#     if isExternalReference(reloc_dest):
#         fn = getFunctionName(reloc_dest)
#         ext_fn = handleExternalRef(fn)
#         DEBUG("External ref from data at {:x} => {} (from {})".format(reloc_dest, ext_fn, fn))
#         DS.symbol_name = "ext_{}".format(ext_fn)
#         DS.symbol_size = itemsize
#     elif is_code(pf):
#         DS.symbol_name = "sub_{0:x}".format(reloc_dest)
#         DS.symbol_size = itemsize
#         DEBUG("Code Ref: {0:x}!".format(reloc_dest))

#         if reloc_dest not in RECOVERED_EAS:
#             new_eas.add(reloc_dest)

#     elif idc.isData(pf):
#         reloc_dest = handleDataRelocation(M, reloc_dest, new_eas)
#         DS.symbol_name = "data_{:x}".format(reloc_dest)
#         DS.symbol_size = itemsize
#         DEBUG("Data Ref!")
#     else:
#         reloc_dest = handleDataRelocation(M, reloc_dest, new_eas)
#         DS.symbol_name = "data_{:x}".format(reloc_dest)
#         DS.symbol_size = itemsize
#         DEBUG("UNKNOWN Ref, assuming data")

def isStartOfFunction(ea):
    fname = idc.GetFunctionName(ea)
    return ea == idc.LocByName(fname)

def isSaneReference(ea):
    if is_block_or_instruction_head(ea):
        return True

    # TODO(pag): Some compilers will dedup strings. This shows up in something
    # like /bin/ls, where you have `almost-all` and `all` as two options, and
    # the latter belongs to the former. A dref to `all` doesn't show up as an
    # item head, so :-/
    elif isInData(ea, ea+1): # and idc.ItemHead(ea) == ea:
        return True
    else:
        return False

def processTable(ea, size):
    """
    Loop through a possible table of pointers
    with an occasional NULL entry permitted

    Returns True, dictionary of pointer->destination, pointer size if its a pointer table
    Returns False, {}, _ if its not a valid pointer table
    """
    global ACCESSED_VIA_JMP

    def scan_table(start, end, readsize):
        table_map = {}

        read_option = {4 : read_dword,
                       8 : read_qword}[readsize]

        # sanity check for xrange
        if (end - start) % readsize != 0:
            return False, table_map, readsize

        for jea in xrange(start, end, readsize):
            pword = read_option(jea)
            if isSaneReference(pword): 
                ACCESSED_VIA_JMP.add(jea)
                DEBUG("Sane table entry at: {:x}".format(pword))
            elif pword == 0:
                DEBUG("Ignoring NULL entry in possible table: {:x}".format(jea))
            else:
                DEBUG("NOT a table entry at {:x}".format(jea))
                return False, table_map, readsize 

            table_map[jea] = pword

        return True, table_map, readsize

    did_find, table, readsz = scan_table(ea, ea+size, get_address_size_in_bytes())
    if did_find == False and get_address_size_in_bytes() == 8:
        DEBUG("Failed to find a table, trying with smaller pointer size")
        did_find, table, readsz = scan_table(ea, ea+size, 4)

    return did_find, table, readsz

def parseSingleStruct(ea, idastruct):
    DEBUG("Parsing idastruct at {:x}".format(ea))
    # get first member offset
    first_off = idc.GetFirstMember(idastruct.tid);

    # get last member offset
    last_off = idc.GetLastMember(idastruct.tid)

    # get starting offests of all members
    ptrs = {}
    members = set()

    read_size = get_address_size_in_bytes()
    read_option = {4 : read_dword,
                   8 : read_qword}[read_size]

    for i in xrange(first_off, last_off+1):
        mn = idc.GetMemberName(idastruct.tid, i)
        # skip padding bytes
        if mn is not None:
            members.add(mn)

    for member in members:
        DEBUG("Checking idastruct member: {}".format(member))
        member_off = idc.GetMemberOffset(idastruct.tid, member)
        assert member_off != -1
        # get element size
        member_sz = idc.GetMemberSize(idastruct.tid, member_off)
        assert member_sz > 0
        
        #if its pointer size, check for ptr
        if member_sz == read_size:
            DEBUG("\tit is pointer sized")
            # check if points to sanity
            member_ea = ea+member_off
            pword = read_option(member_ea)
            if isSaneReference(pword):
                DEBUG("\tAdding reference from {:x} => {:x}".format(member_ea, pword))
                ptrs[member_ea] = pword
            else:
                DEBUG("\tNot a sane reference ({:x})".format(pword))


    return len(ptrs) != 0, ptrs, get_address_size_in_bytes()

def getStructType(ea):
    """ 
    Get type information from an ea. Used to get the structure type id
    """

    flags = idaapi.getFlags(ea)
    ti = idaapi.opinfo_t()
    oi = idaapi.get_opinfo(ea, 0, flags, ti)
    if oi is not None:
        return ti
    else:
        return None

def processStruct(ea, size):
    """
    Find pointers in a structure type
    """
    # get struct size
    idastruct = getStructType(ea)
    if idastruct is None:
        DEBUG("Could not get structure size at: {:x}".format(ea))
        return False, {}, 0

    struct_size = idc.GetStrucSize(idastruct.tid)
    
    #check if this is an array of structs
    assert size % struct_size == 0

    all_ptrs = {}

    num_iters = size / struct_size
    for i in xrange(num_iters):
        # parse a single struct
        start_ea = ea + (i * struct_size)
        worked, ptrs, ptrsize = parseSingleStruct(ea, idastruct)
        if worked:
            all_ptrs.update(ptrs)

    return True, all_ptrs, get_address_size_in_bytes()

def processDataChunk(ea, size):
    """
    Determine if a data chunk has some pointers in it
    """

    # Get chunk type
    # if its a string, skip it
    if IsString(ea):
        DEBUG("Found a string at {:x}".format(ea))
        return False, {}, 0
    elif IsStruct(ea):
        DEBUG("Found a struct at {:x}".format(ea))
        return processStruct(ea, size)
    else:
        DEBUG("Found an unknown blob at {:x}, treating as table".format(ea))
        return processTable(ea, size)

def inValidSegment(ea):
    if idc.SegStart(ea) == idc.BADADDR:
        return False
    return True

def recoverInstructionReferences(I, inst, addr, new_func_eas):
    """Add the memory/code reference information from this instruction
    into the CFG format."""
    global EXTERNAL_FUNCS_TO_RECOVER, EXTERNALS

    DEBUG_PUSH()
    debug_info = ["I: {:x}".format(addr)]
    refs = get_instruction_references(inst, PIE_MODE)
    for ref in refs:

        # Don't add code flows that go to internal code.
        if ref.type == Reference.CODE \
        and not is_analysed_function(ref.addr) \
        and not is_external_segment(ref.addr):
            if is_direct_jump(inst) or is_conditional_jump(inst):
                continue

        addrs = set()
        R = I.xrefs.add()
        R.target_type = reference_target_type(ref)
        R.location = reference_location(ref)
        R.operand_type = reference_operand_type(ref)
        R.address = ref.addr

        if ref.symbol:
            R.name = ref.symbol

            # Handle renaming things like `stderr_ptr` in the `.got` into
            # an external reference to `stderr`.
            if R.location == CFG_pb2.CodeReference.External:
                new_name = fixExternalName(ref.symbol)
                new_addr = idc.LocByName(new_name)
                if new_name != ref.symbol or new_addr != ref.addr:
                    DEBUG("Changing reference to {} into reference to {}".format(
                        ref.symbol, new_name))

                    ref.addr = idc.LocByName(new_name)
                    ref.symbol = new_name
                    R.name = ref.symbol

                    R.target_type = reference_target_type(ref)
                    R.location = reference_location(ref)

        # Make sure anything that isn't yet resolved as a subroutine is resolved.
        if R.target_type == CFG_pb2.CodeReference.CodeTarget \
        and R.location == CFG_pb2.CodeReference.Internal \
        and not idc.GetFunctionName(ref.addr):
            DEBUG("Marking {:x} referenced from {:x} as a function".format(
                ref.addr, addr))
            try_mark_as_function(ref.addr)
            new_func_eas.add(ref.addr)

        # If this is a code ref, and if it's a target to a thunk, then we want
        # the lifter to treat the thunk as if it's the real function, so we
        # mark this code reference as being external.
        #
        # Note: If `isElfThunk` returns `True` then `name` is already in, or
        #       has been added, to the `EXTERNALS` set.
        is_thunk, name = isElfThunk(ref.addr)
        if is_thunk:
            DEBUG("  Redirecting code ref from {:x} to thunk {:x} to external {}".format(
                addr, ref.addr, name))
            ref.symbol = name
            R.name = name
            R.location = CFG_pb2.CodeReference.External
            R.target_type = reference_target_type(ref)

        # Update the externals map.
        if R.location == CFG_pb2.CodeReference.External:
            if R.target_type == CFG_pb2.CodeReference.CodeTarget:
                EXTERNAL_FUNCS_TO_RECOVER.add((R.address, ref.symbol))
            else:
                EXTERNAL_VARS_TO_RECOVER.add((R.address, ref.symbol))

            EXTERNALS.add(ref.symbol)

        debug_info.append(debug_ref_string(R))

    DEBUG_POP()
    DEBUG(" ".join(debug_info))

def recoverInstruction(M, B, inst, inst_bytes, addr, new_func_eas):
    """Recover an instruction, adding it to its parent block."""

    I = B.instructions.add()
    I.ea = addr  # May not be `inst.ea` because of prefix coalescing.
    I.bytes = inst_bytes
    recoverInstructionReferences(I, inst, addr, new_func_eas)

    if is_noreturn_inst(inst):
        I.local_noreturn = True

    table = get_jump_table(inst, PIE_MODE)
    if table:
        I.jump_table_addr = table.table_ea
        I.offset_base_addr = table.offset

def recoverBasicBlock(M, F, block_ea, new_func_eas):
    inst_eas, succ_eas = analyse_block(
        F.ea, block_ea, PIE_MODE)

    DEBUG("BB: {:x} in func {:x} with {} insts".format(
        block_ea, F.ea, len(inst_eas)))
    
    B = F.blocks.add()
    B.ea = block_ea
    B.successor_eas.extend(succ_eas)

    DEBUG_PUSH()
    # Sometimes there will be tail-calls to thunks, or thunk-to-thunks, and 
    # we want to make sure that we can recognize the target as an external,
    # even if it isn't the final destination. The side-effect of this is that
    # the same external function name may show up twice or more in the proto. 
    for succ_ea in succ_eas:
        if is_external_segment(succ_ea):
            is_thunk, thunk_name = isElfThunk(succ_ea)
            if is_thunk:
                EXTERNAL_FUNCS_TO_RECOVER.add((succ_ea, thunk_name))
            else:
                name = get_symbol_name(succ_ea)
                name = fixExternalName(name)
                EXTERNAL_FUNCS_TO_RECOVER.add((succ_ea, name))

    for inst_ea in inst_eas:
        inst, inst_bytes = decode_instruction(inst_ea)
        recoverInstruction(
            M, B, inst, inst_bytes, inst_ea, new_func_eas)

    str_l = ["{0:x}".format(i) for i in succ_eas]
    if len(str_l) > 0:
        DEBUG("Successors: {}".format(", ".join(str_l)))

    DEBUG_POP()

_RECOVERED_FUNCS = set()

def recoverFunction(M, sub_ea, new_func_eas, entrypoints):
    """Decode a function and store it, all of its basic blocks, and all of
    their instructions into the CFG file."""
    global _RECOVERED_FUNCS
    if sub_ea in _RECOVERED_FUNCS:
        return

    _RECOVERED_FUNCS.add(sub_ea)

    if not isStartOfFunction(sub_ea):
        DEBUG("{:x} is not a function! Not recovering.".format(sub_ea))
        return


    DEBUG("Recovering {:x}".format(sub_ea))
    DEBUG_PUSH()
    F = M.funcs.add()
    F.ea = sub_ea
    F.is_entrypoint = (sub_ea in entrypoints)
    name = get_symbol_name(sub_ea)
    if name:
        F.name = name

    blockset, term_insts = analyse_subroutine(sub_ea, PIE_MODE)

    for block_ea in blockset:
        DEBUG("Found block {:x}".format(block_ea))

    for term_inst in term_insts:
        if get_jump_table(term_inst, PIE_MODE):
            DEBUG("Terminator inst {:x} in func {:x} is a jump table".format(
                term_inst.ea, sub_ea))
            updateWithJmpTableTargets(term_inst, blockset, new_func_eas)
    
    processed_blocks = set()
    while len(blockset) > 0:
        block_ea = blockset.pop()
        if block_ea in processed_blocks:
            DEBUG("ERROR: Attempting to add same block twice: {0:x}".format(block_ea))
            continue

        processed_blocks.add(block_ea)
        recoverBasicBlock(M, F, block_ea, new_func_eas)
    DEBUG_POP()

def findDefaultFunctionHeads():
    func_heads = set()
    # Loop through every function, to discover the heads of all blocks that
    # IDA recognizes. This will populate some global sets in `flow.py` that
    # will help distinguish block heads.
    for seg_ea in idautils.Segments():
        seg_type = idc.GetSegmentAttr(seg_ea, idc.SEGATTR_TYPE)
        if seg_type != idc.SEG_CODE:
            continue
        for func_ea in idautils.Functions(seg_ea, idc.SegEnd(seg_ea)):
            if is_code(func_ea):
                func_heads.add(func_ea)
    return func_heads

def recoverSegmentVariables(M, S, seg_ea, seg_end_ea):
    """Look for named locations pointing into the data of this segment, and
    add them to the protobuf."""
    global EMAP_DATA, EXTERNAL_VARS_TO_RECOVER

    for ea, name in idautils.Names():
        if ea < seg_ea or ea >= seg_end_ea:
            continue

        # Try to distinguish an internal name as being an external name. This
        # comes up with things like `stderr@@GLIBC_2.2.5`, that is located in
        # the `.bss` section, whose value will be filled in at runtime to be
        # the address of the actual `stderr`. This is captured by the
        # `extern_name in EMAP_DATA` check.
        #
        # Another example is `__gmon_start___ptr`, that is located in the `.got`
        # section. This is captured by the `is_external_segment` check.
        extern_name = fixExternalName(name)
        if is_external_segment(ea) or extern_name in EMAP_DATA:

            # Ignore thinks like the names of thunks (e.g. `fputs`) in the
            # `.plt`, or `__gmon_start__` in the `.got.plt` section.
            if extern_name in EMAP:
                continue

            EXTERNAL_VARS_TO_RECOVER.add((ea, extern_name))
        
        # Only add named internal variables if they are referenced.   
        elif is_referenced(ea):
            DEBUG("Variable {} at {:x}".format(name, ea))
            V = S.vars.add()
            V.ea = ea
            V.name = name

def recoverSegmentCrossReferences(M, S, seg_ea, seg_end_ea):
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
            X.target_name = get_symbol_name(target_ea)
            X.target_is_code = is_code(target_ea)
            DEBUG("{}-byte reference at {:x} to {:x} ({})".format(
                X.width, ea, target_ea, X.target_name))
            assert is_referenced_by(target_ea, ea)

def recoverSegment(M, seg_ea):
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
    S.name = seg_name

    # Don't look for fixups in the code segment. These are all handled as
    # `CodeReference`s and stored in the `Instruction`s themselves. We also
    # don't want to mark jump table entries embedded in the code section
    # either (see comment below), so this captures that case as well.
    seg_type = idc.GetSegmentAttr(seg_ea, idc.SEGATTR_TYPE)
    if seg_type == idc.SEG_CODE:
        S.read_only = True  # Force this even if it's not true.
        return

    DEBUG_PUSH()
    recoverSegmentCrossReferences(M, S, seg_ea, seg_end_ea)
    recoverSegmentVariables(M, S, seg_ea, seg_end_ea)
    DEBUG_POP()

def recoverSegments(M):
    for seg_ea in idautils.Segments():
        seg_type = idc.GetSegmentAttr(seg_ea, idc.SEGATTR_TYPE)
        # if seg_type not in (idc.SEG_CODE, idc.SEG_DATA, idc.SEG_BSS):
        #     continue
        recoverSegment(M, seg_ea)

def recoverExternalFunctions(M):
    """Recover the named external functions (e.g. `printf`) that are referenced
    within this binary."""

    global EXTERNAL_FUNCS_TO_RECOVER, WEAK_SYMS
    for ea, name in EXTERNAL_FUNCS_TO_RECOVER:
        DEBUG("Recovering extern function {} at {:x}".format(name, ea))
        args, conv, ret, sign = getFromEMAP(name)
        E = M.external_funcs.add()
        E.name = name
        E.ea = ea
        E.argument_count = args
        E.cc = conv
        E.is_weak = idaapi.is_weak_name(ea) or (name in WEAK_SYMS)
        E.has_return = ret == 'N'

        # TODO(pag): This should probably reflect whether or not the function
        #            actually returns something, rather than simply does not
        #            return (e.g. `abort`).
        E.no_return = (not E.has_return)

def recoverExternalVariables(M):
    """Reover the named external variables (e.g. `stdout`) that are referenced
    within this binary."""
    global EXTERNAL_VARS_TO_RECOVER, WEAK_SYMS
    for ea, name in EXTERNAL_VARS_TO_RECOVER:
        DEBUG("Recovering extern variable {} at {:x}".format(name, ea))
        EV = M.external_vars.add()
        EV.ea = ea
        EV.name = name
        EV.is_weak = idaapi.is_weak_name(ea) or (name in WEAK_SYMS)
        if name in EMAP_DATA:
            EV.size = EMAP_DATA[name]
        else:
            EV.size = idc.ItemSize(ea)

def recoverExternals(M):
    recoverExternalFunctions(M)
    recoverExternalVariables(M)

def recoverCfg(outf):
    global EMAP
    M = CFG_pb2.Module()
    M.name = idc.GetInputFile()
    DEBUG("PROCESSING: {0}".format(M.name))

    process_segments(PIE_MODE)
    new_eas = findDefaultFunctionHeads()

    # processDataSegments(M, new_eas)
    entrypoints = set()
    for index, ordinal, ea, name in idautils.Entries():
        assert ea != idc.BADADDR
        new_eas.add(ea)
        entrypoints.add(ea)
        # fwdname = isFwdExport(name, ea)

        # if fwdname is not None:
        #     DEBUG("Skipping fwd export {0} : {1}".format(name, fwdname))
        #     continue

        if not is_internal_code(ea):
            DEBUG("Export {0} at {1} does not point to code; skipping".format(name, hex(ea)))
            continue
        
        if name not in EMAP:
            DEBUG("Entrypoint {} at {:x}".format(name, ea))
            new_eas.add(ea)

    recovered_fns = 0

    while len(new_eas) > 0:
        cur_ea = new_eas.pop()
        if cur_ea in RECOVERED_EAS:
            continue

        RECOVERED_EAS.add(cur_ea)

        is_thunk, thunk_name = isElfThunk(cur_ea)
        if isExternalReference(cur_ea) or is_thunk:
            continue

        if not is_internal_code(cur_ea):
            DEBUG("ERROR Function EA not code: {0:x}".format(cur_ea))
            continue

        if is_external_segment(cur_ea):
            continue

        recoverFunction(M, cur_ea, new_eas, entrypoints)
        recovered_fns += 1

    if recovered_fns == 0:
        DEBUG("COULD NOT RECOVER ANY FUNCTIONS")
        return

    mypath = path.dirname(__file__)
    recoverSegments(M)
    recoverExternals(M)
    outf.write(M.SerializeToString())
    outf.close()

    DEBUG("Recovered {0} functions.".format(recovered_fns))
    DEBUG("Saving to: {0}".format(outf.name))

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

def getExportType(name, ep):
    try:
        DEBUG("Processing export name: {} at: {:x}".format(name, ep))
        args, conv, ret, sign = getFromEMAP(name)
    except KeyError as ke:
        tp = idc.GetType(ep);
        if tp is None or "__" not in tp: 
            #raise Exception("Cannot determine type of function: {0} at: {1:x}".format(name, ep))
            DEBUG("WARNING: Cannot determine type of function: {0} at: {1:x}".format(name, ep))
            return (0, CFG_pb2.ExternalFunction.CalleeCleanup, "N")

        return parseTypeString(tp, ep)

    return args, conv, ret

def makeArgStr(name, declaration):

    argstr = "void"
    args, conv, ret, sign = getFromEMAP(name)

    # return blank string for void calls
    if not declaration and args == 0:
        return ""

    if declaration:
        joinstr = "int a"
    else:
        joinstr = "a"

    argl = [joinstr+str(a) for a in xrange(args)]

    if args > 0:
        argstr = ", ".join(argl)

    return argstr

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
            em_update, emd_update = parseDefsFile(df)
            EMAP.update(em_update)
            EMAP_DATA.update(emd_update)

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

        myname = idc.GetInputFile()
        mypath = path.dirname(__file__)
        outpath = os.path.dirname(args.output.name)
        outf = args.output
        DEBUG("CFG Output File file: {0}".format(outf.name))

        recoverCfg(outf)
    except Exception as e:
        DEBUG(str(e))
        DEBUG(traceback.format_exc())
    
    idc.Exit(0)
