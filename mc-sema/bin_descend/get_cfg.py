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

import itertools

#hack for IDAPython to see google protobuf lib
sys.path.append('/usr/lib/python2.7/dist-packages')
import CFG_pb2

def xrange(begin, end=None, step=1):
    if end:
        return iter(itertools.count(begin, step).next, end)
    else:
        return iter(itertools.count().next, begin)

_DEBUG = False
_DEBUG_FILE = sys.stderr

EXTERNALS = set()
DATA_SEGMENTS = {}

RECOVERED_EAS = set()
ACCESSED_VIA_JMP = set()

EMAP = {}
EMAP_DATA = {}

PIE_MODE = False

OFFSET_TABLES = {}

SPECIAL_REP_HANDLING = [ 
        [0xC3],
        ]

TRAPS = [ 
        idaapi.NN_int3,
        idaapi.NN_icebp,
        ]

CALLS = [
        idaapi.NN_call,
        idaapi.NN_callfi,
        idaapi.NN_callni]

RETS = [
        idaapi.NN_retf,
        idaapi.NN_retfd,
        idaapi.NN_retfq,
        idaapi.NN_retfw,
        idaapi.NN_retn,
        idaapi.NN_retnd,
        idaapi.NN_retnq,
        idaapi.NN_retnw]

COND_BRANCHES = [\
    idaapi.NN_ja,\
    idaapi.NN_jae,\
    idaapi.NN_jb,\
    idaapi.NN_jbe,\
    idaapi.NN_jc,\
    idaapi.NN_jcxz,\
    idaapi.NN_je,\
    idaapi.NN_jecxz,\
    idaapi.NN_jg,\
    idaapi.NN_jge,\
    idaapi.NN_jl,\
    idaapi.NN_jle,\
    idaapi.NN_jna,\
    idaapi.NN_jnae,\
    idaapi.NN_jnb,\
    idaapi.NN_jnbe,\
    idaapi.NN_jnc,\
    idaapi.NN_jne,\
    idaapi.NN_jng,\
    idaapi.NN_jnge,\
    idaapi.NN_jnl,\
    idaapi.NN_jnle,\
    idaapi.NN_jno,\
    idaapi.NN_jnp,\
    idaapi.NN_jns,\
    idaapi.NN_jnz,\
    idaapi.NN_jo,\
    idaapi.NN_jp,\
    idaapi.NN_jpe,\
    idaapi.NN_jpo,\
    idaapi.NN_jrcxz,\
    idaapi.NN_js,\
    idaapi.NN_jz,]

UCOND_BRANCHES = [\
    idaapi.NN_jmp,\
    idaapi.NN_jmpfi,\
    idaapi.NN_jmpni,\
    idaapi.NN_jmpshort]


EXTERNAL_NAMES = [
        "@@GLIBC_",\
        ]

EXTERNAL_DATA_COMMENTS = [
        "Copy of shared data",
        ]

def DEBUG(s):
    global _DEBUG, _DEBUG_FILE
    if _DEBUG:
        _DEBUG_FILE.write(str(s))

def hasExternalDataComment(ea):
    cmt = idc.GetCommentEx(ea, 0)
    return cmt in EXTERNAL_DATA_COMMENTS

def ReftypeString(rt):
    if rt == CFG_pb2.Instruction.DataRef:
        return "DATA"
    elif rt == CFG_pb2.Instruction.CodeRef:
        return "CODE"
    else:
        return "UNKNOWN!"

def readByte(ea):
    byte = readBytesSlowly(ea, ea+1)
    byte = ord(byte) 
    return byte

def readDword(ea):
    bytestr = readBytesSlowly(ea, ea+4)
    dword = struct.unpack("<L", bytestr)[0]
    return dword

def readQword(ea):
    bytestr = readBytesSlowly(ea, ea+8)
    qword = struct.unpack("<Q", bytestr)[0]
    return qword

def isElf():
    return idc.GetLongPrm(idc.INF_FILETYPE) == idc.FT_ELF

def isLinkedElf():
    return idc.GetLongPrm(idc.INF_FILETYPE) == idc.FT_ELF and \
        idc.BeginEA() not in [0xffffffffL, 0xffffffffffffffffL]

def IsString(ea):
    return idc.isASCII(idaapi.getFlags(ea))

def IsStruct(ea):
    return idc.isStruct(idaapi.getFlags(ea))

def fixExternalName(fn):
    
    if fn in EMAP:
        return fn

    if fn in EMAP_DATA:
        return fn

    if not isLinkedElf() and fn[0] == '_':
        return fn[1:]

    if fn.endswith("_0"):
        newfn = fn[:-2]
        if newfn in EMAP:
            return newfn

    for en in EXTERNAL_NAMES:
        if en in fn:
            fn = fn[:fn.find(en)]
            break

    return fn

def nameInMap(themap, fn):

    return fixExternalName(fn) in themap


def getFromEMAP(fname):

    fixname = fixExternalName(fname)
    return EMAP[fixname]


def doesNotReturn(fname):
    try:
        args, conv, ret, sign = getFromEMAP(fname)
        if ret == "Y":
            return True
    except KeyError, ke:
        raise Exception("Unknown external: " + fname)
    
    return False

def isHlt(insn_t):
    return insn_t.itype == idaapi.NN_hlt

def isJmpTable(ea):
    insn_t = idautils.DecodeInstruction(ea)
    is_jmp = insn_t.itype in [idaapi.NN_jmp, 
            idaapi.NN_jmpfi,
            idaapi.NN_jmpni]

    if not is_jmp: return False

    if idaapi.get_switch_info_ex(ea):
        return True

    return False

def addFunction(M, ep):
    F = M.internal_funcs.add()
    F.entry_address = ep
    F.symbol_name = getFunctionName(ep)
    return F

def entryPointHandler(M, ep, name, args_from_stddef=False):

    EP = M.entries.add()
    EP.entry_name = name
    EP.entry_address = ep

    have_edata = False


    # should we get argument count  
    # calling ocnvention, and return type from std_defs?
    if args_from_stddef:
        try:
            (argc, conv, ret, sign) = getFromEMAP(name)
            have_edata = True
        except KeyError as ke:
            pass

    if not have_edata:
        (argc, conv, ret) = getExportType(name, ep)

    EP.entry_extra.entry_argc = argc
    EP.entry_extra.entry_cconv = conv
    if ret == 'Y':
        EP.entry_extra.does_return = False
    else:
        EP.entry_extra.does_return = True
    
    F = addFunction(M, ep)

    DEBUG("At EP {0}:{1:x}\n".format(name,ep))

    return F

def basicBlockHandler(F, block, blockset, processed_blocks):
    B = F.blocks.add()
    B.base_address = block.startEA
    DEBUG("BB: {0:x}\n".format(block.startEA))

    B.block_follows.extend(block.succs)

    if _DEBUG:
        str_l = ["{0:x}".format(i) for i in block.succs]
        if len(str_l) > 0:
            DEBUG("Successors: {0}\n".format(", ".join(str_l)))

    return B

def readInstructionBytes(inst):
    insn_t = idautils.DecodeInstruction(inst)
    return [idc.Byte(b) for b in xrange(inst, inst+insn_t.size)]
        
def isInternalCode(ea):

    pf = idc.GetFlags(ea)
    if idc.isCode(pf) and not idc.isData(pf):
        return True

    # find stray 0x90 (NOP) bytes in .text that IDA 
    # thinks are data items
    if readByte(ea) == 0x90:
        seg = idc.SegStart(ea)
        segtype = idc.GetSegmentAttr(seg, idc.SEGATTR_TYPE)
        if segtype == idc.SEG_CODE:
            mark_as_code(ea)
            return True

    return False

def isNotCode(ea):

    pf = idc.GetFlags(ea)
    return not idc.isCode(pf)

def isExternalReference(ea):
    # see if this is in an internal or external code ref
    DEBUG("Testing {0:x} for externality\n".format(ea))
    ext_types = [idc.SEG_XTRN]
    seg = idc.SegStart(ea)
    if seg == idc.BADADDR:
        DEBUG("WARNING: Could not get segment addr for: {0:x}\n".format(ea))
        return False

    segtype = idc.GetSegmentAttr(seg, idc.SEGATTR_TYPE)
    if segtype in ext_types:
        return True

    if isLinkedElf():
        fn = getFunctionName(ea)
        for extsign in EXTERNAL_NAMES:
            if extsign in fn:
                DEBUG("Assuming external reference because: {} in {}\n".format(extsign, fn))
                return True

        if isExternalData(fn):
            if hasExternalDataComment(ea):
                return True
            else:
                DEBUG("WARNING: May have missed external data ref {} at {:x}".format(fn, ea))

    return False

def getFunctionName(ea):
    return idc.GetTrueNameEx(ea,ea)
    
def addInst(block, addr, inst_bytes, true_target=None, false_target=None):
    # check if there is a lock prefix:
    insn_t = idautils.DecodeInstruction(addr)
    if insn_t is not None and (insn_t.auxpref & 0x1) == 0x1:
        # has LOCK
        i_lock = block.insts.add()
        i_lock.inst_addr = addr
        i_lock.inst_bytes = chr(inst_bytes[0])
        i_lock.inst_len = 1

        addr += 1
        inst_bytes = inst_bytes[1:]

    if insn_t is not None and (insn_t.auxpref & 0x3) == 0x2:
        DEBUG("REP Prefix at: 0x{0:x}\n".format(addr))
        # special handling of certain REP pairs
        rest_bytes = inst_bytes[1:]
        if rest_bytes in SPECIAL_REP_HANDLING:
            # generate a separate REP_PREFIX instruction
            i_rep = block.insts.add()
            i_rep.inst_addr = addr
            i_rep.inst_bytes = chr(inst_bytes[0])
            i_rep.inst_len = 1
            addr += 1
            inst_bytes = inst_bytes[1:]

    inst = block.insts.add()
    inst.inst_addr = addr
    str_val = "".join([chr(b) for b in inst_bytes])
    inst.inst_bytes = str_val
    inst.inst_len = len(inst_bytes)

    if true_target != None: inst.true_target = true_target
    if false_target != None: inst.false_target = false_target

    return inst

def isConditionalJump(ea):
    insn_t = idautils.DecodeInstruction(ea)
    return insn_t.itype in COND_BRANCHES

def isUnconditionalJump(ea):
    insn_t = idautils.DecodeInstruction(ea)
    return insn_t.itype in UCOND_BRANCHES

def isCall(ea):
    insn_t = idautils.DecodeInstruction(ea)
    return insn_t.itype in CALLS

def isRet(ea):
    insn_t = idautils.DecodeInstruction(ea)
    return insn_t.itype in RETS

def isTrap(ea):
    insn_t = idautils.DecodeInstruction(ea)
    return insn_t.itype in TRAPS

def findRelocOffset(ea, size):
    for i in xrange(ea,ea+size):
        if idc.GetFixupTgtOff(i) != -1:
            return i-ea
    
    return -1

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
            DEBUG("Data Range: {0:x} <= {1:x} < {2:x}\n".format(start, start_ea, end))
            DEBUG("Data Range: {:x} - {:x}\n".format(start_ea, end_ea))
            if end_ea <= end:
                return True
            else:
                DEBUG("{0:x} NOT <= {1:x}\n".format(end_ea, end))
                DEBUG("{0:x}-{1:x} overlaps with: {2:x}-{3:x}\n".format(start_ea, end_ea, start, end))
                raise Exception("Overlapping data segments!")
        else:
            if end_ea > start and end_ea <= end:
                DEBUG("Overlaps with: {0:x}-{1:x}\n".format(start, end))
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


def sanityCheckJumpTableSize(table_ea, ecount):
    """ IDA doesn't correctly calculate some  jump table sizes. Fix them.

    This will look for the following jump tables:

    ----
    cmp eax, num_entries
    ja bad_entry
    fall_through:
    mov rax, qword [index * ptr_size + table_base_address]
    jmp rax
    bad_entry:
    ----


    IDA will detect these as jump tables, but it sometimes
    does not correctly calculate the "num_entries" properly,
    which leads us to missing jump table cases.

    Attempt to identify where 'num_entries' is compared, and
    sanity check it vs. what IDA found.

    """
    
    if not isLinkedElf():
        return ecount

    if getBitness() != 64:
        return ecount

    table_insn = idautils.DecodeInstruction(table_ea)
    if table_insn is None:
        DEBUG("Could not decode instruction at {:x}\n".format(table_insn))
        return ecount

    # This code is only reached if we *already know this is a jump table
    # The goal is to sanity check the size

    # First, Check to make sure that this is a "jmp reg" instruction. 
    if table_insn.Operands[0].type != idc.o_reg:
        return ecount

    DEBUG("Sanity checking table at {:x}\n".format(table_ea))

    # get register we jump with
    jmp_reg = table_insn.Operands[0].value

    inst_ea = table_ea
    # This will walk back up to 5 instructions looking for a 'cmp' against
    # the jump register, and use the immediate value from the cmp as 
    # the true jump table case count.

    # This strategy has the potential for false positives, since it
    # does not strictly check for the exact format of jump table instructions.
    # For now that is intentional to allow some flexibility, because we are
    # uncertain what the compiler will emit.

    #TODO(artem): Make this loop strict check for the instructions we expect,
    # if we find the current lax check causing false positives
    for i in xrange(5):
        # walk back a few instructions until we find a cmp
        inst_ea = idc.PrevHead(inst_ea)
        if inst_ea == idc.BADADDR:
            return ecount
        inst = idautils.DecodeInstruction(inst_ea)
        if inst is None:
            return ecount
        if inst.itype == idaapi.NN_cmp and inst.Operands[0].type == idc.o_reg:
            # check if reg in cmp == reg we jump with
            if jmp_reg == inst.Operands[0].value:
                # check if the CMP is with an immediate
                if inst.Operands[1].type == idc.o_imm:
                    # the immediate is our new count
                    # the comaprison is vs the max case#, but the cases start at 0, so add 1
                    # to get case count
                    new_count = 1 + inst.Operands[1].value
                    # compare to ecount. Take the bigger value.
                    if new_count > ecount:
                        DEBUG("Overriding old JMP count of {} with {} for table at {:x}\n".format(ecount, new_count, table_ea))
                        return new_count
            return ecount

    return ecount

def handleJmpTable(I, inst, new_eas):
    si = idaapi.get_switch_info_ex(inst)
    jsize = si.get_jtable_element_size()
    jstart = si.jumps

    # accept 32-bit jump tables in 64-bit, for now
    valid_sizes = [4, getBitness()/8]
    readers = { 4: readDword,
                8: readQword }

    if jsize not in valid_sizes:
        raise Exception("Jump table is not a valid size: {}".format(jsize))
        return

    DEBUG("\tJMPTable Start: {0:x}\n".format(jstart))
    seg_start = idc.SegStart(jstart)

    if seg_start != idc.BADADDR:
        I.jump_table.offset_from_data = jstart - seg_start
        DEBUG("\tJMPTable offset from data: {:x}\n".format(I.jump_table.offset_from_data))

    I.jump_table.zero_offset = 0
    i = 0
    entries = si.get_jtable_size()
    entries = sanityCheckJumpTableSize(inst, entries)
    for i in xrange(entries):
        je = readers[jsize](jstart+i*jsize)
        # check if this is an offset based jump table
        if si.flags & idaapi.SWI_ELBASE == idaapi.SWI_ELBASE:
            # adjust jump target based on offset in table
            # we only ever see these as 32-bit offsets, even
            # when looking at 64-bit applications
            je = 0xFFFFFFFF & (je + si.elbase)

        I.jump_table.table_entries.append(je)
        if je not in RECOVERED_EAS and isStartOfFunction(je):
            new_eas.add(je)

        DEBUG("\t\tAdding JMPTable {0}: {1:x}\n".format(i, je))
    #je = idc.GetFixupTgtOff(jstart+i*jsize)
    #while je != -1:
    #    I.jump_table.table_entries.append(je)
    #    if je not in RECOVERED_EAS: 
    #        new_eas.add(je)
    #    DEBUG("\t\tAdding JMPTable {0}: {1:x}\n".format( i, je))
    #    i += 1
    #    je = idc.GetFixupTgtOff(jstart+i*jsize)

def isElfThunk(ea):
    if not isLinkedElf():
        return False, None

    if isUnconditionalJump(ea):
        real_ext_ref = None

        for cref in idautils.CodeRefsFrom(ea, 0):
            if isExternalReference(cref):
                real_ext_ref = cref
                break

        if real_ext_ref is None:
            for dref in idautils.DataRefsFrom(ea):
                if idc.SegName(dref) in [".got.plt"]:
                    # this is an external call after all
                    for extref in idautils.DataRefsFrom(dref):
                        if isExternalReference(extref):
                            real_ext_ref = extref
 
        if real_ext_ref is not None:
            fn = getFunctionName(real_ext_ref)
            return True, fn

    return False, None

def manualRelocOffset(I, inst, dref):
    insn_t = idautils.DecodeInstruction(inst)

    if insn_t is None:
        return None

    # check for immediates first
    # TODO(artem) special case things like 0x0 that see in COFF objects?
    for (idx, op) in enumerate(insn_t.Operands):
        
        if op.value == dref:
            # IDA will do stupid things like say an immediate operand is a memory operand
            # if it references memory. Try to work around this issue

            # its the first operand (probably a destination) and IDA thinks its o_mem
            # in this case, IDA is probaly right; don't mark it as an immediate
            if idx == 0 and op.type == o_mem:
                continue

            if op.type in [idaapi.o_imm, idaapi.o_mem, idaapi.o_near, idaapi.o_far]:
                # we aren't sure what we have, but it use a register... probably not
                # an immediate but instead a memory reference
                if op.reg > 0:
                    I.mem_reloc_offset = op.offb
                    return "MEM"

                I.imm_reloc_offset = op.offb
                return "IMM"

    for op in insn_t.Operands:

            if op.type in [idaapi.o_displ, idaapi.o_phrase]:
                I.mem_reloc_offset = op.offb
                return "MEM"

    return "MEM"

def opAtOffset(insn_t, off):

    if insn_t is None:
        return None

    for op in insn_t.Operands:
        
        if op.offb == off:
            if op.type in [idaapi.o_displ, idaapi.o_phrase]:
                return "MEM"

            if op.type in [idaapi.o_imm, idaapi.o_mem, idaapi.o_near, idaapi.o_far]:
                return "IMM"

            DEBUG("ERROR: Unknown op type {}, assuming MEM\n".format(op.type))
            return "MEM"

    return None

def setReference(I, optype, reftype, ref):
    if "IMM" == optype:
        I.imm_reference = ref
        I.imm_ref_type = reftype
    elif "MEM" == optype:
        I.mem_reference = ref
        I.mem_ref_type = reftype
    else:
        DEBUG("ERROR: Unknown ref type: {}\n".format(optype))

def addDataReference(M, I, inst, dref, new_eas):
    if inValidSegment(dref): 


        if isExternalReference(dref):
            fn = getFunctionName(dref)

            fn = handleExternalRef(fn)
            if isExternalData(fn):
                I.ext_data_name = fn
                DEBUG("EXTERNAL DATA REF FROM {0:x} to {1}\n".format(inst, fn))
            else:
                I.ext_call_name = fn 
                DEBUG("EXTERNAL CODE REF FROM {0:x} to {1}\n".format(inst, fn))

            return

        which_op = manualRelocOffset(I, inst, dref)
        if which_op is None:
            DEBUG("ERROR: could not decode instruction at {:x}\n".format(inst))
            return

        ref = None
        reftype = None
        if isInternalCode(dref):
            ref = dref
            reftype = CFG_pb2.Instruction.CodeRef
            if dref not in RECOVERED_EAS: 
                new_eas.add(dref)
        else:
            dref_size = idc.ItemSize(dref)
            DEBUG("\t\tData Ref: {0:x}, size: {1}\n".format(
                dref, dref_size))
            ref = handleDataRelocation(M, dref, new_eas)
            reftype = CFG_pb2.Instruction.DataRef

        
        DEBUG("\t\tSetting {} ref at {:x}: to {:x} type: {}\n".format(
            which_op, inst, ref, ReftypeString(reftype)))
        setReference(I, which_op, reftype, ref)

    else:
        DEBUG("WARNING: Data not in valid segment {0:x}\n".format(dref))

def instructionHandler(M, B, inst, new_eas):
    insn_t = idautils.DecodeInstruction(inst)
    if not insn_t:
        # handle jumps after noreturn functions
        if idc.Byte(inst) == 0xCC:
            I = addInst(B, inst, [0xCC])
            return I, True
        else:
            raise Exception("Cannot read instruction at: {0:x}".format(inst))

    # skip HLTs -- they are privileged, and are used in ELFs after a noreturn call
    if isHlt(insn_t):
        return None, False

    #DEBUG("\t\tinst: {0}\n".format(idc.GetDisasm(inst)))
    inst_bytes = readInstructionBytes(inst)
    DEBUG("\t\tBytes: {0}\n".format(inst_bytes))

    I = addInst(B, inst, inst_bytes)

    if isJmpTable(inst):
        DEBUG("Its a jump table\n")
        handleJmpTable(I, inst, new_eas)
        return I, False

    # mark that this is an offset table
    if PIE_MODE and inst in OFFSET_TABLES:
        table_va = OFFSET_TABLES[inst].start_addr
        DEBUG("JMP at {:08x} has offset table {:08x}\n".format(inst, table_va))
        I.offset_table_addr = table_va

    crefs_from_here = idautils.CodeRefsFrom(inst, 0)

    #check for code refs from here
    crefs = []

    # pull code refs from generator into a list
    for cref_i in crefs_from_here:
        crefs.append(cref_i)

    is_call = isCall(inst)
    isize = insn_t.size
    next_ea = inst+isize

    had_refs = False
 
    # this is a call $+5, needs special handling
    if len(crefs) == 0 and is_call and isize == 5:
        selfCallEA = next_ea
        DEBUG("INTERNAL CALL $+5: {0:x}\n".format(selfCallEA))
        DEBUG("LOCAL NORETURN CALL!\n")
        I.local_noreturn = True

        if selfCallEA not in RECOVERED_EAS:
            DEBUG("Adding new EA: {0:x}\n".format(selfCallEA))
            new_eas.add(selfCallEA)
            I.mem_reference = selfCallEA
            I.mem_ref_type = CFG_pb2.Instruction.CodeRef

            return I, True
    
    for cref in crefs:
        DEBUG("Checking code ref {:x}\n".format(cref))
        had_refs = True
        fn = getFunctionName(cref)
        if is_call:

            elfy, fn_replace = isElfThunk(cref) 
            if elfy:
                fn = fn_replace
                DEBUG("Found external call via ELF thunk {:x} => {}\n".format(cref, fn_replace))

            if isExternalReference(cref) or elfy:
                fn = handleExternalRef(fn)
                I.ext_call_name = fn 
                DEBUG("EXTERNAL CALL: {0}\n".format(fn))

                if doesNotReturn(fn):
                    return I, True
            else:
                which_op = manualRelocOffset(I, inst, cref);
                setReference(I, which_op, CFG_pb2.Instruction.CodeRef, cref)

                if cref not in RECOVERED_EAS: 
                    new_eas.add(cref)

                DEBUG("INTERNAL CALL: {0}\n".format(fn))
        elif isUnconditionalJump(inst):
            if isExternalReference(cref):
                fn = handleExternalRef(fn)
                I.ext_call_name = fn 
                DEBUG("EXTERNAL JMP: {0}\n".format(fn))

                if doesNotReturn(fn):
                    DEBUG("Nonreturn JMP\n")
                    return I, True
            else:
                DEBUG("INTERNAL JMP: {0:x}\n".format(cref))
                I.true_target = cref

    #true: jump to where we have a code-ref
    #false: continue as we were
    if isConditionalJump(inst):
        I.true_target = crefs[0]
        I.false_target = inst+len(inst_bytes)
        return I, False

    if is_call and isNotCode(next_ea):
        DEBUG("LOCAL NORETURN CALL!\n")
        I.local_noreturn = True
        return I, True

    relo_off = findRelocOffset(inst, len(inst_bytes))
    # don't re-set reloc offset if we already set it somewhere
    if relo_off != -1:
        # check which operand this would be the offset for
        which_op = opAtOffset(insn_t, relo_off)

        # don't overwrite an offset set by other means
        if "IMM" == which_op and not I.HasField("imm_reloc_offset"):
            DEBUG("findRelocOffset setting imm reloc offset at {0:x} to {1:x}\n".format(inst, relo_off))
            I.imm_reloc_offset = relo_off
        
        if "MEM" == which_op and not I.HasField("mem_reloc_offset"):
            DEBUG("findRelocOffset setting mem reloc offset at {0:x} to {1:x}\n".format(inst, relo_off))
            I.mem_reloc_offset = relo_off

    drefs_from_here = idautils.DataRefsFrom(inst)
    for dref in drefs_from_here:
        had_refs = True
        if dref in crefs:
            continue
        DEBUG("Adding reference because of data refs from {:x}\n".format(inst))
        addDataReference(M, I, inst, dref, new_eas)
        if isUnconditionalJump(inst):
            xdrefs = idautils.DataRefsFrom(dref)
            for xref in xdrefs:
                DEBUG("xref : {0:x}\n".format(xref))
                # check if it refers to come instructions; link Control flow
                if isExternalReference(xref):
                   fn = getFunctionName(xref)
                   fn = handleExternalRef(fn)
                   I.ext_call_name = fn
                   DEBUG("EXTERNAL CALL : {0}\n".format(fn))

    if isLinkedElf() and not PIE_MODE:
        for op in insn_t.Operands:
            if op.type == idc.o_imm:
                if op.value in drefs_from_here:
                    continue
                # we have an immedaite.. check if its in a code or data section
                begin_a = op.value
                end_a = begin_a + idc.ItemSize(begin_a)
                if isInData(begin_a, end_a):
                    # add data reference
                    DEBUG("Adding reference because we fixed IMM value\n")
                    addDataReference(M, I, inst, begin_a, new_eas)
                #elif isInCode(begin_a, end_a):
                # add code ref

    return I, False

def parseDefsFile(df):
    emap = {}
    emap_data = {}
    for l in df.readlines():
        #skip comments / empty lines
        l = l.strip()
        if not l or l[0] == "#":
            continue

        
        if l.startswith('DATA:'):
            # process as data
            (marker, symname, dsize) = l.split()
            if 'PTR' in dsize:
                dsize = getPointerSize()
            emap_data[symname] = int(dsize)
        else:
            fname = args = conv = ret = sign = None
            line_args = l.split()
            if len(line_args) == 2:
                fname, conv = line_args
                if conv == "MCSEMA":
                    DEBUG("Found mcsema internal function: {}\n".format(fname))
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

            emap[fname] = (int(args), realconv, ret, sign)

    
    df.close()

    return emap, emap_data

def processExternalFunction(M, fn):

    args, conv, ret, sign = getFromEMAP(fn)
    ea = idc.LocByName(fn)
    is_weak = idaapi.is_weak_name(ea)

    DEBUG("Program will reference external{}: {}\n".format(" (weak)" if is_weak else "", fn))
    extfn = M.external_funcs.add()
    extfn.symbol_name = fn
    extfn.calling_convention = conv
    extfn.argument_count = args
    extfn.is_weak = is_weak
    if ret == 'N':
        extfn.has_return = True
        extfn.no_return = False
    else:
        extfn.has_return = False
        extfn.no_return = True

def processExternalData(M, dt):

    data_size = EMAP_DATA[dt]
    ea = idc.LocByName(dt)
    is_weak = idaapi.is_weak_name(ea)
    
    DEBUG("Program will reference external{}: {}\n".format(" (weak)" if is_weak else "", dt))

    extdt = M.external_data.add()
    extdt.symbol_name = dt
    extdt.data_size = data_size
    extdt.is_weak = is_weak

def processExternals(M):

    for fn in EXTERNALS:
        fixedn = fixExternalName(fn)
        if nameInMap(EMAP, fixedn):
            processExternalFunction(M, fixedn)
        elif nameInMap(EMAP_DATA, fixedn):
            processExternalData(M, fixedn)
        else:
            DEBUG("UNKNOWN API: {0}\n".format(fixedn))

def readBytesSlowly(start, end):
    bytestr = ""
    for i in xrange(start, end):
        if idc.hasValue(idc.GetFlags(i)):
            bt = idc.Byte(i)
            bytestr += chr(bt)
        else:
            #virtual size may be bigger than size on disk
            #pad with nulls
            #DEBUG("Failed on {0:x}\n".format(i))
            bytestr += "\x00"
    return bytestr

def handleDataRelocation(M, dref, new_eas):
    dref_size = idc.ItemSize(dref)
    if not isInData(dref, dref+dref_size):
        addDataSegment(dref, dref+dref_size)
        return dref + populateDataSegment(M, dref, dref+dref_size, new_eas)
    else:
        return dref

def getBitness():
    if (idaapi.ph.flag & idaapi.PR_USE64) != 0:
        # support 64-bit addressing
        return 64
    else:
        # no support for 64-bit, assume 32-bit
        return 32

def getPointerSize():
    return getBitness() / 8

def relocationSize(reloc_type):
    
    reloc_type = reloc_type & idc.FIXUP_MASK
    size_map = {
        idc.FIXUP_OFF8 : 1,
        idc.FIXUP_BYTE : 1,
        idc.FIXUP_OFF16 : 2,
        idc.FIXUP_SEG16 : 2,
        idc.FIXUP_PTR32 : 4,
        idc.FIXUP_OFF32 : 4,
        idc.FIXUP_PTR48 : 8,
        idc.FIXUP_HI8 : 1,
        idc.FIXUP_HI16 : 2,
        idc.FIXUP_LOW8 : 1,
        idc.FIXUP_LOW16 : 2,
        12: 8,}

    reloc_size = size_map.get(reloc_type, -1)
    return reloc_size


def resolveRelocation(ea):
    rtype = idc.GetFixupTgtType(ea) 

    relocSize = -1
    relocVal = -1

    if getBitness() == 64:
        if rtype == -1:
            raise Exception("No relocation type at ea: {:x}".format(ea))

        DEBUG("rtype : {0:x}, {1:x}, {2:x}\n".format(rtype, idc.GetFixupTgtOff(ea), idc.GetFixupTgtDispl(ea)))
        relocVal = idc.GetFixupTgtDispl(ea) +  idc.GetFixupTgtOff(ea)
    else:
        if rtype == idc.FIXUP_OFF32:
            relocVal = readDword(ea)
        elif rtype == -1:
            raise Exception("No relocation type at ea: {:x}".format(ea))
        else:
            relocVal = idc.GetFixupTgtOff(ea)

    relocSize = relocationSize(rtype)
    return relocVal, relocSize

def insertRelocatedSymbol(M, D, reloc_dest, offset, seg_offset, new_eas, itemsize=-1):
    pf = idc.GetFlags(reloc_dest)

    DS = D.symbols.add()
    DS.base_address = offset+seg_offset

    itemsize = int(itemsize)
    if itemsize == -1:
        itemsize = int(idc.ItemSize(offset))

    DEBUG("Offset: {0:x}, seg_offset: {1:x} => {2:x}\n".format(offset, seg_offset, reloc_dest))
    DEBUG("Reloc Base Address: {0:x}\n".format(DS.base_address))
    DEBUG("Reloc size: {0:x}\n".format(itemsize))

    if isExternalReference(reloc_dest):
        ext_fn = getFunctionName(reloc_dest)
        ext_fn = handleExternalRef(ext_fn)
        DEBUG("External ref from data at {:x} => {}\n".format(reloc_dest, ext_fn))
        DS.symbol_name = "ext_"+ext_fn
        DS.symbol_size = itemsize
    elif idc.isCode(pf):
        DS.symbol_name = "sub_"+hex(reloc_dest)
        DS.symbol_size = itemsize
        DEBUG("Code Ref: {0:x}!\n".format(reloc_dest))

        if reloc_dest not in RECOVERED_EAS:
            new_eas.add(reloc_dest)

    elif idc.isData(pf):
        reloc_dest = handleDataRelocation(M, reloc_dest, new_eas)
        DS.symbol_name = "dta_"+hex(reloc_dest)
        DS.symbol_size = itemsize
        DEBUG("Data Ref!\n")
    else:
        reloc_dest = handleDataRelocation(M, reloc_dest, new_eas)
        DS.symbol_name = "dta_"+hex(reloc_dest)
        DS.symbol_size = itemsize
        DEBUG("UNKNOWN Ref, assuming data\n")

def isStartOfFunction(ea):
    fname = idc.GetFunctionName(ea)
    return ea == idc.LocByName(fname)

def isSaneReference(ea):
    if isInternalCode(ea) and idc.ItemHead(ea) == ea:
        return True
    elif isInData(ea, ea+1) and idc.ItemHead(ea) == ea:
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

    def scan_table(start, end, readsize):
        table_map = {}

        read_option = {4 : readDword,
                       8 : readQword}[readsize]

        # sanity check for xrange
        if (end - start) % readsize != 0:
            return False, table_map, readsize

        for jea in xrange(start, end, readsize):
            pword = read_option(jea)
            if isSaneReference(pword): 
                DEBUG("Sane table entry at: {:x}\n".format(pword))
            elif pword == 0:
                DEBUG("Ignoring NULL entry in possible table: {:x}\n".format(jea))
            else:
                DEBUG("NOT a table entry at {:x}\n".format(jea))
                return False, table_map, readsize 

            table_map[jea] = pword

        return True, table_map, readsize

    did_find, table, readsz = scan_table(ea, ea+size, getPointerSize())
    if did_find == False and getPointerSize() == 8:
        DEBUG("Failed to find a table, trying with smaller pointer size\n")
        did_find, table, readsz = scan_table(ea, ea+size, 4)

    return did_find, table, readsz

def parseSingleStruct(ea, idastruct):
    DEBUG("Parsing idastruct at {:x}\n".format(ea))
    # get first member offset
    first_off = idc.GetFirstMember(idastruct.tid);

    # get last member offset
    last_off = idc.GetLastMember(idastruct.tid)

    # get starting offests of all members
    ptrs = {}
    members = set()

    read_size = getPointerSize()
    read_option = {4 : readDword,
                   8 : readQword}[read_size]

    for i in xrange(first_off, last_off+1):
        mn = idc.GetMemberName(idastruct.tid, i)
        # skip padding bytes
        if mn is not None:
            members.add(mn)

    for member in members:
        DEBUG("Checking idastruct member: {}\n".format(member))
        member_off = idc.GetMemberOffset(idastruct.tid, member)
        assert member_off != -1
        # get element size
        member_sz = idc.GetMemberSize(idastruct.tid, member_off)
        assert member_sz > 0
        
        #if its pointer size, check for ptr
        if member_sz == read_size:
            DEBUG("\tit is pointer sized\n")
            # check if points to sanity
            member_ea = ea+member_off
            pword = read_option(member_ea)
            if isSaneReference(pword):
                DEBUG("\tAdding reference from {:x} => {:x}\n".format(member_ea, pword))
                ptrs[member_ea] = pword
            else:
                DEBUG("\tNot a sane reference ({:x})\n".format(pword))


    return len(ptrs) != 0, ptrs, getPointerSize()

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
        DEBUG("Could not get structure size at: {:x}\n".format(ea))
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

    return True, all_ptrs, getPointerSize()

def processDataChunk(ea, size):
    """
    Determine if a data chunk has some pointers in it
    """

    # Get chunk type
    # if its a string, skip it
    if IsString(ea):
        DEBUG("Found a string at {:x}\n".format(ea))
        return False, {}, 0
    elif IsStruct(ea):
        DEBUG("Found a struct at {:x}\n".format(ea))
        return processStruct(ea, size)
    else:
        DEBUG("Found an unknown blob at {:x}, treating as table\n".format(ea))
        return processTable(ea, size)

#referenced from
# http://stackoverflow.com/questions/32030412/twos-complement-sign-extension-python
def sign_extend(value, bits):
    sign_bit = 1 << (bits - 1)
    return (value & (sign_bit - 1)) - (value & sign_bit)

def checkIfOffsetTable(ea):
    """
    Check if this is an offset table: that is, a table
    off offsets that when added to table base result
    in the VA of a jump target
    """

    DEBUG("LOOKING FOR OFFSET TABLE AT: {:08x}\n".format(ea))
    # preconditions
    # can only really do this when all sections are 
    # correctly based
    if not isLinkedElf():
        DEBUG("\t... not a linked elf\n");
        return False, 0, []

    # only present in PIE executables
    if not PIE_MODE:
        DEBUG("\t... not in PIE mode\n");
        return False

    #TODO: revisit
    if getBitness() != 64:
        DEBUG("\t... not 64-bit\n");
        return False, 0, []

    # check that there is a code reference
    # to ea somewhere
    refs = [x for x in idautils.DataRefsTo(ea)]
    if len(refs) == 0:
        DEBUG("\t... no refs to ea\n");
        return False, 0, []
    
    # assumes 32-bit offsets
    # 1: EA + EA[n] = beginning of an instruction
    entrycount = 0
    entries = []
    while True:
        entry_va = ea+entrycount*4
        entry = readDword(entry_va)
        # no null entries
        if entry == 0:
            break

        if entrycount > 0:
            refs_to_entry = list(idautils.DataRefsTo(entry_va))
            if len(refs_to_entry) > 0:
                DEBUG("\tfound other references {} to table entry {} (@ {:x}).".format(refs_to_entry, entrycount, entry_va))
                break

        dest_guess = ea + sign_extend(entry, 64)
        dest_guess &= 0xFFFFFFFFL
        # has to point to code and to the
        # start of an instruction
        if isInternalCode(dest_guess) and isSaneReference(dest_guess):
            DEBUG("\tAdded destination: {:08x}\n".format(dest_guess))
            entries.append(dest_guess)
            entrycount += 1
        else:
            DEBUG("\tInvalid destination: {:08x}\n".format(dest_guess))
            # invalid entry
            break

    # minimum here is fairly arbitrary
    return (entrycount > 1, entrycount, entries)

def createOffsetTable(M, table_start, table_entries):

    # create new OffsetTable message
    OT = M.offset_tables.add()

    # set table start
    OT.start_addr = table_start

    # loop through table_entries, and populate
    # * original data (int32, readDword(table_start + i * 4))
    # * point-to va (int64, table_entries[i])

    for idx, entry in enumerate(table_entries):
        orig_data = readDword(table_start + idx * 4)
        # orig data value at table index
        OT.table_offsets.append(orig_data)
        # destination at that index
        OT.destinations.append(entry)

    jmp_refs = set()
    for ref in idautils.DataRefsTo(table_start):
        DEBUG("Checking ref to table...\n")
        insn_t = idautils.DecodeInstruction(ref)
        # check if REF points to LEA REG, <value>
        if insn_t.itype == idaapi.NN_lea and insn_t.Operands[0].type == idc.o_reg:
            DEBUG("Found a LEA\n")
            dest_reg = idc.GetOpnd(ref, 0)

            # get next 5 insts
            cur_head = idc.NextHead(ref)
            for i in xrange(5):
                # is it a jump?
                if isUnconditionalJump(cur_head):
                    DEBUG("Found follow unconditional jump at {:08x}\n".format(cur_head))
                    # is it a JMP?
                    jmp_reg = idc.GetOpnd(cur_head, 0)
                    if jmp_reg == dest_reg:
                        # yes: add EA of JMP REG ot jmp_refs 
                        DEBUG("Found JMP using offset table {:08x} at {:08x}\n".format(table_start, cur_head))
                        jmp_refs.add(cur_head)
                cur_head = idc.NextHead(cur_head)
        else:
            DEBUG("NOT a lea :(\n")

    for jmp_ref in jmp_refs:
        OFFSET_TABLES[jmp_ref] = OT

    return jmp_refs

def scanDataForRelocs(M, D, start, end, new_eas, seg_offset):
    i = start
    while i < end:
        if PIE_MODE:
            (is_table, ecount, entries) = checkIfOffsetTable(i)
            if is_table:
                DEBUG("FOUND AN OFFSET TABLE AT: {:08x}\n".format(i))
                DEBUG("Table has {} destinations:\n".format(ecount))
                for e in entries:
                    DEBUG("\t{:08x}\n".format(e))
                    # these may be the only references to certain
                    # code islands. Make sure we recover them
                    #if e not in RECOVERED_EAS:
                    #    new_eas.add(e)

                refs = createOffsetTable(M, i, entries)
                for ref in refs:
                    for e in set(entries):
                        DEBUG("Adding Offset Table XREF {} => {}\n".format(ref, e))
                        idc.AddCodeXref(ref, e, idc.XREF_USER|idc.fl_F)

                i += (4 * ecount) - 1

        more_dref = [d for d in idautils.DataRefsFrom(i)]
        dref_size = idc.ItemSize(i) or 1
        if len(more_dref) == 0 and dref_size == 1 and not PIE_MODE:
            dword = readDword(i)
            DEBUG("Testing address: {0:x}... ".format(i))
            # check for unmakred references
            # that point to the beginning of an item
            if isInData(dword, dword+1) and idc.ItemHead(dword) == dword:
                if idc.MakeDword(i):
                    idc.add_dref(i, dword, idc.XREF_USER|idc.dr_O)
                    DEBUG("making New Data Reference at: {0:x} => {1:x}\n".format(i, dword))
                    dref_size = 4
                else:
                    DEBUG("WARNING: Could not make reference at {:x}\n".format(i))
            # check if code and points to the beginning of an instruction
            elif isInternalCode(dword) and idc.ItemHead(dword) == dword:
                if idc.MakeDword(i):
                    idc.AddCodeXref(i, dword, idc.XREF_USER|idc.fl_F)
                    DEBUG("making New Code Reference at: {0:x} => {1:x}\n".format(i, dword))
                    dref_size = 4
                else:
                    DEBUG("WARNING: Could not make reference at {:x}\n".format(i))
            else:
                DEBUG("not code or data ref\n")

        i += dref_size

    def insertReference(M, D, ea, pointsto, seg_offset, new_eas, force_size=None):
        # do not make code references for mid-function code accessed via a JMP -- 
        # they will be found via the jumptable code. This prevents the insertion
        # of lots of extra code, but could be wrong for some cases
        if ea in ACCESSED_VIA_JMP and not isStartOfFunction(pointsto):
            # bail only if we are access via JMP and not the start
            # of a function
            DEBUG("\t\tNOT ADDING REF: {:08x} -> {:08x}\n".format(ea, pointsto))
            return

        DEBUG("\t\tFound a probable ref from: {0:x} => {1:x}\n".format(ea, pointsto))
        real_size = idc.ItemSize(pointsto)
        if force_size is None:
            reloc_size = idc.ItemSize(ea)
        else:
            reloc_size = force_size
        DEBUG("\t\tReal Ref: {0:x}, reloc size: {2}, ref size: {1}\n".format(pointsto, real_size, reloc_size))
        insertRelocatedSymbol(M, D, pointsto, ea, seg_offset, new_eas, reloc_size)


    i = start
    while i < end:
        DEBUG("Checking address: {:x}\n".format(i))
        dref_size = idc.ItemSize(i) or 1
        if dref_size > getPointerSize():
            DEBUG("Possible table/struct data at {:x}; size: {:x}\n".format(i, dref_size))
            (found, addrs, entry_size) = processDataChunk(i, dref_size)
            if found:
                DEBUG("Its a table/struct, adding {} references\n".format(len(addrs)))
                for ta in sorted(addrs.keys()):
                    if addrs[ta] != 0:
                        insertReference(M, D, ta, addrs[ta], seg_offset, new_eas, force_size=entry_size)
            else:
                DEBUG("Not a stable/struct, skipping\n")

        elif dref_size == getPointerSize() or dref_size == 4:
            if dref_size == 4 and getBitness() == 64:
                # check if IDA missed a qword data reference
                dw = readDword(i+4)
                if dw == 0:
                    if idc.MakeQword(i):
                        DEBUG("Making qword from 32-bit dref at {:x}\n".format(i))
                        dref_size = 8
                    else:
                        DEBUG("WARNING: Failed at make qword at {:x}, ignoring ref\n".format(i))
                        dref_size = 4
                        i += dref_size
                        continue

                else:
                    DEBUG("WARNING: could not make qword from 32-bit dref at {:x}, ignoring ref\n".format(i))
                    dref_size = 4
                    i += dref_size
                    continue

            more_cref = [c for c in idautils.CodeRefsFrom(i,0)]

            # sanity check IDA
            more_cref = filter(lambda x: idc.ItemHead(x) == x, more_cref)

            more_dref = [d for d in idautils.DataRefsFrom(i)]
            more_dref.extend(more_cref)
            # do this check since IDA is crazy and sometimes returns data
            # references > 0xff00000000000000
            if len(more_dref) > 0 and more_dref[0] < 0xff00000000000000:
                DEBUG("\t\tFound a probable ref from: {0:x} => {1:x}\n".format(i, more_dref[0]))
                if len(more_dref) == 1:
                    insertReference(M, D, i, more_dref[0], seg_offset, new_eas)
                else: 
                    DEBUG("\t\tWARNING: Possible data ref problem\n");
                    insertReference(M, D, i, more_dref[0], seg_offset, new_eas)

        i += dref_size

def processRelocationsInData(M, D, start, end, new_eas, seg_offset):

    if start == 0:
        start = 1

    i = idc.GetNextFixupEA(start-1)

    DEBUG("Looking for relocations in {:x} - {:x}\n".format(start, end))

    if i == idc.BADADDR or i > end:
        if isLinkedElf():
            DEBUG("No relocations in binary, scanning for data references\n");
            # no fixups, do manual reloc searching
            scanDataForRelocs(M, D, start, end, new_eas, seg_offset)
        else:
            DEBUG("Not scanning data sections of object file for pointer-alikes\n")
    else:
        DEBUG("Found relocations in binary: ({:x})..\n".format(i))
        while i < end and i != idc.BADADDR:
            pointsto, itemsize = resolveRelocation(i)
            DEBUG("{0:x} Found reloc to: {1:x} (size: {2:x})\n".format(i, pointsto, itemsize))

            if not isExternalReference(pointsto):
                # do not add references in jump tables....
                # MAY BREAK EXTERNAL API CALLS
                if i in ACCESSED_VIA_JMP and not isStartOfFunction(pointsto):
                    # bail only if we are access via JMP and not the start
                    # of a function
                    DEBUG("\t\tNOT ADDING REF: {:08x} -> {:08x}\n".format(i, pointsto))
                else:
                    insertRelocatedSymbol(M, D, pointsto, i, seg_offset, new_eas, itemsize)
            else:
                DEBUG("{:x} is an external reference\n".format(i))
                insertRelocatedSymbol(M, D, pointsto, i, seg_offset, new_eas, itemsize)

            i = idc.GetNextFixupEA(i)

def inValidSegment(ea):
    if idc.SegStart(ea) == idc.BADADDR:
        return False

    return True

def findFreeData():

    max_end = 0
    for (start, end) in DATA_SEGMENTS.values():
        if end > max_end:
            max_end = end

    if idc.__EA64__ is True:
        return max_end+8
    else:
        return max_end+4

def addDataSegment(start, end):
    if end < start:
        raise Exception("Start must be before end")

    seg = idaapi.getseg(start)

    if not seg:
        raise Exception("Data must be in a valid segment")
    
    # if this is in an executalbe region,
    # move it to a data section
    seg_offset = 0
    need_move = (seg.perm & idaapi.SEGPERM_EXEC) != 0
    if need_move:
        free_data = findFreeData()
        seg_offset = free_data - start
        DEBUG("Data Segment {0:x} moved to: {1:x}\n".format(start, start+seg_offset))

    DATA_SEGMENTS[ (start, end,) ] = (start+seg_offset, end+seg_offset,)

    DEBUG("Adding data seg: {0}: {1}-{2}\n".format( 
        idc.SegName(start),
        hex(start+seg_offset),
        hex(end+seg_offset)))

    return seg_offset

def populateDataSegment(M, start, end, new_eas):

    (new_start, new_end) = DATA_SEGMENTS.get( (start, end,), (-1,-1) )

    if (new_start, new_end) == (-1,-1):
        raise Exception("Requested segment ({}, {}) not found".format(start, end))

    seg_offset = new_start - start

    D = M.internal_data.add()
    D.base_address = new_start

    SEGPERM_WRITE = 2
    
    seg = idaapi.getseg(start)
    if (seg.perm & SEGPERM_WRITE) == 0:
        D.read_only = True
    else:
        D.read_only = False

    D.data = readBytesSlowly(start, end)

    processRelocationsInData(M, D, start, end, new_eas, seg_offset)

    DEBUG("Adding data seg: {0}: {1}-{2}\n".format( 
        idc.SegName(start),
        hex(new_start),
        hex(new_end)))

    return seg_offset

def processDataSegments(M, new_eas):
    for n in xrange(idaapi.get_segm_qty()):
        seg = idaapi.getnseg(n)
        ea = seg.startEA
        segtype = idc.GetSegmentAttr(ea, idc.SEGATTR_TYPE)
        if segtype in [idc.SEG_DATA, idc.SEG_BSS]:
            start = idc.SegStart(ea)
            end = idc.SegEnd(ea)
            populateDataSegment(M, start, end, new_eas)

def getInstructionSize(ea):
    insn = idautils.DecodeInstruction(ea)
    return insn.size

def recoverFunctionFromSet(M, F, blockset, new_eas):
    processed_blocks = set()

    while len(blockset) > 0:
        block = blockset.pop()

        if block.startEA == block.endEA:
            DEBUG("Zero sized block: {0:x}\n".format(block.startEA))

        if block.startEA in processed_blocks:
            raise Exception("Attempting to add same block twice: {0:x}".format(block.startEA))

        processed_blocks.add(block.startEA)

        B = basicBlockHandler(F, block, blockset, processed_blocks)
        prevHead = block.startEA
        DEBUG("Starting insn at: {0:x}\n".format(prevHead))
        for head in idautils.Heads(block.startEA, block.endEA):
            # we ended the function on a call

            DEBUG("Processing insn at {:x}\n".format(head))
            I, endBlock = instructionHandler(M, B, head, new_eas)
            # sometimes there is junk after a terminator due to off-by-ones in
            # IDAPython. Ignore them.
            #if endBlock or isRet(head) or isUnconditionalJump(head) or isTrap(head):
            if endBlock or isRet(head) or isTrap(head):
                break
            prevHead = head

        DEBUG("Ending insn at: {0:x}\n".format(prevHead))

def recoverFunction(M, F, fnea, new_eas):
    blockset = getFunctionBlocks(fnea)
    recoverFunctionFromSet(M, F, blockset, new_eas)

class Block:
    def __init__(self, startEA):
        self.startEA = startEA
        self.endEA = startEA
        self.succs = []

def recoverBlock(startEA):
    b = Block(startEA)
    curEA = startEA

    while True:
        insn_t = idautils.DecodeInstruction(curEA)
        if insn_t is None:
            if idc.Byte(curEA) == 0xCC:
                b.endEA = curEA+1
                return b
            else:
                DEBUG("WARNING: Couldn't decode insn at: {0:x}. Ending block.\n".format(curEA))
                b.endEA = curEA
                return b

        # find EA of next inst
        nextEA = curEA+insn_t.size

        crefs = idautils.CodeRefsFrom(curEA, 1)

        # get curEA follows
        follows = [cref for cref in crefs]

        if follows == [nextEA] or isCall(curEA):
            # there is only one following branch, to the next instruction
            # check if this is a JMP 0; in that case, make a new block
            if isUnconditionalJump(curEA):
                b.endEA = nextEA
                for f in follows:
                    # do not decode external code refs
                    if not isExternalReference(f):
                        b.succs.append(f)
                return b

            # if its not JMP 0 or call 0, 
            # add next instruction to current block
            curEA = nextEA
        # check if we need to make a new block
        elif len(follows) == 0:
            # this is a ret, no follows
            b.endEA = nextEA
            return b
        else:
            # this block has several follow blocks
            b.endEA = nextEA
            for f in follows:
                # do not decode external code refs
                if not isExternalReference(f):
                    b.succs.append(f)
            return b

        # right now we know this block has one follows
        # ...but does something else go there? 
        # we may need to split the block anyway
        orefs = idautils.CodeRefsTo(nextEA, 0)
        # who else calls us?

        orefs_list = [oref for oref in orefs]
        if len(orefs_list) > 0:
            b.endEA = nextEA
            b.succs.append(nextEA)
            return b

        # else continue with instruction

def getFunctionBlocks(startea):
    to_recover = [startea]
    
    blocks = {}

    while len(to_recover) > 0:
        # get new block start to recover
        bstart = to_recover.pop()
        # recover the block
        newb = recoverBlock(bstart)
        # save to our recovered block list
        blocks[newb.startEA] = newb
        # add new workers
        for fba in newb.succs:
            if fba not in blocks:
                to_recover.append(fba)

    rv = []
    # easier to debug
    for k in sorted(blocks.keys()):
        rv.append(blocks[k])

    return rv

def preprocessBinary():
    # loop through every instruction and
    # keep a list of jump tables references in the
    # data section. These are used so we can
    # avoid generating unwanted function entry points
    for seg_ea in idautils.Segments():
        segtype = idc.GetSegmentAttr(seg_ea, idc.SEGATTR_TYPE)
        if segtype in [idc.SEG_DATA, idc.SEG_BSS]:
            addDataSegment(seg_ea, idc.SegEnd(seg_ea))

        for head in idautils.Heads(seg_ea, idc.SegEnd(seg_ea)):
            if idc.isCode(idc.GetFlags(head)):
                si = idaapi.get_switch_info_ex(head)
                if si is not None and isUnconditionalJump(head):
                    DEBUG("Found a jmp based switch at: {0:x}\n".format(head))
                    esize = si.get_jtable_element_size()
                    readers = { 4: readDword,
                                8: readQword }
                    base = si.jumps
                    count = si.get_jtable_size()
                    count = sanityCheckJumpTableSize(head, count)
                    jmp_refs = set(idautils.CodeRefsFrom(head, 1))
                    for i in xrange(count):
                        fulladdr = base+i*esize
                        DEBUG("Address accessed via JMP: {:x}\n".format(fulladdr))
                        ACCESSED_VIA_JMP.add(fulladdr)
                        je = readers[esize](fulladdr)
                        if si.flags & idaapi.SWI_ELBASE == idaapi.SWI_ELBASE:
                            # adjust jump target based on offset in table
                            # we only ever see these as 32-bit offsets, even
                            # when looking at 64-bit applications
                            je = 0xFFFFFFFF & (je + si.elbase)
                        if je not in jmp_refs:
                            jmp_refs.add(je)
                            DEBUG("\t\tJMPTable entry not in original; adding ref {:x} => {:x}\n".format(head, je))
                            idc.AddCodeXref(head, je, idc.XREF_USER|idc.fl_F)
                            mark_as_code(je)
            if PIE_MODE:
                # convert all immediate operand location references to numbers
                inslen = idaapi.decode_insn(head)
                if inslen > 0:
                    # check every op
                    for i in range(len(idaapi.cmd.Operands)):
                        # is this op an immediate?
                        op = idaapi.cmd.Operands[i]
                        if op.type == idc.o_imm:
                            # ensure this is operand is a number, not reference
                            idaapi.op_num(head, i)
                            idaapi.del_dref(head, op.value)
                            idaapi.del_cref(head, op.value, False)


def recoverCfg(to_recover, outf, exports_are_apis=False):
    M = CFG_pb2.Module()
    M.module_name = idc.GetInputFile()
    DEBUG("PROCESSING: {0}\n".format(M.module_name))

    our_entries = []
    entrypoints = idautils.Entries()
    exports = {}
    for index,ordinal,exp_ea, exp_name in entrypoints:
        exports[exp_name] = exp_ea
        
    new_eas = set()

    preprocessBinary()

    processDataSegments(M, new_eas)
    
    for name in to_recover:

        if name in exports:
            ea = exports[name]
        else:
            ea = idc.LocByName(name)
            if ea == idc.BADADDR:
                raise Exception("Could not locate entry symbol: {0}".format(name))

        fwdname = isFwdExport(name, ea)

        if fwdname is not None:
            DEBUG("Skipping fwd export {0} : {1}\n".format(name, fwdname))
            continue

        if not isInternalCode(ea):
            DEBUG("Export {0} at {1} does not point to code; skipping\n".format(name, hex(ea)))
            continue
            
        our_entries.append( (name, ea) )

    recovered_fns = 0

    # process main entry points
    for fname, fea in our_entries:

        DEBUG("Recovering: {0}\n".format(fname))

        F = entryPointHandler(M, fea, fname, exports_are_apis)

        RECOVERED_EAS.add(fea)
        recoverFunction(M, F, fea, new_eas)

        recovered_fns += 1

    # process subfunctions
    new_eas.difference_update(RECOVERED_EAS)

    while len(new_eas) > 0:
        cur_ea = new_eas.pop()
        if not isInternalCode(cur_ea):
            raise Exception("Function EA not code: {0:x}".format(cur_ea))

        F = addFunction(M, cur_ea)
        DEBUG("Recovering: {0}\n".format(hex(cur_ea)))
        RECOVERED_EAS.add(cur_ea)

        recoverFunction(M, F, cur_ea, new_eas)

        recovered_fns += 1

    if recovered_fns == 0:
        DEBUG("COULD NOT RECOVER ANY FUNCTIONS\n")
        return

    mypath = path.dirname(__file__)
    processExternals(M)

    outf.write(M.SerializeToString())
    outf.close()

    DEBUG("Recovered {0} functions.\n".format(recovered_fns))
    DEBUG("Saving to: {0}\n".format(outf.name))


def isFwdExport(iname, ea):
    l = ea
    if l == idc.BADADDR:
        raise Exception("Cannot find addr for: " + iname)

    pf = idc.GetFlags(l)

    if not idc.isCode(pf) and idc.isData(pf):
        sz = idc.ItemSize(l)
        iname = idaapi.get_many_bytes(l, sz-1)
        return iname

    return None

def writeDriverLine(batfile, name, ea):

    args, conv, ret = getExportType(name, ea)

    retstr = "return"
    if ret == "Y": retstr = "noreturn"

    batfile.write(" -driver=driver_{0},{0},{1},{2}".format(name, args, retstr))

def generateBatFile(batname, eps):
    infile = idc.GetInputFile()
    batfile = open(batname, 'wb')
    batheader = """
    @echo off
    set /p LLVM_PATH= < LLVM_PATH
    set /p CFG_TO_BC_PATH= < CFG_TO_BC_PATH

    set CFG_TO_BC=%CFG_TO_BC_PATH%\cfg_to_bc.exe
    set OPT=%LLVM_PATH%\opt.exe
    set LLC=%LLVM_PATH%\llc.exe
    REM
    REM
    echo Making API Import libs...
    cmd /c makelibs.bat > NUL
    echo Converting CFG to Bitcode
    del {}.bc 2>NUL
    """.format(infile)

    batfile.write(batheader)
    batfile.write("%CFG_TO_BC% ")
    batfile.write("-ignore-unsupported=true -i={0}_ida.cfg -o={0}.bc\n".format(infile))
    batfile.write("\n")
    batfile.write(" echo Optimizing Bitcode\n")
    batfile.write("%OPT% ")
    batfile.write("-O3 -o {0}_opt.bc {0}.bc\n".format(infile))
    batfile.write("echo Creating .obj\n")
    batfile.write("del kernel32.dll.obj 2>NUL\n")
    batfile.write("%LLC% ")
    batfile.write("-O3 -filetype=obj -o {0}.obj {0}_opt.bc\n".format(infile))
    batfile.write("echo Building export stub\n")
    batfile.write("cl /c {0}_exportstub.c \n".format(infile))
    batfile.write("REM Below is a compilation template. You need to uncomment it to build.\n")
    batfile.write("REM and add some .lib files to the line as well.\n")
    batfile.write("REM \n")
    batfile.write("REM link /NODEFAULTLIB /ENTRY:export_DllEntryPoint /DLL /DEF:{0}.def /OUT:{0} {0}.obj {0}_exportstub.obj msvcrt.lib *.lib \n".format(infile))
    batfile.write("echo Uncomment lines to attempt linking to a DLL\n")
    batfile.close()

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
        DEBUG("Processing export name: {} at: {:x}\n".format(name, ep))
        args, conv, ret, sign = getFromEMAP(name)
    except KeyError as ke:
        tp = idc.GetType(ep);
        if tp is None or "__" not in tp: 
            #raise Exception("Cannot determine type of function: {0} at: {1:x}".format(name, ep))
            DEBUG("WARNING: Cannot determine type of function: {0} at: {1:x}".format(name, ep))
            return (0, CFG_pb2.ExternalFunction.CalleeCleanup, "N")

        return parseTypeString(tp, ep)

    return args, conv, ret

def generateDefFile(defname, eps):
    deffile = open(defname, 'wb')
    deffile.write("EXPORTS\n")
    entrypoints = idautils.Entries()

    for ep_tuple in entrypoints:
        (index, ordinal, ea, name) = ep_tuple

        if name not in eps:
            continue

        fwdname = isFwdExport(name, ea)
        if fwdname is not None:
            deffile.write("{0}={1}\n".format(name, fwdname))
        else:
            args, conv, ret = getExportType(name, ea)

            if conv == CFG_pb2.ExternalFunction.CallerCleanup:
                decor_name = "_export_{0}".format(name)
            elif conv == CFG_pb2.ExternalFunction.CalleeCleanup:
                decor_name = "_export_{0}@{1}".format(name, args*4)
            elif conv == CFG_pb2.ExternalFunction.FastCall:
                decor_name = "@export_{0}@{1}".format(name, args*4)
            else:
                raise Exception("Unknown calling convention: " + str(conv))

            deffile.write("{0}={1}\n".format(name, decor_name))

    deffile.close()

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

def generateExportStub(cname, eps):
    cfile = open(cname, 'wb')
    entrypoints = idautils.Entries()

    for ep_tuple in entrypoints:
        (index, ordinal, ea, name) = ep_tuple

        if name not in eps:
            continue

        fwdname = isFwdExport(name, ea)
        if fwdname is not None:
            continue
        else:
            args, conv, ret =  getExportType(name, ea)

            if conv == CFG_pb2.ExternalFunction.CallerCleanup:
                convstr = "__cdecl"
            elif conv == CFG_pb2.ExternalFunction.CalleeCleanup:
                convstr = "__stdcall"
            elif conv == CFG_pb2.ExternalFunction.FastCall:
                convstr = "__fastcall"
            else:
                raise Exception("Unknown calling convention")

            declargs = makeArgStr(name, declaration=True)
            callargs = makeArgStr(name, declaration=False)

            cfile.write("extern int {2} driver_{0}({1});\n".format(name, declargs, convstr))
            cfile.write("int {3} export_{0}({1}) {{ return driver_{0}({2}); }} \n".format(
                name, declargs, callargs, convstr))
            cfile.write("\n")

    cfile.close()

def getAllExports() :
    entrypoints = idautils.Entries()
    to_recover = set()
    # recover every entry point
    for ep_tuple in entrypoints:
        (index, ordinal, ea, name) = ep_tuple
        to_recover.add(name)

    return to_recover 

# Mark an address as containing code.
def mark_as_code(address):
    if not idc.isCode(idc.GetFlags(address)):
        DEBUG("Marking {:x} as code\n".format(address))
        idc.MakeCode(address)
        idaapi.autoWait()


# Mark an address as being the beginning of a function.
def try_mark_as_function(address):
  if not idaapi.add_func(address, idc.BADADDR):
    DEBUG("Unable to convert code to function: {}".format(address))
    return False
  idaapi.autoWait()
  return True

    
if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("--batch", 
        help="Indicate the script is running in batch mode",
        action="store_true",
        default=False)

    parser.add_argument("--entry-symbol", nargs='*', help="Symbol(s) to start disassembling from")

    parser.add_argument("-o", "--output", type=argparse.FileType('wb'),
        default=None,
        help="The output control flow graph recovered from this file")

    parser.add_argument("-s", "--std-defs", action='append', type=argparse.FileType('r'),
        default=[],
        help="std_defs file: definitions and calling conventions of imported functions and data"
        )
    
    parser.add_argument("-e", "--exports-to-lift", type=argparse.FileType('r'),
        default=None,
        help="A file containing a exported functions to lift, one per line. If not specified, all exports will be lifted."
        )
    parser.add_argument("--make-export-stubs", action="store_true",
        default=False,
        help="Generate a .bat/.c/.def combination to provide export symbols. Use this if you're lifting a DLL and want to re-export the same symbols"
        )
    parser.add_argument("--exports-are-apis", action="store_true",
        default=False,
        help="Exported functions are defined in std_defs. Useful when lifting DLLs"
        )
    parser.add_argument("-d", "--debug", action="store_true",
        default=False,
        help="Enable verbose debugging mode"
        )
    parser.add_argument("--debug_output", type=argparse.FileType('w'),
        default=sys.stderr,
        help="Log to a specific file. Default is stderr."
        )
    
    parser.add_argument("-z", "--syms", type=argparse.FileType('r'), default=None,
        help="File containing <name> <address> pairs of symbols to pre-define."
        )

    parser.add_argument("--pie-mode", action="store_true", default=False,
            help="Assume all immediate values are constants (useful for ELFs built with -fPIE")

    args = parser.parse_args(args=idc.ARGV[1:])

    if args.debug:
        _DEBUG = True
        _DEBUG_FILE = args.debug_output
        DEBUG("Debugging is enabled.")

    if args.pie_mode:
        DEBUG("Using PIE mode.")
        PIE_MODE = True

    # for batch mode: ensure IDA is done processing
    if args.batch:
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
                if not isInternalCode(ea):
                    mark_as_code(ea)
                try_mark_as_function(ea)
                idc.MakeName(ea, name)

        myname = idc.GetInputFile()
        mypath = path.dirname(__file__)

        EMAP = {}
        EMAP_DATA = {}

        if len(args.std_defs) > 0:
            for defsfile in args.std_defs:
                DEBUG("Loading Standard Definitions file: {0}\n".format(defsfile.name))
                em_update, emd_update = parseDefsFile(defsfile)
                EMAP.update(em_update)
                EMAP_DATA.update(emd_update)

        if args.output:
            outpath = os.path.dirname(args.output.name)
        else:
            outpath =  os.path.join(mypath, myname)
            try:
                os.mkdir(outpath)
            except:
                pass

        eps = []
        try:
            if args.exports_to_lift: 
                eps = args.exports_to_lift.readlines()
            elif args.entry_symbol is None:
                eps = getAllExports()

            eps = [ep.strip() for ep in eps]

        except IOError as e:
            DEBUG("Could not open file of exports to lift. See source for details\n")
            idc.Exit(-1)

        if args.entry_symbol:
            eps.extend(args.entry_symbol)

        assert len(eps) > 0, "Need to have at least one entry point to lift"

        DEBUG("Will lift {0} exports\n".format(len(eps)))
        if args.make_export_stubs:
            DEBUG("Generating export stubs...\n");

            outdef = path.join(outpath, "{0}.def".format(myname))
            DEBUG("Output .DEF file: {0}\n".format(outdef))
            generateDefFile(outdef, eps)

            outstub = path.join(outpath, "{0}_exportstub.c".format(myname))
            DEBUG("Output export stub file: {0}\n".format(outstub))
            generateExportStub(outstub, eps)

            outbat = path.join(outpath, "{0}.bat".format(myname))
            DEBUG("Output build .BAT: {0}\n".format(outbat))
            generateBatFile(outbat, eps)


        if args.output:
            outf = args.output
        else:
            cfgname = path.join(outpath, myname + "_ida.cfg")
            cfgpath = path.join(outpath, cfgname)
            outf = open(cfgpath, 'wb')

        DEBUG("CFG Output File file: {0}\n".format(outf.name))

        recoverCfg(eps, outf, args.exports_are_apis)
    except Exception as e:
        DEBUG(str(e))
        DEBUG(traceback.format_exc())
    
    #for batch mode: exit IDA when done
    if args.batch:
        idc.Exit(0)
