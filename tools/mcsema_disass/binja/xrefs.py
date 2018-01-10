import binaryninja as binja
from binaryninja.enums import LowLevelILOperation
import logging

import CFG_pb2
import util

log = logging.getLogger(util.LOGNAME)


class XRef(object):
    IMMEDIATE = 0
    MEMORY = 1
    DISPLACEMENT = 2
    CONTROLFLOW = 3

    TYPE_TO_CFG = {
        IMMEDIATE    : CFG_pb2.CodeReference.ImmediateOperand,
        MEMORY       : CFG_pb2.CodeReference.MemoryOperand,
        DISPLACEMENT : CFG_pb2.CodeReference.MemoryDisplacementOperand,
        CONTROLFLOW  : CFG_pb2.CodeReference.ControlFlowOperand
    }

    def __init__(self, addr, reftype):
        self.addr = addr
        self.type = reftype

    @property
    def cfg_type(self):
        return self.TYPE_TO_CFG[self.type]

    def __repr__(self):
        return '<XREF: 0x{:x} {}>'.format(self.addr, CFG_pb2.CodeReference.OperandType.Name(self.cfg_type))

    def __eq__(self, other):
        if not isinstance(other, XRef):
            return NotImplemented
        return self.addr == other.addr and \
               self.type == other.type

    def __hash__(self):
        return hash((self.addr, self.type))


def get_xrefs(bv, il, reftype=XRef.IMMEDIATE, parent=None):
    """ Recursively gather xrefs in an IL instruction

    Args:
        bv (binja.BinaryView)
        il (binja.LowLevelILInstruction)
        reftype (int)
        parent (binja.LowLevelILInstruction)

    Returns:
        set[XRef]
    """
    if not isinstance(il, binja.LowLevelILInstruction):
        return set()

    refs = set()

    # Update reftype using il information
    op = il.operation

    # Detect a tail call target
    # This is the only instance where a LLIL_JUMP is considered
    if util.is_jump_tail_call(bv, il):
        log.debug('Tail call detected @ 0x%x', il.address)
        return get_xrefs(bv, il.dest, XRef.CONTROLFLOW, il)

    # Some instruction types are ignored
    elif op in [LowLevelILOperation.LLIL_JUMP,
              LowLevelILOperation.LLIL_JUMP_TO,
              LowLevelILOperation.LLIL_UNIMPL,
              LowLevelILOperation.LLIL_UNIMPL_MEM]:
        return set()

    elif op == LowLevelILOperation.LLIL_CALL:
        # Any xref in here will be a control flow target
        reftype = XRef.CONTROLFLOW

    elif op in [LowLevelILOperation.LLIL_LOAD,
                LowLevelILOperation.LLIL_STORE]:

        # Choose the correct operand to look at
        mem_il = il.src if op == LowLevelILOperation.LLIL_LOAD else il.dest

        # Loading from memory
        # Check if we're using a displacement in this
        if mem_il.operation in [LowLevelILOperation.LLIL_CONST,
                                LowLevelILOperation.LLIL_CONST_PTR]:
            # No displacement
            reftype = XRef.MEMORY
        else:
            reftype = XRef.DISPLACEMENT

        # In a load/store, only the operand that references memory gets the new reftype
        # The other operand(s) start at the default (immediate) again
        refs.update(get_xrefs(bv, mem_il, reftype, il))
        for oper in il.operands:
            if oper != mem_il:
                refs.update(get_xrefs(bv, oper))
        return refs

    elif op in [LowLevelILOperation.LLIL_CONST,
                LowLevelILOperation.LLIL_CONST_PTR]:
        # Hit a value, if this is a reference we can save the xref
        if util.is_valid_addr(bv, il.constant):
            # A displacement might be incorrectly classified as an immediate at this point
            if reftype == XRef.IMMEDIATE and parent is not None:
                # There's some other expression including this value
                # look at the disassembly to figure out if this is actually a displacement
                dis = bv.get_disassembly(il.address)
                if '[' in dis and ']' in dis:
                    # Fix the reftype depending on how this value is used
                    reftype = XRef.MEMORY if parent.operation == LowLevelILOperation.LLIL_SET_REG else \
                              XRef.DISPLACEMENT

            refs.add(XRef(il.constant, reftype))

    # Continue searching operands for xrefs
    for oper in il.operands:
        refs.update(get_xrefs(bv, oper, reftype, il))

    return refs
