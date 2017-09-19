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


def get_xrefs(bv, il, reftype=XRef.IMMEDIATE):
    """ Recursively gather xrefs in an IL instruction

    Args:
        bv (binja.BinaryView)
        il (binja.LowLevelILInstruction)
        reftype

    Returns:
        list[XRef]
    """
    if not isinstance(il, binja.LowLevelILInstruction):
        return []

    refs = []

    # Update reftype using il information
    op = il.operation
    if op == LowLevelILOperation.LLIL_CALL:
        # Any xref in here will be a control flow target
        reftype = XRef.CONTROLFLOW

    elif op == LowLevelILOperation.LLIL_LOAD:
        # Loading from memory
        # Check if we're using a displacement in this
        if il.src.operation in [LowLevelILOperation.LLIL_CONST,
                                LowLevelILOperation.LLIL_CONST_PTR,
                                LowLevelILOperation.LLIL_REG]:
            # No displacement
            reftype = XRef.MEMORY
        else:
            reftype = XRef.DISPLACEMENT

    elif op in [LowLevelILOperation.LLIL_CONST,
                LowLevelILOperation.LLIL_CONST_PTR]:
        # Hit a value, if this is a reference we can save the xref
        if util.is_valid_addr(bv, il.constant):
            refs.append(XRef(il.constant, reftype))

    # Continue searching operands for xrefs
    for oper in il.operands:
        refs.extend(get_xrefs(bv, oper, reftype))

    return refs
