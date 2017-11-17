import binaryninja as binja
from binaryninja.enums import (
    SymbolType, TypeClass,
    LowLevelILOperation, RegisterValueType,
    InstructionTextTokenType
)
import logging
import os
from Queue import Queue
from collections import defaultdict

import CFG_pb2
import util
import xrefs
import jmptable
import vars

log = logging.getLogger(util.LOGNAME)

BINJA_DIR = os.path.dirname(os.path.abspath(__file__))
DISASS_DIR = os.path.dirname(BINJA_DIR)

EXT_MAP = {}
EXT_DATA_MAP = {}

CCONV_TYPES = {
    'C': CFG_pb2.ExternalFunction.CallerCleanup,
    'E': CFG_pb2.ExternalFunction.CalleeCleanup,
    'F': CFG_pb2.ExternalFunction.FastCall
}

BINJA_CCONV_TYPES = {
    'cdecl': CFG_pb2.ExternalFunction.CallerCleanup,
    'stdcall': CFG_pb2.ExternalFunction.CalleeCleanup,
    'fastcall': CFG_pb2.ExternalFunction.FastCall
}

RECOVERED = set()
TO_RECOVER = Queue()


def queue_func(addr):
    if addr not in RECOVERED:
        TO_RECOVER.put(addr)


def func_has_return_type(func):
    rtype = func.function_type.return_value.type_class
    return rtype != TypeClass.VoidTypeClass


def recover_ext_func(bv, pb_mod, sym):
    """ Recover external function information
    Uses the map of predefined externals if possible

    Args:
        bv (binja.BinaryView)
        pb_mod (CFG_pb2.Module)
        sym (binaryninja.types.Symbol)
    """
    if sym.name in EXT_MAP:
        log.debug('Found defined external function: %s', sym.name)

        args, cconv, ret, sign = EXT_MAP[sym.name]
        func = bv.get_function_at(sym.address)

        pb_extfn = pb_mod.external_funcs.add()
        pb_extfn.name = sym.name
        pb_extfn.ea = sym.address
        pb_extfn.argument_count = args
        pb_extfn.cc = cconv
        pb_extfn.has_return = func_has_return_type(func)
        pb_extfn.no_return = ret == 'Y'
        pb_extfn.is_weak = False  # TODO: figure out how to decide this

    else:
        log.warn('Unknown external function: %s', sym.name)
        log.warn('Attempting to recover manually')

        func = bv.get_function_at(sym.address)
        ftype = func.function_type

        pb_extfn = pb_mod.external_funcs.add()
        pb_extfn.name = sym.name
        pb_extfn.ea = sym.address
        pb_extfn.argument_count = len(ftype.parameters)
        pb_extfn.has_return = func_has_return_type(func)
        pb_extfn.no_return = not ftype.can_return
        pb_extfn.is_weak = False  # TODO: figure out how to decide this

        # Assume cdecl if the type is unknown
        cconv = ftype.calling_convention
        if cconv is not None and cconv.name in BINJA_CCONV_TYPES:
            pb_extfn.cc = BINJA_CCONV_TYPES[cconv]
        else:
            pb_extfn.cc = CFG_pb2.ExternalFunction.CallerCleanup


def recover_ext_var(bv, pb_mod, sym):
    """ Recover external variable information

    Args:
        bv (binja.BinaryView)
        pb_mod (CFG_pb2.Module)
        sym (binja.types.Symbol)
    """
    if sym.name in EXT_DATA_MAP:
        log.debug('Found defined external var: %s', sym.name)

        pb_extvar = pb_mod.external_vars.add()
        pb_extvar.name = sym.name
        pb_extvar.ea = sym.address
        pb_extvar.size = EXT_DATA_MAP[sym.name]
        pb_extvar.is_weak = False  # TODO: figure out how to decide this
        pb_extvar.is_thread_local = util.is_tls_section(bv, sym.address)
    else:
        log.error('Unknown external var: %s', sym.name)


def recover_externals(bv, pb_mod):
    """Recover info about all external symbols"""
    for sym in bv.get_symbols():
        if sym.type == SymbolType.ImportedFunctionSymbol:
            recover_ext_func(bv, pb_mod, sym)

        if sym.type == SymbolType.ImportedDataSymbol:
            recover_ext_var(bv, pb_mod, sym)


def recover_section_cross_references(bv, pb_seg, real_sect, sect_start, sect_end):
    """ Find references to other code/data in this section

    Args:
        bv (binja.BinaryView)
        pb_seg (CFG_pb2.Segment)
        real_sect (binja.binaryview.Section)
        sect_start (int)
        sect_end (int)
    """
    entry_width = util.clamp(real_sect.align, 4, bv.address_size)
    read_val = {4: util.read_dword,
                8: util.read_qword}[entry_width]
    for addr in xrange(sect_start, sect_end, entry_width):
        xref = read_val(bv, addr)

        if not util.is_valid_addr(bv, xref):
            continue

        pb_ref = pb_seg.xrefs.add()
        pb_ref.ea = addr
        pb_ref.width = entry_width
        pb_ref.target_ea = xref
        pb_ref.target_name = util.find_symbol_name(bv, xref)
        pb_ref.target_is_code = util.is_code(bv, xref)

        if util.is_tls_section(bv, addr):
            pb_ref.target_fixup_kind = CFG_pb2.DataReference.OffsetFromThreadBase
        else:
            pb_ref.target_fixup_kind = CFG_pb2.DataReference.Absolute


def recover_section_vars(bv, pb_seg, sect_start, sect_end):
    """ Gather any symbols that point to data in this section

    Args:x
        bv (binja.BinaryView)
        pb_seg (CFG_pb2.Segment)
        sect_start (int)
        sect_end (int)
    """
    for sym in bv.get_symbols():
        # Ignore functions and externals
        if sym.type in [SymbolType.FunctionSymbol,
                        SymbolType.ImportedFunctionSymbol,
                        SymbolType.ImportedDataSymbol,
                        SymbolType.ImportAddressSymbol]:
            continue

        if sect_start <= sym.address < sect_end:
            pb_segvar = pb_seg.vars.add()
            pb_segvar.ea = sym.address
            pb_segvar.name = sym.name


def recover_sections(bv, pb_mod):
    # Collect all address to split on
    sec_addrs = set()
    for sect in bv.sections.values():
        sec_addrs.add(sect.start)
        sec_addrs.add(sect.end)

    global_starts = [gvar.ea for gvar in pb_mod.global_vars]
    sec_addrs.update(global_starts)

    # Process all the split segments
    sec_splits = sorted(list(sec_addrs))
    for start_addr, end_addr in zip(sec_splits[:-1], sec_splits[1:]):
        real_sect = util.get_section_at(bv, start_addr)

        # Ignore any gaps
        if real_sect is None:
            continue

        log.debug('Processing %s from 0x%x to 0x%x', real_sect.name, start_addr, end_addr)
        pb_seg = pb_mod.segments.add()
        pb_seg.name = real_sect.name
        pb_seg.ea = start_addr
        pb_seg.data = bv.read(start_addr, end_addr - start_addr)
        pb_seg.is_external = util.is_section_external(bv, real_sect)
        pb_seg.read_only = not util.is_readable(bv, start_addr)
        pb_seg.is_thread_local = util.is_tls_section(bv, start_addr)

        sym = bv.get_symbol_at(start_addr)
        pb_seg.is_exported = sym is not None and start_addr in global_starts
        if pb_seg.is_exported and sym.name != real_sect.name:
            pb_seg.variable_name = sym.name

        recover_section_vars(bv, pb_seg, start_addr, end_addr)
        recover_section_cross_references(bv, pb_seg, real_sect, start_addr, end_addr)


def is_local_noreturn(bv, il):
    """
    Args:
        bv (binja.BinaryView)
        il (binja.LowLevelILInstruction):

    Returns:
        bool
    """
    if il.operation in [LowLevelILOperation.LLIL_CALL,
                        LowLevelILOperation.LLIL_JUMP,
                        LowLevelILOperation.LLIL_GOTO]:
        # Resolve the destination address
        tgt_addr = None
        dst = il.dest

        # GOTOs have an il index as the arg
        if isinstance(dst, int):
            tgt_addr = il.function[dst].address

        # Others will have an expression as the argument
        elif isinstance(dst, binja.LowLevelILInstruction):
            # Immediate address
            if dst.operation in [LowLevelILOperation.LLIL_CONST,
                                 LowLevelILOperation.LLIL_CONST_PTR]:
                tgt_addr = dst.constant

            # Register
            elif dst.operation == LowLevelILOperation.LLIL_REG:
                # Attempt to resolve the register value
                func = il.function.source_function
                reg_val = func.get_reg_value_at(il.address, dst.src)
                if reg_val.type == RegisterValueType.ConstantValue:
                    tgt_addr = reg_val.value

        # If a target address was recovered, check if it's in a noreturn function
        if tgt_addr is not None:
            tgt_func = util.get_func_containing(bv, tgt_addr)
            return not tgt_func.function_type.can_return

    # Other instructions that terminate control flow
    return il.operation in [LowLevelILOperation.LLIL_TRAP,
                            LowLevelILOperation.LLIL_BP]


def add_xref(bv, pb_inst, target, optype):
    xref = pb_inst.xrefs.add()
    xref.ea = target
    xref.operand_type = optype

    sym_name = util.find_symbol_name(bv, target)
    if len(sym_name) > 0:
        xref.name = sym_name

    xref.target_type = CFG_pb2.CodeReference.CodeTarget if util.is_code(bv, target) else \
                       CFG_pb2.CodeReference.DataTarget

    xref.location = CFG_pb2.CodeReference.External if util.is_external_ref(bv, target) else \
                    CFG_pb2.CodeReference.Internal

    # If the target happens to be a function, queue it for recovery
    if bv.get_function_at(target) is not None:
        queue_func(target)


def read_inst_bytes(bv, il):
    """ Get the opcode bytes for an instruction
    Args:
        bv (binja.BinaryView)
        il (binja.LowLevelILInstruction)
    Returns:
        str
    """
    inst_len = bv.get_instruction_length(il.address)
    return bv.read(il.address, inst_len)


def recover_inst(bv, pb_block, pb_inst, il):
    """
    Args:
        bv (binja.BinaryView)
        pb_inst (CFG_pb2.Instruction)
        il (binaryninja.lowlevelil.LowLevelILInstruction)
    """
    pb_inst.ea = il.address
    pb_inst.bytes = read_inst_bytes(bv, il)
    for ref in xrefs.get_xrefs(bv, il):
        add_xref(bv, pb_inst, ref.addr, ref.cfg_type)

    if is_local_noreturn(bv, il):
        pb_inst.local_noreturn = True

    table = jmptable.get_jmptable(bv, il)
    if table is not None:
        add_xref(bv, pb_inst, table.base_addr, CFG_pb2.CodeReference.OffsetTable)

        # Add any missing successors
        for tgt in table.targets:
            if tgt not in pb_block.successor_eas:
                pb_block.successor_eas.append(tgt)


def add_block(pb_func, block):
    """
    Args:
        pb_func (CFG_pb2.Function)
        block (binaryninja.basicblock.BasicBlock)

    Returns:
        CFG_pb2.Block
    """
    pb_block = pb_func.blocks.add()
    pb_block.ea = block.start
    pb_block.successor_eas.extend(edge.target.start for edge in block.outgoing_edges)
    return pb_block


def recover_function(bv, pb_mod, addr, is_entry=False):
    func = bv.get_function_at(addr)
    if func is None:
        log.error('No function defined at 0x%x, skipping', addr)
        return

    if func.symbol.type == SymbolType.ImportedFunctionSymbol:
        # Externals are recovered later, skip this
        log.warn("Skipping external function '%s' in main CFG recovery", func.symbol.name)
        return

    # Initialize the protobuf for this function
    log.debug("Recovering function @ 0x%x", addr)
    pb_func = pb_mod.funcs.add()
    pb_func.ea = addr
    pb_func.is_entrypoint = is_entry
    pb_func.name = func.symbol.name

    # Recover all basic blocks
    var_refs = defaultdict(list)
    for block in func:
        pb_block = add_block(pb_func, block)

        # Recover every instruction in the block
        for inst in block.disassembly_text:
            # Skip over anything that isn't an instruction
            if inst.tokens[0].type != InstructionTextTokenType.InstructionToken:
                continue
            il = func.get_lifted_il_at(inst.address)

            pb_inst = pb_block.instructions.add()
            recover_inst(bv, pb_block, pb_inst, il)
            vars.find_stack_var_refs(bv, inst, il, var_refs)

    # Recover stack variables
    vars.recover_stack_vars(pb_func, func, var_refs)


def recover_cfg(bv, args):
    pb_mod = CFG_pb2.Module()
    pb_mod.name = os.path.basename(bv.file.filename)

    # Find the chosen entrypoint in the binary
    if args.entrypoint not in bv.symbols:
        log.fatal('Entrypoint not found: %s', args.entrypoint)
    entry_addr = bv.symbols[args.entrypoint].address

    # Recover the entrypoint func separately
    log.debug('Recovering CFG')
    recover_function(bv, pb_mod, entry_addr, is_entry=True)

    # Recover any discovered functions until there are none left
    while not TO_RECOVER.empty():
        addr = TO_RECOVER.get()

        if addr in RECOVERED:
            continue
        RECOVERED.add(addr)

        recover_function(bv, pb_mod, addr)

    log.debug('Recovering Globals')
    vars.recover_globals(bv, pb_mod)

    log.debug('Processing Segments')
    recover_sections(bv, pb_mod)

    log.debug('Recovering Externals')
    recover_externals(bv, pb_mod)

    return pb_mod


def parse_defs_file(bv, path):
    log.debug('Parsing %s', path)
    with open(path) as f:
        for line in f.readlines():
            # Skip comments/empty lines
            if len(line.strip()) == 0 or line[0] == '#':
                continue

            if line.startswith('DATA:'):
                # DATA: (name) (PTR | size)
                _, dname, dsize = line.split()
                if 'PTR' in dsize:
                    dsize = bv.address_size
                EXT_DATA_MAP[dname] = int(dsize)
            else:
                # (name) (# args) (cconv) (ret) [(sign) | None]
                fname, args, cconv, ret, sign = (line.split() + [None])[:5]

                if cconv not in CCONV_TYPES:
                    log.fatal('Unknown calling convention: %s', cconv)
                    exit(1)

                if ret not in ['Y', 'N']:
                    log.fatal('Unknown return type: %s', ret)
                    exit(1)

                EXT_MAP[fname] = (int(args), CCONV_TYPES[cconv], ret, sign)


def get_cfg(args):
    # Setup logger
    util.init_logger(args.log_file)

    # Load the binary in binja
    bv = util.load_binary(args.binary)

    # Collect all paths to defs files
    log.debug('Parsing definitions files')
    def_paths = set(map(os.path.abspath, args.std_defs))
    def_paths.add(os.path.join(DISASS_DIR, 'defs', '{}.txt'.format(args.os)))  # default defs file

    # Parse all of the defs files
    for fpath in def_paths:
        if os.path.isfile(fpath):
            parse_defs_file(bv, fpath)
        else:
            log.warn('%s is not a file', fpath)

    # Recover module
    log.debug('Starting analysis')
    pb_mod = recover_cfg(bv, args)

    # Save cfg
    log.debug('Saving to file: %s', args.output)
    with open(args.output, 'wb') as f:
        f.write(pb_mod.SerializeToString())

    return 0
