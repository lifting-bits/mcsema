import binaryninja as binja
from binaryninja.enums import (
    SymbolType, TypeClass, CallingConventionName
)
import logging
import os

import CFG_pb2
import util

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


def func_has_return_type(func):
    rtype = func.function_type.return_value.type_class
    return rtype != TypeClass.VoidTypeClass


def recover_ext_func(bv, pb_mod, sym):
    """ Recover external function information
    Uses the map of predefined externals if possible

    Args:
        bv (binja.BinaryView)
        pb_seg (CFG_pb2.Module)
        sym (binja.types.Symbol)
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

        # TODO: binja only returns None for calling conventions?
        pb_extfn.cc = CFG_pb2.ExternalFunction.CallerCleanup


def recover_ext_var(bv, pb_mod, sym):
    """ Recover external variable information

    Args:
        bv (binja.BinaryView)
        pb_seg (CFG_pb2.Module)
        sym (binja.types.Symbol)
    """
    if sym.name in EXT_DATA_MAP:
        log.debug('Found defined external var: %s', sym.name)

        pb_extvar = pb_mod.external_vars.add()
        pb_extvar.name = sym.name
        pb_extvar.ea = sym.address
        pb_extvar.size = EXT_DATA_MAP[sym.name]
        pb_extvar.is_weak = False  # TODO: figure out how to decide this
    else:
        log.error('Unknown external var: %s', sym.name)


def recover_externals(bv, pb_mod):
    """Recover info about all external symbols"""
    for sym in bv.get_symbols():
        if sym.type == SymbolType.ImportedFunctionSymbol:
            recover_ext_func(bv, pb_mod, sym)

        if sym.type == SymbolType.ImportedDataSymbol:
            recover_ext_var(bv, pb_mod, sym)


def recover_section_cross_references(bv, pb_seg, sect):
    """Find references to other code/data in this section

    Args:
        bv (binja.BinaryView)
        pb_seg (CFG_pb2.Segment)
        sect (binja.binaryview.Section)
    """
    entry_width = util.clamp(sect.align, 4, bv.address_size)
    read_val = {4: util.read_dword,
                8: util.read_qword}[entry_width]
    for addr in xrange(sect.start, sect.end, entry_width):
        xref = read_val(bv, addr)

        # TODO: probably need a better way of telling this is a ref
        seg = bv.get_segment_at(xref)
        if seg is None:
            continue

        pb_ref = pb_seg.xrefs.add()
        pb_ref.ea = addr
        pb_ref.width = entry_width
        pb_ref.target_ea = xref
        pb_ref.target_name = util.find_symbol_name(bv, xref)
        pb_ref.target_is_code = util.is_code(bv, xref)


def recover_section_vars(bv, pb_seg, sect):
    """Gather any symbols that point to data in this section

    Args:
        bv (binja.BinaryView)
        pb_seg (CFG_pb2.Segment)
        sect (binja.binaryview.Section)
    """
    for sym in bv.get_symbols():
        if sect.start <= sym.address < sect.end:
            pb_segvar = pb_seg.vars.add()
            pb_segvar.ea = sym.address
            pb_segvar.name = sym.name


def recover_sections(bv, pb_mod):
    for sect in bv.sections.values():
        log.debug('Processing %s', sect.name)
        pb_seg = pb_mod.segments.add()
        pb_seg.name = sect.name
        pb_seg.ea = sect.start
        pb_seg.data = bv.read(sect.start, sect.length)
        pb_seg.is_external = util.is_section_external(bv, sect)
        pb_seg.read_only = not util.is_readable(bv, sect.start)

        recover_section_vars(bv, pb_seg, sect)
        recover_section_cross_references(bv, pb_seg, sect)


def recover_cfg(bv, args):
    pb_mod = CFG_pb2.Module()
    pb_mod.name = os.path.basename(bv.file.filename)

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
