import argparse
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
JMP_TABLES = []

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

RECOVER_OPTS = {
  'stack_vars': False
}

_DEBUG_PREFIX = ""

def DEBUG_PUSH():
  global _DEBUG_PREFIX
  _DEBUG_PREFIX += "  "

def DEBUG_POP():
  global _DEBUG_PREFIX
  _DEBUG_PREFIX = _DEBUG_PREFIX[:-2]

def DEBUG(s):
  log.debug("{}{}".format(_DEBUG_PREFIX, str(s)))

def WARN(s):
  log.warn("{}{}".format(_DEBUG_PREFIX, str(s)))

def ERROR(s):
  log.error("{}{}".format(_DEBUG_PREFIX, str(s)))

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
  DEBUG("Recovering external function {} at {:x}".format(sym.name, sym.address))
  if sym.name in EXT_MAP:
    DEBUG('Found defined external function: {} @ {:x}'.format(sym.name, sym.address))

    args, cconv, ret, sign = EXT_MAP[sym.name]
    func = bv.get_function_at(sym.address)
    if func is None:
      return

    pb_extfn = pb_mod.external_funcs.add()
    pb_extfn.name = sym.name
    pb_extfn.ea = sym.address
    pb_extfn.argument_count = args
    pb_extfn.cc = cconv
    pb_extfn.has_return = func_has_return_type(func)
    pb_extfn.no_return = ret == 'Y'
    pb_extfn.is_weak = False  # TODO: figure out how to decide this

  else:
    WARN("External function is not part of defs file")

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
    DEBUG("Recovering external variable {} at {:x}".format(sym.name, sym.address))

    pb_extvar = pb_mod.external_vars.add()
    pb_extvar.name = sym.name
    pb_extvar.ea = sym.address
    pb_extvar.size = EXT_DATA_MAP[sym.name]
    pb_extvar.is_weak = False  # TODO: figure out how to decide this
    pb_extvar.is_thread_local = util.is_tls_section(bv, sym.address)
  else:
    ERROR("Unknown external variable {} at {:x}".format(sym.name, sym.address))


def recover_externals(bv, pb_mod):
  """Recover info about all external symbols"""
  DEBUG("Recovering externals")
  DEBUG_PUSH()
  for sym in bv.get_symbols():
    if sym.type == SymbolType.ImportedFunctionSymbol:
      recover_ext_func(bv, pb_mod, sym)

    if sym.type == SymbolType.ImportedDataSymbol:
      recover_ext_var(bv, pb_mod, sym)
  DEBUG_POP()

_BYTE_WIDTH_NAME = {4: "dword", 8: "qword"}

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

  DEBUG("Recovering references in [{:x}, {:x}) of section {}".format(
      sect_start, sect_end, real_sect.name))

  DEBUG_PUSH()
  for addr in xrange(sect_start, sect_end, entry_width):
    xref = read_val(bv, addr)

    if not util.is_valid_addr(bv, xref):
      continue

    # Skip this xref if it's a jmp table entry
    if any(xref in tbl.targets for tbl in JMP_TABLES):
      continue

    width_name = _BYTE_WIDTH_NAME.get(entry_width, "{}-byte".format(entry_width))
    DEBUG("Adding {} reference from {:x} to {:x}".format(width_name, addr, xref))

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

  DEBUG_POP()


def recover_section_vars(bv, pb_seg, sect_start, sect_end):
  """ Gather any symbols that point to data in this section

  Args:x
    bv (binja.BinaryView)
    pb_seg (CFG_pb2.Segment)
    sect_start (int)
    sect_end (int)
  """

  DEBUG("Recovering variables in [{:x}, {:x}) of section {}".format(
      sect_start, sect_end, pb_seg.name))
  DEBUG_PUSH()
  for sym in bv.get_symbols():
    # Ignore functions and externals
    if sym.type in [SymbolType.FunctionSymbol,
            SymbolType.ImportedFunctionSymbol,
            SymbolType.ImportedDataSymbol,
            SymbolType.ImportAddressSymbol]:
      continue

    if sect_start <= sym.address < sect_end:
      DEBUG("Adding variable {} at {:x}".format(sym.name, sym.address))
      pb_segvar = pb_seg.vars.add()
      pb_segvar.ea = sym.address
      pb_segvar.name = sym.name

  DEBUG_POP()

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

    DEBUG("Recovering [{:x}, {:x}) from segment {}".format(
        start_addr, end_addr, real_sect.name))

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


_CFG_INST_XREF_TYPE_TO_NAME = {
    CFG_pb2.CodeReference.ImmediateOperand: "imm",
    CFG_pb2.CodeReference.MemoryOperand: "mem",
    CFG_pb2.CodeReference.MemoryDisplacementOperand: "disp",
    CFG_pb2.CodeReference.ControlFlowOperand: "flow"
}


def add_xref(bv, pb_inst, target, optype):
  xref = pb_inst.xrefs.add()
  xref.ea = target
  xref.operand_type = optype

  sym_name = util.find_symbol_name(bv, target)
  if len(sym_name) > 0:
    xref.name = sym_name

  if util.is_code(bv, target):
    xref.target_type = CFG_pb2.CodeReference.CodeTarget
    debug_type = "code"
  else:
    xref.target_type = CFG_pb2.CodeReference.DataTarget
    debug_type = "data"

  if util.is_external_ref(bv, target):
    xref.location = CFG_pb2.CodeReference.External
    debug_loc = "external"
  else:
    xref.location = CFG_pb2.CodeReference.Internal
    debug_loc = "internal"

  # If the target happens to be a function, queue it for recovery
  if bv.get_function_at(target) is not None:
    queue_func(target)

  debug_op = _CFG_INST_XREF_TYPE_TO_NAME[optype]

  return "({} {} {} {:x} {})".format(debug_type, debug_op, debug_loc, target, sym_name)

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
  debug_refs = []
  for ref in xrefs.get_xrefs(bv, il):
    debug_refs.append(add_xref(bv, pb_inst, ref.addr, ref.cfg_type))

  if is_local_noreturn(bv, il):
    pb_inst.local_noreturn = True

  table = jmptable.get_jmptable(bv, il)
  if table is not None:
    debug_refs.append(add_xref(bv, pb_inst, table.base_addr, CFG_pb2.CodeReference.MemoryDisplacementOperand))
    JMP_TABLES.append(table)

    # Add any missing successors
    for tgt in table.targets:
      if tgt not in pb_block.successor_eas:
        pb_block.successor_eas.append(tgt)

  DEBUG("I: {:x} {}".format(il.address, " ".join(debug_refs)))


def add_block(pb_func, block):
  """
  Args:
    pb_func (CFG_pb2.Function)
    block (binaryninja.basicblock.BasicBlock)

  Returns:
    CFG_pb2.Block
  """
  DEBUG("BB: {:x}".format(block.start))
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
  DEBUG("Recovering function {} at {:x}".format(func.symbol.name, addr))

  pb_func = pb_mod.funcs.add()
  pb_func.ea = addr
  pb_func.is_entrypoint = is_entry
  pb_func.name = func.symbol.name

  # Recover all basic blocks
  var_refs = defaultdict(list)
  for block in func:
    DEBUG_PUSH()
    pb_block = add_block(pb_func, block)
    DEBUG_PUSH()
    # Recover every instruction in the block
    for inst in block.disassembly_text:
      # Skip over anything that isn't an instruction
      if inst.tokens[0].type != InstructionTextTokenType.InstructionToken:
        continue
      il = func.get_lifted_il_at(inst.address)

      pb_inst = pb_block.instructions.add()
      recover_inst(bv, pb_block, pb_inst, il)

      # Find any references to stack vars in this instruction
      if RECOVER_OPTS['stack_vars']:
        vars.find_stack_var_refs(bv, inst, il, var_refs)
    DEBUG_POP()
    DEBUG_POP()

  # Recover stack variables
  if RECOVER_OPTS['stack_vars']:
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


def get_cfg(args, fixed_args):
  # Parse any additional args
  parser = argparse.ArgumentParser()

  parser.add_argument(
      '--recover-stack-vars',
      help='Flag to enable stack variable recovery',
      default=False,
      action='store_true')

  extra_args = parser.parse_args(fixed_args)

  if extra_args.recover_stack_vars:
    RECOVER_OPTS['stack_vars'] = True

  # Setup logger
  util.init_logger(args.log_file)

  # Load the binary in binja
  bv = util.load_binary(args.binary)

  # Once for good measure.
  bv.add_analysis_option("linearsweep")
  bv.update_analysis_and_wait()

  # Twice for good luck!
  bv.add_analysis_option("linearsweep")
  bv.update_analysis_and_wait()

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
