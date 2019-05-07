# Copyright (c) 2019 Trail of Bits, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import binaryninja as binja
from binaryninja.enums import (
  Endianness, LowLevelILOperation, SectionSemantics, RegisterValueType, SymbolType
)
from collections import defaultdict
import struct
import magic
import log
import re
import os

from cfg import EXT_MAP, EXT_DATA_MAP
import functions
import CFG_pb2
import xrefs
import vars

BINJA_DIR = os.path.dirname(os.path.abspath(__file__))
DISASS_DIR = os.path.dirname(BINJA_DIR)

ENDIAN_TO_STRUCT = {
  Endianness.LittleEndian: '<',
  Endianness.BigEndian: '>'
}

# Caching results of is_section_external
_EXT_SECTIONS = set()
_INT_SECTIONS = set()

CCONV_TYPES = {
  'C': CFG_pb2.ExternalFunction.CallerCleanup,
  'E': CFG_pb2.ExternalFunction.CalleeCleanup,
  'F': CFG_pb2.ExternalFunction.FastCall
}


######## Binary Stuff ########

def read_dword(bv, addr):
  # type: (binja.BinaryView, int) -> int
  # Pad the data if fewer than 4 bytes are read
  endianness = ENDIAN_TO_STRUCT[bv.endianness]
  data = bv.read(addr, 4)
  padded_data = '{{:\x00{}4s}}'.format(endianness).format(data)
  fmt = '{}L'.format(endianness)
  return struct.unpack(fmt, padded_data)[0]


def read_qword(bv, addr):
  # type: (binja.BinaryView, int) -> int
  # Pad the data if fewer than 8 bytes are read
  endianness = ENDIAN_TO_STRUCT[bv.endianness]
  data = bv.read(addr, 8)
  padded_data = '{{:\x00{}8s}}'.format(endianness).format(data)
  fmt = '{}Q'.format(endianness)
  return struct.unpack(fmt, padded_data)[0]


def load_binary(path):
  magic_type = magic.from_file(path)
  if 'ELF' in magic_type:
    bv_type = binja.BinaryViewType['ELF']
  elif 'PE32' in magic_type:
    bv_type = binja.BinaryViewType['PE']
  elif 'Mach-O' in magic_type:
    bv_type = binja.BinaryViewType['Mach-O']
  else:
    bv_type = binja.BinaryViewType['Raw']

    # Can't do anything with Raw type
    log.fatal('Unknown binary type: "{}", exiting'.format(magic_type))
    exit(1)

  bv = bv_type.open(path)
  log.debug('BinaryNinja analysing binary...')
  bv.update_analysis_and_wait()
  log.debug('Binary analysed')

  # NOTE: at the moment binja will not load a binary
  # that doesn't have an entry point
  if len(bv) == 0:
    log.error('Binary could not be loaded in binja, is it linked?')
    exit(1)

  return bv


######## Searching Functions ########

def find_symbol_name(bv, addr):
  """Attempt to find a symbol for a given address

  Args:
    bv (binja.BinaryView)
    addr (int): Address the symbol should point to

  Returns:
    (str): Symbol name if found, empty string otherwise

  """
  sym = bv.get_symbol_at(addr)
  if sym is not None:
    return sym.name
  return ''


def get_func_containing(bv, addr):
  """ Finds the function, if any, containing the given address
  Args:
    bv (binja.BinaryView)
    addr (int)

  Returns:
    binja.Function
  """
  funcs = bv.get_functions_containing(addr)
  return funcs[0] if funcs is not None else None


def get_section_at(bv, addr):
  """Returns the section in the binary that contains the given address"""
  if not is_valid_addr(bv, addr):
    return None

  for sec in bv.sections.values():
    if sec.start <= addr < sec.end:
      return sec
  return None


def _search_phrase_op(il, target_op):
  """ Helper for finding parts of a phrase[+displacement] il """
  op = il.operation

  # Handle starting points
  if op == LowLevelILOperation.LLIL_SET_REG:
    return _search_phrase_op(il.src, target_op)

  if op == LowLevelILOperation.LLIL_STORE:
    return _search_phrase_op(il.dest, target_op)

  # The phrase il may be inside a LLIL_LOAD
  if op == LowLevelILOperation.LLIL_LOAD:
    return _search_phrase_op(il.src, target_op)

  # Continue left/right at an ADD
  if op == LowLevelILOperation.LLIL_ADD:
    return (_search_phrase_op(il.left, target_op) or
            _search_phrase_op(il.right, target_op))

  # Continue left/right at an ADD
  if op == LowLevelILOperation.LLIL_SUB:
    return (_search_phrase_op(il.left, target_op) or
            _search_phrase_op(il.right, target_op))

    # Continue left/right at an ADD
  if op == LowLevelILOperation.LLIL_CMP_E:
    return (_search_phrase_op(il.left, target_op) or
            _search_phrase_op(il.right, target_op))

  # Terminate when constant is found
  if op == target_op:
    return il


def search_phrase_reg(il):
  """ Searches for the register used in a phrase
  ex: dword [ebp + 0x8] -> ebp

  Args:
    il (binja.LowLevelILInstruction): Instruction to parse

  Returns:
    str: register name
  """
  res = _search_phrase_op(il, LowLevelILOperation.LLIL_REG)
  if res is not None:
    return res.src.name


def search_displacement_base(il):
  """ Searches for the base address used in a phrase[+displacement]
  ex: dword [eax * 4 + 0x08040000] -> 0x08040000
    dword [ebp + 0x8] -> 0x8

  Args:
    il (binja.LowLevelILInstruction): Instruction to parse

  Returns:
    int: base address
  """
  res = _search_phrase_op(il, LowLevelILOperation.LLIL_CONST)
  if res is not None:
    # Interpret the string representation to avoid sign issues
    return int(res.tokens[0].text, 16)


def get_jump_tail_call_target(bv, il):
  """ Get the target function of a tail-call.

  Returns:
    binja.Function
  """

  il = il[0]
  bb = get_basic_block(bv, il)

  try:
    return bv.get_function_at(bb.function.get_low_level_il_at(il.address).dest.constant)
  except AttributeError:
    return None


def get_basic_block(bv, il):
  # Should work eventually, currently a bug in binja
  # bb = il.il_basic_block

  bb = bv.get_basic_blocks_at(il.address)

  if len(bb) > 1:
    for b in bb:
      if b.arch == il.function.arch:
        bb = b
  else:
    bb = bb[0]

  return bb


def get_il_basic_block(il):
  for bb in il.function:
    if bb.start <= il.instr_index and il.instr_index < bb.end:
      return bb
  return None


def get_targets(il):
  try:
    return [e.to_value for e in il.dest.possible_values.table]
  except:
    """ If there is no targets, it's not a form of jump """
    return None


# Recover all LLIL for a single instruction (for `rep movsb` and similar)
def get_all_lifted_il(bv, il, all_il=[]):
  func = il.function
  index = il.instr_index

  while func[index].address == il.address:
    llil = func[index]
    if index not in all_il:
      all_il.append(index)

    if llil.operation is binja.LowLevelILOperation.LLIL_IF:
      inst = func[llil.operands[1]]
      if inst.address == il.address and inst.instr_index not in all_il:
        get_all_lifted_il(bv, inst, all_il)

      inst = func[llil.operands[2]]
      if inst.address == il.address and inst.instr_index not in all_il:
        get_all_lifted_il(bv, inst, all_il)

    elif llil.operation is binja.LowLevelILOperation.LLIL_GOTO:
      inst = func[llil.dest]
      if inst.address == il.address and inst.instr_index not in all_il:
        get_all_lifted_il(bv, inst, all_il)

    if index + 1 < get_il_basic_block(llil).end:
      index += 1
    else:
      break

    try:
      func[index]
    except IndexError:
      break

  return [func[i] for i in all_il]


######## Boolean Getters ########

def is_ELF(bv):
  return bv.view_type == 'ELF'


def is_PE(bv):
  return bv.view_type == 'PE'


def is_valid_addr(bv, addr):
  return bv.get_segment_at(addr) is not None


def is_external_ref(bv, addr):
  sym = bv.get_symbol_at(addr)
  return sym is not None and 'Import' in sym.type.name


def is_code(bv, addr):
  """Returns `True` if the given address lies in a code section"""
  # This is a bit more specific than checking if a segment is executable,
  # Binja will classify a section as ReadOnlyCode or ReadOnlyData, though
  # both sections are still in an executable segment
  sec = get_section_at(bv, addr)
  return sec is not None and sec.semantics == SectionSemantics.ReadOnlyCodeSectionSemantics


def is_executable(bv, addr):
  """Returns `True` if the given address lies in an executable segment"""
  seg = bv.get_segment_at(addr)
  return seg is not None and seg.executable


def is_readable(bv, addr):
  """Returns `True` if the given address lies in a readable segment"""
  seg = bv.get_segment_at(addr)
  return seg is not None and seg.writable


def is_writeable(bv, addr):
  """Returns `True` if the given address lies in a writable segment"""
  seg = bv.get_segment_at(addr)
  return seg is not None and seg.readable


def is_tls_section(bv, addr):
  sect_names = (sect.name for sect in bv.get_sections_at(addr))
  return any(sect in ['.tbss', '.tdata', '.tls'] for sect in sect_names)


def is_jump_tail_call(bv, all_il):
  """ Returns `True` if the given il is a jump to another function """
  il = all_il[0]
  bb = get_basic_block(bv, il)

  if bb.function.get_low_level_il_at(il.address).operation is binja.LowLevelILOperation.LLIL_TAILCALL:
    return True
  return False


def xref_in_all_il(all_il):
  for il in all_il:
    if xref_in_il(il):
      return True
  return False


def xref_in_il(il):
  for token in il.tokens:
    if token.type in [binja.InstructionTextTokenType.PossibleAddressToken,
                      binja.InstructionTextTokenType.IndirectImportToken,
                      binja.InstructionTextTokenType.ImportToken,
                      binja.InstructionTextTokenType.FieldNameToken,
                      binja.InstructionTextTokenType.ExternalSymbolToken,
                      binja.InstructionTextTokenType.DataSymbolToken,
                      binja.InstructionTextTokenType.CodeSymbolToken,
                      binja.InstructionTextTokenType.CodeRelativeAddressToken]:
      return True
  return False


def is_section_external(bv, sect):
  """Returns `True` if the given section contains only external references

  Args:
    bv (binja.BinaryView)
    sect (binja.binaryview.Section)
  """
  if sect.start in _EXT_SECTIONS:
    return True

  if sect.start in _INT_SECTIONS:
    return False

  if is_ELF(bv):
    if re.search(r'\.(got|plt)', sect.name):
      _EXT_SECTIONS.add(sect.start)
      return True

  if is_PE(bv):
    if '.idata' in sect.name:
      _EXT_SECTIONS.add(sect.start)
      return True

  _INT_SECTIONS.add(sect.start)
  return False


def is_end_of_block(address, bb):
  return address+bb.view.get_instruction_length(address) == bb.end


######## Other Helper Functions ########

def clamp(val, vmin, vmax):
  return min(vmax, max(vmin, val))


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
    real_sect = get_section_at(bv, start_addr)

    # Ignore any gaps
    if real_sect is None:
      continue

    log.debug("Recovering [{:x}, {:x}) from segment {}".format(
        start_addr, end_addr, real_sect.name))

    pb_seg = pb_mod.segments.add()
    pb_seg.name = real_sect.name
    pb_seg.ea = start_addr
    pb_seg.data = bv.read(start_addr, end_addr - start_addr)
    pb_seg.is_external = is_section_external(bv, real_sect)
    pb_seg.read_only = not is_readable(bv, start_addr)
    pb_seg.is_thread_local = is_tls_section(bv, start_addr)

    sym = bv.get_symbol_at(start_addr)
    pb_seg.is_exported = sym is not None and start_addr in global_starts
    if pb_seg.is_exported and sym.name != real_sect.name:
      pb_seg.variable_name = sym.name

    vars.recover_section_vars(bv, pb_seg, start_addr, end_addr)
    xrefs.recover_section_cross_references(bv, pb_seg, real_sect, start_addr, end_addr)


def recover_externals(bv, pb_mod):
  """Recover info about all external symbols"""
  for sym in bv.get_symbols():
    if sym.type == SymbolType.ImportedFunctionSymbol:
      functions.recover_ext_func(bv, pb_mod, sym)

    elif sym.type == SymbolType.ImportedDataSymbol:
      vars.recover_ext_var(bv, pb_mod, sym)

    # Todo: Don't hardcode, but this gets the tests working for now
    elif sym.name in ["stdin", "stdout", "stderr"]:
      vars.recover_ext_var(bv, pb_mod, sym)

  #  elif sym.type == SymbolType.ImportAddressSymbol:
  #    pass  # I don't think we need to do anything for these?

  log.pop()


def parse_defs_files(bv, args_os, args_std_defs):
  # Collect all paths to defs files
  log.debug('Finding files to parse')
  def_paths = set(map(os.path.abspath, args_std_defs))
  def_paths.add(os.path.join(DISASS_DIR, 'defs', '{}.txt'.format(args_os)))  # default defs file

  log.debug('Parsing files')
  for fpath in def_paths:
    if os.path.isfile(fpath):
      parse_defs_file(bv, fpath)
    else:
      log.warn('%s is not a file', fpath)


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
