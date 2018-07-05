# Copyright (c) 2017 Trail of Bits, Inc.
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
  Endianness, LowLevelILOperation, SectionSemantics
)
import inspect
import logging
import magic
import re
import struct
from collections import defaultdict

LOGNAME = 'binja.cfg'
log = logging.getLogger(LOGNAME)


class StackFormatter(logging.Formatter):
  def __init__(self, fmt=None, datefmt=None):
    logging.Formatter.__init__(self, fmt, datefmt)
    self.stack_base = len(inspect.stack()) + 7

  def format(self, record):
    record.indent = '  ' * (len(inspect.stack()) - self.stack_base)
    res = logging.Formatter.format(self, record)
    del record.indent
    return res


def init_logger(log_file):
  formatter = StackFormatter('[%(levelname)s] %(indent)s%(message)s')
  handler = logging.FileHandler(log_file)
  handler.setFormatter(formatter)

  log.addHandler(handler)
  log.setLevel(logging.DEBUG)


ENDIAN_TO_STRUCT = {
  Endianness.LittleEndian: '<',
  Endianness.BigEndian: '>'
}


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

  log.debug('Loading binary in binja...')
  bv = bv_type.open(path)
  bv.update_analysis_and_wait()

  # NOTE: at the moment binja will not load a binary
  # that doesn't have an entry point
  if len(bv) == 0:
    log.error('Binary could not be loaded in binja, is it linked?')
    exit(1)

  return bv


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


def is_external_ref(bv, addr):
  sym = bv.get_symbol_at(addr)
  return sym is not None and 'Import' in sym.type.name


def is_valid_addr(bv, addr):
  return bv.get_segment_at(addr) is not None


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


def is_ELF(bv):
  return bv.view_type == 'ELF'


def is_PE(bv):
  return bv.view_type == 'PE'


def clamp(val, vmin, vmax):
  return min(vmax, max(vmin, val))


# Caching results of is_section_external
_EXT_SECTIONS = set()
_INT_SECTIONS = set()


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


def is_tls_section(bv, addr):
  sect_names = (sect.name for sect in bv.get_sections_at(addr))
  return any(sect in ['.tbss', '.tdata', '.tls'] for sect in sect_names)


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


def search_displ_base(il):
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


def is_jump_tail_call(bv, il):
  """ Returns `True` if the given il is a jump to another function """
  return il.operation == LowLevelILOperation.LLIL_JUMP and \
       il.dest.operation == LowLevelILOperation.LLIL_CONST_PTR and \
       get_jump_tail_call_target(bv, il) is not None


def get_jump_tail_call_target(bv, il):
  """ Get the target function of a tail-call.

  Returns:
    binja.Function
  """
  try:
    return bv.get_function_at(il.dest.constant)
  except:
    return None


def collect_il_groups(il_func):
  """ Gather all il instructions grouped by address
  Some instructions (cmov, set, etc.) get expanded into multiple il
  instructions when lifted, but `Function.get_lifted_il_at` will only return the first
  of all the il instructions at an address. This will group all the il instructions
  into a map of address to expanded instructions as follows:

  {
    addr1 => [single il instruction],
    addr2 => [expanded il 1, expanded il 2, ...],
    ...
  }

  Args:
    il_func: IL function to gather all il groups from

  Returns:
    dict: Map from address to all IL instructions at that address

  """
  il_map = defaultdict(list)
  for blk in il_func:
    for il in blk:
      il_map[il.address].append(il)
  return il_map
