# Copyright (c) 2018 Trail of Bits, Inc.
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

import re
import io
import collections
import struct

_DEBUG_FILE = None
_DEBUG_PREFIX = ""

def INIT_DEBUG_FILE(file):
  global _DEBUG_FILE
  _DEBUG_FILE = file

def DEBUG_PUSH():
  global _DEBUG_PREFIX
  _DEBUG_PREFIX += "  "

def DEBUG_POP():
  global _DEBUG_PREFIX
  _DEBUG_PREFIX = _DEBUG_PREFIX[:-2]

def DEBUG(s):
  global _DEBUG_FILE
  if _DEBUG_FILE:
    _DEBUG_FILE.write("{}{}\n".format(_DEBUG_PREFIX, str(s)))
    _DEBUG_FILE.flush()

def DEBUG_FLUSH():
  global _DEBUG_FILE
  if _DEBUG_FILE:
    _DEBUG_FILE.flush()

PARAM_REGISTERS = {
  "rdi" : 0,
  "rsi" : 1,
  "rdx" : 2,
  "rcx" : 3,
  "r8"  : 4,
  "r9"  : 5,
  }

PARAM_REGISTERS_INDEX = {
  0 : "rdi",
  1 : "rsi",
  2 : "rdx",
  3 : "rcx",
  4 : "r8",
  5 : "r9",
  }

def set_comments(bv, addr, str):
  functions = bv.get_functions_containing(addr)
  if functions is None:
    return

  for func in functions:
    old_str = func.get_comment_at(addr)
    new_str = old_str + " ; " + str
    func.set_comment_at(addr, new_str)

def convert_signed32(num):
  num = num & 0xFFFFFFFF
  return (num ^ 0x80000000) - 0x80000000

def is_valid_addr(bv, addr):
  return bv.get_segment_at(addr) is not None
  
def is_invalid_addr(bv, addr):
  return bv.get_segment_at(addr) is None
  
def get_section_at(bv, addr):
  if is_invalid_addr(bv, addr):
    return None

  for sec in bv.sections.values():
    if sec.start <= addr < sec.end:
      return sec
  return None

def is_executable(bv, addr):
  seg = bv.get_segment_at(addr)
  return seg is not None and seg.executable

def is_readable(bv, addr):
  seg = bv.get_segment_at(addr)
  return seg is not None and seg.writable

def is_writeable(bv, addr):
  seg = bv.get_segment_at(addr)
  return seg is not None and seg.readable

def is_ELF(bv):
  return bv.view_type == 'ELF'

def is_PE(bv):
  return bv.view_type == 'PE'

def is_data_variable(bv, addr):
  seg = bv.get_segment_at(addr)
  if seg == None:
    return False

  sect = get_section_at(bv, addr)
  if sect is not None and is_ELF(bv):
    if re.search(r'\.(init|fini)', sect.name):
      return False

  return (seg.executable == False)

# Caching results of is_section_external
_EXT_SECTIONS = set()
_INT_SECTIONS = set()

def is_section_external(bv, sect):
  if sect.start in _EXT_SECTIONS:
    return True

  if sect.start in _INT_SECTIONS:
    return False

  if is_ELF(bv):
    if re.search(r'\.(got|plt)', sect.name):
      _EXT_SECTIONS.add(sect.start)
      return True

  _INT_SECTIONS.add(sect.start)
  return False
  