#!/usr/bin/env python

# Copyright (c) 2017 Trail of Bits, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import idautils
import idaapi
import idc
import sys
import os
import argparse
import struct
import traceback
import collections
import itertools
import pprint

from collections import namedtuple
# Bring in utility libraries.
from util import *

frame_entry = namedtuple('frame_entry', ['cs_start', 'cs_end', 'cs_lp', 'cs_action', 'action_list'])
_FUNC_UNWIND_FRAME_EAS = set()

_EXCEPTION_BLOCKS_EAS = dict()

DW_EH_PE_ptr       = 0x00
DW_EH_PE_uleb128   = 0x01
DW_EH_PE_udata2    = 0x02
DW_EH_PE_udata4    = 0x03
DW_EH_PE_udata8    = 0x04
DW_EH_PE_signed    = 0x08
DW_EH_PE_sleb128   = 0x09
DW_EH_PE_sdata2    = 0x0A
DW_EH_PE_sdata4    = 0x0B
DW_EH_PE_sdata8    = 0x0C

DW_EH_PE_absptr    = 0x00
DW_EH_PE_pcrel     = 0x10
DW_EH_PE_textrel   = 0x20
DW_EH_PE_datarel   = 0x30
DW_EH_PE_funcrel   = 0x40
DW_EH_PE_aligned   = 0x50
DW_EH_PE_indirect  = 0x80
DW_EH_PE_omit      = 0xFF

class EHBlocks(object):
  def __init__(self, start_ea, end_ea):
    self.start_ea = start_ea
    self.end_ea = end_ea

def make_array(ea, size):
  if ea != idc.BADADDR and ea != 0:
    flags = idc.GetFlags(ea)
    if not idc.isByte(flags) or idc.ItemSize(ea) != 1:
      idc.MakeUnknown(ea, 1, idc.DOUNK_SIMPLE)
      idc.MakeByte(ea)
    idc.MakeArray(ea, size)

def read_string(ea):
  s = idc.GetString(ea, -1, idc.ASCSTR_C)
  if s:
    slen = len(s)+1
    idc.MakeUnknown(ea, slen, idc.DOUNK_SIMPLE)
    idaapi.make_ascii_string(ea, slen, idc.ASCSTR_C)
    return s, ea + slen
  else:
    return s, ea

def read_uleb128(ea):
  return read_leb128(ea, False)

def read_sleb128(ea):
  return read_leb128(ea, True)

def enc_size(enc):
  """ Read encoding size
  """
  fmt = enc & 0x0F
  if fmt == DW_EH_PE_ptr:
    return get_address_size_in_bytes()
  elif fmt in [DW_EH_PE_sdata2, DW_EH_PE_udata2]:
    return 2
  elif fmt in [DW_EH_PE_sdata4, DW_EH_PE_udata4]:
    return 4
  elif fmt in [DW_EH_PE_sdata8, DW_EH_PE_udata8]:
    return 8
  elif fmt != DW_EH_PE_omit:
    DEBUG("Encoding {0:x} is not of fixed size".format(enc))
  return 0

def read_enc_value(ea, enc):
  """ Read encoded value
  """
  if enc == DW_EH_PE_omit:
    DEBUG("Error in read_enc_val {0:x}".format(ea))
    return idc.BADADDR, idc.BADADDR

  start = ea
  fmt, mod = enc&0x0F, enc&0x70
  
  if fmt == DW_EH_PE_ptr:
    val = read_pointer(ea)
    ea += get_address_size_in_bytes()
      
  elif fmt in [DW_EH_PE_uleb128, DW_EH_PE_sleb128]:
    val, ea = read_leb128(ea, fmt == DW_EH_PE_sleb128)
    if ea - start > 1:
      make_array(start, ea - start)

  elif fmt in [DW_EH_PE_sdata2, DW_EH_PE_udata2]:
    val = read_word(ea)
    ea += 2
    if fmt == DW_EH_PE_sdata2:
      val = sign_extend(val, 16)
      
  elif fmt in [DW_EH_PE_sdata4, DW_EH_PE_udata4]:
    val = read_dword(ea)
    ea += 4
    if fmt == DW_EH_PE_sdata4:
      val = sign_extend(val, 32)
      
  elif fmt in [DW_EH_PE_sdata8, DW_EH_PE_udata8]:
    val = read_qword(ea)
    ea += 8
    if f == DW_EH_PE_sdata8:
      val = sign_extend(val, 64)
      
  else:
    DEBUG("{0:x}: don't know how to handle {1:x}".format(start, enc))
    return idc.BADADDR, idc.BADADDR

  if mod == DW_EH_PE_pcrel:   
    if val != 0:
      val += start
      val &= (1<<(get_address_size_in_bits())) - 1
  
  elif mod != DW_EH_PE_absptr:
    DEBUG("{0:x}: don't know how to handle {1:x}".format(start, enc))
    return BADADDR, BADADDR

  if (enc & DW_EH_PE_indirect) and val != 0:
    if not idc.isLoaded(val):
      DEBUG("{0:x}: dereference invalid pointer {1:x}".format(start, val))
      return idc.BADADDR, idc.BADADDR
    val = read_pointer(val)

  return val, ea

def _create_frame_entry(start = None, end = None, lp = None, action = None, act_list = None):
    return frame_entry(start, end, lp, action, act_list)

def format_lsda_actions(action_tbl, act_ea, type_addr, type_enc, act_id):
  """ Recover the exception actions and type info
  """
  action_list = []
  if action_tbl == idc.BADADDR:
    return

  DEBUG("start action ea : {:x}".format(act_ea))
  while True:
    ar_filter,ea2 = read_enc_value(act_ea, DW_EH_PE_sleb128)
    ar_disp,  ea3 = read_enc_value(ea2, DW_EH_PE_sleb128)
  
    if ar_filter > 0:
      type_slot = type_addr - ar_filter * enc_size(type_enc)
      type_ea, eatmp = read_enc_value(type_slot, type_enc)
      DEBUG("catch type typeinfo = {:x} {} {}".format(type_ea, get_symbol_name(type_ea), ar_filter))
      action_list.append((ar_disp, ar_filter, type_ea))

    #DEBUG(" format_lsda_actions ea {:x}: ar_disp[{}]: {} ({:x})".format(act_ea, act_id, ar_disp, ar_filter))
    if ar_disp == 0:
      break

    act_ea = ea2 + ar_disp

  return action_list

def create_block_entries(start_ea, heads):
  index = 0
  block_set = set()
  for entry in heads:
    if entry == 0:
      continue
  
    if index < len(heads) - 1:
      ea = heads[index]
      while heads[index] <= ea < heads[index + 1]:
        inst, _ = decode_instruction(ea)
        if not inst:
          break
        block = EHBlocks(ea, ea + inst.size)
        ea = ea + inst.size
        block_set.add(block)
    index = index + 1

  _EXCEPTION_BLOCKS_EAS[start_ea] = block_set

def format_lsda(lsda_ptr, start_ea, range = None,  sjlj = False):
  """  Recover the language specific data area
  """
  lsda_entries = list()
  heads = set()
  lpstart_enc, ea = read_byte(lsda_ptr), lsda_ptr + 1
  if lpstart_enc != DW_EH_PE_omit:
    lpstart, next_ea = read_enc_value(ea, lpstart_enc)
    ea = next_ea
  else:
    lpstart = start_ea

  # get the type encoding and type address associated with the exception handling blocks
  type_enc, ea = read_byte(ea), ea + 1
  type_addr = idc.BADADDR

  if type_enc != DW_EH_PE_omit:
    type_off, next_ea = read_enc_value(ea, DW_EH_PE_uleb128)
    type_addr = next_ea + type_off
    ea = next_ea

  cs_enc, next_ea = read_byte(ea), ea + 1
  ea = next_ea
  cs_len, next_ea = read_enc_value(ea, DW_EH_PE_uleb128)
  action_tbl = next_ea + cs_len
  ea = next_ea

  i = 0
  actions = []
  action_list = []
  while ea < action_tbl:
    if sjlj:
      cs_lp, next_ea = read_enc_val(ea, DW_EH_PE_uleb128, True)
      act_ea = next_ea
      cs_action, next_ea = read_enc_value(next_ea, DW_EH_PE_uleb128)
      DEBUG("ea {:x}: cs_lp[{}] = {}".format(ea, i, cs_lp))
      ea = next_ea
    else:
      cs_start, next_ea = read_enc_value(ea, cs_enc)
      cs_start += lpstart
      DEBUG("ea {:x}: cs_start[{}] = {:x}  ({})".format(ea, i, cs_start, get_symbol_name(start_ea)))
      ea = next_ea
      heads.add(cs_start)
      
      cs_len, next_ea = read_enc_value(ea, cs_enc & 0x0F)
      cs_end = cs_start + cs_len
      DEBUG("ea {:x}: cs_len[{:x}] = {} (end = {:x})".format(ea, i, cs_len, cs_start + cs_len))
      ea = next_ea
      heads.add(cs_end)

      cs_lp, next_ea = read_enc_value(ea, cs_enc)
      cs_lp = cs_lp + lpstart if cs_lp != 0 else cs_lp
      act_ea = next_ea
      DEBUG("ea {:x}: cs_lp[{}] = {:x}".format(ea, i, cs_lp))
      ea = next_ea
      heads.add(cs_lp)

      cs_action, next_ea = read_enc_value(ea, DW_EH_PE_uleb128)
      ea = next_ea

      if cs_action != 0:
        actions.append(cs_action)

      DEBUG_PUSH()
      DEBUG("Landing pad for {0:x}..{1:x}".format(cs_start, cs_start + cs_len))
      DEBUG_POP()

    if cs_action != 0:
      action_offset = action_tbl + cs_action - 1
      action_list = format_lsda_actions(action_tbl, action_offset, type_addr, type_enc, cs_action)

    lsda_entries.append(_create_frame_entry(cs_start, cs_start + cs_len, cs_lp, cs_action, action_list))

    DEBUG("ea {:x}: cs_action[{}] = {}".format(act_ea, i, cs_action))
    i += 1

  create_block_entries(start_ea, sorted(heads))
  FUNC_LSDA_ENTRIES[start_ea] = lsda_entries

class AugmentationData:
  def __init__(self):
    self.aug_present = False
    self.lsda_encoding = DW_EH_PE_omit
    self.personality_ptr = None
    self.fde_encoding = DW_EH_PE_absptr

class EHRecord:
  def __init__(self):
    self.type = ""
    self.version = None
    self.data = None
    self.aug_string = ""
    self.code_align = None
    self.data_align = None
    self.retn_reg = None

_AUGM_PARAM = dict()

def format_entries(ea):
  """ Check the types of entries CIE/FDE recover them
  """
  start_ea = ea
  size, ea = read_dword(ea), ea + 4
  if size == 0:
    return idc.BADADDR

  end_ea = ea + size
  entry = EHRecord()
  
  cie_id, ea = read_dword(ea), ea + 4
  is_cie = cie_id == 0
  entry.type = ["FDE", "CIE"][is_cie]
  #DEBUG("ea {0:x}: type {1} size {2}".format(start_ea, entry.type, size))

  if is_cie:
    entry.version, ea = read_byte(ea), ea + 1
    entry.aug_string, ea = read_string(ea)
    if entry.aug_string is None:
      return end_ea

    entry.code_align, ea = read_uleb128(ea)
    entry.data_align, ea = read_uleb128(ea)
    if entry.version == 1:
      entry.retn_reg, ea = read_byte(ea), ea + 1
    else:
      entry.retn_reg, ea = read_uleb128(ea)

    aug_data = AugmentationData()

    if entry.aug_string[0:1]=='z':
      aug_len, ea = read_uleb128(ea)
      aug_data.aug_present = True
      
      for s in entry.aug_string[1:]:
        if s == 'L':
          aug_data.lsda_encoding, ea = read_byte(ea), ea + 1
        elif s == 'P':                    
          enc, ea = read_byte(ea), ea + 1
          aug_data.personality_ptr, ea2 = read_enc_value(ea, enc)
          #DEBUG("ea {0:x}: personality function {1:x}".format(ea, aug_data.personality_ptr))
          ea = ea2
        elif s == 'R':
          aug_data.fde_encoding, ea = read_byte(ea), ea + 1
        else:
          #DEBUG("ea {0:x}: unhandled string char {1}".format(ea, s))
          return idc.BADADDR

    _AUGM_PARAM[start_ea] = aug_data

  else:
    base_ea = ea - 4
    cie_ea = base_ea - cie_id
    if cie_ea in _AUGM_PARAM:
      aug_data = _AUGM_PARAM[cie_ea]
    else:
      return idc.BADADDR

    pc_begin, ea2 = read_enc_value(ea, aug_data.fde_encoding)
    #DEBUG("ea {0:x}: CIE pointer".format(base_ea))  
    #DEBUG("ea {0:x}: PC begin={1:x}".format(ea, pc_begin))

    ea = ea2
    range_len, ea2 = read_enc_value(ea, aug_data.fde_encoding & 0x0F)
    #DEBUG("ea {:x}: PC range = {:x} (PC end={:x})".format(ea, range_len, range_len + pc_begin))

    if range_len:
      _FUNC_UNWIND_FRAME_EAS.add((pc_begin, range_len))
    
    ea = ea2
    if aug_data.aug_present:
      aug_len, ea = read_uleb128(ea)
      if aug_data.lsda_encoding != DW_EH_PE_omit:
        lsda_ptr, ea2 = read_enc_value(ea, aug_data.lsda_encoding)
        #DEBUG("ea {0:x}: LSDA pointer {1:x}".format(ea, lsda_ptr))
        DEBUG_PUSH()
        if lsda_ptr:
          format_lsda(lsda_ptr, pc_begin, range_len, False)
        DEBUG_POP()

  return end_ea

def recover_frame_entries(seg_ea):
  if seg_ea == idc.BADADDR:
    return

  DEBUG("Recover entries from section : {}".format(idc.SegName(seg_ea)))
  ea = idc.SegStart(seg_ea)
  end_ea = idc.SegEnd(seg_ea)
  while ea != idc.BADADDR and ea < end_ea:
    ea = format_entries(ea)

def recover_exception_table():
  """ Recover the CIE and FDE entries from the segment .eh_frame
  """
  seg_eas = [ea for ea in idautils.Segments() if not is_invalid_ea(ea)]
  
  for seg_ea in seg_eas:
    seg_name = idc.SegName(seg_ea)
    if seg_name in [".eh_frame", "__eh_frame"]:
      recover_frame_entries(seg_ea)
      break

  recover_rtti()

def recover_exception_entries(F, func_ea):
  has_unwind_frame = func_ea in FUNC_LSDA_ENTRIES.keys()
  if has_unwind_frame:
    lsda_entries = FUNC_LSDA_ENTRIES[func_ea]

    for entry in lsda_entries:
      EH = F.eh_frame.add()
      EH.func_ea = func_ea
      EH.start_ea = entry.cs_start
      EH.end_ea = entry.cs_end
      EH.lp_ea = entry.cs_lp
      EH.action = entry.cs_action != 0

      for ar_disp, ar_filter, type_ea  in entry.action_list:
        AC = EH.ttype.add()
        AC.ea = type_ea
        AC.name = get_symbol_name(type_ea)
        AC.size = ar_filter
        AC.is_weak = False
        AC.is_thread_local = False

def fix_function_bounds(min_ea, max_ea):
  for func_ea, range in _FUNC_UNWIND_FRAME_EAS:
    if func_ea == min_ea:
      return func_ea, func_ea + range
  return min_ea, max_ea

def get_exception_landingpad(F, insn_ea):
  has_lp = F.ea in FUNC_LSDA_ENTRIES.keys()
  if has_lp:
    lsda_entries = FUNC_LSDA_ENTRIES[F.ea]
    for entry in lsda_entries:
      if insn_ea >= entry.cs_start and insn_ea < entry.cs_end:
        return entry.cs_lp
  return 0

def get_exception_chunks(sub_ea):
  has_block = sub_ea in _EXCEPTION_BLOCKS_EAS.keys()
  if has_block:
    block_set = _EXCEPTION_BLOCKS_EAS[sub_ea]
    for block in block_set:
      yield block.start_ea, block.end_ea


""" Recover the RTTI information which can't be detected by IDA 6.9
"""

typeinfo_names = [
 "_ZTVSt9type_info",
 "_ZTVN10__cxxabiv117__class_type_infoE",
 "_ZTVN10__cxxabiv120__si_class_type_infoE",
 "_ZTVN10__cxxabiv121__vmi_class_type_infoE",
]

EXTERNAL_NAMES = ("@@GLIBCXX_", "@@CXXABI_")

def get_stripped_name(name):
  for en in EXTERNAL_NAMES:
    if en in name:
      name = name[:name.find(en)]
  return name

def _create_reference_object(name, ea, offset):
  return dict(name=name, addr=ea, offset=offset)

def get_alternative_symbol_name(ea):
  comment = idc.GetCommentEx(ea, 0) or ""
  for comment_line in comment.split("\n"):
    comment_line = comment_line.replace(";", "").strip()
    if not comment_line:
      continue
    mstr = comment_line.split("'")
    if 3 <= len(mstr):
      return mstr[1] + "'" + mstr[2]
  return None

def convert_to_bytes(value):
  is64 = get_address_size_in_bytes() == 8
  if is64:
    sv = struct.pack("<Q", value)
  else:
    sv = struct.pack("<I", value)
  return " ".join("%02X" % ord(c) for c in sv)

def first(val):
  return idc.FindBinary(0, idc.SEARCH_CASE|idc.SEARCH_DOWN, convert_to_bytes(val))

def next(val, ref):
  return idc.FindBinary(ref+1, idc.SEARCH_CASE|idc.SEARCH_DOWN, convert_to_bytes(val))

def find_xrefs(addr):
  lrefs = list(idautils.DataRefsTo(addr))
  if len(lrefs) == 0:
    lrefs = list(idautils.refs(addr, first, next))

  lrefs = [r for r in lrefs if not idc.isCode(idc.GetFlags(r))]
  return lrefs

def get_type_info(ea):
  tis = read_pointer(ea + get_address_size_in_bytes())
  if is_invalid_ea(tis):
    return idc.BADADDR
  name = idc.GetString(tis)
  if name == None or len(name) == 0:
    return idc.BADADDR, name

  ea2 = ea + 2*get_address_size_in_bytes()
  return ea2, name

def get_si_type_info(ea):
  ea2, name = get_type_info(ea)
  pbase = read_pointer(ea2)
  RTTI_REFERENCE_TABLE[ea2] = _create_reference_object(get_alternative_symbol_name(pbase), pbase, 0)
  ea2 += get_address_size_in_bytes()
  return ea2

def get_typeinfo_refs(name, ea):
  if ea == idc.BADADDR:
    return

  ea2 = ea
  if idaapi.is_spec_ea(ea2):
    xrefs = find_xrefs(ea2)
    ea2 += get_address_size_in_bytes()*2
    xrefs.extend(find_xrefs(ea2))
  else:
    ea2 += get_address_size_in_bytes()*2
    xrefs = find_xrefs(ea2)

  for x in xrefs:
    if not is_invalid_ea(x):
      value = read_pointer(x)
      offset = value - ea if value > ea else 0
      RTTI_REFERENCE_TABLE[x] = _create_reference_object(name, ea, offset)
      ea3 = get_si_type_info(x)

def recover_rtti():
  for index, ordinal, ea, name in idautils.Entries():
    if get_stripped_name(name) in typeinfo_names:
      get_typeinfo_refs(name, ea)
