#!/usr/bin/env python

# Copyright (c) 2020 Trail of Bits, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

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

import ida_bytes

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
    flags = idc.get_full_flags(ea)
    if not idc.isByte(flags) or idc.get_item_size(ea) != 1:
      idc.del_items(ea, idc.DOUNK_SIMPLE, 1)
      ida_bytes.create_data(ea, ida_bytes.FF_BYTE, 1, ida_idaapi.BADADDR)
    idc.make_array(ea, size)

def read_string(ea):
  s = idc.get_strlit_contents(ea, -1, idc.ASCSTR_C)
  if s:
    slen = len(s)+1
    idc.del_items(ea, idc.DOUNK_SIMPLE, slen)
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
      if cs_lp != 0:
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

  DEBUG("Recover entries from section : {}".format(idc.get_segm_name(seg_ea)))
  ea = idc.get_segm_start(seg_ea)
  end_ea = idc.get_segm_end(seg_ea)
  while ea != idc.BADADDR and ea < end_ea:
    ea = format_entries(ea)

def recover_exception_table():
  """ Recover the CIE and FDE entries from the segment .eh_frame
  """
  seg_eas = [ea for ea in idautils.Segments() if not is_invalid_ea(ea)]
  
  for seg_ea in seg_eas:
    seg_name = idc.get_segm_name(seg_ea)
    if seg_name in [".eh_frame", "__eh_frame"]:
      recover_frame_entries(seg_ea)
      break

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
