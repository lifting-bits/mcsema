#!/usr/bin/env python

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

# Bring in utility libraries.
from util import *
from table import *
from flow import *
from refs import *
from segment import *

_INFO = idaapi.get_inf_structure()

if _INFO.is_64bit():
  PTRSIZE = 8
else:
  PTRSIZE = 4

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

# sign extend b low bits in x
# from "Bit Twiddling Hacks"
def sign_extn(x, b):
  m = 1 << (b - 1)
  x = x & ((1 << b) - 1)
  return (x ^ m) - m

def make_array(ea, size):
  if ea != idc.BADADDR and ea != 0:
    flags = idc.GetFlags(ea)
    if not idc.isByte(flags) or idc.ItemSize(ea) != 1:
      idc.MakeUnknown(ea, 1, idc.DOUNK_SIMPLE)
      idc.MakeByte(ea)
    idc.MakeArray(ea, size)

def read_string(ea):
  s = idc.GetString(ea, -1, idc.ASCSTR_C)
  slen = len(s)+1
  idc.MakeUnknown(ea, slen, idc.DOUNK_SIMPLE)
  idaapi.make_ascii_string(ea, slen, idc.ASCSTR_C)
  return s, ea + slen

def read_leb128(ea, signed):
  """ Read LEB128 encoded data
  """
  # https://en.wikipedia.org/wiki/LEB128
  val = 0
  shift = 0
  while True:
    byte = idc.Byte(ea)
    val |= (byte & 0x7F)<<shift
    shift += 7
    ea += 1
    if (byte & 0x80) == 0:
      break
  
    if shift > 64:
      DEBUG("Bad leb128 encoding at {0:x}".format(ea - shift/7))
      return idc.BADADDR
  
  if signed and (byte & 0x40):
    val -= (1<<shift)
  return val, ea

def read_uleb128(ea):
  return read_leb128(ea, False)

def read_sleb128(ea):
  return read_leb128(ea, True)

def enc_size(enc):
  """ Read encoding size
  """
  fmt = enc & 0x0F
  if fmt == DW_EH_PE_ptr:
    return PTRSIZE
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
  if enc == DW_EH_PE_omit:
    DEBUG("Error in read_enc_val {0:x}".format(ea))
    return idc.BADADDR, idc.BADADDR

  start = ea
  fmt, mod = enc&0x0F, enc&0x70
  
  if fmt == DW_EH_PE_ptr:
    val = read_pointer(ea)
    ea += PTRSIZE
      
  elif fmt in [DW_EH_PE_uleb128, DW_EH_PE_sleb128]:
    val, ea = read_leb128(ea, fmt == DW_EH_PE_sleb128)
    if ea - start > 1:
      make_array(start, ea - start)

  elif fmt in [DW_EH_PE_sdata2, DW_EH_PE_udata2]:
    val = read_word(ea)
    ea += 2
    if fmt == DW_EH_PE_sdata2:
      val = sign_extn(val, 16)
      
  elif fmt in [DW_EH_PE_sdata4, DW_EH_PE_udata4]:
    val = read_dword(ea)
    ea += 4
    if fmt == DW_EH_PE_sdata4:
      val = sign_extn(val, 32)
      
  elif fmt in [DW_EH_PE_sdata8, DW_EH_PE_udata8]:
    val = read_qword(ea)
    ea += 8
    if f == DW_EH_PE_sdata8:
      val = sign_extn(val, 64)
      
  else:
    DEBUG("{0:x}: don't know how to handle encoding {1:x}".format(start, enc))
    return idc.BADADDR, idc.BADADDR

  if mod == DW_EH_PE_pcrel:   
    if val != 0:
      make_reloff(start, start)
      val += start
      val &= (1<<(PTRSIZE*8)) - 1
  
  elif mod != DW_EH_PE_absptr:
    DEBUG("{0:x}: don't know how to handle encoding {1:x}".format(start, enc))
    return BADADDR, BADADDR

  if (enc & DW_EH_PE_indirect) and val != 0:
    if not idc.isLoaded(val):
      DEBUG("{0:x}: trying to dereference invalid pointer {1:x}".format(start, val))
      return idc.BADADDR, idc.BADADDR
    val = read_pointer(val)

  return val, ea

def make_reloff(ea, base, subtract = False):
  ri = idaapi.refinfo_t()
  flag = idaapi.REF_OFF32|idaapi.REFINFO_NOBASE
  if subtract:
    flag |= idaapi.REFINFO_SUBTRACT
  ri.init(flag, base)
  idaapi.op_offset_ex(ea, 0, ri)

def format_lsda(M, ea, lpstart = None, sjlj = False):
  """  Decode the LSDA (Language specific data section)
  """
  lpstart_enc, ea = read_byte(ea), ea + 1
  if lpstart_enc != DW_EH_PE_omit:
    lpstart, ea2 = read_enc_value(ea, lpstart_enc)
    DEBUG("ea {0:x}: LP start: {1:x}".format(ea, val))
    ea = ea2

  type_enc, ea = read_byte(ea), ea + 1
  type_addr = idc.BADADDR
  
  if type_enc != DW_EH_PE_omit:
    type_off, ea2 = read_enc_value(ea, DW_EH_PE_uleb128)
    type_addr = ea2 + type_off
    DEBUG("ea {:x}: Type offset: {:x} -> {:x}".format(ea, type_off, type_addr))
    make_reloff(ea, ea2)
    ea = ea2

  cs_enc, ea = read_byte(ea), ea + 1
  cs_len, ea2 = read_enc_value(ea, DW_EH_PE_uleb128)
  action_tbl = ea2 + cs_len
  DEBUG("ea {:x}: call site table length: {:x} action table start: {:x}".format(ea, cs_len, action_tbl))
  make_reloff(ea, ea2)
  ea = ea2
  i = 0
  
  EH = M.eh_frame.add()
  actions = []
  while ea < action_tbl:
    if sjlj:
      cs_lp, ea2 = read_enc_val(ea, DW_EH_PE_uleb128, True)
      cs_action, ea3 = read_enc_value(ea2, DW_EH_PE_uleb128)
      DEBUG("ea {:x}: cs_lp[{}] = {}".format(ea, i, cs_lp))
      act_ea = ea2
      ea = ea3
    else:
      cs_start, ea2 = read_enc_value(ea, cs_enc)
      cs_len,   ea3 = read_enc_value(ea2, cs_enc & 0x0F)
      cs_lp,    ea4 = read_enc_value(ea3, cs_enc)
      cs_action,ea5 = read_enc_value(ea4, DW_EH_PE_uleb128)
      
      if lpstart != None:
        cs_start += lpstart
        cs_lp = cs_lp + lpstart if cs_lp != 0 else cs_lp
        EH.start_ea = cs_start
        EH.end_ea = cs_start + cs_len
        EH.lp_ea = cs_lp
      
        DEBUG("ea {:x}: cs_start[{}] = {:x}".format(ea, i, cs_start))
        DEBUG("ea {:x}: cs_len[{:x}] = {} (end = {:x})".format(ea2, i, cs_len, cs_start + cs_len))
        DEBUG("ea {:x}: cs_lp[{}] = {:x}".format(ea3, i, cs_lp))
        DEBUG_PUSH()
        DEBUG("Landing pad for {0:x}..{1:x}".format(cs_start, cs_start + cs_len))
        DEBUG_POP()

      if lpstart != None:
        make_reloff(ea, lpstart)
        if cs_lp != 0:
          make_reloff(ea3, lpstart)
      act_ea = ea4
      ea = ea5
    if cs_action == 0:
      addcmt = "no action"
    else:
      addcmt = "{:x}".format(action_tbl + cs_action - 1)
      actions.append(cs_action)
    EH.action = 0
    DEBUG("ea {:x}: cs_action[{}] = {} ({})".format(act_ea, i, cs_action, addcmt))
    i += 1
  
  actions2 = []
  while len(actions):
    act = actions.pop()
    if not act in actions2:
      act_ea = action_tbl + act - 1
      # print "action %d -> %08X" % (act, act_ea)
      actions2.append(act)
      ar_filter,ea2 = read_enc_value(act_ea, DW_EH_PE_sleb128)
      ar_disp,  ea3 = read_enc_value(ea2, DW_EH_PE_sleb128)
      if ar_filter == 0:
        addcmt = "cleanup"
      else:
        if type_addr == idc.BADADDR:
          addcmt = "no type table?!"
        else:
          if ar_filter > 0:
            # catch expression
            type_slot = type_addr - ar_filter * enc_size(type_enc)
            #idc.MakeComm(type_slot, "Type index %d" % ar_filter)
            type_ea, eatmp = read_enc_value(type_slot, type_enc)
            addcmt = "catch type typeinfo = %08X" % (type_ea)
          else:
            # exception spec list
            type_slot = ttype_addr - ar_filter - 1
            addcmt = "exception spec index list = %08X" % (type_slot)
          
      DEBUG("ea {:x}: ar_filter[{}]: {} ({})".format(act_ea, act, ar_filter, addcmt))
      if ar_disp == 0:
        addcmt = "end"
      else:
        next_ea = ea2 + ar_disp
        next_act = next_ea - act_ea + act
        addcmt = "next: %d => %08X" % (next_act, next_ea)
        actions.append(next_act)
        
      DEBUG("ea {:x}: ar_disp[{}]: {} ({})".format(ea2, act, ar_disp, addcmt))

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

def format_entries(M, ea):
  """ Check the types of entries CIE/FDE recover them
  """
  start_ea = ea
  size, ea = read_dword(ea), ea + 4
  if size == 0:
    return idc.BADADDR

  make_reloff(start_ea, ea)
  end_ea = ea + size
  entry = EHRecord()
  
  cie_id, ea = read_dword(ea), ea + 4
  is_cie = cie_id == 0
  entry.type = ["FIE", "CDE"][is_cie]
  DEBUG("ea {0:x}: type {1} size {2}".format(start_ea, entry.type, size))

  if is_cie:
    entry.version, ea = read_byte(ea), ea + 1
    DEBUG("ea {0:x}: version {0}".format(ea, entry.version))
    
    entry.aug_string, ea = read_string(ea)
    DEBUG("ea {0:x}: augmentation string {1}".format(ea, entry.aug_string))
    
    entry.code_align, ea = read_uleb128(ea)
    DEBUG("ea {0:x}: code alignment factor {1}".format(ea, entry.code_align))
    
    entry.data_align, ea = read_uleb128(ea)
    DEBUG("ea {0:x}: data alignment factor {1}".format(ea, entry.data_align))
    
    if entry.version == 1:
      entry.retn_reg, ea = read_byte(ea), ea + 1
    else:
      entry.retn_reg, ea = read_uleb128(ea)
    
    DEBUG("ea {0:x}: return register {1}".format(ea, entry.retn_reg))
          
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
          DEBUG("ea {0:x}: personality function {1:x}".format(ea, aug_data.personality_ptr))
          ea = ea2
        elif s == 'R':
          aug_data.fde_encoding, ea = read_byte(ea), ea + 1
        else:
          DEBUG("ea {0:x}: unhandled string char {1}".format(ea, s))
          return idc.BADADDR
    
    instr_length = end_ea - ea
    if instr_length > 0:
      make_array(ea, instr_length)
    else:
      DEBUG("ea {0:x}: invalid insn_len {1}?!".format(ea, instr_length))
    
    _AUGM_PARAM[start_ea] = aug_data
  
  else:
    base_ea = ea - 4
    cie_ea = base_ea - cie_id
  
    if cie_ea in _AUGM_PARAM:
      aug_data = _AUGM_PARAM[cie_ea]
    else:
      DEBUG("{0:x} : CIE {1:x} not present?!".format(base_ea, cie_ea))
      return idc.BADADDR
  
    make_reloff(base_ea, base_ea, True)
    DEBUG("ea {0:x}: CIE pointer".format(base_ea))
    
    init_loc, ea2 = read_enc_value(ea, aug_data.fde_encoding)
    DEBUG("ea {0:x}: initial location={1:x}".format(ea, init_loc))
    
    ea = ea2
    range_len, ea2 = read_enc_value(ea, aug_data.fde_encoding & 0x0F)
    DEBUG("ea {:x}: range length={:x} (end={:x})".format(ea, range_len, range_len + init_loc))

    if range_len:
      make_reloff(ea, init_loc)
    
    ea = ea2
    lsda_ptr = 0
    if aug_data.aug_present:
      aug_len, ea = read_uleb128(ea)
      if aug_data.lsda_encoding != DW_EH_PE_omit:
        lsda_ptr, ea2 = read_enc_value(ea, aug_data.lsda_encoding)
        DEBUG("ea {0:x}: LSDA pointer {1:x}".format(ea, lsda_ptr))
        DEBUG_PUSH()
        if lsda_ptr:
          format_lsda(M, lsda_ptr, init_loc, False)
        DEBUG_POP()
        ea = ea2
    
    instr_length = end_ea - ea
    if instr_length > 0:
      make_array(ea, instr_length)
    else:
      DEBUG("ea {0:x}: invalid insn_len = {1}?!".format(ea, instr_length))
      
  return end_ea

def recover_frame_entries(M, seg_ea):
  if seg_ea == idc.BADADDR:
    return

  DEBUG("Recover entries from section : {}".format(idc.SegName(seg_ea)))
  ea = idc.SegStart(seg_ea)
  end_ea = idc.SegEnd(seg_ea)
  while ea != idc.BADADDR and ea < end_ea:
    ea = format_entries(M, ea)

def recover_exception_table(M):
  """ Recover the CIE and FDE entries from the segment .eh_frame
  """
  seg_eas = [ea for ea in idautils.Segments() if not is_invalid_ea(ea)]
  
  for seg_ea in seg_eas:
    seg_name = idc.SegName(seg_ea)
    if seg_name in [".eh_frame", "__eh_frame"]:
      recover_frame_entries(M, seg_ea)
      break