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
import pprint

from util import *

typeinfo_names = [
 "St9type_info",
 "N10__cxxabiv117__class_type_infoE",
 "N10__cxxabiv120__si_class_type_infoE",
 "N10__cxxabiv121__vmi_class_type_infoE",
]

RTTI_REFERENCE_TABLE = dict()

def _create_reference_object(name, ea, offset):
  return dict(name=name, addr=ea, offset=offset)

def vtable_symbol(name):
  return "__ZTV" + name + "@@CXXABI_1.3"

def convert_to_bytes(value):
  """ Convert the address into bytes for lookup into raw binary
  """
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

def next_ea(ea, fmt):
  """ Get the next ea
      p pointer, v vtable pointer, i interger, l long integer
  """
  for f in fmt:
    if f in ['p', 'v', 'l']:
      ea += get_address_size_in_bytes()
    elif f == 'i':
      ea += 4
  return ea

def get_type_info(ea):
  tis = read_pointer(ea + get_address_size_in_bytes())
  if is_invalid_ea(tis):
    return idc.BADADDR
  name = idc.GetString(tis)
  if name == None or len(name) == 0:
    return idc.BADADDR, name

  DEBUG("get_type_info: tis name {}".format(name))
  ea2 = next_ea(ea, "vp")

  # find our vtable 0 followed by ea
  signature = convert_to_bytes(0) + " " + convert_to_bytes(ea)
  vtable = idc.FindBinary(0, idc.SEARCH_CASE|idc.SEARCH_DOWN, signature)
  if not is_invalid_ea(vtable):
    DEBUG("vtable for {} at {:x}".format(name, vtable))
  else:
    vtable = idc.BADADDR
  return ea2, name

def get_si_type_info(ea):
  ea2, name = get_type_info(ea)
  pbase = read_pointer(ea2)
  DEBUG("Format si type info {:x} {:x}".format(pbase, ea2))
  #RTTI_REFERENCE_TABLE[ea2] = _create_reference_object(get_symbol_name(ea2, False), pbase, 0)
  ea2 = next_ea(ea2, "p")
  return ea2

def get_typeinfo_refs(name):
  if name is None or name == "":
    return
  
  name = vtable_symbol(name)
  ea = idc.LocByName(name)
  if is_invalid_ea(ea):
    # try single underscore with the name
    name = name[1:]
    ea = idc.LocByName(name)
    if is_invalid_ea(ea):
      DEBUG("Could not find vtable for {}".format(name))
      return
  
  DEBUG("Found vtable at {:x}".format(ea))
  idx = 0
  ea2 = ea
  while ea2 != idc.BADADDR:
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
        DEBUG("Found {}+{:x} at {:x}".format(name, offset, x))
        RTTI_REFERENCE_TABLE[x] = _create_reference_object(name, ea, offset)
        ea3 = get_si_type_info(x)

    ea2 = idc.LocByName("%s_%d" % (name, idx))
    idx += 1

def recover_rtti():
  DEBUG("Looking for the simple class typeinfo")
  get_typeinfo_refs(typeinfo_names[0])
  get_typeinfo_refs(typeinfo_names[1])
  get_typeinfo_refs(typeinfo_names[2])
  get_typeinfo_refs(typeinfo_names[3])
  DEBUG("{}".format(pprint.pformat(RTTI_REFERENCE_TABLE)))