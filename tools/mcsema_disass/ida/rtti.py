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

from util import *

typeinfo_names = [
 "St9type_info@@CXXABI_1.3",
 "N10__cxxabiv117__class_type_infoE@@CXXABI_1.3",
 "N10__cxxabiv120__si_class_type_infoE@@CXXABI_1.3",
 "N10__cxxabiv121__vmi_class_type_infoE@@CXXABI_1.3",
]

def vtable_symbol(name):
  return "__ZTV" + name

def first(val):
  return idc.FindBinary(0, idc.SEARCH_CASE|idc.SEARCH_DOWN, read_qword(val))

def next(val, ref):
  return idc.FindBinary(ref+1, idc.SEARCH_CASE|idc.SEARCH_DOWN, read_qword(val))

def find_xrefs(addr):
  lrefs = list(idautils.DataRefsTo(addr))
  if len(lrefs) == 0:
    lrefs = list(idautils.refs(addr, first, next))

  lrefs = [r for r in lrefs if not idc.isCode(idc.GetFlags(r))]
  return lrefs

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
  while ea != idc.BADADDR:
    DEBUG("Looking for refs to vtable {:x}".format(ea))
    if idaapi.is_spec_ea(ea):
      DEBUG("Handling special ea")
      xrefs = find_xrefs(ea)
      ea += get_address_size_in_bytes()*2
      xrefs.extend(find_xrefs(ea))
    else:
      ea += get_address_size_in_bytes()*2
      xrefs = find_xrefs(ea)

    for x in xrefs:
      if not is_invalid_ea(x):
        DEBUG("Found {} at {:x}".format(name, x))

    ea = idc.LocByName("%s_%d" % (name, idx))
    idx += 1

def recover_rtti():
  DEBUG("Looking for the simple class typeinfo")
  get_typeinfo_refs(typeinfo_names[0])
  get_typeinfo_refs(typeinfo_names[1])
  get_typeinfo_refs(typeinfo_names[2])
  get_typeinfo_refs(typeinfo_names[3])