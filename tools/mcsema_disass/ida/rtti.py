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
 "__ZTVN10__cxxabiv117__class_type_infoE@@CXXABI_1.3",
 "__ZTVN10__cxxabiv120__si_class_type_infoE@@CXXABI_1.3",
 "__ZTVN10__cxxabiv121__vmi_class_type_infoE@@CXXABI_1.3",
]

def get_typeinfo_refs(name):
  if name is None or name == "":
    return
  
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
    xrefs = list(idautils.DataRefsTo(ea))
    ea += get_address_size_in_bytes()*2
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