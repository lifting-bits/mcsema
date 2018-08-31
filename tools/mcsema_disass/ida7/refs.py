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

import ida_bytes
import ida_nalt
from util import *

class Reference(object):
  __slots__ = ('offset', 'ea', 'symbol', 'type', 'mask')

  INVALID = 0
  IMMEDIATE = 1
  DISPLACEMENT = 2
  MEMORY = 3
  CODE = 4

  TYPE_TO_STR = {
    INVALID: "(null)",
    IMMEDIATE: "imm",
    DISPLACEMENT: "disp",
    MEMORY: "mem",
    CODE: "code",
  }

  def __init__(self, ea, offset, mask=0):
    self.offset = offset
    self.ea = ea
    self.symbol = ""
    self.type = self.INVALID
    self.mask = mask

  def __str__(self):
    mask_str = ""
    if self.mask:
      mask_str = " & {:x}".format(self.mask)
    return "({} {} {}{})".format(
      is_code(self.ea) and "code" or "data",
      self.TYPE_TO_STR[self.type],
      self.symbol or "0x{:x}".format(self.ea),
      mask_str)

  def is_valid(self):
    return self.type != self.INVALID

# Try to determine if `ea` points at a field within a structure. This is a
# heuristic for determining whether or not an immediate `ea` should actually
# be treated as a reference. The intuition is that if it points into a logical
# location, then we should treat it as a reference.
def _is_address_of_struct_field(ea):
  prev_head_ea = idc.prev_head(ea)

  if is_invalid_ea(prev_head_ea):
    return False

  prev_item_size = idc.get_item_size(prev_head_ea)
  if ea >= (prev_head_ea + prev_item_size):
    return False

  # Try to get a type for the last item head.
  flags = ida_bytes.get_full_flags(ea)
  ti = ida_nalt.opinfo_t()
  oi = ida_bytes.get_opinfo(ti, ea, 0, flags)
  if not oi:
    return False

  # Get the size of the struct, and keep going if the suze of the previous
  # item is a multiple of the struct's size (e.g. one struct or an array
  # of that struct).
  struct_size = idc.get_struc_size(oi.tid)
  if not struct_size or 0 != (prev_item_size % struct_size):
    return False

  # Figure out the offset of `ea` within its structure, which may belong to
  # an array of structures, and then check if that offset is associated with
  # a named field.
  arr_index = int((ea - prev_head_ea) / struct_size)
  struct_begin_ea = (arr_index & struct_size) + prev_head_ea
  off_in_struct = ea - struct_begin_ea
  if not idc.get_member_name(oi.tid, off_in_struct):
    return False

  field_begin_ea = struct_begin_ea + off_in_struct
  if field_begin_ea != ea:
    return False

  field_size = idc.GetMemberSize(oi.tid, off_in_struct)
  if not field_size:
    return False

  return True

def _make_array_entry(ea, item_size):
  if item_size == 4:
    item_type = idc.FF_DWORD
  elif item_size == 8:
    item_type = idc.FF_QWORD
  else:
    raise ValueError("Invalid item size")

  ida_bytes.create_data(ea, item_type, item_size, ida_idaapi.BADADDR)

# Try to create an array at `ea`, that extends into something that also looks
# like an array down the line. The idea is that sometimes there are arrays,
# but prefixes of those arrays are missed by IDA (curiously, idaq will sometimes
# correctly get these, but idal64 won't). If we find an immediate that looks
# like it could point at an array entry, then we want to treat it as a
# reference. To do that, we may need to make an array.
#
# TODO(pag): For now, we will assume that items must be at least 4 or 8 bytes
#            i.e. pointer or offset sized entries.
#
# TODO(pag): Should we check that all the entries agree in terms of zero-ness?
#            i.e. if the next entry is zero, then everything up to it should be
#            zero, and if the next entry is non-zero, then everything up to it
#            should be non-zero.
def _try_create_array(ea, max_num_entries=8):
  seg_end_ea = idc.get_segm_end(ea)
  next_head_ea = idc.next_head(ea, seg_end_ea)
  if is_invalid_ea(next_head_ea):
    return False

  item_size = idc.get_item_size(next_head_ea)
  diff = next_head_ea - ea
  
  if item_size not in (4, 8) \
  or 0 != (diff % item_size) \
  or max_num_entries < (diff / item_size):
    return False

  next_next_head_ea = idc.next_head(next_head_ea, seg_end_ea)
  if is_invalid_ea(next_head_ea):
    return False

  if (next_next_head_ea - next_head_ea) != item_size:
    return False

  for entry_ea in xrange(ea, next_head_ea, item_size):
    _make_array_entry(entry_ea, item_size)

  return True

# Return `True` if `ea` is nearby to other heads.
def _nearest_head(ea, bounds):
  seg_ea = idc.get_segm_start(ea)
  seg_end_ea = idc.get_segm_end(ea)
  next_head_ea = idc.next_head(ea, seg_end_ea)
  if not is_invalid_ea(next_head_ea) and bounds >= (next_head_ea - ea):
    return next_head_ea

  prev_head_ea = idc.prev_head(ea, seg_ea)
  if not is_invalid_ea(prev_head_ea) and bounds >= (ea - prev_head_ea):
    return prev_head_ea

  return idc.BADADDR

_POSSIBLE_REFS = set()
_REFS = {}
_HAS_NO_REFS = set()
_NO_REFS = tuple()
_ENABLE_CACHING = False
_BAD_ARM_REF_OFF = (idc.BADADDR, 0)
_NOT_A_REF = set()

# Remove a reference from `from_ea` to `to_ea`.
def remove_instruction_reference(from_ea, to_ea):
  global _REFS, _NOT_A_REF

  _NOT_A_REF.add((from_ea, to_ea))

  try:
    idaapi.del_dref(from_ea, to_ea)
    idaapi.del_cref(from_ea, to_ea, False)
    idaapi.del_cref(from_ea, to_ea, True)
  except:
    pass

  if not _ENABLE_CACHING or from_ea not in _REFS:
    return

  new_refs = []
  found = False
  for old_ref in _REFS[from_ea]:
    if old_ref.ea != to_ea:
      new_refs.append(old_ref)
    else:
      found = True

  if found:
    _REFS[from_ea] = tuple(new_refs)

def _get_arm_ref_candidate(mask, op_val, op_str, all_refs):
  global _BAD_ARM_REF_OFF

  try:
    op_name = op_str.split("@")[0][1:]  # `#asc_400E5C@PAGE` -> `asc_400E5C`.
    ref_ea = idc.get_name_ea_simple(op_name)
    if (ref_ea & mask) == op_val:
      return ref_ea, mask
  except:
    pass

  # NOTE(pag): We deal with candidates because it's possible that this
  #            instruction will have multiple references. In the case of
  #            `@PAGE`-based offsets, it's problematic when the wrong base
  #            is matched, because it really throws off the C++ side of things
  #            because the arrangement of the lifted data being on the same
  #            page is not guaranteed.

  candidates = set()
  for ref_ea in all_refs:
    if (ref_ea & mask) == op_val:
      candidates.add(ref_ea)
      return ref_ea, mask

  if len(candidates):
    for candidate_ea in candidates:
      if candidate_ea == op_val:
        return candidate_ea, mask

    return candidates.pop(), mask

  return _BAD_ARM_REF_OFF

# Try to handle `@PAGE` and `@PAGEOFF` references, resolving them to their
# 'intended' address.
#
# TODO(pag): There must be a better way than just string searching :-/
def _try_get_arm_ref_addr(inst, op, op_val, all_refs):
  global _BAD_ARM_REF_OFF

  if op.type not in (idc.o_imm, idc.o_displ):
    # This is a reference type that the other ref tracking code
    # can handle, return defaults
    return op_val, 0

  op_str = idc.GetOpnd(inst.ea, op.n)

  if '@PAGEOFF' in op_str:
    return _get_arm_ref_candidate(4095, op_val, op_str, all_refs)

  elif '@PAGE' in op_str:
    return _get_arm_ref_candidate(-4096L, op_val, op_str, all_refs)

  elif not is_invalid_ea(op_val) and inst.get_canon_mnem().lower() == "adr":
    return op_val, 0

  return _BAD_ARM_REF_OFF

# Returns `True` if `ea` looks like it points into the middle of an instruction.
def _is_ea_into_bad_code(ea, binary_is_pie):
  if not is_code(ea):
    return False

  import flow  # Circular dependency!
  term_inst, _ = flow.find_linear_terminator(ea)
  if not term_inst:
    return True

  succs = list(flow.get_static_successors(idc.BADADDR, term_inst, binary_is_pie))
  if not succs:
    return True

  for succ_ea in succs:
    if is_invalid_ea(succ_ea):
      return True

  return False

# Try to recognize an operand as a reference candidate when a target fixup
# is not available.
def _get_ref_candidate(inst, op, all_refs, binary_is_pie):
  global _POSSIBLE_REFS, _ENABLE_CACHING

  ref = None
  addr_val = idc.BADADDR
  mask = 0
  is_memop = idc.o_mem == op.type

  if idc.o_imm == op.type:
    addr_val = op.value
  elif op.type in (idc.o_displ, idc.o_mem, idc.o_near):
    addr_val = op.addr
  else:
    return None

  # TODO(artem): We should have a class that has ref heuristics and put ARM
  #              related refs in the ARM class, and X86 in the x86 class that
  #              will avoid these awkward `if IS_ARM` and the comments about
  #              x86 / amd64 stuff.
  if IS_ARM:
    old_addr_val = addr_val
    addr_val, mask = _try_get_arm_ref_addr(inst, op, addr_val, all_refs)

  info = idaapi.refinfo_t()
  has_ref_info = ida_nalt.get_refinfo(info, inst.ea, op.n) == 1

  if is_invalid_ea(addr_val) \
    or idc.get_segm_name(idc.get_segm_start(addr_val)) in ["LOAD"]:
    
    # The `addr_val` that we get might actually be a value that is relative to
    # a base address. For example, in IDA we might see:
    #
    #     mov     eax, ds:rva off_1400022FC[r9+r8*4]
    #
    # And we'd get `addr_val` as `0x22FC`, which isn't a valid EA. Here we
    # detect this and fixup the `addr_val` to include the relative base
    # of `0x140000000`.
    if has_ref_info and info.is_rvaoff():
      addr_val += info.base
      if is_invalid_ea(addr_val):
        return None
    else:
      return None
  
  # The address is a direct memory reference.
  if addr_val not in all_refs and is_memop:
    all_refs.add(addr_val)

  if addr_val not in all_refs and is_head(addr_val):
    all_refs.add(addr_val)

  # Some other instruction/data references this thing. Let's assume it's
  # a real thing within this particular instruction.
  if addr_val not in all_refs and is_referenced(addr_val):
    DEBUG("WARNING: Adding reference from {:x} to {:x}, which is referenced by other stuff".format(
        inst.ea, addr_val))
    all_refs.add(addr_val)

  # Curiously, sometimes `idaq` will recognize references that `idal64` will
  # not. It's possible that this is due to configuration options. This happened
  # in SQLite 3, where the `sqlite3_config` function references a field inside
  # of the `sqlite3Config` global structure variable. 
  if addr_val not in all_refs and _is_address_of_struct_field(addr_val):
    DEBUG("WARNING: Adding reference from {:x} to {:x}, which is a struct field".format(
        inst.ea, addr_val))
    all_refs.add(addr_val)

  # Same as above, `idal64` can miss things that `idaq` gets.
  if addr_val not in all_refs:
    nearest_head_ea = _nearest_head(addr_val, 128)
    if not is_invalid_ea(nearest_head_ea) and not _is_ea_into_bad_code(nearest_head_ea, binary_is_pie):
      DEBUG("WARNING: Adding reference from {:x} to {:x}, which is near other heads".format(
          inst.ea, addr_val))
      all_refs.add(addr_val)

  # # Same as above, `idal64` can miss things that `idaq` gets.
  # if addr_val not in all_refs and _try_create_array(addr_val):
  #   all_refs.add(addr_val)

  # The idea here is that if we have seen a possible ref show up more than once,
  # then lets assume it's actually a real reference. This sometimes happens
  # with strings, especially in SQLite3.
  if addr_val not in all_refs and addr_val in _POSSIBLE_REFS:
    all_refs.add(addr_val)
    DEBUG("WARNING: Adding reference from {:x} to {:x}, which appeared other times".format(
        inst.ea, addr_val))

  if addr_val not in all_refs:
    DEBUG("POSSIBLE ERROR: Not adding reference from {:x} to {:x}; candidates were {}; operand type is {}, has ref info is {}".format(
        inst.ea, addr_val, " ".join("{:x}".format(r) for r in all_refs), op.type, has_ref_info))
    _POSSIBLE_REFS.add(addr_val)
    return None

  ref = Reference(addr_val, op.offb, mask=mask)

  # Make sure we add in a reference to the (possibly new) head, addressed
  # by `addr_val`.
  make_head(addr_val)

  # WTF(pag): This silently kills IDA.
  # idc.add_dref(inst.ea, addr_val, idc.XREF_USER)

  return ref

def memop_is_actually_displacement(inst):
  """IDA will unhelpfully decode something like `jmp ds:off_48A5F0[rax*8]`
  and tell us that this is an `o_mem` rather than an `o_displ`. We really want
  to recognize it as an `o_displ` because the memory reference is a displacement
  and not an absolute address."""
  asm = idc.GetDisasm(inst.ea)
  return "[" in asm and "]" in asm

# Return the set of all references from `ea` to anything.
def get_all_references_from(ea):
  return set(xrefs_from(ea))

# This is a real hack. It can take a few tries to really find references, so
# we'll only enable reference caching after we do some processing of segments.
# Hopefully after such processing, we will have discovered item heads that IDA
# hadn't previously identified. Curiosly, `idaq` will sometimes recognize
# references or item heads that `idal64` does not.
def enable_reference_caching():
  global _ENABLE_CACHING
  _ENABLE_CACHING = True

# Get a list of references from an instruction.
def get_instruction_references(arg, binary_is_pie=False):
  global _ENABLE_CACHING, _NOT_A_REF

  inst = arg
  if isinstance(arg, (int, long)):
    inst, _ = decode_instruction(arg)
  
  if not inst:
    return _NO_REFS

  if _ENABLE_CACHING:
    if inst.ea in _HAS_NO_REFS:
      return _NO_REFS

    if inst.ea in _REFS:
      return _REFS[inst.ea]

  offset_to_ref = {}
  all_refs = get_all_references_from(inst.ea)
  for ea in xrange(inst.ea, inst.ea + inst.size):
    targ_ea = idc.get_fixup_target_off(ea)
    if not is_invalid_ea(targ_ea):
      all_refs.add(targ_ea)
      ref = Reference(targ_ea, ea - inst.ea)
      offset_to_ref[ref.offset] = ref

  refs = []
  for i, op in enumerate(inst.ops):
    if not op.type:
      continue

    op_ea = inst.ea + op.offb
    ref = None
    if op.offb in offset_to_ref:
      ref = offset_to_ref[op.offb]
    
    if not ref or is_invalid_ea(ref.ea):
      ref = _get_ref_candidate(inst, op, all_refs, binary_is_pie)

    if not ref or is_invalid_ea(ref.ea):
      continue

    # Immediate constant, may be the absolute address of a data reference.
    if idc.o_imm == op.type:
      seg_begin = idaapi.getseg(ref.ea)
      seg_end = idaapi.getseg(ref.ea + idc.get_item_size(ref.ea) - 1)

      # If the immediate constant is not within a segment, or crosses
      # two segments then don't treat it as a reference.
      if not seg_begin or not seg_end or seg_begin.start_ea != seg_end.start_ea:
        idaapi.del_dref(op_ea, op.value)
        idaapi.del_cref(op_ea, op.value, False)
        continue

      # If this is a PIE-mode, 64-bit binary, then most likely the immediate
      # operand is not a data ref. 
      if seg_begin.use64() and binary_is_pie:
        idaapi.del_dref(op_ea, op.value)
        idaapi.del_cref(op_ea, op.value, False)
        continue

      # In the special case of "ADR" and "ADRP" instructions for aarch64
      # IDA infers the absolute immediate value to assign as op_type, rather
      # than characterizing it as a displacement from PC
      if idc.print_insn_mnem(inst.ea) in ["ADRP", "ADR"]:
         ref.type = Reference.DISPLACEMENT
      else:
         ref.type = Reference.IMMEDIATE

      ref.symbol = get_symbol_name(op_ea, ref.ea)

    # Displacement within a memory operand, excluding PC-relative
    # displacements when those are memory references.
    #
    # Note: ref.ea may not be op.addr, this happens on AArch64 with
    #       @PAGE and @PAGEOFF memory operands.
    elif idc.o_displ == op.type:
      ref.type = Reference.DISPLACEMENT
      ref.symbol = get_symbol_name(op_ea, ref.ea)

    # Absolute memory reference, and PC-relative memory reference. These
    # are references that IDA can recognize statically.
    elif idc.o_mem == op.type:
      assert ref.ea == op.addr
      if memop_is_actually_displacement(inst):
        ref.type = Reference.DISPLACEMENT
      else:
        ref.type = Reference.MEMORY
      ref.symbol = get_symbol_name(op_ea, ref.ea)

    # Code reference.
    elif idc.o_near == op.type:
      assert ref.ea == op.addr
      ref.type = Reference.CODE
      ref.symbol = get_symbol_name(op_ea, ref.ea)

    # TODO(pag): Not sure what to do with this yet.
    elif idc.o_far == op.type:
      DEBUG("ERROR inst={:x}\ntarget={:x}\nsym={}".format(
          inst.ea, ref.ea, get_symbol_name(op_ea, ref.ea)))
      assert False

    # Note: idc.o_phrase is ignored because it doesn't have a displacement,
    #       and so can't reference a specific symbol.

    if (inst.ea, ref.ea) not in _NOT_A_REF:
      refs.append(ref)

  for ref in refs:
    assert not is_invalid_ea(ref.ea)

  if len(refs):
    refs = tuple(refs)
    if _ENABLE_CACHING:
      _REFS[inst.ea] = refs
    return refs
  else:
    if _ENABLE_CACHING:
      _HAS_NO_REFS.add(inst.ea)
    return _NO_REFS
