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

from flow import *
from table import *
import ida_bytes

def is_sane_reference_target(ea):
  """Returns `True` if `target_ea` looks like the address of some code/data."""
  if is_invalid_ea(ea):
    return False

  flags = idc.get_full_flags(ea)
  if idaapi.is_align(flags):
    return False

  if idc.is_head(flags):
    return True

  if has_string_type(ea):
    return True

  if idc.is_tail(flags):
    head_ea = idc.prev_head(ea)
    if has_string_type(head_ea):
      return True    

  # TODO(pag): Check if it points at a logical element in an array, or at a
  #            field of a struct.

  if idc.is_code(flags):
    return is_block_or_instruction_head(ea)

  if is_referenced(ea):
    return True

  # NOTE(pag): We test `idc.is_code` above; this check looks to see if the
  #            segment itself is a code segment. This check happens after
  #            `is_referenced`, because we may have something like a vtable
  #            embedded in a code segment.
  if is_code(ea):
    return False


  #item_size = idc.get_item_size(ea)

  # If the byte has value but no other flag is set
  # This is possibly not a true reference target
  if not IS_ARM and not IS_SPARC:
    if (flags == idc.FF_IVL) \
      or (flags == idc.FF_UNK) \
      or (flags == 0xfff00300):
      return False

  #DEBUG("!!! target_ea = {:x} item_size = {}".format(ea, item_size))
  #return 1 != item_size
  #NOTE(artem): Above lines commented out since they caused problems
  # and we cannot determine what they fixed. If this code has problems
  # again, consider a solution that handles both cases properly
  return True

def is_read_only_segment(ea):
  seg_ea = idc.get_segm_start(ea)
  seg = idaapi.getseg(seg_ea)

  if not seg:
    return False

  return (seg.perm & idaapi.SEGPERM_WRITE) == 0

_NOT_STRING_TYPE_EAS = set()

# TODO(pag): Why does the following get treated as a string with type `48326`?
#
# ; struct _EXCEPTION_POINTERS ExceptionInfo
# ExceptionInfo   _EXCEPTION_POINTERS <offset dword_5CCFB8, offset dword_5CD008>
def has_string_type(ea):
  global _NOT_STRING_TYPE_EAS
  if ea in _NOT_STRING_TYPE_EAS:
    return False

  if not is_read_only_segment(ea):
    return False

  str_type = idc.get_str_type(ea)
  return (str_type is not None) and str_type != -1

def next_reasonable_head(ea, max_ea):
  """Returns the next 'reasonable' head, skipping over alignments. One heuristic
  for matching strings is to see if there's an unmatched string between two
  matched ones. If the next logical head is a string, but the actual head is
  an alignment, then we really want to find the head of the string.

  TODO(pag): Investigate using `ida_bytes.next_not_tail(ea)`."""
  while ea < max_ea:
    ea = idc.next_head(ea, max_ea)
    flags = idc.get_full_flags(ea)
    if not idaapi.is_align(flags):
      return ea

  return idc.BADADDR

def find_missing_strings_in_segment(seg_ea, seg_end_ea):
  """Try to find and mark missing strings in this segment."""
  global _NOT_STRING_TYPE_EAS
  end_ea = idc.get_segm_end(seg_ea)
  ea, next_ea = seg_ea, seg_ea
  last_was_string = False

  while next_ea < end_ea:
    next_head_ea = next_reasonable_head(next_ea, seg_end_ea)
    ea, next_ea = next_ea, next_head_ea
    item_size = idc.get_item_size(ea)
    if is_jump_table_entry(ea):
      DEBUG("Found jump table at {:x}, jumping to {:x}".format(ea, next_ea))
      continue

    next_is_string = has_string_type(next_head_ea)

    as_str = idc.get_strlit_contents(ea, -1, -1)
    if has_string_type(ea):
      if as_str is not None and len(as_str):
        next_ea = ea + item_size
        last_was_string = True
        DEBUG("Found string {} of length {} at {:x}, jumping to {:x}".format(
            repr(as_str), item_size, ea, next_ea))
        make_head(ea)
        continue
      else:
        _NOT_STRING_TYPE_EAS.add(ea)

    # If we find a zero, then assume it's possibly padding between strings, and
    # so don't change the state of `last_was_string`.
    if 0 == read_byte(ea):
      next_ea = ea + 1
      continue

    if as_str is None or not len(as_str):
      last_was_string = False
      continue

    # The references of variable are getting identified and converted
    # into string; avoid that
    if last_was_string and  is_reference(ea):
      item_size = idc.get_item_size(ea)
      next_ea = ea + item_size
      last_was_string = False

    # A bit aggressive, but lets try to make it into a string.
    if last_was_string and 1 < len(as_str) and not is_reference(ea):
      old_item_size = idc.get_item_size(ea)      
      if 1 != idc.create_strlit(ea, idc.BADADDR):
        last_was_string = False
        continue

      item_size = idc.get_item_size(ea)
      next_ea = ea + item_size
      last_was_string = True

      if 1 != old_item_size or not is_referenced(ea):
        DEBUG("WARNING: Made {:x} into a string of length {}".format(ea, item_size))
      continue

    # Clear the `last_was_string` flag
    last_was_string = False

    # # Look for one string squashed between another. Compilers tend to place
    # # all strings together, and sometimes IDA misses some of the intermediate
    # # ones when they aren't directly referenced.
    # if last_was_string and next_is_string:
    #   max_str_len = (next_head_ea - ea)
    #   if 1 != idc.create_strlit(ea, idc.BADADDR):
    #     last_was_string = False
    #     continue

    #   item_size = idc.get_item_size(ea)
    #   DEBUG("Inferred string {} of length {} at {:x} to {:x}".format(
    #       repr(as_str), item_size, ea, next_head_ea))
    #   make_head(ea)
    #   next_ea = ea + item_size
    #   last_was_string = True

def remaining_item_size(ea):
  flags = idc.get_full_flags(ea)
  size = idc.get_item_size(ea)
  if idc.is_head(flags):
    return size

  head_ea = idc.prev_head(ea, max(0, ea - size))
  if is_invalid_ea(head_ea):
    return 0
  assert (head_ea + size) >= ea
  return (head_ea + size) - ea


_POPCOUNT_TABLE8 = [0] * 2**8
for index in xrange(len(_POPCOUNT_TABLE8)):
  _POPCOUNT_TABLE8[index] = (index & 1) + _POPCOUNT_TABLE8[index >> 1]

def _popcount(v):
  v = struct.unpack("=Q", struct.pack("=Q", v))[0]
  count = 0
  while v:
    count += _POPCOUNT_TABLE8[v & 0xff]
    v = v >> 8
  return count

def find_missing_xrefs_in_segment(seg_ea, seg_end_ea, binary_is_pie):
  """Look for cross-refernces that were missed by IDA. This function assumes
  a natural alignments for pointers (i.e. 4- or 8-byte alignment)."""

  addr_size_bits = get_address_size_in_bits()

  seg_ea = (seg_ea + 3) & ~3  # Align to a 4-byte boundary.

  try_qwords = addr_size_bits == 64
  try_dwords = True
  if try_qwords and binary_is_pie:
    try_dwords = False

  pointer_size = try_qwords and 8 or 4
  ea, next_ea = idc.BADADDR, seg_ea

  missing_refs = []

  maybe_jump_table_entries = []

  while next_ea < seg_end_ea:
    ea, next_ea = next_ea, idc.BADADDR
    if is_invalid_ea(ea):
      break

    flags = idc.get_full_flags(ea)

    # Jump over strings.
    if has_string_type(ea):
      item_size = max(1, remaining_item_size(ea))  # Guarantee forward progress.
      next_ea = ea + item_size
      DEBUG("Found string at {:x}, jumping to {:x}".format(ea, next_ea))
      continue

    if (ea % 4) != 0:
      next_ea = (ea + 3) & ~3
      DEBUG("Aligning from {:x} to {:x}".format(ea, next_ea))
      assert ea < next_ea
      continue

    fixup_ea = idc.get_fixup_target_off(ea)
    if binary_is_pie and not is_sane_reference_target(fixup_ea):
      # This {d|q}word was not a fixup, try the next one
      next_ea = ea + pointer_size
      continue

    qword_data, dword_data = 0, 0

    # Minimum number of set bits for something to be considered an address.
    MIN_NUM_SET_BITS = 1

    # Try to read it as an 8-byte pointer.
    if try_qwords and (ea + 8) <= seg_end_ea:
      target_ea = qword_data = read_qword(ea)
      if is_sane_reference_target(target_ea):
        if MIN_NUM_SET_BITS >= _popcount(target_ea):
          DEBUG("Ignoring possible qword reference from {:x} to {:x}: not enough set bits".format(
              ea, target_ea))

        elif make_dref(ea, target_ea, ida_bytes.FF_QWORD, 8):
          if is_block_or_instruction_head(target_ea):
            maybe_jump_table_entries.append((ea, 8))
          DEBUG("Adding qword reference from {:x} to {:x}".format(ea, target_ea))
          next_ea = ea + 8
          continue

    # Try to read it as a 4-byte pointer.
    if try_dwords and (ea + 4) <= seg_end_ea:
      target_ea = dword_data = read_dword(ea)
      if is_sane_reference_target(target_ea):
        if make_dref(ea, target_ea, idc.FF_DWORD, 4):
          DEBUG("Adding dword reference from {:x} to {:x}".format(ea, target_ea))
          if is_block_or_instruction_head(target_ea):
            maybe_jump_table_entries.append((ea, 4))
          next_ea = ea + 4
          continue

    # We've got a reference from here; it might actually be that we're inside
    # of a larger thing (e.g. an array, or struct) and so this reference target
    # doesn't belong to `ea`, but really a nearby `ea`. Let's go and remove it.
    target_ea = get_reference_target(ea)
    if not is_invalid_ea(target_ea) and 0 != (qword_data | dword_data):
      DEBUG("WARNING: Removing likely in-object reference from nearby {:x} to {:x}".format(
          ea, target_ea))
      ida_bytes.del_items(ea, 4, ida_bytes.DELIT_EXPAND)

    next_ea = ea + 4

  DEBUG("Stopping scan at {:x}".format(ea))

  # Look for missed jump tables.
  for (entry_ea, entry_size) in maybe_jump_table_entries:
    if is_jump_table_entry(entry_ea):
      continue
    inst_ea = None
    for maybe_inst_ea in xrefs_to(entry_ea):
      if is_block_or_instruction_head(maybe_inst_ea):
        inst_ea = maybe_inst_ea
        break
    if not inst_ea:
      continue

    DEBUG("Investigating possibly missed jump table at {:x} referenced by {:x}".format(
        entry_ea, inst_ea))
    try_create_jump_table(inst_ea, entry_ea, entry_size, binary_is_pie)


def _next_code_or_jt_ea(ea):
  """Scan forward looking for the next non-data effective address."""
  seg_end_ea = idc.get_segm_end(ea)
  while ea <= seg_end_ea:
    flags = idc.get_full_flags(ea)
    if idc.is_code(flags):
      break
    if is_jump_table_entry(ea):
      break
    ea += 1
  return ea

def find_missing_xrefs_in_code_segment(seg_ea, seg_end_ea, binary_is_pie):
  """Looks for data cross-references in a code segment."""
  ea, next_ea = seg_ea, seg_ea
  while next_ea < seg_end_ea:
    ea = next_ea

    if is_jump_table_entry(ea):
      next_ea = ea + 1
      continue

    # This manifests in AArch64 as something like:
    #
    #     .text:00400488                 LDR             X0, =main
    #     .text:0040048C                 LDR             X3, =__libc_csu_init
    #     .text:00400490                 LDR             X4, =__libc_csu_fini
    #     .text:00400494                 BL              .__libc_start_main
    #     .text:00400498                 BL              .abort
    #     .text:00400498 ; End of function _start
    #     .text:00400498
    #     .text:00400498 ; ----------------------------------------------------
    #     .text:0040049C                 ALIGN 0x20
    #     .text:004004A0 off_4004A0      DCQ main           
    #     .text:004004A8 off_4004A8      DCQ __libc_csu_init
    #     .text:004004B0 off_4004B0      DCQ __libc_csu_fini
    #
    # Where the `LDR` references a nearby slot in the `.text` segment wherein
    # there is a reference to the real function.
    #
    # In x86, we see this behavior with embedded exception tables. This comes
    # up a bunch in Windows binaries.
    flags = idc.get_full_flags(ea)
    if idc.is_data(flags):
      next_ea = _next_code_or_jt_ea(ea + 1)
      find_missing_xrefs_in_segment(ea, next_ea, binary_is_pie)
      continue

    else:
      next_ea = idc.next_head(ea)
      continue

  DEBUG_POP()

def decode_segment_instructions(seg_ea, binary_is_pie):
  """Tries to find all jump tables ahead of time. A side-effect of this is to
  create a decoded instruction and jump table cache. The other side-effect is
  that the decoding of jump tables will *remove* some cross-references."""
  seg_end_ea = idc.get_segm_end(seg_ea)
  for head_ea in idautils.Heads(seg_ea, seg_end_ea):
    inst, _ = decode_instruction(head_ea)
    if inst:
      get_instruction_references(inst, binary_is_pie)
      table = get_jump_table(inst, binary_is_pie)

  for funcea in idautils.Functions(seg_ea, seg_end_ea):
    find_default_block_heads(funcea)


# NOTE(artem): IDA7 will add "LOAD" segments for parts of the program
# loaded into memory but not defined in a section. Ignore these since
# for normal compiler generated applications they provide no benefit
# but add lots of extra noise
def is_invalid_or_load_segment(ea):
  """Returns true if the segment's start ea is invalid, or if it's
     a "LOAD" segment made by IDA7"""
  seg_name = idc.get_segm_name(ea)
  return is_invalid_ea(ea) or "LOAD" == seg_name

def process_segments(binary_is_pie):
  """Pre-process a segment and try to fill in as many cross-references
  as is possible."""

  seg_eas = [ea for ea in idautils.Segments() if not is_invalid_or_load_segment(ea)]

  # Go through through the data segments and look for strings, and through the
  # code segments and look for instructions. One result is that we should find
  # and identify jump tables, which we need to do so that we don't incorrectly
  # categorize some things as strings.
  for seg_ea in seg_eas:
    seg_name = idc.get_segm_name(seg_ea)
    seg_end_ea = idc.get_segm_end(seg_ea)
    if is_code(seg_ea):
      DEBUG("Looking for instructions in segment {}".format(seg_name))
      DEBUG_PUSH()
      decode_segment_instructions(seg_ea, binary_is_pie)
      DEBUG_POP()
    else:
      DEBUG("Looking for strings in segment {} [{:x}, {:x})".format(
          seg_name, seg_ea, seg_end_ea))
      DEBUG_PUSH()
      find_missing_strings_in_segment(seg_ea, seg_end_ea)
      DEBUG_POP()

  # Now go through through the data segments and find missing cross-references.
  for seg_ea in seg_eas:
    seg_name = idc.get_segm_name(seg_ea)
    seg_end_ea = idc.get_segm_end(seg_ea)
    DEBUG("Looking for cross-references in segment {} [{:x}, {:x})".format(
        seg_name, seg_ea, seg_end_ea))

    DEBUG_PUSH()
    if is_code(seg_ea):
      find_missing_xrefs_in_code_segment(seg_ea, seg_end_ea, binary_is_pie)
    else:
      find_missing_xrefs_in_segment(seg_ea, seg_end_ea, binary_is_pie)
    DEBUG_POP()

  # Okay, hopefully by this point we've been able to introduce more information
  # so that IDA can better find references. We'll enable caching of instruction
  # references from now on so that we don't need to repeat too much work.
  enable_reference_caching()
