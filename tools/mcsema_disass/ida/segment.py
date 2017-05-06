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

from flow import *
from table import *

def is_sane_reference(target_ea):
  """Returns `True` if `target_ea` looks like the address of some code/data."""
  if target_ea == idc.BADADDR:
    return False

  target_flags = idc.GetFlags(target_ea)

  if idaapi.isAlign(target_flags):
    return False

  if not is_code(target_ea):
    # TODO(pag):  If it's a tail then it would be reasonable to check if it's
    #             a pointer to a field in a struct. Not sure how to check that.
    if idc.isHead(target_flags) or idc.isTail(target_flags):
      return True

  if is_block_or_instruction_head(target_ea):
    return True

  return is_referenced(target_ea)

def make_xref(from_ea, to_ea, xref_constructor):
  """Force the data at `from_ea` to reference the data at `to_ea`."""
  if not idc.GetFlags(to_ea):
    DEBUG("  Not making reference from {:x} to {:x}".format(from_ea, to_ea))
    return

  make_head(to_ea)
  xref_constructor(from_ea)
  if is_code(to_ea):
    DEBUG("  Making code reference from {:x} to {:x}".format(from_ea, to_ea))
    idc.AddCodeXref(from_ea, to_ea, idc.XREF_USER | idc.fl_F)
  else:
    DEBUG("  Making data reference from {:x} to {:x}".format(from_ea, to_ea))
    idc.add_dref(from_ea, to_ea, idc.XREF_USER | idc.dr_O)

def has_string_type(ea):
  str_type = idc.GetStringType(ea)
  return (str_type is not None) and str_type != -1

def next_reasonable_head(ea, max_ea):
  """Returns the next 'reasonable' head, skipping over alignments. One heuristic
  for matching strings is to see if there's an unmatched string between two
  matched ones. If the next logical head is a string, but the actual head is
  an alignment, then we really want to find the head of the string.

  TODO(pag): Investigate using `idc.NextNotTail(ea)`."""
  while ea < max_ea:
    ea = idc.NextHead(ea, max_ea)
    flags = idc.GetFlags(ea)
    if not idaapi.isAlign(flags):
      return ea

  return idc.BADADDR

def find_missing_strings_in_segment(seg_ea, seg_end_ea):
  """Try to find and mark missing strings in this segment."""
  end_ea = idc.SegEnd(seg_ea)
  ea, next_ea = seg_ea, seg_ea
  last_was_string = False

  while next_ea < end_ea:
    next_head_ea = next_reasonable_head(next_ea, seg_end_ea)
    ea, next_ea = next_ea, next_head_ea
    item_size = idc.ItemSize(ea)
    if is_jump_table_entry(ea):
      DEBUG("Found jump table at {:x}, jumping to {:x}".format(ea, next_ea))
      continue

    next_is_string = has_string_type(next_head_ea)

    has_str_type = has_string_type(ea)
    if has_str_type:
      next_ea = ea + item_size
      last_was_string = True
      DEBUG("Found string {} of length {} at {:x}, jumping to {:x}".format(
          repr(idc.GetString(ea, -1, -1)), item_size, ea, next_ea))
      make_head(ea)
      continue

    # If we find a zero, then assume it's possibly padding between strings, and
    # so don't change the state of `last_was_string`.
    if 0 == read_byte(ea):
      next_ea = ea + 1
      continue

    as_str = idc.GetString(ea, -1, -1)
    if not as_str or not len(as_str):
      last_was_string = False
      continue

    # This thing was referenced, and it may be a string.
    if is_referenced(ea) and last_was_string and 1 == item_size and 1 < len(as_str):
      if 1 != idc.MakeStr(ea, idc.BADADDR):
        last_was_string = False
        continue
      item_size = idc.ItemSize(ea)
      next_ea = ea + item_size
      last_was_string = True
      continue

    # Look for one string squashed between another. Compilers tend to place
    # all strings together, and sometimes IDA misses some of the intermediate
    # ones when they aren't directly referenced.
    if last_was_string and next_is_string:
      max_str_len = (next_head_ea - ea)
      if 1 != idc.MakeStr(ea, idc.BADADDR):
        last_was_string = False
        continue

      item_size = idc.ItemSize(ea)
      DEBUG("Inferred string {} of length {} at {:x} to {:x}".format(
          repr(as_str), item_size, ea, next_head_ea))
      make_head(ea)
      next_ea = ea + item_size
      last_was_string = True

def find_missing_xrefs_in_segment(seg_ea, seg_end_ea):
  """Look for cross-refernces that were missed by IDA. This function assumes
  a natural alignments for pointers (i.e. 4- or 8-byte alignment)."""
  assert 0 == (seg_ea % 4)

  end_ea = idc.SegEnd(seg_ea)
  try_qwords = get_address_size_in_bits() == 64
  pointer_size = try_qwords and 8 or 4
  ea, next_ea = seg_ea, seg_ea

  while next_ea < end_ea:
    ea, next_ea = next_ea, next_ea + 4
    item_size = idc.ItemSize(ea)

    # Jump over strings.
    has_str_type = has_string_type(ea)
    if has_str_type:
      next_ea = ea + item_size
      continue

    next_head_ea = next_reasonable_head(ea, seg_end_ea)

    # If this thing is referenced then lets assume that IDA has already
    # determined whether or not it contains an xref.
    if is_referenced(ea):
      DEBUG("Data at {:x} is referenced, item size is {}, jumping to {:x}".format(
        ea, item_size, next_ea))
      next_ea = ea + max(item_size, 4)
      continue

    # Check if there's enough space between here and the next thing. If not,
    # then don't make a reference.
    if 4 > (next_head_ea - ea):
      next_ea = next_head_ea
      DEBUG("Jumping to nearby next head {:x}".format(next_head_ea))
      continue

    if (ea % 4) != 0:
      next_aligned_ea = (ea + 3) & ~3
      next_ea = min(next_head_ea, next_aligned_ea)
      DEBUG("Aligning from {:x} to {:x}".format(ea, next_ea))
      assert ea < next_ea
      continue

    xref_size = max(4, min(item_size, pointer_size))
    if is_reference(ea):
      assert xref_size == 4 or xref_size == 8

      # If the 4- and 8-byte pointer values of this reference are the same,
      # then extend it to be an 8-byte pointer.
      if try_qwords:
        if 4 == xref_size:
          target_ea = read_dword(ea)
          if read_qword(ea) == target_ea and not is_referenced(ea + 4):
            make_xref(ea, target_ea, idc.MakeQword)
            xref_size = 8
            DEBUG("Expanded xref size at {:x} to 8 bytes".format(ea))

      # Jump ahead to a reasonable alignment
      next_ea = ea + xref_size
      DEBUG("Found reference at {:x} of size {}, jumping to {:x}".format(
          ea, item_size, next_ea))
      continue

    # Try to read it as an 8-byte pointer.
    if try_qwords and (ea + 8) <= end_ea:
      target_ea = read_qword(ea)
      if is_sane_reference(target_ea):
        make_xref(ea, target_ea, idc.MakeQword)
        next_ea += 4
        continue

    # Try to read it as a 4-byte pointer.
    if (ea + 4) <= end_ea:
      target_ea = read_dword(ea)
      if is_sane_reference(target_ea):
        make_xref(ea, target_ea, idc.MakeDword)
        continue

def decode_segment_instructions(seg_ea, binary_is_pie):
  """Tries to find all jump tables ahead of time. A side-effect of this is to
  create a decoded instruction and jump table cache. The other side-effect is
  that the decoding of jump tables will *remove* some cross-references."""
  seg_end_ea = idc.SegEnd(seg_ea)
  for head in idautils.Heads(seg_ea, seg_end_ea):
    inst, _ = decode_instruction(head)
    get_instruction_references(inst, binary_is_pie)
    table = get_jump_table(inst, binary_is_pie)

  for funcea in idautils.Functions(seg_ea, seg_end_ea):
    find_default_block_heads(funcea)

def process_segments(binary_is_pie):
  """Pre-process a segment and try to fill in as many cross-references
  as is possible."""

  # Start by going through all instructions. One result is that we should find
  # and identify jump tables, which we need to do so that we don't incorrectly
  # categorize some things as strings.
  for seg_ea in idautils.Segments():
    seg_type = idc.GetSegmentAttr(seg_ea, idc.SEGATTR_TYPE)
    seg_name = idc.SegName(seg_ea)
    seg_end_ea = idc.SegEnd(seg_ea)
    if seg_type == idc.SEG_CODE:
      DEBUG("Looking for instructions in segment {}".format(seg_name))
      DEBUG_PUSH()
      decode_segment_instructions(seg_ea, binary_is_pie)
      DEBUG_POP()

  # Now go through through the data segments and look for strings and missing
  # cross-references.
  for seg_ea in idautils.Segments():
    seg_type = idc.GetSegmentAttr(seg_ea, idc.SEGATTR_TYPE)
    seg_name = idc.SegName(seg_ea)
    seg_end_ea = idc.SegEnd(seg_ea)

    if seg_type == idc.SEG_CODE:
      continue

    DEBUG("Looking for strings in segment {}".format(seg_name))
    DEBUG_PUSH()
    find_missing_strings_in_segment(seg_ea, seg_end_ea)
    DEBUG_POP()

    # Ignore PIE binaries when scanning for cross-references that IDA may
    # have missed. The idea here is that there would be no hard-coded cross-
    # referenced addresses -- instead they would be offsets that are
    # indistinguishable from numbers.
    if not binary_is_pie:
      DEBUG("Looking for cross-references in segment {}".format(seg_name))
      DEBUG_PUSH()
      find_missing_xrefs_in_segment(seg_ea, seg_end_ea)
      DEBUG_POP()

  # Okay, hopefully by this point we've been able to introduce more information
  # so that IDA can better find references. We'll enable caching of instruction
  # references from now on so that we don't need to repeat too much work.
  enable_reference_caching()
