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

from refs import *

_FIRST_JUMP_TABLE_ENTRY = {}
_JUMP_TABLE_ENTRY = {}

class JumpTable(object):
  """Represents generic info known about a particular jump table."""

  def __init__(self, builder, entries):
    global _FIRST_JUMP_TABLE_ENTRY, _JUMP_TABLE_ENTRY
    self.inst_ea = builder.jump_ea
    self.table_ea = builder.table_ea
    self.offset = builder.offset
    self.offset_mult = builder.offset_mult
    self.entry_size = builder.entry_size
    self.entry_mult = builder.entry_mult
    self.entries = entries

    max_ea = self.table_ea
    data_flags = (4 == self.entry_size) and idc.FF_DWORD or idc.FF_QWORD

    # Update IDA's understanding of the flow of control out of the jump
    # instruction, as well as references to/from the table.
    for entry_ea, target_ea in entries.items():
      idc.add_cref(self.inst_ea, target_ea, idc.XREF_USER | idc.fl_JN)
      max_ea = max(max_ea, entry_ea + self.entry_size)
    
    # Make sure each entry is seen as referenced.
    for entry_ea, target_ea in entries.items():
      idc.add_dref(self.inst_ea, entry_ea, idc.dr_I)

    # Make sure that the contents of the table are no longer considered
    # code (only affects `is_code`). This is only meaningful if the table
    # itself is embedded in a code segment.
    for ea_into_table in xrange(self.table_ea, max_ea):
      mark_as_not_code(ea_into_table)
      _FIRST_JUMP_TABLE_ENTRY[ea_into_table] = self.table_ea

    _JUMP_TABLE_ENTRY[self.table_ea] = self
    idaapi.auto_wait()

class JumpTableBuilder(object):
  _READERS = {
      4: read_dword,
      8: read_qword
  }

  def __init__(self, inst, binary_is_pie):
    self.entry_size = 0
    self.entry_mult = 1
    self.table_ea = idc.BADADDR
    self.offset = 0
    self.offset_mult = 1
    self.jump_ea = inst.ea
    self.inst = inst
    self.binary_is_pie = binary_is_pie
    self.candidate_target_eas = []

  def read_entry(self, entry_ea):
    data = (self._READERS[self.entry_size])(entry_ea)
    data &= ((1 << (self.entry_size * 8)) - 1)
    data += self.offset * self.offset_mult
    data &= 0xFFFFFFFFFFFFFFFF
    if 4 == self.entry_size and (self.offset & 0xFFFFFFFF) == self.offset:
      data &= 0xFFFFFFFF

    return data

def get_default_jump_table_entries(builder):
  """Return the 'default' jump table entries, based on IDA's ability to
  recognize a jump table. If IDA doesn't recognize the table, then we
  say that there are 0 entries, but we also return what we have inferred
  to be the first entry."""
  si = ida_nalt.get_switch_info(builder.jump_ea)
  if si:
    next_addr = builder.table_ea
    for i in xrange(si.get_jtable_size()):
      target_ea = builder.read_entry(next_addr)
      builder.candidate_target_eas.append(target_ea)
      next_addr += builder.entry_size
  else:
    builder.candidate_target_eas.append(builder.read_entry(builder.table_ea))

def get_num_jump_table_entries(builder):
  """Try to get the number of entries in a jump table. This will use some
  base set of entries."""
  curr_num_targets = len(builder.candidate_target_eas)

  DEBUG("Checking if jump table at {:x} has more than {} entries".format(
      builder.table_ea, curr_num_targets))

  # Use the bounds of the function containing the jump instruction as our
  # initial bounds for candidate jump table targets.
  min_ea, max_ea = get_function_bounds(builder.jump_ea)
  orig_min_ea, orig_max_ea = min_ea, max_ea

  # Treat the current set of targets as candidates, even if the source of
  # those targets is IDA. We will assume that jump table entries point within
  # a given function, or within nearby functions that IDA believes to be
  # different (but hopefully are logically the same). So we will get bounds
  # on the range of possible targets based on the function(s) containing the
  # candidates, and use that as a scanning heuristic to find missing entries.
  last_target_func = None
  for i, curr_target in enumerate(builder.candidate_target_eas):
    is_sane_target = is_block_or_instruction_head(curr_target)
    if not is_sane_target:
      DEBUG("  ERROR jump table {:x} entry candidate {} target {:x} is not sane!".format(
          builder.table_ea, i, curr_target))
      continue

    targ_min_ea, targ_max_ea = get_function_bounds(curr_target)
    if targ_min_ea >= max_ea or targ_max_ea <= min_ea:
      DEBUG("  ERROR jump table {:x} entry candidate {} target {:x} inferred bounds are not sane".format(
          builder.table_ea, i, curr_target))
      continue

    min_ea = min(min_ea, targ_min_ea)
    max_ea = max(max_ea, targ_max_ea)

  if not max_ea:
    return curr_num_targets

  # The candidate entries gave us a wider bound
  if orig_min_ea != min_ea or orig_max_ea != max_ea:
    assert (orig_max_ea - orig_min_ea) < (max_ea - min_ea)
    DEBUG("Old table {:x} target bounds were  [{:x}, {:x})".format(
        builder.table_ea, orig_min_ea, orig_max_ea))

  DEBUG("Jump table {:x} targets can be in the range [{:x}, {:x})".format(
      builder.table_ea, min_ea, max_ea))

  # The candidate targets have given us some rough bounds on the function,
  # now lets go and check all the targets
  max_i = max(curr_num_targets, 1024)
  entry_addr = builder.table_ea
  table_seg_ea = idc.get_segm_start(builder.table_ea)
  for i in xrange(max_i):

    # Make sure we don't read across a segment (e.g. if the jump table is the
    # last thing in our current segment).
    try:
      if table_seg_ea != idc.get_segm_start(entry_addr):
        break
    except:
      break

    entry_data = builder.read_entry(entry_addr)
    next_entry_addr = entry_addr + (builder.entry_size * builder.entry_mult)

    # We will have already checked, or assumed, the sanity of the first
    # `curr_num_targets` entries of the table.
    if i < curr_num_targets:
      entry_addr = next_entry_addr
      continue

    DEBUG("  Checking possible jump table {:x} entry {} at {:x} going to {:x}".format(
        builder.table_ea, i, entry_addr, entry_data))

    if not is_block_or_instruction_head(entry_data):
      DEBUG("    Not an entry, the target {:x} isn't sane.".format(entry_data))
      break
    
    elif min_ea > entry_data or entry_data >= max_ea:
      DEBUG("    Not an entry, the target {:x} is out of range.".format(entry_data))
      break

    # We will assume that any reference to the data in here means
    # that we've gone and found the end of a table.
    #
    # TODO(pag): Handle more fine-grained refs, i.e. ones where there's
    #      a reference into the Nth byte of what could be the
    #      next address.
    elif len(list(idautils.DataRefsTo(entry_addr))):
      DEBUG("    Ignoring entry {:x} is referenced by data.".format(entry_data))
      break
    elif len(list(idautils.CodeRefsTo(entry_addr, 0))):
      DEBUG("    Ignoring entry {:x} is referenced by code (0).".format(entry_data))
      break
    elif len(list(idautils.CodeRefsTo(entry_addr, 1))):
      DEBUG("    Ignoring entry {:x} is referenced by code (1).".format(entry_data))
      break

    entry_addr = next_entry_addr

  if i != curr_num_targets:
    DEBUG("Jump table at {:x} actually has {} entries".format(
        builder.table_ea, i))

  return i

def try_get_simple_jump_table_reader(builder):
  """Try to create a jump table entry reader by looking for address-sized
  code pointers in the memory pointed to by `table_ea`.

  This uses heuristics like assuming certain alignments of table entries,
  and that the entry targets must be code."""
  if 0 != (builder.table_ea % 4):
    return False  # Doesn't meet minimum alignment requirements.

  min_ea, max_ea = get_function_bounds(builder.jump_ea)

  sizes = [4]
  if 64 == get_address_size_in_bits():
    sizes.insert(0, 8)

  # Try the offset table based approach first, as it's likely to be more
  # constrained.
  for offset in (builder.table_ea, builder.table_ea, builder.offset):
    for offset_mult in (1, -1):
      for entry_mult in (1, -1):
        for size in sizes:
          builder.offset = offset
          builder.offset_mult = offset_mult
          builder.entry_size = size
          builder.entry_mult = entry_mult

          target_ea = builder.read_entry(builder.table_ea)

          if min_ea > target_ea or max_ea <= target_ea:
            continue

          if not is_block_or_instruction_head(target_ea):
            continue

          # Read the second entry from the table as a way of verifying our
          # guesses on things like the offset multiplier and entry multiplier.
          next_entry_addr = builder.table_ea + \
                            (builder.entry_size * builder.entry_mult)

          target_ea = builder.read_entry(next_entry_addr)
          if min_ea <= target_ea < max_ea and \
             is_block_or_instruction_head(target_ea):
             return True

  return False

def try_convert_table_offset_to_ea(offset):
  """Try to convert a jump table offset into a valid ea, but only if it is
  near the base of an existing segment. See Issue #321."""
  next_seg = idaapi.get_next_seg(offset)
  if not next_seg:
    return False
  
  next_seg_ea = next_seg.start_ea
  if 0x1000 > (next_seg_ea - offset):
    return False

  seg_name = idc.get_segm_name(next_seg_ea)
  next_seg_end_ea = idc.get_segm_end(next_seg_ea)
  new_seg_ea = offset & ~0xFFF
  res = idaapi.set_segm_start(next_seg_ea, new_seg_ea, idc.SEGMOD_KEEP)
  if not res:
    DEBUG("ERROR: Could not resize {} from [{:x},{:x}) to [{:x},{:x})".format(
        seg_name, next_seg_ea, next_seg_end_ea, new_seg_ea, next_seg_end_ea))
    return False
  else:
    DEBUG("WARNING: Resized {} from [{:x},{:x}) to [{:x},{:x})".format(
        seg_name, next_seg_ea, next_seg_end_ea, new_seg_ea, next_seg_end_ea))
    return True

def get_ida_jump_table_reader(builder, si):
  """Try to trust IDA's ability to recognize a jump table and its entries,
  and return an appropriate jump table entry reader."""

  builder.table_ea = si.jumps
  DEBUG("IDA inferred jump table base: {:x}".format(builder.table_ea))

  builder.entry_size = si.get_jtable_element_size()

  if (si.flags & idaapi.SWI_JMP_INV) == idaapi.SWI_JMP_INV:
    builder.entry_mult = -1

  DEBUG("IDA inferred jump table entry size: {}".format(builder.entry_size))

  # Check if this is an offset based jump table, and if so, create an
  # appropriate wrapper that uses the displacement from the table base
  # address to find the actual jump target.
  if (si.flags & idaapi.SWI_ELBASE) == idaapi.SWI_ELBASE:
    builder.offset = si.elbase
    
    # Figure out if we need to subtract the offset instead of add it.
    if (si.flags2 & idaapi.SWI2_SUBTRACT) == idaapi.SWI2_SUBTRACT:
      builder.offset_mult = -1

    DEBUG("IDA inferred jump table offset: {:x}".format(builder.offset))

    # NOTE(pag): Converting this base to a real address is likely not correct,
    #            hence commenting it out. The jump table in question had
    #            entries like:
    #
    #     dd offset msetTab00 - 140000000h; jump table for switch statement
    #
    #            And then the code would add back in the `0x140000000`. The
    #            way we lift jump tables is to `switch` on the original EAs,
    #            because we can get the address of lifted LLVM basic blocks,
    #            so we need to make sure that the lifted computation and the
    #            original computation produce the same EAs for the jump targets,
    #            and converting the offset to be valid would be incorrect.
    #
    # # See Issue #321. The offset ea may end up being nearby the beginning of
    # # the `.text` segment, e.g. `0x1400000000` is the offset, but the `.text`
    # # begins at `0x1400001000`.
    # if is_invalid_ea(builder.offset):
    #   DEBUG("WARNING: Table offset {:x} is not a valid address".format(
    #       builder.offset))
    #   try_convert_table_offset_to_ea(builder.offset)


  return True

def get_manual_jump_table_reader(builder):
  """Scan backwards looking for something that looks like a jump table,
  even if it's not explicitly referenced in the current instruction.
  This handles the case where we see something like a `mov` or an `lea`
  of the table base address that happens before the actual `jmp`."""
  ret = False
  next_inst_ea = builder.jump_ea
  found_ref_eas = set()
  for i in xrange(5):
    inst_ea = next_inst_ea
    next_inst_ea = idc.prev_head(inst_ea)
    if inst_ea == idc.BADADDR:
      break

    elif builder.jump_ea != inst_ea and is_control_flow(inst_ea):
      break

    refs = get_instruction_references(inst_ea, builder.binary_is_pie)
    if not len(refs):
      continue

    found_ref_eas.add((inst_ea, refs[0].ea))

    builder.table_ea = refs[0].ea
    builder.offset = 0

    # Don't treat things like thunks to be tables.
    if is_thunk(builder.table_ea) or is_external_segment(builder.table_ea):
      builder.table_ea = idc.BADADDR
      continue

    if try_get_simple_jump_table_reader(builder):
      ret = True
      break
  
  if ret:
    DEBUG("Reader inferred jump table base: {:x}".format(builder.table_ea))
    if builder.offset:
      DEBUG("Reader inferred jump table offset: {:x}".format(builder.offset))
    return ret

  if len(found_ref_eas) < 2:
    return ret

  # We're going to try to recognize a jump table of the form:
  #
  #    .text:00000000004009AC ADRP            X1, #asc_400E5C@PAGE ; "\b"
  #    .text:00000000004009B0 ADD             X1, X1, #asc_400E5C@PAGEOFF ; "\b"
  #    .text:00000000004009B4 LDR             W0, [X1,W0,UXTW#2]
  #    .text:00000000004009B8 ADR             X1, loc_4009C4
  #    .text:00000000004009BC ADD             X0, X1, W0,SXTW#2
  #    .text:00000000004009C0 BR              X0
  #
  # Where it's a table of offsets (`asc_400E5C`), and the base offset is
  # the basic block `loc_4009C4`.
  min_ea, max_ea = get_function_bounds(builder.jump_ea)

  inst_block_ea = idc.BADADDR
  block_ea = idc.BADADDR

  for inst_ea, ref_ea in found_ref_eas:
    if is_code_by_flags(ref_ea) and min_ea <= ref_ea < max_ea:
      inst_block_ea = inst_ea
      block_ea = ref_ea
      break

  if idc.BADADDR == block_ea:
    return ret

  found_ref_eas.remove((inst_block_ea, block_ea))

  # The idea here is that we want to trick the jump table reader into thinking
  # that the offset of the jump table is a basic block.
  for inst_ea, ref_ea in found_ref_eas:
    builder.table_ea = ref_ea
    builder.offset = block_ea
    ret = try_get_simple_jump_table_reader(builder)
    if ret:
      break

  if ret:
    DEBUG("Reader inferred jump table base: {:x}".format(builder.table_ea))
    if builder.offset == block_ea:
      DEBUG("Reader inferred jump table offset is the block {:x}".format(
          builder.offset))
      
      # McSema-lifted bitcode doesn't really have a good way of getting the
      # address of a basic block, and even so, we don't really want that either.
      # The way our jump table lifting works is to preserve the original
      # addresses and computation, and `switch` based on that, so we need to
      # make sure that the original basic block address shows up in the lifted
      # bitcode.

      DEBUG("WARNING: Removing reference from {:x} to block {:x}".format(
          inst_block_ea, block_ea))
      remove_instruction_reference(inst_block_ea, block_ea)

  # NOTE(pag): For now we disable this jump table detection, even if it seems
  #            like we find the table. This is because we don't yet have a good
  #            way of dealing with the `ADD X0, X1, W0,SXTW#2`, which scales
  #            the read table entry out by shifting it left by two. Besides
  #            that, the following code actually works reasonably well. To
  #            account for this, on the C++ side, we augment jump table
  #            `switch`es to target blocks that are not referenced by the
  #            successor lists of any other blocks.
  #
  #            It is also pretty important to make sure that we remove the
  #            instruction reference. If/when we have good support for this
  #            kind of jump table, then the above call to
  #            `remove_instruction_reference` has to be removed so that the
  #            various things that the C++ side of things does to handle offset-
  #            based jump tables works. 
  return False

def get_jump_table_reader(builder):
  """Returns the size of a jump table entry, as well as a reader function
  that can extract entries."""
  si = ida_nalt.get_switch_info(builder.jump_ea)
  if si:
    return get_ida_jump_table_reader(builder, si)

  # IDA can be a bit ignorant at recognizing jump tables. This came up
  # in sqlite3 where IDA decided that `jmp ds:off_48A5F0[rax*8]` wasn't
  # a table-based jump. It's possible that this was because IDA
  # incorrectly recognized the memory operand as being an `o_mem` as
  # opposed to being an `o_disp`. `get_instruction_references` correctly
  # resolves this difference, so we'll also try to use it to pick up
  # where IDA leaves off.
  else:
    return get_manual_jump_table_reader(builder)

_JMP_THROUGH_TABLE_INFO = {}
_NOT_A_JMP_THROUGH_TABLE = set()

def get_jump_table(inst, binary_is_pie=False):
  """Returns an instance of JumpTable, or None depending on whether or not
  a jump table was discovered."""
  global _JMP_THROUGH_TABLE_INFO, _NOT_A_JMP_THROUGH_TABLE
  global _INVALID_JMP_TABLE

  if not inst or not is_indirect_jump(inst):
    return None  # Don't cache.

  if inst.ea in _JMP_THROUGH_TABLE_INFO:
    return _JMP_THROUGH_TABLE_INFO[inst.ea]

  elif inst.ea in _NOT_A_JMP_THROUGH_TABLE:
    return None

  elif is_external_segment(inst.ea):
    _NOT_A_JMP_THROUGH_TABLE.add(inst.ea)
    return None

  builder = JumpTableBuilder(inst, binary_is_pie)

  if not get_jump_table_reader(builder):
    _NOT_A_JMP_THROUGH_TABLE.add(builder.jump_ea)
    return None

  DEBUG("Jump table candidate at {:x} referenced by instruction {:x}".format(
      builder.table_ea, builder.jump_ea))

  get_default_jump_table_entries(builder)

  # Try to fix-up the number of entries.
  num_entries = get_num_jump_table_entries(builder)

  # Treat zero- or one-entry 'tables' as not actually being tables.
  if num_entries <= 1:
    DEBUG("Ignoring jump table {:x} with 1 >= {} entries referenced by {:x}".format(
        builder.table_ea, num_entries, builder.jump_ea))
    _NOT_A_JMP_THROUGH_TABLE.add(builder.jump_ea)
    return None

  DEBUG("Jump table {:x} entries:".format(builder.table_ea))

  # We've got a more accurate number of table entries, so go and actually
  # read them to fill in our `JumpTable` data structure.
  entries = {}
  raw_entries = {}
  entry_addr = builder.table_ea
  for i in xrange(num_entries):
    entry_data = builder.read_entry(entry_addr)
    entries[entry_addr] = entry_data
    DEBUG("  {:x} => {:x}".format(entry_addr, entry_data))
    entry_addr += builder.entry_size * builder.entry_mult

  table = JumpTable(builder, entries)
  _JMP_THROUGH_TABLE_INFO[builder.jump_ea] = table

  return table

def is_jump_table_entry(ea):
  """Returns `True` if `ea` falls somewhere inside of the bytes of a jump
  table."""
  global _FIRST_JUMP_TABLE_ENTRY
  return ea in _FIRST_JUMP_TABLE_ENTRY

def get_jump_table_from_entry(entry_ea):
  """Returns a `JumpTable` """
  global _FIRST_JUMP_TABLE_ENTRY, _JUMP_TABLE_ENTRY
  if entry_ea not in _FIRST_JUMP_TABLE_ENTRY:
    return None
  table_ea = _FIRST_JUMP_TABLE_ENTRY[entry_ea]
  return _JUMP_TABLE_ENTRY[table_ea]
