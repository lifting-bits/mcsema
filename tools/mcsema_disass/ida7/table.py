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

from refs import *

import struct

_FIRST_JUMP_TABLE_ENTRY = {}
_JUMP_TABLE_ENTRY = {}
_IS_JUMP_TABLE_ENTRY = set()
_FUDGE_FACTOR = 256

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
    
    entry_type = ida_bytes.FF_QWORD
    if self.entry_size == 4:
      entry_type = ida_bytes.FF_DWORD

    # Make sure each entry is seen as referenced.
    for entry_ea, target_ea in entries.items():
      idc.create_data(entry_ea, entry_type, self.entry_size, idaapi.BADADDR)
      idc.add_dref(entry_ea, target_ea, idc.XREF_USER|idc.dr_I)
      idc.add_dref(self.inst_ea, entry_ea, idc.XREF_USER|idc.dr_I)

    # Make sure that the contents of the table are no longer considered
    # code (only affects `is_code`). This is only meaningful if the table
    # itself is embedded in a code segment.
    for ea_into_table in xrange(self.table_ea, max_ea):
      mark_as_not_code(ea_into_table)
      _FIRST_JUMP_TABLE_ENTRY[ea_into_table] = self.table_ea
      _IS_JUMP_TABLE_ENTRY.add(ea_into_table)

    _JUMP_TABLE_ENTRY[self.table_ea] = self
    idaapi.auto_wait()

_IS_TARGETED_BY_JUMP_TABLE = set()

class JumpTableBuilder(object):
  _READERS = {
      4: read_dword,
      8: read_qword
  }

  def __init__(self, inst, binary_is_pie):
    import util

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
    data &= ((1 << int(self.entry_size * 8)) - 1)
    data += self.offset * self.offset_mult
    data &= 0xFFFFFFFFFFFFFFFF
    if 4 == self.entry_size and (self.offset & 0xFFFFFFFF) == self.offset:
      data &= 0xFFFFFFFF
    return data

def _check_entry_target_ea(target_ea, min_ea, max_ea):
  global _FUDGE_FACTOR
  min_ea = max(0, min_ea - _FUDGE_FACTOR)
  max_ea += _FUDGE_FACTOR
  if min_ea > target_ea or max_ea <= target_ea:
    return False

  if not is_block_or_instruction_head(target_ea):
    return False

  return True

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
  global _IS_TARGETED_BY_JUMP_TABLE

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
    
    _IS_TARGETED_BY_JUMP_TABLE.add(curr_target)

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
  max_i = max(curr_num_targets, 2048)
  entry_addr = builder.table_ea
  table_seg_ea = idc.get_segm_start(builder.table_ea)
  stop_at = max_i

  entry_type = ida_bytes.FF_QWORD
  if builder.entry_size == 4:
    entry_type = ida_bytes.FF_DWORD

  for i in xrange(max_i):

    # Make sure we don't read across a segment (e.g. if the jump table is the
    # last thing in our current segment).
    try:
      if table_seg_ea != idc.get_segm_start(entry_addr):
        break
    except:
      break

    #if entry_addr in _FIRST_JUMP_TABLE_ENTRY:
    #  DEBUG("  Entry at {:x} is already part of another jump table".format(entry_addr))

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
    
    elif not _check_entry_target_ea(entry_data, min_ea, max_ea):
      DEBUG("    Not an entry, the target {:x} is out of range [{:x}, {:x})".format(
          entry_data, min_ea, max_ea))
      stop_at = min(stop_at, i)

      if entry_data != get_reference_target(entry_addr):
        idc.create_data(entry_addr, entry_type, builder.entry_size, idaapi.BADADDR)
        idc.add_dref(entry_addr, entry_data, idc.XREF_USER|idc.dr_I)

      _IS_TARGETED_BY_JUMP_TABLE.add(entry_data)
      for entry_addr_sub_ea in xrange(entry_addr, entry_addr + builder.entry_size):
        _IS_JUMP_TABLE_ENTRY.add(entry_addr_sub_ea)

    # We will assume that any reference to the data in here means
    # that we've gone and found the end of a table.
    #
    # TODO(pag): Handle more fine-grained refs, i.e. ones where there's
    #      a reference into the Nth byte of what could be the
    #      next address.
    elif len(list(idautils.DataRefsTo(entry_addr))):
      if 0 < i:  # The first entry's reference might be a dref in an instruction.
        DEBUG("    Ignoring entry {:x} is referenced by data.".format(entry_data))
        break
    elif len(list(idautils.CodeRefsTo(entry_addr, 0))):
      DEBUG("    Ignoring entry {:x} is referenced by code (0).".format(entry_data))
      break
    elif len(list(idautils.CodeRefsTo(entry_addr, 1))):
      DEBUG("    Ignoring entry {:x} is referenced by code (1).".format(entry_data))
      break

    # Widen the bounds if the fudge factor came into play.
    min_ea = min(min_ea, entry_data)
    max_ea = max(max_ea, entry_data)
    if stop_at < i < max_i:
      stop_at = max_i

    entry_addr = next_entry_addr

  i = min(i, stop_at)
  if i != curr_num_targets:
    DEBUG("Jump table at {:x} actually has {} != {} entries".format(
        builder.table_ea, i, curr_num_targets))

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

          # Read the second entry from the table as a way of verifying our
          # guesses on things like the offset multiplier and entry multiplier.
          next_entry_addr = builder.table_ea + \
                            int(builder.entry_size * builder.entry_mult)

          if _check_entry_target_ea(target_ea, min_ea, max_ea):
            target_ea = builder.read_entry(next_entry_addr)
            # Additional check is added to avoid target_ea becoming valid if the data at next_entry_addr is 0
            if (target_ea != builder.offset)  and _check_entry_target_ea(target_ea, min_ea, max_ea):
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
  
  if builder.entry_size not in (4, 8):
    builder.entry_size = get_address_size_in_bits() // 8
    DEBUG("Using jump table entry size {} instead".format(builder.entry_size))
    
  # Check if this is an offset based jump table, and if so, create an
  # appropriate wrapper that uses the displacement from the table base
  # address to find the actual jump target.
  if (si.flags & idaapi.SWI_ELBASE) == idaapi.SWI_ELBASE:
    builder.offset = si.elbase
    
    # Figure out if we need to subtract the offset instead of add it.
    SWI2_SUBTRACT = idaapi.SWI_SUBTRACT >> 16
    if (si.flags & SWI2_SUBTRACT) == SWI2_SUBTRACT:
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
  if not is_invalid_ea(builder.table_ea):
    if try_get_simple_jump_table_reader(builder):
      return True

  inst_ea = builder.jump_ea
  block_eas = list()
  block_eas.append(inst_ea)
  for i in xrange(8):
    prev_head_ea = idc.prev_head(inst_ea)

    for xref_ea in crefs_to(inst_ea):
      if prev_head_ea != xref_ea:
        inst, _ = decode_instruction(xref_ea)
        if has_delayed_slot(inst):
          block_eas.append(inst.ea + inst.size)
        else:
          block_eas.append(xref_ea)

    inst_ea = prev_head_ea

  ret = False
  next_inst_ea = builder.jump_ea
  found_ref_eas = set()

  for block_ea in block_eas:
    next_inst_ea = block_ea
    for i in xrange(10):
      inst_ea = next_inst_ea
      next_inst_ea = idc.prev_head(inst_ea)
      if inst_ea == idc.BADADDR:
        break

      elif is_noreturn_external_function(inst_ea):
        break

      elif builder.jump_ea != inst_ea and is_control_flow(inst_ea):
        continue

      refs = get_instruction_references(inst_ea, builder.binary_is_pie)
      if not len(refs):
        continue

      found_ref_eas.add((inst_ea, refs[0].ea))

      builder.table_ea = refs[0].ea
      builder.offset = 0
      builder.offset_mult = 1

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

def get_dref_jump_table_reader(builder):
  """Try to get a jump table by looking at any of the blocks that might be
  referenced by data."""
  func = idaapi.get_func(builder.jump_ea)
  if not func:
    return False

  min_entry_ea = idc.BADADDR
  max_entry_ea = 0
  
  import flow

  best_entry_ea = 0
  best_num_entries = 0

  for block_ea in flow.find_default_block_heads(func.start_ea):
    for entry_ea in drefs_to(block_ea):
      builder.table_ea = entry_ea
      builder.offset = 0
      builder.offset_mult = 1
      del builder.candidate_target_eas[:]
      if try_get_simple_jump_table_reader(builder):
        if len(builder.candidate_target_eas) > best_num_entries:
          best_entry_ea = entry_ea

  if best_num_entries:
    builder.table_ea = entry_ea
    builder.offset = 0
    builder.offset_mult = 1
    del builder.candidate_target_eas[:]
    return try_get_simple_jump_table_reader(builder)
  
  return False


def get_jump_table_reader(builder):
  """Returns the size of a jump table entry, as well as a reader function
  that can extract entries."""
  si = ida_nalt.get_switch_info(builder.jump_ea)
  if si:
    if get_ida_jump_table_reader(builder, si):
      return True
    else:
      builder.offset = 0
      builder.offset_mult = 1
      del builder.candidate_target_eas[:]

  # IDA can be a bit ignorant at recognizing jump tables. This came up
  # in sqlite3 where IDA decided that `jmp ds:off_48A5F0[rax*8]` wasn't
  # a table-based jump. It's possible that this was because IDA
  # incorrectly recognized the memory operand as being an `o_mem` as
  # opposed to being an `o_disp`. `get_instruction_references` correctly
  # resolves this difference, so we'll also try to use it to pick up
  # where IDA leaves off.
  if get_manual_jump_table_reader(builder):
    return True

  return False
  #return get_dref_jump_table_reader(builder)

_JMP_THROUGH_TABLE_INFO = {}
_TABLE_INFO = {}
_NOT_A_JMP_THROUGH_TABLE = set()

def _handle_new_builder(builder):
  """Try to finalize a new jump table builder and get the final jump
  table."""
  global _NOT_A_JMP_THROUGH_TABLE, _IS_TARGETED_BY_JUMP_TABLE

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
    _IS_TARGETED_BY_JUMP_TABLE.add(entry_data)
    DEBUG("  {:x} => {:x}".format(entry_addr, entry_data))
    entry_addr += builder.entry_size * builder.entry_mult

  table = JumpTable(builder, entries)
  _JMP_THROUGH_TABLE_INFO[builder.jump_ea] = table
  _TABLE_INFO[builder.table_ea] = table

  return table

def get_jump_table(inst, binary_is_pie=False):
  """Returns an instance of JumpTable, or None depending on whether or not
  a jump table was discovered."""
  global _JMP_THROUGH_TABLE_INFO, _NOT_A_JMP_THROUGH_TABLE, _TABLE_INFO
  global _INVALID_JMP_TABLE, _IS_TARGETED_BY_JUMP_TABLE

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

  if builder.table_ea in _TABLE_INFO:
    DEBUG("  Using pre-existing jump table info")
    table = _TABLE_INFO[builder.table_ea]
    _JMP_THROUGH_TABLE_INFO[builder.jump_ea] = table
    return table

  return _handle_new_builder(builder)

def is_jump_table_entry(ea):
  """Returns `True` if `ea` falls somewhere inside of the bytes of a jump
  table."""
  global _IS_JUMP_TABLE_ENTRY
  return ea in _IS_JUMP_TABLE_ENTRY

def is_jump_table_target(ea):
  """Returns `True` if `ea` is targeted by some jump table."""
  global _IS_TARGETED_BY_JUMP_TABLE
  return ea in _IS_TARGETED_BY_JUMP_TABLE

def get_jump_table_from_entry(entry_ea):
  """Returns a `JumpTable` """
  global _FIRST_JUMP_TABLE_ENTRY, _JUMP_TABLE_ENTRY
  if entry_ea not in _FIRST_JUMP_TABLE_ENTRY:
    return None
  table_ea = _FIRST_JUMP_TABLE_ENTRY[entry_ea]
  return _JUMP_TABLE_ENTRY[table_ea]

def _find_jumps_near(inst_ea):
  """Try to find an indirect jump instruction near `inst_ea`."""
  min_ea, max_ea = get_function_bounds(inst_ea)
  candidates = []
  DEBUG("Looking for indirect jumps in range [{:x}, {:x})".format(min_ea, max_ea))
  while min_ea < max_ea:
    if is_indirect_jump(min_ea):
      DEBUG("  Found indirect jump at {:x}".format(min_ea))
      candidates.append(min_ea)
    min_ea = idc.next_head(min_ea+1)
  return candidates

def try_create_jump_table(inst_ea, entry_ea, entry_size, binary_is_pie=False):
  """Try to create a jump table, beginning at `entry_ea`, and referenced by
  `inst_ea` (which may or may not be a jump instruction)."""
  DEBUG_PUSH()

  if entry_ea in _TABLE_INFO:
    table = _TABLE_INFO[entry_ea]
    DEBUG("Instruction at {:x} references jump table {:x} because of entry at {:x}".format(
        inst_ea, table.table_ea, entry_ea))
    DEBUG_POP()
    return

  if not is_indirect_jump(inst_ea):
    jump_eas = _find_jumps_near(inst_ea)
  else:
    jump_eas = [inst_ea]

  for jump_ea in jump_eas:
    if jump_ea in _JMP_THROUGH_TABLE_INFO:
      continue  # Already have a jump table for this.

    # elif entry_ea in _TABLE_INFO:
    #   table = _TABLE_INFO[entry_ea]
    #   DEBUG("Jump table candidate at {:x} referenced by instruction {:x} because of entry {:x}".format(
    #       table.table_ea, jump_ea, entry_ea))
    #   _JMP_THROUGH_TABLE_INFO[jump_ea] = table
    #   continue

    inst, _ = decode_instruction(jump_ea)
    builder = JumpTableBuilder(inst, binary_is_pie)
    builder.table_ea = entry_ea
    builder.entry_size = entry_size

    if not try_get_simple_jump_table_reader(builder):
      continue

    DEBUG("Jump table candidate at {:x} referenced by instruction {:x}".format(
        builder.table_ea, builder.jump_ea))

    _handle_new_builder(builder)
    break

  DEBUG_POP()

