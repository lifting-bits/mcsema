# Copyright (c) 2017, Trail of Bits
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
# Redistributions of source code must retain the above copyright notice, this
# list of conditions and the following disclaimer.
#
# Redistributions in binary form must reproduce the above copyright notice, this
# list of conditions and the following disclaimer in the documentation and/or
# other materials provided with the distribution.
#
# Neither the name of Trail of Bits nor the names of its
# contributors may be used to endorse or promote products derived from
# this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
# ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from refs import *

class JumpTable(object):
  """Represents generic info known about a particular jump table."""
  __slots__ = ('inst_ea', 'entry_size', 'table_ea', 'entries', 'raw_entries')

  def __init__(self, inst_ea, table_ea, entry_size, entries, raw_entries):
    self.inst_ea = inst_ea
    self.table_ea = table_ea
    self.entry_size = entry_size
    self.entries = entries
    self.raw_entries = raw_entries

    max_ea = table_ea
    data_flags = (4 == entry_size) and idc.FF_DWRD or idc.FF_QWRD

    # Update IDA's understanding of the flow of control out of the jump
    # instruction, as well as references to/from the table.
    for entry_ea, target_ea in entries.items():
      idc.MakeData(entry_ea, data_flags, entry_size, 0)
      idc.AddCodeXref(inst_ea, target_ea, idc.XREF_USER | idc.fl_JN)
      remove_all_refs(entry_ea)
      max_ea = max(max_ea, entry_ea + entry_size)
    
    # Make sure each entry is seen as referenced.
    for entry_ea, target_ea in entries.items():
      idc.add_dref(inst_ea, entry_ea, idc.dr_I)

    # Make sure that the contents of the table are no longer considered
    # code (only affects `is_code`). This is only meaningful if the table
    # itself is embedded in a code segment.
    for ea_into_table in xrange(table_ea, max_ea):
      mark_as_not_code(ea_into_table)

    idaapi.autoWait()

def get_default_jump_table_entries(inst, table_ea, reader):
  """Return the 'default' jump table entries, based on IDA's ability to
  recognize a jump table. If IDA doesn't recognize the table, then we
  say that there are 0 entries, but we also return what we have inferred
  to be the first entry."""
  si = idaapi.get_switch_info_ex(inst.ea)
  
  if si:
    num_entries = si.get_jtable_size()
    entries = []
    next_addr = table_ea
    for i in xrange(num_entries):
      target_ea, raw_target, next_addr = reader(next_addr)
      entries.append(target_ea)
    return num_entries, entries
  else:
    target_ea, raw_target, next_addr = reader(table_ea)
    return 0, [target_ea]

def get_num_jump_table_entries(inst_ea, table_ea, reader, curr_num_targets,
                               curr_targets):
  """Try to get the number of entries in a jump table. This will use some
  base set of entries."""
  DEBUG("Checking if jump table at {:x} has more than {} entries".format(
      table_ea, curr_num_targets))

  # Use the bounds of the function containing the jump instruction as our
  # initial bounds for candidate jump table targets.
  min_ea, max_ea = get_function_bounds(inst_ea)
  
  # Treat the current set of targets as candidates, even if the source of
  # those targets is IDA. We will assume that jump table entries point within
  # a given function, or within nearby functions that IDA believes to be
  # different (but hopefully are logically the same). So we will get bounds
  # on the range of possible targets based on the function(s) containing the
  # candidates, and use that as a scanning heuristic to find missing entries.
  last_target_func = None
  for i, curr_target in enumerate(curr_targets):
    is_sane_target = is_block_or_instruction_head(curr_target)
    if not is_sane_target:
      DEBUG("ERROR jump table {:x} entry {} target {:x} is not sane!".format(
          table_ea, i, curr_target))

    assert is_sane_target
    targ_min_ea, targ_max_ea = get_function_bounds(curr_target)
    min_ea = min(min_ea, targ_min_ea)
    max_ea = max(max_ea, targ_max_ea)

  if not max_ea:
    return curr_num_targets

  DEBUG("Jump table {:x} targets can be in the range [{:x}, {:x})".format(
      table_ea, min_ea, max_ea))

  i = 0
  max_i = max(curr_num_targets, 1024)
  entry_addr = table_ea
  while i < max_i:
    entry_data, raw_entry_data, next_entry_addr = reader(entry_addr)
    
    # Note: if this is a candidate table that IDA doesn't recognize, then
    #     curr_num_targets will be 0, even though there will be one
    #     entry in the `curr_targets`. This first entry will be guaranteed
    #     to be targeted by a data/code ref, so we check that `i` is non-
    #     zero to avoid failing the check before we do anything useful.
    if i and i >= curr_num_targets:
      DEBUG("Checking possible jump table {:x} entry {} at {:x} going to {:x}".format(
          table_ea, i, entry_addr, entry_data))

      if not is_block_or_instruction_head(entry_data):
        DEBUG("Not an entry, the target {:x} isn't sane.".format(entry_data))
        break
      
      elif min_ea > entry_data or entry_data >= max_ea:
        break

      # We will assume that any reference to the data in here means
      # that we've gone and found the end of a table.
      #
      # TODO(pag): Handle more fine-grained refs, i.e. ones where there's
      #      a reference into the Nth byte of what could be the
      #      next address.
      elif len(list(idautils.DataRefsTo(entry_addr))):
        DEBUG("Not an entry, the target {:x} is referenced by data.".format(entry_data))
        break
      elif len(list(idautils.CodeRefsTo(entry_addr, 0))):
        DEBUG("Not an entry, the target {:x} is referenced by code.".format(entry_data))
        break
      elif len(list(idautils.CodeRefsTo(entry_addr, 1))):
        DEBUG("Not an entry, the target {:x} is referenced by code.".format(entry_data))
        break

    entry_addr = next_entry_addr
    i += 1

  if i != curr_num_targets:
    DEBUG("Jump table at {:x} actually has {} entries".format(table_ea, i))
  return i

def wrap_jump_table_reader(entry_size, reader, wrapper):
  """Create a jump table entry reader that will read bytes from memory,
  potentially modify them, thereby converting them into plausible code
  references, and finally returning the modified data, the original
  data, and the address of the next entry to check."""
  def do_read(addr):
    raw_data = reader(addr)
    return wrapper(raw_data), raw_data, (addr + entry_size)
  return do_read

_NO_READER = 0, None, idc.BADADDR

def try_get_simple_jump_table_reader(inst_ea, table_ea):
  """Try to create a jump table entry reader by looking for address-sized
  code pointers in the memory pointed to by `table_ea`.

  This uses heuristics like assuming certain alignments of table entries,
  and that the entry targets must be code."""
  entry_size = 0
  offset_wrapper = (lambda d: 0xFFFFFFFF & (d + table_ea))
  wrappers = [(lambda d: d), offset_wrapper]

  for wrapper in wrappers:
    candidate = 0, None, idc.BADADDR
    target_ea = idc.BADADDR
    if 0 == (table_ea % 8) and 64 == get_address_size_in_bits():
      target_ea = read_qword(table_ea)
      if is_block_or_instruction_head(target_ea):
        reader = wrap_jump_table_reader(8, read_qword, wrapper)
        candidate = 8, reader, table_ea

    if not candidate[0] and 0 == (table_ea % 4):
      target_ea = read_dword(table_ea)
      if is_block_or_instruction_head(target_ea):
        reader = wrap_jump_table_reader(4, read_dword, wrapper)
        candidate = 4, reader, table_ea

    # We've got a jump table target candidate; make sure that the target
    # belongs to the same function as the jump instruction. We use the bounds
    # of the function for checking, just in case the target is treated as
    # soem non-part of the function within the function's bounds.
    if candidate[0]:
      min_ea, max_ea = get_function_bounds(inst_ea)
      if min_ea <= target_ea < max_ea:
        return candidate

  return _NO_READER

def is_thunk(ea):
  """Returns true if some address is a known to IDA to be a thunk."""
  flags = idc.GetFunctionFlags(ea)
  return 0 < flags and 0 != (flags & idaapi.FUNC_THUNK)

def get_ida_jump_table_reader(inst, si, binary_is_pie):
  """Try to trust IDA's ability to recognize a jump table and its entries,
  and return an appropriate jump table entry reader."""
  global _NO_READER
  wrapper = lambda d: d

  # Check if this is an offset based jump table, and if so, create an
  # appropriate wrapper that uses the displacement from the table base
  # address to find the actual jump target.
  if (si.flags & idaapi.SWI_ELBASE) == idaapi.SWI_ELBASE:
    table_ea = si.elbase
    wrapper = (lambda d: 0xFFFFFFFF & (d + table_ea))

  entry_size = si.get_jtable_element_size()
  if 8 == entry_size and 64 == get_address_size_in_bits():
    reader = wrap_jump_table_reader(8, read_qword, wrapper)
    return 8, reader, si.jumps
  
  elif 4 == entry_size:
    reader = wrap_jump_table_reader(4, read_dword, wrapper)
    return 4, reader, si.jumps
  else:
    DEBUG("ERROR! Incorrect jump table entry size {}".format(entry_size))
    return _NO_READER

def get_manual_jump_table_reader(inst, binary_is_pie):
  """Scan backwards looking for something that looks like a jump table,
  even if it's not explicitly referenced in the current instruction.
  This handles the case where we see something like a `mov` or an `lea`
  of the table base address that happens before the actual `jmp`."""
  next_inst_ea = inst.ea
  for i in xrange(5):
    inst_ea = next_inst_ea
    next_inst_ea = idc.PrevHead(inst_ea)
    if inst_ea == idc.BADADDR:
      return _NO_READER
    
    refs = get_instruction_references(inst_ea, binary_is_pie)
    if not len(refs):
      continue

    candidate_table_ea = refs[0].addr
    
    # Don't treat things like thunks to be tables.
    if is_thunk(candidate_table_ea) or is_external_segment(candidate_table_ea):
      return _NO_READER

    reader = try_get_simple_jump_table_reader(inst.ea, candidate_table_ea)
    if reader[0]:
      return reader
  
  return _NO_READER

def get_jump_table_reader(inst, binary_is_pie):
  """Returns the size of a jump table entry, as well as a reader function
  that can extract entries."""
  si = idaapi.get_switch_info_ex(inst.ea)
  if si:
    return get_ida_jump_table_reader(inst, si, binary_is_pie)

  # IDA can be a bit ignorant at recognizing jump tables. This came up
  # in sqlite3 where IDA decided that `jmp ds:off_48A5F0[rax*8]` wasn't
  # a table-based jump. It's possible that this was because IDA
  # incorrectly recognized the memory operand as being an `o_mem` as
  # opposed to being an `o_disp`. `get_instruction_references` correctly
  # resolves this difference, so we'll also try to use it to pick up
  # where IDA leaves off.
  else:
    return get_manual_jump_table_reader(inst, binary_is_pie)

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

  entry_size, reader, table_ea = get_jump_table_reader(inst, binary_is_pie)
  if not entry_size or not reader:
    _NOT_A_JMP_THROUGH_TABLE.add(inst.ea)
    return None

  DEBUG("Jump table candidate at {:x} referenced by instruction {:x}".format(
      table_ea, inst.ea))

  num_entries, default_entries = get_default_jump_table_entries(
    inst, table_ea, reader)

  if len(default_entries):
    DEBUG("Jump table candidate {:x} has {} entries, with {} candidate targets".format(
        table_ea, num_entries, len(default_entries)))

    # Try to fix-up the number of entries.
    num_entries = get_num_jump_table_entries(
      inst.ea, table_ea, reader, num_entries, default_entries)

  # Treat zero- or one-entry 'tables' as not actually being tables.
  if num_entries <= 1:
    DEBUG("Ignoring jump table {:x} with 1 >= {} entries referenced by {:x}".format(
        table_ea, num_entries, inst.ea))
    _NOT_A_JMP_THROUGH_TABLE.add(inst.ea)
    return None

  DEBUG("Jump table {:x} entries:".format(table_ea))

  # We've got a more accurate number of table entries, so go and actually
  # read them to fill in our `JumpTable` data structure.
  entries = {}
  raw_entries = {}
  entry_addr = table_ea
  for i in xrange(num_entries):
    entry_data, raw_entry_data, next_entry_addr = reader(entry_addr)
    raw_entries[entry_addr] = raw_entry_data
    entries[entry_addr] = entry_data

    if raw_entry_data != entry_data:
      DEBUG("  {:x} => {:x} (raw {:x})".format(
          entry_addr, entry_data, raw_entry_data))
    else:
      DEBUG("  {:x} => {:x}".format(entry_addr, entry_data))

    entry_addr = next_entry_addr

  table = JumpTable(inst.ea, table_ea, entry_size, entries, raw_entries)
  _JMP_THROUGH_TABLE_INFO[inst.ea] = table

  return table
