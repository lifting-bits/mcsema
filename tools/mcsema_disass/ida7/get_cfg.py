#!/usr/bin/env python

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

import idautils
import idaapi
import ida_funcs
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
from exception import *

# Bring in Anvill
try:
  import anvill
except:
  import anvill_compat as anvill

ANVILL_PROGRAM = None

#hack for IDAPython to see google protobuf lib
_VERSION_NUM = "{}.{}".format(sys.version_info[0], sys.version_info[1])
if os.path.isdir('/usr/lib/python{}/dist-packages'.format(_VERSION_NUM)):
  sys.path.append('/usr/lib/python{}/dist-packages'.format(_VERSION_NUM))

if os.path.isdir('/usr/local/lib/python{}/dist-packages'.format(_VERSION_NUM)):
  sys.path.append('/usr/local/lib/python{}/dist-packages'.format(_VERSION_NUM))

tools_disass_ida_dir = os.path.dirname(__file__)
tools_disass_dir = os.path.dirname(tools_disass_ida_dir)

# Note: The bootstrap file will copy CFG_pb2.py into this dir!!
import CFG_pb2

EXTERNAL_FUNCS_TO_RECOVER = {}
EXTERNAL_VARS_TO_RECOVER = {}

RECOVERED_EAS = set()
ACCESSED_VIA_JMP = set()

TO_RECOVER = {
  "stack_var" : False,
}

RECOVER_EHTABLE = False

PERSONALITY_FUNCTIONS = [
    "__gxx_personality_v0",
    "__gnat_personality_v0"
    ]

# Map of external functions names to a tuple containing information like the
# number of arguments and calling convention of the function.
EMAP = {}

# Map of external variable names to their sizes, in bytes.
EMAP_DATA = {}

# Map of the functions which are forced to be extern and does not require to
# be recovered.
FORCED_EXTERNAL_EMAP = {}

# `True` if we are getting the CFG of a position independent executable. This
# affects heuristics like trying to turn immediate operands in instructions
# into references into the data.
PIE_MODE = False

# Name of the operating system that runs the program being lifted. E.g. if
# we're lifting an ELF then this will typically be `linux`.
OS_NAME = ""

# Set of substrings that can be found inside of symbol names that are usually
# signs that the symbol is external. For example, `stderr@@GLIBC_2.2.5` is
# really the external `stderr`, so we want to be able to chop out the `@@...`
# part to resolve the "true" name. There are a lot of `@@` variants in PE files,
# e.g. `@@QEAU_..`, `@@AEAV..`, though these are likely for name mangling.
EXTERNAL_NAMES = ("@@GLIBC_", "@@GLIBCXX_", "@@CXXABI_", "@@GCC_")

_NOT_ELF_BEGIN_EAS = (0xffffffff, 0xffffffffffffffff)

# Returns `True` if this is an ELF binary (as opposed to an ELF object file).
def is_linked_ELF_program():
  global _NOT_ELF_BEGIN_EAS
  return IS_ELF and idc.get_inf_attr(INF_START_EA) not in _NOT_ELF_BEGIN_EAS

def is_ELF_got_pointer(ea):
  """Returns `True` if this is a pointer to a pointer stored in the
  `.got` section of an ELF binary. For example, `__gmon_start___ptr` is
  a pointer in the `.got` that will be fixed up to contain the address of
  the external function `__gmon_start__`. We don't want to treat
  `__gmon_start___ptr` as external because it is really a sort of local
  variable that will will resolve with a data cross-reference."""
  seg_name = idc.get_segm_name(ea).lower()
  if ".got" not in seg_name:
    return False

  name = get_symbol_name(ea)
  target_ea = get_reference_target(ea)
  target_name = get_true_external_name(get_symbol_name(target_ea))

  if target_name not in name:
    return False

  return is_referenced_by(target_ea, ea)

def is_ELF_got_pointer_to_external(ea):
  """Similar to `is_ELF_got_pointer`, but requires that the eventual target
  of the pointer is an external."""
  if not is_ELF_got_pointer(ea):
    return False

  target_ea = get_reference_target(ea)
  return is_external_segment(target_ea)

_FIXED_EXTERNAL_NAMES = {}

def demangled_name(name):
  """Tries to demangle a functin name."""
  try:
    dname = idc.demangle_name(name, idc.get_inf_attr(INF_SHORT_DN))
    if dname and len(dname) and "::" not in dname:
      dname = dname.split("(")[0]
      dname = dname.split(" ")[-1]
      if re.match(r"^[a-zA-Z0-9_]+$", dname):
        return dname
    return name
  except:
    return name

def get_true_external_name(fn, demangle=True):
  """Tries to get the 'true' name of `fn`. This removes things like
  ELF-versioning from symbols."""
  if not fn:
    return ""

  orig_fn = fn
  if fn in _FIXED_EXTERNAL_NAMES:
    return _FIXED_EXTERNAL_NAMES[orig_fn]

  if fn in EMAP:
    return fn

  if fn in EMAP_DATA:
    return fn

  # Try to demangle the name, but don't do it if looks like there's a C++
  # namespace.
  if demangle:
    fn = demangled_name(fn)

  # TODO(pag): Is this a macOS or Windows thing?
  if not is_linked_ELF_program() and fn[0] == '_':
    return fn[1:]

  if fn.endswith("_0"):
    newfn = fn[:-2]
    if newfn in EMAP:
      return newfn

  # Go and strip off things like the `@@GLIBC_*` symbol suffixes.
  for en in EXTERNAL_NAMES:
    if en in fn:
      fn = fn[:fn.find(en)]
      break

  if orig_fn != fn:
    DEBUG("True name of {} is {}".format(orig_fn, fn))
  
  _FIXED_EXTERNAL_NAMES[orig_fn] = fn
  return fn

# Set of symbols that IDA identifies as being "weak" symbols. In ELF binaries,
# a weak symbol is kind of an optional linking thing. For example, the 
# `__gmon_start__` function is referenced as a weak symbol. This function is
# used for gcov-based profiling. If gcov is available, then this symbol will
# be resolved to a real function, but if not, it will be NULL and programs
# will detect it as such. An example use of a weak symbol in C would be:
#
#     extern void __gmon_start__(void) __attribute__((weak));
#     ...
#     if (__gmon_start__) {
#       __gmon_start__();
#     }
WEAK_SYMS = set()

# Used to track thunks that are actually implemented. For example, in a static
# binary, you might have a bunch of calls to `strcpy` in the `.plt` section
# that go through the `.plt.got` to call the implementation of `strcpy` compiled
# into the binary.
INTERNALLY_DEFINED_EXTERNALS = {}  # Name external to EA of internal.
INTERNAL_THUNK_EAS = {}  # EA of thunk to EA of implementation.

def parse_os_defs_file(df):
  """Parse the file containing external function and variable
  specifications."""
  global OS_NAME, WEAK_SYMS, EMAP, EMAP_DATA
  global _FIXED_EXTERNAL_NAMES, INTERNALLY_DEFINED_EXTERNALS
  
  is_linux = OS_NAME == "linux"
  for l in df.readlines():
    #skip comments / empty lines
    l = l.strip()
    if not l or l[0] == "#":
      continue

    if l.startswith('DATA:'):
      # process as data
      (marker, symname, dsize) = l.split()
      if 'PTR' in dsize:
        dsize = get_address_size_in_bytes()

      EMAP_DATA[symname] = int(dsize)

    else:
      fname = args = conv = ret = sign = None
      line_args = l.split()

      if len(line_args) == 4:
        (fname, args, conv, ret) = line_args
      elif len(line_args) == 5:
        (fname, args, conv, ret, sign) = line_args

      if conv == "C":
        realconv = CFG_pb2.ExternalFunction.CallerCleanup
      elif conv == "E":
        realconv = CFG_pb2.ExternalFunction.CalleeCleanup
      elif conv == "F":
        realconv = CFG_pb2.ExternalFunction.FastCall
      else:
        DEBUG("ERROR: Unknown calling convention: {}".format(l))
        continue

      if ret not in "YN":
        DEBUG("ERROR: Unknown return type {} in {}".format(ret, l))
        continue

      ea = idc.get_name_ea_simple(fname)

      if not is_invalid_ea(ea):
        if not is_external_segment(ea) and not is_thunk(ea):
          DEBUG("Not treating {} as external, it is defined at {:x}".format(
              fname, ea))
          INTERNALLY_DEFINED_EXTERNALS[fname] = ea
          continue

        # Misidentified and external. This comes up often in PE binaries, for
        # example, we will have the following:
        #
        #   .idata:01400110E8 ; void __stdcall EnterCriticalSection(...)
        #   .idata:01400110E8     extrn EnterCriticalSection:qword
        #
        # Really, we want to try this as code.
        flags = idc.get_full_flags(ea)
        if not idc.is_code(flags) and not idaapi.is_weak_name(ea):
          seg_name = idc.get_segm_name(ea).lower()
          if ".idata" in seg_name:
            EXTERNAL_FUNCS_TO_RECOVER[ea] = fname

          # Refer to issue #308
          else:
            DEBUG("WARNING: External {} at {:x} from definitions file may not be a function".format(
              fname, ea))

      EMAP[fname] = (int(args), realconv, ret, sign)
      if ret == 'Y':
        noreturn_external_function(fname, int(args), realconv, ret, sign)

      # Sometimes there will be things like `__imp___gmon_start__` which
      # is really the implementation of `__gmon_start__`, where that is
      # a weak symbol.
      if is_linux:
        imp_name = "__imp_{}".format(fname)

        if idc.get_name_ea_simple(imp_name):
          _FIXED_EXTERNAL_NAMES[imp_name] = fname
          WEAK_SYMS.add(fname)
          WEAK_SYMS.add(imp_name)

  df.close()

def parse_fextern_defs_file(df):
  """Parse the file containing forced external function which
  does not need to be recovered.
  """
  global FORCED_EXTERNAL_EMAP

  for l in df.readlines():
    #skip comments / empty lines
    l = l.strip()
    if not l or l[0] == "#":
      continue

    fname = args = conv = ret = None
    line_args = l.split()

    if len(line_args) == 4:
      (fname, args, conv, ret) = line_args

    if conv == "C":
      realconv = CFG_pb2.ExternalFunction.CallerCleanup
    elif conv == "E":
      realconv = CFG_pb2.ExternalFunction.CalleeCleanup
    elif conv == "F":
      realconv = CFG_pb2.ExternalFunction.FastCall
    else:
      DEBUG("ERROR: Unknown calling convention for forced extern : {}".format(l))
      continue

    if ret not in "YN":
      DEBUG("ERROR: Unknown return type {} in {}".format(ret, l))
      continue

    ea = idc.get_name_ea_simple(fname)

    FORCED_EXTERNAL_EMAP[fname] = (int(args), realconv, ret, None)

  df.close()

def is_external_reference(ea):
  """Returns `True` if `ea` references external data."""
  return is_external_segment(ea) \
    or ea in EXTERNAL_VARS_TO_RECOVER \
    or ea in EXTERNAL_FUNCS_TO_RECOVER

def get_function_name(ea):
  """Return name of a function, as IDA sees it. This includes allowing
  dummy names, e.g. `sub_abc123`."""
  return get_symbol_name(ea, ea, allow_dummy=True)

def undecorate_external_name(fn):
  # Don't mangle symbols for fully linked ELFs... yet
  in_a_map = fn in EMAP or fn in EMAP_DATA
  if not is_linked_ELF_program():
    if fn.startswith("__imp_"):
      fn = fn[6:]

    if fn.endswith("_0"):
      fn = fn[:-2]

    # name could have been modified by the above tests
    in_a_map = fn in EMAP or fn in EMAP_DATA

    if fn.startswith("_") and not in_a_map:
      fn = fn[1:]

    if fn.startswith("@") and not in_a_map:
      fn = fn[1:]

    if IS_ELF and '@' in fn:
      fn = fn[:fn.find('@')]

  fixfn = get_true_external_name(fn)
  return fixfn

_ELF_THUNKS = {}
_NOT_ELF_THUNKS = set()
_INVALID_THUNK = (False, idc.BADADDR, "")
_INVALID_THUNK_ADDR = (False, idc.BADADDR)

# NOTE(pag): `is_ELF_thunk_by_structure` is arch-specific.

def is_thunk_by_flags(ea):
  """Try to identify a thunk based off of the IDA flags. This isn't actually
  specific to ELFs.

  IDA seems to have a kind of thunk-propagation. So if one thunk calls
  another thunk, then the former thing is treated as a thunk. The former
  thing will not actually follow the 'structured' form matched above, so
  we'll try to recursively match to the 'final' referenced thunk."""
  global _INVALID_THUNK_ADDR

  if not is_thunk(ea):
    return _INVALID_THUNK_ADDR
  
  ea_name = get_function_name(ea)
  inst, _ = decode_instruction(ea)
  if not inst:
    DEBUG("WARNING: {} at {:x} is a thunk with no code??".format(ea_name, ea))
    return _INVALID_THUNK_ADDR

  # Recursively find thunk-to-thunks.
  if is_direct_jump(inst) or is_direct_function_call(inst):
    targ_ea = get_direct_branch_target(inst)
    targ_is_thunk = is_thunk(targ_ea)
    if targ_is_thunk:
      targ_thunk_name = get_symbol_name(ea, targ_ea)
      DEBUG("Found thunk-to-thunk {:x} -> {:x}: {} to {}".format(
          ea, targ_ea, ea_name, targ_thunk_name))
      return True, targ_ea
    
    DEBUG("ERROR? targ_ea={:x} is not thunk".format(targ_ea))

  if not is_external_reference(ea):
    return _INVALID_THUNK_ADDR

  return True, targ_ea

def try_get_thunk_name(ea):
  """Try to figure out if a function is actually a thunk, i.e. a function
  that represents a 'local' definition for an external function. Thunks work
  by having the local function jump through a function pointer that is
  resolved at runtime."""
  global _ELF_THUNKS, _NOT_ELF_THUNKS, _INVALID_THUNK

  if ea in _ELF_THUNKS:
    return _ELF_THUNKS[ea]

  if ea in _NOT_ELF_THUNKS:
    _NOT_ELF_THUNKS.add(ea)
    return _INVALID_THUNK

  # Try two approaches to detecting whether or not
  # something is a thunk.
  is_thunk = False
  target_ea = idc.BADADDR
  if IS_ELF:
    is_thunk, target_ea = is_ELF_thunk_by_structure(ea)

  if not is_thunk:
    is_thunk, target_ea = is_thunk_by_flags(ea)
  
  if not is_thunk:
    _NOT_ELF_THUNKS.add(ea)
    return _INVALID_THUNK

  else:
    name = get_function_name(target_ea)
    name = undecorate_external_name(name)
    name = get_true_external_name(name)
    # if the elf thunk name is not in external table
    if name not in EMAP:
      DEBUG("WARNING: Adding {} as external function".format(name))
      EMAP[name] = (16, CFG_pb2.ExternalFunction.CallerCleanup, "N", None)

    ret = (is_thunk, target_ea, name)
    _ELF_THUNKS[ea] = ret
    return ret

_REFERENCE_OPERAND_TYPE = {
  Reference.IMMEDIATE: CFG_pb2.CodeReference.ImmediateOperand,
  Reference.DISPLACEMENT: CFG_pb2.CodeReference.MemoryDisplacementOperand,
  Reference.MEMORY: CFG_pb2.CodeReference.MemoryOperand,
  Reference.CODE: CFG_pb2.CodeReference.ControlFlowOperand,
}

def reference_operand_type(ref):
  global _REFERENCE_OPERAND_TYPE
  return _REFERENCE_OPERAND_TYPE[ref.type]

def referenced_name(ref):
  if ref.ea in EXTERNAL_VARS_TO_RECOVER:
    return EXTERNAL_VARS_TO_RECOVER[ref.ea]
  elif ref.ea in EXTERNAL_FUNCS_TO_RECOVER:
    return EXTERNAL_FUNCS_TO_RECOVER[ref.ea]
  else:
    return get_true_external_name(ref.symbol)

_OPERAND_NAME = {
  CFG_pb2.CodeReference.ImmediateOperand: "imm",
  CFG_pb2.CodeReference.MemoryDisplacementOperand: "disp",
  CFG_pb2.CodeReference.MemoryOperand: "mem",
  CFG_pb2.CodeReference.ControlFlowOperand: "flow",
}

def format_instruction_reference(ref):
  """Returns a string representation of a cross reference contained
  in an instruction."""
  mask_begin = ""
  mask_end = ""
  if ref.mask:
    mask_begin = "("
    mask_end = " & {:x})".format(ref.mask)

  return "({} {}{:x}{})".format(
      _OPERAND_NAME[ref.operand_type],
      mask_begin,
      ref.ea,
      mask_end)

def recover_instruction_references(I, inst, addr, refs):
  """Add the memory/code reference information from this instruction
  into the CFG format. The LLVM side of things needs to be able to
  match instruction operands to references to internal/external
  code/data.

  The `get_instruction_references` gives us an accurate picture of the
  references as they are, but in practice we want a higher-level perspective
  that resolves things like thunks to their true external representations.

  Note: References are a kind of gotcha that need special explaining. We kind
  of 'devirtualize' references. An example of this is:
    
    extern:00000000002010A8         extrn stderr@@GLIBC_2_2_5

    extern:00000000002010D8 ; struct _IO_FILE *stderr
    extern:00000000002010D8         extrn stderr
              |           ; DATA XREF: .got:stderr_ptr
              `-------------------------------.
                              |             
      .got:0000000000200FF0 stderr_ptr    dq offset stderr
                  |       ; DATA XREF: main+12
                  `-------------------------------.
                                  | 
     .text:0000000000000932         mov   rax, cs:stderr_ptr
     .text:0000000000000939         mov   rdi, [rax]    ; stream
                  ...
     .text:0000000000000949         call  _fprintf
  
  So above we see that the `mov` instruction is dereferencing `stderr_ptr`,
  and from there it's getting the address of `stderr`. Then it dereferences
  that, which is the value of `stderr, getting us the address of the `FILE *`.
  That is passed at the first argument to `fprintf`.

  Now, what we see in the `mcseam-disass` log is a bit different.

      Variable at 200ff0 is the external stderr
      Variable at 2010a8 is the external stderr
      Variable at 2010d8 is the external stderr
              ...
      I: 932 (data mem external 200ff0 stderr)

  So even though the `mov` instruction uses `stderr_ptr` and an extra level
  of indirection, we devirtualize that to `stderr`. But, how could this work?
  It seems like it's removing a layer of indirection. The answer is on the
  LLVM side of things.

  On the LLVM side, `stderr` is a global variable:

      @stderr = external global %struct._IO_FILE*, align 8

  And the corresponding call is:

    %4 = load %struct._IO_FILE*, %struct._IO_FILE** @stderr, align 8
    %5 = call i32 (...) @fprintf(%struct._IO_FILE* %4, i8* ...)

  So now we see that by declaring the global variable `stderr` on the LLVM
  side, we regain this extra level of indirection because all global variables
  are really pointers to their type (i.e. `%struct._IO_FILE**`), thus we
  preserve the intent of the original assembly.
  """
  DEBUG_PUSH()
  debug_info = ["I: {:x}".format(addr)]
  for ref in refs:
    if not ref.is_valid():
      DEBUG("POSSIBLE ERROR: Invalid reference {} at instruction {:x}".format(
          str(ref), inst.ea))
      continue

    # Redirect the thunk target to the internal target.
    if ref.ea in INTERNAL_THUNK_EAS:
      ref.ea = INTERNAL_THUNK_EAS[ref.ea]
      ref.symbol = get_symbol_name(ref.ea)

    if Reference.CODE == ref.type:
      is_thunk, thunk_target_ea, thunk_name = try_get_thunk_name(ref.ea)
      if is_thunk:
        ref.ea = thunk_target_ea
        ref.symbol = thunk_name

    R = I.xrefs.add()
    R.ea = ref.ea
    if ref.mask:
      R.mask = ref.mask
    if ref.imm_val:
      R.ea = ref.imm_val

    R.operand_type = reference_operand_type(ref)
    
    debug_info.append(format_instruction_reference(R))

  DEBUG_POP()
  DEBUG(" ".join(debug_info))

def recover_instruction_offset_table(I, table):
  """Recovers an offset table as a kind of reference."""
  DEBUG("Offset-based jump table")
  R = I.xrefs.add()
  R.ea = table.offset
  R.operand_type = CFG_pb2.CodeReference.OffsetTable

def try_recovery_external_flow(I, inst, refs):
  """We have somehting like:
  
      jmp     cs:EnterCriticalSection
  
  Where `EnterCriticalSection` is in the `.idata` section and is filled in at
  load time to contain the real address of the external
  `EnterCriticalSection`."""
  if not (is_indirect_jump(inst) or is_indirect_function_call(inst)) or \
     not refs or len(refs) > 1:
    return

  ref = refs[0]
  if ref.type == Reference.CODE or ref.ea not in EXTERNAL_FUNCS_TO_RECOVER:
    return

  R = I.xrefs.add()
  R.ea = ref.ea
  R.operand_type = CFG_pb2.CodeReference.ControlFlowOperand

  if is_indirect_jump(inst):
    DEBUG("Tail-calls external {}".format(R.ea))
  else:
    DEBUG("Calls external {}".format(R.ea))

# Groups preserved register sets that save/restore the same set of registers.
_REG_SETS = {}

def recover_instruction(M, F, B, ea):
  """Recover an instruction, adding it to its parent block in the CFG."""
  global _REG_SETS

  inst, inst_bytes = decode_instruction(ea)

  I = B.instructions.add()
  I.ea = ea  # May not be `inst.ea` because of prefix coalescing.

  xrefs = get_instruction_references(inst, PIE_MODE)
  recover_instruction_references(I, inst, ea, xrefs)
  regs_saved = recover_preserved_regs(M, F, inst, xrefs, _REG_SETS)

  DEBUG_PUSH()
  table = get_jump_table(inst, PIE_MODE)
  if table and table.offset and \
     not is_invalid_ea(table.offset * table.offset_mult):
    recover_instruction_offset_table(I, table)

  if not table:
    try_recovery_external_flow(I, inst, xrefs)

  if regs_saved and len(regs_saved):
    DEBUG("Added save record: {}".format(regs_saved))

  DEBUG_POP()

  return I

def recover_basic_block(M, F, block_ea):
  """Add in a basic block to a specific function in the CFG."""
  if is_external_segment_by_flags(block_ea):
    DEBUG("BB: {:x} in func {:x} is an external".format(block_ea, F.ea))
    return

  inst_eas, succ_eas = analyse_block(F.ea, block_ea, PIE_MODE)

  DEBUG("BB: {:x} in func {:x} with {} insts".format(
      block_ea, F.ea, len(inst_eas)))
  
  B = F.blocks.add()
  B.ea = block_ea

  DEBUG_PUSH()

  B.is_referenced_by_data = False
  if is_jump_table_target(block_ea) or \
     idaapi.get_first_dref_to(block_ea) != idc.BADADDR or \
     has_our_dref_to(block_ea):
    DEBUG("Referenced by data")
    B.is_referenced_by_data = True

  I = None
  for inst_ea in inst_eas:
    I = recover_instruction(M, F, B, inst_ea)
    # Get the landing pad associated with the instructions;
    # 0 if no landing pad associated
    if RECOVER_EHTABLE is True and I:
      I.lp_ea = get_exception_landingpad(F, inst_ea)

  DEBUG_PUSH()

  if len(succ_eas) > 0:
    B.successor_eas.extend(succ_eas)
    DEBUG("Successors: {}".format(", ".join("{0:x}".format(i) for i in succ_eas)))
  else:
    DEBUG("No successors")

  DEBUG_POP()
  DEBUG_POP()

def analyze_jump_table_targets(inst, new_eas, new_func_eas):
  """Function recovery is an iterative process. Sometimes we'll find things
  in the entries of the jump table that we need to go mark as code to be
  added into the CFG."""
  table = get_jump_table(inst, PIE_MODE)
  if not table:
    return

  for entry_addr, entry_target in table.entries.items():
    new_eas.add(entry_target)
    if is_start_of_function(entry_target):
      DEBUG("  Jump table {:x} entry at {:x} references function at {:x}".format(
          table.table_ea, entry_addr, entry_target))
      new_func_eas.append(entry_target)
    else:
      DEBUG("  Jump table {:x} entry at {:x} references block at {:x}".format(
          table.table_ea, entry_addr, entry_target))

def recover_value_spec(V, spec):
  """Recovers an Anvill value specification into the CFG proto format."""
  V.type = spec["type"]

  if "name" in spec and len(spec["name"]):
    V.name = spec["name"]

  if "register" in spec:
    V.register = spec["register"]
  elif "memory" in spec:
    mem_spec = spec["memory"]
    V.memory.register = mem_spec["register"]
    if mem_spec["offset"]:
      V.memory.offset = mem_spec["offset"]

def recover_function_spec(F, spec):
  """Recovers most of an Anvill function specification into the CFG proto format."""
  D = F.decl

  if "is_noreturn" in spec:
    D.is_noreturn = spec["is_noreturn"]
  else:
    D.is_noreturn = False
  
  if "is_variadic" in spec:
    D.is_variadic = spec["is_variadic"]
  else:
    D.is_variadic = False

  if "parameters" in spec:
    for param in spec["parameters"]:
      P = D.parameters.add()
      recover_value_spec(P, param)

  if "return_values" in spec:
    for ret_val in spec["return_values"]:
      V = D.return_values.add()
      recover_value_spec(V, ret_val)

  if "calling_convention" in spec:
    D.calling_convention = spec["calling_convention"]
  else:
    D.calling_convention = 0

  recover_value_spec(D.return_address, spec["return_address"])
  recover_value_spec(D.return_stack_pointer, spec["return_stack_pointer"])

def try_get_anvill_func(func_ea, is_thunk, thunk_target_ea):
  """Try to get the Anvill Function object for the function associated with
  `func_ea`, and if it's a thunk, then `thunk_target_ea`."""
  
  if is_thunk:
    try:
      if ANVILL_PROGRAM.add_function_declaration(thunk_target_ea):
        return ANVILL_PROGRAM.get_function(thunk_target_ea)
    except Exception as e:
      pass

  try:
    if ANVILL_PROGRAM.add_function_declaration(func_ea):
      return ANVILL_PROGRAM.get_function(func_ea)
  except:
    pass
  
  return None

_RECOVERED_FUNCS = set()

def recover_function(M, func_ea, new_func_eas, entrypoints, prev_F, processed_blocks):
  """Decode a function and store it, all of its basic blocks, and all of
  their instructions into the CFG file."""
  global _RECOVERED_FUNCS
  global ANVILL_PROGRAM
  global EXTERNAL_FUNCS_TO_RECOVER
  if func_ea in _RECOVERED_FUNCS:
    return prev_F

  _RECOVERED_FUNCS.add(func_ea)

  # `func_ea` could be the entrypoint but may not be identified
  # as the start of the function.
  if not is_start_of_function(func_ea): # and func_ea not in entrypoints:
    DEBUG("{:x} is not a function! Not recovering.".format(func_ea))
    return prev_F

  # Double check to see if it looks like a thunk, and if so, we'll just
  # re-direct to that.
  is_thunk, thunk_target_ea, name = try_get_thunk_name(func_ea)
  if is_thunk and name and is_external_segment(thunk_target_ea):
    EXTERNAL_FUNCS_TO_RECOVER[func_ea] = name
    DEBUG("Deferring recovery of thunk {:x}, resolved to external {}".format(
        func_ea, name))
    return prev_F

  name = get_symbol_name(func_ea)
  processed_blocks.clear()
  F = M.funcs.add()
  F.ea = func_ea
  F.is_entrypoint = (func_ea in entrypoints)

  if not name:
    DEBUG("Recovering {:x}".format(func_ea))
  else:
    F.name = name.format('utf-8')
    DEBUG("Recovering {} at {:x}".format(F.name, func_ea))

    # Try to get the Anvill representation of this function.
    anvill_func = try_get_anvill_func(func_ea, is_thunk, thunk_target_ea)
    if anvill_func:
      recover_function_spec(F, anvill_func.proto())

  DEBUG_PUSH()

  # Update the protobuf with the recovered eh_frame entries
  if RECOVER_EHTABLE is True:
    recover_exception_entries(F, func_ea)
  block_eas, term_insts = analyse_subroutine(func_ea, PIE_MODE)

  for term_inst in term_insts:
    if get_jump_table(term_inst, PIE_MODE):
      DEBUG("Terminator inst {:x} in func {:x} is a jump table".format(
          term_inst.ea, func_ea))
      analyze_jump_table_targets(term_inst, block_eas, new_func_eas)
  
  while len(block_eas) > 0:
    block_ea = block_eas.pop()
    if block_ea in processed_blocks:
      DEBUG("ERROR: Attempting to add same block twice: {0:x}".format(block_ea))
      continue

    processed_blocks.add(block_ea)
    recover_basic_block(M, F, block_ea)

  DEBUG_POP()
  return F

def find_default_function_heads():
  """Loop through every function, to discover the heads of all blocks that
  IDA recognizes. This will populate some global sets in `flow.py` that
  will help distinguish block heads."""
  func_eas = []
  for seg_ea in idautils.Segments():
    seg_type = idc.get_segm_attr(seg_ea, idc.SEGATTR_TYPE)
    if seg_type != idc.SEG_CODE:
      continue

    for func_ea in idautils.Functions(seg_ea, idc.get_segm_end(seg_ea)):
      if is_code_by_flags(func_ea):
        func_eas.append(func_ea)

  return func_eas

def recover_region_variables(M, S, seg_ea, seg_end_ea, exported_vars):
  """Look for named locations pointing into the data of this segment, and
  add them to the protobuf."""
  is_code_seg = is_code(seg_ea)

  for ea, name in idautils.Names():
    if ea < seg_ea or ea >= seg_end_ea:
      continue

    if is_external_segment_by_flags(ea) or ea in EXTERNAL_VARS_TO_RECOVER:
      continue

    if is_code_seg and is_code_by_flags(ea):
      continue

    # Only add named internal variables if they are referenced or exported. 
    if is_referenced(ea) or ea in exported_vars:
      DEBUG("Variable {} at {:x}".format(name, ea))
      V = S.vars.add()
      V.ea = ea
      V.name = name.format('utf-8')

def recover_region_cross_references(M, S, seg_ea, seg_end_ea):
  """Goes through the segment and identifies fixups that need to be
  handled by the LLVM side of things."""

  # Go through and look for the fixups. We start at `seg_ea - 1` because we
  # always try to find the *next* fixup/heads, and if there's one right at
  # the beginning of the segment then we don't want to jump to the second one.
  global PIE_MODE

  max_xref_width = get_address_size_in_bytes()
  min_xref_width = PIE_MODE and max_xref_width or 4

  is_code_seg = is_code(seg_ea)
  seg_name = idc.get_segm_name(seg_ea)
  has_func_pointers = segment_contains_external_function_pointers(seg_ea)

  ea, next_ea = seg_ea, seg_ea
  while next_ea < seg_end_ea:
    ea = next_ea

    # The item size is 1 in some of the cases where it refer to the external data. The
    # references in such cases get ignored. Assign the address size if there is reference
    # to the external data.
    item_size = idc.get_item_size(ea)
    xref_width = min(max(item_size, 4), max_xref_width)
    next_ea = min(ea + xref_width,
                  # idc.GetNextFixupEA(ea),
                  idc.next_head(ea, seg_end_ea))

    # This data is a copy of shared data.
    if is_runtime_external_data_reference(ea):
      continue

    # We don't want to fill the jump table bytes with their actual
    # code cross-references. This is because we can't get the address
    # of a basic block. Our goal is thus to preserve the original values,
    # and implement the switch in terms of those original values on the
    # LLVM side of things.
    #if is_jump_table_entry(ea):
    #  continue

    # Skip over instructions.
    if is_code_seg:
      flags = idc.get_full_flags(ea)
      if idc.is_code(flags):
        next_ea = idc.next_head(ea, seg_end_ea)
        continue

    target_ea = get_reference_target(ea)

    # Handle entries in the `.got.plt` and `.idata` segments. In ELF binaries,
    # this looks like:
    #
    #     .got.plt:000000000032E058 off_32E058      dq offset getenv
    #
    # In PE binaries, this looks like:
    #
    #     .idata:00000001400110D8 ; DWORD __stdcall GetLastError()
    #     .idata:00000001400110D8                 extrn GetLastError:qword
    if is_invalid_ea(target_ea):
      if has_func_pointers and ea in EXTERNAL_FUNCS_TO_RECOVER:
        target_ea = ea

    # Note: it's possible that `ea == target_ea`. This happens with
    #     external references to things like `stderr`, where there's 
    #     an internal slot, whose value is filled in at runtime. 
    if is_invalid_ea(target_ea):
      continue

    elif (ea % 4) != 0:
      DEBUG("WARNING: Unaligned reference at {:x} to {:x}".format(ea, target_ea))
      continue

    elif item_size < min_xref_width:
      DEBUG("WARNING: Ingorning {}-byte item that looks like at reference from {:x} to {:x}; it needs to be at least {} bytes".format(
          item_size, ea, target_ea, min_xref_width))
      continue

    # Probably some really small number.
    elif not idc.get_full_flags(target_ea):
      DEBUG("WARNING: No information about target {:x} from {:x}".format(
          target_ea, ea))
      continue

    else:
      X = S.xrefs.add()
      X.ea = ea
      X.width = xref_width
      X.target_ea = target_ea
      target_name = get_symbol_name(target_ea)

      if is_external_segment(X.target_ea):
        target_name = get_true_external_name(target_name)

      # A cross-reference to some TLS data. Because each thread has its own
      # instance of the data, this reference ends up actually being an offset
      # from a thread base pointer. In x86, this tends to be the base of one of
      # the segment registers, e.g. `fs` or `gs`. On the McSema side, we fill in
      # this xref lazily by computing the offset.
      if is_tls(target_ea):
        X.target_fixup_kind = CFG_pb2.DataReference.OffsetFromThreadBase
        DEBUG("{}-byte TLS offset at {:x} to {:x} ({})".format(
            X.width, ea, target_ea, target_name))

      # A cross-reference to a 'single' thing, where the fixup that we create
      # will be an absolute address to the targeted variable/function.
      else:
        X.target_fixup_kind = CFG_pb2.DataReference.Absolute
        DEBUG("{}-byte reference at {:x} to {:x} ({})".format(
            X.width, ea, target_ea, target_name))

        try_identify_as_external_function(target_ea, target_name)


def recover_region(M, region_name, region_ea, region_end_ea, exported_vars):
  """Recover the data and cross-references from a segment. The data of a
  segment is stored verbatim within the protobuf, and accompanied by a
  series of variable and cross-reference entries."""

  seg_name = idc.get_segm_name(region_ea)

  DEBUG("Recovering region {} [{:x}, {:x}) in segment {}".format(
      region_name, region_ea, region_end_ea, seg_name))

  seg = idaapi.getseg(region_ea)

  # An item spans two regions. This may mean that there's a reference into
  # the middle of an item. This happens with strings.
  item_size = idc.get_item_size(region_end_ea - 1)
  if 1 < item_size:
    DEBUG("  ERROR: Segment should probably include {} more bytes".format(
        item_size - 1))

  S = M.segments.add()
  S.ea = region_ea
  S.data = read_bytes_slowly(region_ea, region_end_ea)
  S.read_only = (seg.perm & idaapi.SEGPERM_WRITE) == 0
  S.is_external = is_external_segment_by_flags(region_ea)
  S.is_thread_local = is_tls_segment(region_ea)
  S.name = seg_name.format('utf-8')
  S.is_exported = region_ea in exported_vars

  if region_name != seg_name:
    S.variable_name = region_name.format('utf-8')

  DEBUG_PUSH()
  recover_region_cross_references(M, S, region_ea, region_end_ea)
  recover_region_variables(M, S, region_ea, region_end_ea, exported_vars)
  DEBUG_POP()

def recover_regions(M, exported_vars, global_vars=[]):
  """Recover all non-external segments into the CFG module. This will also
  recover global variables, specified in terms of a list of
  `(name, begin_ea, end_ea)` tuples, as their own segments."""

  seg_names = {}

  # Collect the segment bounds to lift.
  seg_parts = collections.defaultdict(set)
  for seg_ea in idautils.Segments():
    seg_name = idc.get_segm_name(seg_ea)
    seg_names[seg_ea] = seg_name

    if (not is_external_segment_by_flags(seg_ea) or \
        segment_contains_external_function_pointers(seg_ea)) and \
        not (is_constructor_segment(seg_ea) or is_destructor_segment(seg_ea)):
      seg_parts[seg_ea].add(seg_ea)
      seg_parts[seg_ea].add(idc.get_segm_end(seg_ea))

    # Fix for an important feature - static storage allocation of the objects in C++, where
    # the constructor gets invoked before the main and it typically calls the 'init/__libc_csu_init' function.
    #
    # The function iterate over the array conatined in .init_array initializing the global constructor/destructor
    # function pointers using the symbol `off_201D70` and `off_201D80` as the array bounds as shown below. These
    # symbols falls in section `.init_array` and `.fini_array` correspondingly.
    #
    # .init_array:0000000000201D70 ; ELF Initialization Function Table
    # .init_array:0000000000201D70 ; ===========================================================================
    # .init_array:0000000000201D70 ; Segment type: Pure data
    # .init_array:0000000000201D70 _init_array     segment para public 'DATA' use64
    # .init_array:0000000000201D70                 assume cs:_init_array
    # .init_array:0000000000201D70                 ;org 201D70h
    # .init_array:0000000000201D70 off_201D70      dq offset sub_C40
    # .init_array:0000000000201D70
    # .init_array:0000000000201D78                 dq offset sub_10E5
    # .init_array:0000000000201D78 _init_array     ends
    #
    # .fini_array:0000000000201D80 ; ELF Termination Function Table
    # .fini_array:0000000000201D80 ; ===========================================================================
    # .fini_array:0000000000201D80 ; Segment type: Pure data
    # .fini_array:0000000000201D80 _fini_array     segment para public 'DATA' use64
    # .fini_array:0000000000201D80                 assume cs:_fini_array
    # .fini_array:0000000000201D80                 ;org 201D80h
    # .fini_array:0000000000201D80 off_201D80      dq offset sub_C00
    # .fini_array:0000000000201D80 _fini_array     ends
    #
    # .text:0000000000001160 ; void init(void)
    # .text:0000000000001160                 push    r15
    # .text:0000000000001162                 mov     r15d, edi
    # .text:0000000000001165                 push    r14
    # .text:0000000000001167                 mov     r14, rsi
    # .text:000000000000116A                 push    r13
    # .text:000000000000116C                 mov     r13, rdx
    # .text:000000000000116F                 push    r12
    # .text:0000000000001171                 lea     r12, off_201D70
    # .text:0000000000001178                 push    rbp
    # .text:0000000000001179                 lea     rbp, off_201D80
    # .text:0000000000001180                 push    rbx
    # .text:0000000000001181                 sub     rbp, r12
    # .text:0000000000001184                 xor     ebx, ebx
    # .text:0000000000001186                 sar     rbp, 3
    # .text:000000000000118A                 sub     rsp, 8
    # .text:000000000000118E                 call    _init_proc
    # ...
    # Extracting these sections as different LLVM GlobalVariable will not guarantee the adjacency placement in
    # recompiled binary. Hence it should be lifted as one LLVM GlobalVariable if they are adjacent.

    if is_constructor_segment(seg_ea):
      seg_parts[seg_ea].add(seg_ea)
      end_ea =  idc.get_segm_end(seg_ea)
      if is_destructor_segment(end_ea):
        seg_parts[seg_ea].add(idc.get_segm_end(end_ea))
        DEBUG("WARNING: Global constructor and destructor sections are adjacent!")
      else:
        seg_parts[seg_ea].add(end_ea)
        fini_ea = get_destructor_segment()
        if fini_ea:
          seg_parts[fini_ea].add(fini_ea)
          seg_parts[fini_ea].add(idc.get_segm_end(fini_ea))

  # Treat analysis-identified global variables as segment begin/end points.
  for var_name, begin_ea, end_ea in global_vars:
    if is_invalid_ea(begin_ea) or is_invalid_ea(end_ea):
      DEBUG("ERROR: Variable {} at [{:x}, {:x}) is not valid.".format(
          var_name, begin_ea, end_ea))
      continue

    if is_external_segment_by_flags(begin_ea):
      DEBUG("ERROR: Variable {} at [{:x}, {:x}) is in an external segment.".format(
          var_name, begin_ea, end_ea))
      continue

    seg_ea = idc.get_segm_start(begin_ea)
    seg_name = idc.get_segm_name(seg_ea)

    DEBUG("Splitting segment {} from {:x} to {:x} for global variable {}".format(
        seg_name, begin_ea, end_ea, var_name))

    seg_parts[seg_ea].add(begin_ea)
    seg_names[begin_ea] = var_name

    if end_ea <= idc.get_segm_end(seg_ea):
      seg_parts[seg_ea].add(end_ea)

  # Treat exported variables as segment begin/end points.
  for var_ea in exported_vars:
    seg_ea = idc.get_segm_start(var_ea)
    seg_name = idc.get_segm_name(seg_ea)
    var_name = get_symbol_name(var_ea)
    seg_parts[seg_ea].add(var_ea)
    seg_names[var_ea] = var_name
    DEBUG("Splitting segment {} at {:x} for exported variable {}".format(
        seg_name, var_ea, var_name))

  for seg_ea, eas in seg_parts.items():
    parts = list(sorted(list(eas)))
    seg_name = idc.get_segm_name(seg_ea)
    for begin_ea, end_ea in zip(parts[:-1], parts[1:]):
      region_name = seg_name
      if begin_ea in seg_names and \
        not is_runtime_external_data_reference(begin_ea):
        region_name = seg_names[begin_ea]

      recover_region(M, region_name, begin_ea, end_ea, exported_vars)

def recover_external_functions(M):
  """Recover the named external functions (e.g. `printf`) that are referenced
  within this binary."""
  global EXTERNAL_FUNCS_TO_RECOVER, WEAK_SYMS, EMAP

  for ea, name in EXTERNAL_FUNCS_TO_RECOVER.items():
    
    # Try to fix up the name. Sometimes the thunks have names like `_setlocale`,
    # whereas the external will have the proper `setlocate` name.
    is_thunk, thunk_target_ea, thunk_name = try_get_thunk_name(ea)
    if is_thunk and thunk_name:
      name = thunk_name

    if name not in EMAP and not try_infer_func_for_emap(name, ea):
      DEBUG("ERROR: Not recovering external function {} at {:x}; info not in EMAP".format(name, ea))
      return
    
    anvill_func = try_get_anvill_func(ea, False, ea)

    DEBUG("Recovering extern function {} at {:x}".format(name, ea))
    args, conv, ret, sign = EMAP[name]
    E = M.external_funcs.add()
    E.name = name.format('utf-8')
    E.ea = ea
    E.argument_count = args
    E.cc = conv
    E.is_weak = idaapi.is_weak_name(ea) or (name in WEAK_SYMS)
    E.no_return = ret == 'Y'

    # TODO(pag): This should probably reflect whether or not the function
    #            actually returns something, rather than simply does not
    #            return (e.g. `abort`).
    E.has_return = ret == 'N'

    if anvill_func:
      recover_function_spec(E, anvill_func.proto())
    else:
      recover_function_spec_from_arch(E)

def recover_external_variables(M):
  """Reover the named external variables (e.g. `stdout`) that are referenced
  within this binary."""
  global EXTERNAL_VARS_TO_RECOVER, WEAK_SYMS

  for ea, name in EXTERNAL_VARS_TO_RECOVER.items():
    EV = M.external_vars.add()
    EV.ea = ea
    EV.name = name.format('utf-8')
    EV.is_weak = idaapi.is_weak_name(ea) or (name in WEAK_SYMS)
    EV.is_thread_local = is_tls(ea)
    if name in EMAP_DATA:
      EV.size = EMAP_DATA[name]
    else:
      EV.size = idc.get_item_size(ea)
    if EV.is_thread_local:
      DEBUG("Recovering extern TLS variable {} at {:x} [size: {}]".format(name, ea, EV.size))
    else:
      DEBUG("Recovering extern variable {} at {:x} [size: {}]".format(name, ea, EV.size))

def recover_external_symbols(M):
  recover_external_functions(M)
  recover_external_variables(M)

def is_forced_external(ea):
  name = get_function_name(ea)
  return (name in FORCED_EXTERNAL_EMAP)

def add_fextern_to_emap(name, ea):
  if name in FORCED_EXTERNAL_EMAP:
    EMAP[name] = FORCED_EXTERNAL_EMAP[name]

def try_identify_as_external_function(ea, name=None):
  """Try to identify a function as being an external function."""
  global EXTERNAL_FUNCS_TO_RECOVER, EMAP

  if ea in EXTERNAL_FUNCS_TO_RECOVER:
    return True

  if ea in INTERNAL_THUNK_EAS:
    return False
  
  # First, check if it's a thunk. Some thunks are not location in exported
  # sections. Sometimes there are thunk-to-thunks, where there's a function
  # whose only instruction is a direct jump to the real thunk.
  is_thunk, thunk_target_ea, thunk_name = try_get_thunk_name(ea)

  if is_thunk:
    name = thunk_name

  elif is_external_segment(ea):
    name = get_true_external_name(get_function_name(ea))

  elif is_forced_external(ea):
    name = get_function_name(ea)
    add_fextern_to_emap(name, ea)

  elif not name:
    return False

  # We've got a thunk with an implementation already done.
  if name in INTERNALLY_DEFINED_EXTERNALS:
    impl_ea = INTERNALLY_DEFINED_EXTERNALS[name]
    INTERNAL_THUNK_EAS[ea] = impl_ea
    return False

  # If we don't have info about this function from our std defs file, then
  # try to figure it out from IDA's internal info.
  if name not in EMAP:
    if not try_infer_func_for_emap(name, ea):
      return False
    
    # args, conv, ret, sign

  DEBUG("Function at {:x} is the external function {}".format(ea, name))
  EXTERNAL_FUNCS_TO_RECOVER[ea] = name
  return True

def try_infer_func_for_emap(name, ea):
  """Tries to infer function information to add to the EMAP, which stores
  our external info. This uses IDA's internal type info."""
  global _FIXED_EXTERNAL_NAMES
  global WEAK_SYMS

  is_thunk, thunk_target_ea, thunk_name = try_get_thunk_name(ea)
  if not is_thunk:
    return False

  type_info = idaapi.tinfo_t()
  if not idaapi.get_tinfo2(ea, type_info):
    if thunk_target_ea != ea:
      ea = thunk_target_ea
      type_info = idaapi.tinfo_t()
      if not idaapi.get_tinfo2(ea, type_info):
        return False
    else:
      return False

  func_data = idaapi.func_type_data_t()
  if not type_info.get_func_details(func_data):
    return False

  num_args = func_data.size()
  is_noreturn = 'N'
  if is_noreturn_function(ea):
    is_noreturn = 'Y'

  conv = CFG_pb2.ExternalFunction.CallerCleanup
  if func_data.cc & idaapi.CM_CC_STDCALL:
    conv = CFG_pb2.ExternalFunction.CalleeCleanup
  elif func_data.cc & idaapi.CM_CC_FASTCALL:
    conv = CFG_pb2.ExternalFunction.FastCall

  EMAP[name] = (num_args, conv, is_noreturn, None)

  imp_name = "__imp_{}".format(name)
  if idc.get_name_ea_simple(imp_name):
    _FIXED_EXTERNAL_NAMES[imp_name] = name
    WEAK_SYMS.add(name)
    WEAK_SYMS.add(imp_name)

  return True

def force_add_func_to_emap(target_name, ea):
  """Forcefully adds a function to the EMAP."""
  DEBUG("WARNING: Adding external {} at {:x} as an external code reference".format(
      target_name, ea))
  EMAP[target_name] = (16, CFG_pb2.ExternalFunction.CallerCleanup, "N", None)

  imp_name = "__imp_{}".format(target_name)
  if idc.get_name_ea_simple(imp_name):
    _FIXED_EXTERNAL_NAMES[imp_name] = target_name
    WEAK_SYMS.add(target_name)
    WEAK_SYMS.add(imp_name)

def identify_thunks(func_eas):
  DEBUG("Looking for thunks")
  DEBUG_PUSH()
  for func_ea in func_eas:
    is_thunk, thunk_target_ea, name = try_get_thunk_name(func_ea)
    if is_thunk:
      DEBUG("Found thunk for {} targeting {:x} at {:x}".format(
          name, thunk_target_ea, func_ea))
  DEBUG_POP()

def identify_external_symbols():
  """Try to identify external functions and variables."""
  global _FIXED_EXTERNAL_NAMES

  DEBUG("Looking for external symbols")
  DEBUG_PUSH()
  
  for ea, name in idautils.Names():
    if try_identify_as_external_function(ea) or is_code(ea):
      continue

    elif is_ELF_got_pointer(ea):
      target_ea = get_reference_target(ea)
      target_name = get_true_external_name(get_symbol_name(target_ea))
      
      # Detect missing references.
      if is_external_segment(target_ea):
        if target_name not in EMAP_DATA and target_name not in EMAP:
          DEBUG("ERROR: Missing external reference information for {} referenced at {:x}".format(
              target_name, ea))

          target_flags = idc.get_full_flags(target_ea)
          
          # The missing reference looks like code, so add it to the EMAP with
          # 16 arguments (probably enough, eh?), and assume it uses the cdecl
          # calling convention.
          #
          # NOTE(pag): We use `idc.is_code` and not `is_code` because the latter
          #            operates at the segment granularity, and `target_ea` will
          #            likely point into the `extern` section. Individual
          #            entries in the extern section can have 
          if idc.is_code(target_flags):
            if not try_infer_func_for_emap(target_name, ea):
              force_add_func_to_emap(target_name, ea)

          # The 
          else:
            DEBUG("WARNING: Adding external {} at {:x} as an external data reference".format(
                target_name, ea))
            EMAP_DATA[target_name] = 8  # TODO(pag): Made up, based on max pointer size.

        elif target_name in EMAP_DATA:
          EXTERNAL_VARS_TO_RECOVER[target_ea] = target_name
        elif target_name in EMAP:
          EXTERNAL_FUNCS_TO_RECOVER[target_ea] = target_name

      # Corner case, there is an external reference in the `.got` section
      # into internal data. This was observed in one binary where
      # `fec_scheme_str_ptr` was an entry in the `.got`, but pointed into the
      # `.data` section.
      else:
        DEBUG("External-looking reference from {} at {:x} to {} at {:x} is actually internal".format(
            name, ea, target_name, target_ea))

        if ea in EXTERNAL_VARS_TO_RECOVER:
          del EXTERNAL_VARS_TO_RECOVER[ea]

        if ea in EXTERNAL_FUNCS_TO_RECOVER:
          del EXTERNAL_FUNCS_TO_RECOVER[ea]

        if ea in _FIXED_EXTERNAL_NAMES:
          del _FIXED_EXTERNAL_NAMES[ea]

        if target_name in EMAP_DATA:
          del EMAP_DATA[target_name]

        if target_name in EMAP:
          del EMAP[target_name]

    elif is_external_segment_by_flags(ea) or is_runtime_external_data_reference(ea):
      # idc.Demangle (...) gives incorrect name for the external data objects
      # only de-mangle the name of the external functions
      extern_name = get_true_external_name(name, demangle=is_code(ea))

      if extern_name in EMAP_DATA:
        DEBUG("Variable at {:x} is the external {}".format(ea, extern_name))
        set_symbol_name(ea, extern_name)
        EXTERNAL_VARS_TO_RECOVER[ea] = extern_name

      elif extern_name in EMAP:
        DEBUG("Function at {:x} is the external {}".format(ea, extern_name))
        set_symbol_name(ea, extern_name)
        EXTERNAL_FUNCS_TO_RECOVER[ea] = extern_name

      else:
        # IDA sometimes does this dumb thing where it will actually have a bunch
        # of names for the same address, and it will choose the wrong one. This
        # tends to happen with the `.bss` section, and can be reproduced by a C
        # file with only one global variable `FILE *fp = stdout;`. Some versions
        # of IDA will treat the local copy of `stdout` as being the symbol
        # `__bss_start`.
        comment = ida_bytes.get_cmt(ea, 0) or ""
        for comment_line in comment.split("\n"):
          comment_line = comment_line.replace(";", "").strip()
          found_name = get_true_external_name(comment_line, demangle=is_code(ea))
          if found_name in EMAP_DATA:
            extern_name = found_name
            break

        if extern_name not in PERSONALITY_FUNCTIONS:
          DEBUG("WARNING: Adding variable {} at {:x} as external".format(
              extern_name, ea))

          set_symbol_name(ea, extern_name)  # Rename it.
          EXTERNAL_VARS_TO_RECOVER[ea] = extern_name
          _FIXED_EXTERNAL_NAMES[ea] = extern_name

  DEBUG_POP()

def identify_program_entrypoints(func_eas):
  """Identify all entrypoints into the program. This is pretty much any
  externally visible function."""
  DEBUG("Looking for entrypoints")
  DEBUG_PUSH()

  exclude = set(["_start", "__libc_csu_fini", "__libc_csu_init", 
                 "__data_start", "__dso_handle", "_IO_stdin_used",
                 "_dl_relocate_static_pie", "__DTOR_END__", "__ashlsi3",
                 "__ashldi3", "__ashlti3", "__ashrsi3", "__ashrdi3", "__ashrti3",
                 "__divsi3", "__divdi3", "__divti3", "__lshrsi3", "__lshrdi3",
                 "__lshrti3", "__modsi3", "__moddi3", "__modti3", "__mulsi3",
                 "__muldi3", "__multi3", "__negdi2", "__negti2", "__udivsi3",
                 "__udivdi3", "__udivti3", "__udivmoddi4", "__udivmodti4",
                 "__umodsi3", "__umoddi3", "__umodti3", "__cmpdi2", "__cmpti2",
                 "__ucmpdi2", "__ucmpti2", "__absvsi2", "__absvdi2", "__addvsi3",
                 "__addvdi3", "__mulvsi3", "__mulvdi3", "__negvsi2", "__negvdi2",
                 "__subvsi3", "__subvdi3", "__clzsi2", "__clzdi2", "__clzti2",
                 "__ctzsi2", "__ctzdi2", "__ctzti2", "__ffsdi2", "__ffsti2",
                 "__paritysi2", "__paritydi2", "__parityti2", "__popcountsi2",
                 "__popcountdi2", "__popcountti2", "__bswapsi2", "__bswapdi2"])

  exported_funcs = set()
  exported_vars = set()

  for index, ordinal, ea, name in idautils.Entries():
    assert ea != idc.BADADDR
    if not is_external_segment(ea):
      sym_name = get_symbol_name(ea, allow_dummy=False)
      if not sym_name:
        DEBUG("WEIRD: Forcing entrypoint {:x} name to be {}".format(ea, name))
        set_symbol_name(ea, name)

      if is_code(ea):
        func_eas.append(ea)
        if name not in exclude:
          exported_funcs.add(ea)
      else:
        # If there is reference to the external vtable in the segment, add it
        # as the exported variables. This is required to preserve the typeinfo
        # of the user-define exception type variables. The lazy initilization
        # of the vtable screw up the associated types.
        # It checks for the following vtable variables:
        #      __ZTVSt9type_info,
        #      __ZTVN10__cxxabiv117__class_type_infoE,
        #      __ZTVN10__cxxabiv120__si_class_type_infoE,
        #      __ZTVN10__cxxabiv121__vmi_class_type_infoE
        if name not in exclude and \
          not is_runtime_external_data_reference(ea) or \
          is_external_vtable_reference(ea):
          exported_vars.add(ea)

  DEBUG_POP()
  return exported_funcs, exported_vars

def find_main_in_ELF_file():
  """Tries to automatically find the `main` function if we haven't found it
  yet. IDA recognizes the pattern of `_start` calling `__libc_start_main` in
  ELF binaries, where one of the parameters is the `main` function. IDA will
  helpfully comment it as such."""

  start_ea = idc.get_name_ea_simple("_start")
  if is_invalid_ea(start_ea):
    start_ea = idc.get_name_ea_simple("start")
    if is_invalid_ea(start_ea):
      return idc.BADADDR

  for begin_ea, end_ea in idautils.Chunks(start_ea):
    for inst_ea in idautils.Heads(begin_ea, end_ea):
      comment = ida_bytes.get_cmt(inst_ea, 0)
      if comment and "main" in comment:
        for main_ea in xrefs_from(inst_ea):
          if not is_code(main_ea):
            continue

          # Sometimes the `main` function isn't identified as code. This comes
          # up when there are some alignment bytes in front of `main`.
          try_mark_as_code(main_ea)
          if is_code_by_flags(main_ea):
            try_mark_as_function(main_ea)

          main = idaapi.get_func(main_ea)
          if not main:
            continue

          if main and main.start_ea == main_ea:
            set_symbol_name(main_ea, "main")
            DEBUG("Found main at {:x}".format(main_ea))
            return main_ea

  return idc.BADADDR

def recover_module(entrypoint, gvar_infile = None):
  global EMAP
  global EXTERNAL_FUNCS_TO_RECOVER
  global INTERNAL_THUNK_EAS

  M = CFG_pb2.Module()
  M.name = idc.get_root_filename().format('utf-8')
  DEBUG("Recovering module {}".format(M.name))
  
  entry_ea = idc.BADADDR
  if args.entrypoint:
    entry_ea = idc.get_name_ea_simple(args.entrypoint)
    # If the entrypoint is `main`, then we'll try to find `main` via another
    # means.
    if is_invalid_ea(entry_ea):
      if "main" == args.entrypoint and IS_ELF:
        entry_ea = find_main_in_ELF_file()

    if not is_invalid_ea(entry_ea):
      DEBUG("Found {} at {:x}".format(args.entrypoint, entry_ea))
      if not is_start_of_function(entry_ea):
        try_mark_as_function(entry_ea)

  if RECOVER_EHTABLE:
    recover_exception_table()

  process_segments(PIE_MODE)

  func_eas = find_default_function_heads()

  recovered_fns = 0

  identify_thunks(func_eas)
  identify_external_symbols()
  
  exported_funcs, exported_vars = identify_program_entrypoints(func_eas)

  if is_invalid_ea(entry_ea):
    if args.entrypoint:
      DEBUG("ERROR: Could not find entrypoint {}".format(args.entrypoint))
  else:
    func_eas.append(entry_ea)
    exported_funcs.add(entry_ea)

  prev_F = None
  processed_blocks = set()

  func_eas.sort(reverse=True)

  # Process and recover functions. 
  while len(func_eas):
    func_ea = func_eas.pop()
    if func_ea in RECOVERED_EAS or func_ea in EXTERNAL_FUNCS_TO_RECOVER:
      continue

    RECOVERED_EAS.add(func_ea)

    if try_identify_as_external_function(func_ea):
      DEBUG("ERROR: External function {:x} not previously identified".format(func_ea))
      continue

    if not is_code_by_flags(func_ea):
      DEBUG("ERROR: Function EA not code: {:x}".format(func_ea))
      continue

    if is_external_segment_by_flags(func_ea):
      continue

    prev_F = recover_function(M, func_ea, func_eas, exported_funcs, prev_F, processed_blocks)
    recovered_fns += 1

  recover_deferred_preserved_regs(M)

  if recovered_fns == 0:
    DEBUG("COULD NOT RECOVER ANY FUNCTIONS")
    return

  global_vars = []  # TODO(akshay): Pass in relevant info.
  
  DEBUG("Global Variable {}".format(gvar_infile))
  if gvar_infile is not None:
    GM = CFG_pb2.Module()
    GM.ParseFromString(gvar_infile.read())
    count = 0
    for gvar in GM.global_vars:
      global_vars.append([gvar.name, gvar.ea, gvar.ea + gvar.size])
      
  recover_regions(M, exported_vars, global_vars)
  recover_external_symbols(M)

  DEBUG("Recovered {0} functions.".format(recovered_fns))
  return M

if __name__ == "__main__":

  parser = argparse.ArgumentParser()

  parser.add_argument(
      "--log_file",
      type=argparse.FileType('w'),
      default=sys.stderr,
      help="Log to a specific file. Default is stderr.")

  parser.add_argument(
      '--arch',
      help='Name of the architecture. Valid names are x86, amd64.',
      required=True)

  parser.add_argument(
      '--os',
      help='Name of the operating system. Valid names are linux, windows.',
      required=True)

  parser.add_argument(
      "--output",
      type=argparse.FileType('wb'),
      default=None,
      help="The output control flow graph recovered from this file",
      required=True)

  parser.add_argument(
      "--std-defs",
      action='append',
      type=str,
      default=[],
      help="std_defs file: definitions and calling conventions of imported functions and data")
  
  parser.add_argument(
      "--syms",
      type=argparse.FileType('r'),
      default=None,
      help="File containing <name> <address> pairs of symbols to pre-define.")

  parser.add_argument(
      "--pie-mode",
      action="store_true",
      default=False,
      help="Assume all immediate values are constants (useful for ELFs built with -fPIE")

  parser.add_argument(
      '--entrypoint',
      help="The entrypoint where disassembly should begin",
      required=False)
  
  parser.add_argument(
      '--recover-global-vars',
      type=argparse.FileType('r'),
      default=None,
      help="File containing the global variables to be lifted")

  parser.add_argument(
      '--recover-stack-vars',
      action="store_true",
      default=False,
      help="Flag to enable stack variable recovery")

  parser.add_argument(
      '--recover-exception',
      action="store_true",
      default=False,
      help="Flag to enable the exception handler recovery")

  parser.add_argument(
      '--forced-extern-defs',
      help='List of functions which are forced to be extern and dont need to be recovered',
      default=None,
      required=False)

  parser.add_argument(
      "--rebase",
      help="Amount by which to rebase a binary",
      default=0,
      type=int,
      required=False)

  args = parser.parse_args(args=idc.ARGV[1:])

  if args.log_file != os.devnull:
    INIT_DEBUG_FILE(args.log_file)
    DEBUG("Debugging is enabled.")

  addr_size = {"x86": 32, "amd64": 64, "aarch64": 64, "sparc32": 32,  "sparc64": 64}.get(args.arch, 0)
  if addr_size != get_address_size_in_bits():
    DEBUG("Arch {} address size does not match IDA's available bitness {}! Did you mean to use idal64?".format(
        args.arch, get_address_size_in_bits()))
    idc.process_config_line("ABANDON_DATABASE=YES")
    idc.qexit(-1)

  if args.pie_mode:
    DEBUG("Using PIE mode.")
    PIE_MODE = True
    
  if args.recover_stack_vars:
    DEBUG("Stack variable recovery is deprecated")

  if args.recover_exception:
    RECOVER_EHTABLE = True

  EMAP = {}
  EMAP_DATA = {}

  # Try to find the defs file or this OS
  OS_NAME = args.os
  os_defs_file = os.path.join(tools_disass_dir, "defs", "{}.txt".format(args.os))
  if os.path.isfile(os_defs_file):
    args.std_defs.insert(0, os_defs_file)

  # Load in all defs files, include custom ones.
  for defsfile in args.std_defs:
    with open(defsfile, "r") as df:
      DEBUG("Loading Standard Definitions file: {0}".format(defsfile))
      parse_os_defs_file(df)

  if args.forced_extern_defs:
    defsfile_list = args.forced_extern_defs.split(',')
    for defsfile in defsfile_list:
      extern_defsfile = os.path.abspath(defsfile)
      with open(extern_defsfile, 'r') as df:
        parse_fextern_defs_file(df)   

  # Turn off "automatically make offset" heuristic, and set some
  # other sane defaults.
  idc.set_inf_attr(idc.INF_AF, 0xdfff)
  idc.set_inf_attr(idc.INF_AF2, 0xfffd)

  # Ensure that IDA is done processing
  DEBUG("Using Batch mode.")
  idaapi.auto_wait()

  # Shift the program image in memory.
  if args.rebase:
    rebase_flags = idc.MSF_FIXONCE
    if idc.MOVE_SEGM_OK != idc.rebase_program(args.rebase, rebase_flags):
      DEBUG("ERROR: Failed to rebase program with delta {:08x}".format(args.rebase))

    idaapi.auto_wait()

  ANVILL_PROGRAM = anvill.get_program()

  DEBUG("Starting analysis")
  try:
    # Pre-define a bunch of symbol names and their addresses. Useful when reading
    # a core dump.
    if args.syms:
      for line in args.syms:
        name, ea_str = line.strip().split(" ")
        ea = int(ea_str, base=16)
        if not is_internal_code(ea):
          try_mark_as_code(ea)
        if is_code(ea):
          try_mark_as_function(ea)
          set_symbol_name(ea, name)
      idaapi.auto_wait()
    
    M = recover_module(args.entrypoint, args.recover_global_vars)

    DEBUG("Saving to: {0}".format(args.output.name))
    args.output.write(M.SerializeToString())
    args.output.close()

  except:
    DEBUG(traceback.format_exc())
  
  DEBUG("Done analysis!")
  idc.process_config_line("ABANDON_DATABASE=YES")
  idc.qexit(0)
