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
from collect_variable import *
from exception import *

#hack for IDAPython to see google protobuf lib
if os.path.isdir('/usr/lib/python2.7/dist-packages'):
  sys.path.append('/usr/lib/python2.7/dist-packages')

if os.path.isdir('/usr/local/lib/python2.7/dist-packages'):
  sys.path.append('/usr/local/lib/python2.7/dist-packages')

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

_NOT_ELF_BEGIN_EAS = (0xffffffffL, 0xffffffffffffffffL)

# Returns `True` if this is an ELF binary (as opposed to an ELF object file).
def is_linked_ELF_program():
  global _NOT_ELF_BEGIN_EAS
  return IS_ELF and idc.BeginEA() not in _NOT_ELF_BEGIN_EAS

def is_ELF_got_pointer(ea):
  """Returns `True` if this is a pointer to a pointer stored in the
  `.got` section of an ELF binary. For example, `__gmon_start___ptr` is
  a pointer in the `.got` that will be fixed up to contain the address of
  the external function `__gmon_start__`. We don't want to treat
  `__gmon_start___ptr` as external because it is really a sort of local
  variable that will will resolve with a data cross-reference."""
  seg_name = idc.SegName(ea).lower()
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
    dname = idc.Demangle(name, idc.GetLongPrm(INF_SHORT_DN))
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

      ea = idc.LocByName(fname)

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
        flags = idc.GetFlags(ea)
        if not idc.isCode(flags) and not idaapi.is_weak_name(ea):
          seg_name = idc.SegName(ea).lower()
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

        if idc.LocByName(imp_name):
          _FIXED_EXTERNAL_NAMES[imp_name] = fname
          WEAK_SYMS.add(fname)
          WEAK_SYMS.add(imp_name)

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

def is_ELF_thunk_by_structure(ea):
  """Try to manually identify an ELF thunk by its structure."""
  global _INVALID_THUNK_ADDR

  if ".plt" not in idc.SegName(ea).lower():
    return _INVALID_THUNK_ADDR

  # Scan through looking for a branch, either direct or indirect.
  inst = None
  for i in range(4):  # 1 is good enough for x86, 4 for aarch64.
    inst, _ = decode_instruction(ea)
    if not inst:
      return _INVALID_THUNK_ADDR
    # elif is_direct_jump(inst):
    #   ea = get_direct_branch_target(inst)
    #   inst = None
    elif is_indirect_jump(inst) or is_direct_jump(inst):
      ea = inst.ea
      break
    else:
      ea = inst.ea + inst.size
      inst = None

  if not inst:
    return _INVALID_THUNK_ADDR

  target_ea = get_reference_target(inst.ea)
  if ".got.plt" == idc.SegName(target_ea).lower():
    target_ea = get_reference_target(target_ea)

  # For AArch64, the thunk structure is something like:
  #     .plt:000400470 .atoi
  #     .plt:000400470    ADRP            X16, #off_411000@PAGE
  #     .plt:000400474    LDR             X17, [X16,#off_411000@PAGEOFF]
  #     .plt:000400478    ADD             X16, X16, #off_411000@PAGEOFF
  #     .plt:00040047C    BR              X17 ; atoi
  #
  # With:
  #
  #     extern:000411070 ; int atoi(const char *nptr)
  #     extern:000411070                 IMPORT atoi
  

  # For x86, the thunk structure is something like:
  #   
  #     .plt:00041F10 _qsort      proc near         
  #     .plt:00041F10         jmp   cs:off_31F388
  #     .plt:00041F10 _qsort      endp
  #     
  # With:
  # 
  #     .got.plt:0031F388 off_31F388    dq offset qsort
  #
  # With
  #     extern:0031F388 ; void qsort(void *base, ...)
  #     extern:0031F388                 extrn qsort:near 

  if is_invalid_ea(target_ea):
    return _INVALID_THUNK_ADDR
  
  return True, target_ea

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
    ret = (is_thunk, target_ea, name)
    _ELF_THUNKS[ea] = ret
    return ret

def is_start_of_function(ea):
  """Returns `True` if `ea` is the start of a function."""
  if not is_code(ea):
    return False

  name = idc.GetTrueName(ea) or idc.GetFunctionName(ea)
  return ea == idc.LocByName(name)

_REFERENCE_OPERAND_TYPE = {
  Reference.IMMEDIATE: CFG_pb2.CodeReference.ImmediateOperand,
  Reference.DISPLACEMENT: CFG_pb2.CodeReference.MemoryDisplacementOperand,
  Reference.MEMORY: CFG_pb2.CodeReference.MemoryOperand,
  Reference.CODE: CFG_pb2.CodeReference.ControlFlowOperand,
}

def reference_target_type(ref):
  """Sometimes code references into the GOT would be treated as data
  references. We fall back onto our external maps as an oracle for
  what the type should really be. This has happened with `pcre_free`
  references from Apache."""
  if ref.ea in EXTERNAL_VARS_TO_RECOVER:
    return CFG_pb2.CodeReference.DataTarget

  # TODO(pag): 
  #elif ref.ea in EXTERNAL_FUNCS_TO_RECOVER:
  #  return CFG_pb2.CodeReference.CodeTarget

  elif is_code(ref.ea):
    return CFG_pb2.CodeReference.CodeTarget
  else:
    return CFG_pb2.CodeReference.DataTarget

def reference_operand_type(ref):
  global _REFERENCE_OPERAND_TYPE
  return _REFERENCE_OPERAND_TYPE[ref.type]

def reference_location(ref):
  if ref.ea in EXTERNAL_VARS_TO_RECOVER:
    return CFG_pb2.CodeReference.External
  elif ref.ea in EXTERNAL_FUNCS_TO_RECOVER:
    return CFG_pb2.CodeReference.External
  elif is_external_segment_by_flags(ref.ea):
    DEBUG("WARNING: Reference to {:x} is in an external segment, but is not an external var or function".format(ref.ea))
    return CFG_pb2.CodeReference.External
  else:
    return CFG_pb2.CodeReference.Internal

def referenced_name(ref):
  if ref.ea in EXTERNAL_VARS_TO_RECOVER:
    return EXTERNAL_VARS_TO_RECOVER[ref.ea]
  elif ref.ea in EXTERNAL_FUNCS_TO_RECOVER:
    return EXTERNAL_FUNCS_TO_RECOVER[ref.ea]
  else:
    return get_true_external_name(ref.symbol)

_TARGET_NAME = {
  CFG_pb2.CodeReference.CodeTarget: "code",
  CFG_pb2.CodeReference.DataTarget: "data",
}

_OPERAND_NAME = {
  CFG_pb2.CodeReference.ImmediateOperand: "imm",
  CFG_pb2.CodeReference.MemoryDisplacementOperand: "disp",
  CFG_pb2.CodeReference.MemoryOperand: "mem",
  CFG_pb2.CodeReference.ControlFlowOperand: "flow",
}

_LOCATION_NAME = {
  CFG_pb2.CodeReference.External: "external",
  CFG_pb2.CodeReference.Internal: "internal",
}

def format_instruction_reference(ref):
  """Returns a string representation of a cross reference contained
  in an instruction."""
  mask_begin = ""
  mask_end = ""
  if ref.mask:
    mask_begin = "("
    mask_end = " & {:x})".format(ref.mask)

  return "({} {} {} {}{:x}{} {})".format(
      _TARGET_NAME[ref.target_type],
      _OPERAND_NAME[ref.operand_type],
      _LOCATION_NAME[ref.location],
      mask_begin,
      ref.ea,
      mask_end,
      ref.HasField('name') and ref.name or "")

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

    target_type = reference_target_type(ref)
    location = reference_location(ref)

    addrs = set()
    R = I.xrefs.add()
    R.ea = ref.ea
    if ref.mask:
      R.mask = ref.mask

    R.operand_type = reference_operand_type(ref)
    R.target_type = target_type
    R.location = location
    name = referenced_name(ref)
    if name:
      R.name = name.format('utf-8')
    
    debug_info.append(format_instruction_reference(R))

  DEBUG_POP()
  DEBUG(" ".join(debug_info))

def recover_instruction_offset_table(I, table):
  """Recovers an offset table as a kind of reference."""
  DEBUG("Offset-based jump table")
  R = I.xrefs.add()
  R.ea = table.offset
  R.operand_type = CFG_pb2.CodeReference.OffsetTable
  R.target_type = CFG_pb2.CodeReference.DataTarget
  R.location = CFG_pb2.CodeReference.Internal
  name = get_symbol_name(table.offset * table.offset_mult, allow_dummy=False)
  if name:
    R.name = name.format('utf-8')

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
  R.name = EXTERNAL_FUNCS_TO_RECOVER[ref.ea].format('utf-8')
  R.operand_type = CFG_pb2.CodeReference.ControlFlowOperand
  R.target_type = CFG_pb2.CodeReference.CodeTarget
  R.location = CFG_pb2.CodeReference.External

  if is_indirect_jump(inst):
    DEBUG("Tail-calls external {}".format(R.name))
  else:
    DEBUG("Calls external {}".format(R.name))

def recover_instruction(M, B, ea):
  """Recover an instruction, adding it to its parent block in the CFG."""
  inst, inst_bytes = decode_instruction(ea)

  I = B.instructions.add()
  I.ea = ea  # May not be `inst.ea` because of prefix coalescing.
  I.bytes = inst_bytes

  refs = get_instruction_references(inst, PIE_MODE)
  recover_instruction_references(I, inst, ea, refs)

  if is_noreturn_inst(inst):
    I.local_noreturn = True


  DEBUG_PUSH()
  table = get_jump_table(inst, PIE_MODE)
  if table and table.offset and \
     not is_invalid_ea(table.offset * table.offset_mult):
    recover_instruction_offset_table(I, table)

  if not table:
    try_recovery_external_flow(I, inst, refs)

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
  I = None
  for inst_ea in inst_eas:
    I = recover_instruction(M, B, inst_ea)
    # Get the landing pad associated with the instructions;
    # 0 if no landing pad associated
    if RECOVER_EHTABLE is True and I:
      I.lp_ea = get_exception_landingpad(F, inst_ea)

  DEBUG_PUSH()
  if I and I.local_noreturn:
    DEBUG("Does not return")
  
  elif len(succ_eas) > 0:
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
    if is_start_of_function(entry_target):
      DEBUG("  Jump table {:x} entry at {:x} references function at {:x}".format(
          table.table_ea, entry_addr, entry_target))
      new_func_eas.add(entry_target)
    else:
      DEBUG("  Jump table {:x} entry at {:x} references block at {:x}".format(
          table.table_ea, entry_addr, entry_target))
      new_eas.add(entry_target)

_RECOVERED_FUNCS = set()

def recover_function(M, func_ea, new_func_eas, entrypoints):
  """Decode a function and store it, all of its basic blocks, and all of
  their instructions into the CFG file."""
  global _RECOVERED_FUNCS
  if func_ea in _RECOVERED_FUNCS:
    return

  _RECOVERED_FUNCS.add(func_ea)

  if not is_start_of_function(func_ea):
    DEBUG("{:x} is not a function! Not recovering.".format(func_ea))
    return

  F = M.funcs.add()
  F.ea = func_ea
  F.is_entrypoint = (func_ea in entrypoints)
  name = get_symbol_name(func_ea)
  if name:
    DEBUG("Recovering {} at {:x}".format(name, func_ea))
    F.name = name.format('utf-8')
  else:
    DEBUG("Recovering {:x}".format(func_ea))

  DEBUG_PUSH()
  # Update the protobuf with the recovered eh_frame entries
  if RECOVER_EHTABLE is True:
    recover_exception_entries(F, func_ea)
  blockset, term_insts = analyse_subroutine(func_ea, PIE_MODE)

  for term_inst in term_insts:
    if get_jump_table(term_inst, PIE_MODE):
      DEBUG("Terminator inst {:x} in func {:x} is a jump table".format(
          term_inst.ea, func_ea))
      analyze_jump_table_targets(term_inst, blockset, new_func_eas)
  
  processed_blocks = set()
  while len(blockset) > 0:
    block_ea = blockset.pop()
    if block_ea in processed_blocks:
      DEBUG("ERROR: Attempting to add same block twice: {0:x}".format(block_ea))
      continue

    processed_blocks.add(block_ea)
    recover_basic_block(M, F, block_ea)

  if TO_RECOVER["stack_var"]:
    recover_variables(F, func_ea, processed_blocks)

  DEBUG_POP()

def find_default_function_heads():
  """Loop through every function, to discover the heads of all blocks that
  IDA recognizes. This will populate some global sets in `flow.py` that
  will help distinguish block heads."""
  func_heads = set()
  for seg_ea in idautils.Segments():
    seg_type = idc.GetSegmentAttr(seg_ea, idc.SEGATTR_TYPE)
    if seg_type != idc.SEG_CODE:
      continue

    for func_ea in idautils.Functions(seg_ea, idc.SegEnd(seg_ea)):
      if is_code_by_flags(func_ea):
        func_heads.add(func_ea)

  return func_heads

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
  seg_name = idc.SegName(seg_ea)
  has_func_pointers = segment_contains_external_function_pointers(seg_ea)

  ea, next_ea = seg_ea, seg_ea
  while next_ea < seg_end_ea:
    ea = next_ea

    # The item size is 1 in some of the cases where it refer to the external data. The
    # references in such cases get ignored. Assign the address size if there is reference
    # to the external data.
    item_size = idc.ItemSize(ea)
    xref_width = min(max(item_size, 4), max_xref_width)
    next_ea = min(ea + xref_width,
                  # idc.GetNextFixupEA(ea),
                  idc.NextHead(ea, seg_end_ea))

    # This data is a copy of shared data.
    if is_runtime_external_data_reference(ea):
      continue

    # We don't want to fill the jump table bytes with their actual
    # code cross-references. This is because we can't get the address
    # of a basic block. Our goal is thus to preserve the original values,
    # and implement the switch in terms of those original values on the
    # LLVM side of things.
    if is_jump_table_entry(ea):
      continue

    # Skip over instructions.
    if is_code_seg:
      flags = idc.GetFlags(ea)
      if idc.isCode(flags):
        next_ea = idc.NextHead(ea, seg_end_ea)
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
    elif not idc.GetFlags(target_ea):
      DEBUG("WARNING: No information about target {:x} from {:x}".format(
          target_ea, ea))
      continue

    else:
      X = S.xrefs.add()
      X.ea = ea
      X.width = xref_width
      X.target_ea = target_ea
      X.target_name = get_symbol_name(target_ea)
      X.target_is_code = is_code(target_ea) or \
                         target_ea in EXTERNAL_FUNCS_TO_RECOVER

      if is_external_segment(X.target_ea):
        X.target_name = get_true_external_name(X.target_name)

      # A cross-reference to some TLS data. Because each thread has its own
      # instance of the data, this reference ends up actually being an offset
      # from a thread base pointer. In x86, this tends to be the base of one of
      # the segment registers, e.g. `fs` or `gs`. On the McSema side, we fill in
      # this xref lazily by computing the offset.
      if is_tls(target_ea):
        X.target_fixup_kind = CFG_pb2.DataReference.OffsetFromThreadBase
        DEBUG("{}-byte TLS offset at {:x} to {:x} ({})".format(
            X.width, ea, target_ea, X.target_name))

      # A cross-reference to a 'single' thing, where the fixup that we create
      # will be an absolute address to the targeted variable/function.
      else:
        X.target_fixup_kind = CFG_pb2.DataReference.Absolute
        DEBUG("{}-byte reference at {:x} to {:x} ({})".format(
            X.width, ea, target_ea, X.target_name))

        try_identify_as_external_function(target_ea, X.target_name)


def recover_region(M, region_name, region_ea, region_end_ea, exported_vars):
  """Recover the data and cross-references from a segment. The data of a
  segment is stored verbatim within the protobuf, and accompanied by a
  series of variable and cross-reference entries."""

  seg_name = idc.SegName(region_ea)

  DEBUG("Recovering region {} [{:x}, {:x}) in segment {}".format(
      region_name, region_ea, region_end_ea, seg_name))

  seg = idaapi.getseg(region_ea)

  # An item spans two regions. This may mean that there's a reference into
  # the middle of an item. This happens with strings.
  item_size = idc.ItemSize(region_end_ea - 1)
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
    seg_name = idc.SegName(seg_ea)
    seg_names[seg_ea] = seg_name

    if (not is_external_segment_by_flags(seg_ea) or \
        segment_contains_external_function_pointers(seg_ea)) and \
        not (is_constructor_segment(seg_ea) or is_destructor_segment(seg_ea)):
      seg_parts[seg_ea].add(seg_ea)
      seg_parts[seg_ea].add(idc.SegEnd(seg_ea))

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
      end_ea =  idc.SegEnd(seg_ea)
      if is_destructor_segment(end_ea):
        seg_parts[seg_ea].add(idc.SegEnd(end_ea))
        DEBUG("WARNING: Global constructor and destructor sections are adjacent!")
      else:
        seg_parts[seg_ea].add(end_ea)
        fini_ea = get_destructor_segment()
        if fini_ea:
          seg_parts[fini_ea].add(fini_ea)
          seg_parts[fini_ea].add(idc.SegEnd(fini_ea))

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

    seg_ea = idc.SegStart(begin_ea)
    seg_name = idc.SegName(seg_ea)

    DEBUG("Splitting segment {} from {:x} to {:x} for global variable {}".format(
        seg_name, begin_ea, end_ea, var_name))

    seg_parts[seg_ea].add(begin_ea)
    seg_names[begin_ea] = var_name

    if end_ea <= idc.SegEnd(seg_ea):
      seg_parts[seg_ea].add(end_ea)

  # Treat exported variables as segment begin/end points.
  for var_ea in exported_vars:
    seg_ea = idc.SegStart(var_ea)
    seg_name = idc.SegName(seg_ea)
    var_name = get_symbol_name(var_ea)
    seg_parts[seg_ea].add(var_ea)
    seg_names[var_ea] = var_name
    DEBUG("Splitting segment {} at {:x} for exported variable {}".format(
        seg_name, var_ea, var_name))

  for seg_ea, eas in seg_parts.items():
    parts = list(sorted(list(eas)))
    seg_name = idc.SegName(seg_ea)
    for begin_ea, end_ea in zip(parts[:-1], parts[1:]):
      region_name = seg_name
      if begin_ea in seg_names:
        region_name = seg_names[begin_ea]
      recover_region(M, region_name, begin_ea, end_ea, exported_vars)

def recover_external_functions(M):
  """Recover the named external functions (e.g. `printf`) that are referenced
  within this binary."""
  global EXTERNAL_FUNCS_TO_RECOVER, WEAK_SYMS, EMAP

  for ea, name in EXTERNAL_FUNCS_TO_RECOVER.items():
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
    #      actually returns something, rather than simply does not
    #      return (e.g. `abort`).
    E.has_return = ret == 'N'

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
      EV.size = idc.ItemSize(ea)
    if EV.is_thread_local:
      DEBUG("Recovering extern TLS variable {} at {:x}".format(name, ea))
    else:
      DEBUG("Recovering extern variable {} at {:x}".format(name, ea))

def recover_external_symbols(M):
  recover_external_functions(M)
  recover_external_variables(M)

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

  elif not name:
    return False

  # We've got a thunk with an implementation already done.
  if name in INTERNALLY_DEFINED_EXTERNALS:
    impl_ea = INTERNALLY_DEFINED_EXTERNALS[name]
    INTERNAL_THUNK_EAS[ea] = impl_ea
    return False

  if name not in EMAP:
    return False

  DEBUG("Function at {:x} is the external function {}".format(ea, name))
  EXTERNAL_FUNCS_TO_RECOVER[ea] = name
  return True

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

          target_flags = idc.GetFlags(target_ea)
          
          # The missing reference looks like code, so add it to the EMAP with
          # 16 arguments (probably enough, eh?), and assume it uses the cdecl
          # calling convention.
          #
          # NOTE(pag): We use `idc.isCode` and not `is_code` because the latter
          #            operates at the segment granularity, and `target_ea` will
          #            likely point into the `extern` section. Individual
          #            entries in the extern section can have 
          if idc.isCode(target_flags):
            DEBUG("WARNING: Adding external {} at {:x} as an external code reference".format(
                target_name, ea))
            EMAP[target_name] = (16, CFG_pb2.ExternalFunction.CallerCleanup, "N", None)

            imp_name = "__imp_{}".format(target_name)
            if idc.LocByName(imp_name):
              _FIXED_EXTERNAL_NAMES[imp_name] = target_name
              WEAK_SYMS.add(target_name)
              WEAK_SYMS.add(imp_name)

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
        comment = idc.GetCommentEx(ea, 0) or ""
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

  exclude = set(["_start", "__libc_csu_fini", "__libc_csu_init", "main",
                 "__data_start", "__dso_handle", "_IO_stdin_used",
                 "_dl_relocate_static_pie"])

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
        func_eas.add(ea)
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

  start_ea = idc.LocByName("_start")
  if is_invalid_ea(start_ea):
    start_ea = idc.LocByName("start")
    if is_invalid_ea(start_ea):
      return idc.BADADDR

  for begin_ea, end_ea in idautils.Chunks(start_ea):
    for inst_ea in Heads(begin_ea, end_ea):
      comment = idc.GetCommentEx(inst_ea, 0)
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

          if main and main.startEA == main_ea:
            set_symbol_name(main_ea, "main")
            DEBUG("Found main at {:x}".format(main_ea))
            return main_ea

  return idc.BADADDR

def recover_module(entrypoint, gvar_infile = None):
  global EMAP
  global EXTERNAL_FUNCS_TO_RECOVER
  global INTERNAL_THUNK_EAS

  M = CFG_pb2.Module()
  M.name = idc.GetInputFile().format('utf-8')
  DEBUG("Recovering module {}".format(M.name))

  entry_ea = idc.LocByName(args.entrypoint)

  # If the entrypoint is `main`, then we'll try to find `main` via another
  # means.
  if is_invalid_ea(entry_ea):
    if "main" == args.entrypoint and IS_ELF:
      entry_ea = find_main_in_ELF_file()

  if RECOVER_EHTABLE:
    recover_exception_table()

  process_segments(PIE_MODE)

  func_eas = find_default_function_heads()

  recovered_fns = 0

  identify_thunks(func_eas)
  identify_external_symbols()
  
  exported_funcs, exported_vars = identify_program_entrypoints(func_eas)

  if is_invalid_ea(entry_ea):
    DEBUG("ERROR: Could not find entrypoint {}".format(args.entrypoint))
  else:
    func_eas.add(entry_ea)
    exported_funcs.add(entry_ea)

  # Process and recover functions. 
  while len(func_eas) > 0:
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

    recover_function(M, func_ea, func_eas, exported_funcs)
    recovered_fns += 1

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
      required=True)
  
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

  args = parser.parse_args(args=idc.ARGV[1:])

  if args.log_file != os.devnull:
    INIT_DEBUG_FILE(args.log_file)
    DEBUG("Debugging is enabled.")

  addr_size = {"x86": 32, "amd64": 64, "aarch64": 64}.get(args.arch, 0)
  if addr_size != get_address_size_in_bits():
    DEBUG("Arch {} address size does not match IDA's available bitness {}! Did you mean to use idal64?".format(
        args.arch, get_address_size_in_bits()))
    idc.ChangeConfig("ABANDON_DATABASE=YES")
    idc.Exit(-1)

  if args.pie_mode:
    DEBUG("Using PIE mode.")
    PIE_MODE = True
    
  if args.recover_stack_vars:
    TO_RECOVER["stack_var"] = True

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

  # Turn off "automatically make offset" heuristic, and set some
  # other sane defaults.
  idc.SetShortPrm(idc.INF_START_AF, 0xdfff)
  idc.SetShortPrm(idc.INF_AF2, 0xfffd)

  # Ensure that IDA is done processing
  DEBUG("Using Batch mode.")
  idaapi.autoWait()

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
      idaapi.autoWait()
    
    M = recover_module(args.entrypoint, args.recover_global_vars)

    DEBUG("Saving to: {0}".format(args.output.name))
    args.output.write(M.SerializeToString())
    args.output.close()

  except:
    DEBUG(traceback.format_exc())
  
  DEBUG("Done analysis!")
  idc.ChangeConfig("ABANDON_DATABASE=YES")
  idc.Exit(0)
