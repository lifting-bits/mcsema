# Copyright (c) 2019 Trail of Bits, Inc.
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

from collections import defaultdict
from Queue import Queue

import binaryninja as bn
from binaryninja.enums import (
  SymbolType, TypeClass,
  InstructionTextTokenType
)

RECOVERED = set()
TO_RECOVER = Queue()

DO_NOT_RECOVER = [
  # "_init",
  # "_start",
  # "_dl_relocate_static_pie",
  # "deregister_tm_clones",
  # "register_tm_clones",
  # "__do_global_dtors_aux",
  # "frame_dummy",
  # "__libc_csu_init",
  # "__libc_csu_fini",
  # "_fini"
]

from cfg import EXT_MAP, RECOVER_OPTS
import jmptable
import CFG_pb2
import xrefs
import util
import log

BINJA_CCONV_TYPES = {
  'cdecl': CFG_pb2.ExternalFunction.CallerCleanup,
  'stdcall': CFG_pb2.ExternalFunction.CalleeCleanup,
  'fastcall': CFG_pb2.ExternalFunction.FastCall
}


# Entrypoint for actual function recovery
def recover_functions(bv, pb_mod, entrypoint):
  # Find the chosen entrypoint in the binary
  if entrypoint not in bv.symbols:
    log.fatal('Entrypoint not found: %s', entrypoint)
  entry_addr = bv.symbols[entrypoint].address

  if RECOVER_OPTS["manual_recursive_descent"]:
    # Implement recursive descent
    TO_RECOVER.put(entry_addr)

    while not TO_RECOVER.empty():
      addr = TO_RECOVER.get()
      if addr not in RECOVERED:
        RECOVERED.add(addr)
        recover_function(bv, pb_mod, addr, is_entry=(addr == entry_addr))

  else:
    # Recover all the functions
    for func in bv.functions:
      addr = func.start
      recover_function(bv, pb_mod, addr, is_entry=(addr == entry_addr))


def recover_function(bv, pb_mod, addr, is_entry=False):
  """
  """
  func = bv.get_function_at(addr)

  if func.analysis_skipped:
    func.analysis_skip_override = bn.FunctionAnalysisSkipOverride.NeverSkipFunctionAnalysis
    bv.update_analysis_and_wait()

  if func.symbol.full_name in DO_NOT_RECOVER:
    log.debug("Skipping function {} at {:x} per command-line arguments".format(func.symbol.full_name, addr))
    return
  elif func is None:
    log.error('No function defined at 0x%x, skipping', addr)
    return
  elif func.symbol.type == SymbolType.ImportedFunctionSymbol:
    # Externals are recovered later, skip this
    log.warn("Skipping external function '%s' in main CFG recovery", func.symbol.full_name)
    return

  log.debug("Recovering function {} at {:x}".format(func.symbol.full_name, addr))

  # Recover all basic blocks
  log.pop()
  pb_func, var_refs = recover_blocks(func, pb_mod, is_entry)
  log.push()

  # Recover stack variables
  if RECOVER_OPTS['stack_vars']:
    vars.recover_stack_vars(pb_func, func, var_refs)


def recover_blocks(func, pb_mod, is_entry):
  """
  Args:
  bv (binja.BinaryView)
  func (binja.Function)
  pb_func
  """
  # Initialize the protobuf for this function
  pb_func = pb_mod.funcs.add()
  pb_func.ea = func.start
  pb_func.is_entrypoint = is_entry  # TODO : or exported function
  pb_func.name = func.symbol.name

  var_refs = defaultdict(list)
  for bb in func:
    recover_block(bb, pb_func, var_refs)

  return pb_func, var_refs


def recover_block(bb, pb_func, var_refs):
  log.debug("BB: {:x}".format(bb.start))
  pb_block = pb_func.blocks.add()
  pb_block.ea = bb.start
  pb_block.successor_eas.extend(edge.target.start for edge in bb.outgoing_edges)

  # Recover every instruction in the basic block (bb)
  recovered_addresses = []  # Track what's been recovered as to skip duplicates
  for inst in bb.disassembly_text:
    if inst.address in recovered_addresses:
      continue
    else:
      recovered_addresses.append(inst.address)

    lifted_il = bb.function.get_lifted_il_at(inst.address)
    all_lil = util.get_all_lifted_il(bb.view, lifted_il, [])

    pb_inst = pb_block.instructions.add()
    if util.is_end_of_block(inst.address, bb):
      recover_inst_last(bb.view, bb.function, pb_block, pb_inst, all_lil, inst.address)
    else:
      recover_inst(bb.view, bb.function, pb_block, pb_inst, all_lil, inst.address)

    # Find any references to stack vars in this instruction
    if RECOVER_OPTS['stack_vars']:
      vars.find_stack_var_refs(bb.view, inst, lifted_il, var_refs)


def recover_inst_last(bv, func, pb_block, pb_inst, lifted_il, address):
  recover_inst(bv, func, pb_block, pb_inst, lifted_il, address)

  # Is noreturn?
  bb = util.get_basic_block(bv, lifted_il[0])
  if not bb.can_exit:
    pb_inst.local_noreturn = True

  # Is tailcall? : Add the target of a tail call as a successor
  if util.is_jump_tail_call(bv, lifted_il):
    target = util.get_jump_tail_call_target(bv, lifted_il)
    if target is not None:
      pb_block.successor_eas.append(target.start)

  if len(pb_block.successor_eas):
    log.debug("  Successors: {}".format(", ".join("{:x}".format(ea) for ea in pb_block.successor_eas)))
  else:
    log.debug("  No successors")


def recover_inst(bv, func, pb_block, pb_inst, lifted_il, address):
  """
  Args:
    bv (binja.BinaryView)
    pb_inst (CFG_pb2.Instruction)
    il (binaryninja.lowlevelil.LowLevelILInstruction)
    all_il (list): Collection of all il instructions at this address
             (e.g. all instructions expanded from a cmov)
  """
  pb_inst.ea = address
  pb_inst.bytes = bv.read(address, bv.get_instruction_length(address))

  # Search all il instructions at the current address for xrefs
  refs = xrefs.get_xrefs(bv, func, lifted_il, address)

  # Add all discovered xrefs to pb_inst
  debug_refs = []
  for ref in refs:
    debug_refs.append(xrefs.add_xref(bv, pb_inst, ref.addr, ref.mask, ref.cfg_type))

  # References jump table?
  recover_table(bv, pb_inst, pb_block, debug_refs, lifted_il[0])

  log.debug("I: {:x} {}".format(address, " ".join(debug_refs)))


def recover_table(bv, pb_inst, pb_block, debug_refs, il):
  table = jmptable.get_jmptable(bv, il)
  if table is None:
    return

  debug_refs.append(xrefs.add_xref(bv, pb_inst, table.base_addr, 0, CFG_pb2.CodeReference.OffsetTable))
  jmptable.JMP_TABLES.append(table)

  # Add any missing successors
  for tgt in table.targets:
    if tgt not in pb_block.successor_eas:
      pb_block.successor_eas.append(tgt)


def recover_ext_func(bv, pb_mod, sym):
  """ Recover external function information
  Uses the map of predefined externals if possible

  Args:
    bv (binja.BinaryView)
    pb_mod (CFG_pb2.Module)
    sym (binaryninja.types.Symbol)
  """
  log.debug("Recovering external function {} at {:x}".format(sym.name, sym.address))
  if sym.name in EXT_MAP:
    log.debug('Found defined external function: {} @ {:x}'.format(sym.name, sym.address))

    args, cconv, ret, sign = EXT_MAP[sym.name]
    func = bv.get_function_at(sym.address)
    if func is None:
      return

    pb_extfn = pb_mod.external_funcs.add()
    pb_extfn.name = sym.name
    pb_extfn.ea = sym.address
    pb_extfn.argument_count = args
    pb_extfn.cc = cconv

    pb_extfn.has_return = False
    # pb_extfn.has_return = func.function_type.return_value.type_class != TypeClass.VoidTypeClass
    # log.debug('Has return?' + str(pb_extfn.has_return))

    pb_extfn.no_return = ret == 'Y'
    pb_extfn.is_weak = False  # TODO: figure out how to decide this

  else:
    log.warn("External function is not part of defs file")

    func = bv.get_function_at(sym.address)
    ftype = func.function_type

    pb_extfn = pb_mod.external_funcs.add()
    pb_extfn.name = sym.name
    pb_extfn.ea = sym.address
    pb_extfn.argument_count = len(ftype.parameters)
    pb_extfn.has_return = func.function_type.return_value.type_class != TypeClass.VoidTypeClass
    pb_extfn.no_return = not ftype.can_return
    pb_extfn.is_weak = False  # TODO: figure out how to decide this

    # Assume cdecl if the type is unknown
    cconv = ftype.calling_convention
    if cconv is not None and cconv.name in BINJA_CCONV_TYPES:
      pb_extfn.cc = BINJA_CCONV_TYPES[cconv]
    else:
      pb_extfn.cc = CFG_pb2.ExternalFunction.CallerCleanup
