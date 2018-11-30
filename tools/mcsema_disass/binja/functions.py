# Copyright (c) 2018 Trail of Bits, Inc.
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

  log.pop()
  if RECOVER_OPTS["manual_recursive_descent"]:
    # Impliment recursive descent
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

  log.push()


def recover_function(bv, pb_mod, addr, is_entry=False):
  func = bv.get_function_at(addr)

  if func.symbol.name in DO_NOT_RECOVER:
    return

  if func is None:
    log.error('No function defined at 0x%x, skipping', addr)
    return

  if func.symbol.type == SymbolType.ImportedFunctionSymbol:
    # Externals are recovered later, skip this
    log.warn("Skipping external function '%s' in main CFG recovery", func.symbol.name)
    return

  log.debug("Recovering function {} at {:x}".format(func.symbol.name, addr))

  # Initialize the protobuf for this function
  pb_func = pb_mod.funcs.add()
  pb_func.ea = addr
  pb_func.is_entrypoint = is_entry  # TODO : or exported function
  pb_func.name = func.symbol.name

  # Recover all basic blocks
  il_groups = util.collect_il_groups(func.lifted_il)
  var_refs = defaultdict(list)
  for bb in func:
    pb_block = add_block(pb_func, bb)
    log.push()

    # Recover every instruction in the basic block (bb)
    for inst in bb.disassembly_text:
      # Skip over anything that isn't an instruction
      if inst.tokens[0].type != InstructionTextTokenType.InstructionToken:
        continue

      il = func.get_lifted_il_at(inst.address)
      all_il = il_groups[inst.address]
      pb_inst = pb_block.instructions.add()
      recover_inst(bv, func, pb_block, pb_inst, il, all_il, is_last=(inst.address == bb.end))

      # Find any references to stack vars in this instruction
      if RECOVER_OPTS['stack_vars']:
        vars.find_stack_var_refs(bv, inst, il, var_refs)

    log.pop()

  # Recover stack variables
  if RECOVER_OPTS['stack_vars']:
    vars.recover_stack_vars(pb_func, func, var_refs)


def recover_inst(bv, func, pb_block, pb_inst, il, all_il, is_last):
  """
  Args:
    bv (binja.BinaryView)
    pb_inst (CFG_pb2.Instruction)
    il (binaryninja.lowlevelil.LowLevelILInstruction)
    all_il (list): Collection of all il instructions at this address
             (e.g. all instructions expanded from a cmov)
    is_last (bool)
  """
  pb_inst.ea = il.address
  pb_inst.bytes = bv.read(il.address, bv.get_instruction_length(il.address))

  # Search all il instructions at the current address for xrefs
  refs = set()
  for il_exp in all_il:
    refs.update(xrefs.get_xrefs(bv, func, il_exp))

  # Add all discovered xrefs to pb_inst
  debug_refs = []
  for ref in refs:
    debug_refs.append(xrefs.add_xref(bv, pb_inst, ref.addr, ref.mask, ref.cfg_type))

  if util.is_local_noreturn(bv, il):
    pb_inst.local_noreturn = True

  # Add the target of a tail call as a successor
  if util.is_jump_tail_call(bv, il):
    tgt = il.dest.constant
    pb_block.successor_eas.append(tgt)

  # table = jmptable.get_jmptable(bv, il)
  # if table is not None:
  #   debug_refs.append(add_xref(bv, pb_inst, table.base_addr, 0, CFG_pb2.CodeReference.MemoryDisplacementOperand))
  #   JMP_TABLES.append(table)

  # With new recovery mechanism:?
  table = jmptable.get_jmptable(bv, il)
  if table is not None:
    debug_refs.append(xrefs.add_xref(bv, pb_inst, table.base_addr, 0, CFG_pb2.CodeReference.MemoryDisplacementOperand))
    # if is_offset:
    #   debug_refs.append(add_xref(bv, pb_inst, table.base_addr, 0, CFG_pb2.CodeReference.OffsetTable))
    # else:
    #   debug_refs.append(add_xref(bv, pb_inst, table.base_addr, 0, CFG_pb2.CodeReference.DataTarget))
    jmptable.JMP_TABLES.append(table)

    # Add any missing successors
    for tgt in table.targets:
      if tgt not in pb_block.successor_eas:
        pb_block.successor_eas.append(tgt)

  log.debug("I: {:x} {}".format(il.address, " ".join(debug_refs)))

  if is_last:
    if len(pb_block.successor_eas):
      log.debug("  Successors: {}".format(", ".join("{:x}".format(ea) for ea in pb_block.successor_eas)))
    else:
      log.debug("  No successors")


def add_block(pb_func, block):
  """
  Args:
    pb_func (CFG_pb2.Function)
    block (binaryninja.basicblock.BasicBlock)

  Returns:
    CFG_pb2.Block
  """
  log.debug("BB: {:x}".format(block.start))
  pb_block = pb_func.blocks.add()
  pb_block.ea = block.start
  pb_block.successor_eas.extend(edge.target.start for edge in block.outgoing_edges)
  return pb_block


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
    pb_extfn.has_return = func.function_type.return_value.type_class != TypeClass.VoidTypeClass
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
