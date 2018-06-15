#!/usr/bin/env python

import sys
import collections
import argparse
import pprint
import binaryninja as binja
import mcsema_disass.ida.CFG_pb2

# Debug logging utilities
_DEBUG = False
_DEBUG_FILE = None
_DEBUG_PREFIX = ""

def DEBUG_INIT(file, flag):
  global _DEBUG
  global _DEBUG_FILE
  _DEBUG = flag
  _DEBUG_FILE = file
  
def DEBUG_PUSH():
  global _DEBUG_PREFIX
  _DEBUG_PREFIX += "  "

def DEBUG_POP():
  global _DEBUG_PREFIX
  _DEBUG_PREFIX = _DEBUG_PREFIX[:-2]

def DEBUG(s):
  if _DEBUG:
    _DEBUG_FILE.write("{}{}\n".format(_DEBUG_PREFIX, str(s)))

def convert_signed32(num):
  num = num & 0xFFFFFFFF
  return (num ^ 0x80000000) - 0x80000000
  
def is_valid_addr(bv, addr):
  return bv.get_segment_at(addr) is not None
  
def is_invalid_addr(bv, addr):
  return bv.get_segment_at(addr) is None
  
def get_section_at(bv, addr):
  if is_invalid_addr(bv, addr):
    return None

  for sec in bv.sections.values():
    if sec.start <= addr < sec.end:
      return sec
  return None

def is_executable(bv, addr):
  seg = bv.get_segment_at(addr)
  return seg is not None and seg.executable

def is_readable(bv, addr):
  seg = bv.get_segment_at(addr)
  return seg is not None and seg.writable

def is_writeable(bv, addr):
  seg = bv.get_segment_at(addr)
  return seg is not None and seg.readable

def is_ELF(bv):
  return bv.view_type == 'ELF'

def is_PE(bv):
  return bv.view_type == 'PE'

VARIABLES_TO_RECOVER = {}

def handle_store(bv, func, insn):
  i = 0
  operands = binja.MediumLevelILInstruction.ILOperations[insn.operation]
  for operand in operands:
    name, operand_type = operand
    if operand_type == "int":
      value = insn.operands[i]
      DEBUG("{} {:x}".format(func.name, convert_signed32(value)))
      VARIABLES_TO_RECOVER[convert_signed32(value)] = 1

def handle_function(bv, func):
  if func is None:
    return
  
  # Don't process the external functions
  if func.symbol.type == binja.SymbolType.ImportedFunctionSymbol:
    return

  DEBUG("{:x} {}".format(func.start, func.name))
  for block in func.medium_level_il.basic_blocks:
    for insn in block:
      DEBUG("{:x} {} {}".format(insn.address, str(insn), insn.operation))
      DEBUG("{:x} {} {}".format(insn.address, str(insn.ssa_form), insn.ssa_form.operation))
      DEBUG("{}".format(bv.get_data_var_at(insn.address)))
      if insn.operation ==  binja.MediumLevelILOperation.MLIL_STORE:
         # handle destination operand
         value = insn.dest
         handle_store(bv, func, value)
      elif insn.operation ==  binja.MediumLevelILOperation.MLIL_LOAD:
        value = insn.src
        handle_store(bv, func, value)

def identify_data_variable(bv):
  DEBUG("Looking for data variables")
  DEBUG_PUSH()
  
  for seg in bv.segments:
    addr = seg.start
    if seg is not None and seg.executable:
      continue

    var = addr
    next_var = None
    while True:
      DEBUG("Variable at {:x} ".format(var))
      VARIABLES_TO_RECOVER[var] = 0
      next_var = bv.get_next_data_var_after(var)
      if next_var == var:
        break
      var = next_var
  DEBUG_POP()

def main(binary_file):
  bv = binja.BinaryViewType.get_view_of_file(binary_file)
  bv.update_analysis_and_wait()
  
  DEBUG("Analysis file {} loaded...".format(binary_file))
  DEBUG("Entry points {:x} {}".format(bv.entry_point, bv.entry_function.name))
  
  entry_func = bv.entry_function
  identify_data_variable(bv)
  
  for func in bv.functions:
    handle_function(bv, func)
    
  DEBUG("Number of global variables recovered with Naive approach {}".format(len(VARIABLES_TO_RECOVER)))

def updateCFG(infile):
  M = CFG_pb2.Module()
  with open(in_file, 'rb') as inf:
    M.ParseFromString(inf.read())
    GV = list(M.global_vars)
    
  with open(out_file, "w") as outf:
    outf.write(M.SerializeToString())
  
if __name__ == '__main__':
  parser = argparse.ArgumentParser()
  parser.add_argument("--log_file", type=argparse.FileType('w'),
                      default=sys.stderr,
                      help='Name of the log file. Default is stderr.')
    
  parser.add_argument('--out',
                      help='Name of the output proto buffer file.',
                      required=True)
    
  parser.add_argument('--binary',
                      help='Name of the binary image.',
                      required=True)
  
  args = parser.parse_args(sys.argv[1:])
  
  if args.log_file:
    DEBUG_INIT(args.log_file, True)
    DEBUG("Debugging is enabled.")
  
  BINARY_FILE = args.binary
  main(args.binary)