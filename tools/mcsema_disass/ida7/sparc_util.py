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

import collections
import idaapi
import idautils
import idc

import util

# Maps instruction EAs to a pair of decoded inst, and the bytes of the inst.
PREFIX_ITYPES = tuple()

_DELAYED_SLOT_INSTR = set([idaapi.SPARC_call,
                           idaapi.SPARC_ret,
                           idaapi.SPARC_retl,
                           idaapi.SPARC_jmp,
                           idaapi.SPARC_b,
                           idaapi.SPARC_bp,
                           idaapi.SPARC_bpr,
                           idaapi.SPARC_fb,
                           idaapi.SPARC_fbp,
                           idaapi.SPARC_return])

PERSONALITY_NORMAL = 0
PERSONALITY_DIRECT_JUMP = 1
PERSONALITY_INDIRECT_JUMP = 2
PERSONALITY_DIRECT_CALL = 3
PERSONALITY_INDIRECT_CALL = 4
PERSONALITY_RETURN = 5
PERSONALITY_SYSTEM_CALL = 6
PERSONALITY_SYSTEM_RETURN = 7
PERSONALITY_CONDITIONAL_BRANCH = 8
PERSONALITY_TERMINATOR = 9

PERSONALITIES = collections.defaultdict(int)
PERSONALITIES.update({
  idaapi.SPARC_call: PERSONALITY_DIRECT_CALL,
  
  idaapi.SPARC_ret: PERSONALITY_RETURN,
  idaapi.SPARC_retl: PERSONALITY_RETURN,
  idaapi.SPARC_rett: PERSONALITY_RETURN,
  idaapi.SPARC_return: PERSONALITY_RETURN,
  
  idaapi.SPARC_b: PERSONALITY_DIRECT_JUMP,
  idaapi.SPARC_jmp: PERSONALITY_INDIRECT_JUMP,
  idaapi.SPARC_done: PERSONALITY_INDIRECT_JUMP,
  idaapi.SPARC_retry: PERSONALITY_INDIRECT_JUMP,
  
  #idaapi.SPARC_b: PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.SPARC_bp: PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.SPARC_bpr: PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.SPARC_fb: PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.SPARC_fbp: PERSONALITY_CONDITIONAL_BRANCH,

  idaapi.SPARC_illtrap: PERSONALITY_TERMINATOR,
})

def fixup_personality(inst, p):
  if inst.itype == idaapi.SPARC_b:
    if 0 <= inst.segpref <= 0xf and inst.segpref != 0x8:
      return PERSONALITY_CONDITIONAL_BRANCH
  elif inst.itype == idaapi.SPARC_bp:
    if inst.segpref == 0x8:
      return PERSONALITY_DIRECT_JUMP
  elif inst.itype == idaapi.SPARC_call:
    if inst.ops[0].type == idc.o_phrase:  # Not sure why it's not `o_reg`...
      return PERSONALITY_INDIRECT_CALL
  return p


SPARC_XREF_INSTR_EAS = dict()

OPND_WRITE_FLAGS = {
  0: idaapi.CF_CHG1,
  1: idaapi.CF_CHG2,
  2: idaapi.CF_CHG3,
  3: idaapi.CF_CHG4,
  4: idaapi.CF_CHG5,
  5: idaapi.CF_CHG6,
}

OPND_READ_FLAGS = {
  0: idaapi.CF_USE1,
  1: idaapi.CF_USE2,
  2: idaapi.CF_USE3,
  3: idaapi.CF_USE4,
  4: idaapi.CF_USE5,
  5: idaapi.CF_USE6,
}

OPND_DTYPE_STR = {
  0:'dt_byte',
  1:'dt_word',
  2:'dt_dword',
  3:'dt_float',
  4:'dt_double',
  5:'dt_tbyte',
  6:'dt_packreal',
  7:'dt_qword',
  8:'dt_byte16',
  9:'dt_code',
  10:'dt_void',
  11:'dt_fword',
  12:'dt_bitfild',
  13:'dt_string',
  14:'dt_unicode',
  16:'dt_ldbl',
  17:'dt_byte32',
  18:'dt_byte64'
}

OPND_DTYPE_TO_SIZE = {
  idaapi.dt_byte: 1,
  idaapi.dt_word: 2,
  idaapi.dt_dword: 4,
  idaapi.dt_float: 4,
  idaapi.dt_double: 8,
  idaapi.dt_qword: 8,
  idaapi.dt_byte16: 16,
  idaapi.dt_fword: 6,
  idaapi.dt_byte32: 32,
  idaapi.dt_byte64: 64,
}

OPND_REG_NAME = {
  0 : '%g0',
  1 : '%g1',
  2 : '%g2',
  3 : '%g3',
  4 : '%g4',
  5 : '%g5',
  6 : '%g6',
  7 : '%g7',
  8  : '%o0',
  9  : '%o1',
  10 : '%o2',
  11 : '%o3',
  12 : '%o4',
  13 : '%o5',
  14 : '%o6',
  15 : '%o7',
  16 : '%l0',
  17 : '%l1',
  18 : '%l2',
  19 : '%l3',
  20 : '%l4',
  21 : '%l5',
  22 : '%l6',
  23 : '%l7',
  24 : '%i0',
  25 : '%i1',
  26 : '%i2',
  27 : '%i3',
  28 : '%i4',
  29 : '%i5',
  30 : '%i6',
  31 : '%i7',
}

def get_native_size():
  info = idaapi.get_inf_structure()
  if info.is_64bit():
    return 8
  elif info.is_32bit():
    return 4
  else:
    return 2

def get_register_name(reg_id, size=None):
  if size is None:
    size = get_native_size()
  return idaapi.get_reg_name(reg_id, size)

def get_register_info(reg_name):
  ri = idaapi.reg_info_t()
  success = idaapi.parse_reg_name(reg_name, ri)
  return ri

class Operand(object):
  def __init__(self, opnd, ea, insn, write, read):
    self._operand = opnd
    self._ea = ea
    self._read = read
    self._write= write
    self._insn = insn
    self._type = opnd.type
    self._index = None
    self._base = None
    self._disp = None

    if self._type in (idaapi.o_displ, idaapi.o_phrase):
      specflag1 = self.op_t.specflag1
      specflag2 = self.op_t.specflag2
      has_disp = self.text.find('+') > 0
      base_ = self.op_t.reg
      index_ = None
      disp_ = None
      if specflag1 != 0:
        index_ = (specflag1 & 0x1F)
        disp_ = None
      elif has_disp:
        index_ = None
        disp_ = idc.get_operand_value(self._ea, self.index)

      self._index = index_
      self._base = base_
      self._disp = disp_

  def _get_datatype_size(self, dtype):
    return OPND_DTYPE_TO_SIZE.get(dtype,0)

  def _get_datatypestr_from_dtyp(self, dt_dtyp):
    return OPND_DTYPE_STR.get(dt_dtyp,"")

  @property
  def op_t(self):
    return self._operand

  @property
  def value(self):
    return idc.get_operand_value(self._ea, self.index)

  @property
  def size(self):
    return self._get_datatype_size(self._operand.dtyp)

  @property
  def text(self):
    return idc.print_operand(self._ea, self.index)

  @property
  def dtype(self):
    return self._get_datatypestr_from_dtyp(self._operand.dtyp)

  @property
  def index(self):
    return self._operand.n

  @property
  def type(self):
    return self._type

  @property
  def is_read(self):
    return self._read

  @property
  def is_write(self):
    return self._write

  @property
  def is_void(self):
    return self._type == idaapi.o_void

  @property
  def is_reg(self):
    return self._type ==  idaapi.o_reg

  @property
  def is_mem(self):
    return self._type == idaapi.o_mem

  @property
  def is_phrase(self):
    return self._type == idaapi.o_phrase

  @property
  def is_displ(self):
    return self._type == idaapi.o_displ

  @property
  def is_imm(self):
    return self._type == idaapi.o_imm

  @property
  def is_far(self):
    return self._type == idaapi.o_far

  @property
  def is_near(self):
    return self._type == idaapi.o_near

  @property
  def is_special(self):
    return self._type >= idaapi.o_idpspec0

  @property
  def has_phrase(self):
    return self._type in (idaapi.o_phrase, idaapi.o_displ)

  @property
  def reg_id(self):
    """ID of the register used in the operand."""
    return self._operand.reg

  @property
  def reg(self):
    """Name of the register used in the operand."""
    if self.has_phrase:
      size = get_native_size()
      return get_register_name(self.reg_id, size)

    if self.is_reg:
      return get_register_name(self.reg_id, self.size)

  @property
  def regs(self):
    if self.has_phrase:
      return set(reg for reg in (self.base, self.index) if reg)
    elif self.is_reg:
      return {get_register_name(self.reg_id, self.size)}
    else:
      return set()

  @property
  def base_id(self):
    return self._base

  @property
  def disp_id(self):
    return self._disp

  @property
  def index_id(self):
    return self._index

  @property
  def base_reg(self):
    if self._base is None:
      return None
    return get_register_name(self._base)

  @property
  def index_reg(self):
    if self._index is None:
      return None
    return get_register_name(self._index)


class Instruction(object):
  def __init__(self, ea):
    self._ea = ea
    self._insn, _ = util.decode_instruction(ea)
    self._disass = util.disassemble(ea)
    if self._insn:
      self._operands = self._make_operands()
    else:
      self._operands = []
    self._KILLED_REGS = self._get_killed_regs()

  def _is_operand_write_to(self, index):
    return (self.feature & OPND_WRITE_FLAGS[index])

  def _is_operand_read_from(self, index):
    return (self.feature & OPND_READ_FLAGS[index])

  def _make_operands(self):
    operands = []
    for index, opnd in enumerate(self._insn.ops):
      if opnd.type == idaapi.o_void:
        break
      #util.DEBUG("index {} opnd {}".format(index, opnd))
      operands.append(Operand(opnd,
                              self._ea,
                              insn=self._insn,
                              write=self._is_operand_write_to(index),
                              read=self._is_operand_read_from(index)))
    return operands

  def _get_killed_regs(self):
    killed_regs = []
    for opnd in self._operands:
      if opnd.is_reg and opnd.is_write:
        killed_regs.append(opnd.reg_id)
    return killed_regs

  def is_valid(self):
    return self._insn != None

  def is_nop(self):
    return self._insn.get_canon_mnem() == "nop"

  @property
  def ea(self):
    return self._insn.ea

  @property
  def size(self):
    return self._insn.size

  @property
  def itype(self):
    return self._insn.itype

  @property
  def feature(self):
    return self._insn.get_canon_feature()

  @property
  def operands(self):
    return self._operands

  @property
  def mnemonic(self):
    return self._insn.get_canon_mnem()

  def has_imm_operand(self):
    for opnd in self._operands:
      if opnd and opnd.is_imm:
        return True
    return False

  def is_branch_always(self):
    if self._insn:
      return ((self._insn.itype in [idaapi.SPARC_b,idaapi.SPARC_bp]) \
            and (self._insn.segpref == 8)) or \
            (self._insn.itype in [ idaapi.SPARC_jmp, idaapi.SPARC_jmpl])
    return False

  def is_branch_never(self):
    if self._insn:
      return (self._insn.itype in [idaapi.SPARC_b,idaapi.SPARC_bp]) \
          and (self._insn.segpref == 0x0)
    return False

  def is_return(self):
    _SPARC_RETURN_INST_TYPES = (idaapi.SPARC_ret,
                                idaapi.SPARC_retl,
                                idaapi.SPARC_rett,
                                idaapi.SPARC_return)
    if self._insn:
      return self._insn.itype in _SPARC_RETURN_INST_TYPES

  def is_insn_sll(self):
    return self._insn.itype in [idaapi.SPARC_sll, idaapi.SPARC_sllx]

  def is_insn_bset(self):
    return self._insn.itype in [idaapi.SPARC_bset]

  def is_insn_or(self):
    return self._insn.itype in [idaapi.SPARC_or]

  def is_insn_add(self):
    return self._insn.itype in [idaapi.SPARC_add]

  def is_insn_btog(self):
    return self._insn.itype in [idaapi.SPARC_btog]

  def is_insn_sethi(self):
    return self._insn.itype in [idaapi.SPARC_sethi]

  def is_insn_inc_1(self):
    return self._insn.itype in [ idaapi.SPARC_inc ] \
            and len(self._operands) == 1

  def is_insn_inc_2(self):
    return self._insn.itype in [ idaapi.SPARC_inc ] \
            and len(self._operands) == 2

  def is_reg_killed(self, reg_num):
    return reg_num in self._KILLED_REGS

  def print_reg_killed(self):
    reg_name = ""
    for opnd in self._operands:
      if opnd.is_reg and opnd.is_write:
        reg_name += " "
        reg_name += opnd.reg

  def killed_regs(self):
    for reg in self._KILLED_REGS:
      yield reg

_NO_DELAY_SLOTS = ("ba,a", "bn,a")

def has_delayed_slot(inst):
  if inst.itype not in _DELAYED_SLOT_INSTR:
    return False
  elif inst.itype == idaapi.SPARC_b:
    import util
    inst_name = util.disassemble(inst.ea).split(" ")[0]
    return inst_name not in _NO_DELAY_SLOTS
  else:
    return True
  # ba,a
  # bn,a

def is_wide_instr(inst):
  return inst.itype in [ idaapi.SPARC_setuw ]

def program_in_higher_address(ea):
  """ Check if the program is placed in higher (> 4gb)
      in address space. The text and data are placed in
      higher address space in solaris for sparc v9
  """
  seg_ea = idc.get_segm_start(ea)
  if seg_ea >= 0x100000000:
    return True
  return False


def fixup_delayed_instr_size(inst):
  return 4  # max instruction size in sparc is 4. IDA decodes sethi as inst with size 8

def fixup_instr_as_nop(inst):
  if inst.itype in [ idaapi.SPARC_b, idaapi.SPARC_bp ]:
    if inst.segpref == 0x0:
      return True
  return False

def fixup_function_return_address(inst, next_ea):
  inst, _ = util.decode_instruction(next_ea)
  if not inst:
    return next_ea
  elif inst.itype == idaapi.SPARC_illtrap:  # Structure return.
    return next_ea + 4
  else:
    return next_ea


_INVALID_THUNK_ADDR = (False, idc.BADADDR)

def is_ELF_thunk_by_structure(ea):
  """Try to manually identify an ELF thunk by its structure."""

  global _INVALID_THUNK_ADDR
  inst = None
  
  for i in range(4):  # 1 is good enough for x86, 4 for aarch64.
    inst, _ = util.decode_instruction(ea)
    if not inst:
      break
    # elif is_direct_jump(inst):
    #   ea = get_direct_branch_target(inst)
    #   inst = None
    if util.is_indirect_jump(inst) or util.is_direct_jump(inst):
      target_ea = util.get_reference_target(inst.ea)
      if not util.is_invalid_ea(target_ea):
        seg_name = idc.get_segm_name(target_ea).lower()
        if ".got" in seg_name or ".plt" in seg_name:
          target_ea = util.get_reference_target(target_ea)
          seg_name = idc.get_segm_name(target_ea).lower()

        if "extern" == seg_name:
          return True, target_ea

    ea = inst.ea + inst.size

  return _INVALID_THUNK_ADDR

def _get_branch_target(arg):
  from util import INT_TYPES

  if not isinstance(arg, INT_TYPES):
    branch_inst_ea = arg.ea
  else:
    branch_inst_ea = arg
  try:
    branch_flows = tuple(idautils.CodeRefsFrom(branch_inst_ea, False))
    return branch_flows[0]
  except:
    decoded_inst, _ = util.decode_instruction(branch_inst_ea)
    target_ea = decoded_inst.Op1.addr
    if not target_ea:
      for i, op in enumerate(decoded_inst.ops):
        if op.addr != 0:
          target_ea = op.addr
    return target_ea

_SPARC_LOAD_INST_TYPES = (idaapi.SPARC_lduw,
                          idaapi.SPARC_ldsw,
                          idaapi.SPARC_ldub,
                          idaapi.SPARC_lduba,
                          idaapi.SPARC_ldsb,
                          idaapi.SPARC_ldx)
_SPARC_STORE_INST_TYPES = (idaapi.SPARC_stw, idaapi.SPARC_stb)

_SPARC_SET_INST_TYPES = (idaapi.SPARC_sethi, idaapi.SPARC_setx, idaapi.SPARC_setuw, idaapi.SPARC_setsw)

_SPARC_MOV_INST_TYPES = (idaapi.SPARC_mov, idaapi.SPARC_movr, idaapi.SPARC_pseudo_mov)

_SPARC_OP_3_INST_TYPES = (idaapi.SPARC_mulx, idaapi.SPARC_srl, idaapi.SPARC_srlx, idaapi.SPARC_sra, idaapi.SPARC_srax)


_ONE_BIT_VALS = set()
for i in range(32):
  _ONE_BIT_VALS.add(1 << i)

def decode_wide_instr(inst):
  """ Getting registers updated by `SET`. It sometime update two registers
      both getting used for address computation.
  """
  live_registers = set()
  scan_insn =  Instruction(inst.ea)
  opnd1 = scan_insn.operands[0]

  instr_data = util.read_dword(inst.ea)
  reg_id = (instr_data & 0x3E000000) >> 25
  yield reg_id, 0, opnd1.value & 0xfffffc00

  next_inst_data = util.read_dword(inst.ea + 4)
  next_reg_id = (next_inst_data & 0x3E000000) >> 25
  yield next_reg_id, 1, opnd1.value


def _try_scan_reference_state_4(inst, block_ea, opnd_val, opnd_reg_num, reference_instr_set):
  """ Scan the set of instruction which are part of address reference
  """
  from util import decode_instruction, is_direct_jump, is_indirect_jump
  from util import is_invalid_ea, get_reference_target, xrange
  from util import is_terminator, is_function_call, is_conditional_jump
  from util import is_return

  block_head_eas = set()
  seen_blocks = set()
  seen_instructions = set()
  block_head_eas.add(block_ea)

  func_name = idaapi.get_func_name(inst.ea)
  live_registers = set()
  fixed_addresses = set()
  live_registers_state = dict()
  live_registers_value = dict()

  live_registers.add(opnd_reg_num)
  live_registers_value[opnd_reg_num] = opnd_val
  if inst.itype == idaapi.SPARC_sethi:
    live_registers_state[opnd_reg_num] = 0
  else:
    for reg_num, state, value in decode_wide_instr(inst):
      live_registers.add(reg_num)
      live_registers_state[reg_num] = state
      live_registers_value[reg_num] = value
    #live_registers.update(decode_wide_instr(inst, live_registers_state, live_registers_value))
    #DEBUG("live_registers {} state {}  values {}".format(live_registers, live_registers_state, live_registers_value))
    #live_registers_state[opnd_reg_num] = 1

  #DEBUG("_try_scan_reference_set start with ea {:x}".format(block_ea))
  while len(block_head_eas):
    block_head_ea = block_head_eas.pop()
    if block_head_ea in seen_blocks:
      continue

    seen_blocks.add(block_head_ea)
    next_inst_ea = block_head_ea

    for i in xrange(256):
      #idc.create_insn(next_inst_ea)
      #idaapi.auto_wait()
      scan_inst = Instruction(next_inst_ea)
      if not scan_inst.is_valid():
        continue

      next_inst_ea = scan_inst.ea + scan_inst.size
      prev_inst_ea = idc.prev_head(scan_inst.ea)
      prev_inst =  Instruction(prev_inst_ea)

      op1 = scan_inst.operands[0] if len(scan_inst.operands) > 0 else None
      op2 = scan_inst.operands[1] if len(scan_inst.operands) > 1 else None
      op3 = scan_inst.operands[2] if len(scan_inst.operands) > 2 else None

      # There is no live registers to scan the value
      # break
      if (len(live_registers) == 0) \
        or scan_inst.ea in seen_instructions:
        break

      # Add to the instructions already seen
      seen_instructions.add(scan_inst.ea)
      #DEBUG("Scanning Instruction ea {:x} {} reg_op {} state {}".format(scan_inst.ea, scan_inst._disass, live_registers, live_registers_state))

      if (func_name != idaapi.get_func_name(scan_inst.ea)):
        #DEBUG("Scanning break with new func ea {:x} {} reg_op {}".format(scan_inst.ea, scan_inst._disass, opnd_reg_num))
        break

      if scan_inst.is_branch_never() \
        or is_terminator(scan_inst.ea) \
        or is_function_call(scan_inst.ea): # \
        #or scan_inst.is_nop():
        continue


      if is_direct_jump(scan_inst.ea) \
        or is_indirect_jump(scan_inst.ea) \
        or is_conditional_jump(scan_inst.ea):
        block_head_eas.add(_get_branch_target(scan_inst._insn))


      if scan_inst.itype in _SPARC_LOAD_INST_TYPES:
        if op1.base_id in live_registers:
          if scan_inst.ea not in reference_instr_set:
            reference_instr_set.append(scan_inst.ea)

          if op1.disp_id != None:
            fixup_addr = live_registers_value[op1.base_id] + op1.disp_id
            # The address here should be valid.
            # Still have a check for the sanity
            if not is_invalid_ea(fixup_addr):
              fixed_addresses.add(fixup_addr)

        if op2.reg_id in live_registers:
          live_registers.remove(op2.reg_id)

      elif scan_inst.itype in _SPARC_STORE_INST_TYPES:
        if op2.base_id in live_registers:
          if scan_inst.ea not in reference_instr_set:
            reference_instr_set.append(scan_inst.ea)

          if op2.disp_id != None:
            fixup_addr = live_registers_value[op2.base_id] + op2.disp_id
            # The address here should be valid.
            # Still have a check for the sanity
            if not is_invalid_ea(fixup_addr):
              fixed_addresses.add(fixup_addr)

      elif scan_inst.is_insn_sll():
        if op2.is_imm and op1.reg_id in live_registers:
          state = live_registers_state[op1.reg_id]

          if state < 2: # and op2.value == 12:
            value = live_registers_value[op1.reg_id] << op2.value
            live_registers_value[op3.reg_id] = value
            live_registers_state[op3.reg_id] = state + 1
            live_registers.add(op3.reg_id)

            if scan_inst.ea not in reference_instr_set:
              reference_instr_set.append(scan_inst.ea)

        elif op1.reg_id not in live_registers:
          if op3.reg_id in live_registers:
            live_registers.remove(op3.reg_id)
            del live_registers_state[op3.reg_id]

      elif scan_inst.is_insn_bset():
        if op1.is_imm and op2.reg_id in live_registers:
          state = live_registers_state[op2.reg_id]

          if state in [0, 2] and op1.value <= 0xFFF:
            value = live_registers_value[op2.reg_id] | op1.value
            live_registers_value[op2.reg_id] = value
            live_registers_state[op2.reg_id] = state + 1

            if scan_inst.ea not in reference_instr_set:
              reference_instr_set.append(scan_inst.ea)

            if live_registers_state[op2.reg_id] == 3:
              live_registers.remove(op2.reg_id)
              del live_registers_state[op2.reg_id]

              # The address should be fixed at this state.
              #Add them to the fixed_addresses
              value = live_registers_value[op2.reg_id]
              del live_registers_value[op2.reg_id]
              if not is_invalid_ea(value):
                fixed_addresses.add(value)

      elif scan_inst.is_insn_or():
        if op2.is_imm and op1.reg_id in live_registers:
          state = live_registers_state[op1.reg_id]

          if state in [0, 2] and op2.value <= 0xFFF:
            value = live_registers_value[op1.reg_id] | op2.value
            live_registers_value[op3.reg_id] = value
            live_registers_state[op3.reg_id] = state + 1
            live_registers.add(op3.reg_id)

            if scan_inst.ea not in reference_instr_set:
              reference_instr_set.append(scan_inst.ea)

            if live_registers_state[op3.reg_id] == 3:
              live_registers.remove(op3.reg_id)
              del live_registers_state[op3.reg_id]

              # The address should be fixed at this state.
              #Add them to the fixed_addresses
              value = live_registers_value[op3.reg_id]
              del live_registers_value[op3.reg_id]
              if not is_invalid_ea(value):
                fixed_addresses.add(value)

        elif op1.reg_id not in live_registers:
          if op3.reg_id in live_registers:
            live_registers.remove(op3.reg_id)
            del live_registers_state[op3.reg_id]

      elif scan_inst.is_insn_inc_2():
        if op1.is_imm and op2.reg_id in live_registers:
          state = live_registers_state[op2.reg_id]

          if state in [0, 2] and op1.value <= 0xFFF:
            value = live_registers_value[op2.reg_id] + op1.value
            live_registers_value[op2.reg_id] = value
            live_registers_state[op2.reg_id] = state + 1

            if scan_inst.ea not in reference_instr_set:
              reference_instr_set.append(scan_inst.ea)

            if live_registers_state[op2.reg_id] == 3:
              live_registers.remove(op2.reg_id)
              del live_registers_state[op2.reg_id]

              # The address should be fixed at this state.
              #Add them to the fixed_addresses
              value = live_registers_value[op2.reg_id]
              del live_registers_value[op2.reg_id]
              if not is_invalid_ea(value):
                fixed_addresses.add(value)

      elif scan_inst.is_insn_add():
        if op2.is_imm and op1.reg_id in live_registers:
          state = live_registers_state[op1.reg_id]

          if state in [0, 2] and op2.value <= 0xFFF:
            value = live_registers_value[op1.reg_id] + op2.value
            live_registers_value[op3.reg_id] = value
            live_registers_state[op3.reg_id] = state + 1
            live_registers.add(op3.reg_id)

            if scan_inst.ea not in reference_instr_set:
              reference_instr_set.append(scan_inst.ea)

            if live_registers_state[op3.reg_id] == 3:
              live_registers.remove(op3.reg_id)
              del live_registers_state[op3.reg_id]

              # The address should be fixed at this state.
              #Add them to the fixed_addresses
              value = live_registers_value[op3.reg_id]
              del live_registers_value[op3.reg_id]
              if not is_invalid_ea(value):
                fixed_addresses.add(value)

        elif op1.reg_id not in live_registers:
          if op3.reg_id in live_registers:
            live_registers.remove(op3.reg_id)
            del live_registers_state[op3.reg_id]

      else:
        for reg in scan_inst.killed_regs():
          if reg in live_registers:
            live_registers.remove(reg)
            del live_registers_state[reg]

      if is_return(prev_inst_ea):
        break

          # No need to do further scanning for the branches
      elif prev_inst.is_branch_always():
        block_head_eas.add(_get_branch_target(prev_inst._insn))
        break

  if len(fixed_addresses):
    return list(fixed_addresses)

  # Traverse through the live_registers_value and found all valid addresses generated
  for reg_num in live_registers_value.keys():
    fixup_addr = live_registers_value[reg_num]
    if not is_invalid_ea(fixup_addr):
      fixed_addresses.add(fixup_addr)

  return list(fixed_addresses)


def _get_reference_address(inst, imm_opnd, reference_instr_set):
  fixup_addr = imm_opnd.value
  for item in reference_instr_set:
    util.DEBUG("ea {:x} fixup_addr {}".format(item, fixup_addr))
    scan_instr = Instruction(item)
    if scan_instr.is_insn_sll():
      fixup_addr = fixup_addr << 12;

    elif scan_instr.is_insn_bset():
      fixup_addr = fixup_addr + scan_instr.operands[0].value
      if not util.is_invalid_ea(fixup_addr):
        return fixup_addr

    elif scan_instr.is_insn_or():
      fixup_addr = fixup_addr + scan_instr.operands[1].value
      if not util.is_invalid_ea(fixup_addr):
        return fixup_addr

    elif scan_instr.is_insn_inc_2():
      fixup_addr = fixup_addr + scan_instr.operands[0].value
      if not util.is_invalid_ea(fixup_addr):
        return fixup_addr

    elif scan_instr.is_insn_add():
      fixup_addr = fixup_addr + scan_instr.operands[0].value
      if not util.is_invalid_ea(fixup_addr):
        return fixup_addr

  return fixup_addr

def _try_fix_sparc_ref_addr_solarisv9(inst, op, op_val, all_refs):
  """ SPARC uses multiple instructions to load the address (set/sethi + bset/or + sll + bset/or)
      It checks if the set/sethi is involved in address loading and gets the possible set of
      addreses it loads.
  """
  global SPARC_XREF_INSTR_EAS
  from util import decode_instruction, is_direct_jump, is_indirect_jump
  from util import is_invalid_ea, get_reference_target

  ref_inst = Instruction(inst.ea)
  if not len(ref_inst.operands):
    return op_val, 0, 0

  operands = ref_inst.operands
  ref_op1 = operands[0]
  ref_op2 = operands[1]
  next_inst_ea = ref_inst.ea + ref_inst.size

  op_mask = 0xfffffc00
  addr_fixup_done = False
  next_ea = inst.ea + inst.size

  #func_name = idaapi.get_func_name(inst.ea)
  #DEBUG("SET instruction ea {:x} {}  itype {}".format(inst.ea, disassemble(inst.ea), inst.itype));

  # Identify sethi/set instruction which assign
  # 0 to the registers
  assert (ref_op1.is_imm == True)
  if ref_op1.value < 4096 \
    or ref_op1.value in [ 0x19999999 ]:
    return op_val, 0, op_val

  # Observation: Set of two instructions (sethi, btog) frequently
  # used to calculate stack offset; Don't scan for such cases
  next_inst = Instruction(ref_inst.ea + ref_inst.size)
  if ref_inst.is_insn_sethi() and next_inst.is_insn_btog():
    if next_inst.is_reg_killed(ref_op2.reg_id):
      return op_val, 0, op_val


  target_eas = list()
  reference_inst_eas = list()
  target_eas.append(next_inst_ea)
  reference_inst_eas.append(ref_inst.ea)

  # Check if the `sethi` instruction is in delay slot
  prev_inst_ea = idc.prev_head(inst.ea)
  prev_inst, _ = util.decode_instruction(prev_inst_ea)
  if prev_inst:
    if has_delayed_slot(prev_inst):
      target_eas.append(_get_branch_target(prev_inst))

  for ea in target_eas:
    possible_list = _try_scan_reference_state_4(inst, ea, \
                        op_val, ref_op2.reg_id, reference_inst_eas)

    if len(possible_list) > 0 and  len(reference_inst_eas) > 1:
      if not is_invalid_ea(possible_list[0]):
        addr_fixup_done = True
        fixup_addr = possible_list[0]

      for item in reference_inst_eas:
        SPARC_XREF_INSTR_EAS[item] = fixup_addr
        #DEBUG("Reference instr list {:x}".format(item))

  if addr_fixup_done:
    all_refs.add(fixup_addr)
    #DEBUG("FIXUP address {:x}".format(fixup_addr))
    return fixup_addr, op_mask, op_val

  #DEBUG("NOT_FIXUP address {:x}".format(op_val))
  return op_val, 0, op_val


def _try_scan_reference_state_2(inst, block_ea, opnd_val, opnd_reg_num, reference_instr_set):
  """ Scan the set of two instructions possibly refering to an address. It does the address lookup 
      if they are within 4GB address
  """
  from util import decode_instruction, is_direct_jump, is_indirect_jump
  from util import is_invalid_ea, get_reference_target, xrange
  from util import is_terminator, is_function_call, is_conditional_jump
  from util import is_return

  block_head_eas = set()
  seen_blocks = set()
  seen_instructions = set()
  block_head_eas.add(block_ea)

  func_name = idaapi.get_func_name(inst.ea)
  live_registers = set()
  live_registers_value = dict()

  live_registers.add(opnd_reg_num)
  live_registers_value[opnd_reg_num] = opnd_val

  #DEBUG("_try_scan_reference_state_2 start with ea {:x}".format(block_ea))
  while len(block_head_eas):
    block_head_ea = block_head_eas.pop()
    if block_head_ea in seen_blocks:
      continue

    seen_blocks.add(block_head_ea)
    next_inst_ea = block_head_ea

    for i in xrange(16):
      #idc.create_insn(next_inst_ea)
      #idaapi.auto_wait()
      scan_inst = Instruction(next_inst_ea)
      if not scan_inst.is_valid():
        continue

      next_inst_ea = scan_inst.ea + scan_inst.size
      prev_inst_ea = idc.prev_head(scan_inst.ea)
      prev_inst =  Instruction(prev_inst_ea)

      op1 = scan_inst.operands[0] if len(scan_inst.operands) > 0 else None
      op2 = scan_inst.operands[1] if len(scan_inst.operands) > 1 else None
      op3 = scan_inst.operands[2] if len(scan_inst.operands) > 2 else None

      # There is no live registers to scan the value
      # break
      if (len(live_registers) == 0) \
        or scan_inst.ea in seen_instructions:
        break

      # Add to the instructions already seen
      seen_instructions.add(scan_inst.ea)
      #DEBUG("Scanning Instruction ea {:x} {} reg_op {} mnemonic {} itype {} segpref {}".format(scan_inst.ea, scan_inst._disass, live_registers, scan_inst.mnemonic, scan_inst.itype, ord(scan_inst._insn.segpref)))

      if (func_name != idaapi.get_func_name(scan_inst.ea)):
        #DEBUG("Scanning break with new func ea {:x} {} reg_op {}".format(scan_inst.ea, scan_inst._disass, opnd_reg_num))
        break

      if scan_inst.is_branch_never() \
        or is_terminator(scan_inst.ea) \
        or is_function_call(scan_inst.ea) \
        or scan_inst.is_nop():
        continue

      if is_direct_jump(scan_inst.ea) \
        or is_indirect_jump(scan_inst.ea) \
        or is_conditional_jump(scan_inst.ea):
        block_head_eas.add(_get_branch_target(scan_inst._insn))

      if scan_inst.itype in _SPARC_LOAD_INST_TYPES:
        if op1.base_id in live_registers and op1.disp_id != None:
          if scan_inst.ea not in reference_instr_set:
            reference_instr_set.append(scan_inst.ea)

          fixup_addr = live_registers_value[op1.base_id] + op1.disp_id
          return fixup_addr, True

        if op2.reg_id in live_registers:
          live_registers.remove(op2.reg_id)

      elif scan_inst.itype in _SPARC_STORE_INST_TYPES:
        if op2.base_id in live_registers and op2.disp_id != None:
          if scan_inst.ea not in reference_instr_set:
            reference_instr_set.append(scan_inst.ea)

          fixup_addr = live_registers_value[op2.base_id] + op2.disp_id
          return fixup_addr, True

      elif scan_inst.is_insn_bset():
        if op1.is_imm and op2.reg_id in live_registers:
          if op1.value <= 0xFFF:
            if scan_inst.ea not in reference_instr_set:
              reference_instr_set.append(scan_inst.ea)

            fixup_addr = live_registers_value[op2.reg_id] | op1.value
            return fixup_addr, True

      elif scan_inst.is_insn_or():
        if op2.is_imm and op1.reg_id in live_registers:
          if op2.value <= 0xFFF:
            if scan_inst.ea not in reference_instr_set:
              reference_instr_set.append(scan_inst.ea)

            fixup_addr = live_registers_value[op1.reg_id] | op2.value
            return fixup_addr, True

        elif op1.reg_id not in live_registers:
          if op3.reg_id in live_registers:
            live_registers.remove(op3.reg_id)

      elif scan_inst.is_insn_inc_2():
        if op1.is_imm and op2.reg_id in live_registers:
          if op1.value <= 0xFFF:
            if scan_inst.ea not in reference_instr_set:
              reference_instr_set.append(scan_inst.ea)

            fixup_addr = live_registers_value[op2.reg_id] + op1.value
            return fixup_addr, True

      elif scan_inst.is_insn_add():
        if op2.is_imm and op1.reg_id in live_registers:
          if op2.value <= 0xFFF:
            if scan_inst.ea not in reference_instr_set:
              reference_instr_set.append(scan_inst.ea)

            fixup_addr = live_registers_value[op1.reg_id] + op2.value
            return fixup_addr, True

        elif op1.reg_id not in live_registers:
          if op3.reg_id in live_registers:
            live_registers.remove(op3.reg_id)

      else:
        for reg in scan_inst.killed_regs():
          if reg in live_registers:
            live_registers.remove(reg)

      if is_return(prev_inst_ea):
        break

      # No need to do further scanning for the branches
      elif prev_inst.is_branch_always():
        block_head_eas.add(_get_branch_target(prev_inst._insn))
        break

  return opnd_val, False


def _try_fix_sparc_ref_addr_linux(inst, op, op_val, all_refs):
  """ It checks if the set/sethi is involved in address loading and gets the possible set of
      addreses it loads.
  """
  from util import decode_instruction, is_direct_jump, is_indirect_jump
  from util import is_invalid_ea, get_reference_target

  ref_inst = Instruction(inst.ea)
  if not len(ref_inst.operands):
    return op_val, 0, 0

  operands = ref_inst.operands
  ref_op1 = operands[0]
  ref_op2 = operands[1]
  next_inst_ea = ref_inst.ea + ref_inst.size

  op_mask = 0xfffffc00
  addr_fixup_done = False

  # Identify sethi/set instruction which assign
  # 0 to the registers
  # sethi   0, %g1
  assert (ref_op1.is_imm == True)
  if ref_op1.value < 4096:
    return idc.BADADDR, 0, 0

  if not ref_inst.is_insn_sethi():
    return op_val, op_mask, op_val

  # for ref_ea in all_refs:
  #   if (ref_ea & 0xfffffc00) == op_val and ref_ea not in _ONE_BIT_VALS:
  #     return ref_ea, 0xfffffc00

  # if (op_val & 0xfffffc00) in all_refs and op_val not in _ONE_BIT_VALS:
  #   return op_val, 0xfffffc00

  target_eas = list()
  reference_inst_eas = list()
  target_eas.append(next_inst_ea)
  reference_inst_eas.append(ref_inst.ea)

  # Check if the `sethi` instruction is in delay slot
  prev_inst_ea = idc.prev_head(inst.ea)
  prev_inst, _ = util.decode_instruction(prev_inst_ea)
  if prev_inst:
    if has_delayed_slot(prev_inst):
      target_eas.append(_get_branch_target(prev_inst))


  for ea in target_eas:
    fixed_address, addr_fixup_done = _try_scan_reference_state_2( \
                        inst, ea, op_val, ref_op2.reg_id, reference_inst_eas)

    if addr_fixup_done is True:
      all_refs.add(fixed_address)
      #DEBUG("FIXUP address {:x}".format(fixed_address))
      return fixed_address, op_mask, op_val

  #DEBUG("NOT_FIXUP address {:x}".format(op_val))
  return op_val, op_mask, op_val


def _try_fix_sparc_ref_addr_sll(inst, op, op_val, all_refs):
  """
  """
  global SPARC_XREF_INSTR_EAS
  ref_inst = Instruction(inst.ea)
  if not len(ref_inst.operands):
    return op_val, 0, 0

  operands = ref_inst.operands
  ref_op1 = operands[0]
  ref_op2 = operands[1]

  if ref_inst.itype in [ idaapi.SPARC_sllx]:
    if ref_inst.ea in SPARC_XREF_INSTR_EAS.keys():
      ref_ea = SPARC_XREF_INSTR_EAS[ref_inst.ea]
      return inst.ea, 0, op_val

    elif ref_op2.is_imm and ref_op2.value == 0xc:
      util.DEBUG("Adding xrefs to sll at {:x}. It might have been missed during scanning".format(ref_inst.ea))
      return inst.ea, 0, op_val

  return op_val, 0, op_val


_SPARC_OP_MASK = (("%hi", 0xfffffc00), ("%lo(", 0x3ff))
_BAD_REF = (idc.BADADDR, 0, 0)

# Try to handle things like `sethi %hi(foo), Rd` and `or Rd, %lo(foo), Rd` in
# SPARC code and extract out the `ea` of `foo` and the mask applied to `foo`
# in the instruction.
def try_get_ref_addr(inst, op, op_val, all_refs, _NOT_A_REF):
  global _SPARC_INVALID_MASKED_REF, _SPARC_OP_MASK

  from util import decode_instruction, is_direct_jump, is_indirect_jump
  from util import is_invalid_ea, get_reference_target

  if op.type != idc.o_imm and op.type != idc.o_displ:
    return op_val, 0, 0

  op_str = idc.print_operand(inst.ea, op.n) + "   ";

  for ref_key, op_mask in _SPARC_OP_MASK:
    if ref_key not in op_str:
      continue

    ref_name = op_str[op_str.find("(")+1:op_str.find(")")]
    ref_ea = idc.get_name_ea_simple(ref_name)

    if (ref_ea & op_mask) == op_val:
      all_refs.add(ref_ea)
      return ref_ea, op_mask, 0

    for ref_ea in all_refs:
      if (ref_ea & op_mask) == op_val:
        return ref_ea, op_mask, 0

  #DEBUG("set instruction at {:x} itype {}".format(inst.ea, inst.itype))
  #if inst.itype == idaapi.SPARC_sethi:
  #  return _try_fix_sparc_ref_addr_set(inst, op, op_val, all_refs)
  #el
  if inst.itype in [ idaapi.SPARC_sethi,
                     idaapi.SPARC_setx,
                     idaapi.SPARC_setuw,
                     idaapi.SPARC_setsw]:
    if (program_in_higher_address(inst.ea)):
      return _try_fix_sparc_ref_addr_solarisv9(inst, op, op_val, all_refs)
    else:
      return _try_fix_sparc_ref_addr_linux(inst, op, op_val, all_refs)

  elif inst.itype in [idaapi.SPARC_sllx]:
    if (program_in_higher_address(inst.ea)):
      return _try_fix_sparc_ref_addr_sll(inst, op, op_val, all_refs)

  return op_val, 0, 0

def _get_flow_target_ea(inst, xrefs):
  import util, refs
  if not len(xrefs):
    return util.get_reference_target(inst.ea)
  elif xrefs[0].type == refs.Reference.CODE:
    return xrefs[0].ea
  else:
    return idc.BADADDR

_SPARC_SAVED_REGS_NAMES = ("i0","i1","i2","i3","i4","i5","i6","i7",
                           "l0","l1","l2","l3","l4","l5","l6","l7",
                           "o6")

_SPARC_KILLED_REG_NAMES = ("icc_c", "icc_v", "icc_z", "icc_n",
                           "xcc_c", "xcc_v", "xcc_z", "xcc_n",
                           "fsr_aexc", "fsr_cexc")

_SPARC_RETURN_INST_TYPES = (idaapi.SPARC_ret, idaapi.SPARC_retl,
                            idaapi.SPARC_rett, idaapi.SPARC_return)

_SAVE_RESTORE = None
_SAVE_RESTORE_WITHOUT = {}
_SAVE_RESTORE_WITH = {}
_KILL = None
_FUNC_PRESERVED_REGS = {}

def _kill_at(ea):
  global _KILL
  R = _KILL.ranges.add()
  R.begin_ea = ea


_DEFERRED_PRESERVATION_CHECKS = []
_IS_LEAF_FUNCTION = collections.defaultdict(lambda: True)
_UNWRITTEN_REGS = collections.defaultdict(lambda: set(_SPARC_SAVED_REGS_NAMES))

def recover_deferred_preserved_regs(M):
  for call_ea, func_ea in _DEFERRED_PRESERVATION_CHECKS:
    if _IS_LEAF_FUNCTION[func_ea] and func_ea in _UNWRITTEN_REGS:
      dest_regs = list(_UNWRITTEN_REGS[func_ea])
      dest_regs.sort()
      dest_regs_key = ",".join(dest_regs)

      if dest_regs_key not in _SAVE_RESTORE_WITH:
        reg_set = M.preserved_regs.add()
        for r in dest_regs:
          reg_set.registers.append(r)
        _SAVE_RESTORE_WITH[dest_regs_key] = reg_set

      util.DEBUG("Leaf function at {:x} saves/restores registers: {}".format(
          func_ea, ", ".join(dest_regs)))

      save_restore = _SAVE_RESTORE_WITH[dest_regs_key]
      _FUNC_PRESERVED_REGS[func_ea] = save_restore
      R = save_restore.ranges.add()
      R.begin_ea = call_ea


def recover_preserved_regs(M, F, inst, xrefs, preserved_reg_sets):
  """Recover the preserved registers around a call site or in a function
  body."""
  global _SAVE_RESTORE, _SAVE_RESTORE_WITHOUT, _KILL
  global _DEFERRED_PRESERVATION_CHECKS, _IS_LEAF_FUNCTION

  import util
  
  # Update the set of registers written in this function.
  if _IS_LEAF_FUNCTION[F.ea]:
    ops = util.disassemble(inst.ea).split(", %")
    if ops:
      dest_op = ops[-1]
      _UNWRITTEN_REGS[F.ea].discard(dest_op)
  elif F.ea in _UNWRITTEN_REGS:
    del _UNWRITTEN_REGS[F.ea]

  if not _SAVE_RESTORE:
    _SAVE_RESTORE = M.preserved_regs.add()
    for reg_name in _SPARC_SAVED_REGS_NAMES:
      _SAVE_RESTORE.registers.append(reg_name)

  if not _KILL:
    _KILL = M.dead_regs.add()
    for reg_name in _SPARC_KILLED_REG_NAMES:
      _KILL.registers.append(reg_name)

  if inst.itype == idaapi.SPARC_call:
    _IS_LEAF_FUNCTION[F.ea] = False
    _UNWRITTEN_REGS.pop(F.ea, None)

    if util.is_direct_function_call(inst):

      # Pull out the target from `xrefs`, so that thunk resolution has already
      # happened.
      target_ea = _get_flow_target_ea(inst, xrefs)
      if util.is_invalid_ea(target_ea):
        _kill_at(inst.ea)
        return

      # Calling an extern function, assume it has `save`.
      if util.is_external_segment(target_ea):
        _kill_at(inst.ea)
        R = _SAVE_RESTORE.ranges.add()
        R.begin_ea = inst.ea
        return "call saved (external)"

      # Internal function, check if it starts with a `save`.
      else:

        # We scan the first three instructions looking for a `save`. Most
        # of the time we expect it to be the first instruction; however, if
        # the function needs a really big stack frame, then we might observe
        # a pattern like:
        #
        #     sethi <blah>, %g1
        #     bset <blah>, %g1
        #     save %sp, %g1, %sp
        #
        # And so we want to capture that `save`.
        i = 0
        while i < 3:
          first_inst, _ = util.decode_instruction(target_ea + (i * 4))
          if first_inst and first_inst.itype == idaapi.SPARC_save:
            _kill_at(inst.ea)
            R = _SAVE_RESTORE.ranges.add()
            R.begin_ea = inst.ea
            return "call saved (direct)"
          i += 1

        func_name = util.get_symbol_name(inst.ea, target_ea)
        if not func_name.startswith("__sparc_get_pc_thunk."):
          _kill_at(inst.ea)
          _DEFERRED_PRESERVATION_CHECKS.append((inst.ea, target_ea))
          return "check deferred"

        # Internal function doesn't start with a `save`. It might be
        # a "PC thunk", i.e. it's used to put the program counter into
        # a specific register. We will assume it saves/restores all but
        # that specific register.
        reg_name = func_name.split(".")[-1]
        if reg_name not in _SPARC_SAVED_REGS_NAMES:
          R = _SAVE_RESTORE.ranges.add()
          R.begin_ea = inst.ea
          return "call saved (direct pc thunk)"
        else:
          if reg_name not in _SAVE_RESTORE_WITHOUT:
            _SAVE_RESTORE_WITHOUT[reg_name] = M.preserved_regs.add()
            for r in _SPARC_SAVED_REGS_NAMES:
              if r != reg_name:
                _SAVE_RESTORE_WITHOUT[reg_name].registers.append(r)

          R = _SAVE_RESTORE_WITHOUT[reg_name].ranges.add()
          R.begin_ea = inst.ea
          return "call saved (direct pc thunk without {})".format(reg_name)

    # Indirect call, assume that the target has a `save`.
    #
    # TODO(pag): Consider also marking %g1 through %g5 (caller saved) as
    #            dead. Same for calling external functions above.
    elif util.is_indirect_function_call(inst):
      _IS_LEAF_FUNCTION[F.ea] = False
      _UNWRITTEN_REGS.pop(F.ea, None)

      _kill_at(inst.ea)
      R = _SAVE_RESTORE.ranges.add()
      R.begin_ea = inst.ea
      return "call saved (indirect)"

  # It's a restore; try to do function-granularity save restore.
  elif inst.itype == idaapi.SPARC_restore:
    _IS_LEAF_FUNCTION[F.ea] = False 

    ret_inst0, _ = util.decode_instruction(inst.ea - 4)
    ret_inst1, _ = util.decode_instruction(inst.ea + 4)
    for ret_inst in (ret_inst0, ret_inst1):
      if not ret_inst:
        continue

      # Look for a nearby `ret`, `retl`, `ba` or `jmp` (tail-call).
      if idaapi.SPARC_ret != ret_inst.itype and \
         idaapi.SPARC_retl != ret_inst.itype and \
         idaapi.SPARC_b != ret_inst.itype and \
         idaapi.SPARC_jmp != ret_inst.itype:
        continue

      _kill_at(ret_inst.ea)

      R = _SAVE_RESTORE.ranges.add()
      R.begin_ea = F.ea
      R.end_ea = ret_inst.ea
      return "return saved ({:0x}, {:0x})".format(F.ea, ret_inst.ea)

  # It's a return; this internally does a `restore`.
  elif inst.itype == idaapi.SPARC_return:
    _IS_LEAF_FUNCTION[F.ea] = False
    _UNWRITTEN_REGS.pop(F.ea, None)

    _kill_at(inst.ea)

    R = _SAVE_RESTORE.ranges.add()
    R.begin_ea = F.ea
    R.end_ea = inst.ea
    return "return saved ({:0x}, {:0x})".format(F.ea, inst.ea)

  # It's a trap! May as well consider it like a save/restore point.
  elif inst.itype == idaapi.SPARC_illtrap:
    _kill_at(inst.ea)

    R = _SAVE_RESTORE.ranges.add()
    R.begin_ea = F.ea
    R.end_ea = inst.ea
    return "trap saved ({:0x}, {:0x})".format(F.ea, inst.ea)

  elif inst.itype in _SPARC_RETURN_INST_TYPES:
    _kill_at(inst.ea)

  elif inst.itype == idaapi.SPARC_jmp or inst.itype == idaapi.SPARC_save:
    _IS_LEAF_FUNCTION[F.ea] = False
    _UNWRITTEN_REGS.pop(F.ea, None)

  return ""

if idaapi.get_inf_structure().is_64bit():
  def return_values():
    return {
      "register": "o0",
      "type": "L"
    }

  def return_address():
    return {
      "register": "o7",
      "type": "L"
    }

  def return_stack_pointer():
    return {
      "register": "o6",
      "offset": 0,
      "type": "L"
    }

elif idaapi.get_inf_structure().is_32bit():
  def return_values():
    return {
      "register": "o0",
      "type": "I"
    }
  def return_address():
    return {
      "register": "o7",
      "type": "I"
    }

  def return_stack_pointer():
    return {
      "register": "o6",
      "offset": 0,
      "type": "I"
    }


def recover_value_spec(V, spec):
  """Recovers the default value specification."""
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

def recover_function_spec_from_arch(E):
  """ recover the basic information about the function spec"""
  D = E.decl
  if E.argument_count >= 8:
    D.is_noreturn = E.no_return
    D.is_variadic = (E.argument_count >= 8)
    D.calling_convention = 0
    V = D.return_values.add()
    if D.is_noreturn == False:
      recover_value_spec(V, return_values())
    recover_value_spec(D.return_address, return_address())
    recover_value_spec(D.return_stack_pointer, return_stack_pointer())
