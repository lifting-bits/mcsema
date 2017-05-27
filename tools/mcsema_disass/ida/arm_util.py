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

import collections
import idaapi
import idautils
import idc

# Maps instruction EAs to a pair of decoded inst, and the bytes of the inst.
PREFIX_ITYPES = tuple()

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
  idaapi.ARM_bl: PERSONALITY_DIRECT_CALL,
  idaapi.ARM_blr: PERSONALITY_INDIRECT_CALL,

  idaapi.ARM_ret: PERSONALITY_RETURN,

  idaapi.ARM_b: PERSONALITY_DIRECT_JUMP,
  idaapi.ARM_br: PERSONALITY_INDIRECT_JUMP,

  idaapi.ARM_svc: PERSONALITY_SYSTEM_CALL,
  idaapi.ARM_hvc: PERSONALITY_SYSTEM_CALL,
  idaapi.ARM_smc: PERSONALITY_SYSTEM_CALL,

  idaapi.ARM_hlt: PERSONALITY_TERMINATOR,

  idaapi.ARM_cbnz: PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.ARM_cbz: PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.ARM_tbnz: PERSONALITY_CONDITIONAL_BRANCH,
  idaapi.ARM_tbz: PERSONALITY_CONDITIONAL_BRANCH,
})

def fixup_personality(inst, p):
  """For things like b.le, IDA will give us the `ARM_b` opcode, and we need
  to figure out if it's actually conditional. This is stored in the `segpref`
  field, and `0xe` is the unconditional version."""
  if inst.itype == idaapi.ARM_b:
    if 0 <= inst.segpref <= 0xf and inst.segpref != 0xe:
      return PERSONALITY_CONDITIONAL_BRANCH
  return p
