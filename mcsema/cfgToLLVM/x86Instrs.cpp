/*
 Copyright (c) 2013, Trail of Bits
 All rights reserved.

 Redistribution and use in source and binary forms, with or without modification,
 are permitted provided that the following conditions are met:

 Redistributions of source code must retain the above copyright notice, this
 list of conditions and the following disclaimer.

 Redistributions in binary form must reproduce the above copyright notice, this  list of conditions and the following disclaimer in the documentation and/or
 other materials provided with the distribution.

 Neither the name of the {organization} nor the names of its
 contributors may be used to endorse or promote products derived from
 this software without specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <llvm/IR/DataLayout.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/Intrinsics.h>

#include "mcsema/Arch/Dispatch.h"

#include "raiseX86.h"
#include "X86.h"


#include "JumpTables.h"

#include "x86Helpers.h"
#include "x86Instrs_fpu.h"
#include "x86Instrs_MOV.h"
#include "InstructionDispatch.h"
#include "x86Instrs_flagops.h"

// do any instruction preprocessing/conversion
// before moving on to translation.
// currently used to turn non-conforming jump talbles
// into data sections
//
static void PreProcessInst(TranslationContext &ctx, llvm::BasicBlock *&block) {
  auto ip = ctx.natI;
  auto &inst = ip->get_inst();
  // only add data sections for non-conformant jump tables
  //
  // the conformant tables are handled in the instruction
  // translator via switch()
  if (ip->has_jump_table()) {
    if (!isConformantJumpInst(ip)) {
      std::cerr
          << "WARNING: jump table but non-conformant instruction:" << std::endl
          << std::hex << ip->get_loc();

      VA tbl_va = 0;
      auto jmptbl = ip->get_jump_table();

      bool ok = addJumpTableDataSection(ctx, tbl_va, *jmptbl);

      TASSERT(ok, "Could not add jump table data section!\n");

      auto data_ref_va = static_cast<uint32_t>(tbl_va
          + (4 * jmptbl->getInitialEntry()));

      ip->set_reference(NativeInst::MEMRef, data_ref_va);
      ip->set_ref_type(NativeInst::MEMRef, NativeInst::CFGDataRef);
    }

  // only add data references for unknown jump index table reads
  } else if (ip->has_jump_index_table() &&
             inst.getOpcode() != llvm::X86::MOVZX32rm8) {

    VA idx_va = 0;
    JumpIndexTablePtr idxtbl = ip->get_jump_index_table();

    bool ok = addJumpIndexTableDataSection(ctx, idx_va, *idxtbl);

    TASSERT(ok, "Could not add jump index table data section!\n");

    uint32_t data_ref_va = static_cast<uint32_t>(idx_va
        + idxtbl->getInitialEntry());

    ip->set_reference(NativeInst::MEMRef, data_ref_va);
    ip->set_ref_type(NativeInst::MEMRef, NativeInst::CFGDataRef);
  }
}

// Take the supplied MCInst and turn it into a series of LLVM instructions.
// Insert those instructions into the supplied block.
// Here's the philosophy:
// LLVM MCInst opcodes encode X86 instructions by, roughly:
//
//    mnemonic[bitwidth]<operandlist>
//
//  So for example, there are many different encodings and bitwidths of the
//  "add" mnemonic. each combination has its own space in the opcodes enum
//
//  We're narrowing from the space of LLVM MCInst opcodes in a few steps:
//     1. First by width. we take each mnemonic and classify it by width.
//        there are templated functions for dealing with mnemonic / operand
//        pairs, parameterized around operand width
//     2. next by operand type. Within each parameterized wrapper, we
//        'unrwrap' by extracting each operand and producing input values
//        to the instructions
//     3. finally, in an inner step, we define the instruction semantics
//        entirely in terms of LLVM Value objects. This is where the 'meat'
//        of semantic modeling takes places.
//     The breakdown looks something like this:
//
//     X86::CMP8rr -> [1] -> doCmpRR<8> -> [2] doCmpVV<8> -> [3]
//
//     The innermost is where most of the intelligent decisions happen.
//
InstTransResult LiftInstIntoBlockImpl(TranslationContext &ctx,
                                      llvm::BasicBlock *&block) {
  InstTransResult itr = ContinueBlock;

  // For conditional instructions, get the "true" and "false" targets.
  // This will also look up the target for nonconditional jumps.
  //string trueStrName = "block_0x" + to_string<VA>(ip->get_tr(), hex);
  //string falseStrName = "block_0x" + to_string<VA>(ip->get_fa(), hex);

  auto &inst = ctx.natI->get_inst();

  if (auto lifter = ArchGetInstructionLifter(inst)) {
    PreProcessInst(ctx, block);
    itr = lifter(ctx, block);
    if (TranslateError == itr || TranslateErrorUnsupported == itr) {
      std::cerr << "Error translating instruction at " << std::hex
                << ctx.natI->get_loc() << std::endl;
    }

  // Instruction translation not defined.
  } else {
    auto opcode = inst.getOpcode();
    std::cerr << "Error translating instruction at " << std::hex
              << ctx.natI->get_loc() << "; unsupported opcode " << std::dec
              << opcode << std::endl;
    if (llvm::X86::REP_PREFIX != opcode && llvm::X86::REPNE_PREFIX != opcode) {
      itr = TranslateErrorUnsupported;
    } else {
      std::cerr
          << "Unsupported instruction is a rep/repne, trying to skip to next instr."
          << std::endl;
    }
  }
  return itr;
}
