/*
Copyright (c) 2017, Trail of Bits
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

  Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

  Redistributions in binary form must reproduce the above copyright notice, this
  list of conditions and the following disclaimer in the documentation and/or
  other materials provided with the distribution.

  Neither the name of the organization nor the names of its
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

#ifndef MCSEMA_BC_INSTRUCTION_H_
#define MCSEMA_BC_INSTRUCTION_H_

#include <cstdint>

#include "remill/Arch/Instruction.h"
#include "remill/BC/Lifter.h"

namespace llvm {
class BasicBlock;
class IntegerType;
class Type;
class Value;
}  // namespace llvm

namespace remill {
class IntrinsicTable;
}  // namespace remill

namespace mcsema {

struct NativeXref;
struct TranslationContext;

class InstructionLifter : public remill::InstructionLifter {
 public:
  InstructionLifter(llvm::IntegerType *word_type_,
                    const remill::IntrinsicTable *intrinsics_,
                    TranslationContext &ctx_);

  virtual ~InstructionLifter(void);

  // Lift a single instruction into a basic block.
  bool LiftIntoBlock(remill::Instruction *instr,
                     llvm::BasicBlock *block) override;

 protected:

  // Lift an immediate operand.
  llvm::Value *LiftImmediateOperand(
      remill::Instruction *instr, llvm::BasicBlock *block,
      llvm::Type *arg_type, remill::Operand &op) override;

  // Lift an indirect memory operand to a value.
  llvm::Value *LiftAddressOperand(
      remill::Instruction *instr, llvm::BasicBlock *block,
      remill::Operand &mem) override;

 private:

  llvm::Value *GetAddress(const NativeXref *cfg_xref);

  TranslationContext &ctx;

  remill::Instruction *instr;
  llvm::BasicBlock *block;

  llvm::Value *mem_ref;
  llvm::Value *disp_ref;
  llvm::Value *imm_ref;
};

}  // namespace mcsema

#endif  // MCSEMA_BC_INSTRUCTION_H_
