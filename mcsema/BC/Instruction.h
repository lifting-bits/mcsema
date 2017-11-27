/*
 * Copyright (c) 2017 Trail of Bits, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef MCSEMA_BC_INSTRUCTION_H_
#define MCSEMA_BC_INSTRUCTION_H_

#include <cstdint>

#include "remill/Arch/Instruction.h"
#include "remill/BC/Lifter.h"

namespace llvm {
class Argument;
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
  InstructionLifter(const remill::IntrinsicTable *intrinsics_,
                    TranslationContext &ctx_);

  virtual ~InstructionLifter(void);

  // Lift a single instruction into a basic block.
  remill::LiftStatus LiftIntoBlock(remill::Instruction &inst,
                                   llvm::BasicBlock *block) override;

 protected:

  // Lift an immediate operand.
  llvm::Value *LiftImmediateOperand(
      remill::Instruction &inst, llvm::BasicBlock *block,
      llvm::Argument *arg, remill::Operand &op) override;

  // Lift an indirect memory operand to a value.
  llvm::Value *LiftAddressOperand(
      remill::Instruction &inst, llvm::BasicBlock *block,
      llvm::Argument *arg, remill::Operand &mem) override;

  // Lift a register operand to a value.
  llvm::Value *LiftRegisterOperand(
      remill::Instruction &inst, llvm::BasicBlock *block,
      llvm::Argument *arg, remill::Operand &reg) override;

 private:

  llvm::Value *GetAddress(const NativeXref *cfg_xref);
  llvm::Value *GetMaskedAddress(const NativeXref *cfg_xref);

  TranslationContext &ctx;

  remill::Instruction *inst_ptr;
  llvm::BasicBlock *block;

  llvm::Value *mem_ref;
  llvm::Value *disp_ref;
  llvm::Value *imm_ref;

  bool mem_ref_used;
  bool disp_ref_used;
  bool imm_ref_used;
};

}  // namespace mcsema

#endif  // MCSEMA_BC_INSTRUCTION_H_
