/*
 * Copyright (c) 2020 Trail of Bits, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

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

struct NativeInstructionXref;
struct TranslationContext;

class InstructionLifter : public remill::InstructionLifter {
 public:
  InstructionLifter(const remill::IntrinsicTable *intrinsics_,
                    TranslationContext &ctx_);

  virtual ~InstructionLifter(void);

  // Lift a single instruction into a basic block.
  remill::LiftStatus
  LiftIntoBlock(remill::Instruction &inst, llvm::BasicBlock *block,
                llvm::Value *state_ptr, bool is_delayed) override;

 protected:
  // Lift an immediate operand.
  llvm::Value *
  LiftImmediateOperand(remill::Instruction &inst, llvm::BasicBlock *block,
                       llvm::Argument *arg, remill::Operand &op) override;

  // Lift an indirect memory operand to a value.
  llvm::Value *LiftAddressOperand(remill::Instruction &inst,
                                  llvm::BasicBlock *block,
                                  llvm::Value *state_ptr, llvm::Argument *arg,
                                  remill::Operand &mem) override;

 private:
  llvm::Value *GetAddress(const NativeInstructionXref *cfg_xref);

  TranslationContext &ctx;

  remill::Instruction *inst_ptr{nullptr};
  llvm::BasicBlock *block{nullptr};

  llvm::Value *mem_ref{nullptr};
  llvm::Value *disp_ref{nullptr};
  llvm::Value *imm_ref{nullptr};

  bool mem_ref_used{false};
  bool disp_ref_used{false};
  bool imm_ref_used{false};
};

}  // namespace mcsema
