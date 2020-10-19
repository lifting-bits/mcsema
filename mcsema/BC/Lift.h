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

#include <memory>
#include <string>
#include <tuple>
#include <unordered_map>

#include "remill/Arch/Instruction.h"

namespace remill {
class InstructionLifter;
}  // namespace remill

namespace llvm {
class AllocaInst;
class Argument;
class BasicBlock;
class Function;
class Value;
}  // namespace llvm

namespace mcsema {

struct NativeModule;
struct NativeFunction;
struct NativeBlock;
struct NativeInstruction;
struct NativePreservedRegisters;

struct TranslationContext {
  TranslationContext(void);
  ~TranslationContext(void);

  remill::InstructionLifter *lifter = nullptr;
  const NativeModule *cfg_module = nullptr;
  const NativeFunction *cfg_func = nullptr;
  const NativeBlock *cfg_block = nullptr;
  const NativeInstruction *cfg_inst = nullptr;
  llvm::Function *lifted_func = nullptr;
  std::unordered_map<uint64_t, llvm::BasicBlock *> ea_to_block;
  std::unordered_map<uint64_t, llvm::BasicBlock *> lp_to_block;
  std::vector<std::pair<llvm::Value *, llvm::Value *>> preserved_regs;
  std::unordered_map<uint64_t, const NativePreservedRegisters *>
      func_preserved_regs;
  remill::Instruction inst;
  remill::Instruction delayed_inst;
  std::vector<std::tuple<uint64_t, bool, uint64_t>> work_list;

  llvm::BasicBlock *entry_block{nullptr};
  llvm::Value *stack_ptr_var{nullptr};
  llvm::Value *frame_ptr_var{nullptr};
  llvm::Argument *state_ptr{nullptr};
};

bool LiftCodeIntoModule(const NativeModule *cfg_module);

}  // namespace mcsema
