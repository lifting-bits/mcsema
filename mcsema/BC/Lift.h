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

#ifndef MCSEMA_BC_LIFT_H_
#define MCSEMA_BC_LIFT_H_

#include <unordered_map>

namespace remill {
class InstructionLifter;
}  // namespace remill

namespace llvm {
class BasicBlock;
class Function;
}  // namespace llvm

namespace mcsema {

struct NativeModule;
struct NativeFunction;
struct NativeBlock;
struct NativeInstruction;

struct TranslationContext {
  remill::InstructionLifter *lifter;
  const NativeModule *cfg_module;
  const NativeFunction *cfg_func;
  const NativeBlock *cfg_block;
  const NativeInstruction *cfg_inst;
  llvm::Function *lifted_func;
  std::unordered_map<uint64_t, llvm::BasicBlock *> ea_to_block;
};

bool LiftCodeIntoModule(const NativeModule *cfg_module);

}  // namespace mcsema

#endif  // MCSEMA_BC_LIFT_H_
