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

#ifndef MCSEMA_ARCH_ABI_H_
#define MCSEMA_ARCH_ABI_H_

#include <cstdint>

#include <llvm/IR/CallingConv.h>

namespace llvm {
class Type;
}  // namespace llvm
namespace mcsema {

struct ArgConstraint;

class ArgLoader {
 public:
  explicit ArgLoader(llvm::CallingConv::ID cc_);

  llvm::Value *LoadNextArgument(llvm::BasicBlock *block, llvm::Type *goal_type);

  void StoreReturnValue(llvm::BasicBlock *block, llvm::Value *ret_val);

 private:
  llvm::CallingConv::ID cc;
  uint64_t used_reg_bitmap;
  uint64_t num_loaded_stack_bytes;
  const char * const sp_name;
  const ArgConstraint *reg_table;

  ArgLoader(void) = delete;
};



}  // namespace mcsema

#endif  // MCSEMA_ARCH_ABI_H_
