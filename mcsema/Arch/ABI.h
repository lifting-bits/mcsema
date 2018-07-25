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
#include <vector>

#include "remill/BC/Compat/CallingConvention.h"

namespace llvm {
class Type;
}  // namespace llvm
namespace mcsema {

struct ArgConstraint {
  std::string var_name;
  const int accepted_val_kinds;
};

// Generic functions for reading/writing to the register/stack state in a way
// that respects a supplied calling convention.
class CallingConvention {
 public:
  explicit CallingConvention(llvm::CallingConv::ID cc_);

  llvm::Value *LoadNextArgument(llvm::BasicBlock *block,
                                llvm::Type *goal_type=nullptr,
                                bool is_byval=false);

  void StoreReturnValue(llvm::BasicBlock *block, llvm::Value *ret_val);

  void StoreArguments(llvm::BasicBlock *block,
                      const std::vector<llvm::Value *> &arg_vals);

  void FreeArguments(llvm::BasicBlock *block);

  void AllocateReturnAddress(llvm::BasicBlock *block);
  void FreeReturnAddress(llvm::BasicBlock *block);

  llvm::Value *LoadReturnValue(llvm::BasicBlock *block,
                               llvm::Type *goal_type=nullptr);

  llvm::Value *LoadStackPointer(llvm::BasicBlock *block);

  void StoreStackPointer(llvm::BasicBlock *block, llvm::Value *new_val);

  const char *StackPointerVarName(void) const {
    return sp_name;
  }

  void StoreThreadPointer(llvm::BasicBlock *block, llvm::Value *new_val);

  const char *ThreadPointerVarName(void) const {
    return tp_name;
  }

 private:
  void StoreVectorRetValue(llvm::BasicBlock *block,
                           llvm::Value *ret_val,
                           llvm::VectorType *goal_type);

  llvm::Value *LoadVectorArgument(llvm::BasicBlock *block,
                                  llvm::VectorType *goal_type);
  llvm::Value *LoadNextSimpleArgument(llvm::BasicBlock *block,
                                      llvm::Type *goal_type);

  const char *GetVarForNextArgument(llvm::Type *val_type);
  const char *GetVarForNextReturn(llvm::Type *val_type);

  llvm::CallingConv::ID cc;
  uint64_t used_reg_bitmap;
  uint64_t used_return_bitmap;
  uint64_t num_loaded_stack_bytes;
  uint64_t num_stored_stack_bytes;
  const char * const sp_name;
  const char * const tp_name;
  const std::vector<ArgConstraint> &reg_table;
  const std::vector<ArgConstraint> &return_table;
  CallingConvention(void) = delete;
};

// Return the address of the base of the TLS data.
llvm::Value *GetTLSBaseAddress(llvm::IRBuilder<> &ir);

}  // namespace mcsema

#endif  // MCSEMA_ARCH_ABI_H_
