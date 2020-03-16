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

#ifndef MCSEMA_BC_UTIL_H_
#define MCSEMA_BC_UTIL_H_

#include <cstdint>
#include <list>
#include <optional>
#include <vector>

#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Module.h>

#include "mcsema/CFG/CFG.h"

#include "remill/BC/Annotate.h"

namespace llvm {

class BasicBlock;
class Constant;
class ConstantInt;
class Instruction;
class IntegerType;
class LLVMContext;
class Module;

}  // namespace llvm
namespace mcsema {

struct NativeSegment;

extern std::shared_ptr<llvm::LLVMContext> gContext;
extern llvm::IntegerType *gWordType;
extern std::unique_ptr<llvm::Module> gModule;

template <typename Self>
struct LLVMConstants {

  llvm::ConstantInt *i32(int32_t value) {
    return GetConstantInt(value, 32);
  }

  llvm::ConstantInt *i64(int64_t value) {
    return GetConstantInt(value, 64);
  }

  llvm::ConstantInt *GetConstantInt(int64_t value, int64_t size) {
    return llvm::ConstantInt::get(
        llvm::Type::getIntNTy(static_cast<Self &>(*this).context, size), value);
  }

  llvm::Type *i64_t() {
    return llvm::Type::getInt64Ty(static_cast<Self &>(*this).context);
  }

  llvm::Type *i64_ptr_t() {
    return llvm::Type::getInt64PtrTy(static_cast<Self &>(*this).context);
  }

  llvm::Type *i_n_ptr_t(uint64_t size) {
    return llvm::Type::getIntNPtrTy(static_cast<Self &>(*this).context, size);
  }

  llvm::Type *i8_t() {
    return llvm::Type::getInt8Ty(static_cast<Self &>(*this).context);
  }

  llvm::Type *i8_ptr_t() {
    return llvm::Type::getInt8PtrTy(static_cast<Self &>(*this).context);
  }

  llvm::Type *i_n_ty(uint64_t size) {
    return llvm::Type::getIntNTy(static_cast<Self &>(*this).context, size);
  }

  llvm::Value *undef(llvm::Type *type) {
    return llvm::UndefValue::get(type);
  }

  llvm::Type *ptr(llvm::Type *type, unsigned addr_space=0) {
    return llvm::PointerType::get(type, addr_space);
  }

};

template<typename Self>
struct ModuleUtil {
  llvm::Function &function(const std::string &name) {
    return *static_cast<Self &>(*this).module.getFunction(name);
  }
};

llvm::Value *GetConstantInt(unsigned size, uint64_t value);

// Return the type of a lifted function.
llvm::FunctionType *LiftedFunctionType(void);

// Translate `ea` into an LLVM value that is an address that points into the
// lifted segment associated with `seg`.
llvm::Constant *LiftEA(const NativeSegment *seg, uint64_t ea);

template<typename Yield>
void ForEachLifted(llvm::Module &_module, Yield yield) {
  using funcs = std::vector<llvm::Function *>;
  for (auto f : remill::GetFunctionsByOrigin<funcs, remill::LiftedFunction>(_module)) {
    yield(f);
  }
}

using MetaValue = std::optional<std::string>;

void SetMetadata(llvm::GlobalObject &go, const std::string &kind, const std::string &val);
MetaValue GetMetadata(llvm::GlobalObject &go, const std::string &kind);

}  // namespace mcsema

#endif  // MCSEMA_BC_UTIL_H_
