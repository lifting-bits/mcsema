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

#include <llvm/IR/IRBuilder.h>

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

extern llvm::Constant *gZero;
extern uint64_t gWordMask;

llvm::Value *GetConstantInt(unsigned size, uint64_t value);

// Get a lifted representation of a reference (in code) to `ea`.
llvm::Constant *LiftXrefInCode(uint64_t ea);

// Get a lifted representation of a reference (in data) to `ea`.
llvm::Constant *LiftXrefInData(const NativeSegment *cfg_seg, uint64_t ea,
                               bool cast_to_int = true);

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

// Create a global register state pointer to pass to lifted functions.
llvm::Constant *GetStatePointer(void);

// Return the address of the base of the TLS data.
llvm::Value *GetTLSBaseAddress(llvm::IRBuilder<> &ir);

}  // namespace mcsema
