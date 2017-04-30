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

#include <glog/logging.h>

#include <sstream>
#include <vector>

#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Type.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/InlineAsm.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Module.h>

#include "remill/Arch/Arch.h"
#include "remill/Arch/Name.h"
#include "remill/BC/ABI.h"
#include "remill/BC/Util.h"

#include "mcsema/Arch/Arch.h"
#include "mcsema/BC/Util.h"
#include "mcsema/BC/Callback.h"
#include "mcsema/CFG/CFG.h"

namespace mcsema {
namespace {

static llvm::Function *GetAttachCallFunc(void) {
  static llvm::Function *handler = nullptr;
  if (!handler) {
    auto void_type = llvm::Type::getVoidTy(*gContext);
    auto callback_type = llvm::FunctionType::get(void_type, false);
    handler = llvm::Function::Create(
        callback_type, llvm::GlobalValue::ExternalLinkage,
        "__mcsema_attach_call", gModule);
    handler->addFnAttr(llvm::Attribute::Naked);
  }
  return handler;
}

static llvm::Function *GetDetachCallValueFunc(void) {
  static llvm::Function *handler = nullptr;
  if (!handler) {
    handler = gModule->getFunction("__remill_function_call");
  }
  return handler;
}

// Exported functions, e.g. `main`, are implemented as a small thunk that
// writes the address of the lifted function to the `__mcsema_attach_target`
// thread-local variable. This is so that `__mcsema_attach_call` can figure
// out where to go.
static llvm::GlobalVariable *GetAttachTarget(void) {
  static llvm::GlobalVariable *target = nullptr;
  if (!target) {
    target = new llvm::GlobalVariable(
        *gModule, llvm::PointerType::get(LiftedFunctionType(), 0),
        false  /* IsConstant */, llvm::GlobalValue::ExternalLinkage,
        nullptr  /* Initializer */, "__mcsema_attach_target",
        nullptr  /* InsertBefore */, llvm::GlobalValue::InitialExecTLSModel,
        0  /* AddressSpace */, true  /* IsExternallyInitialized */);
  }
  return target;
}

// Exported functions, e.g. `main`, are implemented as a small thunk that
// writes the native address (as recorded in the CFG) of the lifted function
// to the `__mcsema_attach_target_address` thread-local variable. This is
// so that the right value can be passed in as the third argument (pc) to the
// lifted function.
static llvm::GlobalVariable *GetAttachTargetAddress(void) {
  static llvm::GlobalVariable *target = nullptr;
  if (!target) {
    auto word_type = llvm::Type::getIntNTy(
        *gContext, static_cast<unsigned>(gArch->address_size));

    target = new llvm::GlobalVariable(
        *gModule, word_type, false  /* IsConstant */,
        llvm::GlobalValue::ExternalLinkage, nullptr  /* Initializer */,
        "__mcsema_attach_target_address", nullptr  /* InsertBefore */,
        llvm::GlobalValue::InitialExecTLSModel, 0  /* AddressSpace */,
        true  /* IsExternallyInitialized */);
  }
  return target;
}

}  // namespace

// Get a callback function for an internal function.
llvm::Function *GetNativeToLiftedEntryPoint(const NativeObject *cfg_func) {
  CHECK(!cfg_func->is_external)
      << "Cannot get entry point thunk for external function "
      << cfg_func->name;

  auto callback_func = gModule->getFunction(cfg_func->name);
  if (callback_func) {
    return callback_func;
  }

  // If the native name of the function doesn't yet exist then add it in.
  auto void_type = llvm::Type::getVoidTy(*gContext);
  auto func = gModule->getFunction(cfg_func->lifted_name);
  CHECK(func != nullptr)
      << "Cannot find lifted function " << cfg_func->lifted_name;

  auto word_type = llvm::Type::getIntNTy(
      *gContext, static_cast<unsigned>(gArch->address_size));

  auto callback_type = llvm::FunctionType::get(void_type, false);
  callback_func = llvm::Function::Create(
      callback_type, llvm::GlobalValue::InternalLinkage,  // Tentative linkage.
      cfg_func->name, gModule);

  callback_func->setVisibility(llvm::GlobalValue::DefaultVisibility);
  callback_func->addFnAttr(llvm::Attribute::Naked);
  callback_func->addFnAttr(llvm::Attribute::NoInline);
  callback_func->addFnAttr(llvm::Attribute::NoBuiltin);

  llvm::IRBuilder<> ir(llvm::BasicBlock::Create(*gContext, "", callback_func));
  ir.CreateStore(func, GetAttachTarget());
  ir.CreateStore(llvm::ConstantInt::get(word_type, cfg_func->ea),
                 GetAttachTargetAddress());
  auto handler_call = ir.CreateCall(GetAttachCallFunc());
  handler_call->setTailCallKind(llvm::CallInst::TCK_MustTail);
  ir.CreateRetVoid();

  return callback_func;
}

// Get a callback function for an external function that can be referenced by
// internal code.
llvm::Function *GetLiftedToNativeExitPoint(const NativeObject *cfg_func) {
  CHECK(cfg_func->is_external)
      << "Cannot get exit point thunk for internal function "
      << cfg_func->name << " at " << std::hex << cfg_func->ea;

  CHECK(cfg_func->name != cfg_func->lifted_name);

  auto callback_func = gModule->getFunction(cfg_func->lifted_name);
  if (callback_func) {
    return callback_func;
  }

  auto func = gModule->getFunction(cfg_func->name);
  CHECK(func != nullptr)
      << "Cannot find declaration or definition for external function "
      << cfg_func->name;

  // Stub that will marshal lifted state into the native state.
  callback_func = llvm::Function::Create(
      LiftedFunctionType(), llvm::GlobalValue::InternalLinkage,
      cfg_func->lifted_name, gModule);
  callback_func->setCallingConv(llvm::CallingConv::Fast);
  callback_func->addFnAttr(llvm::Attribute::NoInline);

  auto word_type = llvm::Type::getIntNTy(
      *gContext, static_cast<unsigned>(gArch->address_size));
  auto block = llvm::BasicBlock::Create(*gContext, "", callback_func);

  // Pass through the memory and state pointers, and pass the destination
  // (native external function address) as the PC argument.
  llvm::IRBuilder<> ir(block);
  std::vector<llvm::Value *> args(3);
  args[remill::kMemoryPointerArgNum] = \
      remill::NthArgument(callback_func, remill::kMemoryPointerArgNum);
  args[remill::kStatePointerArgNum] = \
      remill::NthArgument(callback_func, remill::kStatePointerArgNum);
  args[remill::kPCArgNum] = ir.CreatePtrToInt(func, word_type);

  auto handler_call = ir.CreateCall(GetDetachCallValueFunc(), args);
  handler_call->setTailCall(true);
  ir.CreateRet(handler_call);

  return callback_func;
}

}  // namespace mcsema
