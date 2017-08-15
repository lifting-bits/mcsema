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
#include <gflags/gflags.h>

#include <sstream>
#include <string>
#include <vector>

#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Type.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/InlineAsm.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Module.h>

#include "remill/Arch/Arch.h"
#include "remill/Arch/Name.h"
#include "remill/BC/ABI.h"
#include "remill/BC/Util.h"

#include "mcsema/Arch/ABI.h"
#include "mcsema/Arch/Arch.h"
#include "mcsema/BC/Util.h"
#include "mcsema/BC/Callback.h"
#include "mcsema/CFG/CFG.h"

DEFINE_bool(explicit_args, false,
            "Should arguments be explicitly passed to external functions. "
            "This can be good for static analysis and symbolic execution, "
            "but in practice it precludes the possibility of compiling "
            "and running the bitcode.");

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
//    handler->addFnAttr(llvm::Attribute::Naked);
    handler->addFnAttr(llvm::Attribute::NoInline);
    handler->setCallingConv(llvm::CallingConv::Fast);
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

static llvm::Function *CreateGenericCallback(const std::string &callback_name) {
  auto void_type = llvm::Type::getVoidTy(*gContext);
  auto callback_type = llvm::FunctionType::get(void_type, false);

  auto callback_func = llvm::Function::Create(
      callback_type, llvm::GlobalValue::InternalLinkage,  // Tentative linkage.
      callback_name, gModule);

  callback_func->setVisibility(llvm::GlobalValue::DefaultVisibility);
  callback_func->setCallingConv(llvm::CallingConv::Fast);
  callback_func->addFnAttr(llvm::Attribute::Naked);
  callback_func->addFnAttr(llvm::Attribute::NoInline);
  callback_func->addFnAttr(llvm::Attribute::NoBuiltin);

  return callback_func;
}

// Get a callback function for an internal function.
static llvm::Function *GetNativeToLiftedCallback(
    const NativeObject *cfg_func, const std::string &callback_name) {

  // If the native name of the function doesn't yet exist then add it in.
  auto func = gModule->getFunction(cfg_func->lifted_name);
  CHECK(func != nullptr)
      << "Cannot find lifted function " << cfg_func->lifted_name;

  auto attach_func = GetAttachCallFunc();

  std::stringstream asm_str;
  switch (gArch->arch_name) {
    case remill::kArchInvalid:
      LOG(FATAL)
          << "Cannot generate native-to-lifted entrypoint thunk for "
          << "unknown architecture.";
      break;
    case remill::kArchAMD64:
    case remill::kArchAMD64_AVX:
    case remill::kArchAMD64_AVX512:
      asm_str << "pushq $0;";
      if (static_cast<uint32_t>(cfg_func->ea) == cfg_func->ea) {
        asm_str << "pushq $$0x" << std::hex << cfg_func->ea << ";";
      } else {
        asm_str << "pushq %rax;"
                << "movq $$0x" << std::hex << cfg_func->ea << ", %rax;"
                << "xchgq (%rsp), %rax;";
      }
      asm_str << "jmpq *$1;";
      break;

    case remill::kArchX86:
    case remill::kArchX86_AVX:
    case remill::kArchX86_AVX512:
      asm_str << "pushl $0;"
              << "pushl $$0x" << std::hex << cfg_func->ea << ";"
              << "jmpl *$1;";
      break;

    case remill::kArchAArch64LittleEndian:
      LOG(ERROR)
          << "TODO: Create a native-to-lifted callback for the "
          << GetArchName(gArch->arch_name) << " instruction set.";
      asm_str << "nop;";
      break;

    default:
      LOG(FATAL)
          << "Cannot create native-to-lifted callback for the "
          << GetArchName(gArch->arch_name) << " instruction set.";
      break;
  }

  auto void_type = llvm::Type::getVoidTy(*gContext);

  std::vector<llvm::Type *> param_types;
  param_types.push_back(llvm::PointerType::get(func->getType(), 0));
  param_types.push_back(llvm::PointerType::get(attach_func->getType(), 0));

  auto asm_func_type = llvm::FunctionType::get(void_type, param_types, false);
  auto asm_func = llvm::InlineAsm::get(
      asm_func_type, asm_str.str(), "*m,*m,~{dirflag},~{fpsr},~{flags}", true);

  auto callback_func = CreateGenericCallback(callback_name);
  llvm::IRBuilder<> ir(llvm::BasicBlock::Create(*gContext, "", callback_func));

  std::vector<llvm::Value *> asm_args;
  asm_args.push_back(new llvm::GlobalVariable(
      *gModule, func->getType(), true, llvm::GlobalValue::InternalLinkage,
      func));

  asm_args.push_back(new llvm::GlobalVariable(
      *gModule, attach_func->getType(), true,
      llvm::GlobalValue::InternalLinkage, attach_func));

  auto asm_call = ir.CreateCall(asm_func, asm_args);
  asm_call->setTailCall(true);
  ir.CreateRetVoid();

  AnnotateInsts(callback_func, cfg_func->ea);

  return callback_func;
}

static llvm::Function *GetCallback(
    const NativeObject *cfg_func, const std::string callback_name) {

  CHECK(!cfg_func->is_external)
      << "Cannot get entry point thunk for external function "
      << cfg_func->name;

  auto callback_func = gModule->getFunction(callback_name);
  if (callback_func) {
    return callback_func;
  }

  return GetNativeToLiftedCallback(cfg_func, callback_name);
}

// Implements a stub for an externally defined function in such a way that,
// when executed, this stub redirects control flow into the actual external
// function.
static void ImplementLiftedToNativeCallback(
    llvm::Function *callback_func, llvm::Function *extern_func,
    const NativeExternalFunction *cfg_func) {

  callback_func->addFnAttr(llvm::Attribute::NoInline);
  auto word_type = llvm::Type::getIntNTy(
      *gContext, static_cast<unsigned>(gArch->address_size));

  auto block = llvm::BasicBlock::Create(*gContext, "", callback_func);

  // The third argument of lifted functions (including things like
  // `__remill_function_call`) is the program counter. Make sure that
  // the "real" address of the external is passed in as that third argument
  // because it's likely that whatever was in the CFG makes no sense
  // in the lifted code.
  auto args = remill::LiftedFunctionArgs(block);
  args[remill::kPCArgNum] = llvm::ConstantExpr::getPtrToInt(
      extern_func, word_type);

  llvm::IRBuilder<> ir(block);
  auto handler_call = ir.CreateCall(GetDetachCallValueFunc(), args);
  handler_call->setTailCall(true);
  ir.CreateRet(handler_call);
}

// Implements a stub for an externally defined function in such a way that
// the external is explicitly called, and arguments from the modeled CPU
// state are passed into the external.
static void ImplementExplicitArgsCallback(
    llvm::Function *callback_func, llvm::Function *extern_func,
    const NativeExternalFunction *cfg_func) {

  remill::CloneBlockFunctionInto(callback_func);

  // Always inline so that static analyses of the bitcode don't need to dive
  // into an extra function just to see the intended call.
  callback_func->removeFnAttr(llvm::Attribute::NoInline);
  callback_func->addFnAttr(llvm::Attribute::InlineHint);
  callback_func->addFnAttr(llvm::Attribute::AlwaysInline);

  LOG(INFO)
      << "Generating " << cfg_func->num_args
      << " argument getters in function "
      << cfg_func->lifted_name << " for external " << cfg_func->name;

  auto func_type = extern_func->getFunctionType();
  auto num_params = func_type->getNumParams();
  ArgLoader loader(cfg_func->cc);

  if (num_params != cfg_func->num_args) {
    CHECK(num_params < cfg_func->num_args && func_type->isVarArg())
        << "Function " << remill::LLVMThingToString(extern_func)
        << " is expected to be able to take " << cfg_func->num_args
        << " arguments.";
  }

  auto block = &(callback_func->back());

  // create call to function and args
  std::vector<llvm::Value *> call_args;
  for (auto i = 0U; i < cfg_func->num_args; i++) {
    llvm::Type *param_type = nullptr;
    if (i < num_params) {
      param_type = func_type->getParamType(i);
    }
    call_args.push_back(loader.LoadNextArgument(block, param_type));
  }

  llvm::IRBuilder<> ir(block);
  loader.StoreReturnValue(block, ir.CreateCall(extern_func, call_args));

  ir.CreateRet(remill::LoadMemoryPointer(block));
}

}  // namespace

// Get a callback function for an internal function that can be referenced by
// internal code.
llvm::Function *GetNativeToLiftedCallback(const NativeObject *cfg_func) {
  std::stringstream ss;
  ss << "callback_" << cfg_func->lifted_name;
  return GetCallback(cfg_func, ss.str());
}

// Get a callback function for an internal function.
llvm::Function *GetNativeToLiftedEntryPoint(const NativeObject *cfg_func) {
  return GetCallback(cfg_func, cfg_func->name);
}

// Get a callback function for an external function that can be referenced by
// internal code.
llvm::Function *GetLiftedToNativeExitPoint(const NativeObject *cfg_func_) {
  CHECK(cfg_func_->is_external)
      << "Cannot get exit point thunk for internal function "
      << cfg_func_->name << " at " << std::hex << cfg_func_->ea;

  auto cfg_func = reinterpret_cast<const NativeExternalFunction *>(cfg_func_);
  CHECK(cfg_func->name != cfg_func->lifted_name);

  auto callback_func = gModule->getFunction(cfg_func->lifted_name);
  if (callback_func) {
    return callback_func;
  }

  auto extern_func = gModule->getFunction(cfg_func->name);
  CHECK(extern_func != nullptr)
      << "Cannot find declaration or definition for external function "
      << cfg_func->name;

  // Stub that will marshal lifted state into the native state.
  callback_func = llvm::Function::Create(LiftedFunctionType(),
                                         llvm::GlobalValue::InternalLinkage,
                                         cfg_func->lifted_name, gModule);
  callback_func->setCallingConv(llvm::CallingConv::Fast);


  // Pass through the memory and state pointers, and pass the destination
  // (native external function address) as the PC argument.
  if (FLAGS_explicit_args) {
    ImplementExplicitArgsCallback(callback_func, extern_func, cfg_func);

  // We are going from lifted to native code. We don't need an assembly stub
  // because `__remill_function_call` already does the right thing.
  } else {
    ImplementLiftedToNativeCallback(callback_func, extern_func, cfg_func);
  }

  AnnotateInsts(callback_func, cfg_func->ea);

  return callback_func;
}

}  // namespace mcsema
