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
#include "mcsema/Arch/X86/Runtime/CallingConv.h"

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
    handler->addFnAttr(llvm::Attribute::Naked);
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
      asm_str << "pushq %rax;"
              << "movq $0, %rax;"
              << "xchgq (%rsp), %rax;"
              << "pushq %rax;"
              << "movq $1, %rax;"
              << "xchgq (%rsp), %rax;";
      break;

    case remill::kArchX86:
    case remill::kArchX86_AVX:
    case remill::kArchX86_AVX512:
      asm_str << "pushl %eax;"
              << "movl $0, %eax;"
              << "xchgl (%esp), %eax;"
              << "pushl %eax;"
              << "movl $1, %eax;"
              << "xchgl (%esp), %eax;";
      break;

    default:
      LOG(FATAL)
          << "Cannot create native-to-lifted callback for the "
          << GetArchName(gArch->arch_name) << " instruction set.";
      break;
  }

  auto void_type = llvm::Type::getVoidTy(*gContext);
  auto word_type = llvm::Type::getIntNTy(
      *gContext, static_cast<unsigned>(gArch->address_size));

  // Saves a reg on the stack.
  std::vector<llvm::Type *> param_types;
  param_types.push_back(llvm::PointerType::get(word_type, 0));
  param_types.push_back(param_types[0]);
  auto asm_func_type = llvm::FunctionType::get(void_type, param_types, false);
  auto asm_func = llvm::InlineAsm::get(
      asm_func_type, asm_str.str(), "*m,*m,~{dirflag},~{fpsr},~{flags}", true);

  auto callback_func = CreateGenericCallback(callback_name);
  llvm::IRBuilder<> ir(llvm::BasicBlock::Create(*gContext, "", callback_func));

  std::vector<llvm::Value *> asm_args;
  asm_args.push_back(new llvm::GlobalVariable(
      *gModule, word_type, true, llvm::GlobalValue::InternalLinkage,
      llvm::ConstantExpr::getPtrToInt(func, word_type)));

  asm_args.push_back(new llvm::GlobalVariable(
      *gModule, word_type, true, llvm::GlobalValue::InternalLinkage,
      llvm::ConstantInt::get(word_type, cfg_func->ea)));

  ir.CreateCall(asm_func, asm_args);

  auto handler_call = ir.CreateCall(GetAttachCallFunc());
  handler_call->setTailCall(true);
  ir.CreateRetVoid();

  AnnotateInsts(callback_func, cfg_func->ea);

  return callback_func;
}

static void AddArgNForCConv(llvm::IRBuilder<> *ir, int64_t n, llvm::CallingConv::ID cc, llvm::Function *callback_func) {
    
    std::vector<llvm::Type *> tys;
    tys.push_back(llvm::PointerType::getIntNPtrTy(*gContext, static_cast<unsigned>(gArch->address_size)));
    tys.push_back(llvm::PointerType::getIntNPtrTy(*gContext, static_cast<unsigned>(gArch->address_size)));
    auto func_type = llvm::FunctionType::get(llvm::Type::getVoidTy(*gContext), tys, true);
 
    std::string cc_str = "";
    switch(cc) {
      case (NativeExternalFunction::CallerCleanup):
        cc_str = "cdecl";
        break;
      case (NativeExternalFunction::CalleeCleanup):
        cc_str = "stdcall";
        break;
      case (NativeExternalFunction::FastCall):
        cc_str = "fastcall";
        break;
      case (NativeExternalFunction::McsemaCall):
        cc_str = "mcsemacall";
        break;
      default:
        LOG(WARNING) << "trying to get calling conv number " << cc << "\n";
        cc_str = "cdecl"; // XXX(car): just for testing; fix
        break;
    }
    CHECK(!cc_str.empty()) << "Unknown calling convention for function: " << cc << "\n";

    std::stringstream arg_tmp;
    arg_tmp << "__mcsema_" << cc_str << "_arg_" << n;
    std::string arg_func = arg_tmp.str(); 

    LOG(ERROR) << "trying to get " << arg_func << "\n";

    auto f = gModule->getOrInsertFunction(arg_func, func_type);
    std::vector<llvm::Value *> args(2);
    args[0] = remill::NthArgument(callback_func, remill::kMemoryPointerArgNum);
    args[1] = remill::NthArgument(callback_func, remill::kStatePointerArgNum);
    auto ret = ir->CreateCall(f, args);

    ir->CreateStore(ret, remill::NthArgument(callback_func, remill::kMemoryPointerArgNum)); // XXX progress this according to cconv?
    
    return;
}

static llvm::Function *GetCallbackExplicitArgs(
    const NativeObject *cfg_func, const std::string callback_name) {
    // TODO(car): Pull this out into its own function, and add in calling
    //            convention-specific code to pass in arguments. May need
    //            to declare and/or cast the exernal functions as something
    //            like `addr_t foo(...)`.
    auto callback_func = CreateGenericCallback(callback_name);
    llvm::IRBuilder<> ir(llvm::BasicBlock::Create(*gContext, "", callback_func));

    if(auto native_func = reinterpret_cast<const NativeExternalFunction *>(cfg_func)) {
      
      for(int64_t i = 0; i < native_func->num_args; i++) {
        AddArgNForCConv(&ir, i, native_func->cc, callback_func);
      }
    }
    //TODO(car): set calling conv appropriately
    callback_func->setCallingConv(llvm::CallingConv::C);
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

  if (FLAGS_explicit_args) {
    auto callback_func = GetCallbackExplicitArgs(cfg_func, callback_name);
    callback_func->setLinkage(llvm::GlobalValue::ExternalLinkage);
    return callback_func;

  } else {
    return GetNativeToLiftedCallback(cfg_func, callback_name);
  }
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

  AnnotateInsts(callback_func, cfg_func->ea);

  return callback_func;
}

}  // namespace mcsema
