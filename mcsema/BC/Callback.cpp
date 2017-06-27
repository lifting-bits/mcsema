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

static llvm::Instruction *GetArgNForCConv(llvm::IRBuilder<> *ir, int64_t n, const NativeExternalFunction *native_func, llvm::Function *callback_func) {

  // TODO(car/artem): put this in its own "getArgExtractionType()" function
    auto addr_type = llvm::Type::getIntNTy(*gContext, static_cast<unsigned>(gArch->address_size));
    std::vector<llvm::Type *> tys;
    auto arg0type = remill::NthArgument(callback_func, remill::kMemoryPointerArgNum)->getType();
    auto arg1type = remill::NthArgument(callback_func, remill::kStatePointerArgNum)->getType();
    tys.push_back(arg0type);
    tys.push_back(arg1type);
    auto func_type = llvm::FunctionType::get(addr_type, tys, false);

    std::string cc_str = "";
    switch(native_func->cc) {
      case (NativeExternalFunction::calling_conv::CallerCleanup):
        cc_str = "cdecl";
        break;
      case (NativeExternalFunction::calling_conv::CalleeCleanup):
        cc_str = "stdcall";
        break;
      case (NativeExternalFunction::calling_conv::FastCall):
        cc_str = "fastcc";
        break;
      case (NativeExternalFunction::calling_conv::McsemaCall):
        cc_str = "mcsemacall";
        break;
      case (NativeExternalFunction::calling_conv::Unknown):
        // fallthrough
      default:
        LOG(WARNING) << "Function " << native_func->lifted_name << " has unknown calling convention! Processing as cdecl...\n";
        cc_str = "cdecl";
        break;
    }
    
    std::stringstream arg_tmp;
    arg_tmp << "__mcsema_" << cc_str << "_arg_" << n;
    std::string arg_func = arg_tmp.str(); 

    auto f = gModule->getOrInsertFunction(arg_func, func_type);
    CHECK(f) << "Unable to find function " << arg_func << "\n";

    if(llvm::Function *func = reinterpret_cast<llvm::Function *>(f)) {
      func->setLinkage(llvm::Function::ExternalLinkage);
      std::vector<llvm::Value *> args(2);
      args[0] = remill::NthArgument(callback_func, remill::kMemoryPointerArgNum);
      args[1] = remill::NthArgument(callback_func, remill::kStatePointerArgNum);
      auto ret = ir->CreateCall(func, args);
      return ret;
    }
    else {
      CHECK(func) << "getOrInsertFunction() returned non-function\n";
    }
    return nullptr; // shouldn't reach
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

static llvm::Function *getExplicitArgsFunction(const NativeExternalFunction *nf) {
    std::stringstream ss;
    //ss << "_" << nf->name;
    ss << nf->name;
    std::string external_name(ss.str());

    // check if this external function has previously been called
    auto extfun = gModule->getFunction(external_name);

    if(nullptr == extfun) {
        // it hasn't, create a prototype of:
        // uintN_t *_external(uintN_t *arg0, uintN_t *arg1, ...);
        auto ptrtype = llvm::Type::getIntNTy(*gContext, static_cast<unsigned>(gArch->address_size));
        std::vector<llvm::Type *> tys;
        for(int i = 0; i < nf->num_args; i++) {
            tys.push_back(ptrtype);
        }
        // TODO: set calling convention
        auto extcall_type = llvm::FunctionType::get(ptrtype, tys, false);
        extfun = llvm::Function::Create(
                extcall_type, llvm::GlobalValue::ExternalLinkage,
                external_name, gModule);
    }

    return extfun;
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

      if (FLAGS_explicit_args) {

          if(auto native_func = reinterpret_cast<const NativeExternalFunction *>(cfg_func)) {
              LOG(INFO) << "Generating " << native_func->num_args << " args for function " << native_func->lifted_name << "\n";

              // Call something to check if "_" + native_func->name exists in the binary
              // if not, create a function named "_" + native_func->name with:
              //    cconv of native_func->cc
              //    arg count of native_func->arg_count
              // if yes, return pointer to function
              //
              switch(native_func->cc) {
                  case (NativeExternalFunction::calling_conv::CallerCleanup):
                      callback_func->setCallingConv(llvm::CallingConv::C);
                      break;
                  case (NativeExternalFunction::calling_conv::CalleeCleanup):
                      callback_func->setCallingConv(llvm::CallingConv::X86_StdCall);
                      break;
                  case (NativeExternalFunction::calling_conv::FastCall):
                      callback_func->setCallingConv(llvm::CallingConv::X86_FastCall);
                      break;
                  case (NativeExternalFunction::calling_conv::McsemaCall):
                      // fallthrough
                  case (NativeExternalFunction::calling_conv::Unknown):
                      // fallthrough
                  default:
                      LOG(ERROR) << "Function " << native_func->lifted_name << " has unknown calling convention! Processing as cdecl...\n";
                      callback_func->setCallingConv(llvm::CallingConv::C);
              }
              // create call to function and args
              std::vector<llvm::Value *> args;
              for(int64_t i = 0; i < native_func->num_args; i++) {
                  args.push_back(GetArgNForCConv(&ir, i, native_func, callback_func));
              }
              //auto arg_ret =
              // TODO(car): stash return in rax
              ir.CreateCall(getExplicitArgsFunction(native_func), args);
          }
          // need to return a struct memory*
          ir.CreateRet(remill::NthArgument(callback_func, remill::kMemoryPointerArgNum));
      } else {

          std::vector<llvm::Value *> args(3);
          args[remill::kMemoryPointerArgNum] = \
                                               remill::NthArgument(callback_func, remill::kMemoryPointerArgNum);
          args[remill::kStatePointerArgNum] = \
                                              remill::NthArgument(callback_func, remill::kStatePointerArgNum);
          args[remill::kPCArgNum] = ir.CreatePtrToInt(func, word_type);

          auto handler_call = ir.CreateCall(GetDetachCallValueFunc(), args);
          handler_call->setTailCall(true);
          ir.CreateRet(handler_call);
      }

      AnnotateInsts(callback_func, cfg_func->ea);

      return callback_func;
}

}  // namespace mcsema
