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

static const char *GetCallingConvName(
    const NativeExternalFunction *native_func) {
  switch (native_func->cc) {
    case llvm::CallingConv::X86_64_SysV:
      return "amd64_sysv";
    case llvm::CallingConv::X86_64_Win64:
      return "amd64_win64";
    case llvm::CallingConv::X86_StdCall:
      return "stdcall";
    case llvm::CallingConv::X86_FastCall:
      return "fastcall";
    case llvm::CallingConv::C:
      return gArch->IsX86() ? "cdecl" : "c";
    default:
      LOG(FATAL)
          << "Invalid calling convention for function " << native_func->name;
      return nullptr;
  }
}

// Returns a declaration of a function that can be used to take a return
// value from an external function, and store it into the write place in
// the emulated program's register/memory state. This function is then used
// as follows:
//
//    int len = strlen(...);
//    memory = __mcsema_cdecl_ret(memory, state, len);
//
// Where this function writes `len` into the correct place for the `cdecl`
// calling convention.
static llvm::Function *GetOrCreateRetValSetter(const char *calling_conv) {
  std::stringstream arg_tmp;
  arg_tmp << "__mcsema_" << calling_conv << "_ret";
  std::string arg_func = arg_tmp.str();

  auto f = gModule->getFunction(arg_func);
  if (f) {
    return f;
  }

  auto addr_type = remill::AddressType(gModule);
  auto mem_ptr_type = remill::MemoryPointerType(gModule);

  std::vector<llvm::Type *> tys;
  tys.push_back(mem_ptr_type);
  tys.push_back(remill::StatePointerType(gModule));
  tys.push_back(addr_type);
  auto func_type = llvm::FunctionType::get(mem_ptr_type, tys, false);

  f = llvm::Function::Create(
      func_type, llvm::GlobalValue::ExternalLinkage, arg_func, gModule);
  f->setCallingConv(llvm::CallingConv::Fast);
  return f;
}

// Returns a declaration of a function that can get the value of a function
// argument for a given calling convention. For example, this will return the
// declaration of a function like `__mcsema_cdecl_arg_1`, which can be used
// as follows:
//
//    uintptr_t str = __mcsema_cdecl_arg_1(memory, state);
//    ...
//    strlen(str);
//
// Where the `__mcsema_cdecl_arg_1` function knows how to find the logical
// first argument for the cdecl calling convention.
static llvm::Function *GetOrCreateArgNGetter(
    const char *calling_conv, int64_t n) {

  std::stringstream arg_tmp;
  arg_tmp << "__mcsema_" << calling_conv << "_arg_" << n;
  std::string arg_func = arg_tmp.str();

  auto f = gModule->getFunction(arg_func);
  if (f) {
    return f;
  }

  auto addr_type = remill::AddressType(gModule);

  std::vector<llvm::Type *> tys;
  tys.push_back(remill::MemoryPointerType(gModule));
  tys.push_back(remill::StatePointerType(gModule));
  auto func_type = llvm::FunctionType::get(addr_type, tys, false);

  f = llvm::Function::Create(
      func_type, llvm::GlobalValue::ExternalLinkage, arg_func, gModule);
  f->setCallingConv(llvm::CallingConv::Fast);
  return f;
}

// Insert a call to a function to retrieve argument n, depending on the calling
// convention of native_func.
static llvm::Instruction *GetArgNForCConv(
    llvm::IRBuilder<> *ir, int64_t n, const NativeExternalFunction *native_func,
    llvm::Function *callback_func) {

  std::vector<llvm::Value *> args;
  args.push_back(
      remill::NthArgument(callback_func, remill::kMemoryPointerArgNum));
  args.push_back(
      remill::NthArgument(callback_func, remill::kStatePointerArgNum));
  return ir->CreateCall(
      GetOrCreateArgNGetter(GetCallingConvName(native_func), n), args);
}

// Insert a call to a function to set the return value from a function, based
// on the calling convention of `native_func`.
static llvm::Instruction *SetRetForCConv(
    llvm::IRBuilder<> *ir, const NativeExternalFunction *native_func,
    llvm::Function *callback_func, llvm::Value *ret_val) {

  std::vector<llvm::Value *> args;
  args.push_back(
      remill::NthArgument(callback_func, remill::kMemoryPointerArgNum));
  args.push_back(
      remill::NthArgument(callback_func, remill::kStatePointerArgNum));
  args.push_back(ret_val);

  return ir->CreateCall(
      GetOrCreateRetValSetter(GetCallingConvName(native_func)), args);
}

// For an external named `external`, return a function pointer with the type
// `uintptr_t *external(uintptr_t *arg0, uintptr_t *arg1, ...);`. This may
// end up being a casted version of the actual declaration.
//
// TODO(pag,car,artem): Handle floating point types eventually. For this, we
//                      should probably move to a constraint table-based
//                      approach of generating code that will get all the
//                      arguments from the appropriate spots.
static llvm::Constant *GetExplicitArgsFunction(
    const NativeExternalFunction *nf) {

  auto extfun = gModule->getFunction(nf->name);
  CHECK(nullptr != extfun)
      << "Declaration of external " << nf->name << " does not exist.";

  auto ptrtype = llvm::Type::getIntNTy(
      *gContext, static_cast<unsigned>(gArch->address_size));

  std::vector<llvm::Type *> tys;
  for (auto i = 0; i < nf->num_args; i++) {
    tys.push_back(ptrtype);
  }

  return gModule->getOrInsertFunction(
      nf->name, llvm::FunctionType::get(ptrtype, tys, false));
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

  auto func = gModule->getFunction(cfg_func->name);
  CHECK(func != nullptr)
      << "Cannot find declaration or definition for external function "
      << cfg_func->name;

  // Stub that will marshal lifted state into the native state.
  callback_func = llvm::Function::Create(LiftedFunctionType(),
                                         llvm::GlobalValue::InternalLinkage,
                                         cfg_func->lifted_name, gModule);
  callback_func->setCallingConv(llvm::CallingConv::Fast);

  auto block = llvm::BasicBlock::Create(*gContext, "", callback_func);

  // Pass through the memory and state pointers, and pass the destination
  // (native external function address) as the PC argument.
  llvm::IRBuilder<> ir(block);

  if (FLAGS_explicit_args) {

    // Always inline so that static analyses of the bitcode don't need to dive
    // into an extra function just to see the intended call.
    callback_func->addFnAttr(llvm::Attribute::InlineHint);
    callback_func->addFnAttr(llvm::Attribute::AlwaysInline);

    LOG(INFO)
        << "Generating " << cfg_func->num_args
        << " argument getters in function "
        << cfg_func->lifted_name << " for external " << cfg_func->name;

    // create call to function and args
    std::vector<llvm::Value *> call_args;
    for (int64_t i = 0; i < cfg_func->num_args; i++) {
      call_args.push_back(GetArgNForCConv(&ir, i, cfg_func, callback_func));
    }

    ir.CreateRet(SetRetForCConv(&ir, cfg_func, callback_func, ir.CreateCall(
        GetExplicitArgsFunction(cfg_func), call_args)));

  // We are going from lifted to native code. We don't need an assembly stub
  // because `__remill_function_call` already does the right thing.
  } else {
    callback_func->addFnAttr(llvm::Attribute::NoInline);

    auto handler_call = ir.CreateCall(
        GetDetachCallValueFunc(), remill::LiftedFunctionArgs(block));
    handler_call->setTailCall(true);
    ir.CreateRet(handler_call);
  }

  AnnotateInsts(callback_func, cfg_func->ea);

  return callback_func;
}

}  // namespace mcsema
