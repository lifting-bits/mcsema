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

#include "mcsema/Arch/Arch.h"
#include "mcsema/BC/Callback.h"
#include "mcsema/CFG/CFG.h"

namespace mcsema {

// Get a callback function for an internal function.
llvm::Function *GetEntryPoint(const NativeObject *cfg_func,
                              llvm::Function *func) {
  auto module = func->getParent();
  auto &context = module->getContext();
  auto callback_func = module->getFunction(cfg_func->name);
  if (callback_func) {
    return callback_func;
  }

  auto void_type = llvm::Type::getVoidTy(context);
  auto callback_type = llvm::FunctionType::get(void_type, false);
  callback_func = llvm::Function::Create(
      callback_type, llvm::GlobalValue::InternalLinkage,  // Tentative linkage.
      cfg_func->name, module);

  auto handler = llvm::dyn_cast<llvm::Function>(module->getOrInsertFunction(
      "__mcsema_attach_call", callback_type));

  handler->setLinkage(llvm::GlobalValue::ExternalLinkage);
  handler->setVisibility(llvm::GlobalValue::DefaultVisibility);

  callback_func->setVisibility(llvm::GlobalValue::DefaultVisibility);
  callback_func->addFnAttr(llvm::Attribute::Naked);
  callback_func->addFnAttr(llvm::Attribute::NoInline);
  callback_func->addFnAttr(llvm::Attribute::NoBuiltin);

  auto attach_target = llvm::dyn_cast<llvm::GlobalVariable>(
      module->getOrInsertGlobal("__mcsema_attach_target", func->getType()));

  attach_target->setThreadLocal(true);
  attach_target->setThreadLocalMode(llvm::GlobalValue::InitialExecTLSModel);
//  std::stringstream ss;
//  switch (gArch->arch_name) {
//    case remill::kArchInvalid:
//    case remill::kArchX86:
//    case remill::kArchX86_AVX:
//    case remill::kArchX86_AVX512:
//      ss << "pushl %eax;"
//         << "leal " << func->getName().str() << ", %eax;"
//         << "xchgl (%esp), %eax;"
//         << "jmp __mcsema_attach_call;";
//      break;
//    case remill::kArchAMD64:
//    case remill::kArchAMD64_AVX:
//    case remill::kArchAMD64_AVX512:
//      ss << "pushq %%rax;"
//         << "leaq " << func->getName().str() << "(%ip), %%rax;"
//         << "xchgq (%%rsp), %%rax;"
//         << "jmp __mcsema_attach_call;";
//      break;
//  }
//
//  auto asm_type = llvm::FunctionType::get(
//      llvm::Type::getVoidTy(context), false  /* isVarArg */);
//
//  auto asm_code = llvm::InlineAsm::get(
//      asm_type,
//      ss.str(),
//      "~{dirflag},~{fpsr},~{flags}",
//      true  /* hasSideEffects */);

  llvm::IRBuilder<> ir(llvm::BasicBlock::Create(context, "", callback_func));
  ir.CreateStore(func, attach_target);
  auto handler_call = ir.CreateCall(handler);
  handler_call->setTailCallKind(llvm::CallInst::TCK_MustTail);
  ir.CreateRetVoid();

  return callback_func;
}

}  // namespace mcsema
