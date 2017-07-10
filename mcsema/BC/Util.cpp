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

#include <string>

#include <llvm/IR/Constants.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Metadata.h>
#include <llvm/IR/MDBuilder.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>

#include "remill/Arch/Arch.h"
#include "remill/BC/Version.h"

#include "mcsema/Arch/Arch.h"
#include "mcsema/BC/Util.h"

namespace mcsema {
namespace {
static const char * const kRealEIPAnnotation = "mcsema_real_eip";

// Create the node for a `mcsema_real_eip` annotation.
static llvm::MDNode *CreateInstAnnotation(llvm::Function *F, uint64_t addr) {
  auto word_type = llvm::Type::getIntNTy(
      *gContext, static_cast<unsigned>(gArch->address_size));
  auto addr_val = llvm::ConstantInt::get(word_type, addr);
#if LLVM_VERSION_NUMBER >= LLVM_VERSION(3, 6)
  auto addr_md = llvm::ValueAsMetadata::get(addr_val);
  return llvm::MDNode::get(*gContext, addr_md);
#else
  return llvm::MDNode::get(*gContext, addr_val);
#endif
}

// Annotate and instruction with the `mcsema_real_eip` annotation if that
// instruction is unannotated.
static void AnnotateInst(llvm::Instruction *inst, llvm::MDNode *annot) {
  if (!inst->getMetadata(kRealEIPAnnotation)) {
    inst->setMetadata(kRealEIPAnnotation, annot);
  }
}

}  // namespace

llvm::LLVMContext *gContext = nullptr;
llvm::Module *gModule = nullptr;

// Create a `mcsema_real_eip` annotation, and annotate every unannotated
// instruction with this new annotation.
void AnnotateInsts(llvm::Function *func, uint64_t pc) {
  auto annot = CreateInstAnnotation(func, pc);
  for (llvm::BasicBlock &block : *func) {
    for (llvm::Instruction &inst : block) {
      AnnotateInst(&inst, annot);
    }
  }
}

// Return the type of a lifted function.
llvm::FunctionType *LiftedFunctionType(void) {
  static llvm::FunctionType *func_type = nullptr;
  if (!func_type) {
    func_type = gModule->getFunction("__remill_basic_block")->getFunctionType();
  }
  return func_type;
}

}  // namespace mcsema
