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

#include <gflags/gflags.h>
#include <glog/logging.h>

#include <vector>

#include <llvm/IR/Constants.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>

#include "remill/Arch/Arch.h"
#include "remill/BC/ABI.h"
#include "remill/BC/Util.h"
#include "remill/BC/Version.h"

#include "mcsema/Arch/Arch.h"
#include "mcsema/BC/Callback.h"
#include "mcsema/BC/Legacy.h"
#include "mcsema/BC/Util.h"

DEFINE_string(pc_annotation, "",
              "Name of the metadata to apply to every LLVM instruction. The "
              "metadata includes the approximate program counter of the "
              "original instruction that produced the lifted bitcode.");

namespace mcsema {
namespace legacy {
namespace {

// Remove calls to error-related intrinsics.
static void ImplementErrorIntrinsic(const char *name) {
  auto func = gModule->getFunction(name);
  if (!func) {
    return;
  }

  auto void_type = llvm::Type::getVoidTy(*gContext);
  auto abort_func = gModule->getOrInsertFunction(
      "abort", llvm::FunctionType::get(void_type, false));

  func->setLinkage(llvm::GlobalValue::InternalLinkage);

  llvm::IRBuilder<> ir(llvm::BasicBlock::Create(*gContext, "", func));
  ir.CreateCall(abort_func);
  ir.CreateRet(remill::NthArgument(func, remill::kMemoryPointerArgNum));
}

// Create the node for a `mcsema_real_eip` annotation.
static llvm::MDNode *CreateInstAnnotation(llvm::Function *F, uint64_t addr) {
  auto addr_val = llvm::ConstantInt::get(gWordType, addr);
#if LLVM_VERSION_NUMBER >= LLVM_VERSION(3, 6)
  auto addr_md = llvm::ValueAsMetadata::get(addr_val);
  return llvm::MDNode::get(*gContext, addr_md);
#else
  return llvm::MDNode::get(*gContext, addr_val);
#endif
}

static unsigned AnnotationID(void) {
  static bool has_id = false;
  static unsigned id = 0;
  if (!has_id) {
    has_id = true;
    id = gContext->getMDKindID(FLAGS_pc_annotation);
  }
  return id;
}

// Annotate and instruction with the `mcsema_real_eip` annotation if that
// instruction is unannotated.
static void AnnotateInst(llvm::Instruction *inst, llvm::MDNode *annot) {
  auto id = AnnotationID();
  if (!inst->getMetadata(id)) {
    inst->setMetadata(id, annot);
  }
}

}  // namespace

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

// Propagate any instruction annotations.
void PropagateInstAnnotations(void) {
  auto id = AnnotationID();
  std::vector<llvm::Instruction *> pending;
  for (auto &func : *gModule) {
    if (func.isDeclaration()) {
      continue;
    }

    for (auto &block : func) {
      llvm::MDNode *prev = nullptr;

      for (auto &inst : block) {
        auto curr = inst.getMetadata(id);
        if (curr) {
          prev = curr;
        } else if (prev) {
          inst.setMetadata(id, prev);
        } else {
          pending.push_back(&inst);
        }

        if (prev && pending.size()) {
          for (auto pending_inst : pending) {
            pending_inst->setMetadata(id, prev);
          }
          pending.clear();
        }
      }

      if (prev && pending.size()) {
        for (auto pending_inst : pending) {
          pending_inst->setMetadata(id, prev);
        }
        pending.clear();
      }
    }
  }
}

void DowngradeModule(void) {
  ImplementErrorIntrinsic("__remill_error");
  ImplementErrorIntrinsic("__remill_missing_block");
}

}  // namespace legacy
}  // namespace mcsema
