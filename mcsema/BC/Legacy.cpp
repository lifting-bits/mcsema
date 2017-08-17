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

namespace mcsema {
namespace legacy {
namespace {

// Replace indirect control-flow intrinsics (call, jump) with calls to the
// legacy detach call value function.
static void RemoveControlFlowIntrinsic(const char *name) {
  auto callers = remill::CallersOf(gModule->getFunction(name));
  auto detach_call_val = GetLegacyLiftedToNativeExitPoint();
  for (auto call_inst : callers) {
    std::vector<llvm::Value *> args(3);
    args[0] = call_inst->getArgOperand(0);
    args[1] = call_inst->getArgOperand(1);
    args[2] = call_inst->getArgOperand(2);

    auto new_mem_ptr = llvm::CallInst::Create(
        detach_call_val, args, "", call_inst);

    call_inst->replaceAllUsesWith(new_mem_ptr);
    call_inst->eraseFromParent();
  }
}

// Remove the `fastcc` calling convention, and any tail calls.
static void RemoveFastCall(void) {
  for (auto &func : *gModule) {
    if (func.getCallingConv() == llvm::CallingConv::Fast) {
      func.setCallingConv(llvm::CallingConv::C);
    }

    if (func.isDeclaration()) {
      continue;
    }

    for (auto &block : func) {
      for (auto &inst : block) {
        if (auto call_inst = llvm::dyn_cast<llvm::CallInst>(&inst)) {
          if (call_inst->getCallingConv() == llvm::CallingConv::Fast) {
            call_inst->setCallingConv(llvm::CallingConv::C);
          }
          call_inst->setTailCall(false);
        }
      }
    }
  }
}

// Remove calls to error-related intrinsics.
static void RemoveErrorIntrinsic(const char *name) {
  auto callers = remill::CallersOf(gModule->getFunction(name));
  for (auto call_inst : callers) {
    call_inst->replaceAllUsesWith(
        call_inst->getArgOperand(remill::kMemoryPointerArgNum));

    auto block = call_inst->getParent();
    auto term_inst = block->getTerminator();

    term_inst->eraseFromParent();
    call_inst->eraseFromParent();

    new llvm::UnreachableInst(*gContext, block);
  }
}

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

static unsigned AnnotationID(void) {
  static bool has_id = false;
  static unsigned id = 0;
  if (!has_id) {
    has_id = true;
    id = gContext->getMDKindID(kRealEIPAnnotation);
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

void DowngradeModule(void) {
  RemoveControlFlowIntrinsic("__remill_function_call");
  RemoveControlFlowIntrinsic("__remill_jump");
  RemoveErrorIntrinsic("__remill_error");
  RemoveErrorIntrinsic("__remill_missing_block");
  RemoveFastCall();
}

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

}  // namespace legacy
}  // namespace mcsema
