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

#include "Legacy.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wsign-conversion"
#pragma clang diagnostic ignored "-Wconversion"
#pragma clang diagnostic ignored "-Wold-style-cast"
#pragma clang diagnostic ignored "-Wdocumentation"
#pragma clang diagnostic ignored "-Wswitch-enum"
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>
#pragma clang diagnostic pop

#include <remill/Arch/Arch.h>
#include <remill/BC/ABI.h>
#include <remill/BC/Util.h>
#include <remill/BC/Version.h>

#include <vector>

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

}  // namespace legacy
}  // namespace mcsema
