/*
Copyright (c) 2017, Trail of Bits
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

  Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

  Redistributions in binary form must reproduce the above copyright notice, this
  list of conditions and the following disclaimer in the documentation and/or
  other materials provided with the distribution.

  Neither the name of the organization nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <gflags/gflags.h>
#include <glog/logging.h>

#include <algorithm>
#include <unordered_set>
#include <utility>
#include <vector>

#include <llvm/IR/Constants.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/DebugInfo.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Metadata.h>
#include <llvm/IR/MDBuilder.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/PassManager.h>
#include <llvm/IR/Type.h>

#include <llvm/Transforms/IPO.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>
#include <llvm/Transforms/Scalar.h>
#include <llvm/Transforms/Utils/Local.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <llvm/Transforms/Utils/ValueMapper.h>

#include "remill/Arch/Arch.h"
#include "remill/BC/ABI.h"
#include "remill/BC/Util.h"

#include "mcsema/Arch/Arch.h"
#include "mcsema/BC/Optimize.h"
#include "mcsema/BC/Util.h"

DEFINE_bool(lower_memops, true, "Controls whether or not Remill's memory "
                                "access intrinsics are lowered to LLVM "
                                "loads and stores.");

namespace mcsema {
namespace {

// Replace all uses of a specific intrinsic with an undefined value.
static void ReplaceUndefIntrinsic(llvm::Function *function) {
  auto intrinsics = function->getParent()->getFunction("__remill_intrinsics");

  std::vector<llvm::CallInst *> call_insts;
  for (auto callers : function->users()) {
    if (auto call_inst = llvm::dyn_cast<llvm::CallInst>(callers)) {
      auto user_func = call_inst->getParent()->getParent();
      if (user_func != intrinsics) {
        call_insts.push_back(call_inst);
      }
    }
  }

  std::set<llvm::User *> work_list;
  auto undef_val = llvm::UndefValue::get(function->getReturnType());
  for (auto call_inst : call_insts) {
    work_list.insert(call_inst->user_begin(), call_inst->user_end());
    call_inst->replaceAllUsesWith(undef_val);
    call_inst->removeFromParent();
    delete call_inst;
  }

  // Try to propagate `undef` values produced from our intrinsics all the way
  // to store instructions, and treat them as dead stores to be eliminated.
  std::vector<llvm::StoreInst *> dead_stores;
  while (work_list.size()) {
    std::set<llvm::User *> next_work_list;
    for (auto inst : work_list) {
      if (llvm::isa<llvm::CmpInst>(inst) ||
          llvm::isa<llvm::CastInst>(inst)) {
        next_work_list.insert(inst->user_begin(), inst->user_end());
        auto undef_val = llvm::UndefValue::get(inst->getType());
        inst->replaceAllUsesWith(undef_val);
      } else if (auto store_inst = llvm::dyn_cast<llvm::StoreInst>(inst)) {
        dead_stores.push_back(store_inst);
      }
    }
    work_list.swap(next_work_list);
  }

  for (auto dead_store : dead_stores) {
    dead_store->eraseFromParent();
  }
}

static void RemoveFunction(llvm::Function *func) {
  if (!func->hasNUsesOrMore(1)) {
    func->removeFromParent();
    delete func;
  }
}

static void RemoveFunction(const char *name) {
  if (auto func = gModule->getFunction(name)) {
    func->setLinkage(llvm::GlobalValue::InternalLinkage);

//    llvm::SmallVector<std::pair<unsigned, llvm::MDNode *>, 4> mds;
//    func->getAllMetadata(mds);
//    for (auto md_info : mds) {
//      auto num_ops = md_info.second->getNumOperands();
//      for (unsigned i = 0; i < num_ops; ++i) {
//        md_info.second->replaceOperandWith(i, nullptr);
//      }
//      func->setMetadata(md_info.first, nullptr);
//    }

    RemoveFunction(func);
  }
}

// Remove calls to the various undefined value intrinsics.
static void RemoveUndefFuncCalls(void) {
  llvm::Function *undef_funcs[] = {
      gModule->getFunction("__remill_undefined_8"),
      gModule->getFunction("__remill_undefined_16"),
      gModule->getFunction("__remill_undefined_32"),
      gModule->getFunction("__remill_undefined_64"),
      gModule->getFunction("__remill_undefined_f32"),
      gModule->getFunction("__remill_undefined_f64"),
  };

  for (auto undef_func : undef_funcs) {
    if (undef_func) {
      ReplaceUndefIntrinsic(undef_func);
      RemoveFunction(undef_func);
    }
  }
}

static void RunO3(void) {
  llvm::legacy::FunctionPassManager func_manager(gModule);
  llvm::legacy::PassManager module_manager;

  auto TLI = new llvm::TargetLibraryInfoImpl(
      llvm::Triple(gModule->getTargetTriple()));
  TLI->disableAllFunctions();

  llvm::PassManagerBuilder builder;
  builder.OptLevel = 3;
  builder.SizeLevel = 2;
  builder.Inliner = llvm::createFunctionInliningPass(100);
  builder.LibraryInfo = TLI;  // Deleted by `llvm::~PassManagerBuilder`.
  builder.DisableTailCalls = false;  // Enable tail calls.
  builder.DisableUnrollLoops = false;  // Unroll loops!
  builder.DisableUnitAtATime = false;
  builder.SLPVectorize = true;
  builder.LoopVectorize = true;
  builder.LoadCombine = true;
  builder.MergeFunctions = false;  // Try to deduplicate functions.
  builder.VerifyInput = false;
  builder.VerifyOutput = false;

  builder.populateFunctionPassManager(func_manager);
  builder.populateModulePassManager(module_manager);
  func_manager.doInitialization();
  for (auto &func : *gModule) {
    func_manager.run(func);
  }
  func_manager.doFinalization();
  module_manager.run(*gModule);
}

static std::vector<llvm::GlobalVariable *> FindISELs(void) {
  std::vector<llvm::GlobalVariable *> isels;
  auto basic_block = gModule->getFunction("__remill_basic_block");
  if (!basic_block) {
    LOG(ERROR)
        << "Not removing any ISELs or SEMs; can't find __remill_basic_block.";
    return isels;
  }

  auto lifted_func_type = basic_block->getFunctionType();
  auto mem_type = lifted_func_type->getParamType(0);
  auto state_type = lifted_func_type->getParamType(1);

  isels.reserve(gModule->size());
  for (auto &isel : gModule->globals()) {
    if (!isel.hasInitializer()) {
      continue;
    }

    auto sem = llvm::dyn_cast<llvm::Function>(
        isel.getInitializer()->stripPointerCasts());
    if (!sem) {
      continue;
    }

    auto sem_type = sem->getFunctionType();

    if (mem_type == sem_type->getParamType(0) &&
        state_type == sem_type->getParamType(1)) {
      DLOG(INFO)
          << "Found ISEL " << isel.getName().str();
      isels.push_back(&isel);
    }
  }

  return isels;
}

// Remove the ISEL variables used for finding the instruction semantics.
static void RemoveISELs(std::vector<llvm::GlobalVariable *> &isels) {
  std::vector<llvm::GlobalVariable *> next_isels;
  while (isels.size()) {
    next_isels.clear();
    for (auto isel : isels) {
      isel->setLinkage(llvm::GlobalValue::InternalLinkage);
      if (1 >= isel->getNumUses()) {
        DLOG(INFO)
            << "Removing ISEL " << isel->getName().str();
        isel->eraseFromParent();
      } else {
        next_isels.push_back(isel);
      }
    }
    isels.swap(next_isels);
  }
}

// Remove some of the remill intrinsics.
static void RemoveIntrinsics(void) {
  if (auto llvm_used = gModule->getGlobalVariable("llvm.used")) {
    llvm_used->eraseFromParent();
  }

  // This function makes removing intrinsics tricky, so if it's there, then
  // we'll try to get the optimizer to inline it on our behalf, which should
  // drop some references :-D
  if (auto remill_used = gModule->getFunction("__remill_mark_as_used")) {
    if (remill_used->isDeclaration()) {
      remill_used->setLinkage(llvm::GlobalValue::InternalLinkage);
      remill_used->removeFnAttr(llvm::Attribute::NoInline);
      remill_used->addFnAttr(llvm::Attribute::InlineHint);
      remill_used->addFnAttr(llvm::Attribute::AlwaysInline);
      auto block = llvm::BasicBlock::Create(*gContext, "", remill_used);
      (void) llvm::ReturnInst::Create(*gContext, block);
    }
  }

  RemoveFunction("__remill_intrinsics");
  RemoveFunction("__remill_basic_block");
  RemoveFunction("__remill_mark_as_used");
  RemoveFunction("__remill_defer_inlining");
  RemoveFunction("__remill_function_return");
  RemoveFunction("__remill_mark_as_used");
}

// Lower a memory read intrinsic into a `load` instruction.
static void ReplaceMemReadOp(const char *name, llvm::Type *val_type) {
  auto func = gModule->getFunction(name);
  CHECK(func->isDeclaration())
      << "Cannot lower already implemented memory intrinsic " << name;

  std::vector<llvm::CallInst *> callers;
  std::unordered_set<llvm::Function *> memop_callers;
  for (auto user : func->users()) {
    if (auto call_inst = llvm::dyn_cast<llvm::CallInst>(user)) {
      if (call_inst->getCalledFunction() == func) {
        callers.push_back(call_inst);
        memop_callers.insert(call_inst->getFunction());
      }
    }
  }

  for (auto call_inst : callers) {
    auto addr = call_inst->getArgOperand(1);

    llvm::IRBuilder<> ir(call_inst);
    auto ptr = ir.CreateIntToPtr(addr, llvm::PointerType::get(val_type, 0));
    llvm::Value *val = ir.CreateLoad(ptr);
    if (val_type->isX86_FP80Ty()) {
      val = ir.CreateFPTrunc(val, func->getReturnType());
    }
    call_inst->replaceAllUsesWith(val);
  }

  // Update the functions using the memory pointer to
  for (auto func : memop_callers) {
    auto func_attrs = func->getAttributes();
    if (func_attrs.getDereferenceableBytes(remill::kMemoryPointerArgNum)) {
      continue;
    }

    func_attrs.addDereferenceableAttr(
        *gContext, llvm::AttributeSet::ReturnIndex, ~0ULL);
    func_attrs.addDereferenceableAttr(
        *gContext, remill::kMemoryPointerArgNum, ~0ULL);
    func->setAttributes(func_attrs);
  }
}

// Lower a memory write intrinsic into a `store` instruction.
static void ReplaceMemWriteOp(const char *name, llvm::Type *val_type) {
  auto func = gModule->getFunction(name);
  CHECK(func->isDeclaration())
      << "Cannot lower already implemented memory intrinsic " << name;

  std::vector<llvm::CallInst *> callers;
  for (auto user : func->users()) {
    if (auto call_inst = llvm::dyn_cast<llvm::CallInst>(user)) {
      if (call_inst->getCalledFunction() == func) {
        callers.push_back(call_inst);
      }
    }
  }

  for (auto call_inst : callers) {
    auto mem_ptr = call_inst->getArgOperand(0);
    auto addr = call_inst->getArgOperand(1);
    auto val = call_inst->getArgOperand(2);

    llvm::IRBuilder<> ir(call_inst);
    auto ptr = ir.CreateIntToPtr(addr, llvm::PointerType::get(val_type, 0));
    if (val_type->isX86_FP80Ty()) {
      val = ir.CreateFPExt(val, val_type);
    }
    ir.CreateStore(val, ptr);
    call_inst->replaceAllUsesWith(mem_ptr);
  }

  RemoveFunction(func);
}

static void LowerMemOps(void) {
  auto mem_func = gModule->getFunction("__remill_write_memory_8");
  auto mem_ptr_type = llvm::dyn_cast<llvm::PointerType>(
      mem_func->getReturnType());
  auto mem_type = llvm::dyn_cast<llvm::StructType>(
      mem_ptr_type->getElementType());
  mem_type->setBody(llvm::Type::getInt8Ty(*gContext), nullptr, nullptr);

  ReplaceMemReadOp("__remill_read_memory_8",
                   llvm::Type::getInt8Ty(*gContext));
  ReplaceMemReadOp("__remill_read_memory_16",
                   llvm::Type::getInt16Ty(*gContext));
  ReplaceMemReadOp("__remill_read_memory_32",
                   llvm::Type::getInt32Ty(*gContext));
  ReplaceMemReadOp("__remill_read_memory_64",
                   llvm::Type::getInt64Ty(*gContext));
  ReplaceMemReadOp("__remill_read_memory_f32",
                   llvm::Type::getFloatTy(*gContext));
  ReplaceMemReadOp("__remill_read_memory_f64",
                   llvm::Type::getDoubleTy(*gContext));

  ReplaceMemWriteOp("__remill_write_memory_8",
                    llvm::Type::getInt8Ty(*gContext));
  ReplaceMemWriteOp("__remill_write_memory_16",
                    llvm::Type::getInt16Ty(*gContext));
  ReplaceMemWriteOp("__remill_write_memory_32",
                    llvm::Type::getInt32Ty(*gContext));
  ReplaceMemWriteOp("__remill_write_memory_64",
                    llvm::Type::getInt64Ty(*gContext));
  ReplaceMemWriteOp("__remill_write_memory_f32",
                    llvm::Type::getFloatTy(*gContext));
  ReplaceMemWriteOp("__remill_write_memory_f64",
                    llvm::Type::getDoubleTy(*gContext));

  ReplaceMemReadOp("__remill_read_memory_f80",
                   llvm::Type::getX86_FP80Ty(*gContext));
  ReplaceMemWriteOp("__remill_write_memory_f80",
                    llvm::Type::getX86_FP80Ty(*gContext));
}

}  // namespace

void OptimizeModule(void) {
  auto isels = FindISELs();
  RemoveIntrinsics();
  LOG(INFO)
      << "Optimizing module.";
  RemoveISELs(isels);
  if (FLAGS_lower_memops) {
    LowerMemOps();
  }
  RunO3();
  RemoveIntrinsics();
  RemoveUndefFuncCalls();
}

}  // namespace mcsema
