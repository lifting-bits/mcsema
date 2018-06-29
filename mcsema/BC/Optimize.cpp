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

#include <algorithm>
#include <limits>
#include <set>
#include <unordered_set>
#include <utility>
#include <vector>

#include <llvm/ADT/Triple.h>

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
#include <llvm/IR/Type.h>

#include <llvm/Transforms/IPO.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>
#include <llvm/Transforms/Scalar.h>
#include <llvm/Transforms/Utils/Local.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <llvm/Transforms/Utils/ValueMapper.h>

#include "remill/Arch/Arch.h"
#include "remill/BC/ABI.h"
#include "remill/BC/Compat/TargetLibraryInfo.h"
#include "remill/BC/DeadStoreEliminator.h"
#include "remill/BC/Util.h"

#include "mcsema/Arch/Arch.h"
#include "mcsema/BC/Optimize.h"
#include "mcsema/BC/Util.h"

DEFINE_bool(disable_optimizer, false,
            "Disable interprocedural optimizations?");

DEFINE_bool(keep_memops, false,
            "Should the memory intrinsics be replaced or not?");

namespace mcsema {
namespace {

// Replace all uses of a specific intrinsic with an undefined value. We actually
// don't use LLVM's `undef` values because those can behave unpredictably
// across different LLVM versions with different optimization levels. Instead,
// we use a null value (zero, really).
static void ReplaceUndefIntrinsic(llvm::Function *function) {
  auto call_insts = remill::CallersOf(function);
  auto undef_val = llvm::Constant::getNullValue(function->getReturnType());
  for (auto call_inst : call_insts) {
    call_inst->replaceAllUsesWith(undef_val);
    call_inst->removeFromParent();
    delete call_inst;
  }
}

static void RemoveFunction(llvm::Function *func) {
  if (!func->hasNUsesOrMore(1)) {
    func->eraseFromParent();
  }
}

static void RemoveFunction(const char *name) {
  if (auto func = gModule->getFunction(name)) {
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

  TLI->disableAllFunctions();  // `-fno-builtin`.

  llvm::PassManagerBuilder builder;
  builder.OptLevel = 3;
  builder.SizeLevel = 2;
  builder.Inliner = llvm::createFunctionInliningPass(
      std::numeric_limits<int>::max());
  builder.LibraryInfo = TLI;  // Deleted by `llvm::~PassManagerBuilder`.
  builder.DisableUnrollLoops = false;  // Unroll loops!
  builder.DisableUnitAtATime = false;
  builder.SLPVectorize = false;
  builder.LoopVectorize = false;

  // TODO(pag): Not sure when these became available.
  // builder.MergeFunctions = false;  // Try to deduplicate functions.
  // builder.VerifyInput = false;
  // builder.VerifyOutput = false;

  builder.populateFunctionPassManager(func_manager);
  builder.populateModulePassManager(module_manager);
  func_manager.doInitialization();
  for (auto &func : *gModule) {
    func_manager.run(func);
  }
  func_manager.doFinalization();
  module_manager.run(*gModule);
}

// Get a list of all ISELs.
static std::vector<llvm::GlobalVariable *> FindISELs(void) {
  std::vector<llvm::GlobalVariable *> isels;
  remill::ForEachISel(
      gModule, [&](llvm::GlobalVariable *isel, llvm::Function *) {
        isels.push_back(isel);
      });
  return isels;
}

// Remove the ISEL variables used for finding the instruction semantics.
static void PrivatizeISELs(std::vector<llvm::GlobalVariable *> &isels) {
  for (auto isel : isels) {
    isel->setInitializer(nullptr);
    isel->setExternallyInitialized(false);
    isel->setLinkage(llvm::GlobalValue::PrivateLinkage);

    if (!isel->hasNUsesOrMore(2)) {
      isel->eraseFromParent();
    }
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
    std::vector<llvm::CallInst *> uses;
    for (auto use : remill_used->users()) {
      if (auto call = llvm::dyn_cast<llvm::CallInst>(use)) {
        uses.push_back(call);
      }
    }

    for (auto call : uses) {
      call->eraseFromParent();
    }

    if (remill_used->hasNUsesOrMore(1)) {
      if (remill_used->isDeclaration()) {
        remill_used->setLinkage(llvm::GlobalValue::InternalLinkage);
        remill_used->removeFnAttr(llvm::Attribute::NoInline);
        remill_used->addFnAttr(llvm::Attribute::InlineHint);
        remill_used->addFnAttr(llvm::Attribute::AlwaysInline);
        auto block = llvm::BasicBlock::Create(*gContext, "", remill_used);
        (void) llvm::ReturnInst::Create(*gContext, block);
      }
    }

    RemoveFunction(remill_used);
  }

//  if (auto intrinsics = gModule->getFunction("__remill_intrinsics")) {
//    intrinsics->eraseFromParent();
//  }

  RemoveFunction("__remill_basic_block");
  RemoveFunction("__remill_defer_inlining");
  RemoveFunction("__remill_intrinsics");
}

static void ReplaceBarrier(const char *name) {
  auto func = gModule->getFunction(name);
  if (!func) {
    return;
  }

  CHECK(func->isDeclaration())
      << "Cannot lower already implemented memory intrinsic " << name;

  auto callers = remill::CallersOf(func);
  for (auto call_inst : callers) {
    auto mem_ptr = call_inst->getArgOperand(0);
    call_inst->replaceAllUsesWith(mem_ptr);
    call_inst->eraseFromParent();
  }
}

// Lower a memory read intrinsic into a `load` instruction.
static void ReplaceMemReadOp(const char *name, llvm::Type *val_type) {
  auto func = gModule->getFunction(name);
  if (!func) {
    return;
  }

  CHECK(func->isDeclaration())
      << "Cannot lower already implemented memory intrinsic " << name;

  auto callers = remill::CallersOf(func);
  for (auto call_inst : callers) {
    auto addr = call_inst->getArgOperand(1);

    llvm::IRBuilder<> ir(call_inst);
    llvm::Value *ptr = nullptr;
    if (auto as_int = llvm::dyn_cast<llvm::PtrToIntInst>(addr)) {
      ptr = ir.CreateBitCast(
          as_int->getPointerOperand(),
          llvm::PointerType::get(val_type, as_int->getPointerAddressSpace()));

    } else {
      ptr = ir.CreateIntToPtr(addr, llvm::PointerType::get(val_type, 0));
    }

    llvm::Value *val = ir.CreateLoad(ptr);
    if (val_type->isX86_FP80Ty()) {
      val = ir.CreateFPTrunc(val, func->getReturnType());
    }
    call_inst->replaceAllUsesWith(val);
  }
  for (auto call_inst : callers) {
    call_inst->eraseFromParent();
  }
  RemoveFunction(func);
}

// Lower a memory write intrinsic into a `store` instruction.
static void ReplaceMemWriteOp(const char *name, llvm::Type *val_type) {
  auto func = gModule->getFunction(name);
  if (!func) {
    return;
  }

  CHECK(func->isDeclaration())
      << "Cannot lower already implemented memory intrinsic " << name;

  auto callers = remill::CallersOf(func);

  for (auto call_inst : callers) {
    auto mem_ptr = call_inst->getArgOperand(0);
    auto addr = call_inst->getArgOperand(1);
    auto val = call_inst->getArgOperand(2);

    llvm::IRBuilder<> ir(call_inst);

    llvm::Value *ptr = nullptr;
    if (auto as_int = llvm::dyn_cast<llvm::PtrToIntInst>(addr)) {
      ptr = ir.CreateBitCast(
          as_int->getPointerOperand(),
          llvm::PointerType::get(val_type, as_int->getPointerAddressSpace()));
    } else {
      ptr = ir.CreateIntToPtr(addr, llvm::PointerType::get(val_type, 0));
    }

    if (val_type->isX86_FP80Ty()) {
      val = ir.CreateFPExt(val, val_type);
    }

    ir.CreateStore(val, ptr);
    call_inst->replaceAllUsesWith(mem_ptr);
  }
  for (auto call_inst : callers) {
    call_inst->eraseFromParent();
  }
  RemoveFunction(func);
}

static void LowerMemOps(void) {
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

  PrivatizeISELs(isels);

  if (!FLAGS_disable_optimizer) {
    auto bb_func = remill::BasicBlockFunction(gModule);
    auto slots = remill::StateSlots(gModule);
    RunO3();
    remill::RemoveDeadStores(gModule, bb_func, slots);
  }

  RemoveIntrinsics();

  if (!FLAGS_keep_memops) {
    LowerMemOps();
    ReplaceBarrier("__remill_barrier_load_load");
    ReplaceBarrier("__remill_barrier_load_store");
    ReplaceBarrier("__remill_barrier_store_load");
    ReplaceBarrier("__remill_barrier_store_store");
    ReplaceBarrier("__remill_barrier_atomic_begin");
    ReplaceBarrier("__remill_barrier_atomic_end");
  }

  RemoveUndefFuncCalls();
}

}  // namespace mcsema
