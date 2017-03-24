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

#include <llvm/ADT/StringSwitch.h>

#include <llvm/Bitcode/ReaderWriter.h>

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

#include <memory>
#include <unordered_set>
#include <vector>

#include "remill/Arch/Arch.h"
#include "remill/Arch/Instruction.h"
#include "remill/BC/ABI.h"
#include "remill/BC/IntrinsicTable.h"
#include "remill/BC/Lifter.h"

#include "mcsema/Arch/Arch.h"
#include "mcsema/Arch/Dispatch.h"
#include "mcsema/BC/Lift.h"
#include "mcsema/BC/Util.h"
#include "mcsema/CFG/CFG.h"

DEFINE_bool(ignore_unsupported, false,
            "Should unsupported instructions be ignored?");

DEFINE_bool(add_reg_tracer, false,
            "Add a debug function that prints out the register state before "
            "each lifted instruction execution.");

DECLARE_bool(add_breakpoints);  // Already part of Remill's lifting process.

llvm::CallingConv::ID getLLVMCC(ExternalCodeRef::CallingConvention cc) {
  switch (cc) {
    case ExternalCodeRef::CallerCleanup:
      return llvm::CallingConv::C;
    case ExternalCodeRef::CalleeCleanup:
      return llvm::CallingConv::X86_StdCall;
    case ExternalCodeRef::FastCall:
      return llvm::CallingConv::X86_FastCall;
    case ExternalCodeRef::McsemaCall:
      // mcsema internal calls are cdecl with one argument
      return llvm::CallingConv::C;
    default:
      LOG(FATAL)
          << "Unknown calling convention.";
  }

  return llvm::CallingConv::C;
}

//
// common case for arithmetic instructions
// some instructions, like inc and dec, do not need to do this
//


//static void CreateInstrBreakpoint(llvm::BasicBlock *B, VA pc) {
//  auto F = B->getParent();
//  auto M = F->getParent();
//
//  std::stringstream ss;
//  ss << "breakpoint_" << std::hex << pc;
//  auto instr_func_name = ss.str();
//
//  auto IFT = M->getFunction(instr_func_name);
//  if (!IFT) {
//
//    IFT = llvm::Function::Create(
//        LiftedFunctionType(), llvm::GlobalValue::ExternalLinkage,
//        instr_func_name, M);
//
//    IFT->addFnAttr(llvm::Attribute::OptimizeNone);
//    IFT->addFnAttr(llvm::Attribute::NoInline);
//
//    auto &C = M->getContext();
//    llvm::IRBuilder<> ir(llvm::BasicBlock::Create(C, "", IFT));
//    ir.CreateRetVoid();
//  }
//
//  auto state_ptr = &*F->arg_begin();
//  llvm::CallInst::Create(IFT, {state_ptr}, "", B);
//}

//static void AddRegStateTracer(llvm::BasicBlock *B) {
//  auto F = B->getParent();
//  auto M = F->getParent();
//  auto IFT = ArchGetOrCreateRegStateTracer(M);
//
//  auto state_ptr = &*F->arg_begin();
//  llvm::CallInst::Create(IFT, {state_ptr}, "", B);
//}

static const char * const kRealEIPAnnotation = "mcsema_real_eip";

// Create the node for a `mcsema_real_eip` annotation.
static llvm::MDNode *CreateInstAnnotation(llvm::Function *F, VA addr) {
  auto &C = F->getContext();
  auto addr_val = llvm::ConstantInt::get(llvm::Type::getInt64Ty(C), addr);
  auto addr_md = llvm::ValueAsMetadata::get(addr_val);
  return llvm::MDNode::get(C, addr_md);
}

// Annotate and instruction with the `mcsema_real_eip` annotation if that
// instruction is unannotated.
static void AnnotateInst(llvm::Instruction *inst, llvm::MDNode *annot) {
  if (!inst->getMetadata(kRealEIPAnnotation)) {
    inst->setMetadata(kRealEIPAnnotation, annot);
  }
}

// Create a `mcsema_real_eip` annotation, and annotate every unannotated
// instruction with this new annotation.
static void AnnotateInsts(llvm::Function *F, VA pc) {
  auto annot = CreateInstAnnotation(F, pc);
  for (llvm::BasicBlock &B : *F) {
    for (llvm::Instruction &I : B) {
      AnnotateInst(&I, annot);
    }
  }
}

// Update the program counter in the state struct with a hard-coded value.
static void StoreProgramCounter(TranslationContext &ctx,
                                llvm::BasicBlock *block,
                                uint64_t pc) {
  auto pc_ptr = remill::LoadProgramCounterRef(block);
  (void) new llvm::StoreInst(
      llvm::ConstantInt::get(ctx.lifter->word_type, pc), pc_ptr, block);
}

// Tries to get the lifted function beginning at `pc`.
static llvm::Function *GetLiftedFunction(uint64_t pc) {
  std::stringstream ss;
  ss << "sub_" << std::hex << pc;
  auto sub_name = ss.str();
  return gModule->getFunction(sub_name);
}

// Call another lifted function, e.g. `sub_abc123`, or an intrinsic function,
// e.g. `__remill_async_hyper_call`.
static llvm::Value *AddSubFuncCall(llvm::BasicBlock *block,
                                   llvm::Function *sub) {
  // Set up arguments according to our ABI.
  std::vector<llvm::Value *> args(remill::kNumBlockArgs);
  args[remill::kMemoryPointerArgNum] = remill::LoadMemoryPointer(block);
  args[remill::kStatePointerArgNum] = remill::LoadStatePointer(block);
  args[remill::kPCArgNum] = remill::LoadProgramCounter(block);

  auto func = block->getParent();
  sub->setCallingConv(func->getCallingConv());

  return llvm::CallInst::Create(sub, args, "", block);
}

// Add a call to another function, and then update the memory pointer with the
// result of the function.
static void InlineSubFuncCall(llvm::BasicBlock *block,
                              llvm::Function *sub) {
  auto val = AddSubFuncCall(block, sub);
  auto mem_ptr = remill::LoadMemoryPointerRef(block);
  new llvm::StoreInst(val, mem_ptr, block);
}

static llvm::Function *FindFunction(TranslationContext &ctx,
                                    uint64_t target_pc) {
  auto func = GetLiftedFunction(target_pc);
  if (func) {
    return func;
  }

  CHECK(ctx.natI->has_ext_call_target())
      << "Cannot find target of instruction at " << std::hex
      << ctx.natI->get_loc() << "; the static target " << std::hex << target_pc
      << " is not associated with a lifted subroutine, and it does not have"
      << " an external call target.";

  auto target = ctx.natI->get_ext_call_target();
  auto name = target->getSymbolName();

  std::stringstream ss;
  ss << "external_" << name;

  auto ext_func = gModule->getOrInsertFunction(
      ss.str(), ctx.F->getFunctionType());

  return llvm::dyn_cast<llvm::Function>(ext_func);
}


// Get the basic block within this function associated with a specific program
// counter.
static llvm::BasicBlock *GetOrCreateBlock(TranslationContext &ctx,
                                          uint64_t pc) {
  auto &block = ctx.va_to_bb[pc];
  if (!block) {
    LOG(ERROR)
        << "Adding missing block " << std::hex << pc;

    // First, try to see if it's actually related to another function. This is
    // equivalent to a tail-call in the original code.
    if (auto tail_called_func = FindFunction(ctx, pc)) {
      LOG(INFO)
          << "Missing block is a tail call to sub_" << std::hex << pc;

      remill::AddTerminatingTailCall(block, tail_called_func);

    // Terminate the block with an unreachable inst.
    } else {
      new llvm::UnreachableInst(*gContext, block);
    }
  }
  return block;
}

// Lift both targets of a conditional branch into a branch in the bitcode,
// where each side of the branch tail-calls to the functions associated with
// the lifted blocks for those branch targets.
static void LiftConditionalBranch(TranslationContext &ctx,
                                  llvm::BasicBlock *source,
                                  remill::Instruction *instr) {
  auto function = source->getParent();
  auto block_true = GetOrCreateBlock(ctx, instr->branch_taken_pc);
  auto block_false = GetOrCreateBlock(ctx, instr->branch_not_taken_pc);

  // TODO(pag): This is a bit ugly. The idea here is that, from the semantics
  //            code, we need a way to communicate what direction of the
  //            conditional branch should be followed. It turns out to be
  //            easiest just to write to a special variable :-)
  auto branch_taken = remill::FindVarInFunction(function, "BRANCH_TAKEN");

  llvm::IRBuilder<> cond_ir(source);
  auto cond_addr = cond_ir.CreateLoad(branch_taken);
  auto cond = cond_ir.CreateLoad(cond_addr);
  cond_ir.CreateCondBr(
      cond_ir.CreateICmpEQ(
          cond,
          llvm::ConstantInt::get(cond->getType(), 1)),
          block_true,
          block_false);
}

// Returns `true` if `instr` should end a basic block and if a terminator was
// added to end the block.
static bool TryLiftTerminator(TranslationContext &ctx,
                              llvm::BasicBlock *block,
                              remill::Instruction *instr) {
  switch (instr->category) {
    case remill::Instruction::kCategoryInvalid:
    case remill::Instruction::kCategoryError:
      new llvm::UnreachableInst(*gContext, block);
      return true;

    case remill::Instruction::kCategoryNormal:
    case remill::Instruction::kCategoryNoOp:
      return false;

    case remill::Instruction::kCategoryDirectJump:
      llvm::BranchInst::Create(
          GetOrCreateBlock(ctx, instr->branch_taken_pc), block);
      return true;

    case remill::Instruction::kCategoryIndirectJump:
      llvm::ReturnInst::Create(
          *gContext,
          AddSubFuncCall(block, ctx.lifter->intrinsics->jump),
          block);
      return true;

    case remill::Instruction::kCategoryDirectFunctionCall:
      InlineSubFuncCall(
          block, FindFunction(ctx, instr->branch_taken_pc));
      StoreProgramCounter(ctx, block, instr->next_pc);
      return false;

    case remill::Instruction::kCategoryIndirectFunctionCall:
      InlineSubFuncCall(block, ctx.lifter->intrinsics->function_call);
      return false;

    case remill::Instruction::kCategoryFunctionReturn:
      remill::AddTerminatingTailCall(
          block, ctx.lifter->intrinsics->function_return);
      return true;

    case remill::Instruction::kCategoryConditionalBranch:
    case remill::Instruction::kCategoryConditionalAsyncHyperCall:
      LiftConditionalBranch(ctx, block, instr);
      return true;

    case remill::Instruction::kCategoryAsyncHyperCall:
      InlineSubFuncCall(block, ctx.lifter->intrinsics->async_hyper_call);
      StoreProgramCounter(ctx, block, instr->next_pc);
      return false;
  }
}

static bool LiftInstIntoBlock(TranslationContext &ctx,
                              llvm::BasicBlock *block,
                              bool is_last) {
  auto instr_addr = ctx.natI->get_loc();
  auto &bytes = ctx.natI->get_bytes();
  std::unique_ptr<remill::Instruction> instr(
      gArch->DecodeInstruction(instr_addr, bytes));

  CHECK(instr->IsValid())
      << "Cannot decode instruction at " << std::hex << instr_addr;

  DLOG_IF(WARNING, bytes.size() != instr->NumBytes())
      << "Size of decoded instruction at " << std::hex << instr_addr
      << " (" << std::dec << instr->NumBytes()
      << ") doesn't match input instruction size ("
      << bytes.size() << ").";

  auto ret = ctx.lifter->LiftIntoBlock(instr.get(), block);
  if (!ret) {
    LOG(ERROR)
        << "Can't lift instruction " << instr->Serialize();
  }

  if (TryLiftTerminator(ctx, block, instr.get())) {
    CHECK(is_last)
        << "Instruction at " << std::hex << instr_addr
        << " should end the basic block.";
  }

  // Annotate every un-annotated instruction in this function with the
  // program counter of the current instruction.
  AnnotateInsts(ctx.F, instr_addr);

  return ret;
}

// Lift a decoded block into a function.
static bool LiftBlockIntoFunction(TranslationContext &ctx) {
  auto good = true;
  auto block_name = ctx.natB->get_name();
  auto block_pc = ctx.natB->get_base();
  auto block = ctx.va_to_bb[block_pc];

  // Sanity check; make sure that successor blocks exist.
  const auto &follows = ctx.natB->get_follows();
  for (auto succ_block_va : follows) {
    CHECK(1 == ctx.va_to_bb.count(succ_block_va))
        << "Missing successor block " << std::hex << succ_block_va
        << " of block " << ctx.natB->get_base();
  }

  // Store this program counter into the state structure.
  StoreProgramCounter(ctx, block, block_pc);

  // Lift each instruction into the block.
  size_t i = 0;
  for (auto inst : ctx.natB->get_insts()) {
    ctx.natI = inst;
    auto is_last = (++i) >= ctx.natB->get_insts().size();
    good = good && LiftInstIntoBlock(ctx, block, is_last);
  }

  if (!block->getTerminator()) {
    if (follows.size() == 1) {
      llvm::BranchInst::Create(ctx.va_to_bb[follows.front()], block);
    } else {
      LOG_IF(ERROR, !ctx.natI->has_local_noreturn())
          << "Block " << std::hex << block_pc << " has no terminator, and"
          << " instruction at " << std::hex << ctx.natI->get_loc()
          << " is not a local no-return function call.";

      new llvm::UnreachableInst(block->getContext(), block);
    }
  }

//  block->dump();
  return good;
}

static llvm::Function *InsertFunctionIntoModule(NativeModulePtr mod,
                                                NativeFunctionPtr func) {

  static std::unique_ptr<remill::IntrinsicTable> intrinsics;
  if (!intrinsics.get()) {
    intrinsics.reset(new remill::IntrinsicTable(gModule));
  }

  auto F = gModule->getFunction(func->get_name());
  CHECK(nullptr != F)
      << "Could not get func " << func->get_name();

  if (!F->empty()) {
    LOG(WARNING)
        << "Asking to re-insert function: " << func->get_name()
        << "; returning current function instead";
    return F;
  }

  auto word_type = llvm::Type::getIntNTy(*gContext, gArch->address_size);

  remill::CloneBlockFunctionInto(F);

  // For ease of debugging generated code, don't allow lifted functions to
  // be inlined. This will make lifted and native call graphs one-to-one.
  F->addFnAttr(llvm::Attribute::NoInline);

  std::unique_ptr<remill::InstructionLifter> lifter(
      new remill::InstructionLifter(word_type, intrinsics.get()));

  TranslationContext ctx;
  ctx.lifter = lifter.get();
  ctx.natM = mod;
  ctx.natF = func;
  ctx.M = gModule;
  ctx.F = F;

  // Create basic blocks for each basic block in the original function.
  for (auto block_info : func->get_blocks()) {
    ctx.va_to_bb[block_info.first] = llvm::BasicBlock::Create(
        *gContext, block_info.second->get_name(), F);
  }

  // Create a branch from the end of the entry block to the first block
  llvm::BranchInst::Create(ctx.va_to_bb[func->get_start()], &(F->front()));

  // Lift every basic block into the functions.
  auto good = true;
  for (auto block_info : func->get_blocks()) {
    ctx.natB = block_info.second;
    good = good && LiftBlockIntoFunction(ctx);
  }

  return good ? F : nullptr;
}

struct DataSectionVar {
  const DataSection *section;
  llvm::StructType *opaque_type;
  llvm::GlobalVariable *var;
};

// Insert all global data before we insert the CFG
static bool InsertDataSections(NativeModulePtr natMod) {
  auto &globaldata = natMod->getData();

  std::vector<DataSectionVar> gvars;

  // pre-create references to all data sections
  // as later we may have data references that are
  // from one section into another

  for (auto &dt : globaldata) {
    std::stringstream ss;
    ss << "data_" << std::hex << dt.getBase();
    auto bufferName = ss.str();

    LOG(INFO)
        << "Inserting global data section named " << bufferName;

    auto st_opaque = llvm::StructType::create(gModule->getContext());
    // Used to be PrivateLinkage, but that emitted
    // .objs that would not link with MSVC
    auto g = new llvm::GlobalVariable(
        *gModule, st_opaque, dt.isReadOnly(),
        llvm::GlobalVariable::InternalLinkage,
        nullptr, bufferName);
    gvars.push_back({&dt, st_opaque, g});
  }

  // actually populate the data sections
  for (auto &var : gvars) {

    // Data we use to create LLVM values for this section
    // secContents is the actual values we will be inserting
    std::vector<llvm::Constant *> secContents;
    // data_section_types is their types, which are needed to initialize
    // the global variable
    std::vector<llvm::Type *> data_section_types;

    dataSectionToTypesContents(globaldata, *var.section, gModule, secContents,
                               data_section_types, true);

    // fill in the opaqure structure with actual members
    var.opaque_type->setBody(data_section_types, true);

    // create an initializer list using the now filled in opaque
    // structure type
    auto cst = llvm::ConstantStruct::get(var.opaque_type, secContents);
    // align on pointer size boundary, max needed by SSE instructions
    var.var->setAlignment(ArchPointerSize(gModule));
    var.var->setInitializer(cst);

  }
  return true;
}

void RenameLiftedFunctions(NativeModulePtr natMod,
                           const std::set<VA> &entry_point_pcs) {
  // Rename the functions to have their 'nice' names, where available.
  for (auto &f : natMod->get_funcs()) {
    NativeFunctionPtr native_func = f.second;
    if (entry_point_pcs.count(native_func->get_start())) {
      continue;
    }

    auto sub_name = native_func->get_name();
    auto F = gModule->getFunction(sub_name);
    std::stringstream ss;
    ss << "callback_" << sub_name;
    if (!gModule->getFunction(ss.str())) {
      auto &sym_name = native_func->get_symbol_name();
      if (!sym_name.empty()) {
        F->setName(sym_name);
      }
    }
  }
}

static void InitLiftedFunctions(NativeModulePtr natMod) {
  for (auto &f : natMod->get_funcs()) {
    NativeFunctionPtr native_func = f.second;
    auto fname = native_func->get_name();
    auto F = gModule->getFunction(fname);

    if (!F) {
      F = llvm::dyn_cast<llvm::Function>(
          gModule->getOrInsertFunction(fname, LiftedFunctionType()));

      CHECK(F != nullptr)
          << "Could not insert function " << fname << " into module";

      ArchSetCallingConv(gModule, F);
      // make local functions 'static'
      F->setLinkage(llvm::GlobalValue::InternalLinkage);
      LOG(INFO)
          << "Inserted function: " << fname;
    } else {
      LOG(INFO)
          << "Already inserted function: " << fname << ", skipping.";
    }
  }
}

static void InitExternalData(NativeModulePtr natMod) {
  for (auto dr : natMod->getExtDataRefs()) {
    auto dsize = dr->getDataSize();
    auto symname = dr->getSymbolName();
    auto extType = llvm::ArrayType::get(llvm::Type::getInt8Ty(*gContext),
                                        dsize);
    auto gv = llvm::dyn_cast<llvm::GlobalValue>(
        gModule->getOrInsertGlobal(symname, extType));

    CHECK(gv != nullptr)
        << "Could not make global value for external data symbol " << symname;

    if (dr->isWeak()) {
      gv->setLinkage(llvm::GlobalValue::ExternalWeakLinkage);
    } else {
      gv->setLinkage(llvm::GlobalValue::ExternalLinkage);
    }

    llvm::Triple triple(gModule->getTargetTriple());
    if (llvm::Triple::Win32 == triple.getOS()) {
      gv->setDLLStorageClass(llvm::GlobalValue::DLLImportStorageClass);
    }
  }
}

// Iterate over the list of external functions and insert them as
// global functions.
static void InitExternalCode(NativeModulePtr natMod) {
  for (auto e : natMod->getExtCalls()) {
    auto conv = e->getCallingConvention();
    auto argCount = e->getNumArgs();
    auto symName = e->getSymbolName();
    auto funcSign = e->getFunctionSignature();

    // Create the function if it is not already there.
    auto F = gModule->getFunction(symName);
    if (F) {
      continue;
    }

    if (ExternalCodeRef::McsemaCall == conv) {
       // normal mcsema function prototypes
      F = llvm::dyn_cast<llvm::Function>(gModule->getOrInsertFunction(
          ArchNameMcSemaCall(symName), LiftedFunctionType()));
      ArchSetCallingConv(gModule, F);
      F->setLinkage(llvm::GlobalValue::ExternalLinkage);
      continue;
    }

    std::vector<llvm::Type *> arguments;
    llvm::Type *returnType = nullptr;

    // Create arguments.
    const auto Arch = SystemArch(gModule);
    const auto OS = SystemOS(gModule);
    for (auto i = 0; i < argCount; i++) {
      if (_X86_64_ == Arch) {
        if (llvm::Triple::Win32 == OS) {
          if (funcSign.c_str()[i] == 'F') {
            arguments.push_back(llvm::Type::getDoubleTy(*gContext));
          } else {
            arguments.push_back(llvm::Type::getInt64Ty(*gContext));
          }
        } else if (llvm::Triple::Linux == OS) {
          arguments.push_back(llvm::Type::getInt64Ty(*gContext));

        } else {
          LOG(FATAL)
              << "Unknown OS Type!";
        }
      } else {
        arguments.push_back(llvm::Type::getInt32Ty(*gContext));
      }
    }

    // Create function type
    switch (e->getReturnType()) {
      case ExternalCodeRef::NoReturn:
      case ExternalCodeRef::VoidTy:
        returnType = llvm::Type::getVoidTy(*gContext);
        break;

      case ExternalCodeRef::Unknown:
      case ExternalCodeRef::IntTy:
        if (natMod->is64Bit()) {
          returnType = llvm::Type::getInt64Ty(*gContext);
        } else {
          returnType = llvm::Type::getInt32Ty(*gContext);
        }
        break;

      default:
        LOG(FATAL)
            << "Encountered an unknown return type while translating function";
    }

    auto FTy = llvm::FunctionType::get(returnType, arguments, false);
    if (e->isWeak()) {
      F = llvm::Function::Create(FTy, llvm::GlobalValue::ExternalWeakLinkage,
                                 symName, gModule);
    } else {
      F = llvm::Function::Create(FTy, llvm::GlobalValue::ExternalLinkage,
                                 symName, gModule);
    }

    if (e->getReturnType() == ExternalCodeRef::NoReturn) {
      F->setDoesNotReturn();
    }

    // Set calling convention
    if (natMod->is64Bit()) {
      ArchSetCallingConv(gModule, F);
    } else {
      F->setCallingConv(getLLVMCC(conv));
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
  builder.OptLevel = 0;  // -O0.
  builder.SizeLevel = 0;  // -Oz
  builder.Inliner = llvm::createFunctionInliningPass(999);
  builder.LibraryInfo = TLI;  // Deleted by `llvm::~PassManagerBuilder`.
  builder.DisableTailCalls = false;  // Enable tail calls.
  builder.DisableUnrollLoops = false;  // Unroll loops!
  builder.DisableUnitAtATime = false;
  builder.SLPVectorize = false;  // Don't produce vector operations.
  builder.LoopVectorize = false;  // Don't produce vector operations.
  builder.LoadCombine = false;  // Don't coalesce loads.
  builder.MergeFunctions = false;  // Try to deduplicate functions.
  builder.VerifyInput = false;
  builder.VerifyOutput = false;

  builder.populateFunctionPassManager(func_manager);
  builder.populateModulePassManager(module_manager);

  func_manager.add(llvm::createCFGSimplificationPass());
  func_manager.add(llvm::createPromoteMemoryToRegisterPass());
  func_manager.add(llvm::createReassociatePass());
  func_manager.add(llvm::createInstructionCombiningPass());
  func_manager.add(llvm::createDeadStoreEliminationPass());
  func_manager.add(llvm::createDeadCodeEliminationPass());

  func_manager.doInitialization();
  for (auto &func : *gModule) {
    if (func.getName().startswith("sub_")) {
      func_manager.run(func);
    }
  }
  func_manager.doFinalization();
  module_manager.run(*gModule);
}

static bool LiftFunctionsIntoModule(NativeModulePtr natMod) {
  llvm::legacy::FunctionPassManager func_pass_manager(gModule);
  func_pass_manager.add(llvm::createCFGSimplificationPass());
  func_pass_manager.add(llvm::createPromoteMemoryToRegisterPass());
  func_pass_manager.add(llvm::createReassociatePass());
  func_pass_manager.add(llvm::createInstructionCombiningPass());
  func_pass_manager.add(llvm::createDeadStoreEliminationPass());
  func_pass_manager.add(llvm::createDeadCodeEliminationPass());

  func_pass_manager.doInitialization();

  for (auto &func_info : natMod->get_funcs()) {
    NativeFunctionPtr f = func_info.second;
    auto lifted_func = InsertFunctionIntoModule(natMod, f);
    if (!lifted_func) {
      LOG(ERROR)
          << "Could lift function: " << f->get_name();
      return false;
    }
    func_pass_manager.run(*lifted_func);
  }

  func_pass_manager.doFinalization();
  return true;
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
      LOG(INFO)
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
        LOG(INFO)
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
  if (auto used = gModule->getGlobalVariable("llvm.used")) {
    used->eraseFromParent();
  }

  if (auto intrinsic_keeper = gModule->getFunction("__remill_intrinsics")) {
    intrinsic_keeper->eraseFromParent();
  }

  if (auto basic_block = gModule->getFunction("__remill_basic_block")) {
    basic_block->eraseFromParent();
  }

  if (auto mark_used = gModule->getFunction("__remill_mark_as_used")) {
    mark_used->eraseFromParent();
  }
}

bool LiftCodeIntoModule(NativeModulePtr natMod) {
  auto isels = FindISELs();

  InitLiftedFunctions(natMod);
  InitExternalData(natMod);
  InitExternalCode(natMod);
  InsertDataSections(natMod);
  if (!LiftFunctionsIntoModule(natMod)) {
    return false;
  } else {
    RemoveIntrinsics();
    LOG(INFO)
        << "Optimizing module.";
    RemoveISELs(isels);
    RunO3();
    return true;
  }
}
