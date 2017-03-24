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

 Neither the name of the {organization} nor the names of its
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
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Metadata.h>
#include <llvm/IR/MDBuilder.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>

#include <memory>
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

//#include "mcsema/CFG/Externals.h"

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
    if (auto tail_called_func = GetLiftedFunction(pc)) {
      LOG(INFO)
          << "Missing block is a tail call to sub_" << std::hex << pc;

      llvm::ReturnInst::Create(
          *gContext,
          AddSubFuncCall(block, tail_called_func),
          block);

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
      InlineSubFuncCall(block, GetLiftedFunction(instr->branch_taken_pc));
      return false;

    case remill::Instruction::kCategoryIndirectFunctionCall:
      InlineSubFuncCall(block, ctx.lifter->intrinsics->function_call);
      return false;

    case remill::Instruction::kCategoryFunctionReturn:
      llvm::ReturnInst::Create(
          *gContext, remill::LoadMemoryPointer(block), block);
      return true;

    case remill::Instruction::kCategoryConditionalBranch:
    case remill::Instruction::kCategoryConditionalAsyncHyperCall:
      LiftConditionalBranch(ctx, block, instr);
      return true;

    case remill::Instruction::kCategoryAsyncHyperCall:
      InlineSubFuncCall(block, ctx.lifter->intrinsics->async_hyper_call);
      return false;
  }
}

static bool LiftInstIntoBlock(TranslationContext &ctx,
                              llvm::BasicBlock *block,
                              bool is_last) {
  static const remill::Arch *arch = nullptr;
  if (!arch) {
    arch = remill::GetGlobalArch();
  }

  auto instr_addr = ctx.natI->get_loc();
  auto &bytes = ctx.natI->get_bytes();
  std::unique_ptr<remill::Instruction> instr(
      arch->DecodeInstruction(instr_addr, bytes));

  CHECK(instr->IsValid())
      << "Cannot decode instruction at " << std::hex << instr_addr;

  DLOG_IF(WARNING, bytes.size() != instr->NumBytes())
      << "Size of decoded instruction at " << std::hex << instr_addr
      << " (" << std::dec << instr->NumBytes()
      << ") doesn't match input instruction size ("
      << bytes.size() << ").";

  auto ret = ctx.lifter->LiftIntoBlock(instr.get(), block);

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
          << "Block " << std::hex << block_pc << " has no terminator, and "
          << " instruction at " << std::hex << ctx.natI->get_loc()
          << " is not a local no-return function call.";

      new llvm::UnreachableInst(block->getContext(), block);
    }
  }

  block->dump();
  return good;
}

static bool InsertFunctionIntoModule(NativeModulePtr mod,
                                     NativeFunctionPtr func,
                                     llvm::Module *M) {

  static std::unique_ptr<remill::IntrinsicTable> intrinsics;
  if (!intrinsics.get()) {
    intrinsics.reset(new remill::IntrinsicTable(M));
  }

  auto &C = M->getContext();
  auto F = M->getFunction(func->get_name());
  CHECK(nullptr != F)
      << "Could not get func " << func->get_name();

  if (!F->empty()) {
    LOG(WARNING)
        << "Asking to re-insert function: " << func->get_name()
        << "; returning current function instead";
    return true;
  }

  auto arch = remill::GetGlobalArch();
  auto word_type = llvm::Type::getIntNTy(C, arch->address_size);

  auto old_cc = F->getCallingConv();
  remill::CloneBlockFunctionInto(F);

  // Remill uses the fastcall calling convention, but we want to use the OS-
  // specific one.
  F->setCallingConv(old_cc);

  // For ease of debugging generated code, don't allow lifted functions to
  // be inlined. This will make lifted and native call graphs one-to-one.
  F->addFnAttr(llvm::Attribute::NoInline);

  std::unique_ptr<remill::InstructionLifter> lifter(
      new remill::InstructionLifter(word_type, intrinsics.get()));

  TranslationContext ctx;
  ctx.lifter = lifter.get();
  ctx.natM = mod;
  ctx.natF = func;
  ctx.M = M;
  ctx.F = F;

  // Create basic blocks for each basic block in the original function.
  for (auto block_info : func->get_blocks()) {
    ctx.va_to_bb[block_info.first] = llvm::BasicBlock::Create(
        C, block_info.second->get_name(), F);
  }

  // Create a branch from the end of the entry block to the first block
  llvm::BranchInst::Create(ctx.va_to_bb[func->get_start()], &(F->front()));

  // Lift every basic block into the functions.
  auto good = true;
  for (auto block_info : func->get_blocks()) {
    ctx.natB = block_info.second;
    good = good && LiftBlockIntoFunction(ctx);
  }

  return good;
}

struct DataSectionVar {
  const DataSection *section;
  llvm::StructType *opaque_type;
  llvm::GlobalVariable *var;
};

static bool InsertDataSections(NativeModulePtr natMod, llvm::Module *M) {

  auto &globaldata = natMod->getData();
  //insert all global data before we insert the CFG

  std::vector<DataSectionVar> gvars;

  // pre-create references to all data sections
  // as later we may have data references that are
  // from one section into another

  for (auto &dt : globaldata) {
    std::stringstream ss;
    ss << "data_" << std::hex << dt.getBase();

    std::string bufferName = ss.str();

    //report << "inserting global data section named ";
    //report << bufferName << "\n";
    LOG(INFO)
        << "Inserting global data section named " << bufferName;

    auto st_opaque = llvm::StructType::create(M->getContext());
    // Used to be PrivateLinkage, but that emitted
    // .objs that would not link with MSVC
    auto g = new llvm::GlobalVariable(
        *M, st_opaque, dt.isReadOnly(),
        llvm::GlobalVariable::InternalLinkage,
        nullptr, bufferName);
    gvars.push_back({&dt, st_opaque, g});
  }

  // actually populate the data sections
  for (auto &var : gvars) {

    //data we use to create LLVM values for this section
    // secContents is the actual values we will be inserting
    std::vector<llvm::Constant *> secContents;
    // data_section_types is their types, which are needed to initialize
    // the global variable
    std::vector<llvm::Type *> data_section_types;

    dataSectionToTypesContents(globaldata, *var.section, M, secContents,
                               data_section_types, true);

    // fill in the opaqure structure with actual members
    var.opaque_type->setBody(data_section_types, true);

    // create an initializer list using the now filled in opaque
    // structure type
    auto cst = llvm::ConstantStruct::get(var.opaque_type, secContents);
    // align on pointer size boundary, max needed by SSE instructions
    var.var->setAlignment(ArchPointerSize(M));
    var.var->setInitializer(cst);

  }
  return true;
}

void RenameLiftedFunctions(NativeModulePtr natMod, llvm::Module *M,
                           const std::set<VA> &entry_point_pcs) {
  // Rename the functions to have their 'nice' names, where available.
  for (auto &f : natMod->get_funcs()) {
    NativeFunctionPtr native_func = f.second;
    if (entry_point_pcs.count(native_func->get_start())) {
      continue;
    }

    auto sub_name = native_func->get_name();
    auto F = M->getFunction(sub_name);
    std::stringstream ss;
    ss << "callback_" << sub_name;
    if (!M->getFunction(ss.str())) {
      auto &sym_name = native_func->get_symbol_name();
      if (!sym_name.empty()) {
        F->setName(sym_name);
      }
    }
  }
}

static void InitLiftedFunctions(NativeModulePtr natMod, llvm::Module *M) {
  for (auto &f : natMod->get_funcs()) {
    NativeFunctionPtr native_func = f.second;
    auto fname = native_func->get_name();
    auto F = M->getFunction(fname);

    if (!F) {
      F = llvm::dyn_cast<llvm::Function>(
          M->getOrInsertFunction(fname, LiftedFunctionType()));

      CHECK(F != nullptr)
          << "Could not insert function " << fname << " into module";

      ArchSetCallingConv(M, F);
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

static void InitExternalData(NativeModulePtr natMod, llvm::Module *M) {
  for (auto dr : natMod->getExtDataRefs()) {
    auto dsize = dr->getDataSize();
    auto symname = dr->getSymbolName();
    auto extType = llvm::ArrayType::get(llvm::Type::getInt8Ty(M->getContext()),
                                        dsize);
    auto gv = llvm::dyn_cast<llvm::GlobalValue>(
        M->getOrInsertGlobal(symname, extType));

    CHECK(gv != nullptr)
        << "Could not make global value for external data symbol " << symname;

    if (dr->isWeak()) {
      gv->setLinkage(llvm::GlobalValue::ExternalWeakLinkage);
    } else {
      gv->setLinkage(llvm::GlobalValue::ExternalLinkage);
    }

    llvm::Triple triple(M->getTargetTriple());
    if (llvm::Triple::Win32 == triple.getOS()) {
      gv->setDLLStorageClass(llvm::GlobalValue::DLLImportStorageClass);
    }
  }
}

// Iterate over the list of external functions and insert them as
// global functions.
static void InitExternalCode(NativeModulePtr natMod, llvm::Module *M) {
  for (auto e : natMod->getExtCalls()) {
    auto conv = e->getCallingConvention();
    auto argCount = e->getNumArgs();
    auto symName = e->getSymbolName();
    auto funcSign = e->getFunctionSignature();

    // Create the function if it is not already there.
    auto &C = M->getContext();
    auto F = M->getFunction(symName);
    if (F) {
      continue;
    }

    if (ExternalCodeRef::McsemaCall == conv) {
       // normal mcsema function prototypes
      F = llvm::dyn_cast<llvm::Function>(M->getOrInsertFunction(
          ArchNameMcSemaCall(symName), LiftedFunctionType()));
      ArchSetCallingConv(M, F);
      F->setLinkage(llvm::GlobalValue::ExternalLinkage);
      continue;
    }

    std::vector<llvm::Type *> arguments;
    llvm::Type *returnType = nullptr;

    // Create arguments.
    const auto Arch = SystemArch(M);
    const auto OS = SystemOS(M);
    for (auto i = 0; i < argCount; i++) {
      if (_X86_64_ == Arch) {
        if (llvm::Triple::Win32 == OS) {
          if (funcSign.c_str()[i] == 'F') {
            arguments.push_back(llvm::Type::getDoubleTy(C));
          } else {
            arguments.push_back(llvm::Type::getInt64Ty(C));
          }
        } else if (llvm::Triple::Linux == OS) {
          arguments.push_back(llvm::Type::getInt64Ty(C));

        } else {
          LOG(FATAL)
              << "Unknown OS Type!";
        }
      } else {
        arguments.push_back(llvm::Type::getInt32Ty(C));
      }
    }

    // Create function type
    switch (e->getReturnType()) {
      case ExternalCodeRef::NoReturn:
      case ExternalCodeRef::VoidTy:
        returnType = llvm::Type::getVoidTy(C);
        break;

      case ExternalCodeRef::Unknown:
      case ExternalCodeRef::IntTy:
        if (natMod->is64Bit()) {
          returnType = llvm::Type::getInt64Ty(C);
        } else {
          returnType = llvm::Type::getInt32Ty(C);
        }
        break;

      default:
        LOG(FATAL)
            << "Encountered an unknown return type while translating function";
    }

    auto FTy = llvm::FunctionType::get(returnType, arguments, false);
    if (e->isWeak()) {
      F = llvm::Function::Create(FTy, llvm::GlobalValue::ExternalWeakLinkage,
                                 symName, M);
    } else {
      F = llvm::Function::Create(FTy, llvm::GlobalValue::ExternalLinkage,
                                 symName, M);
    }

    if (e->getReturnType() == ExternalCodeRef::NoReturn) {
      F->setDoesNotReturn();
    }

    //set calling convention
    if (natMod->is64Bit()) {
      ArchSetCallingConv(M, F);
    } else {
      F->setCallingConv(getLLVMCC(conv));
    }
  }
}

static bool LiftFunctionsIntoModule(NativeModulePtr natMod, llvm::Module *M) {
  // populate functions
  for (auto &func_info : natMod->get_funcs()) {
    NativeFunctionPtr f = func_info.second;
    if (!InsertFunctionIntoModule(natMod, f, M)) {
      LOG(ERROR)
          << "Could lift function: " << f->get_name();
      return false;
    }
  }
  return true;
}

bool LiftCodeIntoModule(NativeModulePtr natMod, llvm::Module *M) {
  InitLiftedFunctions(natMod, M);
  InitExternalData(natMod, M);
  InitExternalCode(natMod, M);
  InsertDataSections(natMod, M);
  return LiftFunctionsIntoModule(natMod, M);
}
