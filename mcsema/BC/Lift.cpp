/*
 Copyright (c) 2013, Trail of Bits
 All rights reserved.

 Redistribution and use in source and binary forms, with or without modification,
 are permitted provided that the following conditions are met:

 Redistributions of source code must retain the above copyright notice, this
 list of conditions and the following disclaimer.

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

#include <llvm/Support/CommandLine.h>

#include <vector>

#include "mcsema/Arch/Arch.h"
#include "mcsema/Arch/Dispatch.h"
#include "mcsema/BC/Lift.h"
#include "mcsema/BC/Util.h"
#include "mcsema/CFG/CFG.h"

#include "mcsema/CFG/Externals.h"
#include "mcsema/cfgToLLVM/TransExcn.h"

#include "mcsema/BC/Util.h"

static llvm::cl::opt<bool> IgnoreUnsupportedInsts(
    "ignore-unsupported",
    llvm::cl::desc(
        "Ignore unsupported instructions."),
    llvm::cl::init(false));

static llvm::cl::opt<bool> AddTracer(
    "add-reg-tracer",
    llvm::cl::desc(
        "Add a debug function that prints out the register state before "
        "each lifted instruction execution."),
    llvm::cl::init(false));

static llvm::cl::opt<bool> AddBreakpoints(
    "add-breakpoints",
    llvm::cl::desc(
        "Add 'breakpoint' functions between every lifted instruction. This "
        "allows one to set a breakpoint, in the lifted code, just before a "
        "specific lifted instruction is executed."),
    llvm::cl::init(false));

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
      throw TErr(__LINE__, __FILE__, "Unknown calling convention!");
      break;
  }

  return llvm::CallingConv::C;
}

//
// common case for arithmetic instructions
// some instructions, like inc and dec, do not need to do this
//


static void CreateInstrBreakpoint(llvm::BasicBlock *B, VA pc) {
  auto F = B->getParent();
  auto M = F->getParent();

  std::stringstream ss;
  ss << "breakpoint_" << std::hex << pc;
  auto instr_func_name = ss.str();

  auto IFT = M->getFunction(instr_func_name);
  if (!IFT) {

    IFT = llvm::Function::Create(
        LiftedFunctionType(), llvm::GlobalValue::ExternalLinkage,
        instr_func_name, M);

    IFT->addFnAttr(llvm::Attribute::OptimizeNone);
    IFT->addFnAttr(llvm::Attribute::NoInline);

    auto &C = M->getContext();
    llvm::IRBuilder<> ir(llvm::BasicBlock::Create(C, "", IFT));
    ir.CreateRetVoid();
  }

  auto state_ptr = &*F->arg_begin();
  llvm::CallInst::Create(IFT, {state_ptr}, "", B);
}

static void AddRegStateTracer(llvm::BasicBlock *B) {
  auto F = B->getParent();
  auto M = F->getParent();
  auto IFT = ArchGetOrCreateRegStateTracer(M);

  auto state_ptr = &*F->arg_begin();
  llvm::CallInst::Create(IFT, {state_ptr}, "", B);
}

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


// Take the supplied MCInst and turn it into a series of LLVM instructions.
// Insert those instructions into the supplied block.
// Here's the philosophy:
// LLVM MCInst opcodes encode X86 instructions by, roughly:
//
//    mnemonic[bitwidth]<operandlist>
//
//  So for example, there are many different encodings and bitwidths of the
//  "add" mnemonic. each combination has its own space in the opcodes enum
//
//  We're narrowing from the space of LLVM MCInst opcodes in a few steps:
//     1. First by width. we take each mnemonic and classify it by width.
//        there are templated functions for dealing with mnemonic / operand
//        pairs, parameterized around operand width
//     2. next by operand type. Within each parameterized wrapper, we
//        'unrwrap' by extracting each operand and producing input values
//        to the instructions
//     3. finally, in an inner step, we define the instruction semantics
//        entirely in terms of LLVM Value objects. This is where the 'meat'
//        of semantic modeling takes places.
//     The breakdown looks something like this:
//
//     X86::CMP8rr -> [1] -> doCmpRR<8> -> [2] doCmpVV<8> -> [3]
//
//     The innermost is where most of the intelligent decisions happen.
//
static InstTransResult LiftInstIntoBlockImpl(TranslationContext &ctx,
                                      llvm::BasicBlock *&block) {
  InstTransResult itr = ContinueBlock;

  // For conditional instructions, get the "true" and "false" targets.
  // This will also look up the target for nonconditional jumps.
  //string trueStrName = "block_0x" + to_string<VA>(ip->get_tr(), hex);
  //string falseStrName = "block_0x" + to_string<VA>(ip->get_fa(), hex);

  auto &inst = ctx.natI->get_inst();

  if (auto lifter = ArchGetInstructionLifter(inst)) {
    itr = ArchLiftInstruction(ctx, block, lifter);

    if (TranslateError == itr || TranslateErrorUnsupported == itr) {
      std::cerr << "Error translating instruction at " << std::hex
                << ctx.natI->get_loc() << std::endl;
    }

  // Instruction translation not defined.
  } else {
    auto opcode = inst.getOpcode();
    std::cerr << "Error translating instruction at " << std::hex
              << ctx.natI->get_loc() << "; unsupported opcode " << std::dec
              << opcode << std::endl;

    // In the case that we can't find the opcode, try building it out with
    // inline assembly calls in LLVM instead.
    if (IgnoreUnsupportedInsts) {
      ArchBuildInlineAsm(inst, block);
      return itr;
    } else {
      return TranslateErrorUnsupported;
    }
  }
  return itr;
}

static InstTransResult LiftInstIntoBlock(TranslationContext &ctx,
                                         llvm::BasicBlock *&block,
                                         bool doAnnotation) {
  auto pc = ctx.natI->get_loc();

  // Update the program counter.
  auto pc_ty = llvm::Type::getIntNTy(block->getContext(), ArchAddressSize());
  GENERIC_MC_WRITEREG(
      block,
      llvm::X86::EIP,
      llvm::ConstantInt::get(pc_ty, pc));

  // At the beginning of the block, make a call to a dummy function with the
  // same name as the block. This function call cannot be optimized away, and
  // so it serves as a useful marker for where we are.
  if (AddBreakpoints) {
    CreateInstrBreakpoint(block, pc);
  }

  if (AddTracer) {
    AddRegStateTracer(block);
  }

  auto lift_status = LiftInstIntoBlockImpl(ctx, block);

  // we need to loop over this function and find any un-annotated instructions.
  // then we annotate each instruction
  if (doAnnotation) {
    AnnotateInsts(ctx.F, pc);
  }

  return lift_status;
}

static bool LiftBlockIntoFunction(TranslationContext &ctx) {
  auto didError = false;

  //first, either create or look up the LLVM basic block for this native
  //block. we are either creating it for the first time, or, we are
  //going to look up a blank block
  auto block_name = ctx.natB->get_name();
  auto curLLVMBlock = ctx.va_to_bb[ctx.natB->get_base()];

  //then, create a basic block for every follow of this block, if we do not
  //already have that basic block in our LLVM CFG
  const auto &follows = ctx.natB->get_follows();
  for (auto succ_block_va : follows) {
    if (!ctx.va_to_bb.count(succ_block_va)) {
      throw TErr(__LINE__, __FILE__, "Missing successor block!");
    }
  }

  //now, go through each statement and translate it into LLVM IR
  //statements that branch SHOULD be the last statement in a block
  for (auto inst : ctx.natB->get_insts()) {
    ctx.natI = inst;
    switch (LiftInstIntoBlock(ctx, curLLVMBlock, true)) {
      case ContinueBlock:
        break;
      case EndBlock:
      case EndCFG:
        goto done;
      case TranslateErrorUnsupported:
        didError = !IgnoreUnsupportedInsts;
        goto done;
      case TranslateError:
        didError = true;
        goto done;
    }
  }
done:

  if (curLLVMBlock->getTerminator()) {
    return didError;
  }

  // we may need to insert a branch inst to the successor
  // if the block ended on a non-terminator (this happens since we
  // may split blocks in cfg recovery to avoid code duplication)
  if (follows.size() == 1) {
    llvm::BranchInst::Create(ctx.va_to_bb[follows.front()], curLLVMBlock);
  } else {
    new llvm::UnreachableInst(curLLVMBlock->getContext(), curLLVMBlock);
  }

  return didError;
}

static bool InsertFunctionIntoModule(NativeModulePtr mod,
                                     NativeFunctionPtr func, llvm::Module *M) {
  auto &C = M->getContext();
  auto F = M->getFunction(func->get_name());
  if (!F) {
    throw TErr(__LINE__, __FILE__, "Could not get func " + func->get_name());
  }

  if (!F->empty()) {
    std::cout << "WARNING: Asking to re-insert function: " << func->get_name()
              << std::endl << "\tReturning current function instead"
              << std::endl;
    return true;
  }

  auto entryBlock = llvm::BasicBlock::Create(F->getContext(), "entry", F);
  ArchAllocRegisterVars(entryBlock);

  TranslationContext ctx;
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
  llvm::BranchInst::Create(ctx.va_to_bb[func->get_start()], entryBlock);

  // Lift every basic block into the functions.
  auto error = false;
  for (auto block_info : func->get_blocks()) {
    ctx.natB = block_info.second;
    error = LiftBlockIntoFunction(ctx) || error;
  }

  // For ease of debugging generated code, don't allow lifted functions to
  // be inlined. This will make lifted and native call graphs one-to-one.
  F->addFnAttr(llvm::Attribute::NoInline);

  //we should be done, having inserted every block into the module
  return !error;
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
    std::cout << "inserting global data section named ";
    std::cout << bufferName << std::endl;

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

    // fill in the opaque structure with actual members
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

      TASSERT(F != nullptr, "Could not insert function into module");

      ArchSetCallingConv(M, F);
      // make local functions 'static'
      F->setLinkage(llvm::GlobalValue::InternalLinkage);
      std::cout << "Inserted function: " << fname << std::endl;
    } else {
      std::cout << "Already inserted function: " << fname << ", skipping."
                << std::endl;
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
    TASSERT(gv != nullptr, "Could not make global value!");

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
          TASSERT(false, "Unknown OS Type!");
        }
      } else {
        arguments.push_back(llvm::Type::getInt32Ty(C));
      }
    }

    //create function type
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
        throw TErr(
            __LINE__, __FILE__,
            "Encountered an unknown return type while translating function");
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
      std::string fname = f->get_name();
      std::cerr << "Could not insert function: " << fname
                << " into the LLVM module" << std::endl;
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
