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
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Metadata.h>
#include <llvm/IR/MDBuilder.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>

#include <llvm/Support/CommandLine.h>

#include <vector>

#include "mcsema/Arch/Dispatch.h"

#include "mcsema/cfgToLLVM/raiseX86.h"
#include "mcsema/cfgToLLVM/x86Instrs.h"
#include "mcsema/cfgToLLVM/x86Helpers.h"
#include "mcsema/cfgToLLVM/ArchOps.h"
#include "mcsema/cfgToLLVM/InstructionDispatch.h"
#include "mcsema/cfgToLLVM/Externals.h"

bool ignoreUnsupportedInsts = false;

static llvm::cl::opt<bool> AddBreakpoints(
    "add-breakpoints",
    llvm::cl::desc(
        "Add debug breakpoint function calls before each lifted instruction."),
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

llvm::Value *INTERNAL_M_READ(unsigned width, unsigned addrspace,
                             llvm::BasicBlock *b, llvm::Value *addr) {
  llvm::Value *readLoc = addr;
  llvm::LLVMContext &C = b->getContext();

  auto readLocTy = readLoc->getType();
  llvm::Type *PtrTy = llvm::Type::getIntNPtrTy(C, width, addrspace);

  if (readLocTy != PtrTy) {
    if (readLocTy->isPointerTy()) {
      llvm::DataLayout DL(b->getParent()->getParent());
      llvm::Type *IntPtrTy = DL.getIntPtrType(C, addrspace);
      readLoc = new llvm::PtrToIntInst(readLoc, IntPtrTy, "", b);
    }

    TASSERT(readLoc->getType()->isIntegerTy(), "Expected integer type.");
    readLoc = new llvm::IntToPtrInst(readLoc, PtrTy, "", b);
  }

  auto is_volatile = addrspace != 0;
  return new llvm::LoadInst(readLoc, "", is_volatile, b);
}

void INTERNAL_M_WRITE(int width, unsigned addrspace, llvm::BasicBlock *b,
                      llvm::Value *addr, llvm::Value *data) {
  llvm::Value *writeLoc = addr;
  llvm::LLVMContext &C = b->getContext();
  auto writeLocTy = writeLoc->getType();
  llvm::Type *PtrTy = llvm::Type::getIntNPtrTy(C, width, addrspace);

  if (writeLocTy != PtrTy) {
    if (writeLocTy->isPointerTy()) {
      llvm::DataLayout DL(b->getParent()->getParent());
      llvm::Type *IntPtrTy = DL.getIntPtrType(C, addrspace);
      writeLoc = new llvm::PtrToIntInst(writeLoc, IntPtrTy, "", b);
    }

    TASSERT(writeLoc->getType()->isIntegerTy(), "Expected integer type.");

    writeLoc = new llvm::IntToPtrInst(writeLoc, PtrTy, "", b);
  }

  auto is_volatile = addrspace != 0;
  (void) new llvm::StoreInst(data, writeLoc, is_volatile, b);
}

void M_WRITE_T(NativeInstPtr ip, llvm::BasicBlock *b, llvm::Value *addr,
               llvm::Value *data, llvm::Type *ptrtype) {
  //this is also straightforward
  llvm::Value *writeLoc = addr;
  unsigned addrspace = ip->get_addr_space();

  TASSERT(ptrtype->getPointerAddressSpace() == addrspace,
          "Mismatched pointer address spaces.");

  //however, if the incoming 'addr' location is not a pointer, we must
  //first turn it into an addr

  if (addr->getType()->isPointerTy() == false) {
    writeLoc = new llvm::IntToPtrInst(addr, ptrtype, "", b);
  } else if (addr->getType() != ptrtype) {
    writeLoc = llvm::CastInst::CreatePointerCast(addr, ptrtype, "", b);
  }

  (void) new llvm::StoreInst(data, writeLoc, b);
}

static llvm::Value *GetReadReg(llvm::Function *F, MCSemaRegs reg) {
  std::stringstream ss;
  ss << ArchRegisterName(reg) << "_read";
  auto reg_name = ss.str();

  for (llvm::Instruction &I : F->front()) {
    if (I.getName().str() == reg_name) {
      return &I;
    }
  }

  std::cerr
      << "Can't find variable " << reg_name << " for register number " << reg
      << " in function " << F->getName().str() << std::endl;
  return nullptr;
}

static llvm::Value *GetWriteReg(llvm::Function *F, MCSemaRegs reg) {
  std::stringstream ss;
  ss << ArchRegisterName(reg) << "_write";
  auto reg_name = ss.str();

  for (llvm::Instruction &I : F->front()) {
    if (I.getName().str() == reg_name) {
      return &I;
    }
  }

  std::cerr
      << "Can't find variable " << reg_name << " for register number " << reg
      << " in function " << F->getName().str() << std::endl;
  return nullptr;
}

void GENERIC_MC_WRITEREG(llvm::BasicBlock *B, MCSemaRegs mc_reg,
                         llvm::Value *val) {
  auto F = B->getParent();
  auto M = F->getParent();
  auto &C = M->getContext();
  llvm::DataLayout DL(M);

  auto val_size = DL.getTypeAllocSizeInBits(val->getType());
  auto reg_ptr = GetWriteReg(F, mc_reg);

  auto reg_ptr_ty = llvm::dyn_cast<llvm::PointerType>(reg_ptr->getType());
  auto reg_ty = reg_ptr_ty->getElementType();
  auto reg_size = DL.getTypeAllocSizeInBits(reg_ty);

  if (val_size != reg_size) {
    if (val_size < reg_size) {
      val = new llvm::ZExtInst(val, reg_ty, "", B);
    } else {
      val = new llvm::TruncInst(val, reg_ty, "", B);
    }
  }

  (void) new llvm::StoreInst(val, reg_ptr, "", B);
}

llvm::Value *GENERIC_MC_READREG(llvm::BasicBlock *B, MCSemaRegs mc_reg,
                                int desired_size) {
  auto F = B->getParent();
  auto M = F->getParent();
  auto &C = M->getContext();

  if (llvm::X86::NoRegister == mc_reg) {
    std::cerr
        << "Reading 0 for no-register read-reg" << std::endl;
    return ConstantInt(desired_size, 0);
  }

  llvm::DataLayout DL(M);

  auto val_ptr = GetReadReg(F, mc_reg);
  llvm::Value *val = new llvm::LoadInst(val_ptr, "", B);
  auto val_ty = val->getType();
  auto val_size = DL.getTypeAllocSizeInBits(val_ty);

  if (desired_size != val_size) {
    if (val_ty->isIntegerTy()) {
      auto dst_ty = llvm::Type::getIntNTy(C, desired_size);
      if (desired_size < val_size) {
        val = new llvm::TruncInst(val, dst_ty, "", B);
      } else {
        val = new llvm::ZExtInst(val, dst_ty, "", B);
      }
    } else if (val_ty->isFloatTy()) {
      // TODO(pag): do somehting here?
    }
  }
  return val;
}

llvm::Value *GENERIC_READREG(llvm::BasicBlock *b, MCSemaRegs reg) {
  return GENERIC_MC_READREG(b, reg, ArchRegisterSize(reg));
}

void GENERIC_WRITEREG(llvm::BasicBlock *b, MCSemaRegs reg, llvm::Value *v) {
  return GENERIC_MC_WRITEREG(b, reg, v);
}

llvm::Value *F_READ(llvm::BasicBlock *b, MCSemaRegs flag, int size) {
  auto v = GENERIC_READREG(b, flag);
  auto &C = b->getContext();
  auto dest_ty = llvm::Type::getIntNTy(C, size);
  if (dest_ty != v->getType()) {
    v = new llvm::TruncInst(v, dest_ty, "", b);
  }
  return v;
}

llvm::Value *F_READ(llvm::BasicBlock *b, MCSemaRegs flag) {
  return F_READ(b, flag, 1);
}

void F_WRITE(llvm::BasicBlock *b, MCSemaRegs flag, llvm::Value *v) {
  auto &C = b->getContext();
  auto bool_ty = llvm::Type::getInt1Ty(C);
  auto int8_ty = llvm::Type::getInt8Ty(C);
  if (v->getType() != bool_ty) {
    v = new llvm::TruncInst(v, bool_ty, "", b);
  }
  v = new llvm::ZExtInst(v, int8_ty, "", b);
  return GENERIC_WRITEREG(b, flag, v);
}

void F_ZAP(llvm::BasicBlock *, MCSemaRegs) {

}

void F_SET(llvm::BasicBlock *b, MCSemaRegs flag) {
  F_WRITE(b, flag, CONST_V<8>(b, 1));
}

void F_CLEAR(llvm::BasicBlock *b, MCSemaRegs flag) {
  F_WRITE(b, flag, CONST_V<8>(b, 0));
}

//
// common case for arithmetic instructions
// some instructions, like inc and dec, do not need to do this
//


static void CreateInstrBreakpoint(llvm::BasicBlock *B, VA pc) {
  auto M = B->getParent()->getParent();
  auto &C = M->getContext();

  std::stringstream ss;
  ss << "breakpoint"; //_0x" << std::hex << pc;
  auto instr_func_name = ss.str();

  auto IFT = M->getFunction(instr_func_name);
  if (!IFT) {
    std::stringstream as;
    as << "  .globl " << instr_func_name << "\n";
    as << "  .type " << instr_func_name << ",@function\n";
    as << instr_func_name << ":\n";
    as << "  .cfi_startproc\n";
    as << "  ret" << "\n";
    as << "  .size " << instr_func_name << ",1\n";
    as << "  .cfi_endproc\n";
    as << "\n";
    M->appendModuleInlineAsm(as.str());

    auto VoidTy = llvm::Type::getVoidTy(M->getContext());
    auto IFTy = llvm::FunctionType::get(VoidTy, false);
    IFT = llvm::Function::Create(IFTy, llvm::GlobalValue::ExternalLinkage,
                                 instr_func_name, M);
  }

  llvm::CallInst::Create(IFT, "", B);
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
    auto r = LiftInstIntoBlock(ctx, curLLVMBlock, true);
    if (r == TranslateError) {
      didError = true;
      break;
    } else if (r == TranslateErrorUnsupported && !ignoreUnsupportedInsts) {
      didError = true;
      break;
    }
  }

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


static llvm::Constant *CreateConstantBlob(llvm::LLVMContext &ctx,
                                    const std::vector<uint8_t> &blob) {
  auto charTy = llvm::Type::getInt8Ty(ctx);
  auto arrT = llvm::ArrayType::get(charTy, blob.size());
  std::vector<llvm::Constant *> array_elements;
  for (auto cur : blob) {
    auto c = llvm::ConstantInt::get(charTy, cur);
    array_elements.push_back(c);
  }
  return llvm::ConstantArray::get(arrT, array_elements);
}

static llvm::GlobalVariable *GetSectionForDataAddr(
    const std::list<DataSection> &dataSecs, llvm::Module *M, VA data_addr,
    VA &section_base) {

  for (auto &dt : dataSecs) {
    VA start = dt.getBase();
    VA end = start + dt.getSize();

    if (data_addr >= start && data_addr < end) {
      std::stringstream ss;
      ss << "data_" << std::hex << start;
      section_base = start;
      return M->getNamedGlobal(ss.str());
    }
  }
  return nullptr;
}

static llvm::Constant* getPtrSizedValue(llvm::Module *M, llvm::Constant *v,
                                        int valsize) {
  auto final_val = v;

  //
  // this sometimes doesn't work since LLVM assembler is broken :(
  //
  if ((ArchPointerSize(M) == Pointer32 && valsize == 4)
      || (ArchPointerSize(M) == Pointer64 && valsize == 8)) {
    final_val = v;
  } else if (ArchPointerSize(M) == Pointer64 && valsize == 4) {
    auto int_val = llvm::ConstantExpr::getPtrToInt(
        v, llvm::Type::getInt64Ty(M->getContext()));
    final_val = llvm::ConstantExpr::getTrunc(
        int_val, llvm::Type::getInt32Ty(M->getContext()));
  }

  return final_val;
}

void dataSectionToTypesContents(const std::list<DataSection> &globaldata,
                                const DataSection &ds, llvm::Module *M,
                                std::vector<llvm::Constant *> &secContents,
                                std::vector<llvm::Type *> &data_section_types,
                                bool convert_to_callback) {
  // find what elements will be needed for this data section
  // There are three main types:
  // Functions: pointer to a known function in the cfg
  // Data Symbol: pointer to another data section item
  // Blob: opaque data treated as byte array
  //
  // The final data structure will look something like
  // struct data_section {
  //  function f1,
  //  function f2,
  //  uint8_t blob0[100];
  //  datasymbol d0;
  //  uint8_t blob1[200];
  //  ....
  //  };
  //
  const std::list<DataSectionEntry> &ds_entries = ds.getEntries();
  for (auto &data_sec_entry : ds_entries) {
    std::string sym_name;

    if (data_sec_entry.getSymbol(sym_name)) {

      std::cout
          << __FUNCTION__ << ": Found symbol: " << sym_name << " in "
          << std::hex << data_sec_entry.getBase() << std::endl;

      if (sym_name.find("ext_") == 0) {

        // TODO(pag): this is flaky!
        auto ext_sym_name = sym_name.c_str() + 4 /* strlen("ext_") */;

        llvm::Constant *final_val = nullptr;
        auto ext_v = M->getNamedValue(ext_sym_name);

        if (ext_v != nullptr && llvm::isa<llvm::Function>(ext_v)) {
          final_val = getPtrSizedValue(M, ext_v, data_sec_entry.getSize());
          //cout << "External function" << sym_name << " has type: " << final_val->getType() << "\n";
        } else if (ext_v != nullptr) {
          final_val = getPtrSizedValue(M, ext_v, data_sec_entry.getSize());
          //cout << "External data" << sym_name << " has type: " << final_val->getType() << "\n";
          // assume ext data
        } else {
          TASSERT(ext_v != nullptr,
                  "Could not find external: " + std::string(ext_sym_name));
          //cout << "External fail" << sym_name << " has type: " << final_val->getType() << "\n";
        }

        secContents.push_back(final_val);
        data_section_types.push_back(final_val->getType());

      } else if (sym_name.find("sub_") == 0) {

        // TODO(pag): This is so flaky.
        auto sub_addr_str = sym_name.c_str() + 4 /* strlen("sub_") */;
        VA sub_addr = 0;
        sscanf(sub_addr_str, "%lx", &sub_addr);

        // add function pointer to data section
        // to do this, create a callback driver for
        // it first (since it may be called externally)

        llvm::Function *func = nullptr;

        if (convert_to_callback) {
          func = ArchAddCallbackDriver(M, sub_addr);
          TASSERT(func != nullptr, "Could make callback for: " + sym_name);
        } else {
          func = M->getFunction(sym_name);
          TASSERT(func != nullptr, "Could not find function: " + sym_name);
        }

        auto final_val = getPtrSizedValue(M, func, data_sec_entry.getSize());
        secContents.push_back(final_val);
        data_section_types.push_back(final_val->getType());

      } else if (sym_name.find("data_") == 0) {

        // TODO(pag): This is so flaky.
        auto data_addr_str = sym_name.c_str() + 5 /* strlen("data_") */;
        VA data_addr = 0;
        sscanf(data_addr_str, "%lx", &data_addr);

        // data symbol
        // get the base of the data section for this symobol
        // then compute the offset from base of data
        // and store as integer value of (base+offset)
        VA section_base;
        auto g_ref = GetSectionForDataAddr(globaldata, M, data_addr,
                                           section_base);
        TASSERT(g_ref != nullptr,
                "Could not get data addr for:" + std::string(data_addr_str));
        // instead of referencing an element directly
        // we just convert the pointer to an integer
        // and add its offset from the base of data
        // to the new data section pointer
        VA addr_diff = data_addr - section_base;
        llvm::Constant *final_val = nullptr;
        //cout << " Symbol name : " << string(func_addr_str) << " : "
        //     << to_string<VA>(func_addr, hex) << " : "
        //     << to_string<VA>(section_base, hex) << "\n";
        //cout.flush();
        if (ArchPointerSize(M) == Pointer32) {
          auto int_val = llvm::ConstantExpr::getPtrToInt(
              g_ref, llvm::Type::getInt32Ty(M->getContext()));
          final_val = llvm::ConstantExpr::getAdd(
              int_val, CONST_V_INT<32>(M->getContext(), addr_diff));
        } else {
          auto int_val = llvm::ConstantExpr::getPtrToInt(
              g_ref, llvm::Type::getInt64Ty(M->getContext()));
          final_val = llvm::ConstantExpr::getAdd(
              int_val, CONST_V_INT<64>(M->getContext(), addr_diff));
        }
        secContents.push_back(final_val);
        data_section_types.push_back(final_val->getType());

      } else {
        std::cerr
            << __FUNCTION__ << ": Unknown data section entry symbol type "
            << sym_name << std::endl;
      }
    } else {
      // add array
      // this holds opaque data in a byte array
      auto arr = CreateConstantBlob(M->getContext(), data_sec_entry.getBytes());
      secContents.push_back(arr);
      data_section_types.push_back(arr->getType());
    }  // if dsec_itr
  }  // for list
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
    auto native_func = f.second;
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
    auto native_func = f.second;
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
    auto f = func_info.second;
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
