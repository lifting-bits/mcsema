/*
 Copyright (c) 2013, Trail of Bits
 All rights reserved.

 Redistribution and use in source and binary forms, with or without modification,
 are permitted provided that the following conditions are met:

 Redistributions of source code must retain the above copyright notice, this
 list of conditions and the following disclaimer.

 Redistributions in binary form must reproduce the above copyright notice, this  list of conditions and the following disclaimer in the documentation and/or
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
#include "toLLVM.h"
#include "raiseX86.h"
#include "X86.h"
#include "x86Instrs.h"
#include "x86Helpers.h"
#include "ArchOps.h"
#include "RegisterUsage.h"

#include <llvm/Object/COFF.h>
#include <llvm/IR/Constants.h>
#include <llvm/ADT/StringSwitch.h>
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/Module.h"
#include "llvm/Bitcode/ReaderWriter.h"
#include "llvm/LinkAllPasses.h"

#include "llvm/IR/Type.h"
#include "postPasses.h"
#include <boost/graph/breadth_first_search.hpp>
#include "Externals.h"
#include "../common/to_string.h"
#include "../common/Defaults.h"
#include "Annotation.h"

#include <vector>
#include <llvm/IR/InlineAsm.h>
#include <llvm/IR/MDBuilder.h>
#include "llvm/IR/InstIterator.h"

using namespace llvm;
using namespace std;

bool ignoreUnsupportedInsts = false;

#include <llvm/ADT/SmallVector.h>

Instruction *noAliasMCSemaScope(Instruction *inst) {
  //TODO this requires newer version of LLVM
  return inst;
}

Instruction *aliasMCSemaScope(Instruction *inst) {
  //TODO this requires newer version of LLVM
  return inst;
}

CallingConv::ID getLLVMCC(ExternalCodeRef::CallingConvention cc) {
  switch (cc) {
    case ExternalCodeRef::CallerCleanup:
      return CallingConv::C;
    case ExternalCodeRef::CalleeCleanup:
      return CallingConv::X86_StdCall;
    case ExternalCodeRef::FastCall:
      return CallingConv::X86_FastCall;
    default:
      throw TErr(__LINE__, __FILE__, "Unknown calling convention!");
      break;
  }

  return CallingConv::C;
}

llvm::Value *INTERNAL_M_READ(unsigned width, unsigned addrspace, llvm::BasicBlock *b,
                             llvm::Value *addr) {
  llvm::Value *readLoc = addr;
  llvm::LLVMContext &C = b->getContext();

  if (readLoc->getType()->isPointerTy()) {
    const llvm::DataLayout *DL = b->getDataLayout();
    llvm::Type *IntPtrTy =  DL->getIntPtrType(C, addrspace);
    readLoc = new llvm::PtrToIntInst(readLoc, IntPtrTy, "", b);
  }

  TASSERT(readLoc->getType()->isIntegerTy(), "Expected integer type.");

  llvm::Type *PtrTy = llvm::Type::getIntNPtrTy(C, width, addrspace);
  readLoc = new llvm::IntToPtrInst(readLoc, PtrTy, "", b);

  bool is_volatile = addrspace != 0;
  llvm::Instruction *read = noAliasMCSemaScope(
      new llvm::LoadInst(readLoc, "", is_volatile, b));

  TASSERT(read != NULL, "Could not create a LoadInst in M_READ");

  return read;
}

void INTERNAL_M_WRITE(int width, unsigned addrspace, llvm::BasicBlock *b,
                      llvm::Value *addr, llvm::Value *data) {
  llvm::Value *writeLoc = addr;
  llvm::LLVMContext &C = b->getContext();

  if (writeLoc->getType()->isPointerTy()) {
    const llvm::DataLayout *DL = b->getDataLayout();
    llvm::Type *IntPtrTy =  DL->getIntPtrType(C, addrspace);
    writeLoc = new llvm::PtrToIntInst(writeLoc, IntPtrTy, "", b);
  }

  TASSERT(writeLoc->getType()->isIntegerTy(), "Expected integer type.");

  llvm::Type *PtrTy = llvm::Type::getIntNPtrTy(C, width, addrspace);
  writeLoc = new llvm::IntToPtrInst(writeLoc, PtrTy, "", b);

  bool is_volatile = addrspace != 0;

  llvm::Instruction *written = noAliasMCSemaScope(
      new llvm::StoreInst(data, writeLoc, is_volatile, b));
  noAliasMCSemaScope(written);

  TASSERT(written != NULL, "");

  return;
}

void M_WRITE_T(InstPtr ip, llvm::BasicBlock *b, llvm::Value *addr,
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

  llvm::Instruction *written = noAliasMCSemaScope(
      new llvm::StoreInst(data, writeLoc, b));
  TASSERT(written != NULL, "Failed to create StoreInst");

  return;
}

class bfs_cfg_visitor : public boost::default_bfs_visitor {
 private:
  NativeFunctionPtr natFun;
  Function *F;
  NativeModulePtr natMod;
  bool &didError;
 public:
  bfs_cfg_visitor(NativeFunctionPtr n, NativeModulePtr m, Function *F_, bool &e)
      : natFun(n),
        F(F_),
        natMod(m),
        didError(e) {
  }
  template<typename Vertex, typename Graph>
  void discover_vertex(Vertex u, const Graph & g) const;
};

Value *lookupLocalByName(Function *F, string localName) {
  BasicBlock *entry = &F->getEntryBlock();
  BasicBlock::iterator it = entry->begin();

  localName += "";
  while (it != entry->end()) {
    Value *v = it;

    if (v->getName() == localName) {
      return v;
    }

    ++it;
  }

  throw TErr(__LINE__, __FILE__, "localname: " + localName + " is not found");
  return NULL;
}

Value *MCRegToValue(BasicBlock *b, unsigned reg) {
  Module *M = b->getParent()->getParent();

  if (getPointerSize(M) == Pointer32) {
    return x86::MCRegToValue(b, reg);
  } else {
    return x86_64::MCRegToValue(b, reg);
  }
}

static int accessOffset(int reg) {
  switch(reg) {
    case X86::DH: return 8;
    case X86::CH: return 8;
    case X86::BH: return 8;
    case X86::AH: return 8;
    default: return 0;
  }
}

static int readRegWidth(int reg) {
  switch(reg) {
    case X86::DH: return 8;
    case X86::CH: return 8;
    case X86::BH: return 8;
    case X86::AH: return 8;
    case X86::AX: return 16;
    case X86::AL: return 8;
    case X86::EAX: return 32;
    case X86::RAX: return 64;
    case X86::BX: return 16;
    case X86::BL: return 8;
    case X86::EBX: return 32;
    case X86::RBX: return 64;
    case X86::CX: return 16;
    case X86::CL: return 8;
    case X86::ECX: return 32;
    case X86::RCX: return 64;
    case X86::DX: return 16;
    case X86::DL: return 8;
    case X86::EDX: return 32;
    case X86::RDX: return 64;
    case X86::SIL: return 8;
    case X86::SI: return 16;
    case X86::ESI: return 32;
    case X86::RSI: return 64;
    case X86::DIL: return 8;
    case X86::DI: return 16;
    case X86::EDI: return 32;
    case X86::RDI: return 64;
    case X86::SPL: return 8;
    case X86::SP: return 16;
    case X86::ESP: return 32;
    case X86::RSP: return 64;
    case X86::BPL: return 8;
    case X86::BP: return 16;
    case X86::EBP: return 32;
    case X86::RBP: return 64;
    case X86::R8B: return 8;
    case X86::R8W: return 16;
    case X86::R8D: return 32;
    case X86::R8: return 64;
    case X86::R9B: return 8;
    case X86::R9W: return 16;
    case X86::R9D: return 32;
    case X86::R9: return 64;
    case X86::R10B: return 8;
    case X86::R10W: return 16;
    case X86::R10D: return 32;
    case X86::R10: return 64;
    case X86::R11B: return 8;
    case X86::R11W: return 16;
    case X86::R11D: return 32;
    case X86::R11: return 64;
    case X86::R12B: return 8;
    case X86::R12W: return 16;
    case X86::R12D: return 32;
    case X86::R12: return 64;
    case X86::R13B: return 8;
    case X86::R13W: return 16;
    case X86::R13D: return 32;
    case X86::R13: return 64;
    case X86::R14B: return 8;
    case X86::R14W: return 16;
    case X86::R14D: return 32;
    case X86::R14: return 64;
    case X86::R15B: return 8;
    case X86::R15W: return 16;
    case X86::R15D: return 32;
    case X86::R15: return 64;


    case X86::ST0: return 80;
    case X86::ST1: return 80;
    case X86::ST2: return 80;
    case X86::ST3: return 80;
    case X86::ST4: return 80;
    case X86::ST5: return 80;
    case X86::ST6: return 80;
    case X86::ST7: return 80;

    case X86::XMM0: return 128;
    case X86::XMM1: return 128;
    case X86::XMM2: return 128;
    case X86::XMM3: return 128;
    case X86::XMM4: return 128;
    case X86::XMM5: return 128;
    case X86::XMM6: return 128;
    case X86::XMM7: return 128;
    case X86::XMM8: return 128;
    case X86::XMM9: return 128;
    case X86::XMM10: return 128;
    case X86::XMM11: return 128;
    case X86::XMM12: return 128;
    case X86::XMM13: return 128;
    case X86::XMM14: return 128;
    case X86::XMM15: return 128;

    case X86::EIP: return 32;
    case X86::RIP: return 64;

    default:
      throw TErr(__LINE__, __FILE__, "Reg type "+to_string<unsigned>(reg, dec)+" is unknown");
  }

  return -1;
}

static const char *regName(int reg) {
  switch(reg) {
    case X86::DH: return "DH";
    case X86::CH: return "CH";
    case X86::BH: return "BH";
    case X86::AH: return "AH";
    case X86::AX: return "AX";
    case X86::AL: return "AL";
    case X86::EAX: return "EAX";
    case X86::RAX: return "RAX";
    case X86::BX: return "BX";
    case X86::BL: return "BL";
    case X86::EBX: return "EBX";
    case X86::RBX: return "RBX";
    case X86::CX: return "CX";
    case X86::CL: return "CL";
    case X86::ECX: return "ECX";
    case X86::RCX: return "RCX";
    case X86::DX: return "DX";
    case X86::DL: return "DL";
    case X86::EDX: return "EDX";
    case X86::RDX: return "RDX";
    case X86::SIL: return "SIL";
    case X86::SI: return "SI";
    case X86::ESI: return "ESI";
    case X86::RSI: return "RSI";
    case X86::DIL: return "DIL";
    case X86::DI: return "DI";
    case X86::EDI: return "EDI";
    case X86::RDI: return "RDI";
    case X86::SPL: return "SPL";
    case X86::SP: return "SP";
    case X86::ESP: return "ESP";
    case X86::RSP: return "RSP";
    case X86::BPL: return "BPL";
    case X86::BP: return "BP";
    case X86::EBP: return "EBP";
    case X86::RBP: return "RBP";
    case X86::R8B: return "R8B";
    case X86::R8W: return "R8W";
    case X86::R8D: return "R8D";
    case X86::R8: return "R8";
    case X86::R9B: return "R9B";
    case X86::R9W: return "R9W";
    case X86::R9D: return "R9D";
    case X86::R9: return "R9";
    case X86::R10B: return "R10B";
    case X86::R10W: return "R10W";
    case X86::R10D: return "R10D";
    case X86::R10: return "R10";
    case X86::R11B: return "R11B";
    case X86::R11W: return "R11W";
    case X86::R11D: return "R11D";
    case X86::R11: return "R11";
    case X86::R12B: return "R12B";
    case X86::R12W: return "R12W";
    case X86::R12D: return "R12D";
    case X86::R12: return "R12";
    case X86::R13B: return "R13B";
    case X86::R13W: return "R13W";
    case X86::R13D: return "R13D";
    case X86::R13: return "R13";
    case X86::R14B: return "R14B";
    case X86::R14W: return "R14W";
    case X86::R14D: return "R14D";
    case X86::R14: return "R14";
    case X86::R15B: return "R15B";
    case X86::R15W: return "R15W";
    case X86::R15D: return "R15D";
    case X86::R15: return "R15";


    case X86::ST0: return "ST0";
    case X86::ST1: return "ST1";
    case X86::ST2: return "ST2";
    case X86::ST3: return "ST3";
    case X86::ST4: return "ST4";
    case X86::ST5: return "ST5";
    case X86::ST6: return "ST6";
    case X86::ST7: return "ST7";

    case X86::XMM0: return "XMM0";
    case X86::XMM1: return "XMM1";
    case X86::XMM2: return "XMM2";
    case X86::XMM3: return "XMM3";
    case X86::XMM4: return "XMM4";
    case X86::XMM5: return "XMM5";
    case X86::XMM6: return "XMM6";
    case X86::XMM7: return "XMM7";
    case X86::XMM8: return "XMM8";
    case X86::XMM9: return "XMM9";
    case X86::XMM10: return "XMM10";
    case X86::XMM11: return "XMM11";
    case X86::XMM12: return "XMM12";
    case X86::XMM13: return "XMM13";
    case X86::XMM14: return "XMM14";
    case X86::XMM15: return "XMM15";

    case X86::EIP: return "EIP";
    case X86::RIP: return "RIP";

    default:
      throw TErr(__LINE__, __FILE__, "Reg type "+to_string<unsigned>(reg, dec)+" is unknown");
  }

  return nullptr;
}

static int gReadWriteId = 0;

static std::string regAddrName(int mc_reg) {
  std::stringstream ss;
  ss << regName(mc_reg) << "." << gReadWriteId++;
  return ss.str();
}

static std::string regValName(int mc_reg) {
  std::stringstream ss;
  ss << regName(mc_reg) << "_val." << gReadWriteId++;
  return ss.str();
}

void GENERIC_MC_WRITEREG(BasicBlock *b, int mc_reg, Value *v) {
  auto M = b->getParent()->getParent();
  auto &C = M->getContext();
  auto backing_reg = llvm::dyn_cast<llvm::AllocaInst>(MCRegToValue(b, mc_reg));
  auto backing_reg_ty = backing_reg->getAllocatedType();
  auto size = readRegWidth(mc_reg);
  auto index_in_backing_reg = accessOffset(mc_reg) / 8;
  if (32 == size && Pointer64 == getPointerSize(M)) {
    size = 64;
  }

  DataLayout DL(M);
  auto value_size = DL.getTypeAllocSizeInBits(v->getType());
  if (64 >= size) {
    auto reg_ty = Type::getIntNTy(C, size);
    if (value_size < size) {
      v = new llvm::ZExtInst(v, reg_ty, "", b);
      value_size = size;
    } else if (value_size > size) {
      v = new llvm::TruncInst(v, reg_ty, "", b);
      value_size = size;
    }
  }

  auto backing_reg_size = DL.getTypeAllocSizeInBits(backing_reg_ty);
  if (backing_reg_size == value_size) {
    new llvm::StoreInst(v, backing_reg, b);
    return;
  }

  auto value_ty = Type::getIntNTy(C, value_size);
  auto value_ptr_ty = PointerType::get(value_ty, 0);
  auto i32_ty = Type::getInt32Ty(C);
  auto zero = ConstantInt::get(i32_ty, 0, false);
  auto index = ConstantInt::get(i32_ty, index_in_backing_reg, false);
  auto cast = new llvm::BitCastInst(backing_reg, value_ptr_ty, "", b);
  llvm::Value *index_list[] = {index};
  auto addr = llvm::GetElementPtrInst::Create(
      cast, index_list, regAddrName(mc_reg), b);

  new llvm::StoreInst(v, addr, b);
}

Value *GENERIC_MC_READREG(BasicBlock *b, int mc_reg, int desired_size) {
  auto M = b->getParent()->getParent();
  auto &C = M->getContext();
  auto backing_reg = llvm::dyn_cast<llvm::AllocaInst>(MCRegToValue(b, mc_reg));
  auto backing_reg_ty = backing_reg->getAllocatedType();
  auto desired_ty = llvm::Type::getIntNTy(C, desired_size);
  auto size = readRegWidth(mc_reg);

  DataLayout DL(M);
  llvm::Value *val = nullptr;

  if (size == DL.getTypeAllocSizeInBits(backing_reg_ty)) {
    val = new llvm::LoadInst(backing_reg, regValName(mc_reg), b);
  } else {

    auto index_in_backing_reg = accessOffset(mc_reg) / 8;
    auto dst_ty = Type::getIntNTy(C, size);
    auto dst_ptr_ty = PointerType::get(dst_ty, 0);
    auto i32_ty = Type::getInt32Ty(C);
    auto zero = ConstantInt::get(i32_ty, 0, false);
    auto index = ConstantInt::get(i32_ty, index_in_backing_reg, false);
    auto cast = new llvm::BitCastInst(backing_reg, dst_ptr_ty, "", b);
    llvm::Value *index_list[] = {index};
    auto addr = llvm::GetElementPtrInst::Create(
        cast, index_list, regAddrName(mc_reg), b);
    val = new llvm::LoadInst(addr, regValName(mc_reg), b);
  }

  if (desired_size > size) {
    val = new llvm::ZExtInst(val, desired_ty, val->getName() + ".zext", b);
  } else if (desired_size < size) {
    val = new llvm::TruncInst(val, desired_ty, val->getName() + ".trunc", b);
  }

  return val;
}

Value *GENERIC_READREG(BasicBlock *b, MCSemaRegs reg) {
  Module *M = b->getParent()->getParent();
  Value *localRegVar;

  if (getPointerSize(M) == Pointer32) {
    localRegVar = x86::lookupLocal(b->getParent(), reg);
  } else {
    localRegVar = x86_64::lookupLocal(b->getParent(), reg);
  }
  Instruction *readFlag = noAliasMCSemaScope(new LoadInst(localRegVar, "", b));
  return readFlag;
}

void GENERIC_WRITEREG(BasicBlock *b, MCSemaRegs reg, Value *v) {
  Module *M = b->getParent()->getParent();
  Value *localRegVar;
  std::string regName;

  if (getPointerSize(M) == Pointer32) {
    localRegVar = x86::lookupLocal(b->getParent(), reg);
    regName = x86::getRegisterName(reg);
  } else {
    localRegVar = x86_64::lookupLocal(b->getParent(), reg);
    regName = x86_64::getRegisterName(reg);
  }
  if (localRegVar == NULL)
    throw TErr(__LINE__, __FILE__, "regname " + regName + " not found");
  Instruction *st = noAliasMCSemaScope(new StoreInst(v, localRegVar, b));
  TASSERT(st != NULL, "");
  return;
}

Value *F_READ(BasicBlock *b, MCSemaRegs flag) {
  return GENERIC_READREG(b, flag);
}

void F_WRITE(BasicBlock *b, MCSemaRegs flag, Value *v) {
  return GENERIC_WRITEREG(b, flag, v);
}

void F_ZAP(BasicBlock *b, MCSemaRegs flag) {
  F_WRITE(b, flag, UndefValue::get(Type::getInt1Ty(b->getContext())));
  return;
}

void F_SET(BasicBlock *b, MCSemaRegs flag) {
  F_WRITE(b, flag, CONST_V<1>(b, 1));
  return;
}

void F_CLEAR(BasicBlock *b, MCSemaRegs flag) {
  F_WRITE(b, flag, CONST_V<1>(b, 0));
  return;
}

//
// common case for arithmetic instructions
// some instructions, like inc and dec, do not need to do this
//

void allocateLocals(Function *F, int bits) {
  //always at the beginning of a function
  //we need to allocate local variables via alloca, these locals will
  //live for the life of the function context and be the sources/sinks
  //of any activity involving registers or flags
  BasicBlock *begin = &F->getEntryBlock();
  switch (bits) {
    case 32: {
      //UPDATEREGS -- when we add something to 'regs' struct change here
      //create a local for every member in the 'regs' struct
      //create 32-bit width general purpose registers
      Type *uintTy = Type::getInt32Ty(F->getContext());
      Instruction *eaxA = new AllocaInst(uintTy, "EAX", begin);
      Instruction *ebxA = new AllocaInst(uintTy, "EBX", eaxA);
      Instruction *ecxA = new AllocaInst(uintTy, "ECX", ebxA);
      Instruction *edxA = new AllocaInst(uintTy, "EDX", ecxA);
      Instruction *esiA = new AllocaInst(uintTy, "ESI", edxA);
      Instruction *ediA = new AllocaInst(uintTy, "EDI", esiA);
      Instruction *ebpA = new AllocaInst(uintTy, "EBP", ediA);
      Instruction *espA = new AllocaInst(uintTy, "ESP", ebpA);
      //create other fields for flags

      Type *boolTy = Type::getInt1Ty(F->getContext());
      Instruction *zfA = new AllocaInst(boolTy, "ZF", espA);
      Instruction *sfA = new AllocaInst(boolTy, "PF", zfA);
      Instruction *ofA = new AllocaInst(boolTy, "AF", sfA);
      Instruction *cfA = new AllocaInst(boolTy, "CF", ofA);
      Instruction *pfA = new AllocaInst(boolTy, "SF", cfA);
      Instruction *afA = new AllocaInst(boolTy, "OF", pfA);
      Instruction *dfA = new AllocaInst(boolTy, "DF", afA);
      TASSERT(dfA != NULL, "");

      // FPU STACK
      Type *floatTy = Type::getX86_FP80Ty(F->getContext());
      // 8 float values make up the ST registers
      Type *floatArrayTy = ArrayType::get(floatTy, 8);
      Instruction *stRegs = new AllocaInst(floatArrayTy, "STi", dfA);

      // sanity check
      TASSERT(stRegs != NULL, "");

      // FPU FLAGS
      Instruction *fpu_B = new AllocaInst(boolTy, "FPU_B", stRegs);
      Instruction *fpu_C3 = new AllocaInst(boolTy, "FPU_C3", fpu_B);

      // TOP of stack from FPU flags
      // really a 3-bit integer
      Type *topTy = Type::getIntNTy(F->getContext(), 3);
      Instruction *fpu_TOP = new AllocaInst(topTy, "FPU_TOP", fpu_C3);
      TASSERT(fpu_TOP != NULL, "");

      Instruction *fpu_C2 = new AllocaInst(boolTy, "FPU_C2", fpu_TOP);
      Instruction *fpu_C1 = new AllocaInst(boolTy, "FPU_C1", fpu_C2);
      Instruction *fpu_C0 = new AllocaInst(boolTy, "FPU_C0", fpu_C1);
      Instruction *fpu_ES = new AllocaInst(boolTy, "FPU_ES", fpu_C0);
      Instruction *fpu_SF = new AllocaInst(boolTy, "FPU_SF", fpu_ES);
      Instruction *fpu_PE = new AllocaInst(boolTy, "FPU_PE", fpu_SF);
      Instruction *fpu_UE = new AllocaInst(boolTy, "FPU_UE", fpu_PE);
      Instruction *fpu_OE = new AllocaInst(boolTy, "FPU_OE", fpu_UE);
      Instruction *fpu_ZE = new AllocaInst(boolTy, "FPU_ZE", fpu_OE);
      Instruction *fpu_DE = new AllocaInst(boolTy, "FPU_DE", fpu_ZE);
      Instruction *fpu_IE = new AllocaInst(boolTy, "FPU_IE", fpu_DE);

      // sanity check
      TASSERT(fpu_IE != NULL, "");

      // FPU CONTROL FLAGS
      Type *int2Ty = Type::getIntNTy(F->getContext(), 2);
      Instruction *fpu_X = new AllocaInst(boolTy, "FPU_X", fpu_IE);
      Instruction *fpu_RC = new AllocaInst(int2Ty, "FPU_RC", fpu_X);
      Instruction *fpu_PC = new AllocaInst(int2Ty, "FPU_PC", fpu_RC);
      Instruction *fpu_PM = new AllocaInst(boolTy, "FPU_PM", fpu_PC);
      Instruction *fpu_UM = new AllocaInst(boolTy, "FPU_UM", fpu_PM);
      Instruction *fpu_OM = new AllocaInst(boolTy, "FPU_OM", fpu_UM);
      Instruction *fpu_ZM = new AllocaInst(boolTy, "FPU_ZM", fpu_OM);
      Instruction *fpu_DM = new AllocaInst(boolTy, "FPU_DM", fpu_ZM);
      Instruction *fpu_IM = new AllocaInst(boolTy, "FPU_IM", fpu_DM);

      TASSERT(fpu_IM != NULL, "");

      // FPU TAG WORD
      // 8 2-bit values. One for each ST register
      Type *tagArrayType = ArrayType::get(int2Ty, 8);
      Instruction *fpu_TagWord = new AllocaInst(tagArrayType, "FPU_TAG",
                                                fpu_IM);

      TASSERT(fpu_TagWord != NULL, "");

      Instruction *fpu_LASTIP_SEG = new AllocaInst(
          Type::getInt16Ty(F->getContext()), "FPU_LASTIP_SEG", fpu_TagWord);
      Instruction *fpu_LASTIP_OFF = new AllocaInst(
          Type::getInt32Ty(F->getContext()), "FPU_LASTIP_OFF",
          fpu_LASTIP_SEG);
      Instruction *fpu_LASTDATA_SEG = new AllocaInst(
          Type::getInt16Ty(F->getContext()), "FPU_LASTDATA_SEG",
          fpu_LASTIP_OFF);
      Instruction *fpu_LASTDATA_OFF = new AllocaInst(
          Type::getInt32Ty(F->getContext()), "FPU_LASTDATA_OFF",
          fpu_LASTDATA_SEG);

      Instruction *fpu_FOPCODE = new AllocaInst(
          Type::getIntNTy(F->getContext(), 11), "FPU_FOPCODE",
          fpu_LASTDATA_OFF);
      TASSERT(fpu_FOPCODE != NULL, "");

      //vector registers
      Instruction *vec_xmm0 = new AllocaInst(
          Type::getIntNTy(F->getContext(), 128), "XMM0", fpu_FOPCODE);
      Instruction *vec_xmm1 = new AllocaInst(
          Type::getIntNTy(F->getContext(), 128), "XMM1", vec_xmm0);
      Instruction *vec_xmm2 = new AllocaInst(
          Type::getIntNTy(F->getContext(), 128), "XMM2", vec_xmm1);
      Instruction *vec_xmm3 = new AllocaInst(
          Type::getIntNTy(F->getContext(), 128), "XMM3", vec_xmm2);
      Instruction *vec_xmm4 = new AllocaInst(
          Type::getIntNTy(F->getContext(), 128), "XMM4", vec_xmm3);
      Instruction *vec_xmm5 = new AllocaInst(
          Type::getIntNTy(F->getContext(), 128), "XMM5", vec_xmm4);
      Instruction *vec_xmm6 = new AllocaInst(
          Type::getIntNTy(F->getContext(), 128), "XMM6", vec_xmm5);
      Instruction *vec_xmm7 = new AllocaInst(
          Type::getIntNTy(F->getContext(), 128), "XMM7", vec_xmm6);
      Instruction *vec_xmm8 = new AllocaInst(
          Type::getIntNTy(F->getContext(), 128), "XMM8", vec_xmm7);
      Instruction *vec_xmm9 = new AllocaInst(
          Type::getIntNTy(F->getContext(), 128), "XMM9", vec_xmm8);
      Instruction *vec_xmm10 = new AllocaInst(
          Type::getIntNTy(F->getContext(), 128), "XMM10", vec_xmm9);
      Instruction *vec_xmm11 = new AllocaInst(
          Type::getIntNTy(F->getContext(), 128), "XMM11", vec_xmm10);
      Instruction *vec_xmm12 = new AllocaInst(
          Type::getIntNTy(F->getContext(), 128), "XMM12", vec_xmm11);
      Instruction *vec_xmm13 = new AllocaInst(
          Type::getIntNTy(F->getContext(), 128), "XMM13", vec_xmm12);
      Instruction *vec_xmm14 = new AllocaInst(
          Type::getIntNTy(F->getContext(), 128), "XMM14", vec_xmm13);
      Instruction *vec_xmm15 = new AllocaInst(
          Type::getIntNTy(F->getContext(), 128), "XMM15", vec_xmm14);

      // stack base and limit
      Instruction *stack_base = new AllocaInst(
          Type::getInt32Ty(F->getContext()), "STACK_BASE", vec_xmm15);
      Instruction *stack_limit = new AllocaInst(
          Type::getInt32Ty(F->getContext()), "STACK_LIMIT", stack_base);
    }
      break;

    case 64: {
      //create 64-bit width general purpose registers
      Type *uintTy = Type::getInt64Ty(F->getContext());
      Instruction *raxA = new AllocaInst(uintTy, "RAX", begin);
      Instruction *rbxA = new AllocaInst(uintTy, "RBX", raxA);
      Instruction *rcxA = new AllocaInst(uintTy, "RCX", rbxA);
      Instruction *rdxA = new AllocaInst(uintTy, "RDX", rcxA);
      Instruction *rsiA = new AllocaInst(uintTy, "RSI", rdxA);
      Instruction *rdiA = new AllocaInst(uintTy, "RDI", rsiA);
      Instruction *rbpA = new AllocaInst(uintTy, "RBP", rdiA);
      Instruction *rspA = new AllocaInst(uintTy, "RSP", rbpA);

      Instruction *r8A = new AllocaInst(uintTy, "R8", rspA);
      Instruction *r9A = new AllocaInst(uintTy, "R9", r8A);
      Instruction *r10A = new AllocaInst(uintTy, "R10", r9A);
      Instruction *r11A = new AllocaInst(uintTy, "R11", r10A);
      Instruction *r12A = new AllocaInst(uintTy, "R12", r11A);
      Instruction *r13A = new AllocaInst(uintTy, "R13", r12A);
      Instruction *r14A = new AllocaInst(uintTy, "R14", r13A);
      Instruction *r15A = new AllocaInst(uintTy, "R15", r14A);

      Instruction *ripA = new AllocaInst(uintTy, "RIP", r14A);
      //create other fields for flags

      Type *boolTy = Type::getInt1Ty(F->getContext());
      Instruction *zfA = new AllocaInst(boolTy, "ZF", ripA);
      Instruction *sfA = new AllocaInst(boolTy, "PF", zfA);
      Instruction *ofA = new AllocaInst(boolTy, "AF", sfA);
      Instruction *cfA = new AllocaInst(boolTy, "CF", ofA);
      Instruction *pfA = new AllocaInst(boolTy, "SF", cfA);
      Instruction *afA = new AllocaInst(boolTy, "OF", pfA);
      Instruction *dfA = new AllocaInst(boolTy, "DF", afA);
      TASSERT(dfA != NULL, "");

      // FPU STACK
      //Type    *floatTy =  IntegerType::get(F->getContext(), 128);
      Type *floatTy = Type::getX86_FP80Ty(F->getContext());
      // 8 float values make up the ST registers
      Type *floatArrayTy = ArrayType::get(floatTy, 8);
      Instruction *stRegs = new AllocaInst(floatArrayTy, "STi", dfA);

      // sanity check
      TASSERT(stRegs != NULL, "");

      // FPU FLAGS
      Instruction *fpu_B = new AllocaInst(boolTy, "FPU_B", stRegs);
      Instruction *fpu_C3 = new AllocaInst(boolTy, "FPU_C3", fpu_B);

      // TOP of stack from FPU flags
      // really a 3-bit integer
      Type *topTy = Type::getIntNTy(F->getContext(), 3);
      Instruction *fpu_TOP = new AllocaInst(topTy, "FPU_TOP", fpu_C3);
      TASSERT(fpu_TOP != NULL, "");

      Instruction *fpu_C2 = new AllocaInst(boolTy, "FPU_C2", fpu_TOP);
      Instruction *fpu_C1 = new AllocaInst(boolTy, "FPU_C1", fpu_C2);
      Instruction *fpu_C0 = new AllocaInst(boolTy, "FPU_C0", fpu_C1);
      Instruction *fpu_ES = new AllocaInst(boolTy, "FPU_ES", fpu_C0);
      Instruction *fpu_SF = new AllocaInst(boolTy, "FPU_SF", fpu_ES);
      Instruction *fpu_PE = new AllocaInst(boolTy, "FPU_PE", fpu_SF);
      Instruction *fpu_UE = new AllocaInst(boolTy, "FPU_UE", fpu_PE);
      Instruction *fpu_OE = new AllocaInst(boolTy, "FPU_OE", fpu_UE);
      Instruction *fpu_ZE = new AllocaInst(boolTy, "FPU_ZE", fpu_OE);
      Instruction *fpu_DE = new AllocaInst(boolTy, "FPU_DE", fpu_ZE);
      Instruction *fpu_IE = new AllocaInst(boolTy, "FPU_IE", fpu_DE);

      // sanity check
      TASSERT(fpu_IE != NULL, "");

      // FPU CONTROL FLAGS
      Type *int2Ty = Type::getIntNTy(F->getContext(), 2);
      Instruction *fpu_X = new AllocaInst(boolTy, "FPU_X", fpu_IE);
      Instruction *fpu_RC = new AllocaInst(int2Ty, "FPU_RC", fpu_X);
      Instruction *fpu_PC = new AllocaInst(int2Ty, "FPU_PC", fpu_RC);
      Instruction *fpu_PM = new AllocaInst(boolTy, "FPU_PM", fpu_PC);
      Instruction *fpu_UM = new AllocaInst(boolTy, "FPU_UM", fpu_PM);
      Instruction *fpu_OM = new AllocaInst(boolTy, "FPU_OM", fpu_UM);
      Instruction *fpu_ZM = new AllocaInst(boolTy, "FPU_ZM", fpu_OM);
      Instruction *fpu_DM = new AllocaInst(boolTy, "FPU_DM", fpu_ZM);
      Instruction *fpu_IM = new AllocaInst(boolTy, "FPU_IM", fpu_DM);

      TASSERT(fpu_IM != NULL, "");

      // FPU TAG WORD
      // 8 2-bit values. One for each ST register
      Type *tagArrayType = ArrayType::get(int2Ty, 8);
      Instruction *fpu_TagWord = new AllocaInst(tagArrayType, "FPU_TAG",
                                                fpu_IM);

      TASSERT(fpu_TagWord != NULL, "");

      Instruction *fpu_LASTIP_SEG = new AllocaInst(
          Type::getInt16Ty(F->getContext()), "FPU_LASTIP_SEG", fpu_TagWord);
      Instruction *fpu_LASTIP_OFF = new AllocaInst(
          Type::getInt64Ty(F->getContext()), "FPU_LASTIP_OFF",
          fpu_LASTIP_SEG);
      Instruction *fpu_LASTDATA_SEG = new AllocaInst(
          Type::getInt16Ty(F->getContext()), "FPU_LASTDATA_SEG",
          fpu_LASTIP_OFF);
      Instruction *fpu_LASTDATA_OFF = new AllocaInst(
          Type::getInt64Ty(F->getContext()), "FPU_LASTDATA_OFF",
          fpu_LASTDATA_SEG);

      Instruction *fpu_FOPCODE = new AllocaInst(
          Type::getIntNTy(F->getContext(), 11), "FPU_FOPCODE",
          fpu_LASTDATA_OFF);
      TASSERT(fpu_FOPCODE != NULL, "");

      //vector registers
      Instruction *vec_xmm0 = new AllocaInst(
          Type::getIntNTy(F->getContext(), 128), "XMM0", fpu_FOPCODE);
      Instruction *vec_xmm1 = new AllocaInst(
          Type::getIntNTy(F->getContext(), 128), "XMM1", vec_xmm0);
      Instruction *vec_xmm2 = new AllocaInst(
          Type::getIntNTy(F->getContext(), 128), "XMM2", vec_xmm1);
      Instruction *vec_xmm3 = new AllocaInst(
          Type::getIntNTy(F->getContext(), 128), "XMM3", vec_xmm2);
      Instruction *vec_xmm4 = new AllocaInst(
          Type::getIntNTy(F->getContext(), 128), "XMM4", vec_xmm3);
      Instruction *vec_xmm5 = new AllocaInst(
          Type::getIntNTy(F->getContext(), 128), "XMM5", vec_xmm4);
      Instruction *vec_xmm6 = new AllocaInst(
          Type::getIntNTy(F->getContext(), 128), "XMM6", vec_xmm5);
      Instruction *vec_xmm7 = new AllocaInst(
          Type::getIntNTy(F->getContext(), 128), "XMM7", vec_xmm6);
      Instruction *vec_xmm8 = new AllocaInst(
          Type::getIntNTy(F->getContext(), 128), "XMM8", vec_xmm7);
      Instruction *vec_xmm9 = new AllocaInst(
          Type::getIntNTy(F->getContext(), 128), "XMM9", vec_xmm8);
      Instruction *vec_xmm10 = new AllocaInst(
          Type::getIntNTy(F->getContext(), 128), "XMM10", vec_xmm9);
      Instruction *vec_xmm11 = new AllocaInst(
          Type::getIntNTy(F->getContext(), 128), "XMM11", vec_xmm10);
      Instruction *vec_xmm12 = new AllocaInst(
          Type::getIntNTy(F->getContext(), 128), "XMM12", vec_xmm11);
      Instruction *vec_xmm13 = new AllocaInst(
          Type::getIntNTy(F->getContext(), 128), "XMM13", vec_xmm12);
      Instruction *vec_xmm14 = new AllocaInst(
          Type::getIntNTy(F->getContext(), 128), "XMM14", vec_xmm13);
      Instruction *vec_xmm15 = new AllocaInst(
          Type::getIntNTy(F->getContext(), 128), "XMM15", vec_xmm14);

      // stack base and limit
      Instruction *stack_base = new AllocaInst(
          Type::getInt64Ty(F->getContext()), "STACK_BASE", vec_xmm15);
      Instruction *stack_limit = new AllocaInst(
          Type::getInt64Ty(F->getContext()), "STACK_LIMIT", stack_base);
    }
      break;

    default:
      throw TErr(__LINE__, __FILE__,
                 "Unsupported bitwidth " + to_string<int>(bits, dec));
  }

  return;
}

BasicBlock *bbFromStrName(string n, Function *F) {
  BasicBlock *found = NULL;

  for (Function::iterator it = F->begin(); it != F->end(); ++it) {
    BasicBlock *b = it;

    if (b->getName() == n) {
      found = b;
      break;
    }
  }

  return found;
}

InstTransResult disInstr(InstPtr ip, BasicBlock *&block, NativeBlockPtr nb,
                         Function *F, NativeFunctionPtr natF,
                         NativeModulePtr natM, bool doAnnotation) {

  //add a string representation of this instruction to the CFG
  //this string representation should be removed by optimizations

  //in the future, we could have different target decoders here
  InstTransResult disInst_result = disInstrX86(ip, block, nb, F, natF, natM);

  if (doAnnotation) {
    // we need to loop over this function and find any un-annotated instructions.
    // then we annotate each instruction
    for (inst_iterator I = inst_begin(F), E = inst_end(F); I != E; ++I) {
      VA inst_eip;
      bool had_md;
      had_md = getAnnotation(&(*I), inst_eip);
      if (false == had_md) {
        addAnnotation(&(*I), ip->get_loc());
      }
    }
  }

  return disInst_result;
}

template<typename Vertex, typename Graph>
void bfs_cfg_visitor::discover_vertex(Vertex u, const Graph &g) const {
  NativeBlockPtr curBlock = this->natFun->block_from_id(u);
  BasicBlock *curLLVMBlock = NULL;

  if (curBlock == NULL)
    throw TErr(__LINE__, __FILE__,
               "Could not look up block " + to_string<Vertex>(u, dec));

  //first, either create or look up the LLVM basic block for this native
  //block. we are either creating it for the first time, or, we are
  //going to look up a blank block
  curLLVMBlock = bbFromStrName(curBlock->get_name(), this->F);

  if (curLLVMBlock == NULL) {
    //we need to create the block, so do that
    curLLVMBlock = BasicBlock::Create(this->F->getContext(),
                                      curBlock->get_name(), this->F);
    TASSERT(curLLVMBlock != NULL, "");
  }

  //then, create a basic block for every follow of this block, if we do not
  //already have that basic block in our LLVM CFG
  list<VA> &follows = curBlock->get_follows();
  for (list<VA>::iterator i = follows.begin(); i != follows.end(); ++i) {
    VA blockBase = *i;
    //try and look up a block that has this blocks name
    NativeBlockPtr followNat = this->natFun->block_from_base(blockBase);
    string followName = followNat->get_name();

    BasicBlock *fBB = bbFromStrName(followName, this->F);

    if (fBB == NULL) {
      fBB = BasicBlock::Create(this->F->getContext(), followNat->get_name(),
                               this->F);
      TASSERT(fBB != NULL, "");
    }
  }

  //now, go through each statement and translate it into LLVM IR
  //statements that branch SHOULD be the last statement in a block
  list<InstPtr> stmts = curBlock->get_insts();

  for (list<InstPtr>::iterator it = stmts.begin(); it != stmts.end(); ++it) {
    InstPtr inst = *it;

    InstTransResult r = disInstr(inst, curLLVMBlock, curBlock, this->F,
                                 this->natFun, this->natMod, true);

    if (r == TranslateError) {
      this->didError = true;
      break;
    }
    if (r == TranslateErrorUnsupported && ignoreUnsupportedInsts == false) {
      this->didError = true;
      break;
    }
  }

  // we may need to insert a branch inst to the successor
  // if the block ended on a non-terminator (this happens since we
  // may split blocks in cfg recovery to avoid code duplication)
  if (follows.size() == 1 && curLLVMBlock->getTerminator() == nullptr) {
    VA blockBase = *(follows.begin());
    std::string bbName = "block_0x" + to_string<VA>(blockBase, std::hex);
    BasicBlock *nextBB = bbFromStrName(bbName, this->F);

    BranchInst::Create(nextBB, curLLVMBlock);
  }

  return;
}

static bool insertFunctionIntoModule(NativeModulePtr mod,
                                     NativeFunctionPtr func, Module *M) {
  //okay, now we traverse the graph and add the instructions and blocks
  //into the llvm module

  //first, get the LLVM function for this native function
  Function *F = M->getFunction(func->get_name());

  if (F == NULL)
    throw TErr(__LINE__, __FILE__, "Could not get func " + func->get_name());
  //
  if (F->empty() == false) {
    cout << "WARNING: Asking to re-insert function: " << func->get_name()
         << std::endl;
    cout << "\tReturning current function instead" << std::endl;
    return true;
  }

  //create the entry block for the function
  //this block will alloca cells on the 'stack' for every register in the
  //register member structure
  BasicBlock *entryBlock = BasicBlock::Create(F->getContext(), "entry", F);
  TASSERT(entryBlock != NULL, "");

  allocateLocals(F, getPointerSize(M));
  //and at the beginning of the function, we spill all the context

  writeContextToLocals(entryBlock, getPointerSize(M), ABICallSpill);
  //writeContextToLocals(entryBlock, 32, AllRegs);

  //then we put an unconditional branch from the 'entry' block to the first
  //block, and we create the first block
  NativeBlockPtr funcEntry = func->block_from_base(func->get_start());
  BasicBlock *firstBlock = BasicBlock::Create(F->getContext(),
                                              funcEntry->get_name(), F);
  TASSERT(firstBlock != NULL, "");
  //create a branch from the end of the entry block to the first block
  BranchInst::Create(firstBlock, entryBlock);

  //now, start crawling everything in NativeFunctionPtr
  CFG funcGraph = func->get_cfg();
  bool error = false;
  bfs_cfg_visitor v(func, mod, F, error);

  //visit every vertex in the graph, starting from the entry block, which
  //always should be block 0
  //this traversal wil build us the LLVM graph from the native graph
  boost::breadth_first_search(funcGraph,
                              boost::vertex(func->entry_block_id(), funcGraph),
                              boost::visitor(v));

  //check that the function we created is valid

  //we should be done, having inserted every block into the module
  if (error) {
    return false;
  } else {
    return true;
  }
}

bool doPostAnalysis(NativeModulePtr N, Module *M) {
  //first, we need to instantiate the pass manager and perform the mem2reg transform
  //on the module to lift it at least into SSA form
  PassManager modulePasses;
  FunctionPassManager functionPasses(M);
  PassManagerBuilder builder;

  llvm::errs() << "in : " << __FUNCTION__ << "\n";

  builder.OptLevel = 1;
  builder.SizeLevel = 2;

  //register our specific analyses
  registerPostPasses(builder);

  builder.populateModulePassManager(modulePasses);
  builder.populateFunctionPassManager(functionPasses);

  functionPasses.doInitialization();
  for (Module::iterator i = M->begin(), e = M->end(); i != e; ++i) {
    functionPasses.run(*i);
  }
  functionPasses.doFinalization();

  modulePasses.run(*M);

  return true;
}

namespace x86 {
bool addEntryPointDriverRaw(Module *M, string name, VA entry) {
  string s("sub_" + to_string<VA>(entry, hex));
  Function *F = M->getFunction(s);

  if (F != NULL) {
    vector<Type *> args;
    vector<Value*> subArg;
    args.push_back(g_PRegStruct);
    Type *returnTy = Type::getVoidTy(M->getContext());
    FunctionType *FT = FunctionType::get(returnTy, args, false);

    // check if driver name already exists.. maybe its the name of an
    // extcall and we will have a serious conflict?

    Function *driverF = M->getFunction(name);
    if (driverF == NULL) {
      // function does not exist. this is good.
      // insert the function prototype
      driverF = (Function *) M->getOrInsertFunction(name, FT);
    } else {
      throw TErr(__LINE__, __FILE__,
                 "Cannot insert driver. Function " + name + " already exists.");
    }

    if (driverF == NULL) {
      throw TErr(__LINE__, __FILE__,
                 "Could not get or insert function " + name);
    }

    //insert the function logical body
    //insert a primary BB
    BasicBlock *driverBB = BasicBlock::Create(driverF->getContext(),
                                              "driverBlockRaw", driverF);

    Function::ArgumentListType::iterator it =
        driverF->getArgumentList().begin();
    Function::ArgumentListType::iterator end = driverF->getArgumentList().end();

    while (it != end) {
      Argument *curArg = it;
      subArg.push_back(curArg);
      it++;
    }

    CallInst* ci = CallInst::Create(F, subArg, "", driverBB);
    ci->setCallingConv(CallingConv::X86_StdCall);
    ReturnInst::Create(driverF->getContext(), driverBB);
    return true;
  }

  return false;
}

bool addEntryPointDriver(Module *M, string name, VA entry, int np, bool ret,
                         raw_ostream &report,
                         ExternalCodeRef::CallingConvention cconv) {
  //convert the VA into a string name of a function, try and look it up
  string s("sub_" + to_string<VA>(entry, hex));
  Function *F = M->getFunction(s);
  Type *int32ty = Type::getInt32Ty(M->getContext());
  Type *int32PtrTy = PointerType::get(int32ty, 0);

  if (F != NULL) {
    //build function prototype from name and numParms
    vector<Type *> args;

    for (int i = 0; i < np; i++) {
      args.push_back(Type::getInt32Ty(M->getContext()));
    }

    Type *returnTy = NULL;
    if (ret) {
      returnTy = Type::getInt32Ty(M->getContext());
    } else {
      returnTy = Type::getVoidTy(M->getContext());
    }

    FunctionType *FT = FunctionType::get(returnTy, args, false);

    //insert the function prototype
    Function *driverF = (Function *) M->getOrInsertFunction(name, FT);
    // set drivers calling convention to match user specification
    driverF->setCallingConv(getLLVMCC(cconv));

    TASSERT(driverF != NULL, "");

    //insert the function logical body
    //insert a primary BB
    BasicBlock *driverBB = BasicBlock::Create(driverF->getContext(),
                                              "driverBlock", driverF);

    //insert an alloca for the register context structure
    Instruction *aCtx = new AllocaInst(g_RegStruct, "", driverBB);
    TASSERT(aCtx != NULL, "Could not allocate register context!");

    //write the parameters into the stack
    Function::ArgumentListType::iterator fwd_it = driverF->getArgumentList()
        .begin();
    Function::ArgumentListType::iterator fwd_end = driverF->getArgumentList()
        .end();
    AttrBuilder B;
    B.addAttribute(Attribute::InReg);

    if (cconv == ExternalCodeRef::FastCall) {
      // make __fastcall functions work:
      // set ecx to arg[0]
      if (fwd_it != fwd_end) {

        int k = x86::getRegisterOffset(ECX);
        Value *ecxFieldGEPV[] = { CONST_V<32>(driverBB, 0), CONST_V<32>(
            driverBB, k) };

        // make driver take this from register
        fwd_it->addAttr(AttributeSet::get(fwd_it->getContext(), 1, B));

        Value *ecxP = GetElementPtrInst::CreateInBounds(aCtx, ecxFieldGEPV, "",
                                                        driverBB);
        Argument *curArg = &(*fwd_it);
        aliasMCSemaScope(new StoreInst(curArg, ecxP, driverBB));
      }
      // make __fastcall functions work:
      // set edx to arg[1]
      ++fwd_it;
      if (fwd_it != fwd_end) {
        int k = x86::getRegisterOffset(EDX);
        Value *edxFieldGEPV[] = { CONST_V<32>(driverBB, 0), CONST_V<32>(
            driverBB, k) };

        // make driver take this from register
        fwd_it->addAttr(AttributeSet::get(fwd_it->getContext(), 2, B));

        Value *edxP = GetElementPtrInst::CreateInBounds(aCtx, edxFieldGEPV, "",
                                                        driverBB);

        Argument *curArg = &(*fwd_it);
        aliasMCSemaScope(new StoreInst(curArg, edxP, driverBB));
      }
    }  // fastcall

    //write the parameters into the stack
    Function::ArgumentListType::reverse_iterator it = driverF->getArgumentList()
        .rbegin();
    Function::ArgumentListType::reverse_iterator end =
        driverF->getArgumentList().rend();

    Value *stackSize = archGetStackSize(M, driverBB);
    Value *aStack = archAllocateStack(M, stackSize, driverBB);

    // position pointer to end of stack
    Value *stackBaseInt = BinaryOperator::Create(BinaryOperator::Add, aStack,
                                                 stackSize, "", driverBB);
    Value *stackPosInt = stackBaseInt;

    // decrement stackPtr to leave some slack space on the stack.
    // our current implementation of varargs functions just passes
    // a big number of arguments to the destination function.
    // This works because they are declared cdecl and the caller cleans up
    // ... BUT
    // if there is not enough stack for all these args, we may dereference
    // unallocated memory. Leave some slack so this doesn't happen.
    stackPosInt = BinaryOperator::Create(BinaryOperator::Sub, stackPosInt,
                                         CONST_V<32>(driverBB, 4 * 12), "",
                                         driverBB);

    // decrement stackPtr once to have a slot for
    // "return address", even if there are no arguments
    stackPosInt = BinaryOperator::Create(BinaryOperator::Sub, stackPosInt,
                                         CONST_V<32>(driverBB, 4), "",
                                         driverBB);

    int args_to_push = driverF->getArgumentList().size();
    if (cconv == ExternalCodeRef::FastCall) {
      // these are already in registers
      args_to_push -= 2;
      if (args_to_push < 0) {
        args_to_push = 0;
      }
    }

    // save arguments on the stack
    while (args_to_push > 0) {
      Argument *curArg = &(*it);
      // convert to int32 ptr
      Value *stackPosPtr = noAliasMCSemaScope(
          new IntToPtrInst(stackPosInt, int32PtrTy, "", driverBB));
      // write argument
      Instruction *k = noAliasMCSemaScope(
          new StoreInst(curArg, stackPosPtr, driverBB));
      // decrement stack
      stackPosInt = BinaryOperator::Create(BinaryOperator::Sub, stackPosInt,
                                           CONST_V<32>(driverBB, 4), "",
                                           driverBB);
      ++it;
      --args_to_push;
    }

    int k = x86::getRegisterOffset(ESP);
    Value *spFieldGEPV[] =
        { CONST_V<32>(driverBB, 0), CONST_V<32>(driverBB, k) };
    k = x86::getRegisterOffset(STACK_BASE);
    Value *stackBaseGEPV[] = { CONST_V<32>(driverBB, 0), CONST_V<32>(driverBB,
                                                                     k) };
    k = x86::getRegisterOffset(STACK_LIMIT);
    Value *stackLimitGEPV[] = { CONST_V<32>(driverBB, 0), CONST_V<32>(driverBB,
                                                                      k) };

    Value *spValP = GetElementPtrInst::CreateInBounds(aCtx, spFieldGEPV, "",
                                                      driverBB);

    Value *sBaseValP = GetElementPtrInst::CreateInBounds(aCtx, stackBaseGEPV,
                                                         "", driverBB);

    Value *sLimitValP = GetElementPtrInst::CreateInBounds(aCtx, stackLimitGEPV,
                                                          "", driverBB);

    // stack limit = start of allocation (stack grows down);
    Instruction *tmp1 = aliasMCSemaScope(
        new StoreInst(aStack, sLimitValP, driverBB));
    // stack base = stack alloc start + stack size
    Instruction *tmp2 = aliasMCSemaScope(
        new StoreInst(stackBaseInt, sBaseValP, driverBB));

    // all functions assume DF is clear on entry
    k = x86::getRegisterOffset(DF);
    Value *dflagGEPV[] = { CONST_V<32>(driverBB, 0), CONST_V<32>(driverBB, k) };

    Value *dflagP = GetElementPtrInst::CreateInBounds(aCtx, dflagGEPV, "",
                                                      driverBB);

    Instruction *tmp3 = aliasMCSemaScope(
        new StoreInst(CONST_V<1>(driverBB, 0), dflagP, driverBB));

    Instruction *j = aliasMCSemaScope(
        new StoreInst(stackPosInt, spValP, driverBB));
    TASSERT(j != NULL, "Could not write stack value to ESP");

    //call the sub function with register struct as argument
    vector<Value*> subArg;

    subArg.push_back(aCtx);

    CallInst* ci = CallInst::Create(F, subArg, "", driverBB);
    ci->setCallingConv(CallingConv::X86_StdCall);

    archFreeStack(M, aStack, driverBB);

    //if we are requested, return the EAX value, else return void
    if (ret) {
      //do a GEP and load for the EAX register in the reg structure
      int j = x86::getRegisterOffset(EAX);
      Value *eaxGEPV[] = { CONST_V<32>(driverBB, 0), CONST_V<32>(driverBB, j) };

      Value *eaxVP = GetElementPtrInst::CreateInBounds(aCtx, eaxGEPV, "",
                                                       driverBB);
      Instruction *eaxV = aliasMCSemaScope(new LoadInst(eaxVP, "", driverBB));

      //return that value
      ReturnInst::Create(driverF->getContext(), eaxV, driverBB);
    } else {
      ReturnInst::Create(driverF->getContext(), driverBB);
    }

  } else {
    report << "Could not find entry point function\n";
    return false;
  }

  return true;
}
}

static Constant* makeConstantBlob(LLVMContext &ctx,
                                  const vector<uint8_t> &blob) {

  Type *charTy = Type::getInt8Ty(ctx);
  //cout << blob.size() << "\n";
  //cout.flush();
  ArrayType *arrT = ArrayType::get(charTy, blob.size());
  vector<uint8_t>::const_iterator it = blob.begin();
  vector<Constant*> array_elements;
  while (it != blob.end()) {
    uint8_t cur = *it;
    IntegerType *ty = Type::getInt8Ty(ctx);
    Constant *c = ConstantInt::get(ty, cur);

    array_elements.push_back(c);
    ++it;
  }

  return ConstantArray::get(arrT, array_elements);
}

static GlobalVariable* getSectionForDataAddr(const list<DataSection> &dataSecs,
                                             Module *M, VA data_addr,
                                             VA &section_base) {

  for (list<DataSection>::const_iterator git = dataSecs.begin();
      git != dataSecs.end(); git++) {
    const DataSection &dt = *git;
    VA start = dt.getBase();
    VA end = start + dt.getSize();

    if (data_addr >= start && data_addr < end) {
      std::string gvar_name = "data_0x" + to_string<VA>(start, hex);  //+"_ptr";
      section_base = start;
      return M->getNamedGlobal(gvar_name);
    }

  }

  return NULL;

}

static Constant* getPtrSizedValue(Module *M, Constant *v, int valsize) {
        Constant *final_val = v;

        //if(getPointerSize(M) == Pointer32) {
        //    TASSERT( valsize == 4, "Invalid size of pointer ref")
        //} else  if(getPointerSize(M) == Pointer64) {
        //    TASSERT( valsize == 8, "Invalid size of pointer ref")
        //}

        // 
        // this sometimes doesn't work since LLVM assembler is broken :(
        //
        if ( (getPointerSize(M) == Pointer32 && valsize == 4) ||
                (getPointerSize(M) == Pointer64 && valsize == 8) ) {
            final_val = v;
        } else if (getPointerSize(M) == Pointer64 && valsize == 4)  {
          Constant *int_val = ConstantExpr::getPtrToInt(
              v, Type::getInt64Ty(M->getContext()));
          final_val = ConstantExpr::getTrunc(int_val, Type::getInt32Ty(M->getContext()));
        }

        return final_val;
}

void dataSectionToTypesContents(const list<DataSection> &globaldata,
                                DataSection& ds, Module *M,
                                vector<Constant*>& secContents,
                                vector<Type*>& data_section_types,
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
  for (list<DataSectionEntry>::const_iterator dsec_itr = ds_entries.begin();
      dsec_itr != ds_entries.end(); dsec_itr++) {
    string sym_name;

    if (dsec_itr->getSymbol(sym_name)) {
      const char *func_addr_str = sym_name.c_str() + 4;
      VA func_addr = strtol(func_addr_str, NULL, 16);

      cout << __FUNCTION__ << ": Found symbol: " << sym_name << "\n";

      if (sym_name.find("ext_") == 0) {

        Constant *final_val  = nullptr;

        GlobalValue *ext_v = M->getNamedValue(func_addr_str);

        if(ext_v != nullptr && isa<Function>(ext_v)) {
            final_val = getPtrSizedValue(M, ext_v, dsec_itr->getSize());
            //cout << "External function" << sym_name << " has type: " << final_val->getType() << "\n";
        } else if(ext_v != nullptr) {
            final_val = getPtrSizedValue(M, ext_v, dsec_itr->getSize());
            //cout << "External data" << sym_name << " has type: " << final_val->getType() << "\n";
            // assume ext data
        } else {
            TASSERT(ext_v != nullptr, "Could not find external: " + string(func_addr_str));
            //cout << "External fail" << sym_name << " has type: " << final_val->getType() << "\n";
        }


        secContents.push_back(final_val);
        data_section_types.push_back(final_val->getType());

      } else if (sym_name.find("sub_") == 0) {
        // add function pointer to data section
        // to do this, create a callback driver for
        // it first (since it may be called externally)

        Function *func = NULL;

        if (convert_to_callback) {
          func = dynamic_cast<Function*>(archMakeCallbackForLocalFunction(
              M, func_addr));
          TASSERT(func != NULL, "Could make callback for: " + sym_name);
        } else {
          func = M->getFunction(sym_name);
          TASSERT(func != NULL, "Could not find function: " + sym_name);
        }

        Constant *final_val = getPtrSizedValue(M, func, dsec_itr->getSize());
        secContents.push_back(final_val);
        data_section_types.push_back(final_val->getType());

      } else {
        // data symbol
        // get the base of the data section for this symobol
        // then compute the offset from base of data
        // and store as integer value of (base+offset)
        VA section_base;
        GlobalVariable *g_ref = getSectionForDataAddr(globaldata, M, func_addr,
                                                      section_base);
        TASSERT(g_ref != NULL,
                "Could not get data addr for:" + string(func_addr_str));
        // instead of referencing an element directly
        // we just convert the pointer to an integer
        // and add its offset from the base of data
        // to the new data section pointer
        VA addr_diff = func_addr - section_base;
        Constant *final_val;
        //cout << " Symbol name : " << string(func_addr_str) << " : "
        //     << to_string<VA>(func_addr, hex) << " : "
        //     << to_string<VA>(section_base, hex) << "\n";
        //cout.flush();
        if (getPointerSize(M) == Pointer32) {
          Constant *int_val = ConstantExpr::getPtrToInt(
              g_ref, Type::getInt32Ty(M->getContext()));
          final_val = ConstantExpr::getAdd(
              int_val, CONST_V_INT<32>(M->getContext(), addr_diff));
        } else {
          Constant *int_val = ConstantExpr::getPtrToInt(
              g_ref, Type::getInt64Ty(M->getContext()));
          final_val = ConstantExpr::getAdd(
              int_val, CONST_V_INT<64>(M->getContext(), addr_diff));
        }
        secContents.push_back(final_val);
        data_section_types.push_back(final_val->getType());
      }
    } else {
      // add array
      // this holds opaque data in a byte array
      Constant *arr = makeConstantBlob(M->getContext(), dsec_itr->getBytes());
      secContents.push_back(arr);
      data_section_types.push_back(arr->getType());
    }  // if dsec_itr
  }  // for list
}

static bool insertDataSections(NativeModulePtr natMod, Module *M,
                               raw_ostream &report) {

  list<DataSection> &globaldata = natMod->getData();
  list<DataSection>::iterator git = globaldata.begin();

  //insert all global data before we insert the CFG

  vector<pair<StructType*, GlobalVariable*> > gvars;

  // pre-create references to all data sections
  // as later we may have data references that are
  // from one section into another

  while (git != globaldata.end()) {
    DataSection &dt = *git;
    string bufferName;
    bufferName = "data_0x" + to_string<VA>(dt.getBase(), hex);
    //report << "inserting global data section named ";
    //report << bufferName << "\n";
    std::cout << "inserting global data section named ";
    std::cout << bufferName << std::endl;

    StructType *st_opaque = StructType::create(M->getContext());
    GlobalVariable *g = new GlobalVariable(*M, st_opaque, dt.isReadOnly(),
    // Used to be PrivateLinkage, but that emitted
    // .objs that would not link with MSVC
                                           GlobalVariable::InternalLinkage,
                                           NULL,
                                           bufferName);
    gvars.push_back(pair<StructType*, GlobalVariable*>(st_opaque, g));
    git++;
  }

  // actually populate the data sections
  git = globaldata.begin();
  vector<pair<StructType*, GlobalVariable*> >::const_iterator gvit =
      gvars.begin();
  while (git != globaldata.end() && gvit != gvars.end()) {
    //data from the native module
    DataSection &dt = *git;

    //data we use to create LLVM values for this section
    // secContents is the actual values we will be inserting
    vector<Constant*> secContents;
    // data_section_types is their types, which are needed to initialize
    // the global variable
    vector<Type*> data_section_types;

    // create an opaque structure so we can create an opaque global
    // variable.
    // The opaque variable currently serves as a base for self-
    // referential data.
    StructType *st_opaque = gvit->first;
    GlobalVariable *g = gvit->second;

    dataSectionToTypesContents(globaldata, dt, M, secContents,
                               data_section_types, true);

    // fill in the opaqure structure with actual members
    st_opaque->setBody(data_section_types, true);

    // create an initializer list using the now filled in opaque
    // structure type
    Constant *cst = ConstantStruct::get(st_opaque, secContents);
    // align on pointer size boundary, max needed by SSE instructions
    g->setAlignment(getPointerSize(M));
    g->setInitializer(cst);

    git++;
    gvit++;

  }  // while git != globaldata.end()

  return true;

}

bool natModToModule(NativeModulePtr natMod, Module *M, raw_ostream &report) {
  bool result = true;

  //iterate over every functions CFG we identified in natMod
  list<NativeFunctionPtr> funcs = natMod->get_funcs();
  list<NativeFunctionPtr>::iterator i = funcs.begin();

  // insert all functions (but not populate yet)
  while (i != funcs.end()) {
    NativeFunctionPtr f = *i;
    std::string fname = f->get_name();

    Function *F = M->getFunction(fname);

    if (F == NULL) {
      Constant *FC = M->getOrInsertFunction(fname, getBaseFunctionType(M));
      F = dyn_cast<Function>(FC);

      TASSERT(F != NULL, "Could not insert function into module");

      archSetCallingConv(M, F);
      // make local functions 'static'
      F->setLinkage(GlobalValue::InternalLinkage);
      cout << "Inserted function: " << fname << std::endl;
    } else {
      cout << "Already inserted function: " << fname << ", skipping."
           << std::endl;
    }

    ++i;
  }

  list<ExternalDataRefPtr> extDataRefs = natMod->getExtDataRefs();
  list<ExternalDataRefPtr>::iterator data_it = extDataRefs.begin();

  for (; data_it != extDataRefs.end(); ++data_it) {
    ExternalDataRefPtr dr = *data_it;
    int dsize = dr->getDataSize();
    std::string symname = dr->getSymbolName();
    //if (dsize > 16) {
    //  throw TErr(__LINE__, __FILE__, "Unsupported external data size!");
    //}

    //Type *extType = Type::getIntNTy(M->getContext(), dsize * 8);
    Type *extType = ArrayType::get(Type::getInt8Ty(M->getContext()), 
            dsize);

    GlobalValue *gv = dyn_cast<GlobalValue>(
        M->getOrInsertGlobal(symname, extType));
    TASSERT(gv != NULL, "Could not make global value!");
    if(dr->isWeak())
    {
      gv->setLinkage(
          /*GlobalValue::AvailableExternallyLinkage*/GlobalValue::ExternalWeakLinkage);
    }
    else
    {
      gv->setLinkage(
          /*GlobalValue::AvailableExternallyLinkage*/GlobalValue::ExternalLinkage);
    }

    const std::string &triple = M->getTargetTriple();

    if (triple == WINDOWS_TRIPLE) {
      // this only makes sense for win32
      gv->setDLLStorageClass(GlobalValue::DLLImportStorageClass);
    }
  }

  //iterate over the list of external functions and insert them as
  //global functions
  list<ExternalCodeRefPtr> extCalls = natMod->getExtCalls();
  list<ExternalCodeRefPtr>::iterator it = extCalls.begin();
  for (; it != extCalls.end(); ++it) {
    ExternalCodeRefPtr e = *it;

    ExternalCodeRef::CallingConvention conv = e->getCallingConvention();
    int8_t argCount = e->getNumArgs();
    string symName = e->getSymbolName();
    string funcSign = e->getFunctionSignature();

    //create the function if it is not already there
    Function *f = M->getFunction(symName);
    if (f == NULL) {
      vector<Type*> arguments;
      Type *returnType = NULL;

      //create arguments
      for (int i = 0; i < argCount; i++) {
        if (getSystemArch(M) == _X86_64_) {
          if (getSystemOS(M) == llvm::Triple::Win32) {

            if (funcSign.c_str()[i] == 'f') {
              arguments.push_back(Type::getDoubleTy(M->getContext()));
            } else {
              arguments.push_back(Type::getIntNTy(M->getContext(), 64));
            }
          } else if (getSystemOS(M) == llvm::Triple::Linux) {
            arguments.push_back(Type::getInt64Ty(M->getContext()));

          } else {
            TASSERT(false, "Unknown OS Type!");
          }
        } else {
          arguments.push_back(Type::getInt32Ty(M->getContext()));
        }
      }

      //create function type
      switch (e->getReturnType()) {
        case ExternalCodeRef::NoReturn:
        case ExternalCodeRef::VoidTy:
          returnType = Type::getVoidTy(M->getContext());
          break;

        case ExternalCodeRef::Unknown:
        case ExternalCodeRef::IntTy:
          if (natMod->is64Bit()) {
            returnType = Type::getInt64Ty(M->getContext());
          } else {
            returnType = Type::getInt32Ty(M->getContext());
          }
          break;
        default:
          throw TErr(
              __LINE__, __FILE__,
              "Encountered an unknown return type while translating function");
      }
      FunctionType *ft = FunctionType::get(returnType, arguments, false);
      if(e->isWeak())
      {
        f = Function::Create(ft, GlobalValue::ExternalWeakLinkage, symName, M);
      }
      else
      {
        f = Function::Create(ft, GlobalValue::ExternalLinkage, symName, M);
      }

      if (e->getReturnType() == ExternalCodeRef::NoReturn) {
        f->setDoesNotReturn();
      }

      //set calling convention
      if (natMod->is64Bit()) {
        archSetCallingConv(M, f);
      } else {
        f->setCallingConv(getLLVMCC(conv));
      }
    }
  }

  // insert data after functions -- data may have function references
  insertDataSections(natMod, M, report);

  // populate functions
  i = funcs.begin();
  while (i != funcs.end()) {
    NativeFunctionPtr f = *i;

    if (insertFunctionIntoModule(natMod, f, M) == false) {
        std::string fname = f->get_name();
        cerr << "Could not insert function: " << fname << " into the LLVM module\n";
        result = false;
        break;
    }
    ++i;
  }

  return result;
}
