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
#include "toLLVM.h"
#include "raiseX86.h"
#include "X86.h"
#include "x86Instrs.h"
#include "x86Helpers.h"
#include "ArchOps.h"
#include "RegisterUsage.h"

#include "llvm/ADT/StringSwitch.h"

#include "llvm/Bitcode/ReaderWriter.h"

#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"

#include "llvm/LinkAllPasses.h"

#include "llvm/Object/COFF.h"

#include "llvm/Support/CommandLine.h"

#include <boost/graph/breadth_first_search.hpp>
#include "Externals.h"
#include "../common/to_string.h"
#include "../common/Defaults.h"
#include "Annotation.h"

#include <vector>

using namespace llvm;
using namespace std;

bool ignoreUnsupportedInsts = false;

static llvm::cl::opt<bool> AddBreakpoints(
    "add-breakpoints",
    llvm::cl::desc(
        "Add debug breakpoint function calls before each lifted instruction."),
    llvm::cl::init(false));


static llvm::cl::opt<bool> BlockPerInstr(
    "put-instrs-in-blocks",
    llvm::cl::desc(
        "Add debug breakpoint function calls before each lifted instruction."),
    llvm::cl::init(false));


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
    case ExternalCodeRef::McsemaCall:
      // mcsema internal calls are cdecl with one argument
      return CallingConv::C;
    default:
      throw TErr(__LINE__, __FILE__, "Unknown calling convention!");
      break;
  }

  return CallingConv::C;
}

llvm::Value *INTERNAL_M_READ(unsigned width, unsigned addrspace,
                             llvm::BasicBlock *b, llvm::Value *addr) {
  llvm::Value *readLoc = addr;
  llvm::LLVMContext &C = b->getContext();

  auto readLocTy = readLoc->getType();
  llvm::Type *PtrTy = llvm::Type::getIntNPtrTy(C, width, addrspace);

  if (readLocTy != PtrTy) {
    if (readLocTy->isPointerTy()) {
      const llvm::DataLayout *DL = b->getDataLayout();
      llvm::Type *IntPtrTy = DL->getIntPtrType(C, addrspace);
      readLoc = new llvm::PtrToIntInst(readLoc, IntPtrTy, "", b);
    }

    TASSERT(readLoc->getType()->isIntegerTy(), "Expected integer type.");
    readLoc = new llvm::IntToPtrInst(readLoc, PtrTy, "", b);
  }

  bool is_volatile = addrspace != 0;
  llvm::Instruction *read = noAliasMCSemaScope(
      new llvm::LoadInst(readLoc, "", is_volatile, b));

  TASSERT(read != nullptr, "Could not create a LoadInst in M_READ");

  return read;
}

void INTERNAL_M_WRITE(int width, unsigned addrspace, llvm::BasicBlock *b,
                      llvm::Value *addr, llvm::Value *data) {
  llvm::Value *writeLoc = addr;
  llvm::LLVMContext &C = b->getContext();
  auto writeLocTy = writeLoc->getType();
  llvm::Type *PtrTy = llvm::Type::getIntNPtrTy(C, width, addrspace);

  if (writeLocTy != PtrTy) {
    if (writeLocTy->isPointerTy()) {
      const llvm::DataLayout *DL = b->getDataLayout();
      llvm::Type *IntPtrTy = DL->getIntPtrType(C, addrspace);
      writeLoc = new llvm::PtrToIntInst(writeLoc, IntPtrTy, "", b);
    }

    TASSERT(writeLoc->getType()->isIntegerTy(), "Expected integer type.");

    writeLoc = new llvm::IntToPtrInst(writeLoc, PtrTy, "", b);
  }

  bool is_volatile = addrspace != 0;

  llvm::Instruction *written = noAliasMCSemaScope(
      new llvm::StoreInst(data, writeLoc, is_volatile, b));
  noAliasMCSemaScope(written);

  TASSERT(written != nullptr, "");

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
  TASSERT(written != nullptr, "Failed to create StoreInst");

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

Value *MCRegToValue(BasicBlock *b, unsigned reg) {
  Module *M = b->getParent()->getParent();

  if (ArchPointerSize(M) == Pointer32) {
    return x86::MCRegToValue(b, reg);
  } else {
    return x86_64::MCRegToValue(b, reg);
  }
}

static int accessOffset(int reg) {
  switch (reg) {
    case llvm::X86::DH:
      return 8;
    case llvm::X86::CH:
      return 8;
    case llvm::X86::BH:
      return 8;
    case llvm::X86::AH:
      return 8;
    default:
      return 0;
  }
}

static int readRegWidth(int reg) {
  switch (reg) {
    case llvm::X86::DH:
      return 8;
    case llvm::X86::CH:
      return 8;
    case llvm::X86::BH:
      return 8;
    case llvm::X86::AH:
      return 8;
    case llvm::X86::AX:
      return 16;
    case llvm::X86::AL:
      return 8;
    case llvm::X86::EAX:
      return 32;
    case llvm::X86::RAX:
      return 64;
    case llvm::X86::BX:
      return 16;
    case llvm::X86::BL:
      return 8;
    case llvm::X86::EBX:
      return 32;
    case llvm::X86::RBX:
      return 64;
    case llvm::X86::CX:
      return 16;
    case llvm::X86::CL:
      return 8;
    case llvm::X86::ECX:
      return 32;
    case llvm::X86::RCX:
      return 64;
    case llvm::X86::DX:
      return 16;
    case llvm::X86::DL:
      return 8;
    case llvm::X86::EDX:
      return 32;
    case llvm::X86::RDX:
      return 64;
    case llvm::X86::SIL:
      return 8;
    case llvm::X86::SI:
      return 16;
    case llvm::X86::ESI:
      return 32;
    case llvm::X86::RSI:
      return 64;
    case llvm::X86::DIL:
      return 8;
    case llvm::X86::DI:
      return 16;
    case llvm::X86::EDI:
      return 32;
    case llvm::X86::RDI:
      return 64;
    case llvm::X86::SPL:
      return 8;
    case llvm::X86::SP:
      return 16;
    case llvm::X86::ESP:
      return 32;
    case llvm::X86::RSP:
      return 64;
    case llvm::X86::BPL:
      return 8;
    case llvm::X86::BP:
      return 16;
    case llvm::X86::EBP:
      return 32;
    case llvm::X86::RBP:
      return 64;
    case llvm::X86::R8B:
      return 8;
    case llvm::X86::R8W:
      return 16;
    case llvm::X86::R8D:
      return 32;
    case llvm::X86::R8:
      return 64;
    case llvm::X86::R9B:
      return 8;
    case llvm::X86::R9W:
      return 16;
    case llvm::X86::R9D:
      return 32;
    case llvm::X86::R9:
      return 64;
    case llvm::X86::R10B:
      return 8;
    case llvm::X86::R10W:
      return 16;
    case llvm::X86::R10D:
      return 32;
    case llvm::X86::R10:
      return 64;
    case llvm::X86::R11B:
      return 8;
    case llvm::X86::R11W:
      return 16;
    case llvm::X86::R11D:
      return 32;
    case llvm::X86::R11:
      return 64;
    case llvm::X86::R12B:
      return 8;
    case llvm::X86::R12W:
      return 16;
    case llvm::X86::R12D:
      return 32;
    case llvm::X86::R12:
      return 64;
    case llvm::X86::R13B:
      return 8;
    case llvm::X86::R13W:
      return 16;
    case llvm::X86::R13D:
      return 32;
    case llvm::X86::R13:
      return 64;
    case llvm::X86::R14B:
      return 8;
    case llvm::X86::R14W:
      return 16;
    case llvm::X86::R14D:
      return 32;
    case llvm::X86::R14:
      return 64;
    case llvm::X86::R15B:
      return 8;
    case llvm::X86::R15W:
      return 16;
    case llvm::X86::R15D:
      return 32;
    case llvm::X86::R15:
      return 64;

    case llvm::X86::ST0:
      return 80;
    case llvm::X86::ST1:
      return 80;
    case llvm::X86::ST2:
      return 80;
    case llvm::X86::ST3:
      return 80;
    case llvm::X86::ST4:
      return 80;
    case llvm::X86::ST5:
      return 80;
    case llvm::X86::ST6:
      return 80;
    case llvm::X86::ST7:
      return 80;

    case llvm::X86::XMM0:
      return 128;
    case llvm::X86::XMM1:
      return 128;
    case llvm::X86::XMM2:
      return 128;
    case llvm::X86::XMM3:
      return 128;
    case llvm::X86::XMM4:
      return 128;
    case llvm::X86::XMM5:
      return 128;
    case llvm::X86::XMM6:
      return 128;
    case llvm::X86::XMM7:
      return 128;
    case llvm::X86::XMM8:
      return 128;
    case llvm::X86::XMM9:
      return 128;
    case llvm::X86::XMM10:
      return 128;
    case llvm::X86::XMM11:
      return 128;
    case llvm::X86::XMM12:
      return 128;
    case llvm::X86::XMM13:
      return 128;
    case llvm::X86::XMM14:
      return 128;
    case llvm::X86::XMM15:
      return 128;

    case llvm::X86::EIP:
      return 32;
    case llvm::X86::RIP:
      return 64;

    default:
      throw TErr(__LINE__, __FILE__,
                 "Reg type " + to_string<unsigned>(reg, dec) + " is unknown");
  }

  return -1;
}

static const char *regName(int reg) {
  switch (reg) {
    case llvm::X86::DH:
      return "DH";
    case llvm::X86::CH:
      return "CH";
    case llvm::X86::BH:
      return "BH";
    case llvm::X86::AH:
      return "AH";
    case llvm::X86::AX:
      return "AX";
    case llvm::X86::AL:
      return "AL";
    case llvm::X86::EAX:
      return "EAX";
    case llvm::X86::RAX:
      return "RAX";
    case llvm::X86::BX:
      return "BX";
    case llvm::X86::BL:
      return "BL";
    case llvm::X86::EBX:
      return "EBX";
    case llvm::X86::RBX:
      return "RBX";
    case llvm::X86::CX:
      return "CX";
    case llvm::X86::CL:
      return "CL";
    case llvm::X86::ECX:
      return "ECX";
    case llvm::X86::RCX:
      return "RCX";
    case llvm::X86::DX:
      return "DX";
    case llvm::X86::DL:
      return "DL";
    case llvm::X86::EDX:
      return "EDX";
    case llvm::X86::RDX:
      return "RDX";
    case llvm::X86::SIL:
      return "SIL";
    case llvm::X86::SI:
      return "SI";
    case llvm::X86::ESI:
      return "ESI";
    case llvm::X86::RSI:
      return "RSI";
    case llvm::X86::DIL:
      return "DIL";
    case llvm::X86::DI:
      return "DI";
    case llvm::X86::EDI:
      return "EDI";
    case llvm::X86::RDI:
      return "RDI";
    case llvm::X86::SPL:
      return "SPL";
    case llvm::X86::SP:
      return "SP";
    case llvm::X86::ESP:
      return "ESP";
    case llvm::X86::RSP:
      return "RSP";
    case llvm::X86::BPL:
      return "BPL";
    case llvm::X86::BP:
      return "BP";
    case llvm::X86::EBP:
      return "EBP";
    case llvm::X86::RBP:
      return "RBP";
    case llvm::X86::R8B:
      return "R8B";
    case llvm::X86::R8W:
      return "R8W";
    case llvm::X86::R8D:
      return "R8D";
    case llvm::X86::R8:
      return "R8";
    case llvm::X86::R9B:
      return "R9B";
    case llvm::X86::R9W:
      return "R9W";
    case llvm::X86::R9D:
      return "R9D";
    case llvm::X86::R9:
      return "R9";
    case llvm::X86::R10B:
      return "R10B";
    case llvm::X86::R10W:
      return "R10W";
    case llvm::X86::R10D:
      return "R10D";
    case llvm::X86::R10:
      return "R10";
    case llvm::X86::R11B:
      return "R11B";
    case llvm::X86::R11W:
      return "R11W";
    case llvm::X86::R11D:
      return "R11D";
    case llvm::X86::R11:
      return "R11";
    case llvm::X86::R12B:
      return "R12B";
    case llvm::X86::R12W:
      return "R12W";
    case llvm::X86::R12D:
      return "R12D";
    case llvm::X86::R12:
      return "R12";
    case llvm::X86::R13B:
      return "R13B";
    case llvm::X86::R13W:
      return "R13W";
    case llvm::X86::R13D:
      return "R13D";
    case llvm::X86::R13:
      return "R13";
    case llvm::X86::R14B:
      return "R14B";
    case llvm::X86::R14W:
      return "R14W";
    case llvm::X86::R14D:
      return "R14D";
    case llvm::X86::R14:
      return "R14";
    case llvm::X86::R15B:
      return "R15B";
    case llvm::X86::R15W:
      return "R15W";
    case llvm::X86::R15D:
      return "R15D";
    case llvm::X86::R15:
      return "R15";

    case llvm::X86::ST0:
      return "ST0";
    case llvm::X86::ST1:
      return "ST1";
    case llvm::X86::ST2:
      return "ST2";
    case llvm::X86::ST3:
      return "ST3";
    case llvm::X86::ST4:
      return "ST4";
    case llvm::X86::ST5:
      return "ST5";
    case llvm::X86::ST6:
      return "ST6";
    case llvm::X86::ST7:
      return "ST7";

    case llvm::X86::XMM0:
      return "XMM0";
    case llvm::X86::XMM1:
      return "XMM1";
    case llvm::X86::XMM2:
      return "XMM2";
    case llvm::X86::XMM3:
      return "XMM3";
    case llvm::X86::XMM4:
      return "XMM4";
    case llvm::X86::XMM5:
      return "XMM5";
    case llvm::X86::XMM6:
      return "XMM6";
    case llvm::X86::XMM7:
      return "XMM7";
    case llvm::X86::XMM8:
      return "XMM8";
    case llvm::X86::XMM9:
      return "XMM9";
    case llvm::X86::XMM10:
      return "XMM10";
    case llvm::X86::XMM11:
      return "XMM11";
    case llvm::X86::XMM12:
      return "XMM12";
    case llvm::X86::XMM13:
      return "XMM13";
    case llvm::X86::XMM14:
      return "XMM14";
    case llvm::X86::XMM15:
      return "XMM15";

    case llvm::X86::EIP:
      return "EIP";
    case llvm::X86::RIP:
      return "RIP";

    default:
      throw TErr(__LINE__, __FILE__,
                 "Reg type " + to_string<unsigned>(reg, dec) + " is unknown");
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

Type *BackingRegTy(llvm::Value *V) {
  if (auto alloca_inst = llvm::dyn_cast<llvm::AllocaInst>(V)) {
    return alloca_inst->getAllocatedType();
  } else if (auto gep_inst = llvm::dyn_cast<llvm::GetElementPtrInst>(V)) {
    return gep_inst->getType()->getArrayElementType();
  } else {
    return nullptr;
  }
}

void GENERIC_MC_WRITEREG(BasicBlock *b, int mc_reg, Value *v) {
  auto M = b->getParent()->getParent();
  auto &C = M->getContext();
  auto backing_reg = MCRegToValue(b, mc_reg);
  auto backing_reg_ty = BackingRegTy(backing_reg);
  auto size = readRegWidth(mc_reg);
  auto index_in_backing_reg = accessOffset(mc_reg) / 8;
  if (32 == size && Pointer64 == ArchPointerSize(M)) {
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
  llvm::Value *addr = nullptr;

  if (index_in_backing_reg) {
    auto i32_ty = Type::getInt32Ty(C);
    auto index = ConstantInt::get(i32_ty, index_in_backing_reg, false);
    auto cast = new llvm::BitCastInst(backing_reg, value_ptr_ty, "", b);
    llvm::Value *index_list[] = {index};
    addr = llvm::GetElementPtrInst::Create(cast, index_list,
                                           regAddrName(mc_reg), b);
  } else {
    addr = new llvm::BitCastInst(backing_reg, value_ptr_ty, regAddrName(mc_reg),
                                 b);
  }

  new llvm::StoreInst(v, addr, b);
}

Value *GENERIC_MC_READREG(BasicBlock *b, int mc_reg, int desired_size) {
  auto M = b->getParent()->getParent();
  auto &C = M->getContext();
  auto backing_reg = MCRegToValue(b, mc_reg);
  auto backing_reg_ty = BackingRegTy(backing_reg);
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

    llvm::Value *addr = nullptr;
    if (index_in_backing_reg) {
      auto i32_ty = Type::getInt32Ty(C);
      auto index = ConstantInt::get(i32_ty, index_in_backing_reg, false);
      auto cast = new llvm::BitCastInst(backing_reg, dst_ptr_ty, "", b);
      llvm::Value *index_list[] = {index};
      addr = llvm::GetElementPtrInst::Create(cast, index_list,
                                             regAddrName(mc_reg), b);
    } else {
      addr = new llvm::BitCastInst(backing_reg, dst_ptr_ty, regAddrName(mc_reg),
                                   b);
    }

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

  if (ArchPointerSize(M) == Pointer32) {
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

  if (ArchPointerSize(M) == Pointer32) {
    localRegVar = x86::lookupLocal(b->getParent(), reg);
    regName = x86::getRegisterName(reg);
  } else {
    localRegVar = x86_64::lookupLocal(b->getParent(), reg);
    regName = x86_64::getRegisterName(reg);
  }
  if (localRegVar == nullptr)
    throw TErr(__LINE__, __FILE__, "regname " + regName + " not found");
  Instruction *st = noAliasMCSemaScope(new StoreInst(v, localRegVar, b));
  TASSERT(st != nullptr, "");
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

namespace x86 {
static Instruction *GEPLocal(Type *Ty, const char *name, BasicBlock *B) {
  auto reg = getRegisterFromName(name);
  auto F = B->getParent();
  auto &C = F->getContext();
  auto i32_ty = Type::getInt32Ty(C);
  llvm::Value *indexes[] = {ConstantInt::get(i32_ty, 0), ConstantInt::get(
      i32_ty, getRegisterOffset(reg))};
  auto state_ptr = & *F->arg_begin();
  Instruction *ptr = GetElementPtrInst::Create(state_ptr, indexes, name, B);

  // Round up to nearest byte size.
  if (auto IntTy = dyn_cast<IntegerType>(Ty)) {
    auto bit_width = (IntTy->getBitWidth() + 7) & ~7;
    if (IntTy->getBitWidth() != bit_width) {
      auto PtrIntTy = Type::getIntNPtrTy(C, IntTy->getBitWidth());

      ptr->setName(ptr->getName() + "_full");
      ptr = new BitCastInst(ptr, PtrIntTy, name, B);
    }
  }

  return ptr;
}
static Instruction *GEPLocal(Type *Ty, const char *name, Instruction *I) {
  return GEPLocal(Ty, name, I->getParent());
}
}  // namespace x86

namespace x86_64 {
static Instruction *GEPLocal(Type *Ty, const char *name, BasicBlock *B) {
  auto reg = getRegisterFromName(name);
  auto F = B->getParent();
  auto &C = F->getContext();
  auto i32_ty = Type::getInt32Ty(C);
  llvm::Value *indexes[] = {ConstantInt::get(i32_ty, 0), ConstantInt::get(
      i32_ty, getRegisterOffset(reg))};
  auto state_ptr = & *F->arg_begin();
  Instruction *ptr = GetElementPtrInst::Create(state_ptr, indexes, name, B);

  // Round up to nearest byte size.
  if (auto IntTy = dyn_cast<IntegerType>(Ty)) {
    auto bit_width = (IntTy->getBitWidth() + 7) & ~7;
    if (IntTy->getBitWidth() != bit_width) {
      auto PtrIntTy = Type::getIntNPtrTy(C, IntTy->getBitWidth());

      ptr->setName(ptr->getName() + "_full");
      ptr = new BitCastInst(ptr, PtrIntTy, name, B);
    }
  }

  return ptr;
}

static Instruction *GEPLocal(Type *Ty, const char *name, Instruction *I) {
  return GEPLocal(Ty, name, I->getParent());
}

}  // namespace x86

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
      Type *RegTy = Type::getInt32Ty(F->getContext());

      Instruction *eipA = x86::GEPLocal(RegTy, "XIP", begin);
      Instruction *eaxA = x86::GEPLocal(RegTy, "XAX", eipA);
      Instruction *ebxA = x86::GEPLocal(RegTy, "XBX", eaxA);
      Instruction *ecxA = x86::GEPLocal(RegTy, "XCX", ebxA);
      Instruction *edxA = x86::GEPLocal(RegTy, "XDX", ecxA);
      Instruction *esiA = x86::GEPLocal(RegTy, "XSI", edxA);
      Instruction *ediA = x86::GEPLocal(RegTy, "XDI", esiA);
      Instruction *ebpA = x86::GEPLocal(RegTy, "XBP", ediA);
      Instruction *espA = x86::GEPLocal(RegTy, "XSP", ebpA);
      //create other fields for flags

      Type *boolTy = Type::getInt1Ty(F->getContext());
      Instruction *zfA = x86::GEPLocal(boolTy, "ZF", espA);
      Instruction *sfA = x86::GEPLocal(boolTy, "PF", zfA);
      Instruction *ofA = x86::GEPLocal(boolTy, "AF", sfA);
      Instruction *cfA = x86::GEPLocal(boolTy, "CF", ofA);
      Instruction *pfA = x86::GEPLocal(boolTy, "SF", cfA);
      Instruction *afA = x86::GEPLocal(boolTy, "OF", pfA);
      Instruction *dfA = x86::GEPLocal(boolTy, "DF", afA);
      TASSERT(dfA != nullptr, "");

      // FPU STACK
      Type *floatTy = Type::getX86_FP80Ty(F->getContext());
      // 8 float values make up the ST registers
      Type *floatArrayTy = ArrayType::get(floatTy, 8);
      Instruction *stRegs = x86::GEPLocal(floatArrayTy, "STi", afA);

      // FPU FLAGS
      Instruction *fpu_B = x86::GEPLocal(boolTy, "FPU_FLAG_BUSY", stRegs);
      Instruction *fpu_C3 = x86::GEPLocal(boolTy, "FPU_FLAG_C3", fpu_B);

      // TOP of stack from FPU flags
      // really a 3-bit integer
      Type *topTy = Type::getIntNTy(F->getContext(), 3);
      Instruction *fpu_TOP = x86::GEPLocal(topTy, "FPU_FLAG_TOP", fpu_C3);
      TASSERT(fpu_TOP != nullptr, "");

      Instruction *fpu_C2 = x86::GEPLocal(boolTy, "FPU_FLAG_C2", fpu_TOP);
      Instruction *fpu_C1 = x86::GEPLocal(boolTy, "FPU_FLAG_C1", fpu_C2);
      Instruction *fpu_C0 = x86::GEPLocal(boolTy, "FPU_FLAG_C0", fpu_C1);
      Instruction *fpu_ES = x86::GEPLocal(boolTy, "FPU_FLAG_ES", fpu_C0);
      Instruction *fpu_SF = x86::GEPLocal(boolTy, "FPU_FLAG_SF", fpu_ES);
      Instruction *fpu_PE = x86::GEPLocal(boolTy, "FPU_FLAG_PE", fpu_SF);
      Instruction *fpu_UE = x86::GEPLocal(boolTy, "FPU_FLAG_UE", fpu_PE);
      Instruction *fpu_OE = x86::GEPLocal(boolTy, "FPU_FLAG_OE", fpu_UE);
      Instruction *fpu_ZE = x86::GEPLocal(boolTy, "FPU_FLAG_ZE", fpu_OE);
      Instruction *fpu_DE = x86::GEPLocal(boolTy, "FPU_FLAG_DE", fpu_ZE);
      Instruction *fpu_IE = x86::GEPLocal(boolTy, "FPU_FLAG_IE", fpu_DE);

      // sanity check
      TASSERT(fpu_IE != nullptr, "");

      // FPU CONTROL FLAGS
      Type *int2Ty = Type::getIntNTy(F->getContext(), 2);
      Instruction *fpu_X = x86::GEPLocal(boolTy, "FPU_CONTROL_X", fpu_IE);
      Instruction *fpu_RC = x86::GEPLocal(int2Ty, "FPU_CONTROL_RC", fpu_X);
      Instruction *fpu_PC = x86::GEPLocal(int2Ty, "FPU_CONTROL_PC", fpu_RC);
      Instruction *fpu_PM = x86::GEPLocal(boolTy, "FPU_CONTROL_PM", fpu_PC);
      Instruction *fpu_UM = x86::GEPLocal(boolTy, "FPU_CONTROL_UM", fpu_PM);
      Instruction *fpu_OM = x86::GEPLocal(boolTy, "FPU_CONTROL_OM", fpu_UM);
      Instruction *fpu_ZM = x86::GEPLocal(boolTy, "FPU_CONTROL_ZM", fpu_OM);
      Instruction *fpu_DM = x86::GEPLocal(boolTy, "FPU_CONTROL_DM", fpu_ZM);
      Instruction *fpu_IM = x86::GEPLocal(boolTy, "FPU_CONTROL_IM", fpu_DM);

      TASSERT(fpu_IM != nullptr, "");

      // FPU TAG WORD
      // 8 2-bit values. One for each ST register
      Type *tagArrayType = ArrayType::get(int2Ty, 8);
      Instruction *fpu_TagWord = x86::GEPLocal(tagArrayType, "FPU_TAG", fpu_IM);

      Instruction *fpu_LASTIP_SEG = x86::GEPLocal(
          Type::getInt16Ty(F->getContext()), "FPU_LASTIP_SEG", fpu_TagWord);
      Instruction *fpu_LASTIP_OFF = x86::GEPLocal(RegTy, "FPU_LASTIP_OFF",
                                                  fpu_LASTIP_SEG);
      Instruction *fpu_LASTDATA_SEG = x86::GEPLocal(
          Type::getInt16Ty(F->getContext()), "FPU_LASTDATA_SEG",
          fpu_LASTIP_OFF);
      Instruction *fpu_LASTDATA_OFF = x86::GEPLocal(RegTy, "FPU_LASTDATA_OFF",
                                                    fpu_LASTDATA_SEG);

      Instruction *fpu_FOPCODE = x86::GEPLocal(
          Type::getIntNTy(F->getContext(), 11), "FPU_FOPCODE",
          fpu_LASTDATA_OFF);
      TASSERT(fpu_FOPCODE != nullptr, "");

      //vector registers
      Instruction *vec_xmm0 = x86::GEPLocal(
          Type::getIntNTy(F->getContext(), 128), "XMM0", fpu_FOPCODE);
      Instruction *vec_xmm1 = x86::GEPLocal(
          Type::getIntNTy(F->getContext(), 128), "XMM1", vec_xmm0);
      Instruction *vec_xmm2 = x86::GEPLocal(
          Type::getIntNTy(F->getContext(), 128), "XMM2", vec_xmm1);
      Instruction *vec_xmm3 = x86::GEPLocal(
          Type::getIntNTy(F->getContext(), 128), "XMM3", vec_xmm2);
      Instruction *vec_xmm4 = x86::GEPLocal(
          Type::getIntNTy(F->getContext(), 128), "XMM4", vec_xmm3);
      Instruction *vec_xmm5 = x86::GEPLocal(
          Type::getIntNTy(F->getContext(), 128), "XMM5", vec_xmm4);
      Instruction *vec_xmm6 = x86::GEPLocal(
          Type::getIntNTy(F->getContext(), 128), "XMM6", vec_xmm5);
      Instruction *vec_xmm7 = x86::GEPLocal(
          Type::getIntNTy(F->getContext(), 128), "XMM7", vec_xmm6);
      Instruction *vec_xmm8 = x86::GEPLocal(
          Type::getIntNTy(F->getContext(), 128), "XMM8", vec_xmm7);
      Instruction *vec_xmm9 = x86::GEPLocal(
          Type::getIntNTy(F->getContext(), 128), "XMM9", vec_xmm8);
      Instruction *vec_xmm10 = x86::GEPLocal(
          Type::getIntNTy(F->getContext(), 128), "XMM10", vec_xmm9);
      Instruction *vec_xmm11 = x86::GEPLocal(
          Type::getIntNTy(F->getContext(), 128), "XMM11", vec_xmm10);
      Instruction *vec_xmm12 = x86::GEPLocal(
          Type::getIntNTy(F->getContext(), 128), "XMM12", vec_xmm11);
      Instruction *vec_xmm13 = x86::GEPLocal(
          Type::getIntNTy(F->getContext(), 128), "XMM13", vec_xmm12);
      Instruction *vec_xmm14 = x86::GEPLocal(
          Type::getIntNTy(F->getContext(), 128), "XMM14", vec_xmm13);
      Instruction *vec_xmm15 = x86::GEPLocal(
          Type::getIntNTy(F->getContext(), 128), "XMM15", vec_xmm14);

      // stack base and limit
      Instruction *stack_base = x86::GEPLocal(RegTy, "STACK_BASE", vec_xmm15);
      Instruction *stack_limit = x86::GEPLocal(RegTy, "STACK_LIMIT",
                                               stack_base);
      break;
    }

    case 64: {
      //create 64-bit width general purpose registers
      Type *RegTy = Type::getInt64Ty(F->getContext());
      Instruction *ripA = x86_64::GEPLocal(RegTy, "XIP", begin);
      Instruction *raxA = x86_64::GEPLocal(RegTy, "XAX", ripA);
      Instruction *rbxA = x86_64::GEPLocal(RegTy, "XBX", raxA);
      Instruction *rcxA = x86_64::GEPLocal(RegTy, "XCX", rbxA);
      Instruction *rdxA = x86_64::GEPLocal(RegTy, "XDX", rcxA);
      Instruction *rsiA = x86_64::GEPLocal(RegTy, "XSI", rdxA);
      Instruction *rdiA = x86_64::GEPLocal(RegTy, "XDI", rsiA);
      Instruction *rbpA = x86_64::GEPLocal(RegTy, "XBP", rdiA);
      Instruction *rspA = x86_64::GEPLocal(RegTy, "XSP", rbpA);

      //create other fields for flags

      Type *boolTy = Type::getInt1Ty(F->getContext());
      Instruction *zfA = x86_64::GEPLocal(boolTy, "ZF", rspA);
      Instruction *sfA = x86_64::GEPLocal(boolTy, "PF", zfA);
      Instruction *ofA = x86_64::GEPLocal(boolTy, "AF", sfA);
      Instruction *cfA = x86_64::GEPLocal(boolTy, "CF", ofA);
      Instruction *pfA = x86_64::GEPLocal(boolTy, "SF", cfA);
      Instruction *afA = x86_64::GEPLocal(boolTy, "OF", pfA);
      Instruction *dfA = x86_64::GEPLocal(boolTy, "DF", afA);
      TASSERT(dfA != nullptr, "");

      // FPU STACK
      //Type    *floatTy =  IntegerType::get(F->getContext(), 128);
      Type *floatTy = Type::getX86_FP80Ty(F->getContext());
      // 8 float values make up the ST registers
      Type *floatArrayTy = ArrayType::get(floatTy, 8);
      Instruction *stRegs = x86_64::GEPLocal(floatArrayTy, "STi", dfA);

      // sanity check
      TASSERT(stRegs != nullptr, "");

      // FPU FLAGS
      Instruction *fpu_B = x86_64::GEPLocal(boolTy, "FPU_FLAG_BUSY", stRegs);
      Instruction *fpu_C3 = x86_64::GEPLocal(boolTy, "FPU_FLAG_C3", fpu_B);

      // TOP of stack from FPU flags
      // really a 3-bit integer
      Type *topTy = Type::getIntNTy(F->getContext(), 3);
      Instruction *fpu_TOP = x86_64::GEPLocal(topTy, "FPU_FLAG_TOP", fpu_C3);
      TASSERT(fpu_TOP != nullptr, "");

      Instruction *fpu_C2 = x86_64::GEPLocal(boolTy, "FPU_FLAG_C2", fpu_TOP);
      Instruction *fpu_C1 = x86_64::GEPLocal(boolTy, "FPU_FLAG_C1", fpu_C2);
      Instruction *fpu_C0 = x86_64::GEPLocal(boolTy, "FPU_FLAG_C0", fpu_C1);
      Instruction *fpu_ES = x86_64::GEPLocal(boolTy, "FPU_FLAG_ES", fpu_C0);
      Instruction *fpu_SF = x86_64::GEPLocal(boolTy, "FPU_FLAG_SF", fpu_ES);
      Instruction *fpu_PE = x86_64::GEPLocal(boolTy, "FPU_FLAG_PE", fpu_SF);
      Instruction *fpu_UE = x86_64::GEPLocal(boolTy, "FPU_FLAG_UE", fpu_PE);
      Instruction *fpu_OE = x86_64::GEPLocal(boolTy, "FPU_FLAG_OE", fpu_UE);
      Instruction *fpu_ZE = x86_64::GEPLocal(boolTy, "FPU_FLAG_ZE", fpu_OE);
      Instruction *fpu_DE = x86_64::GEPLocal(boolTy, "FPU_FLAG_DE", fpu_ZE);
      Instruction *fpu_IE = x86_64::GEPLocal(boolTy, "FPU_FLAG_IE", fpu_DE);

      // sanity check
      TASSERT(fpu_IE != nullptr, "");

      // FPU CONTROL FLAGS
      Type *int2Ty = Type::getIntNTy(F->getContext(), 2);
      Instruction *fpu_X = x86_64::GEPLocal(boolTy, "FPU_CONTROL_X", fpu_IE);
      Instruction *fpu_RC = x86_64::GEPLocal(int2Ty, "FPU_CONTROL_RC", fpu_X);
      Instruction *fpu_PC = x86_64::GEPLocal(int2Ty, "FPU_CONTROL_PC", fpu_RC);
      Instruction *fpu_PM = x86_64::GEPLocal(boolTy, "FPU_CONTROL_PM", fpu_PC);
      Instruction *fpu_UM = x86_64::GEPLocal(boolTy, "FPU_CONTROL_UM", fpu_PM);
      Instruction *fpu_OM = x86_64::GEPLocal(boolTy, "FPU_CONTROL_OM", fpu_UM);
      Instruction *fpu_ZM = x86_64::GEPLocal(boolTy, "FPU_CONTROL_ZM", fpu_OM);
      Instruction *fpu_DM = x86_64::GEPLocal(boolTy, "FPU_CONTROL_DM", fpu_ZM);
      Instruction *fpu_IM = x86_64::GEPLocal(boolTy, "FPU_CONTROL_IM", fpu_DM);

      TASSERT(fpu_IM != nullptr, "");

      // FPU TAG WORD
      // 8 2-bit values. One for each ST register
      Type *tagArrayType = ArrayType::get(int2Ty, 8);
      Instruction *fpu_TagWord = x86_64::GEPLocal(tagArrayType, "FPU_TAG",
                                                  fpu_IM);

      TASSERT(fpu_TagWord != nullptr, "");

      Instruction *fpu_LASTIP_SEG = x86_64::GEPLocal(
          Type::getInt16Ty(F->getContext()), "FPU_LASTIP_SEG", fpu_TagWord);
      Instruction *fpu_LASTIP_OFF = x86_64::GEPLocal(RegTy, "FPU_LASTIP_OFF",
                                                     fpu_LASTIP_SEG);
      Instruction *fpu_LASTDATA_SEG = x86_64::GEPLocal(
          Type::getInt16Ty(F->getContext()), "FPU_LASTDATA_SEG",
          fpu_LASTIP_OFF);
      Instruction *fpu_LASTDATA_OFF = x86_64::GEPLocal(RegTy,
                                                       "FPU_LASTDATA_OFF",
                                                       fpu_LASTDATA_SEG);

      Instruction *fpu_FOPCODE = x86_64::GEPLocal(
          Type::getIntNTy(F->getContext(), 11), "FPU_FOPCODE",
          fpu_LASTDATA_OFF);
      TASSERT(fpu_FOPCODE != nullptr, "");

      //vector registers
      Instruction *vec_xmm0 = x86_64::GEPLocal(
          Type::getIntNTy(F->getContext(), 128), "XMM0", fpu_FOPCODE);
      Instruction *vec_xmm1 = x86_64::GEPLocal(
          Type::getIntNTy(F->getContext(), 128), "XMM1", vec_xmm0);
      Instruction *vec_xmm2 = x86_64::GEPLocal(
          Type::getIntNTy(F->getContext(), 128), "XMM2", vec_xmm1);
      Instruction *vec_xmm3 = x86_64::GEPLocal(
          Type::getIntNTy(F->getContext(), 128), "XMM3", vec_xmm2);
      Instruction *vec_xmm4 = x86_64::GEPLocal(
          Type::getIntNTy(F->getContext(), 128), "XMM4", vec_xmm3);
      Instruction *vec_xmm5 = x86_64::GEPLocal(
          Type::getIntNTy(F->getContext(), 128), "XMM5", vec_xmm4);
      Instruction *vec_xmm6 = x86_64::GEPLocal(
          Type::getIntNTy(F->getContext(), 128), "XMM6", vec_xmm5);
      Instruction *vec_xmm7 = x86_64::GEPLocal(
          Type::getIntNTy(F->getContext(), 128), "XMM7", vec_xmm6);
      Instruction *vec_xmm8 = x86_64::GEPLocal(
          Type::getIntNTy(F->getContext(), 128), "XMM8", vec_xmm7);
      Instruction *vec_xmm9 = x86_64::GEPLocal(
          Type::getIntNTy(F->getContext(), 128), "XMM9", vec_xmm8);
      Instruction *vec_xmm10 = x86_64::GEPLocal(
          Type::getIntNTy(F->getContext(), 128), "XMM10", vec_xmm9);
      Instruction *vec_xmm11 = x86_64::GEPLocal(
          Type::getIntNTy(F->getContext(), 128), "XMM11", vec_xmm10);
      Instruction *vec_xmm12 = x86_64::GEPLocal(
          Type::getIntNTy(F->getContext(), 128), "XMM12", vec_xmm11);
      Instruction *vec_xmm13 = x86_64::GEPLocal(
          Type::getIntNTy(F->getContext(), 128), "XMM13", vec_xmm12);
      Instruction *vec_xmm14 = x86_64::GEPLocal(
          Type::getIntNTy(F->getContext(), 128), "XMM14", vec_xmm13);
      Instruction *vec_xmm15 = x86_64::GEPLocal(
          Type::getIntNTy(F->getContext(), 128), "XMM15", vec_xmm14);

      // stack base and limit
      Instruction *stack_base = x86_64::GEPLocal(RegTy, "STACK_BASE",
                                                 vec_xmm15);
      Instruction *stack_limit = x86_64::GEPLocal(RegTy, "STACK_LIMIT",
                                                  stack_base);

      Instruction *r8A = x86_64::GEPLocal(RegTy, "R8", stack_limit);
      Instruction *r9A = x86_64::GEPLocal(RegTy, "R9", r8A);
      Instruction *r10A = x86_64::GEPLocal(RegTy, "R10", r9A);
      Instruction *r11A = x86_64::GEPLocal(RegTy, "R11", r10A);
      Instruction *r12A = x86_64::GEPLocal(RegTy, "R12", r11A);
      Instruction *r13A = x86_64::GEPLocal(RegTy, "R13", r12A);
      Instruction *r14A = x86_64::GEPLocal(RegTy, "R14", r13A);
      Instruction *r15A = x86_64::GEPLocal(RegTy, "R15", r14A);
    }
      break;

    default:
      throw TErr(__LINE__, __FILE__,
                 "Unsupported bitwidth " + to_string<int>(bits, dec));
  }

  return;
}

BasicBlock *bbFromStrName(string n, Function *F) {
  BasicBlock *found = nullptr;

  for (Function::iterator it = F->begin(); it != F->end(); ++it) {
    BasicBlock *b = it;

    if (b->getName() == n) {
      found = b;
      break;
    }
  }

  return found;
}

static void CreateInstrBreakpoint(llvm::BasicBlock *B, VA pc) {
  auto M = B->getParent()->getParent();
  auto &C = M->getContext();

  std::stringstream ss;
  ss << "breakpoint_0x" << std::hex << pc;
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

InstTransResult liftInstr(InstPtr ip, BasicBlock *&block, NativeBlockPtr nb,
                          Function *F, NativeFunctionPtr natF,
                          NativeModulePtr natM, bool doAnnotation) {

  auto pc = ip->get_loc();

  // Put each instruction into its own basic block.
  if (BlockPerInstr) {
    std::stringstream ss;
    ss << "instr_0x" << std::hex << pc;
    auto &C = F->getContext();
    auto instr_block = BasicBlock::Create(C, ss.str(), F);
    BranchInst::Create(instr_block, block);
    block = instr_block;
  }

  // At the beginning of the block, make a call to a dummy function with the
  // same name as the block. This function call cannot be optimized away, and
  // so it serves as a useful marker for where we are.
  if (AddBreakpoints) {
    CreateInstrBreakpoint(block, pc);
  }

  InstTransResult disInst_result = liftInstrImpl(ip, block, nb, F, natF, natM);

  // we need to loop over this function and find any un-annotated instructions.
  // then we annotate each instruction
  if (doAnnotation) {
    for (auto &B : *F) {
      for (auto &I : B) {
        VA inst_eip;
        if (!getAnnotation( &I, inst_eip)) {
          addAnnotation(&I, pc);
        }
      }
    }
  }

  return disInst_result;
}

template<typename Vertex, typename Graph>
void bfs_cfg_visitor::discover_vertex(Vertex u, const Graph &g) const {
  auto curBlock = this->natFun->block_from_id(u);
  llvm::BasicBlock *curLLVMBlock = nullptr;

  if ( !curBlock) {
    throw TErr(__LINE__, __FILE__,
               "Could not look up block " + to_string<Vertex>(u, dec));
  }

  //first, either create or look up the LLVM basic block for this native
  //block. we are either creating it for the first time, or, we are
  //going to look up a blank block
  curLLVMBlock = bbFromStrName(curBlock->get_name(), this->F);

  if (curLLVMBlock == nullptr) {
    //we need to create the block, so do that
    curLLVMBlock = BasicBlock::Create(this->F->getContext(),
                                      curBlock->get_name(), this->F);
    TASSERT(curLLVMBlock != nullptr, "");
  }

  //then, create a basic block for every follow of this block, if we do not
  //already have that basic block in our LLVM CFG
  const auto &follows = curBlock->get_follows();
  for (auto blockBase : follows) {
    //try and look up a block that has this blocks name
    auto followNat = this->natFun->block_from_base(blockBase);
    auto followName = followNat->get_name();
    auto fBB = bbFromStrName(followName, this->F);

    if ( !fBB) {
      fBB = BasicBlock::Create(this->F->getContext(), followNat->get_name(),
                               this->F);
    }
  }

  //now, go through each statement and translate it into LLVM IR
  //statements that branch SHOULD be the last statement in a block
  for (InstPtr inst : curBlock->get_insts()) {
    auto r = liftInstr(inst, curLLVMBlock, curBlock, this->F, this->natFun,
                      this->natMod, true);

    if (r == TranslateError) {
      this->didError = true;
      break;
    } else if (r == TranslateErrorUnsupported
        && ignoreUnsupportedInsts == false) {
      this->didError = true;
      break;
    }
  }

  if (curLLVMBlock->getTerminator()) {
    return;
  }

  // we may need to insert a branch inst to the successor
  // if the block ended on a non-terminator (this happens since we
  // may split blocks in cfg recovery to avoid code duplication)
  if (follows.size() == 1) {
    VA blockBase = *(follows.begin());
    std::string bbName = "block_0x" + to_string<VA>(blockBase, std::hex);
    BasicBlock *nextBB = bbFromStrName(bbName, this->F);

    BranchInst::Create(nextBB, curLLVMBlock);
  } else {
    new UnreachableInst(curLLVMBlock->getContext(), curLLVMBlock);
  }
}

static bool insertFunctionIntoModule(NativeModulePtr mod,
                                     NativeFunctionPtr func, Module *M) {
  //okay, now we traverse the graph and add the instructions and blocks
  //into the llvm module

  //first, get the LLVM function for this native function
  Function *F = M->getFunction(func->get_name());

  if ( !F) {
    throw TErr(__LINE__, __FILE__, "Could not get func " + func->get_name());
  }

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
  TASSERT(entryBlock != nullptr, "");

  allocateLocals(F, ArchPointerSize(M));

  //then we put an unconditional branch from the 'entry' block to the first
  //block, and we create the first block
  NativeBlockPtr funcEntry = func->block_from_base(func->get_start());
  BasicBlock *firstBlock = BasicBlock::Create(F->getContext(),
                                              funcEntry->get_name(), F);
  TASSERT(firstBlock != nullptr, "");
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

  // For ease of debugging generated code, don't allow lifted functions to
  // be inlined. This will make lifted and native call graphs one-to-one.
  F->addFnAttr(llvm::Attribute::NoInline);

  //we should be done, having inserted every block into the module
  return !error;
}


static Constant* makeConstantBlob(llvm::LLVMContext &ctx,
                                  const std::vector<uint8_t> &blob) {

  Type *charTy = llvm::Type::getInt8Ty(ctx);
  auto arrT = llvm::ArrayType::get(charTy, blob.size());
  std::vector<llvm::Constant *> array_elements;
  for (auto cur : blob) {
    auto ty = llvm::Type::getInt8Ty(ctx);
    auto c = llvm::ConstantInt::get(ty, cur);
    array_elements.push_back(c);
  }

  return llvm::ConstantArray::get(arrT, array_elements);
}

static llvm::GlobalVariable *getSectionForDataAddr(
    const std::list<DataSection> &dataSecs, llvm::Module *M, VA data_addr,
    VA &section_base) {

  for (auto &dt : dataSecs) {
    VA start = dt.getBase();
    VA end = start + dt.getSize();

    if (data_addr >= start && data_addr < end) {
      std::string gvar_name = "data_0x" + to_string<VA>(start, hex);  //+"_ptr";
      section_base = start;
      return M->getNamedGlobal(gvar_name);
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
                                DataSection& ds, llvm::Module *M,
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
  for (list<DataSectionEntry>::const_iterator dsec_itr = ds_entries.begin();
      dsec_itr != ds_entries.end(); dsec_itr++) {
    string sym_name;

    if (dsec_itr->getSymbol(sym_name)) {
      const char *func_addr_str = sym_name.c_str() + 4;
      VA func_addr = strtoull(func_addr_str, nullptr, 16);

      std::cout << __FUNCTION__ << ": Found symbol: " << sym_name << "\n";

      if (sym_name.find("ext_") == 0) {

        Constant *final_val = nullptr;

        GlobalValue *ext_v = M->getNamedValue(func_addr_str);

        if (ext_v != nullptr && isa<Function>(ext_v)) {
          final_val = getPtrSizedValue(M, ext_v, dsec_itr->getSize());
          //cout << "External function" << sym_name << " has type: " << final_val->getType() << "\n";
        } else if (ext_v != nullptr) {
          final_val = getPtrSizedValue(M, ext_v, dsec_itr->getSize());
          //cout << "External data" << sym_name << " has type: " << final_val->getType() << "\n";
          // assume ext data
        } else {
          TASSERT(ext_v != nullptr,
                  "Could not find external: " + string(func_addr_str));
          //cout << "External fail" << sym_name << " has type: " << final_val->getType() << "\n";
        }

        secContents.push_back(final_val);
        data_section_types.push_back(final_val->getType());

      } else if (sym_name.find("sub_") == 0) {
        // add function pointer to data section
        // to do this, create a callback driver for
        // it first (since it may be called externally)

        Function *func = nullptr;

        if (convert_to_callback) {
          func = ArchAddCallbackDriver(M, func_addr);
          TASSERT(func != nullptr, "Could make callback for: " + sym_name);
        } else {
          func = M->getFunction(sym_name);
          TASSERT(func != nullptr, "Could not find function: " + sym_name);
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
        TASSERT(g_ref != nullptr,
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
        if (ArchPointerSize(M) == Pointer32) {
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

struct DataSectionVar {
  DataSection *section;
  llvm::StructType *opaque_type;
  llvm::GlobalVariable *var;
};

static bool insertDataSections(NativeModulePtr natMod, Module *M) {

  list<DataSection> &globaldata = natMod->getData();
  list<DataSection>::iterator git = globaldata.begin();

  //insert all global data before we insert the CFG

  std::vector<DataSectionVar> gvars;

  // pre-create references to all data sections
  // as later we may have data references that are
  // from one section into another

  for (DataSection &dt : globaldata) {
    std::string bufferName;
    bufferName = "data_0x" + to_string<VA>(dt.getBase(), hex);
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
  for (DataSectionVar &var : gvars) {

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
    auto cst = ConstantStruct::get(var.opaque_type, secContents);
    // align on pointer size boundary, max needed by SSE instructions
    var.var->setAlignment(ArchPointerSize(M));
    var.var->setInitializer(cst);

  }

  return true;

}

void renameLiftedFunctions(NativeModulePtr natMod, llvm::Module *M,
                           const std::set<VA> &entry_point_pcs) {
  list<NativeFunctionPtr> funcs = natMod->get_funcs();

  // Rename the functions to have their 'nice' names, where available.
  for (auto f : funcs) {
    if (entry_point_pcs.count(f->get_start())) {
      continue;
    }
    auto sub_name = f->get_name();
    auto F = M->getFunction(sub_name);
    std::stringstream ss;
    ss << "callback_" << sub_name;
    if ( !M->getFunction(ss.str())) {
      auto &sym_name = f->get_symbol_name();
      if ( !sym_name.empty()) {
        F->setName(sym_name);
      }
    }
  }
}

static void initLiftedFunctions(NativeModulePtr natMod, llvm::Module *M) {
  for (auto f : natMod->get_funcs()) {
    auto fname = f->get_name();
    auto F = M->getFunction(fname);

    if ( !F) {
      F = llvm::dyn_cast<llvm::Function>(
          M->getOrInsertFunction(fname, getBaseFunctionType(M)));

      TASSERT(F != nullptr, "Could not insert function into module");

      ArchSetCallingConv(M, F);
      // make local functions 'static'
      F->setLinkage(llvm::GlobalValue::InternalLinkage);
      cout << "Inserted function: " << fname << std::endl;
    } else {
      cout << "Already inserted function: " << fname << ", skipping."
           << std::endl;
    }
  }
}

static void initExternalData(NativeModulePtr natMod, llvm::Module *M) {
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

    const auto &triple = M->getTargetTriple();
    if (WINDOWS_TRIPLE == triple) {
      // this only makes sense for win32
      gv->setDLLStorageClass(llvm::GlobalValue::DLLImportStorageClass);
    }
  }
}

// Iterate over the list of external functions and insert them as
// global functions.
static void initExternalCode(NativeModulePtr natMod, llvm::Module *M) {
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

    if(conv == ExternalCodeRef::McsemaCall) {
       // normal mcsema function prototypes
      llvm::Function *newF = llvm::dyn_cast<llvm::Function>(
            M->getOrInsertFunction(ArchNameMcsemaCall(symName), getBaseFunctionType(M)));
      ArchSetCallingConv(M, newF);
      newF->setLinkage(llvm::GlobalValue::ExternalLinkage);
      continue;
    }

    std::vector<llvm::Type*> arguments;
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
          arguments.push_back(Type::getInt64Ty(C));

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

    auto FTy = FunctionType::get(returnType, arguments, false);
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

static bool liftFunctionsIntoModule(NativeModulePtr natMod, Module *M) {
  // populate functions
  for (auto f : natMod->get_funcs()) {
    if ( !insertFunctionIntoModule(natMod, f, M)) {
      std::string fname = f->get_name();
      cerr << "Could not insert function: " << fname
           << " into the LLVM module\n";
      return false;
      break;
    }
  }
  return true;
}

bool liftNativeCodeIntoModule(NativeModulePtr natMod, Module *M) {
  bool result = true;
  initLiftedFunctions(natMod, M);
  initExternalData(natMod, M);
  initExternalCode(natMod, M);
  insertDataSections(natMod, M);
  return liftFunctionsIntoModule(natMod, M);
}
