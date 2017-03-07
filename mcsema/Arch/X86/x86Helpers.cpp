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

#include <iostream>

#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/Intrinsics.h>
#include <llvm/Support/CodeGen.h>

#include "raiseX86.h"
#include "Externals.h"
#include "x86Helpers.h"
#include "TransExcn.h"

// check if addr falls into a data section, and is at least minAddr.
// the minAddr check exists for times when we are not sure if an address
// is a data reference or an immediate value; in some cases data is mapped
// at 0x0 and determining this could be tricky

bool addrIsInData(VA addr, NativeModulePtr m, VA &base, VA minAddr = 0x0) {
  // sanity check:
  // assume no data references before minAddr.
  if (addr < minAddr) {
    return false;
  }

  auto &sections = m->getData();
  if (sections.empty()) {
    std::cerr << __FUNCTION__ << ": WARNING: no data sections!" << std::endl;
    return false;

  }
  for (auto &curSec : sections) {
    VA low = curSec.getBase();
    VA high = low + curSec.getSize();

    if (addr >= low && addr < high) {
      base = low;
      return true;
    }
  }

  return false;
}

// Compute a Value from a complex address expression
// such as [0x123456+eax*4]
// If the expression references global data, use
// that in the computation instead of assuming values
// are opaque immediates
namespace x86 {
llvm::Value *getAddrFromExpr(llvm::BasicBlock *b, NativeModulePtr mod,
                             const llvm::MCOperand &Obase,
                             const llvm::MCOperand &Oscale,
                             const llvm::MCOperand &Oindex, const int64_t Odisp,
                             const llvm::MCOperand &Oseg, bool dataOffset) {
  TASSERT(Obase.isReg(), "");
  TASSERT(Oscale.isImm(), "");
  TASSERT(Oindex.isReg(), "");
  TASSERT(Oseg.isReg(), "");

  unsigned baseReg = Obase.getReg();
  int64_t disp = Odisp;

  //first, we should ask, is disp an absolute reference to
  //some global symbol in the original source module?
  //if it is, we can replace its value with that of a pointer
  //to global data
  //HANDY HEURISTIC HACK
  //if the base register is the stack pointer or the frame
  //pointer, then skip this part
  llvm::Value *d = nullptr;
  auto iTy = llvm::IntegerType::getInt32Ty(b->getContext());

  if (dataOffset
      || (mod && disp && baseReg != llvm::X86::EBP &&
          baseReg != llvm::X86::ESP)) {
    auto int_val = getGlobalFromOriginalAddr<32>(disp, mod,
                                                 dataOffset ? 0 : 0x1000, b);
    d = int_val;
  } else {
    //there is no disp value, or its relative to esp/ebp in which case
    //we might not want to do anything
  }

  if (nullptr == d) {
    //create a constant integer out of the raw displacement
    //we were unable to assign the displacement to an address
    d = llvm::ConstantInt::getSigned(iTy, disp);
  }

  llvm::Value *rVal = nullptr;

  //read the base register (if given)
  if (baseReg != llvm::X86::NoRegister) {
    rVal = R_READ<32>(b, baseReg);
  } else {
    //if the base is not present, just use 0
    rVal = CONST_V<32>(b, 0);
  }

  llvm::Value *dispComp = nullptr;
  dispComp = llvm::BinaryOperator::Create(llvm::Instruction::Add, rVal, d, "",
                                          b);

  //add the index amount, if present
  if (Oindex.getReg() != llvm::X86::NoRegister) {
    auto index = R_READ<32>(b, Oindex.getReg());

    int64_t scaleAmt = Oscale.getImm();
    if (scaleAmt > 1) {
      index = llvm::BinaryOperator::CreateMul(index, CONST_V<32>(b, scaleAmt),
                                              "", b);
    }

    dispComp = llvm::BinaryOperator::CreateAdd(dispComp, index, "", b);
  }

  //convert the resulting integer into a pointer type
  auto piTy = llvm::Type::getInt32PtrTy(b->getContext());
  return new llvm::IntToPtrInst(dispComp, piTy, "", b);
}
}

llvm::Value *getAddrFromExpr(llvm::BasicBlock *b, NativeModulePtr mod,
                             const llvm::MCInst &inst, NativeInstPtr ip,
                             uint32_t which) {
  const auto &base = inst.getOperand(which + 0);
  const auto &scale = inst.getOperand(which + 1);
  const auto &index = inst.getOperand(which + 2);
  const auto &disp = inst.getOperand(which + 3);
  const auto &seg = inst.getOperand(which + 4);

  TASSERT(base.isReg(), "");
  TASSERT(scale.isImm(), "");
  TASSERT(index.isReg(), "");
  TASSERT(disp.isImm(), "");
  TASSERT(seg.isReg(), "");

  // determine if this instruction is using a memory reference
  // or if the displacement should be used at face value
  bool has_ref = ip->has_reference(NativeInst::MEMRef);
  int64_t real_disp =
      has_ref ? ip->get_reference(NativeInst::MEMRef) : disp.getImm();
  auto M = b->getParent()->getParent();

  if (ArchPointerSize(M) == Pointer32) {

    return x86::getAddrFromExpr(b, mod, base, scale, index, real_disp, seg,
                                has_ref);

  } else {
    return x86_64::getAddrFromExpr(b, mod, base, scale, index, real_disp, seg,
                                   has_ref);
  }

}

llvm::Value *MEM_AS_DATA_REF(llvm::BasicBlock *B, NativeModulePtr natM,
                             const llvm::MCInst &inst, NativeInstPtr ip,
                             uint32_t which) {
  if (false == ip->has_mem_reference) {
    throw TErr(__LINE__, __FILE__,
               "Want to use MEM as data ref but have no MEM reference");
  }
  return getAddrFromExpr(B, natM, inst, ip, which);
}

llvm::Instruction *callMemcpy(llvm::BasicBlock *B, llvm::Value *dest,
                              llvm::Value *src, uint32_t size, uint32_t align,
                              bool isVolatile) {
  auto copySize = CONST_V<32>(B, size);
  // ALIGN: 4 byte alignment, i think
  auto alignSize = CONST_V<32>(B, align);
  // VOLATILE: false
  auto vIsVolatile = CONST_V<1>(B, isVolatile);

  llvm::Type *Tys[] = {dest->getType(), src->getType(), copySize->getType()};

  auto M = B->getParent()->getParent();
  auto doMemCpy = llvm::Intrinsic::getDeclaration(
      M, llvm::Intrinsic::memcpy, Tys);

  llvm::Value *callArgs[] = {dest,  // DST
      src,  // SRC
      copySize,  // SIZE
      alignSize,  // ALIGN
      vIsVolatile  // VOLATILE
      };

  // actually call llvm.memcpy
  return llvm::CallInst::Create(doMemCpy, callArgs, "", B);
}
