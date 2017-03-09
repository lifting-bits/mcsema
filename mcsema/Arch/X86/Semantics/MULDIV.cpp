/*
 Copyright (c) 2014, Trail of Bits
 All rights reserved.

 Redistribution and use in source and binary forms, with or without modification,
 are permitted provided that the following conditions are met:

 Redistributions of source code must retain the above copyright notice, this
 list of conditions and the following disclaimer.

 Redistributions in binary form must reproduce the above copyright notice, this
 list of conditions and the following disclaimer in the documentation and/or
 other materials provided with the distribution.

 Neither the name of Trail of Bits nor the names of its
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
#include <sstream>
#include <string>
#include <vector>

#include <llvm/IR/Argument.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/Intrinsics.h>

#include <llvm/MC/MCInst.h>

#include "mcsema/Arch/Arch.h"
#include "mcsema/Arch/Dispatch.h"
#include "mcsema/Arch/Register.h"

#include "mcsema/Arch/X86/Util.h"
#include "mcsema/Arch/X86/Semantics/MULDIV.h"

#include "mcsema/BC/Util.h"

#define NASSERT(cond) TASSERT(cond, "")

template<int width>
static void doMulV(NativeInstPtr ip, llvm::BasicBlock *&b, llvm::Value *rhs) {
  // Handle the different source register depending on the bit width
  llvm::Value *lhs = nullptr;

  switch (width) {
    case 8:
      lhs = R_READ<8>(b, llvm::X86::AL);
      break;
    case 16:
      lhs = R_READ<16>(b, llvm::X86::AX);
      break;
    case 32:
      lhs = R_READ<32>(b, llvm::X86::EAX);
      break;
    case 64:
      lhs = R_READ<64>(b, llvm::X86::RAX);
      break;
    default:
      throw TErr(__LINE__, __FILE__, "Not supported width");
  }

  llvm::Type *dt = llvm::Type::getIntNTy(b->getContext(), width * 2);
  llvm::Value *a1_x = new llvm::ZExtInst(lhs, dt, "", b);
  llvm::Value *a2_x = new llvm::ZExtInst(rhs, dt, "", b);
  llvm::Value *tmp = llvm::BinaryOperator::Create(llvm::Instruction::Mul, a1_x,
                                                  a2_x, "", b);

  llvm::Type *t = llvm::Type::getIntNTy(b->getContext(), width);
  llvm::Value *res_sh = llvm::BinaryOperator::Create(
      llvm::Instruction::LShr, tmp, CONST_V<width * 2>(b, width), "", b);
  llvm::Value *wrAX = new llvm::TruncInst(tmp, t, "", b);
  llvm::Value *wrDX = new llvm::TruncInst(res_sh, t, "", b);

  // set clear CF and OF if DX is clear, set if DX is set
  llvm::Value *r = new llvm::ICmpInst( *b, llvm::CmpInst::ICMP_NE, wrDX,
                                      CONST_V<width>(b, 0));

  F_WRITE(b, llvm::X86::CF, r);
  F_WRITE(b, llvm::X86::OF, r);

  switch (width) {
    case 8:
      R_WRITE<width>(b, llvm::X86::AH, wrDX);
      R_WRITE<width>(b, llvm::X86::AL, wrAX);
      break;
    case 16:
      R_WRITE<width>(b, llvm::X86::DX, wrDX);
      R_WRITE<width>(b, llvm::X86::AX, wrAX);
      break;
    case 32:
      R_WRITE<width>(b, llvm::X86::EDX, wrDX);
      R_WRITE<width>(b, llvm::X86::EAX, wrAX);
      break;
    case 64:
      R_WRITE<width>(b, llvm::X86::RDX, wrDX);
      R_WRITE<width>(b, llvm::X86::RAX, wrAX);
      break;
    default:
      throw TErr(__LINE__, __FILE__, "Not supported width");
  }

}

template<int width>
static InstTransResult doMulR(NativeInstPtr ip, llvm::BasicBlock *&b,
                              const llvm::MCOperand &src) {
  NASSERT(src.isReg());

  doMulV<width>(ip, b, R_READ<width>(b, src.getReg()));

  return ContinueBlock;
}

template<int width>
static InstTransResult doMulM(NativeInstPtr ip, llvm::BasicBlock *&b,
                              llvm::Value *memAddr) {
  NASSERT(memAddr != nullptr);

  doMulV<width>(ip, b, M_READ<width>(ip, b, memAddr));

  return ContinueBlock;
}

struct IMulRes {
  llvm::Value *full;
  llvm::Value *trunc;
};

template<int width>
static IMulRes doIMulVV(NativeInstPtr ip, llvm::BasicBlock *&b,
                        llvm::Value *lhs, llvm::Value *rhs) {
  //model the semantics of the signed multiply
  llvm::Value *a1 = lhs;
  llvm::Value *a2 = rhs;

  llvm::Type *st = llvm::Type::getIntNTy(b->getContext(), width);
  llvm::Type *dt = llvm::Type::getIntNTy(b->getContext(), width * 2);

  llvm::Value *a1_x = new llvm::SExtInst(a1, dt, "", b);
  llvm::Value *a2_x = new llvm::SExtInst(a2, dt, "", b);
  llvm::Value *tmp = llvm::BinaryOperator::Create(llvm::Instruction::Mul, a1_x,
                                                  a2_x, "", b);

  llvm::Value *dest = new llvm::TruncInst(tmp, st, "", b);
  llvm::Value *dest_x = new llvm::SExtInst(dest, dt, "", b);

  llvm::Value *zero = llvm::ConstantInt::get(st, 0, true);
  llvm::Value *r = new llvm::ICmpInst( *b, llvm::CmpInst::ICMP_NE, dest_x, tmp);
  llvm::Value *sf = new llvm::ICmpInst( *b, llvm::CmpInst::ICMP_SLT, dest,
                                       zero);

  F_WRITE(b, llvm::X86::SF, sf);
  F_WRITE(b, llvm::X86::OF, r);
  F_WRITE(b, llvm::X86::CF, r);

  return {tmp, dest};
}

template<int width>
static IMulRes doIMulV(NativeInstPtr ip, llvm::BasicBlock *&b,
                       llvm::Value *rhs) {
  // Handle the different source register depending on the bit width
  llvm::Value *lhs;

  switch (width) {
    case 8:
      lhs = R_READ<8>(b, llvm::X86::AL);
      break;
    case 16:
      lhs = R_READ<16>(b, llvm::X86::AX);
      break;
    case 32:
      lhs = R_READ<32>(b, llvm::X86::EAX);
      break;
    case 64:
      lhs = R_READ<64>(b, llvm::X86::RAX);
      break;
    default:
      throw TErr(__LINE__, __FILE__, "Not supported width");
  }
  return doIMulVV<width>(ip, b, lhs, rhs);
}

template<int width>
static InstTransResult doIMulR(NativeInstPtr ip, llvm::BasicBlock *&b,
                               const llvm::MCOperand &src) {
  NASSERT(src.isReg());

  auto imul_res = doIMulV<width>(ip, b, R_READ<width>(b, src.getReg()));
  //Value   *res =

  llvm::Type *t = llvm::Type::getIntNTy(b->getContext(), width);
  llvm::Value *res_sh = llvm::BinaryOperator::Create(
      llvm::Instruction::LShr, imul_res.full, CONST_V<width * 2>(b, width), "",
      b);

  llvm::Value *wrDX = new llvm::TruncInst(res_sh, t, "", b);
  llvm::Value *wrAX = imul_res.trunc;

  switch (width) {
    case 8:
      R_WRITE<width>(b, llvm::X86::AH, wrDX);
      R_WRITE<width>(b, llvm::X86::AL, wrAX);
      break;
    case 16:
      R_WRITE<width>(b, llvm::X86::DX, wrDX);
      R_WRITE<width>(b, llvm::X86::AX, wrAX);
      break;
    case 32:
      R_WRITE<width>(b, llvm::X86::EDX, wrDX);
      R_WRITE<width>(b, llvm::X86::EAX, wrAX);
      break;
    case 64:
      R_WRITE<width>(b, llvm::X86::RDX, wrDX);
      R_WRITE<width>(b, llvm::X86::RAX, wrAX);
      break;
    default:
      throw TErr(__LINE__, __FILE__, "Not supported width");
  }

  return ContinueBlock;
}

template<int width>
static InstTransResult doIMulM(NativeInstPtr ip, llvm::BasicBlock *&b,
                               llvm::Value *memAddr) {
  NASSERT(memAddr != nullptr);

  auto imul_res = doIMulV<width>(ip, b, M_READ<width>(ip, b, memAddr));

  llvm::Type *t = llvm::Type::getIntNTy(b->getContext(), width);
  llvm::Value *res_sh = llvm::BinaryOperator::Create(
      llvm::Instruction::LShr, imul_res.full, CONST_V<width * 2>(b, width), "",
      b);
  llvm::Value *wrDX = new llvm::TruncInst(res_sh, t, "", b);
  llvm::Value *wrAX = imul_res.trunc;

  switch (width) {
    case 8:
      R_WRITE<width>(b, llvm::X86::AX, wrAX);
      break;
    case 16:
      R_WRITE<width>(b, llvm::X86::DX, wrDX);
      R_WRITE<width>(b, llvm::X86::AX, wrAX);
      break;
    case 32:
      R_WRITE<width>(b, llvm::X86::EDX, wrDX);
      R_WRITE<width>(b, llvm::X86::EAX, wrAX);
      break;
    case 64:
      R_WRITE<width>(b, llvm::X86::RDX, wrDX);
      R_WRITE<width>(b, llvm::X86::RAX, wrAX);
      break;
    default:
      throw new TErr(__LINE__, __FILE__, "Not supported width");
  }

  return ContinueBlock;
}

template<int width>
static InstTransResult doIMulRM(NativeInstPtr ip, llvm::BasicBlock *&b,
                                const llvm::MCOperand &dst,
                                const llvm::MCOperand &lhs, llvm::Value *rhs) {
  NASSERT(dst.isReg());
  NASSERT(lhs.isReg());
  NASSERT(rhs != nullptr);

  auto imul_res = doIMulVV<width>(ip, b, R_READ<width>(b, lhs.getReg()),
                                  M_READ<width>(ip, b, rhs));

  R_WRITE<width>(b, dst.getReg(), imul_res.trunc);

  return ContinueBlock;
}

template<int width>
static InstTransResult doIMulRR(NativeInstPtr ip, llvm::BasicBlock *&b,
                                const llvm::MCOperand &dst,
                                const llvm::MCOperand &lhs,
                                const llvm::MCOperand &rhs) {
  NASSERT(dst.isReg());
  NASSERT(lhs.isReg());
  NASSERT(rhs.isReg());

  auto imul_res = doIMulVV<width>(ip, b, R_READ<width>(b, lhs.getReg()),
                                  R_READ<width>(b, rhs.getReg()));
  //write out the result
  R_WRITE<width>(b, dst.getReg(), imul_res.trunc);

  return ContinueBlock;
}

template<int width>
static llvm::Value *doIMulVVV(NativeInstPtr ip, llvm::BasicBlock *&b,
                              llvm::Value *lhs, llvm::Value *rhs) {

  return doIMulVV<width>(ip, b, lhs, rhs).trunc;
}

template<int width>
static InstTransResult doIMulRMI(NativeInstPtr ip, llvm::BasicBlock *&b,
                                 const llvm::MCOperand &dst, llvm::Value *lhs,
                                 const llvm::MCOperand &rhs) {
  NASSERT(dst.isReg());
  NASSERT(lhs != nullptr);
  NASSERT(rhs.isImm());

  llvm::Value *res = doIMulVVV<width>(ip, b, M_READ<width>(ip, b, lhs),
                                      CONST_V<width>(b, rhs.getImm()));

  R_WRITE<width>(b, dst.getReg(), res);

  return ContinueBlock;
}

template<int width>
static InstTransResult doIMulRMV(NativeInstPtr ip, llvm::BasicBlock *&b,
                                 const llvm::MCOperand &dst, llvm::Value *lhs,
                                 llvm::Value *rhs) {
  NASSERT(dst.isReg());
  NASSERT(lhs != nullptr);

  llvm::Value *res = doIMulVVV<width>(ip, b, M_READ<width>(ip, b, lhs), rhs);

  R_WRITE<width>(b, dst.getReg(), res);

  return ContinueBlock;
}

template<int width>
static InstTransResult doIMulRRI(NativeInstPtr ip, llvm::BasicBlock *&b,
                                 const llvm::MCOperand &dst,
                                 const llvm::MCOperand &lhs,
                                 const llvm::MCOperand &rhs) {
  NASSERT(dst.isReg());
  NASSERT(lhs.isReg());
  NASSERT(rhs.isImm());

  llvm::Value *res = doIMulVVV<width>(ip, b, R_READ<width>(b, lhs.getReg()),
                                      CONST_V<width>(b, rhs.getImm()));

  R_WRITE<width>(b, dst.getReg(), res);

  return ContinueBlock;
}

template<int width>
static InstTransResult doIMulRRV(NativeInstPtr ip, llvm::BasicBlock *&b,
                                 llvm::Value *addr, const llvm::MCOperand &lhs,
                                 const llvm::MCOperand &dst) {
  NASSERT(dst.isReg());
  NASSERT(lhs.isReg());

  llvm::Value *res = doIMulVVV<width>(ip, b, R_READ<width>(b, lhs.getReg()),
                                      addr);

  R_WRITE<width>(b, dst.getReg(), res);

  return ContinueBlock;
}

template<int width>
static InstTransResult doIMulRMI8(NativeInstPtr ip, llvm::BasicBlock *&b,
                                  const llvm::MCOperand &dst, llvm::Value *lhs,
                                  const llvm::MCOperand &rhs) {
  NASSERT(dst.isReg());
  NASSERT(lhs != nullptr);
  NASSERT(rhs.isImm());

  llvm::Value *vRhs = CONST_V<8>(b, rhs.getImm());
  llvm::Type *sx = llvm::Type::getIntNTy(b->getContext(), width);
  llvm::Value *vRhs_x = new llvm::SExtInst(vRhs, sx, "", b);

  llvm::Value *res = doIMulVVV<width>(ip, b, M_READ<width>(ip, b, lhs), vRhs_x);

  R_WRITE<width>(b, dst.getReg(), res);

  return ContinueBlock;
}

template<int width>
static InstTransResult doIMulRRI8(NativeInstPtr ip, llvm::BasicBlock *&b,
                                  const llvm::MCOperand &dst,
                                  const llvm::MCOperand &lhs,
                                  const llvm::MCOperand &rhs) {
  NASSERT(dst.isReg());
  NASSERT(lhs.isReg());
  NASSERT(rhs.isImm());

  llvm::Value *vRhs = CONST_V<8>(b, rhs.getImm());
  llvm::Type *sx = llvm::Type::getIntNTy(b->getContext(), width);
  llvm::Value *vRhs_x = new llvm::SExtInst(vRhs, sx, "", b);

  llvm::Value *res = doIMulVVV<width>(ip, b, R_READ<width>(b, lhs.getReg()),
                                      vRhs_x);

  R_WRITE<width>(b, dst.getReg(), res);

  return ContinueBlock;
}

template<int width>
static InstTransResult doDivV(NativeInstPtr ip, llvm::BasicBlock *&b,
                              llvm::Value *divisor,
                              llvm::Instruction::BinaryOps whichdiv) {

  //read in EDX and EAX
  llvm::Value *ax;
  llvm::Value *dx;

  switch (width) {
    case 8:
      ax = R_READ<8>(b, llvm::X86::AL);
      dx = R_READ<8>(b, llvm::X86::AH);
      break;
    case 16:
      ax = R_READ<16>(b, llvm::X86::AX);
      dx = R_READ<16>(b, llvm::X86::DX);
      break;
    case 32:
      ax = R_READ<32>(b, llvm::X86::EAX);
      dx = R_READ<32>(b, llvm::X86::EDX);
      break;
    case 64:
      ax = R_READ<64>(b, llvm::X86::RAX);
      dx = R_READ<64>(b, llvm::X86::RDX);
      break;
    default:
      throw TErr(__LINE__, __FILE__, "Not supported width");
  }

  llvm::Value *dividend = concatInts<width>(b, dx, ax);

  // tmp <- EDX:EAX / divisor
  // but first, extend divisor
  llvm::Type *text = llvm::Type::getIntNTy(b->getContext(), width * 2);
  llvm::Type *t = llvm::Type::getIntNTy(b->getContext(), width);

  llvm::Value *divisorext = nullptr;
  switch (whichdiv) {

    case llvm::Instruction::SDiv:
      divisorext = new llvm::SExtInst(divisor, text, "", b);
      break;
    case llvm::Instruction::UDiv:
      divisorext = new llvm::ZExtInst(divisor, text, "", b);
      break;
    default:
      throw TErr(__LINE__, __FILE__, "Invalid operation given to doDivV");
  }

  //EAX <- tmp
  llvm::Value *res;
  llvm::Value *mod;
  llvm::Instruction::BinaryOps modop;
  switch (whichdiv) {
    case llvm::Instruction::SDiv:
      modop = llvm::Instruction::SRem;
      break;
    case llvm::Instruction::UDiv:
      modop = llvm::Instruction::URem;
      break;
    default:
      throw TErr(__LINE__, __FILE__, "Invalid operation given to doDivV");
  };
  res = llvm::BinaryOperator::Create(whichdiv, dividend, divisorext, "", b);

  //EDX <- EDX:EAX mod divisor
  mod = llvm::BinaryOperator::Create(modop, dividend, divisorext, "", b);

  llvm::Value *wrDx = new llvm::TruncInst(mod, t, "", b);
  llvm::Value *wrAx = new llvm::TruncInst(res, t, "", b);

  switch (width) {
    case 8:
      R_WRITE<8>(b, llvm::X86::AH, wrDx);
      R_WRITE<8>(b, llvm::X86::AL, wrAx);
      break;
    case 16:
      R_WRITE<16>(b, llvm::X86::DX, wrDx);
      R_WRITE<16>(b, llvm::X86::AX, wrAx);
      break;
    case 32:
      R_WRITE<32>(b, llvm::X86::EDX, wrDx);
      R_WRITE<32>(b, llvm::X86::EAX, wrAx);
      break;
    case 64:
      R_WRITE<64>(b, llvm::X86::RDX, wrDx);
      R_WRITE<64>(b, llvm::X86::RAX, wrAx);
      break;
    default:
      throw TErr(__LINE__, __FILE__, "Not supported width");
  }

  return ContinueBlock;
}

template<int width>
static InstTransResult doIDivR(NativeInstPtr ip, llvm::BasicBlock *&b,
                               const llvm::MCOperand &div) {
  NASSERT(div.isReg());

  llvm::Value *reg_v = R_READ<width>(b, div.getReg());

  doDivV<width>(ip, b, reg_v, llvm::Instruction::SDiv);

  return ContinueBlock;
}

template<int width>
static InstTransResult doIDivM(NativeInstPtr ip, llvm::BasicBlock *&b,
                               llvm::Value *memLoc) {
  NASSERT(memLoc != nullptr);

  llvm::Value *from_mem = M_READ<width>(ip, b, memLoc);

  doDivV<width>(ip, b, from_mem, llvm::Instruction::SDiv);

  return ContinueBlock;
}

template<int width>
static InstTransResult doDivR(NativeInstPtr ip, llvm::BasicBlock *&b,
                              const llvm::MCOperand &div) {
  NASSERT(div.isReg());

  llvm::Value *reg_v = R_READ<width>(b, div.getReg());

  doDivV<width>(ip, b, reg_v, llvm::Instruction::UDiv);

  return ContinueBlock;
}

template<int width>
static InstTransResult doDivM(NativeInstPtr ip, llvm::BasicBlock *&b,
                              llvm::Value *memLoc) {
  NASSERT(memLoc != nullptr);

  llvm::Value *from_mem = M_READ<width>(ip, b, memLoc);

  doDivV<width>(ip, b, from_mem, llvm::Instruction::UDiv);

  return ContinueBlock;
}
/* GOOD */
GENERIC_TRANSLATION_REF(IMUL32rm,
                        doIMulRM<32>(ip, block, OP(0), OP(1), ADDR_NOREF(2)),
                        doIMulRM<32>(ip, block, OP(0), OP(1), MEM_REFERENCE(2)))
GENERIC_TRANSLATION_REF(IMUL64rm,
                        doIMulRM<64>(ip, block, OP(0), OP(1), ADDR_NOREF(2)),
                        doIMulRM<64>(ip, block, OP(0), OP(1), MEM_REFERENCE(2)))
GENERIC_TRANSLATION_REF(IMUL16rm,
                        doIMulRM<16>(ip, block, OP(0), OP(1), ADDR_NOREF(2)),
                        doIMulRM<16>(ip, block, OP(0), OP(1), MEM_REFERENCE(2)))
GENERIC_TRANSLATION(IMUL8r, doIMulR<8>(ip, block, OP(0)))
GENERIC_TRANSLATION_REF(IMUL8m, doIMulM<8>(ip, block, ADDR_NOREF(0)),
                        doIMulM<8>(ip, block, MEM_REFERENCE(0)))
GENERIC_TRANSLATION(IMUL16r, doIMulR<16>(ip, block, OP(0)))
GENERIC_TRANSLATION_REF(IMUL16m, doIMulM<16>(ip, block, ADDR_NOREF(0)),
                        doIMulM<16>(ip, block, MEM_REFERENCE(0)))
GENERIC_TRANSLATION(IMUL32r, doIMulR<32>(ip, block, OP(0)))
GENERIC_TRANSLATION(MUL32r, doMulR<32>(ip, block, OP(0)))
GENERIC_TRANSLATION(MUL64r, doMulR<64>(ip, block, OP(0)))
GENERIC_TRANSLATION_REF(MUL32m, doMulM<32>(ip, block, ADDR_NOREF(0)),
                        doMulM<32>(ip, block, MEM_REFERENCE(0)))
GENERIC_TRANSLATION_REF(MUL64m, doMulM<64>(ip, block, ADDR_NOREF(0)),
                        doMulM<64>(ip, block, MEM_REFERENCE(0)))
GENERIC_TRANSLATION(MUL16r, doMulR<16>(ip, block, OP(0)))
GENERIC_TRANSLATION_REF(MUL16m, doMulM<16>(ip, block, ADDR_NOREF(0)),
                        doMulM<16>(ip, block, MEM_REFERENCE(0)))
GENERIC_TRANSLATION(MUL8r, doMulR<8>(ip, block, OP(0)))
GENERIC_TRANSLATION_REF(MUL8m, doMulM<8>(ip, block, ADDR_NOREF(0)),
                        doMulM<8>(ip, block, MEM_REFERENCE(0)))
GENERIC_TRANSLATION_REF(IMUL32m, doIMulM<32>(ip, block, ADDR_NOREF(0)),
                        doIMulM<32>(ip, block, MEM_REFERENCE(0)))
GENERIC_TRANSLATION_REF(IMUL64m, doIMulM<64>(ip, block, ADDR_NOREF(0)),
                        doIMulM<64>(ip, block, MEM_REFERENCE(0)))
GENERIC_TRANSLATION(IMUL32rr, doIMulRR<32>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION(IMUL64rr, doIMulRR<64>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION(IMUL64r, doIMulR<64>(ip, block, OP(0)))
GENERIC_TRANSLATION(IMUL16rr, doIMulRR<16>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION_REF(
    IMUL16rmi, doIMulRMI<16>(ip, block, OP(0), ADDR_NOREF(1), OP(6)),
    doIMulRMI<16>(ip, block, OP(0), MEM_REFERENCE(1), OP(6)))
GENERIC_TRANSLATION_REF(
    IMUL16rmi8, doIMulRMI8<16>(ip, block, OP(0), ADDR_NOREF(1), OP(6)),
    doIMulRMI8<16>(ip, block, OP(0), MEM_REFERENCE(1), OP(6)))
GENERIC_TRANSLATION(IMUL16rri, doIMulRRI<16>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION(IMUL16rri8, doIMulRRI<16>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION_REF(
    IMUL32rmi, doIMulRMI<32>(ip, block, OP(0), ADDR_NOREF(1), OP(6)),
    doIMulRMI<32>(ip, block, OP(0), MEM_REFERENCE(1), OP(6)))
GENERIC_TRANSLATION_REF(
    IMUL32rmi8, doIMulRMI8<32>(ip, block, OP(0), ADDR_NOREF(1), OP(6)),
    doIMulRMI8<32>(ip, block, OP(0), MEM_REFERENCE(1), OP(6)))
GENERIC_TRANSLATION_REF(
    IMUL64rmi8, doIMulRMI8<64>(ip, block, OP(0), ADDR_NOREF(1), OP(6)),
    doIMulRMI8<64>(ip, block, OP(0), MEM_REFERENCE(1), OP(6)))
GENERIC_TRANSLATION(IMUL32rri, doIMulRRI<32>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION(IMUL32rri8, doIMulRRI<32>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION(IMUL64rri8, doIMulRRI<64>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION_REF(
    IMUL64rri32, doIMulRRI<64>(ip, block, OP(0), OP(1), OP(2)),
    doIMulRRV<64>(ip, block, IMM_AS_DATA_REF(block, natM, ip), OP(0), OP(1)))
GENERIC_TRANSLATION_MI(
    IMUL64rmi32,
    doIMulRMI<64>(ip, block, OP(0), ADDR_NOREF(1), OP(2)),
    doIMulRMI<64>(ip, block, OP(0), MEM_REFERENCE(1), OP(2)),
    doIMulRMV<64>(ip, block, OP(0), ADDR_NOREF(1), IMM_AS_DATA_REF(block, natM, ip)),
    doIMulRMV<64>(ip, block, OP(0), MEM_REFERENCE(1), IMM_AS_DATA_REF(block, natM, ip)))
GENERIC_TRANSLATION(IDIV8r, doIDivR<8>(ip, block, OP(0)))
GENERIC_TRANSLATION(IDIV16r, doIDivR<16>(ip, block, OP(0)))
GENERIC_TRANSLATION(IDIV32r, doIDivR<32>(ip, block, OP(0)))
GENERIC_TRANSLATION(IDIV64r, doIDivR<64>(ip, block, OP(0)))
GENERIC_TRANSLATION_REF(IDIV8m, doIDivM<8>(ip, block, ADDR_NOREF(0)),
                        doIDivM<8>(ip, block, MEM_REFERENCE(0)))
GENERIC_TRANSLATION_REF(IDIV16m, doIDivM<16>(ip, block, ADDR_NOREF(0)),
                        doIDivM<16>(ip, block, MEM_REFERENCE(0)))
GENERIC_TRANSLATION_REF(IDIV32m, doIDivM<32>(ip, block, ADDR_NOREF(0)),
                        doIDivM<32>(ip, block, MEM_REFERENCE(0)))
GENERIC_TRANSLATION_REF(IDIV64m, doIDivM<64>(ip, block, ADDR_NOREF(0)),
                        doIDivM<64>(ip, block, MEM_REFERENCE(0)))

GENERIC_TRANSLATION(DIV8r, doDivR<8>(ip, block, OP(0)))
GENERIC_TRANSLATION(DIV16r, doDivR<16>(ip, block, OP(0)))
GENERIC_TRANSLATION(DIV32r, doDivR<32>(ip, block, OP(0)))
GENERIC_TRANSLATION(DIV64r, doDivR<64>(ip, block, OP(0)))
GENERIC_TRANSLATION_REF(DIV8m, doDivM<8>(ip, block, ADDR_NOREF(0)),
                        doDivM<8>(ip, block, MEM_REFERENCE(0)))
GENERIC_TRANSLATION_REF(DIV16m, doDivM<16>(ip, block, ADDR_NOREF(0)),
                        doDivM<16>(ip, block, MEM_REFERENCE(0)))
GENERIC_TRANSLATION_REF(DIV32m, doDivM<32>(ip, block, ADDR_NOREF(0)),
                        doDivM<32>(ip, block, MEM_REFERENCE(0)))
GENERIC_TRANSLATION_REF(DIV64m, doDivM<64>(ip, block, ADDR_NOREF(0)),
                        doDivM<64>(ip, block, MEM_REFERENCE(0)))

void MULDIV_populateDispatchMap(DispatchMap &m) {
  m[llvm::X86::IMUL32rm] = translate_IMUL32rm;
  m[llvm::X86::IMUL64rm] = translate_IMUL64rm;
  m[llvm::X86::IMUL16rm] = translate_IMUL16rm;
  m[llvm::X86::IMUL8r] = translate_IMUL8r;
  m[llvm::X86::IMUL8m] = translate_IMUL8m;
  m[llvm::X86::IMUL16r] = translate_IMUL16r;
  m[llvm::X86::IMUL16m] = translate_IMUL16m;
  m[llvm::X86::MUL32r] = translate_MUL32r;
  m[llvm::X86::MUL64r] = translate_MUL64r;
  m[llvm::X86::MUL32m] = translate_MUL32m;
  m[llvm::X86::MUL64m] = translate_MUL64m;
  m[llvm::X86::MUL16r] = translate_MUL16r;
  m[llvm::X86::MUL16m] = translate_MUL16m;
  m[llvm::X86::MUL8r] = translate_MUL8r;
  m[llvm::X86::MUL8m] = translate_MUL8m;
  m[llvm::X86::IMUL32r] = translate_IMUL32r;
  m[llvm::X86::IMUL32m] = translate_IMUL32m;
  m[llvm::X86::IMUL64m] = translate_IMUL64m;
  m[llvm::X86::IMUL32rr] = translate_IMUL32rr;
  m[llvm::X86::IMUL16rr] = translate_IMUL16rr;
  m[llvm::X86::IMUL16rmi] = translate_IMUL16rmi;
  m[llvm::X86::IMUL16rmi8] = translate_IMUL16rmi8;
  m[llvm::X86::IMUL16rri] = translate_IMUL16rri;
  m[llvm::X86::IMUL16rri8] = translate_IMUL16rri8;
  m[llvm::X86::IMUL32rmi] = translate_IMUL32rmi;
  m[llvm::X86::IMUL32rmi8] = translate_IMUL32rmi8;
  m[llvm::X86::IMUL64rmi8] = translate_IMUL64rmi8;
  m[llvm::X86::IMUL32rri] = translate_IMUL32rri;
  m[llvm::X86::IMUL32rri8] = translate_IMUL32rri8;
  m[llvm::X86::IMUL64rri8] = translate_IMUL64rri8;
  m[llvm::X86::IMUL64rri32] = translate_IMUL64rri32;
  m[llvm::X86::IMUL64rmi32] = translate_IMUL64rmi32;
  m[llvm::X86::IMUL64rr] = translate_IMUL64rr;
  m[llvm::X86::IMUL64r] = translate_IMUL64r;

  m[llvm::X86::IDIV8r] = translate_IDIV8r;
  m[llvm::X86::IDIV16r] = translate_IDIV16r;
  m[llvm::X86::IDIV32r] = translate_IDIV32r;
  m[llvm::X86::IDIV64r] = translate_IDIV64r;
  m[llvm::X86::IDIV8m] = translate_IDIV8m;
  m[llvm::X86::IDIV16m] = translate_IDIV16m;
  m[llvm::X86::IDIV32m] = translate_IDIV32m;
  m[llvm::X86::IDIV64m] = translate_IDIV64m;
  m[llvm::X86::DIV8r] = translate_DIV8r;
  m[llvm::X86::DIV16r] = translate_DIV16r;
  m[llvm::X86::DIV32r] = translate_DIV32r;
  m[llvm::X86::DIV64r] = translate_DIV64r;
  m[llvm::X86::DIV8m] = translate_DIV8m;
  m[llvm::X86::DIV16m] = translate_DIV16m;
  m[llvm::X86::DIV32m] = translate_DIV32m;
  m[llvm::X86::DIV64m] = translate_DIV64m;
}
