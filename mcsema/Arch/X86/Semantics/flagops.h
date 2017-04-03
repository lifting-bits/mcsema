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

#pragma once

#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/Intrinsics.h>
#include <llvm/IR/Instruction.h>

#include "mcsema/Arch/X86/Util.h"
#include "mcsema/cfgToLLVM/TransExcn.h"

template<int width>
static void WriteZF(llvm::BasicBlock *b, llvm::Value *w) {
  //set ZF
  //ZF is set if the result is 0 and clear otherwise
  F_WRITE(
      b, llvm::X86::ZF,
      new llvm::ICmpInst( *b, llvm::CmpInst::ICMP_EQ, w, CONST_V<width>(b, 0)));
}

template<int width>
static void WriteCFShiftR(llvm::BasicBlock *b, llvm::Value *val,
                          llvm::Value *shiftAmt) {
  auto v = llvm::BinaryOperator::CreateLShr(
      val,
      llvm::BinaryOperator::CreateSub(shiftAmt, CONST_V<width>(b, 1), "", b),
      "", b);
  auto &C = b->getContext();
  F_WRITE(
      b,
      llvm::X86::CF,
      new llvm::ZExtInst(
          new llvm::TruncInst(v, llvm::Type::getInt1Ty(C), "", b),
          llvm::Type::getInt8Ty(C), "", b));
}

template<int width>
static void WriteAFAddSub(llvm::BasicBlock *b, llvm::Value *res,
                          llvm::Value *o1, llvm::Value *o2) {
  auto v1 = llvm::BinaryOperator::CreateXor(res, o1, "", b);
  auto v2 = llvm::BinaryOperator::CreateXor(v1, o2, "", b);
  auto v3 = llvm::BinaryOperator::CreateAnd(v2, CONST_V<width>(b, 16), "", b);
  auto c = new llvm::ICmpInst( *b, llvm::CmpInst::ICMP_NE, v3,
                              CONST_V<width>(b, 0));
  F_WRITE(b, llvm::X86::AF, c);
}

template<int width>
static void WriteAF2(llvm::BasicBlock *b, llvm::Value *r, llvm::Value *lhs,
                     llvm::Value *rhs) {
  //this will implement the (r ^ lhs ^ rhs) & 0x10 approach used by VEX
  //but it will also assume that the values as input are full width
  auto t1 = llvm::BinaryOperator::CreateXor(r, lhs, "", b);
  auto t2 = llvm::BinaryOperator::CreateXor(t1, rhs, "", b);
  auto t3 = llvm::BinaryOperator::CreateAnd(t2, CONST_V<width>(b, 0x10), "", b);
  auto cr = new llvm::ICmpInst( *b, llvm::CmpInst::ICMP_NE, t3,
                               CONST_V<width>(b, 0));
  F_WRITE(b, llvm::X86::AF, cr);
}

template<int width>
static void WriteCFAdd(llvm::BasicBlock *b, llvm::Value *res,
                       llvm::Value *argL) {
  //cf = res < argL
  auto cmpRes = new llvm::ICmpInst( *b, llvm::CmpInst::ICMP_ULT, res, argL);
  F_WRITE(b, llvm::X86::CF, cmpRes);
}

static void WriteCFSub(llvm::BasicBlock *b, llvm::Value *argL,
                       llvm::Value *argR) {
  auto cmpRes = new llvm::ICmpInst( *b, llvm::CmpInst::ICMP_ULT, argL, argR);
  F_WRITE(b, llvm::X86::CF, cmpRes);
}

template<int width>
static void WriteOFSub(llvm::BasicBlock *b, llvm::Value *res, llvm::Value *lhs,
                       llvm::Value *rhs) {
  //of = lshift((lhs ^ rhs ) & (lhs ^ res), 12 - width) & 2048
  //where lshift is written as if n >= 0, x << n, else x >> (-n)
  auto xor1 = llvm::BinaryOperator::CreateXor(lhs, rhs, "", b);
  auto xor2 = llvm::BinaryOperator::CreateXor(lhs, res, "", b);
  auto anded = llvm::BinaryOperator::CreateAnd(xor1, xor2, "", b);

  llvm::Value *shifted = nullptr;
  // extract sign bit
  switch (width) {
    case 8:
    case 16:
    case 32:
    case 64:
      shifted = llvm::BinaryOperator::CreateLShr(anded,
                                                 CONST_V<width>(b, width - 1),
                                                 "", b);
      break;

    default:
      throw TErr(__LINE__, __FILE__, "Invalid bitwidth");
  }

  //truncate anded1
  auto &C = b->getContext();
  auto trunced = new llvm::ZExtInst(
      new llvm::TruncInst(shifted, llvm::Type::getInt1Ty(C), "", b),
      llvm::Type::getInt8Ty(C), "", b);

  //write to OF
  F_WRITE(b, llvm::X86::OF, trunced);
}

template<int width>
static void WriteOFAdd(llvm::BasicBlock *b, llvm::Value *res, llvm::Value *lhs,
                       llvm::Value *rhs) {
  //of = lshift((lhs ^ rhs ^ -1) & (lhs ^ res), 12 - width) & 2048
  //where lshift is written as if n >= 0, x << n, else x >> (-n)

  auto xor1 = llvm::BinaryOperator::CreateXor(lhs, rhs, "", b);
  auto xor2 = llvm::BinaryOperator::CreateXor(xor1, CONST_V<width>(b, -1), "",
                                              b);
  auto xor3 = llvm::BinaryOperator::CreateXor(lhs, res, "", b);
  auto anded = llvm::BinaryOperator::CreateAnd(xor2, xor3, "", b);
  llvm::Value *shifted = nullptr;
  // shifts corrected to always place the OF bit
  // in the bit 0 position. This way it works for
  // all sized ints
  switch (width) {
    case 8:
      //lshift by 4
      shifted = llvm::BinaryOperator::CreateLShr(anded,
                                                 CONST_V<width>(b, 11 - 4), "",
                                                 b);
      break;
      //in these two cases, we rshift instead
    case 16:
      //rshift by 4
      shifted = llvm::BinaryOperator::CreateLShr(anded,
                                                 CONST_V<width>(b, 11 + 4), "",
                                                 b);
      break;
    case 32:
      //rshift by 20
      shifted = llvm::BinaryOperator::CreateLShr(anded,
                                                 CONST_V<width>(b, 11 + 20), "",
                                                 b);
      break;
    case 64:
      //rshift by 52
      shifted = llvm::BinaryOperator::CreateLShr(anded,
                                                 CONST_V<width>(b, 11 + 52), "",
                                                 b);
      break;

    default:
      throw TErr(__LINE__, __FILE__, "Invalid bitwidth");
  }

  //and by 1
  auto anded1 = llvm::BinaryOperator::CreateAnd(shifted, CONST_V<width>(b, 1),
                                                "", b);

  //truncate anded1
  auto &C = b->getContext();
  auto trunced = new llvm::ZExtInst(
      new llvm::TruncInst(anded1, llvm::Type::getInt1Ty(C), "", b),
      llvm::Type::getInt8Ty(C), "", b);

  //write to OF
  F_WRITE(b, llvm::X86::OF, trunced);
}

template<int width>
static void WritePF(llvm::BasicBlock *b, llvm::Value *written) {
  auto M = b->getParent()->getParent();
  //truncate the written value to one byte
  //if the width is already 8, we don't need to do this
  llvm::Value *lsb = nullptr;
  if (width > 8) {
    lsb = new llvm::TruncInst(written, llvm::Type::getInt8Ty(b->getContext()),
                              "", b);
  } else {
    lsb = written;
  }

  //use llvm.ctpop.i8 to count the bits set in this byte
  auto &C = b->getContext();
  llvm::Type *s[] = {llvm::Type::getInt8Ty(C)};
  auto popCntFun = llvm::Intrinsic::getDeclaration(M, llvm::Intrinsic::ctpop,
                                                   s);

  std::vector<llvm::Value *> countArgs;
  countArgs.push_back(lsb);

  auto count = llvm::CallInst::Create(popCntFun, countArgs, "", b);

  //truncate the count to a bit
  auto ty = llvm::Type::getInt1Ty(C);
  auto countTrunc = new llvm::ZExtInst(new llvm::TruncInst(count, ty, "", b),
                                       llvm::Type::getInt8Ty(C), "", b);

  //negate that bit via xor 1
  auto neg = llvm::BinaryOperator::CreateXor(countTrunc, CONST_V<8>(b, 1), "",
                                             b);

  //write that bit to PF
  F_WRITE(b, llvm::X86::PF, neg);
}

template<int width>
static void WriteSF(llvm::BasicBlock *b, llvm::Value *written) {
  //%1 = SIGNED CMP %written < 0
  //Value   *scmp = new ICmpInst(   *b,
  //                                ICmpInst::ICMP_SLT,
  //                                written,
  //                                CONST_V<width>(b, 0));

  // extract sign bit
  auto signBit = llvm::BinaryOperator::CreateLShr(written,
                                                  CONST_V<width>(b, width - 1),
                                                  "", b);
  auto &C = b->getContext();
  auto trunc = new llvm::ZExtInst(
      new llvm::TruncInst(signBit, llvm::Type::getInt1Ty(C), "", b),
      llvm::Type::getInt8Ty(C), "", b);
  F_WRITE(b, llvm::X86::SF, trunc);
}
