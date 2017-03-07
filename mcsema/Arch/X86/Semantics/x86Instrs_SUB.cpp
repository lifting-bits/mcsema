/*
 Copyright (c) 2014, Trail of Bits
 All rights reserved.

 Redistribution and use in source and binary forms, with or without modification,
 are permitted provided that the following conditions are met:

 Redistributions of source code must retain the above copyright notice, this
 list of conditions and the following disclaimer.

 Redistributions in binary form must reproduce the above copyright notice, this  list of conditions and the following disclaimer in the documentation and/or
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

#include "InstructionDispatch.h"
#include "raiseX86.h"
#include "x86Helpers.h"
#include "x86Instrs_flagops.h"
#include "x86Instrs_SUB.h"

#define NASSERT(cond) TASSERT(cond, "")

template<int width>
static llvm::Value *doSubVV(NativeInstPtr ip, llvm::BasicBlock *&b,
                            llvm::Value *lhs, llvm::Value *rhs) {
  auto subRes = llvm::BinaryOperator::CreateSub(lhs, rhs, "", b);

  // Write the flag updates.
  WriteAFAddSub<width>(b, subRes, lhs, rhs);
  WritePF<width>(b, subRes);
  WriteZF<width>(b, subRes);
  WriteSF<width>(b, subRes);
  WriteCFSub(b, lhs, rhs);
  WriteOFSub<width>(b, subRes, lhs, rhs);

  return subRes;
}

template<int width>
static InstTransResult doSubMI(NativeInstPtr ip, llvm::BasicBlock *&b,
                               llvm::Value *addr, const llvm::MCOperand &imm) {
  NASSERT(addr != NULL);
  NASSERT(imm.isImm());

  auto mem_v = M_READ<width>(ip, b, addr);
  auto c = CONST_V<width>(b, imm.getImm());
  auto res = doSubVV<width>(ip, b, mem_v, c);
  M_WRITE<width>(ip, b, addr, res);
  return ContinueBlock;
}

template<int width>
static InstTransResult doSubMV(NativeInstPtr ip, llvm::BasicBlock *&b,
                               llvm::Value *lhs, llvm::Value *rhs) {
  NASSERT(lhs != NULL);
  NASSERT(rhs != NULL);

  auto mem_v = M_READ<width>(ip, b, lhs);
  auto res = doSubVV<width>(ip, b, mem_v, rhs);
  M_WRITE<width>(ip, b, lhs, res);
  return ContinueBlock;
}

template<int width>
static InstTransResult doSubMR(NativeInstPtr ip, llvm::BasicBlock *&b,
                               llvm::Value *addr, const llvm::MCOperand &o1) {
  NASSERT(addr != NULL);
  NASSERT(o1.isReg());

  auto lhs = M_READ<width>(ip, b, addr);
  auto rhs = R_READ<width>(b, o1.getReg());
  auto res = doSubVV<width>(ip, b, lhs, rhs);
  M_WRITE<width>(ip, b, addr, res);
  return ContinueBlock;
}

template<int width>
static InstTransResult doSubRI(NativeInstPtr ip, llvm::BasicBlock *&b,
                               const llvm::MCOperand &dst,
                               const llvm::MCOperand &src1,
                               const llvm::MCOperand &src2) {
  NASSERT(src1.isReg());
  NASSERT(src2.isImm());
  NASSERT(dst.isReg());

  auto srcReg = R_READ<width>(b, src1.getReg());
  auto c = CONST_V<width>(b, src2.getImm());
  auto subRes = doSubVV<width>(ip, b, srcReg, c);
  R_WRITE<width>(b, dst.getReg(), subRes);
  return ContinueBlock;
}

template<int width>
static InstTransResult doSubRV(NativeInstPtr ip, llvm::BasicBlock *&b,
                               llvm::Value *addr, const llvm::MCOperand &dst,
                               const llvm::MCOperand &src1) {
  NASSERT(src1.isReg());
  NASSERT(dst.isReg());
  TASSERT(addr != NULL, "");

  auto srcReg = R_READ<width>(b, src1.getReg());
  auto subRes = doSubVV<width>(ip, b, srcReg, addr);
  R_WRITE<width>(b, dst.getReg(), subRes);
  return ContinueBlock;
}

template<int dstWidth, int srcWidth>
static InstTransResult doSubRI(NativeInstPtr ip, llvm::BasicBlock *&b,
                               const llvm::MCOperand &dst,
                               const llvm::MCOperand &src1,
                               const llvm::MCOperand &src2) {
  NASSERT(src1.isReg());
  NASSERT(src2.isImm());
  NASSERT(dst.isReg());

  auto srcReg = R_READ<dstWidth>(b, src1.getReg());
  auto c = CONST_V<srcWidth>(b, src2.getImm());
  auto cInst = llvm::CastInst::CreateIntegerCast(c, srcReg->getType(), true, "",
                                                 b);
  auto subRes = doSubVV<dstWidth>(ip, b, srcReg, cInst);
  R_WRITE<dstWidth>(b, dst.getReg(), subRes);
  return ContinueBlock;
}

template<int width>
static InstTransResult doSubRM(NativeInstPtr ip, llvm::BasicBlock *&b,
                               llvm::Value *addr, const llvm::MCOperand &o1,
                               const llvm::MCOperand &o2) {
  NASSERT(addr != NULL);
  NASSERT(o1.isReg());
  NASSERT(o2.isReg());

  auto lhs = R_READ<width>(b, o1.getReg());
  auto rhs = M_READ<width>(ip, b, addr);
  auto res = doSubVV<width>(ip, b, lhs, rhs);
  R_WRITE<width>(b, o2.getReg(), res);
  return ContinueBlock;
}

template<int width>
static InstTransResult doSubRR(NativeInstPtr ip, llvm::BasicBlock *&b,
                               const llvm::MCOperand &dst,
                               const llvm::MCOperand &src1,
                               const llvm::MCOperand &src2) {
  NASSERT(dst.isReg());
  NASSERT(src1.isReg());
  NASSERT(src2.isReg());

  auto r1 = R_READ<width>(b, src1.getReg());
  auto r2 = R_READ<width>(b, src2.getReg());
  auto res = doSubVV<width>(ip, b, r1, r2);
  R_WRITE<width>(b, dst.getReg(), res);
  return ContinueBlock;
}

template<int width>
static llvm::Value *doSbbVV(NativeInstPtr ip, llvm::BasicBlock *&b,
                            llvm::Value *o1, llvm::Value *o2) {
  NASSERT(o1 != NULL);
  NASSERT(o2 != NULL);

  auto cf = F_READ(b, llvm::X86::CF);
  auto cf_ex = new llvm::ZExtInst(cf,
                                  llvm::Type::getIntNTy(b->getContext(), width),
                                  "", b);
  auto t0 = llvm::BinaryOperator::CreateAdd(o2, cf_ex, "", b);
  auto res = llvm::BinaryOperator::CreateSub(o1, t0, "", b);

  WriteAFAddSub<width>(b, res, o1, o2);
  WritePF<width>(b, res);
  WriteZF<width>(b, res);
  WriteSF<width>(b, res);
  WriteCFSub(b, o1, o2);
  WriteOFSub<width>(b, res, o1, t0);
  return res;
}

template<int width>
static InstTransResult doSbbMI(NativeInstPtr ip, llvm::BasicBlock *&b,
                               llvm::Value *addr, const llvm::MCOperand &imm) {
  NASSERT(addr != NULL);
  NASSERT(imm.isImm());

  auto mem_v = M_READ<width>(ip, b, addr);
  auto c = CONST_V<width>(b, imm.getImm());
  auto res = doSbbVV<width>(ip, b, mem_v, c);
  M_WRITE<width>(ip, b, addr, res);
  return ContinueBlock;
}

template<int width>
static InstTransResult doSbbMV(NativeInstPtr ip, llvm::BasicBlock *&b,
                               llvm::Value *addr, llvm::Value *rhs) {
  NASSERT(addr != NULL);
  NASSERT(rhs != NULL);

  auto mem_v = M_READ<width>(ip, b, addr);
  auto res = doSbbVV<width>(ip, b, mem_v, rhs);
  M_WRITE<width>(ip, b, addr, res);
  return ContinueBlock;
}

template<int width>
static InstTransResult doSbbMR(NativeInstPtr ip, llvm::BasicBlock *&b,
                               llvm::Value *addr, const llvm::MCOperand &src) {
  NASSERT(addr != NULL);
  NASSERT(src.isReg());

  auto mem_v = M_READ<width>(ip, b, addr);
  auto r1 = R_READ<width>(b, src.getReg());
  auto res = doSbbVV<width>(ip, b, mem_v, r1);
  M_WRITE<width>(ip, b, addr, res);
  WriteOFSub<width>(b, res, mem_v, r1);
  return ContinueBlock;
}

template<int width>
static InstTransResult doSbbRI(NativeInstPtr ip, llvm::BasicBlock *&b,
                               const llvm::MCOperand &o1,
                               const llvm::MCOperand &o2,
                               const llvm::MCOperand &dst) {
  NASSERT(o1.isReg());
  NASSERT(o2.isImm());
  NASSERT(dst.isReg());

  auto r1 = R_READ<width>(b, o1.getReg());
  auto c = CONST_V<width>(b, o2.getImm());
  auto res = doSbbVV<width>(ip, b, r1, c);
  R_WRITE<width>(b, dst.getReg(), res);
  return ContinueBlock;
}

template<int width>
static InstTransResult doSbbRV(NativeInstPtr ip, llvm::BasicBlock *&b,
                               llvm::Value *addr, const llvm::MCOperand &dst,
                               const llvm::MCOperand &src1) {
  NASSERT(src1.isReg());
  NASSERT(dst.isReg());
  TASSERT(addr != NULL, "");

  auto srcReg = R_READ<width>(b, src1.getReg());
  auto subRes = doSbbVV<width>(ip, b, srcReg, addr);
  R_WRITE<width>(b, dst.getReg(), subRes);
  return ContinueBlock;
}

template<int width>
static InstTransResult doSbbRM(NativeInstPtr ip, llvm::BasicBlock *&b,
                               const llvm::MCOperand &o1, llvm::Value *addr,
                               const llvm::MCOperand &dst) {
  NASSERT(o1.isReg());
  NASSERT(addr != NULL);
  NASSERT(dst.isReg());

  auto r1 = R_READ<width>(b, o1.getReg());
  auto mem_v = M_READ<width>(ip, b, addr);
  auto res = doSbbVV<width>(ip, b, r1, mem_v);
  R_WRITE<width>(b, dst.getReg(), res);
  return ContinueBlock;
}

template<int width>
static InstTransResult doSbbRR(NativeInstPtr ip, llvm::BasicBlock *&b,
                               const llvm::MCOperand &o1,
                               const llvm::MCOperand &o2,
                               const llvm::MCOperand &dst) {
  NASSERT(o1.isReg());
  NASSERT(o2.isReg());
  NASSERT(dst.isReg());

  auto r1 = R_READ<width>(b, o1.getReg());
  auto r2 = R_READ<width>(b, o2.getReg());
  auto res = doSbbVV<width>(ip, b, r1, r2);
  R_WRITE<width>(b, dst.getReg(), res);
  return ContinueBlock;
}

GENERIC_TRANSLATION(
    SUB16i16,
    doSubRI<16>(ip, block, llvm::MCOperand::createReg(llvm::X86::AX), llvm::MCOperand::createReg(llvm::X86::AX), OP(0)))
GENERIC_TRANSLATION_REF(SUB16mi, doSubMI<16>(ip, block, ADDR_NOREF(0), OP(5)),
                        doSubMI<16>(ip, block, MEM_REFERENCE(0), OP(5)))
GENERIC_TRANSLATION_REF(SUB16mi8, doSubMI<16>(ip, block, ADDR_NOREF(0), OP(5)),
                        doSubMI<16>(ip, block, MEM_REFERENCE(0), OP(5)))
GENERIC_TRANSLATION_REF(SUB16mr, doSubMR<16>(ip, block, ADDR_NOREF(0), OP(5)),
                        doSubMR<16>(ip, block, MEM_REFERENCE(0), OP(5)))
GENERIC_TRANSLATION(SUB16ri, doSubRI<16>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION(SUB16ri8, doSubRI<16>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION_REF(SUB16rm,
                        doSubRM<16>(ip, block, ADDR_NOREF(2), OP(0), OP(1)),
                        doSubRM<16>(ip, block, MEM_REFERENCE(2), OP(0), OP(1)))
GENERIC_TRANSLATION(SUB16rr, doSubRR<16>(ip, block, OP(1), OP(2), OP(0)))
GENERIC_TRANSLATION(SUB16rr_REV, doSubRR<16>(ip, block, OP(1), OP(2), OP(0)))
GENERIC_TRANSLATION_REF(
    SUB32i32,
    doSubRI<32>(ip, block, llvm::MCOperand::createReg(llvm::X86::EAX), llvm::MCOperand::createReg(llvm::X86::EAX), OP(0)),
    doSubRV<32>(ip, block, IMM_AS_DATA_REF<32>(block, natM, ip),
                llvm::MCOperand::createReg(llvm::X86::EAX),
                llvm::MCOperand::createReg(llvm::X86::EAX)))

GENERIC_TRANSLATION_MI(
    SUB32mi, doSubMI<32>(ip, block, ADDR_NOREF(0), OP(5)),
    doSubMI<32>(ip, block, MEM_REFERENCE(0), OP(5)),
    doSubMV<32>(ip, block, ADDR_NOREF(0), IMM_AS_DATA_REF(block, natM, ip)),
    doSubMV<32>(ip, block, MEM_REFERENCE(0), IMM_AS_DATA_REF(block, natM, ip)))

GENERIC_TRANSLATION_REF(SUB32mi8, doSubMI<32>(ip, block, ADDR_NOREF(0), OP(5)),
                        doSubMI<32>(ip, block, MEM_REFERENCE(0), OP(5)))

GENERIC_TRANSLATION_REF(SUB64mi8, doSubMI<64>(ip, block, ADDR_NOREF(0), OP(5)),
                        doSubMI<64>(ip, block, MEM_REFERENCE(0), OP(5)))

GENERIC_TRANSLATION_REF(SUB32mr, doSubMR<32>(ip, block, ADDR_NOREF(0), OP(5)),
                        doSubMR<32>(ip, block, MEM_REFERENCE(0), OP(5)))

GENERIC_TRANSLATION_REF(SUB64mr, doSubMR<64>(ip, block, ADDR_NOREF(0), OP(5)),
                        doSubMR<64>(ip, block, MEM_REFERENCE(0), OP(5)))

GENERIC_TRANSLATION(SUB32ri, doSubRI<32>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION(SUB32ri8, doSubRI<32>(ip, block, OP(0), OP(1), OP(2)))
//GENERIC_TRANSLATION(SUB64ri32, doSubRI<64>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION_REF(
    SUB64ri32, doSubRI<64>(ip, block, OP(0), OP(1), OP(2)),
    doSubRV<64>(ip, block, IMM_AS_DATA_REF(block, natM, ip), OP(0), OP(1)))

GENERIC_TRANSLATION_REF(
    SUB64i32,
    doSubRI<64>(ip, block, llvm::MCOperand::createReg(llvm::X86::RAX), llvm::MCOperand::createReg(llvm::X86::RAX), OP(0)),
    doSubRV<64>(ip, block, IMM_AS_DATA_REF(block, natM, ip),
                llvm::MCOperand::createReg(llvm::X86::RAX),
                llvm::MCOperand::createReg(llvm::X86::RAX)))

GENERIC_TRANSLATION_REF(SUB32rm,
                        doSubRM<32>(ip, block, ADDR_NOREF(2), OP(0), OP(1)),
                        doSubRM<32>(ip, block, MEM_REFERENCE(2), OP(0), OP(1)))
GENERIC_TRANSLATION(SUB32rr, doSubRR<32>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION(SUB32rr_REV, doSubRR<32>(ip, block, OP(0), OP(1), OP(2)))

GENERIC_TRANSLATION_REF(SUB64rm,
                        doSubRM<64>(ip, block, ADDR_NOREF(2), OP(0), OP(1)),
                        doSubRM<64>(ip, block, MEM_REFERENCE(2), OP(0), OP(1)))
GENERIC_TRANSLATION(SUB64rr, doSubRR<64>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION(SUB64rr_REV, doSubRR<64>(ip, block, OP(0), OP(1), OP(2)))

GENERIC_TRANSLATION(
    SUB8i8,
    doSubRI<8>(ip, block, llvm::MCOperand::createReg(llvm::X86::AL), llvm::MCOperand::createReg(llvm::X86::AL), OP(0)))
GENERIC_TRANSLATION_REF(SUB8mi, doSubMI<8>(ip, block, ADDR_NOREF(0), OP(5)),
                        doSubMI<8>(ip, block, MEM_REFERENCE(0), OP(5)))
GENERIC_TRANSLATION_REF(SUB8mr, doSubMR<8>(ip, block, ADDR_NOREF(0), OP(5)),
                        doSubMR<8>(ip, block, MEM_REFERENCE(0), OP(5)))
GENERIC_TRANSLATION(SUB8ri, doSubRI<8>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION_REF(SUB8rm,
                        doSubRM<8>(ip, block, ADDR_NOREF(2), OP(0), OP(1)),
                        doSubRM<8>(ip, block, MEM_REFERENCE(2), OP(0), OP(1)))
GENERIC_TRANSLATION(SUB8rr, doSubRR<8>(ip, block, OP(1), OP(2), OP(0)))
GENERIC_TRANSLATION(SUB8rr_REV, doSubRR<8>(ip, block, OP(1), OP(2), OP(0)))
GENERIC_TRANSLATION(
    SBB16i16,
    doSbbRI<16>(ip, block, llvm::MCOperand::createReg(llvm::X86::AX), OP(0), llvm::MCOperand::createReg(llvm::X86::AX)))
GENERIC_TRANSLATION_REF(SBB16mi, doSbbMI<16>(ip, block, ADDR_NOREF(0), OP(5)),
                        doSbbMI<16>(ip, block, MEM_REFERENCE(0), OP(5)))
GENERIC_TRANSLATION_REF(SBB16mi8, doSbbMI<16>(ip, block, ADDR_NOREF(0), OP(5)),
                        doSbbMI<16>(ip, block, MEM_REFERENCE(0), OP(5)))
GENERIC_TRANSLATION_REF(SBB16mr, doSbbMR<16>(ip, block, ADDR_NOREF(0), OP(5)),
                        doSbbMR<16>(ip, block, MEM_REFERENCE(0), OP(5)))
GENERIC_TRANSLATION(SBB16ri, doSbbRI<16>(ip, block, OP(1), OP(2), OP(0)))
GENERIC_TRANSLATION(SBB16ri8, doSbbRI<16>(ip, block, OP(1), OP(2), OP(0)))
GENERIC_TRANSLATION_REF(SBB16rm,
                        doSbbRM<16>(ip, block, OP(1), ADDR_NOREF(2), OP(0)),
                        doSbbRM<16>(ip, block, OP(1), MEM_REFERENCE(2), OP(0)))
GENERIC_TRANSLATION(SBB16rr, doSbbRR<16>(ip, block, OP(1), OP(2), OP(0)))
GENERIC_TRANSLATION(SBB16rr_REV, doSbbRR<16>(ip, block, OP(1), OP(2), OP(0)))
GENERIC_TRANSLATION_REF(
    SBB32i32,
    doSbbRI<32>(ip, block, llvm::MCOperand::createReg(llvm::X86::EAX), OP(0), llvm::MCOperand::createReg(llvm::X86::EAX)),
    doSbbRV<32>(ip, block, IMM_AS_DATA_REF<32>(block, natM, ip),
                llvm::MCOperand::createReg(llvm::X86::EAX),
                llvm::MCOperand::createReg(llvm::X86::EAX)))
GENERIC_TRANSLATION(SBB32ri, doSbbRI<32>(ip, block, OP(1), OP(2), OP(0)))
GENERIC_TRANSLATION(SBB32ri8, doSbbRI<32>(ip, block, OP(1), OP(2), OP(0)))
GENERIC_TRANSLATION(SBB64ri8, doSbbRI<64>(ip, block, OP(1), OP(2), OP(0)))
GENERIC_TRANSLATION_MI(
    SBB32mi, doSbbMI<32>(ip, block, ADDR_NOREF(0), OP(5)),
    doSbbMI<32>(ip, block, MEM_REFERENCE(0), OP(5)),
    doSbbMV<32>(ip, block, ADDR_NOREF(0), IMM_AS_DATA_REF(block, natM, ip)),
    doSbbMV<32>(ip, block, MEM_REFERENCE(0), IMM_AS_DATA_REF(block, natM, ip)))

GENERIC_TRANSLATION_REF(SBB32mi8, doSbbMI<32>(ip, block, ADDR_NOREF(0), OP(5)),
                        doSbbMI<32>(ip, block, MEM_REFERENCE(0), OP(5)))
GENERIC_TRANSLATION_REF(SBB64mi8, doSbbMI<64>(ip, block, ADDR_NOREF(0), OP(5)),
                        doSbbMI<64>(ip, block, MEM_REFERENCE(0), OP(5)))
GENERIC_TRANSLATION_REF(SBB32mr, doSbbMR<32>(ip, block, ADDR_NOREF(0), OP(5)),
                        doSbbMR<32>(ip, block, MEM_REFERENCE(0), OP(5)))
GENERIC_TRANSLATION_REF(SBB32rm,
                        doSbbRM<32>(ip, block, OP(1), ADDR_NOREF(2), OP(0)),
                        doSbbRM<32>(ip, block, OP(1), MEM_REFERENCE(2), OP(0)))
GENERIC_TRANSLATION(SBB32rr, doSbbRR<32>(ip, block, OP(1), OP(2), OP(0)))
GENERIC_TRANSLATION(SBB32rr_REV, doSbbRR<32>(ip, block, OP(1), OP(2), OP(0)))

GENERIC_TRANSLATION_REF(SBB64mr, doSbbMR<64>(ip, block, ADDR_NOREF(0), OP(5)),
                        doSbbMR<64>(ip, block, MEM_REFERENCE(0), OP(5)))
GENERIC_TRANSLATION_REF(SBB64rm,
                        doSbbRM<64>(ip, block, OP(1), ADDR_NOREF(2), OP(0)),
                        doSbbRM<64>(ip, block, OP(1), MEM_REFERENCE(2), OP(0)))
GENERIC_TRANSLATION(SBB64rr, doSbbRR<64>(ip, block, OP(1), OP(2), OP(0)))
GENERIC_TRANSLATION(SBB64rr_REV, doSbbRR<64>(ip, block, OP(1), OP(2), OP(0)))

GENERIC_TRANSLATION(
    SBB8i8,
    doSbbRI<8>(ip, block, llvm::MCOperand::createReg(llvm::X86::AL), OP(0), llvm::MCOperand::createReg(llvm::X86::AL)))
GENERIC_TRANSLATION(SBB8ri, doSbbRI<8>(ip, block, OP(1), OP(2), OP(0)))
GENERIC_TRANSLATION_REF(SBB8mi, doSbbMI<8>(ip, block, ADDR_NOREF(0), OP(5)),
                        doSbbMI<8>(ip, block, MEM_REFERENCE(0), OP(5)))
GENERIC_TRANSLATION_REF(SBB8mr, doSbbMR<8>(ip, block, ADDR_NOREF(0), OP(5)),
                        doSbbMR<8>(ip, block, MEM_REFERENCE(0), OP(5)))
GENERIC_TRANSLATION_REF(SBB8rm,
                        doSbbRM<8>(ip, block, OP(1), ADDR_NOREF(2), OP(0)),
                        doSbbRM<8>(ip, block, OP(1), MEM_REFERENCE(2), OP(0)))
GENERIC_TRANSLATION(SBB8rr, doSbbRR<8>(ip, block, OP(1), OP(2), OP(0)))
GENERIC_TRANSLATION(SBB8rr_REV, doSbbRR<8>(ip, block, OP(1), OP(2), OP(0)))

static InstTransResult translate_SUB64ri8(TranslationContext &ctx,
                                          llvm::BasicBlock *&block) {
  InstTransResult ret;
  auto ip = ctx.natI;
  auto &inst = ip->get_inst();
  ret = doSubRI<64, 8>(ip, block, OP(0), OP(1), OP(2));
  return ret;
}

void SUB_populateDispatchMap(DispatchMap &m) {
  m[llvm::X86::SUB16i16] = translate_SUB16i16;
  m[llvm::X86::SUB16mi] = translate_SUB16mi;
  m[llvm::X86::SUB16mi8] = translate_SUB16mi8;
  m[llvm::X86::SUB16mr] = translate_SUB16mr;
  m[llvm::X86::SUB16ri] = translate_SUB16ri;
  m[llvm::X86::SUB16ri8] = translate_SUB16ri8;
  m[llvm::X86::SUB16rm] = translate_SUB16rm;
  m[llvm::X86::SUB16rr] = translate_SUB16rr;
  m[llvm::X86::SUB16rr_REV] = translate_SUB16rr_REV;
  m[llvm::X86::SUB32i32] = translate_SUB32i32;
  m[llvm::X86::SUB32mi] = translate_SUB32mi;
  m[llvm::X86::SUB32mi8] = translate_SUB32mi8;
  m[llvm::X86::SUB32mr] = translate_SUB32mr;

  m[llvm::X86::SUB64mi8] = translate_SUB64mi8;
  m[llvm::X86::SUB64mr] = translate_SUB64mr;

  m[llvm::X86::SUB32ri] = translate_SUB32ri;
  m[llvm::X86::SUB32ri8] = translate_SUB32ri8;
  m[llvm::X86::SUB32rm] = translate_SUB32rm;
  m[llvm::X86::SUB32rr] = translate_SUB32rr;
  m[llvm::X86::SUB32rr_REV] = translate_SUB32rr_REV;

  m[llvm::X86::SUB64rm] = translate_SUB64rm;
  m[llvm::X86::SUB64rr] = translate_SUB64rr;
  m[llvm::X86::SUB64rr_REV] = translate_SUB64rr_REV;

  m[llvm::X86::SUB8i8] = translate_SUB8i8;
  m[llvm::X86::SUB8mi] = translate_SUB8mi;
  m[llvm::X86::SUB8mr] = translate_SUB8mr;
  m[llvm::X86::SUB8ri] = translate_SUB8ri;
  m[llvm::X86::SUB8rm] = translate_SUB8rm;
  m[llvm::X86::SUB8rr] = translate_SUB8rr;
  m[llvm::X86::SUB8rr_REV] = translate_SUB8rr_REV;
  m[llvm::X86::SBB16i16] = translate_SBB16i16;
  m[llvm::X86::SBB16mi] = translate_SBB16mi;
  m[llvm::X86::SBB16mi8] = translate_SBB16mi8;
  m[llvm::X86::SBB16mr] = translate_SBB16mr;
  m[llvm::X86::SBB16ri] = translate_SBB16ri;
  m[llvm::X86::SBB16ri8] = translate_SBB16ri8;
  m[llvm::X86::SBB16rm] = translate_SBB16rm;
  m[llvm::X86::SBB16rr] = translate_SBB16rr;
  m[llvm::X86::SBB16rr_REV] = translate_SBB16rr_REV;
  m[llvm::X86::SBB32i32] = translate_SBB32i32;
  m[llvm::X86::SBB32mi] = translate_SBB32mi;
  m[llvm::X86::SBB32mi8] = translate_SBB32mi8;
  m[llvm::X86::SBB64mi8] = translate_SBB64mi8;

  m[llvm::X86::SBB32mr] = translate_SBB32mr;
  m[llvm::X86::SBB64mr] = translate_SBB64mr;

  m[llvm::X86::SBB32ri] = translate_SBB32ri;
  m[llvm::X86::SBB32ri8] = translate_SBB32ri8;

  m[llvm::X86::SBB64ri8] = translate_SBB64ri8;

  m[llvm::X86::SBB32rm] = translate_SBB32rm;
  m[llvm::X86::SBB32rr] = translate_SBB32rr;
  m[llvm::X86::SBB32rr_REV] = translate_SBB32rr_REV;

  m[llvm::X86::SBB64rm] = translate_SBB64rm;
  m[llvm::X86::SBB64rr] = translate_SBB64rr;
  m[llvm::X86::SBB64rr_REV] = translate_SBB64rr_REV;

  m[llvm::X86::SBB8i8] = translate_SBB8i8;
  m[llvm::X86::SBB8mi] = translate_SBB8mi;
  m[llvm::X86::SBB8mr] = translate_SBB8mr;
  m[llvm::X86::SBB8ri] = translate_SBB8ri;
  m[llvm::X86::SBB8rm] = translate_SBB8rm;
  m[llvm::X86::SBB8rr] = translate_SBB8rr;
  m[llvm::X86::SBB8rr_REV] = translate_SBB8rr_REV;

  m[llvm::X86::SUB64ri8] = translate_SUB64ri8;
  m[llvm::X86::SUB64ri32] = translate_SUB64ri32;
  m[llvm::X86::SUB64i32] = translate_SUB64i32;
}
