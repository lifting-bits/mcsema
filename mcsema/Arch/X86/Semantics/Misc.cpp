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

#include <llvm/Support/CodeGen.h>
#include <llvm/Support/Debug.h>

#include "mcsema/Arch/Arch.h"
#include "mcsema/Arch/Dispatch.h"
#include "mcsema/Arch/Register.h"

#include "mcsema/Arch/X86/Util.h"
#include "mcsema/Arch/X86/Semantics/MOV.h"
#include "mcsema/Arch/X86/Semantics/flagops.h"
#include "mcsema/Arch/X86/Semantics/Misc.h"

#include "mcsema/BC/Util.h"

static InstTransResult doNoop(llvm::BasicBlock *b) {
  //isn't this exciting
  return ContinueBlock;
}

static InstTransResult doHlt(llvm::BasicBlock *b) {
  //isn't this exciting
  std::cerr << "WARNING: Treating HLT as no-op, but HLT is normally privileged"
            << std::endl;
  return ContinueBlock;
}

static InstTransResult doInt3(llvm::BasicBlock *b) {
  auto M = b->getParent()->getParent();
  //emit an LLVM trap intrinsic
  //this should be changed to a debugtrap intrinsic eventually
  auto trapIntrin = llvm::Intrinsic::getDeclaration(M, llvm::Intrinsic::trap);
  llvm::CallInst::Create(trapIntrin, "", b);
  (void) new llvm::UnreachableInst(b->getContext(), b);
  return ContinueBlock;
}

static InstTransResult doTrap(llvm::BasicBlock *b) {
  auto M = b->getParent()->getParent();
  auto trapIntrin = llvm::Intrinsic::getDeclaration(M, llvm::Intrinsic::trap);
  llvm::CallInst::Create(trapIntrin, "", b);
  (void) new llvm::UnreachableInst(b->getContext(), b);
  return ContinueBlock;
}

static InstTransResult doInt(llvm::BasicBlock *&b, const llvm::MCOperand &o) {
  TASSERT(o.isImm(), "Operand not immediate");
  auto F = b->getParent();
  auto M = F->getParent();
  auto &C = M->getContext();
  int interrupt_val = o.getImm();
  auto os = SystemOS(M);

  if (0x2e == interrupt_val && llvm::Triple::Win32 == os) {
    TASSERT(false, "System call via interrupt is not supported!");
  }

  if (0x80 == interrupt_val && llvm::Triple::Linux == os) {
    TASSERT(32 == ArchAddressSize(),
            "int 0x80 syscall not supported on 64-bit.");
    llvm::Type *arg_tys[] = {llvm::Type::getInt32Ty(C)};
    auto syscall_func_ty = llvm::FunctionType::get(
        llvm::Type::getInt32Ty(C), arg_tys, true /* IsVarArg */);
    auto syscall_func = M->getOrInsertFunction("syscall", syscall_func_ty);

    std::vector<llvm::Value *> args = {
      R_READ<32>(b, llvm::X86::EAX),  // syscall num
      R_READ<32>(b, llvm::X86::EBX),
      R_READ<32>(b, llvm::X86::ECX),
      R_READ<32>(b, llvm::X86::EDX),
      R_READ<32>(b, llvm::X86::ESI),
      R_READ<32>(b, llvm::X86::EDI),
      R_READ<32>(b, llvm::X86::EBP),
    };
    auto ret = llvm::CallInst::Create(syscall_func, args, "", b);
    R_WRITE<32>(b, llvm::X86::EAX, ret);

    return ContinueBlock;
  }

  std::cerr << "WARNING: Treating INT " << interrupt_val << " as trap!"
            << std::endl;

  return doTrap(b);
}

static InstTransResult doCdq(llvm::BasicBlock *b) {
  // EDX <- SEXT(EAX)

  //read EAX
  auto EAX_v = R_READ<32>(b, llvm::X86::EAX);
  auto sign_bit = CONST_V<32>(b, 1ULL << 31U);
  auto test_bit = llvm::BinaryOperator::CreateAnd(EAX_v, sign_bit, "", b);
  auto is_zero = new llvm::ICmpInst( *b, llvm::CmpInst::ICMP_EQ, test_bit,
                                    CONST_V<32>(b, 0));
  auto edx_val = llvm::SelectInst::Create(is_zero, CONST_V<32>(b, 0),
                                          CONST_V<32>(b, 0xFFFFFFFF), "", b);

  //write this value to EDX
  R_WRITE<32>(b, llvm::X86::EDX, edx_val);

  return ContinueBlock;
}

template<int width>
static InstTransResult doBswapR(NativeInstPtr ip, llvm::BasicBlock *&b,
                                const llvm::MCOperand &reg) {
  TASSERT(reg.isReg(), "");

  auto &C = b->getContext();
  auto M = b->getModule();

  auto intNTy = llvm::Type::getIntNTy(C, width);
  auto bswapFTy = llvm::FunctionType::get(intNTy, {intNTy}, false);

  std::stringstream ss;
  ss << "llvm.bswap.i" << width;
  auto bswapF = llvm::dyn_cast<llvm::Function>(
      M->getOrInsertFunction(ss.str(), bswapFTy));

  if (llvm::Intrinsic::bswap != bswapF->getIntrinsicID()) {
    bswapF->recalculateIntrinsicID();
  }

  auto tmp = R_READ<width>(b, reg.getReg());
  auto res = llvm::CallInst::Create(bswapF, {tmp}, "", b);
  R_WRITE<width>(b, reg.getReg(), res);
  return ContinueBlock;
}

static InstTransResult doLAHF(llvm::BasicBlock *b) {

  //we need to create an 8-bit value out of the status
  //flags, shift and OR them, and then write them into AH

  auto cf = F_READ(b, llvm::X86::CF);
  auto af = F_READ(b, llvm::X86::AF);
  auto pf = F_READ(b, llvm::X86::PF);
  auto zf = F_READ(b, llvm::X86::ZF);
  auto sf = F_READ(b, llvm::X86::SF);

  //shift everything
  auto p_0 = cf;
  auto p_1 = llvm::BinaryOperator::CreateShl(CONST_V<8>(b, 1), CONST_V<8>(b, 1),
                                             "", b);
  auto p_2 = llvm::BinaryOperator::CreateShl(pf, CONST_V<8>(b, 2), "", b);
  auto p_3 = llvm::BinaryOperator::CreateShl(CONST_V<8>(b, 0), CONST_V<8>(b, 3),
                                             "", b);
  auto p_4 = llvm::BinaryOperator::CreateShl(af, CONST_V<8>(b, 4), "", b);
  auto p_5 = llvm::BinaryOperator::CreateShl(CONST_V<8>(b, 0), CONST_V<8>(b, 5),
                                             "", b);
  auto p_6 = llvm::BinaryOperator::CreateShl(zf, CONST_V<8>(b, 6), "", b);
  auto p_7 = llvm::BinaryOperator::CreateShl(sf, CONST_V<8>(b, 7), "", b);

  //OR everything
  auto res = llvm::BinaryOperator::CreateOr(
      llvm::BinaryOperator::CreateOr(
          llvm::BinaryOperator::CreateOr(
              llvm::BinaryOperator::CreateOr(p_0, p_1, "", b), p_2, "", b),
          p_3, "", b),
      llvm::BinaryOperator::CreateOr(
          llvm::BinaryOperator::CreateOr(
              llvm::BinaryOperator::CreateOr(p_4, p_5, "", b), p_6, "", b),
          p_7, "", b),
      "", b);

  R_WRITE<8>(b, llvm::X86::AH, res);

  return ContinueBlock;
}

static InstTransResult doStd(llvm::BasicBlock *b) {
  F_SET(b, llvm::X86::DF);
  return ContinueBlock;
}

static InstTransResult doCld(llvm::BasicBlock *b) {
  F_CLEAR(b, llvm::X86::DF);
  return ContinueBlock;
}

static InstTransResult doStc(llvm::BasicBlock *b) {
  F_SET(b, llvm::X86::CF);
  return ContinueBlock;
}

static InstTransResult doClc(llvm::BasicBlock *b) {
  F_CLEAR(b, llvm::X86::CF);
  return ContinueBlock;
}

template<int width>
static InstTransResult doLeaV(llvm::BasicBlock *&b, const llvm::MCOperand &dst,
                              llvm::Value *addrInt) {
  //write the address into the register
  R_WRITE<width>(b, dst.getReg(), addrInt);
  return ContinueBlock;
}

template<int width>
static InstTransResult doLea(NativeInstPtr ip, llvm::BasicBlock *&b,
                             llvm::Value *addr, const llvm::MCOperand &dst) {
  // LEA <r>, <expr>
  TASSERT(addr != NULL, "");
  TASSERT(dst.isReg(), "");

  //addr is an address, so, convert it to an integer value to write
  auto ty = llvm::Type::getIntNTy(b->getContext(), width);
  auto addrInt = addr;
  if (addr->getType()->isPointerTy()) {
    addrInt = new llvm::PtrToIntInst(addr, ty, "", b);
  }

  return doLeaV<width>(b, dst, addrInt);
}

static InstTransResult doRdtsc(llvm::BasicBlock *b) {
  /* write out a call to the RDTSC intrinsic */
  auto M = b->getParent()->getParent();
  auto &C = M->getContext();
  //emit an LLVM trap intrinsic
  //this should be changed to a debugtrap intrinsic eventually
  auto rcc = llvm::Intrinsic::getDeclaration(M,
                                             llvm::Intrinsic::readcyclecounter);
  auto ret = llvm::CallInst::Create(rcc, "", b);
  auto Int32Ty = llvm::Type::getInt32Ty(C);
  auto low = new llvm::TruncInst(ret, Int32Ty, "", b);
  auto high = new llvm::TruncInst(
      llvm::BinaryOperator::Create(llvm::Instruction::LShr, ret,
                                   llvm::ConstantInt::get(Int32Ty, 32), "", b),
      Int32Ty, "", b);
  R_WRITE<32>(b, llvm::X86::EDX, high);
  R_WRITE<32>(b, llvm::X86::EAX, low);
  return ContinueBlock;
}

static InstTransResult doAAA(llvm::BasicBlock *b) {

  auto F = b->getParent();
  auto &C = F->getContext();
  //trueBlock for when ((AL & 0x0F > 9) || (AF == 1)); falseblock otherwise
  auto trueBlock = llvm::BasicBlock::Create(C, "", F);
  auto falseBlock = llvm::BasicBlock::Create(C, "", F);
  auto endBlock = llvm::BasicBlock::Create(C, "", F);

  llvm::Value *al = nullptr;
  llvm::Value *af = nullptr;

  al = R_READ<8>(b, llvm::X86::AL);
  af = F_READ(b, llvm::X86::AF);

  // AL & 0x0F
  auto andRes = llvm::BinaryOperator::CreateAnd(al, CONST_V<8>(b, 0x0F), "", b);

  // ((AL & 0x0F) > 9)?
  auto testRes = new llvm::ICmpInst( *b, llvm::CmpInst::ICMP_UGT, andRes,
                                    CONST_V<8>(b, 9));

  auto orRes = llvm::BinaryOperator::CreateOr(testRes, af, "", b);

  llvm::BranchInst::Create(trueBlock, falseBlock, orRes, b);

  //True Block Statements
  llvm::Value *alRes = llvm::BinaryOperator::CreateAdd(al,
                                                       CONST_V<8>(trueBlock, 6),
                                                       "", trueBlock);
  R_WRITE<8>(trueBlock, llvm::X86::AL, alRes);

  auto ahRes = llvm::BinaryOperator::CreateAdd(
      R_READ<8>(trueBlock, llvm::X86::AH), CONST_V<8>(trueBlock, 1), "",
      trueBlock);
  R_WRITE<8>(trueBlock, llvm::X86::AH, ahRes);

  F_SET(trueBlock, llvm::X86::AF);
  F_SET(trueBlock, llvm::X86::CF);

  alRes = llvm::BinaryOperator::CreateAnd(alRes, CONST_V<8>(trueBlock, 0x0F),
                                          "", trueBlock);
  R_WRITE<8>(trueBlock, llvm::X86::AL, alRes);

  llvm::BranchInst::Create(endBlock, trueBlock);

  //False Block Statements
  F_CLEAR(falseBlock, llvm::X86::AF);
  F_CLEAR(falseBlock, llvm::X86::CF);

  alRes = llvm::BinaryOperator::CreateAnd(al, CONST_V<8>(trueBlock, 0x0F), "",
                                          falseBlock);
  R_WRITE<8>(falseBlock, llvm::X86::AL, alRes);

  llvm::BranchInst::Create(endBlock, falseBlock);

  F_ZAP(endBlock, llvm::X86::OF);
  F_ZAP(endBlock, llvm::X86::SF);
  F_ZAP(endBlock, llvm::X86::ZF);
  F_ZAP(endBlock, llvm::X86::PF);

  //update our parents concept of what the current block is
  b = endBlock;

  return ContinueBlock;
}

static InstTransResult doAAS(llvm::BasicBlock *b) {

  auto F = b->getParent();
  auto &C = F->getContext();

  //trueBlock for when ((AL & 0x0F > 9) || (AF == 1)); falseblock otherwise
  auto trueBlock = llvm::BasicBlock::Create(C, "", F);
  auto falseBlock = llvm::BasicBlock::Create(C, "", F);
  auto endBlock = llvm::BasicBlock::Create(C, "", F);

  llvm::Value *al = nullptr;
  llvm::Value *af = nullptr;

  al = R_READ<8>(b, llvm::X86::AL);
  af = F_READ(b, llvm::X86::AF);

  // AL & 0x0F
  llvm::Value *andRes = llvm::BinaryOperator::CreateAnd(al, CONST_V<8>(b, 0x0F),
                                                        "", b);

  // ((AL & 0x0F) > 9)?
  llvm::Value *testRes = new llvm::ICmpInst( *b, llvm::CmpInst::ICMP_UGT,
                                            andRes, CONST_V<8>(b, 9));

  llvm::Value *orRes = llvm::BinaryOperator::CreateOr(testRes, af, "", b);

  llvm::BranchInst::Create(trueBlock, falseBlock, orRes, b);

  //True Block Statements
  llvm::Value *alRes = llvm::BinaryOperator::CreateSub(al,
                                                       CONST_V<8>(trueBlock, 6),
                                                       "", trueBlock);
  R_WRITE<8>(trueBlock, llvm::X86::AL, alRes);

  llvm::Value *ahRes = llvm::BinaryOperator::CreateSub(
      R_READ<8>(trueBlock, llvm::X86::AH), CONST_V<8>(trueBlock, 1), "",
      trueBlock);
  R_WRITE<8>(trueBlock, llvm::X86::AH, ahRes);

  F_SET(trueBlock, llvm::X86::AF);
  F_SET(trueBlock, llvm::X86::CF);

  alRes = llvm::BinaryOperator::CreateAnd(alRes, CONST_V<8>(trueBlock, 0x0F),
                                          "", trueBlock);
  R_WRITE<8>(trueBlock, llvm::X86::AL, alRes);

  llvm::BranchInst::Create(endBlock, trueBlock);

  //False Block Statements
  F_CLEAR(falseBlock, llvm::X86::AF);
  F_CLEAR(falseBlock, llvm::X86::CF);

  alRes = llvm::BinaryOperator::CreateAnd(al, CONST_V<8>(trueBlock, 0x0F), "",
                                          falseBlock);
  R_WRITE<8>(falseBlock, llvm::X86::AL, alRes);

  llvm::BranchInst::Create(endBlock, falseBlock);

  F_ZAP(endBlock, llvm::X86::OF);
  F_ZAP(endBlock, llvm::X86::SF);
  F_ZAP(endBlock, llvm::X86::ZF);
  F_ZAP(endBlock, llvm::X86::PF);

  //update our parents concept of what the current block is
  b = endBlock;

  return ContinueBlock;
}

static InstTransResult doAAM(llvm::BasicBlock *b) {

  llvm::Value *al = nullptr;

  al = R_READ<8>(b, llvm::X86::AL);

  llvm::Value *res = llvm::BinaryOperator::Create(llvm::Instruction::SDiv, al,
                                                  CONST_V<8>(b, 0x0A), "", b);
  llvm::Value *mod = llvm::BinaryOperator::Create(llvm::Instruction::SRem, al,
                                                  CONST_V<8>(b, 0x0A), "", b);

  R_WRITE<8>(b, llvm::X86::AL, mod);
  R_WRITE<8>(b, llvm::X86::AH, res);

  WriteSF<8>(b, mod);
  WriteZF<8>(b, mod);
  WritePF<8>(b, mod);
  F_ZAP(b, llvm::X86::OF);
  F_ZAP(b, llvm::X86::AF);
  F_ZAP(b, llvm::X86::CF);

  return ContinueBlock;
}

static InstTransResult doAAD(llvm::BasicBlock *b) {

  llvm::Value *al = nullptr;
  llvm::Value *ah = nullptr;

  al = R_READ<8>(b, llvm::X86::AL);
  ah = R_READ<8>(b, llvm::X86::AH);

  llvm::Value *tmp = llvm::BinaryOperator::Create(llvm::Instruction::Mul, ah,
                                                  CONST_V<8>(b, 0x0A), "", b);
  tmp = llvm::BinaryOperator::CreateAdd(tmp, al, "", b);
  tmp = llvm::BinaryOperator::CreateAnd(tmp, CONST_V<8>(b, 0xFF), "", b);

  R_WRITE<8>(b, llvm::X86::AL, tmp);
  R_WRITE<8>(b, llvm::X86::AH, CONST_V<8>(b, 0x00));

  WriteSF<8>(b, tmp);
  WriteZF<8>(b, tmp);
  WritePF<8>(b, tmp);
  F_ZAP(b, llvm::X86::OF);
  F_ZAP(b, llvm::X86::AF);
  F_ZAP(b, llvm::X86::CF);

  return ContinueBlock;
}

template<int width>
static InstTransResult doCwd(llvm::BasicBlock *b) {

  // read ax or eax
  llvm::Value *ax_val = R_READ<width>(b, llvm::X86::EAX);

  // sign extend to twice width
  auto dt = llvm::Type::getIntNTy(b->getContext(), width * 2);
  auto tmp = new llvm::SExtInst(ax_val, dt, "", b);

  // rotate leftmost bits into rightmost
  auto t = llvm::Type::getIntNTy(b->getContext(), width);
  auto res_sh = llvm::BinaryOperator::Create(llvm::Instruction::LShr, tmp,
                                             CONST_V<width * 2>(b, width), "",
                                             b);
  // original rightmost
  auto wrAX = new llvm::TruncInst(tmp, t, "", b);
  // original leftmost
  auto wrDX = new llvm::TruncInst(res_sh, t, "", b);
  switch (width) {
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

static InstTransResult translate_SAHF(TranslationContext &ctx,
                                      llvm::BasicBlock *&block) {
  auto ah_val = R_READ<8>(block, llvm::X86::AH);

  SHR_SET_FLAG<8, 1>(block, ah_val, llvm::X86::CF, 0);
  // bit 1 is reserved
  SHR_SET_FLAG<8, 1>(block, ah_val, llvm::X86::PF, 2);
  // bit 3 is reserved
  SHR_SET_FLAG<8, 1>(block, ah_val, llvm::X86::AF, 4);
  // bit 5 is reserved
  SHR_SET_FLAG<8, 1>(block, ah_val, llvm::X86::ZF, 6);
  SHR_SET_FLAG<8, 1>(block, ah_val, llvm::X86::SF, 7);

  return ContinueBlock;
}

template<int width>
static InstTransResult doBtmi(NativeInstPtr ip, llvm::BasicBlock *&b,
                              llvm::Value *base, const llvm::MCOperand &index) {
  TASSERT(index.isImm(), "Operand must be an immediate");

  int imm = index.getImm();
  int bytes_offt = imm / 8;
  int whichbit = imm % 8;
  if (whichbit < 0) {
    // make this always positive
    whichbit *= -1;
  }

  auto addrInt = base;

  if (base->getType()->isPointerTy()) {
    addrInt = new llvm::PtrToIntInst(
        base, llvm::Type::getIntNTy(b->getContext(), width), "", b);
  }

  // pick which byte we need to bit test
  auto new_base = llvm::BinaryOperator::Create(llvm::Instruction::Add, addrInt,
                                               CONST_V<width>(b, bytes_offt),
                                               "", b);

  auto base_val = M_READ<8>(ip, b, new_base);
  SHR_SET_FLAG_V<8, 1>(b, base_val, llvm::X86::CF, CONST_V<8>(b, whichbit));

  return ContinueBlock;
}

template<int width>
static InstTransResult doBtri(llvm::BasicBlock *&b, const llvm::MCOperand &base,
                              const llvm::MCOperand &index) {
  TASSERT(base.isReg(), "Operand must be an immediate");
  TASSERT(index.isImm(), "Operand must be an immediate");

  unsigned whichbit = index.getImm();
  whichbit %= width;

  auto base_val = R_READ<width>(b, base.getReg());
  SHR_SET_FLAG_V<width, 1>(b, base_val, llvm::X86::CF,
                           CONST_V<width>(b, whichbit));

  return ContinueBlock;
}

template<int width>
static InstTransResult doBtrr(llvm::BasicBlock *&b, const llvm::MCOperand &base,
                              const llvm::MCOperand &index) {

  TASSERT(base.isReg(), "operand must be register");
  TASSERT(index.isReg(), "operand must be register");

  auto base_val = R_READ<width>(b, base.getReg());
  auto index_val = R_READ<width>(b, index.getReg());

  // modulo the index by register size
  auto index_mod = llvm::BinaryOperator::CreateURem(index_val,
                                                    CONST_V<width>(b, width),
                                                    "", b);

  SHR_SET_FLAG_V<width, 1>(b, base_val, llvm::X86::CF, index_mod);

  return ContinueBlock;
}


template<int width>
static InstTransResult doBtmr(NativeInstPtr ip, llvm::BasicBlock *&b,
                               llvm::Value *base,
                               const llvm::MCOperand &index) {
  TASSERT(index.isReg(), "Operand must be an immediate");
  auto index_val = R_READ<width>(b, index.getReg());
  auto word_size = CONST_V<width>(b, width);
  auto bit = llvm::BinaryOperator::CreateURem(index_val, word_size, "", b);
  auto word = llvm::BinaryOperator::CreateUDiv(index_val, word_size, "", b);
  auto ptr = ADDR_TO_POINTER<width>(b, base);
  auto gep = llvm::GetElementPtrInst::CreateInBounds(ptr, {word}, "", b);
  auto val = M_READ<width>(ip, b, gep);
  SHR_SET_FLAG_V<width, 1>(b, val, llvm::X86::CF, bit);
  return ContinueBlock;
}

template<int width>
static InstTransResult doBTSrr(llvm::BasicBlock *&b,
                               const llvm::MCOperand &base,
                               const llvm::MCOperand &index) {
  TASSERT(base.isReg(), "Operand must be a register");
  TASSERT(index.isReg(), "Operand must be a register");

  auto base_val = R_READ<width>(b, base.getReg());
  auto index_val = R_READ<width>(b, index.getReg());

  // modulo the index by register size
  auto index_mod = llvm::BinaryOperator::CreateURem(index_val,
                                                    CONST_V<width>(b, width),
                                                    "", b);

  SHR_SET_FLAG_V<width, 1>(b, base_val, llvm::X86::CF,
                           index_mod);

  auto bit_mask = llvm::BinaryOperator::CreateShl(CONST_V<width>(b, 1),
          index_mod, "", b);

  auto new_base_val = llvm::BinaryOperator::Create(
      llvm::Instruction::Or, base_val, bit_mask, "",
      b);
  R_WRITE<width>(b, base.getReg(), new_base_val);

  return ContinueBlock;

}

template<int width>
static InstTransResult doBTSri(llvm::BasicBlock *&b,
                               const llvm::MCOperand &base,
                               const llvm::MCOperand &index) {
  TASSERT(base.isReg(), "Operand must be a register");
  TASSERT(index.isImm(), "Operand must be an immediate");

  unsigned whichbit = index.getImm();
  whichbit %= width;

  auto base_val = R_READ<width>(b, base.getReg());
  SHR_SET_FLAG_V<width, 1>(b, base_val, llvm::X86::CF,
                           CONST_V<width>(b, whichbit));

  auto new_base_val = llvm::BinaryOperator::Create(
      llvm::Instruction::Or, base_val, CONST_V<width>(b, 1ULL << whichbit), "",
      b);
  R_WRITE<width>(b, base.getReg(), new_base_val);

  return ContinueBlock;
}

template<int width>
static InstTransResult doBTSmi(NativeInstPtr ip, llvm::BasicBlock *&b,
                               llvm::Value *base,
                               const llvm::MCOperand &index) {
  TASSERT(index.isImm(), "Operand must be an immediate");

  int imm = index.getImm();
  int bytes_offt = imm / 8;
  int whichbit = imm % 8;
  if (whichbit < 0) {
    // make this always positive
    whichbit *= -1;
  }

  auto addrInt = base;

  if (base->getType()->isPointerTy()) {
    addrInt = new llvm::PtrToIntInst(
        base, llvm::Type::getIntNTy(b->getContext(), width), "", b);
  }

  // pick which byte we need to bit test
  auto new_base = llvm::BinaryOperator::Create(llvm::Instruction::Add, addrInt,
                                               CONST_V<width>(b, bytes_offt),
                                               "", b);

  auto base_val = M_READ<8>(ip, b, new_base);
  SHR_SET_FLAG_V<8, 1>(b, base_val, llvm::X86::CF, CONST_V<8>(b, whichbit));

  auto new_base_val = llvm::BinaryOperator::Create(llvm::Instruction::Or,
                                                   base_val,
                                                   CONST_V<8>(b, 1 << whichbit),
                                                   "", b);
  M_WRITE<8>(ip, b, new_base, new_base_val);

  return ContinueBlock;
}

template<int width>
static InstTransResult doBTSmr(NativeInstPtr ip, llvm::BasicBlock *&b,
                               llvm::Value *base,
                               const llvm::MCOperand &index) {
  TASSERT(index.isReg(), "Operand must be an immediate");
  auto index_val = R_READ<width>(b, index.getReg());
  auto word_size = CONST_V<width>(b, width);
  auto bit = llvm::BinaryOperator::CreateURem(index_val, word_size, "", b);
  auto word = llvm::BinaryOperator::CreateUDiv(index_val, word_size, "", b);
  auto ptr = ADDR_TO_POINTER<width>(b, base);
  auto gep = llvm::GetElementPtrInst::CreateInBounds(ptr, {word}, "", b);
  auto val = M_READ<width>(ip, b, gep);

  SHR_SET_FLAG_V<width, 1>(b, val, llvm::X86::CF, bit);

  auto bit_to_set = llvm::BinaryOperator::CreateShl(
      CONST_V<width>(b, 1), bit, "", b);

  auto new_val = llvm::BinaryOperator::CreateOr(val, bit_to_set, "", b);
  M_WRITE<width>(ip, b, gep, new_val);

  return ContinueBlock;
}

template<int width>
static InstTransResult doBTRmi(NativeInstPtr ip, llvm::BasicBlock *&b,
                               llvm::Value *base,
                               const llvm::MCOperand &index) {
  TASSERT(index.isImm(), "Operand must be an immediate");

  int imm = index.getImm();
  int bytes_offt = imm / 8;
  int whichbit = imm % 8;
  if (whichbit < 0) {
    // make this always positive
    whichbit *= -1;
  }

  auto addrInt = base;

  if (base->getType()->isPointerTy()) {
    addrInt = new llvm::PtrToIntInst(
        base, llvm::Type::getIntNTy(b->getContext(), width), "", b);
  }

  // pick which byte we need to bit test
  auto new_base = llvm::BinaryOperator::Create(llvm::Instruction::Add, addrInt,
                                               CONST_V<width>(b, bytes_offt),
                                               "", b);

  auto base_val = M_READ<8>(ip, b, new_base);
  SHR_SET_FLAG_V<8, 1>(b, base_val, llvm::X86::CF, CONST_V<8>(b, whichbit));

  auto new_base_val = llvm::BinaryOperator::Create(
      llvm::Instruction::And, base_val, CONST_V<8>(b, ~(1ULL << whichbit)), "",
      b);

  M_WRITE<8>(ip, b, new_base, new_base_val);

  return ContinueBlock;
}

template<int width>
static InstTransResult doBTRmr(NativeInstPtr ip, llvm::BasicBlock *&b,
                               llvm::Value *base,
                               const llvm::MCOperand &index) {
  TASSERT(index.isReg(), "Operand must be an immediate");
  auto index_val = R_READ<width>(b, index.getReg());
  auto word_size = CONST_V<width>(b, width);
  auto bit = llvm::BinaryOperator::CreateURem(index_val, word_size, "", b);
  auto word = llvm::BinaryOperator::CreateUDiv(index_val, word_size, "", b);
  auto ptr = ADDR_TO_POINTER<width>(b, base);
  auto gep = llvm::GetElementPtrInst::CreateInBounds(ptr, {word}, "", b);
  auto val = M_READ<width>(ip, b, gep);
  SHR_SET_FLAG_V<width, 1>(b, val, llvm::X86::CF, bit);
  auto bit_to_clear = llvm::BinaryOperator::CreateXor(
      llvm::BinaryOperator::CreateLShr(CONST_V<width>(b, 1), bit, "", b),
      CONST_V<width>(b, 0), "", b);
  auto new_val = llvm::BinaryOperator::CreateAnd(val, bit_to_clear, "", b);
  M_WRITE<width>(ip, b, gep, new_val);

  return ContinueBlock;
}

template<int width>
static InstTransResult doBsrr(llvm::BasicBlock *&b, const llvm::MCOperand &dst,
                              const llvm::MCOperand &src) {

  TASSERT(dst.isReg(), "operand must be register");
  TASSERT(src.isReg(), "operand must be register");

  auto src_val = R_READ<width>(b, src.getReg());

  llvm::Type *s[] = {llvm::Type::getIntNTy(b->getContext(), width)};
  auto ctlzFn = llvm::Intrinsic::getDeclaration(b->getParent()->getParent(),
                                                llvm::Intrinsic::ctlz, s);

  TASSERT(ctlzFn != NULL, "Could not find ctlz intrinsic");

  std::vector<llvm::Value *> ctlzArgs;
  ctlzArgs.push_back(src_val);
  ctlzArgs.push_back(CONST_V<1>(b, 0));
  auto ctlz = llvm::CallInst::Create(ctlzFn, ctlzArgs, "", b);

  auto index_of_first_1 = llvm::BinaryOperator::CreateSub(
      CONST_V<width>(b, width), ctlz, "", b);

  auto is_zero = new llvm::ICmpInst( *b, llvm::CmpInst::ICMP_EQ,
                                    CONST_V<width>(b, 0), index_of_first_1);

  F_WRITE(b, llvm::X86::ZF, is_zero);

  auto fix_index = llvm::BinaryOperator::CreateSub(index_of_first_1,
                                                   CONST_V<width>(b, 1), "", b);

  // See if we write to register
  auto save_index = llvm::SelectInst::Create(is_zero,  // check if the source was zero
      src_val,  // if it was, do not change contents
      fix_index,  // if it was not, set index
      "", b);

  R_WRITE<width>(b, dst.getReg(), save_index);

  return ContinueBlock;
}

template<int width>
static InstTransResult doBsfrm(NativeInstPtr ip, llvm::BasicBlock *&b,
                               const llvm::MCOperand &dst,
                               llvm::Value *memAddr) {

  TASSERT(dst.isReg(), "operand must be register");

  auto src_val = M_READ<width>(ip, b, memAddr);

  llvm::Type *s[] = {llvm::Type::getIntNTy(b->getContext(), width)};
  auto cttzFn = llvm::Intrinsic::getDeclaration(b->getParent()->getParent(),
                                                llvm::Intrinsic::cttz, s);

  TASSERT(cttzFn != NULL, "Could not find cttz intrinsic");

  std::vector<llvm::Value *> cttzArgs;
  cttzArgs.push_back(src_val);
  cttzArgs.push_back(CONST_V<1>(b, 0));
  auto cttz = llvm::CallInst::Create(cttzFn, cttzArgs, "", b);

  auto is_zero = new llvm::ICmpInst( *b, llvm::CmpInst::ICMP_EQ,
                                    CONST_V<width>(b, width), cttz);

  F_WRITE(b, llvm::X86::ZF, is_zero);

  // See if we write to register
  auto save_index = llvm::SelectInst::Create(is_zero,  // check if the source was zero
      src_val,  // if it was, do not change contents
      cttz,  // if it was not, set index
      "", b);

  R_WRITE<width>(b, dst.getReg(), save_index);

  return ContinueBlock;
}

template<int width>
static InstTransResult doBsfr(llvm::BasicBlock *&b, const llvm::MCOperand &dst,
                              const llvm::MCOperand &src) {

  TASSERT(dst.isReg(), "operand must be register");
  TASSERT(src.isReg(), "operand must be register");

  auto src_val = R_READ<width>(b, src.getReg());

  llvm::Type *s[] = {llvm::Type::getIntNTy(b->getContext(), width)};
  auto cttzFn = llvm::Intrinsic::getDeclaration(b->getParent()->getParent(),
                                                llvm::Intrinsic::cttz, s);

  TASSERT(cttzFn != NULL, "Could not find cttz intrinsic");

  std::vector<llvm::Value *> cttzArgs;
  cttzArgs.push_back(src_val);
  cttzArgs.push_back(CONST_V<1>(b, 0));
  auto cttz = llvm::CallInst::Create(cttzFn, cttzArgs, "", b);

  auto is_zero = new llvm::ICmpInst( *b, llvm::CmpInst::ICMP_EQ,
                                    CONST_V<width>(b, width), cttz);

  F_WRITE(b, llvm::X86::ZF, is_zero);

  // See if we write to register
  auto save_index = llvm::SelectInst::Create(is_zero,  // check if the source was zero
      src_val,  // if it was, do not change contents
      cttz,  // if it was not, set index
      "", b);

  R_WRITE<width>(b, dst.getReg(), save_index);

  return ContinueBlock;
}

GENERIC_TRANSLATION(CDQ, doCdq(block))
GENERIC_TRANSLATION(INT3, doInt3(block))
GENERIC_TRANSLATION(INT, doInt(block, OP(0)))
GENERIC_TRANSLATION(TRAP, doTrap(block))
GENERIC_TRANSLATION(NOOP, doNoop(block))
GENERIC_TRANSLATION(HLT, doHlt(block))

GENERIC_TRANSLATION(BSWAP32r, doBswapR<32>(ip, block, OP(0)))
GENERIC_TRANSLATION(BSWAP64r, doBswapR<64>(ip, block, OP(0)))

GENERIC_TRANSLATION(LAHF, doLAHF(block))
GENERIC_TRANSLATION(STD, doStd(block))
GENERIC_TRANSLATION(CLD, doCld(block))
GENERIC_TRANSLATION(STC, doStc(block))
GENERIC_TRANSLATION(CLC, doClc(block))

GENERIC_TRANSLATION_REF(LEA16r, doLea<16>(ip, block, ADDR_NOREF(1), OP(0)),
                        doLea<16>(ip, block, MEM_REFERENCE(1), OP(0)))

template<int width>
static InstTransResult doLeaRef(TranslationContext &ctx,
                                llvm::BasicBlock *&block) {
  InstTransResult ret;
  auto F = block->getParent();
  auto ip = ctx.natI;
  auto &inst = ip->get_inst();
  auto natM = ctx.natM;
  if (ip->has_code_ref()) {
    NativeInst::CFGOpType optype;

    if (ip->has_mem_reference) {
      optype = NativeInst::MEMRef;
    } else if (ip->has_imm_reference) {
      optype = NativeInst::IMMRef;
    } else {
      throw TErr(__LINE__, __FILE__, "Have code ref but no reference");
    }

    auto callback_fn = ArchAddCallbackDriver(block->getParent()->getParent(),
                                             ip->get_reference(optype));
    auto addrInt = new llvm::PtrToIntInst(
        callback_fn, llvm::Type::getIntNTy(block->getContext(), width), "",
        block);
    ret = doLeaV<width>(block, OP(0), addrInt);
  } else if (ip->has_mem_reference) {
    ret = doLea<width>(ip, block, MEM_REFERENCE(1), OP(0));
  } else if (ip->has_imm_reference) {
    ret = doLea<width>(ip, block, IMM_AS_DATA_REF<width>(block, natM, ip),
                       OP(0));
  } else {
    ret = doLea<width>(ip, block, ADDR_NOREF(1), OP(0));
  }
  return ret;
}

static InstTransResult translate_LEA32r(TranslationContext &ctx,
                                        llvm::BasicBlock *&block) {
  return doLeaRef<32>(ctx, block);
}

static InstTransResult translate_LEA64r(TranslationContext &ctx,
                                        llvm::BasicBlock *&block) {
  return doLeaRef<64>(ctx, block);
}

static InstTransResult translate_LEA64_32r(TranslationContext &ctx,
                                           llvm::BasicBlock *&block) {
  return doLeaRef<32>(ctx, block);
}

static InstTransResult translate_CPUID32(TranslationContext &ctx,
                                         llvm::BasicBlock *&block) {
  auto eax = R_READ<32>(block, llvm::X86::EAX);
  auto ecx = R_READ<32>(block, llvm::X86::ECX);

  CREATE_BLOCK(b0, block);
  CREATE_BLOCK(b1, block);
  CREATE_BLOCK(b2, block);
  CREATE_BLOCK(b4, block);
  CREATE_BLOCK(b7, block);
  CREATE_BLOCK(b11, block);
  CREATE_BLOCK(b8m, block);

  CREATE_BLOCK(bdefault, block);
  CREATE_BLOCK(bexit, block);

  CREATE_BLOCK(eax4_b0, block_b4);
  CREATE_BLOCK(eax4_b1, block_b4);
  CREATE_BLOCK(eax4_b2, block_b4);
  CREATE_BLOCK(eax4_b3, block_b4);
  CREATE_BLOCK(eax4_bdefault, block_b4);

  CREATE_BLOCK(eax11_b0, block_b11);
  CREATE_BLOCK(eax11_b1, block_b11);
  CREATE_BLOCK(eax11_bdefault, block_b11);

  auto si = llvm::SwitchInst::Create(eax, block_bdefault, 7, block);

  // 32-bit CPUID values taken by sampling from a live CPU

  // eax = 0
  R_WRITE<32>(block_b0, llvm::X86::EAX, CONST_V<32>(block, 0x0000000d));
  R_WRITE<32>(block_b0, llvm::X86::EBX, CONST_V<32>(block, 0x756e6547));
  R_WRITE<32>(block_b0, llvm::X86::ECX, CONST_V<32>(block, 0x6c65746e));
  R_WRITE<32>(block_b0, llvm::X86::EDX, CONST_V<32>(block, 0x49656e69));
  llvm::BranchInst::Create(block_bexit, block_b0);

  // eax = 1
  R_WRITE<32>(block_b1, llvm::X86::EAX, CONST_V<32>(block, 0x000306c3));
  R_WRITE<32>(block_b1, llvm::X86::EBX, CONST_V<32>(block, 0x05100800));
  R_WRITE<32>(block_b1, llvm::X86::ECX, CONST_V<32>(block, 0x7ffafbff));
  R_WRITE<32>(block_b1, llvm::X86::EDX, CONST_V<32>(block, 0xbfebfbff));
  llvm::BranchInst::Create(block_bexit, block_b1);

  // eax = 2
  R_WRITE<32>(block_b2, llvm::X86::EAX, CONST_V<32>(block, 0x76035a01));
  R_WRITE<32>(block_b2, llvm::X86::EBX, CONST_V<32>(block, 0x00f0b5ff));
  R_WRITE<32>(block_b2, llvm::X86::ECX, CONST_V<32>(block, 0x00000000));
  R_WRITE<32>(block_b2, llvm::X86::EDX, CONST_V<32>(block, 0x00c10000));
  llvm::BranchInst::Create(block_bexit, block_b2);

  llvm::SwitchInst *si_eax4 = llvm::SwitchInst::Create(ecx, block_eax4_bdefault,
                                                       4, block_b4);
  // eax = 4, ecx = 0
  R_WRITE<32>(block_eax4_b0, llvm::X86::EAX, CONST_V<32>(block, 0x1c004121));
  R_WRITE<32>(block_eax4_b0, llvm::X86::EBX, CONST_V<32>(block, 0x01c0003f));
  R_WRITE<32>(block_eax4_b0, llvm::X86::ECX, CONST_V<32>(block, 0x0000003f));
  R_WRITE<32>(block_eax4_b0, llvm::X86::EDX, CONST_V<32>(block, 0x00000000));
  llvm::BranchInst::Create(block_bexit, block_eax4_b0);

  // eax = 4, ecx = 1
  R_WRITE<32>(block_eax4_b1, llvm::X86::EAX, CONST_V<32>(block, 0x1c004122));
  R_WRITE<32>(block_eax4_b1, llvm::X86::EBX, CONST_V<32>(block, 0x01c0003f));
  R_WRITE<32>(block_eax4_b1, llvm::X86::ECX, CONST_V<32>(block, 0x0000003f));
  R_WRITE<32>(block_eax4_b1, llvm::X86::EDX, CONST_V<32>(block, 0x00000000));
  llvm::BranchInst::Create(block_bexit, block_eax4_b1);

  // eax = 4, ecx = 2
  R_WRITE<32>(block_eax4_b2, llvm::X86::EAX, CONST_V<32>(block, 0x1c004143));
  R_WRITE<32>(block_eax4_b2, llvm::X86::EBX, CONST_V<32>(block, 0x01c0003f));
  R_WRITE<32>(block_eax4_b2, llvm::X86::ECX, CONST_V<32>(block, 0x000001ff));
  R_WRITE<32>(block_eax4_b2, llvm::X86::EDX, CONST_V<32>(block, 0x00000000));
  llvm::BranchInst::Create(block_bexit, block_eax4_b2);

  // eax = 4, ecx = 3
  R_WRITE<32>(block_eax4_b3, llvm::X86::EAX, CONST_V<32>(block, 0x1c03c163));
  R_WRITE<32>(block_eax4_b3, llvm::X86::EBX, CONST_V<32>(block, 0x03c0003f));
  R_WRITE<32>(block_eax4_b3, llvm::X86::ECX, CONST_V<32>(block, 0x00000fff));
  R_WRITE<32>(block_eax4_b3, llvm::X86::EDX, CONST_V<32>(block, 0x00000006));
  llvm::BranchInst::Create(block_bexit, block_eax4_b3);

  // eax = 4, default
  doTrap(block_eax4_bdefault);

  si_eax4->addCase(CONST_V<32>(block_b4, 0), block_eax4_b0);
  si_eax4->addCase(CONST_V<32>(block_b4, 1), block_eax4_b1);
  si_eax4->addCase(CONST_V<32>(block_b4, 2), block_eax4_b2);
  si_eax4->addCase(CONST_V<32>(block_b4, 3), block_eax4_b3);

  // eax = 7
  R_WRITE<32>(block_b7, llvm::X86::EAX, CONST_V<32>(block, 0x00000000));
  R_WRITE<32>(block_b7, llvm::X86::EBX, CONST_V<32>(block, 0xffffffff));
  R_WRITE<32>(block_b7, llvm::X86::ECX, CONST_V<32>(block, 0x00000000));
  R_WRITE<32>(block_b7, llvm::X86::EDX, CONST_V<32>(block, 0x00000000));
  llvm::BranchInst::Create(block_bexit, block_b7);

  llvm::SwitchInst *si_eax11 = llvm::SwitchInst::Create(ecx,
                                                        block_eax11_bdefault, 2,
                                                        block_b11);
  // eax = 11, ecx = 0
  R_WRITE<32>(block_eax11_b0, llvm::X86::EAX, CONST_V<32>(block, 0x00000001));
  R_WRITE<32>(block_eax11_b0, llvm::X86::EBX, CONST_V<32>(block, 0x00000002));
  R_WRITE<32>(block_eax11_b0, llvm::X86::ECX, CONST_V<32>(block, 0x00000100));
  R_WRITE<32>(block_eax11_b0, llvm::X86::EDX, CONST_V<32>(block, 0x00000005));
  llvm::BranchInst::Create(block_bexit, block_eax11_b0);

  // eax = 11, ecx = 1
  R_WRITE<32>(block_eax11_b1, llvm::X86::EAX, CONST_V<32>(block, 0x00000004));
  R_WRITE<32>(block_eax11_b1, llvm::X86::EBX, CONST_V<32>(block, 0x00000004));
  R_WRITE<32>(block_eax11_b1, llvm::X86::ECX, CONST_V<32>(block, 0x00000201));
  R_WRITE<32>(block_eax11_b1, llvm::X86::EDX, CONST_V<32>(block, 0x00000003));
  llvm::BranchInst::Create(block_bexit, block_eax11_b1);

  si_eax11->addCase(CONST_V<32>(block_b11, 0), block_eax11_b0);
  si_eax11->addCase(CONST_V<32>(block_b11, 1), block_eax11_b1);

  doTrap(block_eax11_bdefault);

  // eax = 0x80000000
  R_WRITE<32>(block_b8m, llvm::X86::EAX, CONST_V<32>(block, 0x00000000));
  R_WRITE<32>(block_b8m, llvm::X86::EBX, CONST_V<32>(block, 0x00000000));
  R_WRITE<32>(block_b8m, llvm::X86::ECX, CONST_V<32>(block, 0x00000000));
  R_WRITE<32>(block_b8m, llvm::X86::EDX, CONST_V<32>(block, 0x00000000));
  llvm::BranchInst::Create(block_bexit, block_b8m);

  doTrap(block_bdefault);

  si->addCase(CONST_V<32>(block, 0), block_b0);
  si->addCase(CONST_V<32>(block, 1), block_b1);
  si->addCase(CONST_V<32>(block, 2), block_b2);
  si->addCase(CONST_V<32>(block, 4), block_b4);
  si->addCase(CONST_V<32>(block, 7), block_b7);
  si->addCase(CONST_V<32>(block, 11), block_b11);
  si->addCase(CONST_V<32>(block, 0x80000000), block_b8m);

  block = block_bexit;

  return ContinueBlock;
}

GENERIC_TRANSLATION(AAA, doAAA(block))
GENERIC_TRANSLATION(AAS, doAAS(block))
GENERIC_TRANSLATION(AAM8i8, doAAM(block))
GENERIC_TRANSLATION(AAD8i8, doAAD(block))
GENERIC_TRANSLATION(RDTSC, doRdtsc(block))
GENERIC_TRANSLATION(CWD, doCwd<16>(block))
GENERIC_TRANSLATION(CWDE, doCwd<32>(block))
GENERIC_TRANSLATION(CQO, doCwd<64>(block));

GENERIC_TRANSLATION(BT64rr, doBtrr<64>(block, OP(0), OP(1)))
GENERIC_TRANSLATION(BT32rr, doBtrr<32>(block, OP(0), OP(1)))
GENERIC_TRANSLATION(BT16rr, doBtrr<16>(block, OP(0), OP(1)))

GENERIC_TRANSLATION(BTS64rr, doBTSrr<64>(block, OP(0), OP(1)))
GENERIC_TRANSLATION(BTS32rr, doBTSrr<32>(block, OP(0), OP(1)))
GENERIC_TRANSLATION(BTS16rr, doBTSrr<16>(block, OP(0), OP(1)))

GENERIC_TRANSLATION(BT64ri8, doBtri<64>(block, OP(0), OP(1)))
GENERIC_TRANSLATION(BT32ri8, doBtri<32>(block, OP(0), OP(1)))
GENERIC_TRANSLATION(BT16ri8, doBtri<16>(block, OP(0), OP(1)))

GENERIC_TRANSLATION(BTS64ri8, doBTSri<64>(block, OP(0), OP(1)))
GENERIC_TRANSLATION(BTS32ri8, doBTSri<32>(block, OP(0), OP(1)))

GENERIC_TRANSLATION_REF(BT32mi8, doBtmi<32>(ip, block, ADDR_NOREF(0), OP(5)),
                        doBtmi<32>(ip, block, MEM_REFERENCE(0), OP(5)))

GENERIC_TRANSLATION_REF(BT64mi8, doBtmi<64>(ip, block, ADDR_NOREF(0), OP(5)),
                        doBtmi<64>(ip, block, MEM_REFERENCE(0), OP(5)))

GENERIC_TRANSLATION_REF(BT32mr, doBtmr<32>(ip, block, ADDR_NOREF(0), OP(5)),
                        doBtmr<32>(ip, block, MEM_REFERENCE(0), OP(5)))

GENERIC_TRANSLATION_REF(BT64mr, doBtmr<64>(ip, block, ADDR_NOREF(0), OP(5)),
                        doBtmr<64>(ip, block, MEM_REFERENCE(0), OP(5)))

GENERIC_TRANSLATION_REF(BTS32mr, doBTSmr<32>(ip, block, ADDR_NOREF(0), OP(5)),
                        doBTSmr<32>(ip, block, MEM_REFERENCE(0), OP(5)))

GENERIC_TRANSLATION_REF(BTS32mi8, doBTSmi<32>(ip, block, ADDR_NOREF(0), OP(5)),
                        doBTSmi<32>(ip, block, MEM_REFERENCE(0), OP(5)))

GENERIC_TRANSLATION_REF(BTS64mi8, doBTSmi<64>(ip, block, ADDR_NOREF(0), OP(5)),
                        doBTSmi<64>(ip, block, MEM_REFERENCE(0), OP(5)))

GENERIC_TRANSLATION_REF(BTS64mr, doBTSmr<64>(ip, block, ADDR_NOREF(0), OP(5)),
                        doBTSmr<64>(ip, block, MEM_REFERENCE(0), OP(5)))

GENERIC_TRANSLATION_REF(BTR32mi8, doBTRmi<32>(ip, block, ADDR_NOREF(0), OP(5)),
                        doBTRmi<32>(ip, block, MEM_REFERENCE(0), OP(5)))

GENERIC_TRANSLATION_REF(BTR64mi8, doBTRmi<64>(ip, block, ADDR_NOREF(0), OP(5)),
                        doBTRmi<64>(ip, block, MEM_REFERENCE(0), OP(5)))

GENERIC_TRANSLATION_REF(BTR32mr, doBTRmr<32>(ip, block, ADDR_NOREF(0), OP(5)),
                        doBTRmr<32>(ip, block, MEM_REFERENCE(0), OP(5)))

GENERIC_TRANSLATION_REF(BTR64mr, doBTRmr<64>(ip, block, ADDR_NOREF(0), OP(5)),
                        doBTRmr<64>(ip, block, MEM_REFERENCE(0), OP(5)))

GENERIC_TRANSLATION(BSR32rr, doBsrr<32>(block, OP(0), OP(1)))
GENERIC_TRANSLATION(BSR16rr, doBsrr<16>(block, OP(0), OP(1)))
GENERIC_TRANSLATION(BSR64rr, doBsrr<64>(block, OP(0), OP(1)))
GENERIC_TRANSLATION(BSF32rr, doBsfr<32>(block, OP(0), OP(1)))
GENERIC_TRANSLATION_REF(BSF32rm, (doBsfrm<32>(ip, block, OP(0), ADDR_NOREF(1))),
                        (doBsfrm<32>(ip, block, OP(0), MEM_REFERENCE(1))))
GENERIC_TRANSLATION(BSF16rr, doBsfr<16>(block, OP(0), OP(1)))

void Misc_populateDispatchMap(DispatchMap &m) {
  m[llvm::X86::AAA] = translate_AAA;
  m[llvm::X86::AAS] = translate_AAS;
  m[llvm::X86::AAM8i8] = translate_AAM8i8;
  m[llvm::X86::AAD8i8] = translate_AAD8i8;
  m[llvm::X86::LEA16r] = translate_LEA16r;
  m[llvm::X86::LEA32r] = translate_LEA32r;
  m[llvm::X86::LEA64_32r] = translate_LEA64_32r;
  m[llvm::X86::LEA64r] = translate_LEA64r;
  m[llvm::X86::LAHF] = translate_LAHF;
  m[llvm::X86::STD] = translate_STD;
  m[llvm::X86::CLD] = translate_CLD;
  m[llvm::X86::STC] = translate_STC;
  m[llvm::X86::CLC] = translate_CLC;
  m[llvm::X86::BSWAP32r] = translate_BSWAP32r;
  m[llvm::X86::BSWAP64r] = translate_BSWAP64r;
  m[llvm::X86::CDQ] = translate_CDQ;
  m[llvm::X86::INT3] = translate_INT3;
  m[llvm::X86::INT] = translate_INT;
  m[llvm::X86::MFENCE] = translate_NOOP;
  m[llvm::X86::NOOP] = translate_NOOP;
  m[llvm::X86::NOOPW] = translate_NOOP;
  m[llvm::X86::NOOPL] = translate_NOOP;
  m[llvm::X86::HLT] = translate_HLT;
  m[llvm::X86::LOCK_PREFIX] = translate_NOOP;
  m[llvm::X86::REP_PREFIX] = translate_NOOP;
  m[llvm::X86::REPNE_PREFIX] = translate_NOOP;
  m[llvm::X86::PAUSE] = translate_NOOP;
  m[llvm::X86::RDTSC] = translate_RDTSC;
  m[llvm::X86::CWD] = translate_CWD;
  m[llvm::X86::CWDE] = translate_CWDE;
  m[llvm::X86::CQO] = translate_CQO;
  m[llvm::X86::CDQ] = translate_CDQ;
  m[llvm::X86::SAHF] = translate_SAHF;
  m[llvm::X86::BT64rr] = translate_BT64rr;
  m[llvm::X86::BT32rr] = translate_BT32rr;
  m[llvm::X86::BT16rr] = translate_BT16rr;
  m[llvm::X86::BTS64rr] = translate_BTS64rr;
  m[llvm::X86::BTS32rr] = translate_BTS32rr;
  m[llvm::X86::BTS16rr] = translate_BTS16rr;
  m[llvm::X86::BT64ri8] = translate_BT64ri8;
  m[llvm::X86::BT32ri8] = translate_BT32ri8;
  m[llvm::X86::BT16ri8] = translate_BT16ri8;
  m[llvm::X86::BT64mi8] = translate_BT64mi8;
  m[llvm::X86::BT32mr] = translate_BT32mr;
  m[llvm::X86::BT64mr] = translate_BT64mr;
  m[llvm::X86::BTS64mr] = translate_BTS64mr;
  m[llvm::X86::BTS32mr] = translate_BTS32mr;
  m[llvm::X86::BTS64mi8] = translate_BTS64mi8;
  m[llvm::X86::BTS64ri8] = translate_BTS64ri8;
  m[llvm::X86::BTR64mi8] = translate_BTR64mi8;
  m[llvm::X86::BTR32mr] = translate_BTR32mr;
  m[llvm::X86::BTR64mr] = translate_BTR64mr;
  m[llvm::X86::BT32mi8] = translate_BT32mi8;
  m[llvm::X86::BTS32mi8] = translate_BTS32mi8;
  m[llvm::X86::BTS32ri8] = translate_BTS32ri8;
  m[llvm::X86::BTR32mi8] = translate_BTR32mi8;
  m[llvm::X86::BSR64rr] = translate_BSR64rr;
  m[llvm::X86::BSR32rr] = translate_BSR32rr;
  m[llvm::X86::BSR16rr] = translate_BSR16rr;
  m[llvm::X86::BSF32rr] = translate_BSF32rr;
  m[llvm::X86::BSF32rm] = translate_BSF32rm;
  m[llvm::X86::BSF16rr] = translate_BSF16rr;
  m[llvm::X86::TRAP] = translate_TRAP;
  m[llvm::X86::CPUID] = translate_CPUID32;
}
