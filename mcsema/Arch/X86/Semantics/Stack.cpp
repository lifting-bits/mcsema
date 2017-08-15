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
#include <llvm/IR/Attributes.h>
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
#include "mcsema/Arch/X86/Semantics/Stack.h"
#include "mcsema/Arch/X86/Semantics/MOV.h"

#include "mcsema/BC/Util.h"

#include "mcsema/CFG/Externals.h"

#define NASSERT(cond) TASSERT(cond, "")

template<int width>
static void doPushVT(NativeInstPtr ip, llvm::BasicBlock *&b, llvm::Value *v) {
  //ESP <- ESP - 4
  //Memory[ESP] = v
  if (ArchPointerSize(b->getParent()->getParent())) {
    auto oldESP = R_READ<32>(b, llvm::X86::ESP);
    auto newESP = llvm::BinaryOperator::CreateSub(oldESP,
                                                  CONST_V<32>(b, (width / 8)),
                                                  "", b);

    auto intVal = llvm::CastInst::CreatePointerCast(
        v, llvm::Type::getInt32Ty(b->getContext()), "", b);

    M_WRITE_0<width>(b, newESP, intVal);
    R_WRITE<32>(b, llvm::X86::ESP, newESP);

  } else {
    auto oldESP = R_READ<64>(b, llvm::X86::RSP);
    auto newESP = llvm::BinaryOperator::CreateSub(oldESP,
                                                  CONST_V<64>(b, (width / 8)),
                                                  "", b);
    auto intVal = llvm::CastInst::CreatePointerCast(
        v, llvm::Type::getInt64Ty(b->getContext()), "", b);

    M_WRITE_0<width>(b, newESP, intVal);
    R_WRITE<64>(b, llvm::X86::RSP, newESP);
  }
}

template<int width>
static void doPushV(NativeInstPtr ip, llvm::BasicBlock *&b, llvm::Value *v) {
  //ESP <- ESP - 4
  //Memory[ESP] = v
  auto M = b->getParent()->getParent();
  if (ArchPointerSize(M) == Pointer32) {
    auto oldESP = x86::R_READ<32>(b, llvm::X86::ESP);
    auto newESP = llvm::BinaryOperator::CreateSub(oldESP,
                                                  CONST_V<32>(b, (width / 8)),
                                                  "", b);

    M_WRITE_0<width>(b, newESP, v);
    x86::R_WRITE<32>(b, llvm::X86::ESP, newESP);
  } else {
    auto oldRSP = x86_64::R_READ<64>(b, llvm::X86::RSP);
    auto newRSP = llvm::BinaryOperator::CreateSub(oldRSP,
                                                  CONST_V<64>(b, (width / 8)),
                                                  "", b);

    M_WRITE_0<width>(b, newRSP, v);
    x86_64::R_WRITE<64>(b, llvm::X86::RSP, newRSP);
  }
}

template<int width>
static InstTransResult doPushAV(NativeInstPtr ip, llvm::BasicBlock *b) {
  // Temp := (ESP);
  // Push(EAX);
  // Push(ECX);
  // Push(EDX);
  // Push(EBX);
  // Push(Temp);
  // Push(EBP);
  // Push(ESI);
  // Push(EDI);
  auto Temp = R_READ<width>(b, llvm::X86::ESP);

  doPushV<width>(ip, b, R_READ<width>(b, llvm::X86::EAX));
  doPushV<width>(ip, b, R_READ<width>(b, llvm::X86::ECX));
  doPushV<width>(ip, b, R_READ<width>(b, llvm::X86::EDX));
  doPushV<width>(ip, b, R_READ<width>(b, llvm::X86::EBX));
  doPushV<width>(ip, b, Temp);
  doPushV<width>(ip, b, R_READ<width>(b, llvm::X86::EBP));
  doPushV<width>(ip, b, R_READ<width>(b, llvm::X86::ESI));
  doPushV<width>(ip, b, R_READ<width>(b, llvm::X86::EDI));

  return ContinueBlock;
}

namespace x86 {
static InstTransResult doEnter(NativeInstPtr ip, llvm::BasicBlock *&b,
                               const llvm::MCOperand &frameSize,
                               const llvm::MCOperand &nestingLevel) {
  auto F = b->getParent();
  NASSERT(frameSize.isImm());
  NASSERT(nestingLevel.isImm());

  auto vFrameSize = CONST_V<32>(b, frameSize.getImm());
  auto vNestingLevel = CONST_V<32>(b, nestingLevel.getImm());

  //Push EBP
  doPushV<32>(ip, b, x86::R_READ<32>(b, llvm::X86::EBP));

  //set FrameTemp equal to the current value in ESP
  auto frameTemp = x86::R_READ<32>(b, llvm::X86::ESP);

  //we'll need some blocks for -
  //  * the loop header
  //  * the loop body
  //  * the end of the loop
  auto &C = b->getContext();
  auto loopHeader = llvm::BasicBlock::Create(C, "loopHeader", F);
  auto loopBody = llvm::BasicBlock::Create(C, "loopBody", F);
  auto loopEnd = llvm::BasicBlock::Create(C, "loopEnd", F);
  auto cont = llvm::BasicBlock::Create(C, "continue", F);
  auto preLoop = llvm::BasicBlock::Create(C, "preLoop", F);
  auto loopSetup = llvm::BasicBlock::Create(C, "loopSetup", F);

  //test to see if NestingLevel is 0
  auto isNestZ = new llvm::ICmpInst( *b, llvm::CmpInst::ICMP_EQ, vNestingLevel,
                                    CONST_V<32>(b, 0));
  llvm::BranchInst::Create(cont, preLoop, isNestZ, b);

  //test to see if NestingLevel is greater than 1
  auto testRes = new llvm::ICmpInst( *preLoop, llvm::CmpInst::ICMP_UGT,
                                    vNestingLevel, CONST_V<32>(b, 1));
  llvm::BranchInst::Create(loopSetup, loopEnd, testRes, preLoop);

  //initialize i to 1
  auto i_init = CONST_V<32>(loopSetup, 1);
  llvm::BranchInst::Create(loopHeader, loopSetup);

  //the counter is a PHI instruction
  auto i = llvm::PHINode::Create(llvm::Type::getInt32Ty(F->getContext()), 2, "",
                                 loopHeader);
  i->addIncoming(i_init, loopSetup);
  //test and see if we should leave
  auto leaveLoop = new llvm::ICmpInst( *loopHeader, llvm::CmpInst::ICMP_ULT, i,
                                      vNestingLevel);
  llvm::BranchInst::Create(loopBody, loopEnd, leaveLoop, loopHeader);

  //subtract 4 from EBP
  auto oEBP = x86::R_READ<32>(loopBody, llvm::X86::EBP);
  auto nEBP = llvm::BinaryOperator::CreateSub(oEBP, CONST_V<32>(loopBody, 4),
                                              "", loopBody);
  x86::R_WRITE<32>(loopBody, llvm::X86::EBP, nEBP);
  doPushV<32>(ip, loopBody, nEBP);

  //add to the counter
  auto i_inc = llvm::BinaryOperator::CreateAdd(i, CONST_V<32>(loopBody, 1), "",
                                               loopBody);
  i->addIncoming(i_inc, loopBody);
  llvm::BranchInst::Create(loopHeader, loopBody);

  //now at the end of the loop, push the frame temp
  doPushV<32>(ip, loopEnd, frameTemp);
  llvm::BranchInst::Create(cont, loopEnd);

  //write the frame temp into EBP
  x86::R_WRITE<32>(cont, llvm::X86::EBP, frameTemp);
  //Subtract the size from ESP
  auto oESP = x86::R_READ<32>(cont, llvm::X86::ESP);
  auto nESP = llvm::BinaryOperator::CreateSub(oESP, vFrameSize, "", cont);
  x86::R_WRITE<32>(cont, llvm::X86::ESP, nESP);

  //update our caller to use the 'continue' block as the place to continue
  //sticking instructions
  b = cont;

  return ContinueBlock;
}
}

namespace x86_64 {
static InstTransResult doEnter(NativeInstPtr ip, llvm::BasicBlock *&b,
                               const llvm::MCOperand &frameSize,
                               const llvm::MCOperand &nestingLevel) {
  auto F = b->getParent();
  NASSERT(frameSize.isImm());
  NASSERT(nestingLevel.isImm());

  auto vFrameSize = CONST_V<64>(b, frameSize.getImm());
  auto vNestingLevel = CONST_V<64>(b, nestingLevel.getImm());

  //Push EBP
  doPushV<64>(ip, b, R_READ<64>(b, llvm::X86::RBP));

  //set FrameTemp equal to the current value in ESP
  auto frameTemp = R_READ<64>(b, llvm::X86::RSP);

  //we'll need some blocks for -
  //  * the loop header
  //  * the loop body
  //  * the end of the loop
  auto &C = b->getContext();
  auto loopHeader = llvm::BasicBlock::Create(C, "loopHeader", F);
  auto loopBody = llvm::BasicBlock::Create(C, "loopBody", F);
  auto loopEnd = llvm::BasicBlock::Create(C, "loopEnd", F);
  auto cont = llvm::BasicBlock::Create(C, "continue", F);
  auto preLoop = llvm::BasicBlock::Create(C, "preLoop", F);
  auto loopSetup = llvm::BasicBlock::Create(C, "loopSetup", F);

  //test to see if NestingLevel is 0
  auto isNestZ = new llvm::ICmpInst( *b, llvm::CmpInst::ICMP_EQ, vNestingLevel,
                                    CONST_V<64>(b, 0));

  llvm::BranchInst::Create(cont, preLoop, isNestZ, b);

  //test to see if NestingLevel is greater than 1
  auto testRes = new llvm::ICmpInst( *preLoop, llvm::CmpInst::ICMP_UGT,
                                    vNestingLevel, CONST_V<64>(b, 1));
  llvm::BranchInst::Create(loopSetup, loopEnd, testRes, preLoop);

  //initialize i to 1
  auto i_init = CONST_V<64>(loopSetup, 1);
  llvm::BranchInst::Create(loopHeader, loopSetup);

  //the counter is a PHI instruction
  auto i = llvm::PHINode::Create(llvm::Type::getInt64Ty(F->getContext()), 2, "",
                                 loopHeader);
  i->addIncoming(i_init, loopSetup);
  //test and see if we should leave
  auto leaveLoop = new llvm::ICmpInst( *loopHeader, llvm::CmpInst::ICMP_ULT, i,
                                      vNestingLevel);
  llvm::BranchInst::Create(loopBody, loopEnd, leaveLoop, loopHeader);

  //subtract 8 from EBP
  auto oEBP = R_READ<64>(loopBody, llvm::X86::RBP);
  auto nEBP = llvm::BinaryOperator::CreateSub(oEBP, CONST_V<64>(loopBody, 8),
                                              "", loopBody);
  R_WRITE<64>(loopBody, llvm::X86::RBP, nEBP);
  doPushV<64>(ip, loopBody, nEBP);

  //add to the counter
  auto i_inc = llvm::BinaryOperator::CreateAdd(i, CONST_V<64>(loopBody, 1), "",
                                               loopBody);
  i->addIncoming(i_inc, loopBody);
  llvm::BranchInst::Create(loopHeader, loopBody);

  //now at the end of the loop, push the frame temp
  doPushV<64>(ip, loopEnd, frameTemp);
  llvm::BranchInst::Create(cont, loopEnd);

  //write the frame temp into EBP
  R_WRITE<64>(cont, llvm::X86::RBP, frameTemp);
  //Subtract the size from ESP
  auto oESP = R_READ<64>(cont, llvm::X86::RSP);
  auto nESP = llvm::BinaryOperator::CreateSub(oESP, vFrameSize, "", cont);
  R_WRITE<64>(cont, llvm::X86::RSP, nESP);
  //update our caller to use the 'continue' block as the place to continue
  //sticking instructions
  b = cont;

  return ContinueBlock;
}
}

static InstTransResult doEnter(NativeInstPtr ip, llvm::BasicBlock *&b,
                               const llvm::MCOperand &frameSize,
                               const llvm::MCOperand &nestingLevel) {
  auto M = b->getParent()->getParent();
  if (ArchPointerSize(M) == Pointer32) {
    return x86::doEnter(ip, b, frameSize, nestingLevel);
  } else {
    return x86_64::doEnter(ip, b, frameSize, nestingLevel);
  }
}

static InstTransResult doLeave(NativeInstPtr ip, llvm::BasicBlock *b) {
  // LEAVE
  auto M = b->getParent()->getParent();

  if (ArchPointerSize(M) == Pointer32) {
    // read EBP
    auto link_pointer = x86::R_READ<32>(b, llvm::X86::EBP);
    auto base_pointer = M_READ<32>(ip, b, link_pointer);
    R_WRITE<32>(b, llvm::X86::EBP, base_pointer);

    //write this to ESP
    R_WRITE<32>(
        b,
        llvm::X86::ESP,
        llvm::BinaryOperator::Create(llvm::Instruction::Add, link_pointer,
                                     CONST_V<32>(b, 4), "", b));

  } else {
    auto link_pointer = x86::R_READ<64>(b, llvm::X86::RBP);
    auto base_pointer = M_READ<64>(ip, b, link_pointer);
    R_WRITE<64>(b, llvm::X86::RBP, base_pointer);

    //write this to ESP
    R_WRITE<64>(
        b,
        llvm::X86::RSP,
        llvm::BinaryOperator::Create(llvm::Instruction::Add, link_pointer,
                                     CONST_V<64>(b, 8), "", b));
  }

  return ContinueBlock;
}

static InstTransResult doLeave64(NativeInstPtr ip, llvm::BasicBlock *b) {
  // LEAVE

  // read RBP
  auto vRBP = x86_64::R_READ<64>(b, llvm::X86::RBP);

  //write this to RSP
  x86_64::R_WRITE<64>(b, llvm::X86::RSP, vRBP);

  //do a pop into EBP
  //read from memory at the top of the stack
  auto vRSP = x86_64::R_READ<64>(b, llvm::X86::RSP);
  auto atTop = M_READ<64>(ip, b, vRSP);

  //write this value into EBP
  x86_64::R_WRITE<64>(b, llvm::X86::RBP, atTop);

  //add 8 to the stack pointer
  auto updt = llvm::BinaryOperator::CreateAdd(vRSP, CONST_V<64>(b, 8), "", b);
  x86_64::R_WRITE<64>(b, llvm::X86::RSP, updt);

  return ContinueBlock;
}

template<int width>
static InstTransResult doPopR(NativeInstPtr ip, llvm::BasicBlock *&b,
                              const llvm::MCOperand &dst) {
  NASSERT(dst.isReg());
  auto M = b->getParent()->getParent();

  //read the stack pointer
  llvm::Value *oldRSP = nullptr;

  if (ArchPointerSize(M) == Pointer32) {
    oldRSP = x86::R_READ<32>(b, llvm::X86::ESP);
  } else {
    oldRSP = x86_64::R_READ<64>(b, llvm::X86::RSP);
  }

  //read the value from the memory at the stack pointer address
  auto m = M_READ_0<width>(b, oldRSP);

  //write that value into dst
  R_WRITE<width>(b, dst.getReg(), m);

  //add to the stack pointer
  if (ArchPointerSize(M) == Pointer32) {
    auto newESP = llvm::BinaryOperator::CreateAdd(oldRSP,
                                                  CONST_V<32>(b, (width / 8)),
                                                  "", b);

    //update the stack pointer register
    x86::R_WRITE<32>(b, llvm::X86::ESP, newESP);
  } else {
    auto newRSP = llvm::BinaryOperator::CreateAdd(oldRSP,
                                                  CONST_V<64>(b, (width / 8)),
                                                  "", b);

    //update the stack pointer register
    x86_64::R_WRITE<64>(b, llvm::X86::RSP, newRSP);
  }

  return ContinueBlock;
}

template<int width>
static llvm::Value *doPopV(llvm::BasicBlock *b) {
  //read the stack pointer
  auto xsp = 32 == width ? llvm::X86::ESP : llvm::X86::RSP;
  auto oldESP = R_READ<width>(b, xsp);

  //read the value from the memory at the stack pointer address,
  //and throw it away
  auto m = INTERNAL_M_READ(width, 0, b, oldESP);
  NASSERT(m != nullptr);

  //add to the stack pointer
  auto newESP = llvm::BinaryOperator::CreateAdd(oldESP,
                                                CONST_V<width>(b, (width / 8)),
                                                "", b);

  //update the stack pointer register
  R_WRITE<width>(b, xsp, newESP);

  return m;
}

template<int width>
static InstTransResult doPopAV(NativeInstPtr ip, llvm::BasicBlock *b) {
  // EDI := Pop();
  // ESI := Pop();
  // EBP := Pop();
  // throwaway := Pop (); (* Skip ESP *)
  // EBX := Pop();
  // EDX := Pop();
  // ECX := Pop();
  // EAX := Pop();

  doPopR<width>(ip, b, llvm::MCOperand::createReg(llvm::X86::EDI));
  doPopR<width>(ip, b, llvm::MCOperand::createReg(llvm::X86::ESI));
  doPopR<width>(ip, b, llvm::MCOperand::createReg(llvm::X86::EBP));
  doPopV<width>(b);
  doPopR<width>(ip, b, llvm::MCOperand::createReg(llvm::X86::EBX));
  doPopR<width>(ip, b, llvm::MCOperand::createReg(llvm::X86::EDX));
  doPopR<width>(ip, b, llvm::MCOperand::createReg(llvm::X86::ECX));
  doPopR<width>(ip, b, llvm::MCOperand::createReg(llvm::X86::EAX));

  return ContinueBlock;
}

template<int width>
static InstTransResult doPushR(NativeInstPtr ip, llvm::BasicBlock *&b,
                               const llvm::MCOperand &src) {
  //PUSH <r>
  NASSERT(src.isReg());

  //first, read from <r> into a temp
  auto TMP = R_READ<width>(b, src.getReg());

  doPushV<width>(ip, b, TMP);

  return ContinueBlock;
}

template<int width>
static InstTransResult doPushI(NativeInstPtr ip, llvm::BasicBlock *&b,
                               const llvm::MCOperand &src) {
  // PUSH <imm>
  NASSERT(src.isImm());

  auto OrigIMM = CONST_V<width>(b, src.getImm());
  // PUSHi32 and PUSHi16 will never be extended
  // in IA32
  llvm::Value *SExt_Val = OrigIMM;

  // PUSHi8 is extended to operand size, which is 32 or 64
  if (width == 8) {
    if (ArchPointerSize(M) == Pointer32) {
    SExt_Val = new llvm::SExtInst(OrigIMM,
                                  llvm::Type::getInt32Ty(b->getContext()), "",
                                  b);
    doPushV<32>(ip, b, SExt_Val);
    } else { //Pointer64
      SExt_Val = new llvm::SExtInst(OrigIMM,
                                  llvm::Type::getInt64Ty(b->getContext()), "",
                                  b);
    doPushV<64>(ip, b, SExt_Val);
    }
  } else {
    if (width == 32 && ip->has_ext_call_target()) {
      std::string target = ip->get_ext_call_target()->getSymbolName();
      auto M = b->getParent()->getParent();
      auto externFunction = M->getFunction(target);
      NASSERT(externFunction != nullptr);
      doPushVT<width>(ip, b, externFunction);
    } else {
      doPushV<width>(ip, b, SExt_Val);
    }
  }

  return ContinueBlock;
}

template<int width>
static InstTransResult doPopM(NativeInstPtr ip, llvm::BasicBlock *&b,
                              llvm::Value *addr) {
  NASSERT(addr != nullptr);

  auto xsp = 32 == width ? llvm::X86::ESP : llvm::X86::RSP;
  //read the stack pointer
  auto oldESP = R_READ<width>(b, xsp);

  //read the value from the memory at the stack pointer address
  auto m = M_READ_0<width>(b, oldESP);

  //write that value into dst
  M_WRITE<width>(ip, b, addr, m);

  //add to the stack pointer
  auto newESP = llvm::BinaryOperator::CreateAdd(oldESP,
                                                CONST_V<width>(b, (width / 8)),
                                                "", b);

  //update the stack pointer register
  R_WRITE<32>(b, xsp, newESP);

  return ContinueBlock;
}

template<int width>
static InstTransResult doPushRMM(NativeInstPtr ip, llvm::BasicBlock *&b,
                                 llvm::Value *addr) {
  NASSERT(addr != nullptr);

  auto fromMem = M_READ<width>(ip, b, addr);
  doPushV<width>(ip, b, fromMem);

  return ContinueBlock;
}

static InstTransResult translate_PUSH32rmm(TranslationContext &ctx,
                                           llvm::BasicBlock *&block) {
  InstTransResult ret;
  auto natM = ctx.natM;
  auto ip = ctx.natI;
  auto &inst = ip->get_inst();
  auto F = block->getParent();

  if (ip->has_external_ref()) {
    auto addrInt = getValueForExternal<32>(F->getParent(), ip, block);
    TASSERT(addrInt != nullptr, "Could not get address for external");
    doPushV<32>(ip, block, addrInt);
    return ContinueBlock;
  } else if (ip->has_mem_reference) {
    ret = doPushRMM<32>(ip, block, MEM_AS_DATA_REF(block, natM, inst, ip, 0));
  } else {
    ret = doPushRMM<32>(ip, block, ADDR_NOREF(0));
  }
  return ret;
}

static InstTransResult translate_PUSH64rmm(TranslationContext &ctx,
                                           llvm::BasicBlock *&block) {
  InstTransResult ret;
  auto natM = ctx.natM;
  auto ip = ctx.natI;
  auto &inst = ip->get_inst();
  auto F = block->getParent();

  if (ip->has_external_ref()) {
    auto addrInt = getValueForExternal<64>(F->getParent(), ip, block);
    TASSERT(addrInt != nullptr, "Could not get address for external");
    doPushV<64>(ip, block, addrInt);
    return ContinueBlock;
  } else if (ip->has_mem_reference) {
    ret = doPushRMM<64>(ip, block, MEM_AS_DATA_REF(block, natM, inst, ip, 0));
  } else {
    ret = doPushRMM<64>(ip, block, ADDR_NOREF(0));
  }
  return ret;
}

static InstTransResult translate_PUSHi32(TranslationContext &ctx,
                                         llvm::BasicBlock *&block) {
  InstTransResult ret;
  auto natM = ctx.natM;
  auto ip = ctx.natI;
  auto &inst = ip->get_inst();
  auto F = block->getParent();
  if (ip->has_code_ref()) {
    auto callback_fn = ArchAddCallbackDriver(
        block->getParent()->getParent(), ip->get_reference(NativeInst::IMMRef));
    auto addrInt = new llvm::PtrToIntInst(
        callback_fn, llvm::Type::getInt32Ty(block->getContext()), "", block);
    doPushV<32>(ip, block, addrInt);
    ret = ContinueBlock;
  } else if (ip->has_imm_reference) {
    auto M = F->getParent();
    auto ref = IMM_AS_DATA_REF(block, natM, ip);

    // this may fail catastrophically, but we can only push those 32-bits
    // or we break the stack
    if (Pointer64 == ArchPointerSize(M)) {
      ref = new llvm::TruncInst(ref,
                                llvm::Type::getInt32Ty(block->getContext()), "",
                                block);
    }

    doPushV<32>(ip, block, ref);
    ret = ContinueBlock;
  } else {
    ret = doPushI<32>(ip, block, OP(0));
  }
  return ret;
}

#define EMIT_SHL_OR(destval, inval, shiftcount) do {\
    auto tmp = llvm::BinaryOperator::CreateShl(inval, CONST_V<width>(b, shiftcount), "", b); \
    destval = llvm::BinaryOperator::CreateOr(destval, tmp, "", b); \
    } while (0)

#define EMIT_SHR_AND(destval, inval, shiftcount) do {\
    auto tmp = llvm::BinaryOperator::CreateLShr(inval, CONST_V<width>(b, shiftcount), "", b); \
    destval = llvm::BinaryOperator::CreateAnd(destval, tmp, "", b); \
    } while (0)

template<int width>
static llvm::Value *checkIfBitSet(llvm::Value *field, int bit,
                                  llvm::BasicBlock *b) {

  auto tmp = llvm::BinaryOperator::CreateAnd(field, CONST_V<width>(b, 1 << bit),
                                             "", b);
  return new llvm::ICmpInst( *b, llvm::CmpInst::ICMP_NE, tmp,
                            CONST_V<width>(b, 0));
}

template<int width>
static InstTransResult doPopF(NativeInstPtr ip, llvm::BasicBlock *b) {
  auto newFlags = doPopV<width>(b);

  // bit 0: CF
  F_WRITE(b, llvm::X86::CF, checkIfBitSet<width>(newFlags, 0, b));
  // bit 1: 1 (reserved)
  // bit 2: PF
  F_WRITE(b, llvm::X86::PF, checkIfBitSet<width>(newFlags, 2, b));
  // bit 3: 0
  // bit 4: AF
  F_WRITE(b, llvm::X86::AF, checkIfBitSet<width>(newFlags, 4, b));
  // bit 5: 0
  // bit 6: ZF
  F_WRITE(b, llvm::X86::ZF, checkIfBitSet<width>(newFlags, 6, b));
  // bit 7: SF
  F_WRITE(b, llvm::X86::SF, checkIfBitSet<width>(newFlags, 7, b));
  // bit 8: TF (set to zero)
  // bit 9: IF (set to 1)
  // bit 10: DF
  F_WRITE(b, llvm::X86::DF, checkIfBitSet<width>(newFlags, 10, b));
  // bit 11: OF
  F_WRITE(b, llvm::X86::OF, checkIfBitSet<width>(newFlags, 11, b));

  return ContinueBlock;

}

template<int width>
static InstTransResult doPushF(NativeInstPtr ip, llvm::BasicBlock *b) {

  // put eflags into one value.
  //
  auto toT = llvm::Type::getIntNTy(b->getContext(), width);

  auto cf = new llvm::ZExtInst(F_READ(b, llvm::X86::CF), toT, "", b);
  auto pf = new llvm::ZExtInst(F_READ(b, llvm::X86::PF), toT, "", b);
  auto af = new llvm::ZExtInst(F_READ(b, llvm::X86::AF), toT, "", b);
  auto zf = new llvm::ZExtInst(F_READ(b, llvm::X86::ZF), toT, "", b);
  auto sf = new llvm::ZExtInst(F_READ(b, llvm::X86::SF), toT, "", b);
  auto df = new llvm::ZExtInst(F_READ(b, llvm::X86::DF), toT, "", b);
  auto of = new llvm::ZExtInst(F_READ(b, llvm::X86::OF), toT, "", b);

  auto eflags_base = CONST_V<width>(b, 0x202);

  // bit 0: CF
  auto cur_flags = llvm::BinaryOperator::CreateOr(eflags_base, cf, "", b);
  // bit 1: 1 (reserved)
  // bit 2: PF
  EMIT_SHL_OR(cur_flags, pf, 2);
  // bit 3: 0
  // bit 4: AF
  EMIT_SHL_OR(cur_flags, af, 4);
  // bit 5: 0
  // bit 6: ZF
  EMIT_SHL_OR(cur_flags, zf, 6);
  // bit 7: SF
  EMIT_SHL_OR(cur_flags, sf, 7);
  // bit 8: TF (set to zero)
  // bit 9: IF (set to 1)
  // bit 10: DF
  EMIT_SHL_OR(cur_flags, df, 10);
  // bit 11: OF
  EMIT_SHL_OR(cur_flags, of, 11);
  // rest set to 0
  //
  // push on stack
  doPushV<width>(ip, b, cur_flags);

  return ContinueBlock;
}

GENERIC_TRANSLATION(PUSHF64, doPushF<64>(ip, block))
GENERIC_TRANSLATION(PUSHF32, doPushF<32>(ip, block))
GENERIC_TRANSLATION(POPF64, doPopF<64>(ip, block))
GENERIC_TRANSLATION(POPF32, doPopF<32>(ip, block))
//GENERIC_TRANSLATION(PUSHF16, doPushF<16>(ip, block))
GENERIC_TRANSLATION(ENTER, doEnter(ip, block, OP(0), OP(1)))
GENERIC_TRANSLATION(LEAVE, doLeave(ip, block))
GENERIC_TRANSLATION(LEAVE64, doLeave64(ip, block))
GENERIC_TRANSLATION(POP16r, doPopR<16>(ip, block, OP(0)))
GENERIC_TRANSLATION(POP32r, doPopR<32>(ip, block, OP(0)))

GENERIC_TRANSLATION(POP64r, doPopR<64>(ip, block, OP(0)))

GENERIC_TRANSLATION(PUSH16r, doPushR<16>(ip, block, OP(0)))
GENERIC_TRANSLATION(PUSH32r, doPushR<32>(ip, block, OP(0)))
GENERIC_TRANSLATION(PUSH64r, doPushR<64>(ip, block, OP(0)))
GENERIC_TRANSLATION(POPA32, doPopAV<32>(ip, block));
GENERIC_TRANSLATION(PUSHA32, doPushAV<32>(ip, block));
//GENERIC_TRANSLATION_REF(PUSH32rmm,
//        doPushRMM<32>(ip, block, ADDR_NOREF(0)),
//        doPushRMM<32>(ip, block, MEM_REFERENCE(0)));
GENERIC_TRANSLATION_REF(PUSHi8, doPushI<8>(ip, block, OP(0)),
                        doPushV<8>(ip, block, MEM_REFERENCE(0) ))
GENERIC_TRANSLATION_REF(PUSHi16, doPushI<16>(ip, block, OP(0)),
                        doPushV<16>(ip, block, MEM_REFERENCE(0) ))
GENERIC_TRANSLATION_REF(POP32rmm, doPopM<32>(ip, block, ADDR_NOREF(0)),
                        doPopM<32>(ip, block, MEM_REFERENCE(0)));
GENERIC_TRANSLATION_REF(POP64rmm, doPopM<64>(ip, block, ADDR_NOREF(0)),
                        doPopM<32>(ip, block, MEM_REFERENCE(0)));

void Stack_populateDispatchMap(DispatchMap &m) {
  m[llvm::X86::ENTER] = translate_ENTER;
  m[llvm::X86::LEAVE] = translate_LEAVE;
  m[llvm::X86::LEAVE64] = translate_LEAVE64;
  m[llvm::X86::POP16r] = translate_POP16r;
  m[llvm::X86::POP32r] = translate_POP32r;
  m[llvm::X86::PUSH16r] = translate_PUSH16r;
  m[llvm::X86::PUSH32r] = translate_PUSH32r;
  m[llvm::X86::PUSH32i8] = translate_PUSHi8;
  m[llvm::X86::PUSHi16] = translate_PUSHi16;
  m[llvm::X86::PUSHi32] = translate_PUSHi32;
  m[llvm::X86::PUSH32rmm] = translate_PUSH32rmm;
  m[llvm::X86::POPA32] = translate_POPA32;
  m[llvm::X86::PUSHA32] = translate_PUSHA32;
  m[llvm::X86::PUSHF32] = translate_PUSHF32;
  m[llvm::X86::PUSHF64] = translate_PUSHF64;
  m[llvm::X86::POP32rmm] = translate_POP32rmm;

  m[llvm::X86::PUSH64r] = translate_PUSH64r;
  m[llvm::X86::PUSH64rmr] = translate_PUSH64r;  // TODO(pag): Is this right??
  m[llvm::X86::PUSH64rmm] = translate_PUSH64rmm;
  m[llvm::X86::PUSH64i8] = translate_PUSHi8;
  m[llvm::X86::PUSH64i32] = translate_PUSHi32;

  m[llvm::X86::POP64r] = translate_POP64r;
  m[llvm::X86::POP64rmm] = translate_POP64rmm;
  m[llvm::X86::POPF64] = translate_POPF64;
  m[llvm::X86::POPF32] = translate_POPF32;
}
