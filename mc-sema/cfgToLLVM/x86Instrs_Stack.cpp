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
#include "InstructionDispatch.h"
#include "toLLVM.h"
#include "X86.h"
#include "raiseX86.h"
#include "x86Instrs_Stack.h"
#include "x86Instrs_MOV.h"
#include "x86Helpers.h"
#include "Externals.h"
#include "ArchOps.h"
#include <llvm/IR/Attributes.h>
#include "llvm/Support/Debug.h"
#include <iostream>

#define NASSERT(cond) TASSERT(cond, "")

using namespace llvm;

template<int width>
static void doPushVT(InstPtr ip, BasicBlock *&b, Value *v) {
  //ESP <- ESP - 4
  //Memory[ESP] = v
  if (ArchPointerSize(b->getParent()->getParent())) {
    Value *oldESP = R_READ<32>(b, X86::ESP);
    Value *newESP = BinaryOperator::CreateSub(oldESP,
                                              CONST_V<32>(b, (width / 8)), "",
                                              b);

    Value *intVal = CastInst::CreatePointerCast(
        v, Type::getInt32Ty(b->getContext()), "", b);

    M_WRITE_0<width>(b, newESP, intVal);
    R_WRITE<32>(b, X86::ESP, newESP);
  } else {

    Value *oldESP = R_READ<64>(b, X86::RSP);
    Value *newESP = BinaryOperator::CreateSub(oldESP,
                                              CONST_V<64>(b, (width / 8)), "",
                                              b);

    Value *intVal = CastInst::CreatePointerCast(
        v, Type::getInt64Ty(b->getContext()), "", b);

    M_WRITE_0<width>(b, newESP, intVal);
    R_WRITE<64>(b, X86::RSP, newESP);
  }

  return;
}

template<int width>
static void doPushV(InstPtr ip, BasicBlock *&b, Value *v) {
  //ESP <- ESP - 4
  //Memory[ESP] = v
  llvm::Module *M = b->getParent()->getParent();
  if (ArchPointerSize(M) == Pointer32) {
    Value *oldESP = x86::R_READ<32>(b, X86::ESP);
    Value *newESP = BinaryOperator::CreateSub(oldESP,
                                              CONST_V<32>(b, (width / 8)), "",
                                              b);

    M_WRITE_0<width>(b, newESP, v);
    x86::R_WRITE<32>(b, X86::ESP, newESP);
  } else {
    Value *oldRSP = x86_64::R_READ<64>(b, X86::RSP);
    Value *newRSP = BinaryOperator::CreateSub(oldRSP,
                                              CONST_V<64>(b, (width / 8)), "",
                                              b);

    M_WRITE_0<width>(b, newRSP, v);
    x86_64::R_WRITE<64>(b, X86::RSP, newRSP);
  }

  return;
}

template<int width>
static InstTransResult doPushAV(InstPtr ip, BasicBlock *b) {
  // Temp := (ESP);
  // Push(EAX);
  // Push(ECX);
  // Push(EDX);
  // Push(EBX);
  // Push(Temp);
  // Push(EBP);
  // Push(ESI);
  // Push(EDI);
  Value *Temp = R_READ<width>(b, X86::ESP);

  doPushV<width>(ip, b, R_READ<width>(b, X86::EAX));
  doPushV<width>(ip, b, R_READ<width>(b, X86::ECX));
  doPushV<width>(ip, b, R_READ<width>(b, X86::EDX));
  doPushV<width>(ip, b, R_READ<width>(b, X86::EBX));
  doPushV<width>(ip, b, Temp);
  doPushV<width>(ip, b, R_READ<width>(b, X86::EBP));
  doPushV<width>(ip, b, R_READ<width>(b, X86::ESI));
  doPushV<width>(ip, b, R_READ<width>(b, X86::EDI));

  return ContinueBlock;
}

namespace x86 {
static InstTransResult doEnter(InstPtr ip, BasicBlock *&b,
                               const MCOperand &frameSize,
                               const MCOperand &nestingLevel) {
  Function *F = b->getParent();
  NASSERT(frameSize.isImm());
  NASSERT(nestingLevel.isImm());

  Value *vFrameSize = CONST_V<32>(b, frameSize.getImm());
  Value *vNestingLevel = CONST_V<32>(b, nestingLevel.getImm());

  //Push EBP
  doPushV<32>(ip, b, x86::R_READ<32>(b, X86::EBP));

  //set FrameTemp equal to the current value in ESP
  Value *frameTemp = x86::R_READ<32>(b, X86::ESP);

  //we'll need some blocks for -
  //  * the loop header
  //  * the loop body
  //  * the end of the loop
  BasicBlock *loopHeader = BasicBlock::Create(b->getContext(), "loopHeader", F);
  BasicBlock *loopBody = BasicBlock::Create(b->getContext(), "loopBody", F);
  BasicBlock *loopEnd = BasicBlock::Create(b->getContext(), "loopEnd", F);
  BasicBlock *cont = BasicBlock::Create(b->getContext(), "continue", F);
  BasicBlock *preLoop = BasicBlock::Create(b->getContext(), "preLoop", F);
  BasicBlock *loopSetup = BasicBlock::Create(b->getContext(), "loopSetup", F);

  //test to see if NestingLevel is 0
  Value *isNestZ = new ICmpInst( *b, CmpInst::ICMP_EQ, vNestingLevel,
                                CONST_V<32>(b, 0));
  BranchInst::Create(cont, preLoop, isNestZ, b);

  //test to see if NestingLevel is greater than 1
  Value *testRes = new ICmpInst( *preLoop, CmpInst::ICMP_UGT, vNestingLevel,
                                CONST_V<32>(b, 1));
  BranchInst::Create(loopSetup, loopEnd, testRes, preLoop);

  //initialize i to 1
  Value *i_init = CONST_V<32>(loopSetup, 1);
  BranchInst::Create(loopHeader, loopSetup);

  //the counter is a PHI instruction
  PHINode *i = PHINode::Create(Type::getInt32Ty(F->getContext()), 2, "",
                               loopHeader);
  i->addIncoming(i_init, loopSetup);
  //test and see if we should leave
  Value *leaveLoop = new ICmpInst( *loopHeader, CmpInst::ICMP_ULT, i,
                                  vNestingLevel);
  BranchInst::Create(loopBody, loopEnd, leaveLoop, loopHeader);

  //subtract 4 from EBP
  Value *oEBP = x86::R_READ<32>(loopBody, X86::EBP);
  Value *nEBP = BinaryOperator::CreateSub(oEBP, CONST_V<32>(loopBody, 4), "",
                                          loopBody);
  x86::R_WRITE<32>(loopBody, X86::EBP, nEBP);
  doPushV<32>(ip, loopBody, nEBP);

  //add to the counter
  Value *i_inc = BinaryOperator::CreateAdd(i, CONST_V<32>(loopBody, 1), "",
                                           loopBody);
  i->addIncoming(i_inc, loopBody);
  BranchInst::Create(loopHeader, loopBody);

  //now at the end of the loop, push the frame temp
  doPushV<32>(ip, loopEnd, frameTemp);
  BranchInst::Create(cont, loopEnd);

  //write the frame temp into EBP
  x86::R_WRITE<32>(cont, X86::EBP, frameTemp);
  //Subtract the size from ESP
  Value *oESP = x86::R_READ<32>(cont, X86::ESP);
  Value *nESP = BinaryOperator::CreateSub(oESP, vFrameSize, "", cont);
  x86::R_WRITE<32>(cont, X86::ESP, nESP);

  //update our caller to use the 'continue' block as the place to continue
  //sticking instructions
  b = cont;

  return ContinueBlock;
}
}

namespace x86_64 {
static InstTransResult doEnter(InstPtr ip, BasicBlock *&b,
                               const MCOperand &frameSize,
                               const MCOperand &nestingLevel) {
  Function *F = b->getParent();
  NASSERT(frameSize.isImm());
  NASSERT(nestingLevel.isImm());

  Value *vFrameSize = CONST_V<64>(b, frameSize.getImm());
  Value *vNestingLevel = CONST_V<64>(b, nestingLevel.getImm());

  //Push EBP
  doPushV<64>(ip, b, R_READ<64>(b, X86::RBP));

  //set FrameTemp equal to the current value in ESP
  Value *frameTemp = R_READ<64>(b, X86::RSP);

  //we'll need some blocks for -
  //  * the loop header
  //  * the loop body
  //  * the end of the loop
  BasicBlock *loopHeader = BasicBlock::Create(b->getContext(), "loopHeader", F);
  BasicBlock *loopBody = BasicBlock::Create(b->getContext(), "loopBody", F);
  BasicBlock *loopEnd = BasicBlock::Create(b->getContext(), "loopEnd", F);
  BasicBlock *cont = BasicBlock::Create(b->getContext(), "continue", F);
  BasicBlock *preLoop = BasicBlock::Create(b->getContext(), "preLoop", F);
  BasicBlock *loopSetup = BasicBlock::Create(b->getContext(), "loopSetup", F);

  //test to see if NestingLevel is 0
  Value *isNestZ = new ICmpInst( *b, CmpInst::ICMP_EQ, vNestingLevel,
                                CONST_V<64>(b, 0));

  BranchInst::Create(cont, preLoop, isNestZ, b);

  //test to see if NestingLevel is greater than 1
  Value *testRes = new ICmpInst( *preLoop, CmpInst::ICMP_UGT, vNestingLevel,
                                CONST_V<64>(b, 1));
  BranchInst::Create(loopSetup, loopEnd, testRes, preLoop);

  //initialize i to 1
  Value *i_init = CONST_V<64>(loopSetup, 1);
  BranchInst::Create(loopHeader, loopSetup);

  //the counter is a PHI instruction
  PHINode *i = PHINode::Create(Type::getInt64Ty(F->getContext()), 2, "",
                               loopHeader);
  i->addIncoming(i_init, loopSetup);
  //test and see if we should leave
  Value *leaveLoop = new ICmpInst( *loopHeader, CmpInst::ICMP_ULT, i,
                                  vNestingLevel);
  BranchInst::Create(loopBody, loopEnd, leaveLoop, loopHeader);

  //subtract 8 from EBP
  Value *oEBP = R_READ<64>(loopBody, X86::RBP);
  Value *nEBP = BinaryOperator::CreateSub(oEBP, CONST_V<64>(loopBody, 8), "",
                                          loopBody);
  R_WRITE<64>(loopBody, X86::RBP, nEBP);
  doPushV<64>(ip, loopBody, nEBP);

  //add to the counter
  Value *i_inc = BinaryOperator::CreateAdd(i, CONST_V<64>(loopBody, 1), "",
                                           loopBody);
  i->addIncoming(i_inc, loopBody);
  BranchInst::Create(loopHeader, loopBody);

  //now at the end of the loop, push the frame temp
  doPushV<64>(ip, loopEnd, frameTemp);
  BranchInst::Create(cont, loopEnd);

  //write the frame temp into EBP
  R_WRITE<64>(cont, X86::RBP, frameTemp);
  //Subtract the size from ESP
  Value *oESP = R_READ<64>(cont, X86::RSP);
  Value *nESP = BinaryOperator::CreateSub(oESP, vFrameSize, "", cont);
  R_WRITE<64>(cont, X86::RSP, nESP);
  //update our caller to use the 'continue' block as the place to continue
  //sticking instructions
  b = cont;

  return ContinueBlock;
}
}

static InstTransResult doEnter(InstPtr ip, BasicBlock *&b,
                               const MCOperand &frameSize,
                               const MCOperand &nestingLevel) {
  llvm::Module *M = b->getParent()->getParent();
  if (ArchPointerSize(M) == Pointer32) {
    return x86::doEnter(ip, b, frameSize, nestingLevel);
  } else {
    return x86_64::doEnter(ip, b, frameSize, nestingLevel);
  }
}

static InstTransResult doLeave(InstPtr ip, BasicBlock *b) {
  // LEAVE
  llvm::Module *M = b->getParent()->getParent();

  if (ArchPointerSize(M) == Pointer32) {
    // read EBP
    Value *link_pointer = x86::R_READ<32>(b, X86::EBP);
    Value *base_pointer = M_READ<32>(ip, b, link_pointer);
    R_WRITE<32>(b, X86::EBP, base_pointer);

    //write this to ESP
    R_WRITE<32>(
        b,
        X86::ESP,
        llvm::BinaryOperator::Create(Instruction::Add, link_pointer,
                                     CONST_V<32>(b, 4), "", b));

  } else {
    Value *link_pointer = x86::R_READ<64>(b, X86::RBP);
    Value *base_pointer = M_READ<64>(ip, b, link_pointer);
    R_WRITE<64>(b, X86::RBP, base_pointer);

    //write this to ESP
    R_WRITE<64>(
        b,
        X86::RSP,
        llvm::BinaryOperator::Create(Instruction::Add, link_pointer,
                                     CONST_V<64>(b, 8), "", b));
  }

  return ContinueBlock;
}

static InstTransResult doLeave64(InstPtr ip, BasicBlock *b) {
  // LEAVE

  // read RBP
  Value *vRBP = x86_64::R_READ<64>(b, X86::RBP);

  //write this to RSP
  x86_64::R_WRITE<64>(b, X86::RSP, vRBP);

  //do a pop into EBP
  //read from memory at the top of the stack
  Value *vRSP = x86_64::R_READ<64>(b, X86::RSP);
  Value *atTop = M_READ<64>(ip, b, vRSP);

  //write this value into EBP
  x86_64::R_WRITE<64>(b, X86::RBP, atTop);

  //add 8 to the stack pointer
  Value *updt = BinaryOperator::CreateAdd(vRSP, CONST_V<64>(b, 8), "", b);
  x86_64::R_WRITE<64>(b, X86::RSP, updt);

  return ContinueBlock;
}

template<int width>
static InstTransResult doPopR(InstPtr ip, BasicBlock *&b,
                              const MCOperand &dst) {
  NASSERT(dst.isReg());
  llvm::Module *M = b->getParent()->getParent();

  //read the stack pointer
  Value *oldRSP;

  if (ArchPointerSize(M) == Pointer32) {
    oldRSP = x86::R_READ<32>(b, X86::ESP);
  } else {
    oldRSP = x86_64::R_READ<64>(b, X86::RSP);
  }

  //read the value from the memory at the stack pointer address
  Value *m = M_READ_0<width>(b, oldRSP);

  //write that value into dst
  R_WRITE<width>(b, dst.getReg(), m);

  //add to the stack pointer
  if (ArchPointerSize(M) == Pointer32) {
    Value *newESP = BinaryOperator::CreateAdd(oldRSP,
                                              CONST_V<32>(b, (width / 8)), "",
                                              b);

    //update the stack pointer register
    x86::R_WRITE<32>(b, X86::ESP, newESP);
  } else {
    Value *newRSP = BinaryOperator::CreateAdd(oldRSP,
                                              CONST_V<64>(b, (width / 8)), "",
                                              b);

    //update the stack pointer register
    x86_64::R_WRITE<64>(b, X86::RSP, newRSP);
  }

  return ContinueBlock;
}

template<int width>
static InstTransResult doPopD(BasicBlock *b) {
  //read the stack pointer
  Value *oldESP = R_READ<width>(b, X86::ESP);

  //read the value from the memory at the stack pointer address,
  //and throw it away
  Value *m = M_READ_0<width>(b, oldESP);
  NASSERT(m != NULL);

  //add to the stack pointer
  Value *newESP = BinaryOperator::CreateAdd(oldESP,
                                            CONST_V<width>(b, (width / 8)), "",
                                            b);

  //update the stack pointer register
  R_WRITE<width>(b, X86::ESP, newESP);

  return ContinueBlock;
}

template<int width>
static InstTransResult doPopAV(InstPtr ip, BasicBlock *b) {
  // EDI := Pop();
  // ESI := Pop();
  // EBP := Pop();
  // throwaway := Pop (); (* Skip ESP *)
  // EBX := Pop();
  // EDX := Pop();
  // ECX := Pop();
  // EAX := Pop();

  doPopR<width>(ip, b, MCOperand::CreateReg(X86::EDI));
  doPopR<width>(ip, b, MCOperand::CreateReg(X86::ESI));
  doPopR<width>(ip, b, MCOperand::CreateReg(X86::EBP));
  doPopD<width>(b);
  doPopR<width>(ip, b, MCOperand::CreateReg(X86::EBX));
  doPopR<width>(ip, b, MCOperand::CreateReg(X86::EDX));
  doPopR<width>(ip, b, MCOperand::CreateReg(X86::ECX));
  doPopR<width>(ip, b, MCOperand::CreateReg(X86::EAX));

  return ContinueBlock;
}

template<int width>
static InstTransResult doPushR(InstPtr ip, BasicBlock *&b,
                               const MCOperand &src) {
  //PUSH <r>
  NASSERT(src.isReg());

  //first, read from <r> into a temp
  Value *TMP = R_READ<width>(b, src.getReg());

  doPushV<width>(ip, b, TMP);

  return ContinueBlock;
}

template<int width>
static InstTransResult doPushI(InstPtr ip, BasicBlock *&b,
                               const MCOperand &src) {
  // PUSH <imm>
  NASSERT(src.isImm());

  Value *OrigIMM = CONST_V<width>(b, src.getImm());
  // PUSHi32 and PUSHi16 will never be extended
  // in IA32
  Value *SExt_Val = OrigIMM;

  // PUSHi8 is extended to operand size, which is 32
  if (width == 8) {
    SExt_Val = new SExtInst(OrigIMM, Type::getInt32Ty(b->getContext()), "", b);
    doPushV<32>(ip, b, SExt_Val);
  } else {
    if (width == 32 && ip->has_ext_call_target()) {
      std::string target = ip->get_ext_call_target()->getSymbolName();
      Module *M = b->getParent()->getParent();
      Function *externFunction = M->getFunction(target);
      NASSERT(externFunction != NULL);
      doPushVT<width>(ip, b, externFunction);
    } else {
      doPushV<width>(ip, b, SExt_Val);
    }
  }

  return ContinueBlock;
}

template<int width>
static InstTransResult doPopM(InstPtr ip, BasicBlock *&b, Value *addr) {
  NASSERT(addr != NULL);

  //read the stack pointer
  Value *oldESP = R_READ<32>(b, X86::ESP);

  //read the value from the memory at the stack pointer address
  Value *m = M_READ_0<width>(b, oldESP);

  //write that value into dst
  M_WRITE<width>(ip, b, addr, m);

  //add to the stack pointer
  Value *newESP = BinaryOperator::CreateAdd(oldESP, CONST_V<32>(b, (width / 8)),
                                            "", b);

  //update the stack pointer register
  R_WRITE<32>(b, X86::ESP, newESP);

  return ContinueBlock;
}

template<int width>
static InstTransResult doPushRMM(InstPtr ip, BasicBlock *&b, Value *addr) {
  NASSERT(addr != NULL);

  Value *fromMem = M_READ<width>(ip, b, addr);
  doPushV<width>(ip, b, fromMem);

  return ContinueBlock;
}

static InstTransResult translate_PUSH32rmm(NativeModulePtr natM,
                                           BasicBlock *& block, InstPtr ip,
                                           MCInst &inst) {
  InstTransResult ret;
  Function *F = block->getParent();
  if (ip->has_external_ref()) {
    Value *addrInt = getValueForExternal<32>(F->getParent(), ip, block);
    TASSERT(addrInt != NULL, "Could not get address for external");
    doPushV<32>(ip, block, addrInt);
    return ContinueBlock;
  } else if (ip->has_mem_reference) {
    ret = doPushRMM<32>(ip, block, MEM_AS_DATA_REF(block, natM, inst, ip, 0));
  } else {
    ret = doPushRMM<32>(ip, block, ADDR_NOREF(0));
  }
  return ret;
}

static InstTransResult translate_PUSH64rmm(NativeModulePtr natM,
                                           BasicBlock *& block, InstPtr ip,
                                           MCInst &inst) {
  InstTransResult ret;
  Function *F = block->getParent();
  if (ip->has_external_ref()) {
    Value *addrInt = getValueForExternal<64>(F->getParent(), ip, block);
    TASSERT(addrInt != NULL, "Could not get address for external");
    doPushV<64>(ip, block, addrInt);
    return ContinueBlock;
  } else if (ip->has_mem_reference) {
    ret = doPushRMM<64>(ip, block, MEM_AS_DATA_REF(block, natM, inst, ip, 0));
  } else {
    ret = doPushRMM<64>(ip, block, ADDR_NOREF(0));
  }
  return ret;
}

static InstTransResult translate_PUSHi32(NativeModulePtr natM,
                                         BasicBlock *&block, InstPtr ip,
                                         MCInst &inst) {
  InstTransResult ret;
  Function *F = block->getParent();
  if (ip->has_code_ref()) {
    Value *callback_fn = ArchAddCallbackDriver(
        block->getParent()->getParent(), ip->get_reference(Inst::IMMRef));
    Value *addrInt = new PtrToIntInst(
        callback_fn, llvm::Type::getInt32Ty(block->getContext()), "", block);
    doPushV<32>(ip, block, addrInt);
    ret = ContinueBlock;
  } else if (ip->has_imm_reference) {
    Module *M = F->getParent();
    Value *ref = IMM_AS_DATA_REF(block, natM, ip);

    // this may fail catastrophically, but we can only push those 32-bits
    // or we break the stack
    if (Pointer64 == ArchPointerSize(M)) {
        ref = new llvm::TruncInst(ref, llvm::Type::getInt32Ty(block->getContext()), "", block);
    }

    doPushV<32>(ip, block, ref);
    ret = ContinueBlock;
  } else {
    ret = doPushI<32>(ip, block, OP(0));
  }
  return ret;
}

#define EMIT_SHL_OR(destval, inval, shiftcount) do {\
    Value *tmp = BinaryOperator::CreateShl(inval, CONST_V<width>(b, shiftcount), "", b); \
    destval = BinaryOperator::CreateOr(destval, tmp, "", b); \
    } while (0)

#define EMIT_SHR_AND(destval, inval, shiftcount) do {\
    Value *tmp = BinaryOperator::CreateLShr(inval, CONST_V<width>(b, shiftcount), "", b); \
    destval = BinaryOperator::CreateAnd(destval, tmp, "", b); \
    } while (0)

template<int width>
static Value * checkIfBitSet(Value *field, int bit, BasicBlock *b) {

  Value *tmp = BinaryOperator::CreateAnd(field, CONST_V<width>(b, 1 << bit), "",
                                         b);
  Value *res = new ICmpInst( *b, CmpInst::ICMP_NE, tmp, CONST_V<width>(b, 0));

  return res;
}

template<int width>
static InstTransResult doPopF(InstPtr ip, BasicBlock *b) {
  Value *newFlags = R_READ<width>(b, X86::ESP);
  doPopD<width>(b);

  // bit 0: CF
  F_WRITE(b, CF, checkIfBitSet<width>(newFlags, 0, b));
  // bit 1: 1 (reserved)
  // bit 2: PF
  F_WRITE(b, PF, checkIfBitSet<width>(newFlags, 2, b));
  // bit 3: 0
  // bit 4: AF
  F_WRITE(b, AF, checkIfBitSet<width>(newFlags, 4, b));
  // bit 5: 0
  // bit 6: ZF
  F_WRITE(b, ZF, checkIfBitSet<width>(newFlags, 6, b));
  // bit 7: SF
  F_WRITE(b, SF, checkIfBitSet<width>(newFlags, 7, b));
  // bit 8: TF (set to zero)
  // bit 9: IF (set to 1)
  // bit 10: DF
  F_WRITE(b, DF, checkIfBitSet<width>(newFlags, 10, b));
  // bit 11: OF
  F_WRITE(b, OF, checkIfBitSet<width>(newFlags, 11, b));

  return ContinueBlock;

}

template<int width>
static InstTransResult doPushF(InstPtr ip, BasicBlock *b) {

  // put eflags into one value.
  //
  Type *toT = Type::getIntNTy(b->getContext(), width);

  Value *cf = new ZExtInst(F_READ(b, CF), toT, "", b);
  Value *pf = new ZExtInst(F_READ(b, PF), toT, "", b);
  Value *af = new ZExtInst(F_READ(b, AF), toT, "", b);
  Value *zf = new ZExtInst(F_READ(b, ZF), toT, "", b);
  Value *sf = new ZExtInst(F_READ(b, SF), toT, "", b);
  Value *df = new ZExtInst(F_READ(b, DF), toT, "", b);
  Value *of = new ZExtInst(F_READ(b, OF), toT, "", b);

  Value *eflags_base = CONST_V<width>(b, 0x202);

  // bit 0: CF
  Value *cur_flags = BinaryOperator::CreateOr(eflags_base, cf, "", b);
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

void Stack_populateDispatchMap(DispatchMap &m) {
  m[X86::ENTER] = translate_ENTER;
  m[X86::LEAVE] = translate_LEAVE;
  m[X86::LEAVE64] = translate_LEAVE64;
  m[X86::POP16r] = translate_POP16r;
  m[X86::POP32r] = translate_POP32r;
  m[X86::PUSH16r] = translate_PUSH16r;
  m[X86::PUSH32r] = translate_PUSH32r;
  m[X86::PUSH32i8] = translate_PUSHi8;
  m[X86::PUSHi16] = translate_PUSHi16;
  m[X86::PUSHi32] = translate_PUSHi32;
  m[X86::PUSH32rmm] = translate_PUSH32rmm;
  m[X86::POPA32] = translate_POPA32;
  m[X86::PUSHA32] = translate_PUSHA32;
  m[X86::PUSHF32] = translate_PUSHF32;
  m[X86::PUSHF64] = translate_PUSHF64;
  m[X86::POP32rmm] = translate_POP32rmm;

  m[X86::PUSH64r] = translate_PUSH64r;
  m[X86::PUSH64rmm] = translate_PUSH64rmm;
  m[X86::PUSH64i8] = translate_PUSHi8;
  m[X86::PUSH64i32] = translate_PUSHi32;

  m[X86::POP64r] = translate_POP64r;
  m[X86::POPF64] = translate_POPF64;
  m[X86::POPF32] = translate_POPF32;
}
