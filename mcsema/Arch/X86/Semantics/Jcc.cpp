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
#include "mcsema/Arch/X86/Semantics/Jcc.h"

#include "mcsema/BC/Util.h"

#define NASSERT(cond) TASSERT(cond, "")

static llvm::Value *CMP(llvm::BasicBlock *&b, llvm::Value *x, llvm::Value *y) {
  return new llvm::ICmpInst( *b, llvm::CmpInst::ICMP_EQ, x, y);
}

static llvm::Value *AND(llvm::BasicBlock *&b, llvm::Value *x, llvm::Value *y) {
  return llvm::BinaryOperator::Create(llvm::Instruction::And, x, y, "", b);
}

static llvm::Value *OR(llvm::BasicBlock *&b, llvm::Value *x, llvm::Value *y) {
  return llvm::BinaryOperator::Create(llvm::Instruction::Or, x, y, "", b);
}

//emit the LLVM statements that perform the test associated with each 
//type of conditional jump
llvm::Value *emitTestCode(llvm::BasicBlock *&b, unsigned opCode) {
  llvm::Value *emittedInsn = nullptr;
#define ONE CONST_V<1>(b, 1)
#define ZERO CONST_V<1>(b, 0)
#define OF_F F_READ(b, llvm::X86::OF)
#define CF_F F_READ(b, llvm::X86::CF)
#define PF_F F_READ(b, llvm::X86::PF)
#define AF_F F_READ(b, llvm::X86::AF)
#define ZF_F F_READ(b, llvm::X86::ZF)
#define SF_F F_READ(b, llvm::X86::SF)

  switch (opCode) {
    case llvm::X86::JO_4:
    case llvm::X86::JO_1:
      // OF == 1
      emittedInsn = CMP(b, OF_F, ONE);
      break;

    case llvm::X86::JNO_4:
    case llvm::X86::JNO_1:
      // OF == 0
      emittedInsn = CMP(b, OF_F, ZERO);
      break;

    case llvm::X86::JB_4:
    case llvm::X86::JB_1:
      // CF == 1
      emittedInsn = CMP(b, CF_F, ONE);
      break;

    case llvm::X86::JAE_4:
    case llvm::X86::JAE_1:
      // CF == 0
      emittedInsn = CMP(b, CF_F, ZERO);
      break;

    case llvm::X86::JE_4:
    case llvm::X86::JE_1:
      //ZF == 1
      emittedInsn = CMP(b, ZF_F, ONE);
      break;

    case llvm::X86::JNE_4:
    case llvm::X86::JNE_1:
      //ZF == 0
      emittedInsn = CMP(b, ZF_F, ZERO);
      break;

    case llvm::X86::JBE_4:
    case llvm::X86::JBE_1:
      //CF = 1 or ZF = 1
      emittedInsn = OR(b, CMP(b, CF_F, ONE), CMP(b, ZF_F, ONE));
      break;

    case llvm::X86::JA_4:
    case llvm::X86::JA_1:
      //CF = 0 and ZF = 0
      emittedInsn = AND(b, CMP(b, CF_F, ZERO), CMP(b, ZF_F, ZERO));
      break;

    case llvm::X86::JS_4:
    case llvm::X86::JS_1:
      //SF = 1
      emittedInsn = CMP(b, SF_F, ONE);
      break;

    case llvm::X86::JNS_4:
    case llvm::X86::JNS_1:
      //SF = 0
      emittedInsn = CMP(b, SF_F, ZERO);
      break;

    case llvm::X86::JP_4:
    case llvm::X86::JP_1:
      //PF = 1
      emittedInsn = CMP(b, PF_F, ONE);
      break;

    case llvm::X86::JNP_4:
    case llvm::X86::JNP_1:
      //PF = 0
      emittedInsn = CMP(b, PF_F, ZERO);
      break;

    case llvm::X86::JL_4:
    case llvm::X86::JL_1:
      //SF!=OF
      emittedInsn = CMP(b, CMP(b, SF_F, OF_F), ZERO);
      break;

    case llvm::X86::JGE_4:
    case llvm::X86::JGE_1:
      //SF=OF
      emittedInsn = CMP(b, SF_F, OF_F);
      break;

    case llvm::X86::JLE_4:
    case llvm::X86::JLE_1:
      //ZF=1 or SF != OF
      emittedInsn = OR(b, CMP(b, ZF_F, ONE), CMP(b, CMP(b, SF_F, OF_F), ZERO));
      break;

    case llvm::X86::JG_4:
    case llvm::X86::JG_1:
      //ZF=0 and SF=OF
      emittedInsn = AND(b, CMP(b, ZF_F, ZERO), CMP(b, SF_F, OF_F));
      break;

    case llvm::X86::JCXZ:
      emittedInsn = CMP(b, R_READ<16>(b, llvm::X86::CX), CONST_V<16>(b, 0));
      break;

    case llvm::X86::JECXZ:
      emittedInsn = CMP(b, R_READ<32>(b, llvm::X86::ECX), CONST_V<32>(b, 0));
      break;

    case llvm::X86::JRCXZ:
      emittedInsn = CMP(b, R_READ<64>(b, llvm::X86::RCX), CONST_V<64>(b, 0));
      break;

    default:
      throw TErr(__LINE__, __FILE__, "NIY");
      break;
  }

#undef ONE
#undef ZERO
#undef OF_F
#undef CF_F
#undef PF_F
#undef AF_F
#undef ZF_F
#undef SF_F

  NASSERT(emittedInsn != nullptr);

  return emittedInsn;
}
//emit a conditional branch
static InstTransResult doCondBranch(NativeInstPtr ip, llvm::BasicBlock *&b,
                                    llvm::BasicBlock *ifTrue,
                                    llvm::BasicBlock *ifFalse,
                                    llvm::Value *cond) {
  //we should have targets for this branch
  NASSERT(ifTrue != nullptr);
  NASSERT(ifFalse != nullptr);
  NASSERT(cond != nullptr);

  //emit a branch on the condition
  llvm::BranchInst::Create(ifTrue, ifFalse, cond, b);

  return EndBlock;
}

static InstTransResult translate_Jcc(TranslationContext &ctx,
                                     llvm::BasicBlock *&block) {

  auto F = block->getParent();
  auto ip = ctx.natI;
  auto &inst = ip->get_inst();

  auto ifTrue = ctx.va_to_bb[ip->get_tr()];
  auto ifFalse = ctx.va_to_bb[ip->get_fa()];

  return doCondBranch(ip, block, ifTrue, ifFalse,
                      emitTestCode(block, inst.getOpcode()));

}

void Jcc_populateDispatchMap(DispatchMap &m) {

  //for conditional instructions, get the "true" and "false" targets
  //this will also look up the target for nonconditional jumps

  m[llvm::X86::JBE_4] = translate_Jcc;
  m[llvm::X86::JBE_1] = translate_Jcc;
  m[llvm::X86::JA_4] = translate_Jcc;
  m[llvm::X86::JA_1] = translate_Jcc;
  m[llvm::X86::JS_4] = translate_Jcc;
  m[llvm::X86::JS_1] = translate_Jcc;
  m[llvm::X86::JNS_4] = translate_Jcc;
  m[llvm::X86::JNS_1] = translate_Jcc;
  m[llvm::X86::JP_4] = translate_Jcc;
  m[llvm::X86::JP_1] = translate_Jcc;
  m[llvm::X86::JNP_4] = translate_Jcc;
  m[llvm::X86::JNP_1] = translate_Jcc;
  m[llvm::X86::JL_4] = translate_Jcc;
  m[llvm::X86::JL_1] = translate_Jcc;
  m[llvm::X86::JGE_4] = translate_Jcc;
  m[llvm::X86::JGE_1] = translate_Jcc;
  m[llvm::X86::JG_4] = translate_Jcc;
  m[llvm::X86::JG_1] = translate_Jcc;
  m[llvm::X86::JCXZ] = translate_Jcc;
  m[llvm::X86::JRCXZ] = translate_Jcc;
  m[llvm::X86::JO_4] = translate_Jcc;
  m[llvm::X86::JO_1] = translate_Jcc;
  m[llvm::X86::JNO_4] = translate_Jcc;
  m[llvm::X86::JNO_1] = translate_Jcc;
  m[llvm::X86::JB_4] = translate_Jcc;
  m[llvm::X86::JB_1] = translate_Jcc;
  m[llvm::X86::JAE_4] = translate_Jcc;
  m[llvm::X86::JAE_1] = translate_Jcc;
  m[llvm::X86::JLE_4] = translate_Jcc;
  m[llvm::X86::JLE_1] = translate_Jcc;
  m[llvm::X86::JNE_4] = translate_Jcc;
  m[llvm::X86::JNE_1] = translate_Jcc;
  m[llvm::X86::JE_4] = translate_Jcc;
  m[llvm::X86::JE_1] = translate_Jcc;
}
