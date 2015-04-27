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
#include "x86Helpers.h"
#include "x86Instrs_Jcc.h"
#include <string>
#include "../common/to_string.h"
#include "llvm/Support/Debug.h"

#define NASSERT(cond) TASSERT(cond, "")

using namespace llvm;

static Value *CMP(BasicBlock *&b, Value *x, Value *y) {
    return new ICmpInst(*b, CmpInst::ICMP_EQ, x, y);
}

static Value *AND(BasicBlock *&b, Value *x, Value *y) {
    return BinaryOperator::Create(Instruction::And, x, y, "", b);
}

static Value *OR(BasicBlock *&b, Value *x, Value *y) {
    return BinaryOperator::Create(Instruction::Or, x, y, "", b);
}

//emit the LLVM statements that perform the test associated with each 
//type of conditional jump
Value *emitTestCode(BasicBlock *&b, unsigned opCode) {
    Value       *emittedInsn = NULL;
    #define ONE CONST_V<1>(b, 1)
    #define ZERO CONST_V<1>(b, 0)
    #define OF_F F_READ(b, OF)
    #define CF_F F_READ(b, CF)
    #define PF_F F_READ(b, PF)
    #define AF_F F_READ(b, AF)
    #define ZF_F F_READ(b, ZF)
    #define SF_F F_READ(b, SF)

    switch(opCode) {
        case X86::JO_4:
        case X86::JO_1:
            // OF == 1 
            emittedInsn = CMP(b, OF_F, ONE);
            break;

        case X86::JNO_4:
        case X86::JNO_1:
            // OF == 0
            emittedInsn = CMP(b, OF_F, ZERO); 
            break;

        case X86::JB_4:
        case X86::JB_1:
            // CF == 1 
            emittedInsn = CMP(b, CF_F, ONE);
            break;

        case X86::JAE_4:
        case X86::JAE_1:
            // CF == 0
            emittedInsn = CMP(b, CF_F, ZERO); 
            break;

        case X86::JE_4:
        case X86::JE_1:
            //ZF == 1
            emittedInsn = CMP(b, ZF_F, ONE);
            break;

        case X86::JNE_4:
        case X86::JNE_1:
            //ZF == 0
            emittedInsn = CMP(b, ZF_F, ZERO);
            break;

        case X86::JBE_4:
        case X86::JBE_1:
            //CF = 1 or ZF = 1
            emittedInsn = OR(b, CMP(b, CF_F, ONE), CMP(b, ZF_F, ONE));
            break;

        case X86::JA_4:
        case X86::JA_1:
            //CF = 0 and ZF = 0 
            emittedInsn = AND(b, CMP(b, CF_F, ZERO), CMP(b, ZF_F, ZERO));
            break;

        case X86::JS_4:
        case X86::JS_1:
            //SF = 1
            emittedInsn = CMP(b, SF_F, ONE);
            break;

        case X86::JNS_4:
        case X86::JNS_1:
            //SF = 0
            emittedInsn = CMP(b, SF_F, ZERO);
            break;

        case X86::JP_4:
        case X86::JP_1:
            //PF = 1
            emittedInsn = CMP(b, PF_F, ONE);
            break;

        case X86::JNP_4:
        case X86::JNP_1:
            //PF = 0
            emittedInsn = CMP(b, PF_F, ZERO);
            break;

        case X86::JL_4:
        case X86::JL_1:
            //SF!=OF
            emittedInsn = CMP(b, CMP(b, SF_F, OF_F), ZERO);
            break;

        case X86::JGE_4:
        case X86::JGE_1:
            //SF=OF
            emittedInsn = CMP(b, SF_F, OF_F);
            break;

        case X86::JLE_4:
        case X86::JLE_1:
            //ZF=1 or SF != OF
            emittedInsn = OR(b, CMP(b, ZF_F, ONE), CMP(b, CMP(b, SF_F, OF_F), ZERO));
            break;

        case X86::JG_4:
        case X86::JG_1:
            //ZF=0 and SF=OF
            emittedInsn = AND(b, CMP(b, ZF_F, ZERO), CMP(b, SF_F, OF_F));
            break;

        case X86::JCXZ:
            emittedInsn = CMP(b, R_READ<16>(b, X86::CX), CONST_V<16>(b, 0));
            break;

        case X86::JECXZ_32:
            emittedInsn = CMP(b, R_READ<32>(b, X86::ECX), CONST_V<32>(b, 0));
            break;

        default:
        //case X86::JRCXZ:  
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

    NASSERT(emittedInsn != NULL );

    return emittedInsn;
}
//emit a conditional branch
static InstTransResult doCondBranch(InstPtr ip,   BasicBlock *&b, 
                                BasicBlock  *ifTrue, 
                                BasicBlock  *ifFalse, 
                                Value       *cond)
{
    //we should have targets for this branch
    NASSERT( ifTrue != NULL );
    NASSERT( ifFalse != NULL );
    NASSERT( cond != NULL );

    //emit a branch on the condition
    BranchInst::Create(ifTrue, ifFalse, cond, b);

    return EndBlock;
}

static InstTransResult translate_Jcc(NativeModulePtr natM, BasicBlock *& block, InstPtr ip, MCInst &inst) {

    Function *F = block->getParent();
    uint32_t target = ip->get_arch();
    llvm::dbgs() << "MOV64rm " << " 64";
    llvm::dbgs() << "\tRepresentation: " << ip->printInst() << "\n";

    std::string  trueStrName = "block_0x"+to_string<VA>(ip->get_tr(), std::hex);
    std::string  falseStrName = "block_0x"+to_string<VA>(ip->get_fa(), std::hex);

    BasicBlock          *ifTrue = bbFromStrName(trueStrName, F);
    BasicBlock          *ifFalse = bbFromStrName(falseStrName, F);

    return doCondBranch(ip, block, ifTrue, 
                                ifFalse, 
                                emitTestCode(block, inst.getOpcode() ) );
}

void Jcc_populateDispatchMap(DispatchMap &m) {

    //for conditional instructions, get the "true" and "false" targets 
    //this will also look up the target for nonconditional jumps

    m[X86::JBE_4] = translate_Jcc;
    m[X86::JBE_1] = translate_Jcc;
    m[X86::JA_4] = translate_Jcc;
    m[X86::JA_1] = translate_Jcc;
    m[X86::JS_4] = translate_Jcc;
    m[X86::JS_1] = translate_Jcc;
    m[X86::JNS_4] = translate_Jcc;
    m[X86::JNS_1] = translate_Jcc;
    m[X86::JP_4] = translate_Jcc;
    m[X86::JP_1] = translate_Jcc;
    m[X86::JNP_4] = translate_Jcc;
    m[X86::JNP_1] = translate_Jcc;
    m[X86::JL_4] = translate_Jcc;
    m[X86::JL_1] = translate_Jcc;
    m[X86::JGE_4] = translate_Jcc;
    m[X86::JGE_1] = translate_Jcc;
    m[X86::JG_4] = translate_Jcc;
    m[X86::JG_1] = translate_Jcc;
    m[X86::JCXZ] = translate_Jcc;
    m[X86::JRCXZ] = translate_Jcc;
    m[X86::JO_4] = translate_Jcc;
    m[X86::JO_1] = translate_Jcc;
    m[X86::JNO_4] = translate_Jcc;
    m[X86::JNO_1] = translate_Jcc;
    m[X86::JB_4] = translate_Jcc;
    m[X86::JB_1] = translate_Jcc;
    m[X86::JAE_4] = translate_Jcc;
    m[X86::JAE_1] = translate_Jcc;
    m[X86::JLE_4] = translate_Jcc;
    m[X86::JLE_1] = translate_Jcc;
    m[X86::JNE_4] = translate_Jcc;
    m[X86::JNE_1] = translate_Jcc;
    m[X86::JE_4] = translate_Jcc;
    m[X86::JE_1] = translate_Jcc;
}
