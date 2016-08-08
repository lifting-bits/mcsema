/*
Copyright (c) 2015, Trail of Bits
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
#include "x86Instrs_CMOV.h"
#include "RegisterUsage.h"

#define NASSERT(cond) TASSERT(cond, "")

using namespace llvm;

static Value *EQ(BasicBlock *b, MCSemaRegs f1, MCSemaRegs f2) {

    Value *l = F_READ(b, f1);
    Value *r = F_READ(b, f2);
    Value *is_eq = new ICmpInst(*b, CmpInst::ICMP_EQ, l, r);
    return is_eq;
}

static Value *NE(BasicBlock *b, MCSemaRegs f1, MCSemaRegs f2) {

    Value *l = F_READ(b, f1);
    Value *r = F_READ(b, f2);
    Value *is_ne = new ICmpInst(*b, CmpInst::ICMP_NE, l, r);
    return is_ne;
}

static Value *NOT(BasicBlock *b, MCSemaRegs flag) {

    Value *f = F_READ(b, flag);
    Value *not_f = BinaryOperator::CreateNot(f, "", b);
    return not_f;
}

static Value *AND(BasicBlock *b, Value *v1, Value *v2) {
   Value *andv = BinaryOperator::CreateAnd(v1, v2, "", b);
   return andv;
}

static Value *OR(BasicBlock *b, Value *v1, Value *v2) {
   Value *andv = BinaryOperator::CreateOr(v1, v2, "", b);
   return andv;
}

static Value *CHOOSE_IF(BasicBlock *b, Value *cmp, Value *trueval, Value *falseval) {
    Value *se = SelectInst::Create(cmp, trueval, falseval, "", b);
    return se;
}

template <int width>
static InstTransResult  doCMOV(
        BasicBlock *b, 
        MCOperand &dst, 
        Value *condition, 
        Value *newval) 
{
    Value *orig = R_READ<width>(b, dst.getReg());

    Value *to_write = CHOOSE_IF(b, 
            condition,
            newval,
            orig);

    R_WRITE<width>(b, dst.getReg(), to_write);
    return ContinueBlock;
}

#define EMIT_CMOV_RM(width, condition) [] (NativeModulePtr natM, BasicBlock *&block, InstPtr ip, MCInst &inst)->InstTransResult {\
    BasicBlock *b = block;\
    if( ip->has_mem_reference ) {\
        return doCMOV<width>(block, OP(0), condition, M_READ<width>(ip, b, MEM_REFERENCE(2)));\
    }else {\
        return doCMOV<width>(block, OP(0), condition, M_READ<width>(ip, b, ADDR_NOREF(2)));\
    }\
}

#define EMIT_CMOV_RR(width, condition) [] (NativeModulePtr natM, BasicBlock *&b, InstPtr ip, MCInst &inst)->InstTransResult {\
    return doCMOV<width>(b, OP(0), condition, R_READ<width>(b, OP(2).getReg())); \
}

#define EMIT_CMOV(which, condition) \
        m[which ## 16rm] = EMIT_CMOV_RM(16, condition);\
        m[which ## 16rr] = EMIT_CMOV_RR(16, condition);\
        m[which ## 32rm] = EMIT_CMOV_RM(32, condition);\
        m[which ## 32rr] = EMIT_CMOV_RR(32, condition);\
        m[which ## 64rm] = EMIT_CMOV_RM(64, condition);\
        m[which ## 64rr] = EMIT_CMOV_RR(64, condition);

void CMOV_populateDispatchMap(DispatchMap &m) {
        EMIT_CMOV(X86::CMOVA,   AND(b, NOT(b, CF), NOT(b, ZF)));
        EMIT_CMOV(X86::CMOVAE,  NOT(b, CF));
        EMIT_CMOV(X86::CMOVB,   F_READ(b, CF));
        EMIT_CMOV(X86::CMOVBE,  OR(b, F_READ(b, CF), F_READ(b, ZF)));
        EMIT_CMOV(X86::CMOVE,   F_READ(b, ZF));
        EMIT_CMOV(X86::CMOVG,   AND(b, NOT(b, ZF), EQ(b, SF, OF)));
        EMIT_CMOV(X86::CMOVGE,  EQ(b, SF, OF));
        EMIT_CMOV(X86::CMOVL,   NE(b, SF, OF));
        EMIT_CMOV(X86::CMOVLE,  OR(b, F_READ(b, ZF), NE(b, SF, OF)));
        EMIT_CMOV(X86::CMOVNE,  NOT(b, ZF));
        EMIT_CMOV(X86::CMOVNO,  NOT(b, OF));
        EMIT_CMOV(X86::CMOVNP,  NOT(b, PF));
        EMIT_CMOV(X86::CMOVNS,  NOT(b, SF));
        EMIT_CMOV(X86::CMOVO,   F_READ(b, OF));
        EMIT_CMOV(X86::CMOVP,   F_READ(b, PF));
        EMIT_CMOV(X86::CMOVS,   F_READ(b, SF));
}
