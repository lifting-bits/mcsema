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
// for MOV related ops
#include "x86Instrs_MOV.h"
#include "x86Instrs_CMOV.h"

#define NASSERT(cond) TASSERT(cond, "")

using namespace llvm;

template <int width>
static InstTransResult doCmovaRR(  InstPtr ip, BasicBlock      *&b,
                            const MCOperand &dst,
                            const MCOperand &src1,
                            const MCOperand &src2) 
{
    NASSERT(dst.isReg());
    NASSERT(src1.isReg());
    NASSERT(src2.isReg());

    Function    *F = b->getParent();
    BasicBlock  *condSatisfied = 
        BasicBlock::Create(b->getContext(), "condSatisfied", F);
    BasicBlock  *done = 
        BasicBlock::Create(b->getContext(), "done", F);

    Value   *cf = F_READ(b, "CF");
    Value   *zf = F_READ(b, "ZF");
    Value   *cfCmp = new ICmpInst(*b, CmpInst::ICMP_EQ, cf, CONST_V<1>(b, 0));
    Value   *zfCmp = new ICmpInst(*b, CmpInst::ICMP_EQ, zf, CONST_V<1>(b, 0));
    Value   *andRes = BinaryOperator::CreateAnd(cfCmp, zfCmp, "", b);

    BranchInst::Create(condSatisfied, done, andRes, b);

    doRRMov<width>(ip, condSatisfied, dst, src2);
    BranchInst::Create(done, condSatisfied);

    b = done;

    return ContinueBlock;
}

template <int width>
static InstTransResult doCmovaRM(  InstPtr ip, BasicBlock      *&b,
                            const MCOperand &dst,
                            const MCOperand &src1,
                            Value           *addr) 
{
    NASSERT(dst.isReg());
    NASSERT(src1.isReg());
    NASSERT(addr != NULL);

    Function    *F = b->getParent();
    BasicBlock  *condSatisfied = 
        BasicBlock::Create(b->getContext(), "condSatisfied", F);
    BasicBlock  *done = 
        BasicBlock::Create(b->getContext(), "done", F);

    Value   *cf = F_READ(b, "CF");
    Value   *zf = F_READ(b, "ZF");
    Value   *cfCmp = new ICmpInst(*b, CmpInst::ICMP_EQ, cf, CONST_V<1>(b, 0));
    Value   *zfCmp = new ICmpInst(*b, CmpInst::ICMP_EQ, zf, CONST_V<1>(b, 0));
    Value   *andRes = BinaryOperator::CreateAnd(cfCmp, zfCmp, "", b);

    BranchInst::Create(condSatisfied, done, andRes, b);

    doRMMov<width>(ip, condSatisfied, addr, dst);
    BranchInst::Create(done, condSatisfied);

    b = done;

    return ContinueBlock;
}

template <int width>
static InstTransResult doCmovaeRR( InstPtr ip, BasicBlock      *&b,
                            const MCOperand &dst,
                            const MCOperand &src1,
                            const MCOperand &src2) 
{
    NASSERT(dst.isReg());
    NASSERT(src1.isReg());
    NASSERT(src2.isReg());

    Function    *F = b->getParent();
    BasicBlock  *condSatisfied = 
        BasicBlock::Create(b->getContext(), "condSatisfied", F);
    BasicBlock  *done = 
        BasicBlock::Create(b->getContext(), "done", F);

    Value   *cf = F_READ(b, "CF");
    Value   *cfCmp = new ICmpInst(*b, CmpInst::ICMP_EQ, cf, CONST_V<1>(b, 0));

    BranchInst::Create(condSatisfied, done, cfCmp, b);

    doRRMov<width>(ip, condSatisfied, dst, src2);
    BranchInst::Create(done, condSatisfied);

    b = done;

    return ContinueBlock;
}

template <int width>
static InstTransResult doCmovaeRM( InstPtr ip, BasicBlock      *&b,
                            const MCOperand &dst,
                            const MCOperand &src1,
                            Value           *addr) 
{
    NASSERT(dst.isReg());
    NASSERT(src1.isReg());
    NASSERT(addr != NULL);

    Function    *F = b->getParent();
    BasicBlock  *condSatisfied = 
        BasicBlock::Create(b->getContext(), "condSatisfied", F);
    BasicBlock  *done = 
        BasicBlock::Create(b->getContext(), "done", F);

    Value   *cf = F_READ(b, "CF");
    Value   *cfCmp = new ICmpInst(*b, CmpInst::ICMP_EQ, cf, CONST_V<1>(b, 0));

    BranchInst::Create(condSatisfied, done, cfCmp, b);

    doRMMov<width>(ip, condSatisfied, addr, dst);
    BranchInst::Create(done, condSatisfied);

    b = done;

    return ContinueBlock;
}

template <int width>
static InstTransResult doCmovbRR( InstPtr ip, BasicBlock      *&b,
                            const MCOperand &dst,
                            const MCOperand &src1,
                            const MCOperand &src2) 
{
    NASSERT(dst.isReg());
    NASSERT(src1.isReg());
    NASSERT(src2.isReg());

    Function    *F = b->getParent();
    BasicBlock  *condSatisfied = 
        BasicBlock::Create(b->getContext(), "condSatisfied", F);
    BasicBlock  *done = 
        BasicBlock::Create(b->getContext(), "done", F);

    Value   *cf = F_READ(b, "CF");
    Value   *cfCmp = new ICmpInst(*b, CmpInst::ICMP_EQ, cf, CONST_V<1>(b, 1));

    BranchInst::Create(condSatisfied, done, cfCmp, b);

    doRRMov<width>(ip, condSatisfied, dst, src2);
    BranchInst::Create(done, condSatisfied);

    b = done;

    return ContinueBlock;
}

template <int width>
static InstTransResult doCmovbRM( InstPtr ip, BasicBlock      *&b,
                            const MCOperand &dst,
                            const MCOperand &src1,
                            Value           *addr) 
{
    NASSERT(dst.isReg());
    NASSERT(src1.isReg());
    NASSERT(addr != NULL);

    Function    *F = b->getParent();
    BasicBlock  *condSatisfied = 
        BasicBlock::Create(b->getContext(), "condSatisfied", F);
    BasicBlock  *done = 
        BasicBlock::Create(b->getContext(), "done", F);

    Value   *cf = F_READ(b, "CF");
    Value   *cfCmp = new ICmpInst(*b, CmpInst::ICMP_EQ, cf, CONST_V<1>(b, 1));

    BranchInst::Create(condSatisfied, done, cfCmp, b);

    doRMMov<width>(ip, condSatisfied, addr, dst);
    BranchInst::Create(done, condSatisfied);

    b = done;

    return ContinueBlock;
}

template <int width>
static InstTransResult doCmovbeRR( InstPtr ip, BasicBlock      *&b,
                            const MCOperand &dst,
                            const MCOperand &src1,
                            const MCOperand &src2) 
{
    NASSERT(dst.isReg());
    NASSERT(src1.isReg());
    NASSERT(src2.isReg());

    Function    *F = b->getParent();
    BasicBlock  *condSatisfied = 
        BasicBlock::Create(b->getContext(), "condSatisfied", F);
    BasicBlock  *done = 
        BasicBlock::Create(b->getContext(), "done", F);

    Value   *cf = F_READ(b, "CF");
    Value   *zf = F_READ(b, "ZF");
    Value   *cfCmp = new ICmpInst(*b, CmpInst::ICMP_EQ, cf, CONST_V<1>(b, 1));
    Value   *zfCmp = new ICmpInst(*b, CmpInst::ICMP_EQ, zf, CONST_V<1>(b, 1));
    Value   *orRes = BinaryOperator::CreateOr(cfCmp, zfCmp, "", b);

    BranchInst::Create(condSatisfied, done, orRes, b);

    doRRMov<width>(ip, condSatisfied, dst, src2);
    BranchInst::Create(done, condSatisfied);

    b = done;

    return ContinueBlock;
}

template <int width>
static InstTransResult doCmovbeRM( InstPtr ip, BasicBlock      *&b,
                            const MCOperand &dst,
                            const MCOperand &src1,
                            Value           *addr) 
{
    NASSERT(dst.isReg());
    NASSERT(src1.isReg());
    NASSERT(addr != NULL);

    Function    *F = b->getParent();
    BasicBlock  *condSatisfied = 
        BasicBlock::Create(b->getContext(), "condSatisfied", F);
    BasicBlock  *done = 
        BasicBlock::Create(b->getContext(), "done", F);

    Value   *cf = F_READ(b, "CF");
    Value   *zf = F_READ(b, "ZF");
    Value   *cfCmp = new ICmpInst(*b, CmpInst::ICMP_EQ, cf, CONST_V<1>(b, 1));
    Value   *zfCmp = new ICmpInst(*b, CmpInst::ICMP_EQ, zf, CONST_V<1>(b, 1));
    Value   *orRes = BinaryOperator::CreateOr(cfCmp, zfCmp, "", b);

    BranchInst::Create(condSatisfied, done, orRes, b);

    doRMMov<width>(ip, condSatisfied, addr, dst);
    BranchInst::Create(done, condSatisfied);

    b = done;

    return ContinueBlock;
}

template <int width>
static InstTransResult doCmoveRR(  InstPtr ip, BasicBlock      *&b,
                            const MCOperand &dst,
                            const MCOperand &src1,
                            const MCOperand &src2) 
{
    NASSERT(dst.isReg());
    NASSERT(src1.isReg());
    NASSERT(src2.isReg());

    Function    *F = b->getParent();
    BasicBlock  *condSatisfied = 
        BasicBlock::Create(b->getContext(), "condSatisfied", F);
    BasicBlock  *done = 
        BasicBlock::Create(b->getContext(), "done", F);

    Value   *zf = F_READ(b, "ZF");
    Value   *zfCmp = new ICmpInst(*b, CmpInst::ICMP_EQ, zf, CONST_V<1>(b, 1));

    BranchInst::Create(condSatisfied, done, zfCmp, b);

    doRRMov<width>(ip, condSatisfied, dst, src2);
    BranchInst::Create(done, condSatisfied);

    b = done;

    return ContinueBlock;
}

template <int width>
static InstTransResult doCmoveRM(  InstPtr ip, BasicBlock      *&b,
                            const MCOperand &dst,
                            const MCOperand &src1,
                            Value           *addr) 
{
    NASSERT(dst.isReg());
    NASSERT(src1.isReg());
    NASSERT(addr != NULL);

    Function    *F = b->getParent();
    BasicBlock  *condSatisfied = 
        BasicBlock::Create(b->getContext(), "condSatisfied", F);
    BasicBlock  *done = 
        BasicBlock::Create(b->getContext(), "done", F);

    Value   *zf = F_READ(b, "ZF");
    Value   *zfCmp = new ICmpInst(*b, CmpInst::ICMP_EQ, zf, CONST_V<1>(b, 1));

    BranchInst::Create(condSatisfied, done, zfCmp, b);

    doRMMov<width>(ip, condSatisfied, addr, dst);
    BranchInst::Create(done, condSatisfied);

    b = done;

    return ContinueBlock;
}

template <int width>
static InstTransResult doCmovgRR(  InstPtr ip, BasicBlock      *&b,
                            const MCOperand &dst,
                            const MCOperand &src1,
                            const MCOperand &src2) 
{
    NASSERT(dst.isReg());
    NASSERT(src1.isReg());
    NASSERT(src2.isReg());

    Function    *F = b->getParent();
    BasicBlock  *condSatisfied = 
        BasicBlock::Create(b->getContext(), "condSatisfied", F);
    BasicBlock  *done = 
        BasicBlock::Create(b->getContext(), "done", F);

    Value   *zf = F_READ(b, "ZF");
    Value   *sf = F_READ(b, "SF");
    Value   *of = F_READ(b, "OF");
    Value   *zfCmp = new ICmpInst(*b, CmpInst::ICMP_EQ, zf, CONST_V<1>(b, 0));
    Value   *sf_of_Cmp = new ICmpInst(*b, CmpInst::ICMP_EQ, sf, of);
    Value   *andRes = BinaryOperator::CreateAnd(zfCmp, sf_of_Cmp, "", b);

    BranchInst::Create(condSatisfied, done, andRes, b);

    doRRMov<width>(ip, condSatisfied, dst, src2);
    BranchInst::Create(done, condSatisfied);

    b = done;

    return ContinueBlock;
}

template <int width>
static InstTransResult doCmovgRM(  InstPtr ip, BasicBlock      *&b,
                            const MCOperand &dst,
                            const MCOperand &src1,
                            Value           *addr) 
{
    NASSERT(dst.isReg());
    NASSERT(src1.isReg());
    NASSERT(addr != NULL);

    Function    *F = b->getParent();
    BasicBlock  *condSatisfied = 
        BasicBlock::Create(b->getContext(), "condSatisfied", F);
    BasicBlock  *done = 
        BasicBlock::Create(b->getContext(), "done", F);

    Value   *zf = F_READ(b, "ZF");
    Value   *sf = F_READ(b, "SF");
    Value   *of = F_READ(b, "OF");
    Value   *zfCmp = new ICmpInst(*b, CmpInst::ICMP_EQ, zf, CONST_V<1>(b, 0));
    Value   *sf_of_Cmp = new ICmpInst(*b, CmpInst::ICMP_EQ, sf, of);
    Value   *andRes = BinaryOperator::CreateAnd(zfCmp, sf_of_Cmp, "", b);

    BranchInst::Create(condSatisfied, done, andRes, b);

    doRMMov<width>(ip, condSatisfied, addr, dst);
    BranchInst::Create(done, condSatisfied);

    b = done;

    return ContinueBlock;
}

template <int width>
static InstTransResult doCmovgeRR(  InstPtr ip, BasicBlock      *&b,
                            const MCOperand &dst,
                            const MCOperand &src1,
                            const MCOperand &src2) 
{
    NASSERT(dst.isReg());
    NASSERT(src1.isReg());
    NASSERT(src2.isReg());

    Function    *F = b->getParent();
    BasicBlock  *condSatisfied = 
        BasicBlock::Create(b->getContext(), "condSatisfied", F);
    BasicBlock  *done = 
        BasicBlock::Create(b->getContext(), "done", F);

    Value   *sf = F_READ(b, "SF");
    Value   *of = F_READ(b, "OF");
    Value   *sf_of_Cmp = new ICmpInst(*b, CmpInst::ICMP_EQ, sf, of);

    BranchInst::Create(condSatisfied, done, sf_of_Cmp, b);

    doRRMov<width>(ip, condSatisfied, dst, src2);
    BranchInst::Create(done, condSatisfied);

    b = done;

    return ContinueBlock;
}

template <int width>
static InstTransResult doCmovgeRM(  InstPtr ip, BasicBlock      *&b,
                            const MCOperand &dst,
                            const MCOperand &src1,
                            Value           *addr) 
{
    NASSERT(dst.isReg());
    NASSERT(src1.isReg());
    NASSERT(addr != NULL);

    Function    *F = b->getParent();
    BasicBlock  *condSatisfied = 
        BasicBlock::Create(b->getContext(), "condSatisfied", F);
    BasicBlock  *done = 
        BasicBlock::Create(b->getContext(), "done", F);

    Value   *sf = F_READ(b, "SF");
    Value   *of = F_READ(b, "OF");
    Value   *sf_of_Cmp = new ICmpInst(*b, CmpInst::ICMP_EQ, sf, of);

    BranchInst::Create(condSatisfied, done, sf_of_Cmp, b);

    doRMMov<width>(ip, condSatisfied, addr, dst);
    BranchInst::Create(done, condSatisfied);

    b = done;

    return ContinueBlock;
}

template <int width>
static InstTransResult doCmovlRR(  InstPtr ip, BasicBlock      *&b,
                            const MCOperand &dst,
                            const MCOperand &src1,
                            const MCOperand &src2) 
{
    NASSERT(dst.isReg());
    NASSERT(src1.isReg());
    NASSERT(src2.isReg());

    Function    *F = b->getParent();
    BasicBlock  *condSatisfied = 
        BasicBlock::Create(b->getContext(), "condSatisfied", F);
    BasicBlock  *done = 
        BasicBlock::Create(b->getContext(), "done", F);

    Value   *sf = F_READ(b, "SF");
    Value   *of = F_READ(b, "OF");
    Value   *sf_of_Cmp = new ICmpInst(*b, CmpInst::ICMP_NE, sf, of);

    BranchInst::Create(condSatisfied, done, sf_of_Cmp, b);

    doRRMov<width>(ip, condSatisfied, dst, src2);
    BranchInst::Create(done, condSatisfied);

    b = done;

    return ContinueBlock;
}

template <int width>
static InstTransResult doCmovlRM(  InstPtr ip, BasicBlock      *&b,
                            const MCOperand &dst,
                            const MCOperand &src1,
                            Value           *addr) 
{
    NASSERT(dst.isReg());
    NASSERT(src1.isReg());
    NASSERT(addr != NULL);

    Function    *F = b->getParent();
    BasicBlock  *condSatisfied = 
        BasicBlock::Create(b->getContext(), "condSatisfied", F);
    BasicBlock  *done = 
        BasicBlock::Create(b->getContext(), "done", F);

    Value   *sf = F_READ(b, "SF");
    Value   *of = F_READ(b, "OF");
    Value   *sf_of_Cmp = new ICmpInst(*b, CmpInst::ICMP_NE, sf, of);

    BranchInst::Create(condSatisfied, done, sf_of_Cmp, b);

    doRMMov<width>(ip, condSatisfied, addr, dst);
    BranchInst::Create(done, condSatisfied);

    b = done;

    return ContinueBlock;
}

template <int width>
static InstTransResult doCmovleRR( InstPtr ip, BasicBlock      *&b,
                            const MCOperand &dst,
                            const MCOperand &src1,
                            const MCOperand &src2) 
{
    NASSERT(dst.isReg());
    NASSERT(src1.isReg());
    NASSERT(src2.isReg());

    Function    *F = b->getParent();
    BasicBlock  *condSatisfied = 
        BasicBlock::Create(b->getContext(), "condSatisfied", F);
    BasicBlock  *done = 
        BasicBlock::Create(b->getContext(), "done", F);

    Value   *zf = F_READ(b, "ZF");
    Value   *sf = F_READ(b, "SF");
    Value   *of = F_READ(b, "OF");
    Value   *zfCmp = new ICmpInst(*b, CmpInst::ICMP_EQ, zf, CONST_V<1>(b, 1));
    Value   *sf_of_Cmp = new ICmpInst(*b, CmpInst::ICMP_NE, sf, of);
    Value   *orRes = BinaryOperator::CreateOr(zfCmp, sf_of_Cmp, "", b);

    BranchInst::Create(condSatisfied, done, orRes, b);

    doRRMov<width>(ip, condSatisfied, dst, src2);
    BranchInst::Create(done, condSatisfied);

    b = done;

    return ContinueBlock;
}

template <int width>
static InstTransResult doCmovleRM( InstPtr ip, BasicBlock      *&b,
                            const MCOperand &dst,
                            const MCOperand &src1,
                            Value           *addr) 
{
    NASSERT(dst.isReg());
    NASSERT(src1.isReg());
    NASSERT(addr != NULL);

    Function    *F = b->getParent();
    BasicBlock  *condSatisfied = 
        BasicBlock::Create(b->getContext(), "condSatisfied", F);
    BasicBlock  *done = 
        BasicBlock::Create(b->getContext(), "done", F);

    Value   *zf = F_READ(b, "ZF");
    Value   *sf = F_READ(b, "SF");
    Value   *of = F_READ(b, "OF");
    Value   *zfCmp = new ICmpInst(*b, CmpInst::ICMP_EQ, zf, CONST_V<1>(b, 1));
    Value   *sf_of_Cmp = new ICmpInst(*b, CmpInst::ICMP_NE, sf, of);
    Value   *orRes = BinaryOperator::CreateOr(zfCmp, sf_of_Cmp, "", b);

    BranchInst::Create(condSatisfied, done, orRes, b);

    doRMMov<width>(ip, condSatisfied, addr, dst);
    BranchInst::Create(done, condSatisfied);

    b = done;

    return ContinueBlock;
}

template <int width>
static InstTransResult doCmovneRR( InstPtr ip, BasicBlock      *&b,
                            const MCOperand &dst,
                            const MCOperand &src1,
                            const MCOperand &src2) 
{
    NASSERT(dst.isReg());
    NASSERT(src1.isReg());
    NASSERT(src2.isReg());

    Function    *F = b->getParent();
    BasicBlock  *condSatisfied = 
        BasicBlock::Create(b->getContext(), "condSatisfied", F);
    BasicBlock  *done = 
        BasicBlock::Create(b->getContext(), "done", F);

    Value   *zf = F_READ(b, "ZF");
    Value   *zfCmp = new ICmpInst(*b, CmpInst::ICMP_EQ, zf, CONST_V<1>(b, 0));

    BranchInst::Create(condSatisfied, done, zfCmp, b);

    doRRMov<width>(ip, condSatisfied, dst, src2);
    BranchInst::Create(done, condSatisfied);

    b = done;

    return ContinueBlock;
}

template <int width>
static InstTransResult doCmovneRM( InstPtr ip, BasicBlock      *&b,
                            const MCOperand &dst,
                            const MCOperand &src1,
                            Value           *addr) 
{
    NASSERT(dst.isReg());
    NASSERT(src1.isReg());
    NASSERT(addr != NULL);

    Function    *F = b->getParent();
    BasicBlock  *condSatisfied = 
        BasicBlock::Create(b->getContext(), "condSatisfied", F);
    BasicBlock  *done = 
        BasicBlock::Create(b->getContext(), "done", F);

    Value   *zf = F_READ(b, "ZF");
    Value   *zfCmp = new ICmpInst(*b, CmpInst::ICMP_EQ, zf, CONST_V<1>(b, 0));

    BranchInst::Create(condSatisfied, done, zfCmp, b);

    doRMMov<width>(ip, condSatisfied, addr, dst);
    BranchInst::Create(done, condSatisfied);

    b = done;

    return ContinueBlock;
}

template <int width>
static InstTransResult doCmovnoRR( InstPtr ip, BasicBlock      *&b,
                            const MCOperand &dst,
                            const MCOperand &src1,
                            const MCOperand &src2) 
{
    NASSERT(dst.isReg());
    NASSERT(src1.isReg());
    NASSERT(src2.isReg());

    Function    *F = b->getParent();
    BasicBlock  *condSatisfied = 
        BasicBlock::Create(b->getContext(), "condSatisfied", F);
    BasicBlock  *done = 
        BasicBlock::Create(b->getContext(), "done", F);

    Value   *of = F_READ(b, "OF");
    Value   *ofCmp = new ICmpInst(*b, CmpInst::ICMP_EQ, of, CONST_V<1>(b, 0));

    BranchInst::Create(condSatisfied, done, ofCmp, b);

    doRRMov<width>(ip, condSatisfied, dst, src2);
    BranchInst::Create(done, condSatisfied);

    b = done;

    return ContinueBlock;
}

template <int width>
static InstTransResult doCmovnoRM( InstPtr ip, BasicBlock      *&b,
                            const MCOperand &dst,
                            const MCOperand &src1,
                            Value           *addr) 
{
    NASSERT(dst.isReg());
    NASSERT(src1.isReg());
    NASSERT(addr != NULL);

    Function    *F = b->getParent();
    BasicBlock  *condSatisfied = 
        BasicBlock::Create(b->getContext(), "condSatisfied", F);
    BasicBlock  *done = 
        BasicBlock::Create(b->getContext(), "done", F);

    Value   *of = F_READ(b, "OF");
    Value   *ofCmp = new ICmpInst(*b, CmpInst::ICMP_EQ, of, CONST_V<1>(b, 0));

    BranchInst::Create(condSatisfied, done, ofCmp, b);

    doRMMov<width>(ip, condSatisfied, addr, dst);
    BranchInst::Create(done, condSatisfied);

    b = done;

    return ContinueBlock;
}

template <int width>
static InstTransResult doCmovnpRR( InstPtr ip, BasicBlock      *&b,
                            const MCOperand &dst,
                            const MCOperand &src1,
                            const MCOperand &src2) 
{
    NASSERT(dst.isReg());
    NASSERT(src1.isReg());
    NASSERT(src2.isReg());

    Function    *F = b->getParent();
    BasicBlock  *condSatisfied = 
        BasicBlock::Create(b->getContext(), "condSatisfied", F);
    BasicBlock  *done = 
        BasicBlock::Create(b->getContext(), "done", F);

    Value   *pf = F_READ(b, "PF");
    Value   *pfCmp = new ICmpInst(*b, CmpInst::ICMP_EQ, pf, CONST_V<1>(b, 0));

    BranchInst::Create(condSatisfied, done, pfCmp, b);

    doRRMov<width>(ip, condSatisfied, dst, src2);
    BranchInst::Create(done, condSatisfied);

    b = done;

    return ContinueBlock;
}

template <int width>
static InstTransResult doCmovnpRM( InstPtr ip, BasicBlock      *&b,
                            const MCOperand &dst,
                            const MCOperand &src1,
                            Value           *addr) 
{
    NASSERT(dst.isReg());
    NASSERT(src1.isReg());
    NASSERT(addr != NULL);

    Function    *F = b->getParent();
    BasicBlock  *condSatisfied = 
        BasicBlock::Create(b->getContext(), "condSatisfied", F);
    BasicBlock  *done = 
        BasicBlock::Create(b->getContext(), "done", F);

    Value   *pf = F_READ(b, "PF");
    Value   *pfCmp = new ICmpInst(*b, CmpInst::ICMP_EQ, pf, CONST_V<1>(b, 0));

    BranchInst::Create(condSatisfied, done, pfCmp, b);

    doRMMov<width>(ip, condSatisfied, addr, dst);
    BranchInst::Create(done, condSatisfied);

    b = done;

    return ContinueBlock;
}

template <int width>
static InstTransResult doCmovnsRR( InstPtr ip, BasicBlock      *&b,
                            const MCOperand &dst,
                            const MCOperand &src1,
                            const MCOperand &src2) 
{
    NASSERT(dst.isReg());
    NASSERT(src1.isReg());
    NASSERT(src2.isReg());

    Function    *F = b->getParent();
    BasicBlock  *condSatisfied = 
        BasicBlock::Create(b->getContext(), "condSatisfied", F);
    BasicBlock  *done = 
        BasicBlock::Create(b->getContext(), "done", F);

    Value   *sf = F_READ(b, "SF");
    Value   *sfCmp = new ICmpInst(*b, CmpInst::ICMP_EQ, sf, CONST_V<1>(b, 0));

    BranchInst::Create(condSatisfied, done, sfCmp, b);

    doRRMov<width>(ip, condSatisfied, dst, src2);
    BranchInst::Create(done, condSatisfied);

    b = done;

    return ContinueBlock;
}

template <int width>
static InstTransResult doCmovnsRM( InstPtr ip, BasicBlock      *&b,
                            const MCOperand &dst,
                            const MCOperand &src1,
                            Value           *addr) 
{
    NASSERT(dst.isReg());
    NASSERT(src1.isReg());
    NASSERT(addr != NULL);

    Function    *F = b->getParent();
    BasicBlock  *condSatisfied = 
        BasicBlock::Create(b->getContext(), "condSatisfied", F);
    BasicBlock  *done = 
        BasicBlock::Create(b->getContext(), "done", F);

    Value   *sf = F_READ(b, "SF");
    Value   *sfCmp = new ICmpInst(*b, CmpInst::ICMP_EQ, sf, CONST_V<1>(b, 0));

    BranchInst::Create(condSatisfied, done, sfCmp, b);

    doRMMov<width>(ip, condSatisfied, addr, dst);
    BranchInst::Create(done, condSatisfied);

    b = done;

    return ContinueBlock;
}

template <int width>
static InstTransResult doCmovoRR( InstPtr ip, BasicBlock      *&b,
                            const MCOperand &dst,
                            const MCOperand &src1,
                            const MCOperand &src2) 
{
    NASSERT(dst.isReg());
    NASSERT(src1.isReg());
    NASSERT(src2.isReg());

    Function    *F = b->getParent();
    BasicBlock  *condSatisfied = 
        BasicBlock::Create(b->getContext(), "condSatisfied", F);
    BasicBlock  *done = 
        BasicBlock::Create(b->getContext(), "done", F);

    Value   *of = F_READ(b, "OF");
    Value   *ofCmp = new ICmpInst(*b, CmpInst::ICMP_EQ, of, CONST_V<1>(b, 1));

    BranchInst::Create(condSatisfied, done, ofCmp, b);

    doRRMov<width>(ip, condSatisfied, dst, src2);
    BranchInst::Create(done, condSatisfied);

    b = done;

    return ContinueBlock;
}

template <int width>
static InstTransResult doCmovoRM( InstPtr ip, BasicBlock      *&b,
                            const MCOperand &dst,
                            const MCOperand &src1,
                            Value           *addr) 
{
    NASSERT(dst.isReg());
    NASSERT(src1.isReg());
    NASSERT(addr != NULL);

    Function    *F = b->getParent();
    BasicBlock  *condSatisfied = 
        BasicBlock::Create(b->getContext(), "condSatisfied", F);
    BasicBlock  *done = 
        BasicBlock::Create(b->getContext(), "done", F);

    Value   *of = F_READ(b, "OF");
    Value   *ofCmp = new ICmpInst(*b, CmpInst::ICMP_EQ, of, CONST_V<1>(b, 1));

    BranchInst::Create(condSatisfied, done, ofCmp, b);

    doRMMov<width>(ip, condSatisfied, addr, dst);
    BranchInst::Create(done, condSatisfied);

    b = done;

    return ContinueBlock;
}

template <int width>
static InstTransResult doCmovpRR(  InstPtr ip, BasicBlock      *&b,
                            const MCOperand &dst,
                            const MCOperand &src1,
                            const MCOperand &src2) 
{
    NASSERT(dst.isReg());
    NASSERT(src1.isReg());
    NASSERT(src2.isReg());

    Function    *F = b->getParent();
    BasicBlock  *condSatisfied = 
        BasicBlock::Create(b->getContext(), "condSatisfied", F);
    BasicBlock  *done = 
        BasicBlock::Create(b->getContext(), "done", F);

    Value   *pf = F_READ(b, "PF");
    Value   *pfCmp = new ICmpInst(*b, CmpInst::ICMP_EQ, pf, CONST_V<1>(b, 1));

    BranchInst::Create(condSatisfied, done, pfCmp, b);

    doRRMov<width>(ip, condSatisfied, dst, src2);
    BranchInst::Create(done, condSatisfied);

    b = done;

    return ContinueBlock;
}

template <int width>
static InstTransResult doCmovpRM(  InstPtr ip, BasicBlock      *&b,
                            const MCOperand &dst,
                            const MCOperand &src1,
                            Value           *addr) 
{
    NASSERT(dst.isReg());
    NASSERT(src1.isReg());
    NASSERT(addr != NULL);

    Function    *F = b->getParent();
    BasicBlock  *condSatisfied = 
        BasicBlock::Create(b->getContext(), "condSatisfied", F);
    BasicBlock  *done = 
        BasicBlock::Create(b->getContext(), "done", F);

    Value   *pf = F_READ(b, "PF");
    Value   *pfCmp = new ICmpInst(*b, CmpInst::ICMP_EQ, pf, CONST_V<1>(b, 1));

    BranchInst::Create(condSatisfied, done, pfCmp, b);

    doRMMov<width>(ip, condSatisfied, addr, dst);
    BranchInst::Create(done, condSatisfied);

    b = done;

    return ContinueBlock;
}

template <int width>
static InstTransResult doCmovsRR(  InstPtr ip, BasicBlock      *&b,
                            const MCOperand &dst,
                            const MCOperand &src1,
                            const MCOperand &src2) 
{
    NASSERT(dst.isReg());
    NASSERT(src1.isReg());
    NASSERT(src2.isReg());

    Function    *F = b->getParent();
    BasicBlock  *condSatisfied = 
        BasicBlock::Create(b->getContext(), "condSatisfied", F);
    BasicBlock  *done = 
        BasicBlock::Create(b->getContext(), "done", F);

    Value   *sf = F_READ(b, "SF");
    Value   *sfCmp = new ICmpInst(*b, CmpInst::ICMP_EQ, sf, CONST_V<1>(b, 1));

    BranchInst::Create(condSatisfied, done, sfCmp, b);

    doRRMov<width>(ip, condSatisfied, dst, src2);
    BranchInst::Create(done, condSatisfied);

    b = done;

    return ContinueBlock;
}

template <int width>
static InstTransResult doCmovsRM(  InstPtr ip, BasicBlock      *&b,
                            const MCOperand &dst,
                            const MCOperand &src1,
                            Value           *addr) 
{
    NASSERT(dst.isReg());
    NASSERT(src1.isReg());
    NASSERT(addr != NULL);

    Function    *F = b->getParent();
    BasicBlock  *condSatisfied = 
        BasicBlock::Create(b->getContext(), "condSatisfied", F);
    BasicBlock  *done = 
        BasicBlock::Create(b->getContext(), "done", F);

    Value   *sf = F_READ(b, "SF");
    Value   *sfCmp = new ICmpInst(*b, CmpInst::ICMP_EQ, sf, CONST_V<1>(b, 1));

    BranchInst::Create(condSatisfied, done, sfCmp, b);

    doRMMov<width>(ip, condSatisfied, addr, dst);
    BranchInst::Create(done, condSatisfied);

    b = done;

    return ContinueBlock;
}

GENERIC_TRANSLATION_MEM(CMOVA16rm, 
	doCmovaRM<16>(ip, block, OP(0), OP(1), ADDR(2)),
	doCmovaRM<16>(ip, block, OP(0), OP(1), STD_GLOBAL_OP(2)))
GENERIC_TRANSLATION(CMOVA16rr, doCmovaRR<16>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION_MEM(CMOVA32rm, 
	doCmovaRM<32>(ip, block, OP(0), OP(1), ADDR(2)),
	doCmovaRM<32>(ip, block, OP(0), OP(1), STD_GLOBAL_OP(2)))
GENERIC_TRANSLATION(CMOVA32rr, doCmovaRR<32>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION_MEM(CMOVAE16rm, 
	doCmovaeRM<16>(ip, block, OP(0), OP(1), ADDR(2)),
	doCmovaeRM<16>(ip, block, OP(0), OP(1), STD_GLOBAL_OP(2)))
GENERIC_TRANSLATION(CMOVAE16rr, doCmovaeRR<16>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION_MEM(CMOVAE32rm, 
	doCmovaeRM<32>(ip, block, OP(0), OP(1), ADDR(2)),
	doCmovaeRM<32>(ip, block, OP(0), OP(1), STD_GLOBAL_OP(2)))
GENERIC_TRANSLATION(CMOVAE32rr, doCmovaeRR<32>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION_MEM(CMOVB16rm, 
	doCmovbRM<16>(ip, block, OP(0), OP(1), ADDR(2)),
	doCmovbRM<16>(ip, block, OP(0), OP(1), STD_GLOBAL_OP(2)))
GENERIC_TRANSLATION(CMOVB16rr, doCmovbRR<16>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION_MEM(CMOVB32rm, 
	doCmovbRM<32>(ip, block, OP(0), OP(1), ADDR(2)),
	doCmovbRM<32>(ip, block, OP(0), OP(1), STD_GLOBAL_OP(2)))
GENERIC_TRANSLATION(CMOVB32rr, doCmovbRR<32>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION_MEM(CMOVBE16rm, 
	doCmovbeRM<16>(ip, block, OP(0), OP(1), ADDR(2)),
	doCmovbeRM<16>(ip, block, OP(0), OP(1), STD_GLOBAL_OP(2)))
GENERIC_TRANSLATION(CMOVBE16rr, doCmovbeRR<16>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION_MEM(CMOVBE32rm, 
	doCmovbeRM<32>(ip, block, OP(0), OP(1), ADDR(2)),
	doCmovbeRM<32>(ip, block, OP(0), OP(1), STD_GLOBAL_OP(2)))
GENERIC_TRANSLATION(CMOVBE32rr, doCmovbeRR<32>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION_MEM(CMOVE16rm, 
	doCmoveRM<16>(ip, block, OP(0), OP(1), ADDR(2)),
	doCmoveRM<16>(ip, block, OP(0), OP(1), STD_GLOBAL_OP(2)))
GENERIC_TRANSLATION(CMOVE16rr, doCmoveRR<16>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION_MEM(CMOVE32rm, 
	doCmoveRM<32>(ip, block, OP(0), OP(1), ADDR(2)),
	doCmoveRM<32>(ip, block, OP(0), OP(1), STD_GLOBAL_OP(2)))
GENERIC_TRANSLATION(CMOVE32rr, doCmoveRR<32>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION_MEM(CMOVG16rm, 
	doCmovgRM<16>(ip, block, OP(0), OP(1), ADDR(2)),
	doCmovgRM<16>(ip, block, OP(0), OP(1), STD_GLOBAL_OP(2)))
GENERIC_TRANSLATION(CMOVG16rr, doCmovgRR<16>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION_MEM(CMOVG32rm, 
	doCmovgRM<32>(ip, block, OP(0), OP(1), ADDR(2)),
	doCmovgRM<32>(ip, block, OP(0), OP(1), STD_GLOBAL_OP(2)))
GENERIC_TRANSLATION(CMOVG32rr, doCmovgRR<32>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION_MEM(CMOVGE16rm, 
	doCmovgeRM<16>(ip, block, OP(0), OP(1), ADDR(2)),
	doCmovgeRM<16>(ip, block, OP(0), OP(1), STD_GLOBAL_OP(2)))
GENERIC_TRANSLATION(CMOVGE16rr, doCmovgeRR<16>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION_MEM(CMOVGE32rm, 
	doCmovgeRM<32>(ip, block, OP(0), OP(1), ADDR(2)),
	doCmovgeRM<32>(ip, block, OP(0), OP(1), STD_GLOBAL_OP(2)))
GENERIC_TRANSLATION(CMOVGE32rr, doCmovgeRR<32>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION_MEM(CMOVL16rm, 
	doCmovlRM<16>(ip, block, OP(0), OP(1), ADDR(2)),
	doCmovlRM<16>(ip, block, OP(0), OP(1), STD_GLOBAL_OP(2)))
GENERIC_TRANSLATION(CMOVL16rr, doCmovlRR<16>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION_MEM(CMOVL32rm, 
	doCmovlRM<32>(ip, block, OP(0), OP(1), ADDR(2)),
	doCmovlRM<32>(ip, block, OP(0), OP(1), STD_GLOBAL_OP(2)))
GENERIC_TRANSLATION(CMOVL32rr, doCmovlRR<16>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION_MEM(CMOVLE16rm, 
	doCmovleRM<16>(ip, block, OP(0), OP(1), ADDR(2)),
	doCmovleRM<16>(ip, block, OP(0), OP(1), STD_GLOBAL_OP(2)))
GENERIC_TRANSLATION(CMOVLE16rr, doCmovleRR<16>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION_MEM(CMOVLE32rm, 
	doCmovleRM<32>(ip, block, OP(0), OP(1), ADDR(2)),
	doCmovleRM<32>(ip, block, OP(0), OP(1), STD_GLOBAL_OP(2)))
GENERIC_TRANSLATION(CMOVLE32rr, doCmovleRR<32>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION_MEM(CMOVNE16rm, 
	doCmovneRM<16>(ip, block, OP(0), OP(1), ADDR(2)),
	doCmovneRM<16>(ip, block, OP(0), OP(1), STD_GLOBAL_OP(2)))
GENERIC_TRANSLATION(CMOVNE16rr, doCmovneRR<16>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION_MEM(CMOVNE32rm, 
	doCmovneRM<32>(ip, block, OP(0), OP(1), ADDR(2)),
	doCmovneRM<32>(ip, block, OP(0), OP(1), STD_GLOBAL_OP(2)))
GENERIC_TRANSLATION(CMOVNE32rr, doCmovneRR<32>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION_MEM(CMOVNO16rm, 
	doCmovnoRM<16>(ip, block, OP(0), OP(1), ADDR(2)),
	doCmovnoRM<16>(ip, block, OP(0), OP(1), STD_GLOBAL_OP(2)))
GENERIC_TRANSLATION(CMOVNO16rr, doCmovnoRR<16>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION_MEM(CMOVNO32rm, 
	doCmovnoRM<32>(ip, block, OP(0), OP(1), ADDR(2)),
	doCmovnoRM<32>(ip, block, OP(0), OP(1), STD_GLOBAL_OP(2)))
GENERIC_TRANSLATION(CMOVNO32rr, doCmovnoRR<32>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION_MEM(CMOVNP16rm, 
	doCmovnpRM<16>(ip, block, OP(0), OP(1), ADDR(2)),
	doCmovnpRM<16>(ip, block, OP(0), OP(1), STD_GLOBAL_OP(2)))
GENERIC_TRANSLATION(CMOVNP16rr, doCmovnpRR<16>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION_MEM(CMOVNP32rm, 
	doCmovnpRM<32>(ip, block, OP(0), OP(1), ADDR(2)),
	doCmovnpRM<32>(ip, block, OP(0), OP(1), STD_GLOBAL_OP(2)))
GENERIC_TRANSLATION(CMOVNP32rr, doCmovnpRR<32>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION_MEM(CMOVNS16rm, 
	doCmovnsRM<16>(ip, block, OP(0), OP(1), ADDR(2)),
	doCmovnsRM<16>(ip, block, OP(0), OP(1), STD_GLOBAL_OP(2)))
GENERIC_TRANSLATION(CMOVNS16rr, doCmovnsRR<16>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION_MEM(CMOVNS32rm, 
	doCmovnsRM<32>(ip, block, OP(0), OP(1), ADDR(2)),
	doCmovnsRM<32>(ip, block, OP(0), OP(1), STD_GLOBAL_OP(2)))
GENERIC_TRANSLATION(CMOVNS32rr, doCmovnsRR<32>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION_MEM(CMOVO16rm, 
	doCmovoRM<16>(ip, block, OP(0), OP(1), ADDR(2)),
	doCmovoRM<16>(ip, block, OP(0), OP(1), STD_GLOBAL_OP(2)))
GENERIC_TRANSLATION(CMOVO16rr, doCmovoRR<16>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION_MEM(CMOVO32rm, 
	doCmovoRM<32>(ip, block, OP(0), OP(1), ADDR(2)),
	doCmovoRM<32>(ip, block, OP(0), OP(1), STD_GLOBAL_OP(2)))
GENERIC_TRANSLATION(CMOVO32rr, doCmovoRR<32>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION_MEM(CMOVP16rm, 
	doCmovpRM<16>(ip, block, OP(0), OP(1), ADDR(2)),
	doCmovpRM<16>(ip, block, OP(0), OP(1), STD_GLOBAL_OP(2)))
GENERIC_TRANSLATION(CMOVP16rr, doCmovpRR<16>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION_MEM(CMOVP32rm, 
	doCmovpRM<32>(ip, block, OP(0), OP(1), ADDR(2)),
	doCmovpRM<32>(ip, block, OP(0), OP(1), STD_GLOBAL_OP(2)))
GENERIC_TRANSLATION(CMOVP32rr, doCmovpRR<32>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION_MEM(CMOVS16rm, 
	doCmovsRM<16>(ip, block, OP(0), OP(1), ADDR(2)),
	doCmovsRM<16>(ip, block, OP(0), OP(1), STD_GLOBAL_OP(2)))
GENERIC_TRANSLATION(CMOVS16rr, doCmovsRR<16>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION_MEM(CMOVS32rm, 
	doCmovsRM<32>(ip, block, OP(0), OP(1), ADDR(2)),
	doCmovsRM<32>(ip, block, OP(0), OP(1), STD_GLOBAL_OP(2)))
GENERIC_TRANSLATION(CMOVS32rr, doCmovsRR<32>(ip, block, OP(0), OP(1), OP(2)))

void CMOV_populateDispatchMap(DispatchMap &m) {
        m[X86::CMOVA16rm] = translate_CMOVA16rm;
        m[X86::CMOVA16rr] = translate_CMOVA16rr;
        m[X86::CMOVA32rm] = translate_CMOVA32rm;
        m[X86::CMOVA32rr] = translate_CMOVA32rr;
        m[X86::CMOVAE16rm] = translate_CMOVAE16rm;
        m[X86::CMOVAE16rr] = translate_CMOVAE16rr;
        m[X86::CMOVAE32rm] = translate_CMOVAE32rm;
        m[X86::CMOVAE32rr] = translate_CMOVAE32rr;
        m[X86::CMOVB16rm] = translate_CMOVB16rm;
        m[X86::CMOVB16rr] = translate_CMOVB16rr;
        m[X86::CMOVB32rm] = translate_CMOVB32rm;
        m[X86::CMOVB32rr] = translate_CMOVB32rr;
        m[X86::CMOVBE16rm] = translate_CMOVBE16rm;
        m[X86::CMOVBE16rr] = translate_CMOVBE16rr;
        m[X86::CMOVBE32rm] = translate_CMOVBE32rm;
        m[X86::CMOVBE32rr] = translate_CMOVBE32rr;
        m[X86::CMOVE16rm] = translate_CMOVE16rm;
        m[X86::CMOVE16rr] = translate_CMOVE16rr;
        m[X86::CMOVE32rm] = translate_CMOVE32rm;
        m[X86::CMOVE32rr] = translate_CMOVE32rr;
        m[X86::CMOVG16rm] = translate_CMOVG16rm;
        m[X86::CMOVG16rr] = translate_CMOVG16rr;
        m[X86::CMOVG32rm] = translate_CMOVG32rm;
        m[X86::CMOVG32rr] = translate_CMOVG32rr;
        m[X86::CMOVGE16rm] = translate_CMOVGE16rm;
        m[X86::CMOVGE16rr] = translate_CMOVGE16rr;
        m[X86::CMOVGE32rm] = translate_CMOVGE32rm;
        m[X86::CMOVGE32rr] = translate_CMOVGE32rr;
        m[X86::CMOVL16rm] = translate_CMOVL16rm;
        m[X86::CMOVL16rr] = translate_CMOVL16rr;
        m[X86::CMOVL32rm] = translate_CMOVL32rm;
        m[X86::CMOVL32rr] = translate_CMOVL32rr;
        m[X86::CMOVLE16rm] = translate_CMOVLE16rm;
        m[X86::CMOVLE16rr] = translate_CMOVLE16rr;
        m[X86::CMOVLE32rm] = translate_CMOVLE32rm;
        m[X86::CMOVLE32rr] = translate_CMOVLE32rr;
        m[X86::CMOVNE16rm] = translate_CMOVNE16rm;
        m[X86::CMOVNE16rr] = translate_CMOVNE16rr;
        m[X86::CMOVNE32rm] = translate_CMOVNE32rm;
        m[X86::CMOVNE32rr] = translate_CMOVNE32rr;
        m[X86::CMOVNO16rm] = translate_CMOVNO16rm;
        m[X86::CMOVNO16rr] = translate_CMOVNO16rr;
        m[X86::CMOVNO32rm] = translate_CMOVNO32rm;
        m[X86::CMOVNO32rr] = translate_CMOVNO32rr;
        m[X86::CMOVNP16rm] = translate_CMOVNP16rm;
        m[X86::CMOVNP16rr] = translate_CMOVNP16rr;
        m[X86::CMOVNP32rm] = translate_CMOVNP32rm;
        m[X86::CMOVNP32rr] = translate_CMOVNP32rr;
        m[X86::CMOVNS16rm] = translate_CMOVNS16rm;
        m[X86::CMOVNS16rr] = translate_CMOVNS16rr;
        m[X86::CMOVNS32rm] = translate_CMOVNS32rm;
        m[X86::CMOVNS32rr] = translate_CMOVNS32rr;
        m[X86::CMOVO16rm] = translate_CMOVO16rm;
        m[X86::CMOVO16rr] = translate_CMOVO16rr;
        m[X86::CMOVO32rm] = translate_CMOVO32rm;
        m[X86::CMOVO32rr] = translate_CMOVO32rr;
        m[X86::CMOVP16rm] = translate_CMOVP16rm;
        m[X86::CMOVP16rr] = translate_CMOVP16rr;
        m[X86::CMOVP32rm] = translate_CMOVP32rm;
        m[X86::CMOVP32rr] = translate_CMOVP32rr;
        m[X86::CMOVS16rm] = translate_CMOVS16rm;
        m[X86::CMOVS16rr] = translate_CMOVS16rr;
        m[X86::CMOVS32rm] = translate_CMOVS32rm;
        m[X86::CMOVS32rr] = translate_CMOVS32rr;
}
