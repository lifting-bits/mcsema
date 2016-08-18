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
#include "x86Instrs_MULDIV.h"

#define NASSERT(cond) TASSERT(cond, "")

using namespace llvm;
using namespace std;

template <int width>
static void doMulV(InstPtr ip,  BasicBlock  *&b,
                Value       *rhs)
{
    // Handle the different source register depending on the bit width
    Value   *lhs;

    switch(width) {
        case 8:
            lhs = R_READ<8>(b, X86::AL);
            break;
        case 16:
            lhs = R_READ<16>(b, X86::AX);
            break;
        case 32:
            lhs = R_READ<32>(b, X86::EAX);
            break;
        case 64:
            lhs = R_READ<64>(b, X86::RAX);
            break;
        default:
            throw TErr(__LINE__, __FILE__, "Not supported width");
    }

    Type    *dt = Type::getIntNTy(b->getContext(), width*2);
    Value   *a1_x = new ZExtInst(lhs, dt, "", b);
    Value   *a2_x = new ZExtInst(rhs, dt, "", b);
    Value   *tmp = BinaryOperator::Create(Instruction::Mul, a1_x, a2_x, "", b);
   
    Type    *t = Type::getIntNTy(b->getContext(), width);
    Value   *res_sh = BinaryOperator::Create(Instruction::LShr, tmp, CONST_V<width*2>(b, width), "", b);
    Value   *wrAX = new TruncInst(tmp, t, "", b);
    Value   *wrDX = new TruncInst(res_sh, t, "", b);

    // set clear CF and OF if DX is clear, set if DX is set
    Value   *r = new ICmpInst(*b, CmpInst::ICMP_NE, wrDX, CONST_V<width>(b, 0));

    F_WRITE(b, CF, r);
    F_WRITE(b, OF, r);

    switch(width) {
        case 8:
            R_WRITE<width>(b, X86::AH, wrDX);
            R_WRITE<width>(b, X86::AL, wrAX);
            break;
        case 16:
            R_WRITE<width>(b, X86::DX, wrDX);
            R_WRITE<width>(b, X86::AX, wrAX);
            break;
        case 32:
            R_WRITE<width>(b, X86::EDX, wrDX);
            R_WRITE<width>(b, X86::EAX, wrAX);
            break;
        case 64:
            R_WRITE<width>(b, X86::RDX, wrDX);
            R_WRITE<width>(b, X86::RAX, wrAX);
            break;
        default:
            throw TErr(__LINE__, __FILE__, "Not supported width");
    }

}

template <int width>
static Value *doIMulV(InstPtr ip,  BasicBlock  *&b,
                Value       *rhs)
{
    // Handle the different source register depending on the bit width
    Value   *lhs;

    switch(width) {
        case 8:
            lhs = R_READ<8>(b, X86::AL);
            break;
        case 16:
            lhs = R_READ<16>(b, X86::AX);
            break;
        case 32:
            lhs = R_READ<32>(b, X86::EAX);
            break;
        case 64:
            lhs = R_READ<64>(b, X86::RAX);
            break;
        default:
            throw TErr(__LINE__, __FILE__, "Not supported width");
    }

    //model the semantics of the signed multiply
    Value   *a1 = lhs;
    Value   *a2 = rhs;

    Type    *dt = Type::getIntNTy(b->getContext(), width*2);
    Value   *a1_x = new SExtInst(a1, dt, "", b);
    Value   *a2_x = new SExtInst(a2, dt, "", b);
    Value   *tmp = BinaryOperator::Create(Instruction::Mul, a1_x, a2_x, "", b);
    Value   *dest = BinaryOperator::Create(Instruction::Mul, a1, a2, "", b);
   
    //R_WRITE<width>(b, dst.getReg(), dest);

    Value   *dest_x = new SExtInst(dest, dt, "", b);
    Value   *r = new ICmpInst(*b, CmpInst::ICMP_NE, dest_x, tmp);

    F_WRITE(b, CF, r);
    F_WRITE(b, OF, r);

    return tmp;
}

template <int width>
static InstTransResult doMulR(InstPtr ip,    BasicBlock *&b, 
                           const MCOperand &src)
{
    NASSERT(src.isReg());

    doMulV<width>(ip, b, R_READ<width>(b, src.getReg()));

    return ContinueBlock;
}

template <int width>
static InstTransResult doMulM(InstPtr ip,    BasicBlock *&b, 
                           Value *memAddr)
{
    NASSERT(memAddr != NULL);

    doMulV<width>(ip, b, M_READ<width>(ip, b, memAddr));

    return ContinueBlock;
}

template <int width>
static InstTransResult doIMulR(InstPtr ip,    BasicBlock *&b, 
                           const MCOperand &src)
{
    NASSERT(src.isReg());

    Value   *res = doIMulV<width>(ip, b, R_READ<width>(b, src.getReg()));

    Type    *t = Type::getIntNTy(b->getContext(), width);
    Value   *res_sh = BinaryOperator::Create(Instruction::LShr, res, CONST_V<width*2>(b, width), "", b);
    Value   *wrAX = new TruncInst(res, t, "", b);
    Value   *wrDX = new TruncInst(res_sh, t, "", b);

    switch(width) {
        case 8:
            R_WRITE<width>(b, X86::AH, wrDX);
            R_WRITE<width>(b, X86::AL, wrAX);
            break;
        case 16:
            R_WRITE<width>(b, X86::DX, wrDX);
            R_WRITE<width>(b, X86::AX, wrAX);
            break;
        case 32:
            R_WRITE<width>(b, X86::EDX, wrDX);
            R_WRITE<width>(b, X86::EAX, wrAX);
            break;
        case 64:
            R_WRITE<width>(b, X86::RDX, wrDX);
            R_WRITE<width>(b, X86::RAX, wrAX);
            break;
        default:
            throw TErr(__LINE__, __FILE__, "Not supported width");
    }
    
    return ContinueBlock;
}

template <int width>
static InstTransResult doIMulM(InstPtr ip,     BasicBlock      *&b,
                            Value           *memAddr)
{
    NASSERT(memAddr != NULL);

    Value   *res = doIMulV<width>(ip, b, M_READ<width>(ip, b, memAddr));

    Type    *t = Type::getIntNTy(b->getContext(), width);
    Value   *res_sh = BinaryOperator::Create(Instruction::LShr, res, CONST_V<width*2>(b, width), "", b);
    Value   *wrAX = new TruncInst(res, t, "", b);
    Value   *wrDX = new TruncInst(res_sh, t, "", b);

    switch(width) {
        case 8:
            R_WRITE<width>(b, X86::AX, res);
            break;
        case 16:
            R_WRITE<width>(b, X86::DX, wrDX);
            R_WRITE<width>(b, X86::AX, wrAX);
            break;
        case 32:
            R_WRITE<width>(b, X86::EDX, wrDX);
            R_WRITE<width>(b, X86::EAX, wrAX);
            break;
        case 64:
            R_WRITE<width>(b, X86::RDX, wrDX);
            R_WRITE<width>(b, X86::RAX, wrAX);
            break;
        default:
            throw new TErr(__LINE__, __FILE__, "Not supported width");
    }

    return ContinueBlock;
}

template <int width>
static Value *doIMulVV(InstPtr ip,     BasicBlock  *&b,
                Value       *lhs,
                Value       *rhs)
{
    //model the semantics of the signed multiply
    Value   *a1 = lhs;
    Value   *a2 = rhs;

    Type    *dt = Type::getIntNTy(b->getContext(), width*2);
    Value   *a1_x = new SExtInst(a1, dt, "", b);
    Value   *a2_x = new SExtInst(a2, dt, "", b);
    Value   *tmp = BinaryOperator::Create(Instruction::Mul, a1_x, a2_x, "", b);
    Value   *dest = BinaryOperator::Create(Instruction::Mul, a1, a2, "", b);
   

    Value   *dest_x = new SExtInst(dest, dt, "", b);
    Value   *r = new ICmpInst(*b, CmpInst::ICMP_NE, dest_x, tmp);

    F_WRITE(b, SF, r);
    F_WRITE(b, OF, r);

    return dest;
}

template <int width>
static InstTransResult doIMulRM(InstPtr ip,    BasicBlock      *&b,
                            const MCOperand &dst,
                            const MCOperand &lhs,
                            Value           *rhs)
{
    NASSERT(dst.isReg());
    NASSERT(lhs.isReg());
    NASSERT(rhs != NULL);

    Value   *res = 
        doIMulVV<width>(ip, b,
                        R_READ<width>(b, lhs.getReg()),
                        M_READ<width>(ip, b, rhs));

    R_WRITE<width>(b, dst.getReg(), res);

    return ContinueBlock;
}

template <int width>
static InstTransResult doIMulRR(InstPtr ip,    BasicBlock *&b,
                            const MCOperand &dst, 
                            const MCOperand &lhs, 
                            const MCOperand &rhs)
{
    NASSERT(dst.isReg());
    NASSERT(lhs.isReg());
    NASSERT(rhs.isReg());

    Value *res = 
        doIMulVV<width>(ip, b, 
                        R_READ<width>(b, lhs.getReg()), 
                        R_READ<width>(b, rhs.getReg()));
    //write out the result
    R_WRITE<width>(b, dst.getReg(), res);
    
    return ContinueBlock;
}

template <int width>
static Value *doIMulVVV(InstPtr ip,    BasicBlock  *&b,
                Value       *lhs,
                Value       *rhs)
{
    //model the semantics of the signed multiply
    Value   *a1 = lhs;
    Value   *a2 = rhs;

    Type    *dt = Type::getIntNTy(b->getContext(), width*2);
    Value   *a1_x = new SExtInst(a1, dt, "", b);
    Value   *a2_x = new SExtInst(a2, dt, "", b);
    Value   *tmp = BinaryOperator::Create(Instruction::Mul, a1_x, a2_x, "", b);
    Value   *dest = BinaryOperator::Create(Instruction::Mul, a1, a2, "", b);
   
    //R_WRITE<width>(b, dst.getReg(), dest);

    Value   *dest_x = new SExtInst(dest, dt, "", b);
    Value   *r = new ICmpInst(*b, CmpInst::ICMP_NE, dest_x, tmp);

    F_WRITE(b, SF, r);
    F_WRITE(b, OF, r);

    return dest;
}

template <int width>
static InstTransResult doIMulRMI(InstPtr ip,   BasicBlock      *&b,
                            const MCOperand &dst,
                            Value           *lhs,
                            const MCOperand &rhs)
{
    NASSERT(dst.isReg());
    NASSERT(lhs != NULL);
    NASSERT(rhs.isImm());

    Value   *res = 
        doIMulVVV<width>(ip, b,
                        M_READ<width>(ip, b, lhs),
                        CONST_V<width>(b, rhs.getImm()));

    R_WRITE<width>(b, dst.getReg(), res);

    return ContinueBlock;
}

template <int width>
static InstTransResult doIMulRRI(InstPtr ip,   BasicBlock      *&b,
                            const MCOperand &dst,
                            const MCOperand &lhs,
                            const MCOperand &rhs)
{
    NASSERT(dst.isReg());
    NASSERT(lhs.isReg());
    NASSERT(rhs.isImm());

    Value   *res = 
        doIMulVVV<width>(ip, b,
                        R_READ<width>(b, lhs.getReg()),
                        CONST_V<width>(b, rhs.getImm()));

    R_WRITE<width>(b, dst.getReg(), res);

    return ContinueBlock;
}

template <int width>
static InstTransResult doIMulRRV(InstPtr ip,   BasicBlock      *&b,
                            Value *addr,
                            const MCOperand &lhs,
                            const MCOperand &dst)
{
    NASSERT(dst.isReg());
    NASSERT(lhs.isReg());

    Value   *res = 
        doIMulVVV<width>(ip, b,
                        R_READ<width>(b, lhs.getReg()),
                        addr);

    R_WRITE<width>(b, dst.getReg(), res);

    return ContinueBlock;
}


template <int width>
static InstTransResult doIMulRMI8(InstPtr ip,  BasicBlock      *&b,
                            const MCOperand &dst,
                            Value           *lhs,
                            const MCOperand &rhs)
{
    NASSERT(dst.isReg());
    NASSERT(lhs != NULL);
    NASSERT(rhs.isImm());

    Value   *vRhs = CONST_V<8>(b, rhs.getImm());
    Type    *sx = Type::getIntNTy(b->getContext(), width);
    Value   *vRhs_x = new SExtInst(vRhs, sx, "", b); 

    Value   *res = 
        doIMulVVV<width>(ip, b,
                        M_READ<width>(ip, b, lhs),
                        vRhs_x);

    R_WRITE<width>(b, dst.getReg(), res);

    return ContinueBlock;
}

template <int width>
static InstTransResult doIMulRRI8(InstPtr ip,  BasicBlock      *&b,
                            const MCOperand &dst,
                            const MCOperand &lhs,
                            const MCOperand &rhs)
{
    NASSERT(dst.isReg());
    NASSERT(lhs.isReg());
    NASSERT(rhs.isImm());

    Value   *vRhs = CONST_V<8>(b, rhs.getImm());
    Type    *sx = Type::getIntNTy(b->getContext(), width);
    Value   *vRhs_x = new SExtInst(vRhs, sx, "", b); 

    Value   *res = 
        doIMulVVV<width>(ip, b,
                        R_READ<width>(b, lhs.getReg()),
                        vRhs_x);

    R_WRITE<width>(b, dst.getReg(), res);

    return ContinueBlock;
}

template <int width>
static InstTransResult doDivV(InstPtr ip, BasicBlock *&b, Value *divisor, 
        llvm::Instruction::BinaryOps whichdiv) {

    //read in EDX and EAX
    Value   *ax;
    Value   *dx;

    switch(width) {
        case 8:
            ax = R_READ<8>(b, X86::AL);
            dx = R_READ<8>(b, X86::AH);
            break;
        case 16:
            ax = R_READ<16>(b, X86::AX);
            dx = R_READ<16>(b, X86::DX);
            break;
        case 32:
            ax = R_READ<32>(b, X86::EAX);
            dx = R_READ<32>(b, X86::EDX);
            break;
        case 64:
            ax = R_READ<64>(b, X86::RAX);
            dx = R_READ<64>(b, X86::RDX);
            break;
        default:
            throw TErr(__LINE__, __FILE__, "Not supported width");
    }

    Value   *dividend = concatInts<width>(b, dx, ax);

    // tmp <- EDX:EAX / divisor 
    // but first, extend divisor
    Type    *text = Type::getIntNTy(b->getContext(), width*2);
    Type    *t = Type::getIntNTy(b->getContext(), width);

    Value   *divisorext = nullptr;
    switch(whichdiv) {

        case Instruction::SDiv:
            divisorext = new SExtInst(divisor, text, "", b);
            break;
        case Instruction::UDiv:
            divisorext = new ZExtInst(divisor, text, "", b);
            break;
        default:
            throw TErr(__LINE__, __FILE__, "Invalid operation given to doDivV");
    }

    //EAX <- tmp
    Value   *res;
    Value   *mod;
    Instruction::BinaryOps modop;
    switch(whichdiv) {
        case Instruction::SDiv:
            modop = Instruction::SRem;
            break;
        case Instruction::UDiv:
            modop = Instruction::URem;
            break;
        default:
            throw TErr(__LINE__, __FILE__, "Invalid operation given to doDivV");
    };
    res = 
      BinaryOperator::Create(whichdiv, dividend, divisorext, "", b);

    //EDX <- EDX:EAX mod divisor
    mod = 
      BinaryOperator::Create(modop, dividend, divisorext, "", b);

    Value   *wrDx = new TruncInst(mod, t, "", b);
    Value   *wrAx = new TruncInst(res, t, "", b);

    switch(width) {
        case 8:
            R_WRITE<8>(b, X86::AH, wrDx);
            R_WRITE<8>(b, X86::AL, wrAx);
            break;
        case 16:
            R_WRITE<16>(b, X86::DX, wrDx);
            R_WRITE<16>(b, X86::AX, wrAx);
            break;
        case 32:
            R_WRITE<32>(b, X86::EDX, wrDx);
            R_WRITE<32>(b, X86::EAX, wrAx);
            break;
        case 64:
            R_WRITE<64>(b, X86::RDX, wrDx);
            R_WRITE<64>(b, X86::RAX, wrAx);
            break;
        default:
            throw TErr(__LINE__, __FILE__, "Not supported width");
    }

    return ContinueBlock;
}

template <int width>
static InstTransResult doIDivR(InstPtr ip,  BasicBlock *&b,
                        const MCOperand &div)
{
    NASSERT(div.isReg());

    Value   *reg_v = R_READ<width>(b, div.getReg());

    doDivV<width>(ip, b, reg_v, Instruction::SDiv);

    return ContinueBlock;
}

template <int width>
static InstTransResult doIDivM(InstPtr ip, BasicBlock *&b, Value *memLoc) {
    NASSERT(memLoc != NULL);

    Value   *from_mem = M_READ<width>(ip, b, memLoc);

    doDivV<width>(ip, b, from_mem, Instruction::SDiv);

    return ContinueBlock;
}

template <int width>
static InstTransResult doDivR(InstPtr ip,  BasicBlock *&b,
                        const MCOperand &div)
{
    NASSERT(div.isReg());

    Value   *reg_v = R_READ<width>(b, div.getReg());

    doDivV<width>(ip, b, reg_v, Instruction::UDiv);

    return ContinueBlock;
}

template <int width>
static InstTransResult doDivM(InstPtr ip, BasicBlock *&b, Value *memLoc) {
    NASSERT(memLoc != NULL);

    Value   *from_mem = M_READ<width>(ip, b, memLoc);

    doDivV<width>(ip, b, from_mem, Instruction::UDiv);

    return ContinueBlock;
}
/* GOOD */
GENERIC_TRANSLATION_REF(IMUL32rm, 
    doIMulRM<32>(ip,  block, OP(0), OP(1), ADDR_NOREF(2)),
    doIMulRM<32>(ip,  block, OP(0), OP(1), MEM_REFERENCE(2)))
GENERIC_TRANSLATION_REF(IMUL64rm,
    doIMulRM<64>(ip,  block, OP(0), OP(1), ADDR_NOREF(2)),
    doIMulRM<64>(ip,  block, OP(0), OP(1), MEM_REFERENCE(2)))
GENERIC_TRANSLATION_REF(IMUL16rm, 
    doIMulRM<16>(ip,  block, OP(0), OP(1), ADDR_NOREF(2)),
    doIMulRM<16>(ip,  block, OP(0), OP(1), MEM_REFERENCE(2)))
GENERIC_TRANSLATION(IMUL8r, doIMulR<8>(ip, block, OP(0)))
GENERIC_TRANSLATION_REF(IMUL8m, 
    doIMulM<8>(ip, block, ADDR_NOREF(0)),
    doIMulM<8>(ip, block, MEM_REFERENCE(0)))
GENERIC_TRANSLATION(IMUL16r, doIMulR<16>(ip, block, OP(0)))
GENERIC_TRANSLATION_REF(IMUL16m, 
    doIMulM<16>(ip, block, ADDR_NOREF(0)),
    doIMulM<16>(ip, block, MEM_REFERENCE(0)))
GENERIC_TRANSLATION(IMUL32r, doIMulR<32>(ip, block, OP(0)))
GENERIC_TRANSLATION(MUL32r, doMulR<32>(ip, block, OP(0)))
GENERIC_TRANSLATION(MUL64r, doMulR<64>(ip, block, OP(0)))
GENERIC_TRANSLATION_REF(MUL32m, 
    doMulM<32>(ip, block, ADDR_NOREF(0)),
    doMulM<32>(ip, block, MEM_REFERENCE(0)))
GENERIC_TRANSLATION_REF(MUL64m, 
    doMulM<64>(ip, block, ADDR_NOREF(0)),
    doMulM<64>(ip, block, MEM_REFERENCE(0)))
GENERIC_TRANSLATION(MUL16r, doMulR<16>(ip, block, OP(0)))
GENERIC_TRANSLATION_REF(MUL16m, 
    doMulM<16>(ip, block, ADDR_NOREF(0)),
    doMulM<16>(ip, block, MEM_REFERENCE(0)))
GENERIC_TRANSLATION(MUL8r, doMulR<8>(ip, block, OP(0)))
GENERIC_TRANSLATION_REF(MUL8m, 
    doMulM<8>(ip, block, ADDR_NOREF(0)),
    doMulM<8>(ip, block, MEM_REFERENCE(0)))
GENERIC_TRANSLATION_REF(IMUL32m, 
    doIMulM<32>(ip, block, ADDR_NOREF(0)),
    doIMulM<32>(ip, block, MEM_REFERENCE(0)))
GENERIC_TRANSLATION_REF(IMUL64m, 
    doIMulM<64>(ip, block, ADDR_NOREF(0)),
    doIMulM<64>(ip, block, MEM_REFERENCE(0)))
GENERIC_TRANSLATION(IMUL32rr, doIMulRR<32>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION(IMUL64rr, doIMulRR<64>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION(IMUL64r, doIMulR<64>(ip, block, OP(0)))
GENERIC_TRANSLATION(IMUL16rr, doIMulRR<16>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION_REF(IMUL16rmi, 
    doIMulRMI<16>(ip, block, OP(0), ADDR_NOREF(1), OP(6)),
    doIMulRMI<16>(ip, block, OP(0), MEM_REFERENCE(1), OP(6)))
GENERIC_TRANSLATION_REF(IMUL16rmi8, 
    doIMulRMI8<16>(ip, block, OP(0), ADDR_NOREF(1), OP(6)),
    doIMulRMI8<16>(ip, block, OP(0), MEM_REFERENCE(1), OP(6)))
GENERIC_TRANSLATION(IMUL16rri, doIMulRRI<16>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION(IMUL16rri8, doIMulRRI<16>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION_REF(IMUL32rmi, 
    doIMulRMI<32>(ip, block, OP(0), ADDR_NOREF(1), OP(6)),
    doIMulRMI<32>(ip, block, OP(0), MEM_REFERENCE(1), OP(6)))
GENERIC_TRANSLATION_REF(IMUL32rmi8, 
    doIMulRMI8<32>(ip, block, OP(0), ADDR_NOREF(1), OP(6)),
    doIMulRMI8<32>(ip, block, OP(0), MEM_REFERENCE(1), OP(6)))
GENERIC_TRANSLATION_REF(IMUL64rmi8, 
    doIMulRMI8<64>(ip, block, OP(0), ADDR_NOREF(1), OP(6)),
    doIMulRMI8<64>(ip, block, OP(0), MEM_REFERENCE(1), OP(6)))
GENERIC_TRANSLATION(IMUL32rri, doIMulRRI<32>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION(IMUL32rri8, doIMulRRI<32>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION(IMUL64rri8, doIMulRRI<64>(ip, block, OP(0), OP(1), OP(2)))
//GENERIC_TRANSLATION(IMUL64rri32, doIMulRRI<64>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION_REF(IMUL64rri32,
        doIMulRRI<64>(ip, block, OP(0), OP(1), OP(2)),
        doIMulRRV<64>(ip, block, IMM_AS_DATA_REF(block, natM, ip), OP(0), OP(1)))
/* END GOOD */
GENERIC_TRANSLATION(IDIV8r, doIDivR<8>(ip, block, OP(0)))
GENERIC_TRANSLATION(IDIV16r, doIDivR<16>(ip, block, OP(0)))
GENERIC_TRANSLATION(IDIV32r, doIDivR<32>(ip, block, OP(0)))
GENERIC_TRANSLATION(IDIV64r, doIDivR<64>(ip, block, OP(0)))
GENERIC_TRANSLATION_REF(IDIV8m, 
    doIDivM<8>(ip,    block, ADDR_NOREF(0)),
    doIDivM<8>(ip,    block, MEM_REFERENCE(0)))
GENERIC_TRANSLATION_REF(IDIV16m, 
    doIDivM<16>(ip,   block, ADDR_NOREF(0)),
    doIDivM<16>(ip,   block, MEM_REFERENCE(0)))
GENERIC_TRANSLATION_REF(IDIV32m, 
    doIDivM<32>(ip,   block, ADDR_NOREF(0)),
    doIDivM<32>(ip,   block, MEM_REFERENCE(0)))
GENERIC_TRANSLATION_REF(IDIV64m,
  doIDivM<64>(ip,   block, ADDR_NOREF(0)),
  doIDivM<64>(ip,   block, MEM_REFERENCE(0)))

GENERIC_TRANSLATION(DIV8r, doDivR<8>(ip, block, OP(0)))
GENERIC_TRANSLATION(DIV16r, doDivR<16>(ip, block, OP(0)))
GENERIC_TRANSLATION(DIV32r, doDivR<32>(ip, block, OP(0)))
GENERIC_TRANSLATION(DIV64r, doDivR<64>(ip, block, OP(0)))
GENERIC_TRANSLATION_REF(DIV8m, 
    doDivM<8>(ip,    block, ADDR_NOREF(0)),
    doDivM<8>(ip,    block, MEM_REFERENCE(0)))
GENERIC_TRANSLATION_REF(DIV16m, 
    doDivM<16>(ip,   block, ADDR_NOREF(0)),
    doDivM<16>(ip,   block, MEM_REFERENCE(0)))
GENERIC_TRANSLATION_REF(DIV32m, 
    doDivM<32>(ip,   block, ADDR_NOREF(0)),
    doDivM<32>(ip,   block, MEM_REFERENCE(0)))
GENERIC_TRANSLATION_REF(DIV64m, 
    doDivM<64>(ip,   block, ADDR_NOREF(0)),
    doDivM<64>(ip,   block, MEM_REFERENCE(0)))

void MULDIV_populateDispatchMap(DispatchMap &m) {

    m[X86::IMUL32rm] = translate_IMUL32rm;
    m[X86::IMUL64rm] = translate_IMUL64rm;
    m[X86::IMUL16rm] = translate_IMUL16rm;
    m[X86::IMUL8r] = translate_IMUL8r;
    m[X86::IMUL8m] = translate_IMUL8m;
    m[X86::IMUL16r] = translate_IMUL16r;
    m[X86::IMUL16m] = translate_IMUL16m;
    m[X86::MUL32r] = translate_MUL32r;
    m[X86::MUL64r] = translate_MUL64r;
    m[X86::MUL32m] = translate_MUL32m;
    m[X86::MUL64m] = translate_MUL64m;
    m[X86::MUL16r] = translate_MUL16r;
    m[X86::MUL16m] = translate_MUL16m;
    m[X86::MUL8r] = translate_MUL8r;
    m[X86::MUL8m] = translate_MUL8m;
    m[X86::IMUL32r] = translate_IMUL32r;
    m[X86::IMUL32m] = translate_IMUL32m;
    m[X86::IMUL64m] = translate_IMUL64m;
    m[X86::IMUL32rr] = translate_IMUL32rr;
    m[X86::IMUL16rr] = translate_IMUL16rr;
    m[X86::IMUL16rmi] = translate_IMUL16rmi;
    m[X86::IMUL16rmi8] = translate_IMUL16rmi8;
    m[X86::IMUL16rri] = translate_IMUL16rri;
    m[X86::IMUL16rri8] = translate_IMUL16rri8;
    m[X86::IMUL32rmi] = translate_IMUL32rmi;
    m[X86::IMUL32rmi8] = translate_IMUL32rmi8;
    m[X86::IMUL64rmi8] = translate_IMUL64rmi8;
    m[X86::IMUL32rri] = translate_IMUL32rri;
    m[X86::IMUL32rri8] = translate_IMUL32rri8;
    m[X86::IMUL64rri8] = translate_IMUL64rri8;
    m[X86::IMUL64rri32] = translate_IMUL64rri32;
    m[X86::IMUL64rr] = translate_IMUL64rr;
    m[X86::IMUL64r] = translate_IMUL64r;

    m[X86::IDIV8r] = translate_IDIV8r;
    m[X86::IDIV16r] = translate_IDIV16r;
    m[X86::IDIV32r] = translate_IDIV32r;
    m[X86::IDIV64r] = translate_IDIV64r;
    m[X86::IDIV8m] = translate_IDIV8m;
    m[X86::IDIV16m] = translate_IDIV16m;
    m[X86::IDIV32m] = translate_IDIV32m;
    m[X86::IDIV64m] = translate_IDIV64m;
    m[X86::DIV8r] = translate_DIV8r;
    m[X86::DIV16r] = translate_DIV16r;
    m[X86::DIV32r] = translate_DIV32r;
    m[X86::DIV64r] = translate_DIV64r;
    m[X86::DIV8m] = translate_DIV8m;
    m[X86::DIV16m] = translate_DIV16m;
    m[X86::DIV32m] = translate_DIV32m;
    m[X86::DIV64m] = translate_DIV64m;
}
