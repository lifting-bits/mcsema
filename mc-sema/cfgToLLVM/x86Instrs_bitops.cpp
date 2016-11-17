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
#include "x86Instrs_flagops.h"
#include "x86Instrs_bitops.h"
#include "llvm/Support/Debug.h"

using namespace llvm;

template <int width>
static Value * doAndVV(BasicBlock *&b, Value *o1, Value *o2)
{
    // Do the operation.
    Value *result = BinaryOperator::Create(Instruction::And, o1, o2, "", b);

    // Update flags.
    WriteSF<width>(b, result);
    WriteZF<width>(b, result);
    WritePF<width>(b, result);
    F_CLEAR(b, OF);
    F_CLEAR(b, CF);
    F_ZAP(b, AF);

    return result;
}

Value *doAndVV32(BasicBlock *&b, Value *o1, Value *o2)
{
    return doAndVV<32>(b, o1, o2);
}

template <int width>
static Value * doAndVV(InstPtr ip, BasicBlock *&b, Value *o1, Value *o2)
{
    return doAndVV<width>(b, o1, o2);
}

template <int width>
static InstTransResult doAndMI(InstPtr ip, BasicBlock *&b,
                               Value           *addr,
                               const MCOperand &imm)
{
    TASSERT(addr != NULL, "");
    TASSERT(imm.isImm(), "");

    Value *fromMem = M_READ<width>(ip, b, addr);
    Value *fromImm = CONST_V<width>(b, imm.getImm());

    Value *res = doAndVV<width>(ip, b, fromMem, fromImm);

    M_WRITE<width>(ip, b, addr, res);

    return ContinueBlock;
}

template <int width>
static InstTransResult doAndMV(InstPtr ip, BasicBlock *&b,
                               Value           *addr,
                               Value           *rhs)
{
    TASSERT(addr != NULL, "");
    TASSERT(rhs != NULL, "");

    Value *fromMem = M_READ<width>(ip, b, addr);

    Value *res = doAndVV<width>(ip, b, fromMem, rhs);

    M_WRITE<width>(ip, b, addr, res);

    return ContinueBlock;
}

template <int width>
static InstTransResult doAndMR(InstPtr ip, BasicBlock *&b,
                               Value           *addr,
                               const MCOperand &src)
{
    TASSERT(addr != NULL, "");
    TASSERT(src.isReg(), "");

    Value *addr_v = M_READ<width>(ip, b, addr);
    Value *reg_v = R_READ<width>(b, src.getReg());

    Value *res = doAndVV<width>(ip, b, addr_v, reg_v);

    M_WRITE<width>(ip, b, addr, res);

    return ContinueBlock;
}

template <int width>
static InstTransResult doAndRI(InstPtr ip, BasicBlock *&b,
                               const MCOperand &dst,
                               const MCOperand &o1,
                               const MCOperand &o2)
{
    TASSERT(dst.isReg(), "");
    TASSERT(o1.isReg(), "");
    TASSERT(o2.isImm(), "");

    Value *o1_v = R_READ<width>(b, o1.getReg());
    Value *o2_v = CONST_V<width>(b, o2.getImm());

    R_WRITE<width>(b, dst.getReg(), doAndVV<width>(ip, b, o1_v, o2_v));

    return ContinueBlock;
}

template <int width>
static InstTransResult doAndRV(InstPtr ip, BasicBlock *&b,
                               Value *addr,
                               const MCOperand &o1,
                               const MCOperand &o2)
{
    TASSERT(o2.isReg(), "");
    TASSERT(o1.isReg(), "");

    Value *o1_v = R_READ<width>(b, o1.getReg());

    R_WRITE<width>(b, o2.getReg(), doAndVV<width>(ip, b, o1_v, addr));

    return ContinueBlock;
}

template <int width>
static InstTransResult doAndRM(InstPtr ip, BasicBlock *&b,
                               Value           *addr,
                               const MCOperand &o1,
                               const MCOperand &dst)
{
    TASSERT(dst.isReg(), "");
    TASSERT(addr != NULL, "");
    TASSERT(o1.isReg(), "");

    Value *addr_v = M_READ<width>(ip, b, addr);
    Value *o1_v = R_READ<width>(b, o1.getReg());

    R_WRITE<width>(b, dst.getReg(), doAndVV<width>(ip, b, addr_v, o1_v));

    return ContinueBlock;
}

template <int width>
static InstTransResult doAndRR(InstPtr ip, BasicBlock *&b,
                               const MCOperand &dst,
                               const MCOperand &o1,
                               const MCOperand &o2)
{
    TASSERT(dst.isReg(), "");
    TASSERT(o1.isReg(), "");
    TASSERT(o2.isReg(), "");

    Value *o1_v = R_READ<width>(b, o1.getReg());
    Value *o2_v = R_READ<width>(b, o2.getReg());

    R_WRITE<width>(b, dst.getReg(), doAndVV<width>(ip, b, o1_v, o2_v));

    return ContinueBlock;
}

template <int width>
static Value * doNotV(InstPtr ip, BasicBlock *&b, Value *v)
{
    TASSERT(v != NULL, "");

    Value *highest = NULL;

    switch (width)
    {
        case 8:
            highest = CONST_V<width>(b, 0xFFU);
            break;

        case 16:
            highest = CONST_V<width>(b, 0xFFFFU);
            break;

        case 32:
            highest = CONST_V<width>(b, 0xFFFFFFFFUL);
            break;

        case 64:
            highest = CONST_V<width>(b, 0xFFFFFFFFFFFFFFFFULL);
            break;
    }

    // We can do this by 0xffff - v in the two's complement machine.
    Value *res = BinaryOperator::CreateSub(highest, v, "", b);

    // No flags affected.

    return res;
}

template <int width>
static InstTransResult doNotM(InstPtr ip, BasicBlock *&b, Value *a)
{
    TASSERT(a != NULL, "");

    Value *m = M_READ<width>(ip, b, a);

    Value *res = doNotV<width>(ip, b, m);

    M_WRITE<width>(ip, b, a, res);

    return ContinueBlock;
}

template <int width>
static InstTransResult doNotR(InstPtr ip, BasicBlock *&b, const MCOperand &o)
{
    TASSERT(o.isReg(), "");

    Value *r = R_READ<width>(b, o.getReg());

    Value *res = doNotV<width>(ip, b, r);

    R_WRITE<width>(b, o.getReg(), res);

    return ContinueBlock;
}

template <int width>
static Value * doOrVV(InstPtr ip, BasicBlock *&b, Value *o1, Value *o2)
{
    // Do the operation.
    Value *result = BinaryOperator::Create(Instruction::Or, o1, o2, "", b);

    // Set flags.
    F_ZAP(b, AF);
    F_CLEAR(b, OF);
    F_CLEAR(b, CF);
    WriteSF<width>(b, result);
    WriteZF<width>(b, result);
    WritePF<width>(b, result);

    return result;
}

template <int width>
static InstTransResult doOrMI(InstPtr ip, BasicBlock *&b,
                              Value           *addr,
                              const MCOperand &imm)
{
    TASSERT(addr != NULL, "");
    TASSERT(imm.isImm(), "");

    Value *fromMem = M_READ<width>(ip, b, addr);
    Value *fromImm = CONST_V<width>(b, imm.getImm());

    Value *res = doOrVV<width>(ip, b, fromMem, fromImm);

    M_WRITE<width>(ip, b, addr, res);

    return ContinueBlock;
}

template <int width>
static InstTransResult doOrMV(InstPtr ip, BasicBlock *&b,
                              Value           *addr,
                              Value           *rhs)
{
    TASSERT(addr != NULL, "");
    TASSERT(rhs != NULL, "");

    Value *fromMem = M_READ<width>(ip, b, addr);

    Value *res = doOrVV<width>(ip, b, fromMem, rhs);

    M_WRITE<width>(ip, b, addr, res);

    return ContinueBlock;
}

template <int width>
static InstTransResult doOrMR(InstPtr ip, BasicBlock *&b,
                              Value           *addr,
                              const MCOperand &src)
{
    TASSERT(addr != NULL, "");
    TASSERT(src.isReg(), "");

    Value *addr_v = M_READ<width>(ip, b, addr);
    Value *reg_v = R_READ<width>(b, src.getReg());

    Value *res = doOrVV<width>(ip, b, addr_v, reg_v);

    M_WRITE<width>(ip, b, addr, res);

    return ContinueBlock;
}

template <int width>
static InstTransResult doOrRI(InstPtr ip, BasicBlock *&b,
                              const MCOperand &dst,
                              const MCOperand &o1,
                              const MCOperand &o2)
{
    TASSERT(dst.isReg(), "");
    TASSERT(o1.isReg(), "");
    TASSERT(o2.isImm(), "");

    Value *o1_v = R_READ<width>(b, o1.getReg());
    Value *o2_v = CONST_V<width>(b, o2.getImm());

    R_WRITE<width>(b, dst.getReg(), doOrVV<width>(ip, b, o1_v, o2_v));

    return ContinueBlock;
}

template <int width>
static InstTransResult doOrRV(InstPtr ip, BasicBlock *&b,
                              Value *addr,
                              const MCOperand &o1,
                              const MCOperand &o2)
{
    TASSERT(o2.isReg(), "");
    TASSERT(o1.isReg(), "");

    Value *o1_v = R_READ<width>(b, o1.getReg());

    R_WRITE<width>(b, o2.getReg(), doOrVV<width>(ip, b, o1_v, addr));

    return ContinueBlock;
}

template <int width>
static InstTransResult doOrRM(InstPtr ip, BasicBlock *&b,
                              Value           *addr,
                              const MCOperand &o1,
                              const MCOperand &dst)
{
    TASSERT(addr != NULL, "");
    TASSERT(o1.isReg(), "");
    TASSERT(dst.isReg(), "");

    Value *addr_v = M_READ<width>(ip, b, addr);
    Value *o1_v = R_READ<width>(b, o1.getReg());

    R_WRITE<width>(b, dst.getReg(), doOrVV<width>(ip, b, addr_v, o1_v));

    return ContinueBlock;
}

template <int width>
static InstTransResult doOrRR(InstPtr ip, BasicBlock *&b,
                              const MCOperand &dst,
                              const MCOperand &o1,
                              const MCOperand &o2)
{
    TASSERT(dst.isReg(), "");
    TASSERT(o1.isReg(), "");
    TASSERT(o2.isReg(), "");

    Value *o1_v = R_READ<width>(b, o1.getReg());
    Value *o2_v = R_READ<width>(b, o2.getReg());

    R_WRITE<width>(b, dst.getReg(), doOrVV<width>(ip, b, o1_v, o2_v));

    return ContinueBlock;
}

template <int width>
static Value * doXorVV(InstPtr ip, BasicBlock *&b, Value *o1, Value *o2)
{
    Value *xoredVal = BinaryOperator::Create(Instruction::Xor, o1, o2, "", b);

    // Clear CF and OF.
    F_CLEAR(b, CF);
    F_CLEAR(b, OF);

    // Set SF, ZF, and PF.
    WriteSF<width>(b, xoredVal);
    WriteZF<width>(b, xoredVal);
    WritePF<width>(b, xoredVal);

    // Undefine AF.
    F_ZAP(b, AF);

    return xoredVal;
}

template <int width>
static InstTransResult doXorMI(InstPtr ip, BasicBlock *&b,
                               Value           *addr,
                               const MCOperand &imm)
{
    TASSERT(addr != NULL, "");
    TASSERT(imm.isImm(), "");

    Value *fromMem = M_READ<width>(ip, b, addr);
    Value *fromImm = CONST_V<width>(b, imm.getImm());

    Value *res = doXorVV<width>(ip, b, fromMem, fromImm);
    M_WRITE<width>(ip, b, addr, res);

    return ContinueBlock;
}

template <int width>
static InstTransResult doXorMV(InstPtr ip, BasicBlock *&b,
                               Value           *addr,
                               Value           *rhs)
{
    TASSERT(addr != NULL, "");
    TASSERT(rhs != NULL, "");

    Value *fromMem = M_READ<width>(ip, b, addr);

    Value *res = doXorVV<width>(ip, b, fromMem, rhs);
    M_WRITE<width>(ip, b, addr, res);

    return ContinueBlock;
}

template <int width>
static InstTransResult doXorMR(InstPtr ip, BasicBlock *&b,
                               Value           *addr,
                               const MCOperand &reg)
{
    TASSERT(addr != NULL, "");
    TASSERT(reg.isReg(), "");

    Value *fromMem = M_READ<width>(ip, b, addr);
    Value *fromReg = R_READ<width>(b, reg.getReg());
    Value *res = doXorVV<width>(ip, b, fromMem, fromReg);
    M_WRITE<width>(ip, b, addr, res);

    return ContinueBlock;
}

template <int width>
static InstTransResult doXorRI(InstPtr ip, BasicBlock *&b,
                               const MCOperand &dst,
                               const MCOperand &o1,
                               const MCOperand &o2)
{
    TASSERT(dst.isReg(), "");
    TASSERT(o1.isReg(), "");
    TASSERT(o2.isImm(), "");

    Value *o1_v = R_READ<width>(b, o1.getReg());
    Value *o2_v = CONST_V<width>(b, o2.getImm());

    R_WRITE<width>(b, dst.getReg(), doXorVV<width>(ip, b, o1_v, o2_v));

    return ContinueBlock;
}

template <int width>
static InstTransResult doXorRV(InstPtr ip, BasicBlock *&b,
                               Value *addr,
                               const MCOperand &o1,
                               const MCOperand &o2)
{
    TASSERT(o1.isReg(), "");
    TASSERT(o2.isReg(), "");

    Value *o1_v = R_READ<width>(b, o1.getReg());

    R_WRITE<width>(b, o2.getReg(), doXorVV<width>(ip, b, o1_v, addr));

    return ContinueBlock;
}

template <int width>
static InstTransResult doXorRM(InstPtr ip, BasicBlock *&b,
                               const MCOperand &dst,
                               const MCOperand &src1,
                               Value           *mem)
{
    TASSERT(mem != NULL, "");
    TASSERT(dst.isReg(), "");
    TASSERT(src1.isReg(), "");

    Value *fromMem = M_READ<width>(ip, b, mem);
    Value *fromReg = R_READ<width>(b, src1.getReg());
    Value *res = doXorVV<width>(ip, b, fromMem, fromReg);
    R_WRITE<width>(b, dst.getReg(), res);

    return ContinueBlock;
}

template <int width>
static InstTransResult doXorRR(InstPtr ip, BasicBlock *&b,
                               const MCOperand &dst,
                               const MCOperand &o1,
                               const MCOperand &o2)
{
    TASSERT(dst.isReg(), "");
    TASSERT(o1.isReg(), "");
    TASSERT(o2.isReg(), "");

    // Read the sources.
    Value *o1_v = R_READ<width>(b, o1.getReg());
    Value *o2_v = R_READ<width>(b, o2.getReg());

    // Do the operation.
    R_WRITE<width>(b, dst.getReg(), doXorVV<width>(ip, b, o1_v, o2_v));

    return ContinueBlock;
}

GENERIC_TRANSLATION(AND16i16, doAndRI<16>(ip, block, MCOperand::CreateReg(X86::AX), MCOperand::CreateReg(X86::AX), OP(0)))
GENERIC_TRANSLATION_REF(AND16mi,
    doAndMI<16>(ip, block, ADDR_NOREF(0), OP(5)),
    doAndMI<16>(ip, block, MEM_REFERENCE(0), OP(5)))
GENERIC_TRANSLATION_REF(AND16mi8,
    doAndMI<16>(ip, block, ADDR_NOREF(0), OP(5)),
    doAndMI<16>(ip, block, MEM_REFERENCE(0), OP(5)))
GENERIC_TRANSLATION_REF(AND16mr,
    doAndMR<16>(ip, block, ADDR_NOREF(0), OP(5)),
    doAndMR<16>(ip, block, MEM_REFERENCE(0), OP(5)))
GENERIC_TRANSLATION(AND16ri, doAndRI<16>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION(AND16ri8, doAndRI<16>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION_REF(AND16rm,
    doAndRM<16>(ip, block, ADDR_NOREF(2), OP(0), OP(1)),
    doAndRM<16>(ip, block, MEM_REFERENCE(2), OP(0), OP(1)))
GENERIC_TRANSLATION(AND16rr, doAndRR<16>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION(AND16rr_REV, doAndRR<16>(ip, block, OP(0), OP(1), OP(2)))
//GENERIC_TRANSLATION(AND32i32, doAndRI<32>(ip, block, MCOperand::CreateReg(X86::EAX), MCOperand::CreateReg(X86::EAX), OP(0)))
GENERIC_TRANSLATION_REF(AND32i32, 
        doAndRI<32>(ip, block, MCOperand::CreateReg(X86::EAX), MCOperand::CreateReg(X86::EAX), OP(0)),
        doAndRV<32>(ip, block, IMM_AS_DATA_REF<32>(block, natM, ip), MCOperand::CreateReg(X86::EAX), MCOperand::CreateReg(X86::EAX)))

GENERIC_TRANSLATION_MI(AND32mi,
    doAndMI<32>(ip, block, ADDR_NOREF(0), OP(5)),
    doAndMI<32>(ip, block, MEM_REFERENCE(0), OP(5)),
    doAndMV<32>(ip, block, ADDR_NOREF(0), IMM_AS_DATA_REF(block, natM, ip)),
    doAndMV<32>(ip, block, MEM_REFERENCE(0), IMM_AS_DATA_REF(block, natM, ip)))

GENERIC_TRANSLATION_REF(AND64mi8,
     doAndMI<64>(ip, block, ADDR_NOREF(0), OP(5)),
     doAndMI<64>(ip, block, MEM_REFERENCE(0), OP(5)))
GENERIC_TRANSLATION_MI(AND64mi32,
     doAndMI<64>(ip, block, ADDR_NOREF(0), OP(5)),
     doAndMI<64>(ip, block, MEM_REFERENCE(0), OP(5)),
     doAndMV<64>(ip, block, ADDR_NOREF(0), IMM_AS_DATA_REF(block, natM, ip)),
     doAndMV<64>(ip, block, MEM_REFERENCE(0), IMM_AS_DATA_REF(block, natM, ip)))

GENERIC_TRANSLATION_REF(AND32mi8,
    doAndMI<32>(ip, block, ADDR_NOREF(0), OP(5)),
    doAndMI<32>(ip, block, MEM_REFERENCE(0), OP(5)))
GENERIC_TRANSLATION_REF(AND32mr,
    doAndMR<32>(ip, block, ADDR_NOREF(0), OP(5)),
    doAndMR<32>(ip, block, MEM_REFERENCE(0), OP(5)))
GENERIC_TRANSLATION_REF(AND64mr,
    doAndMR<64>(ip, block, ADDR_NOREF(0), OP(5)),
    doAndMR<64>(ip, block, MEM_REFERENCE(0), OP(5)))

GENERIC_TRANSLATION(AND32ri, doAndRI<32>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION(AND32ri8, doAndRI<32>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION(AND64ri8, doAndRI<64>(ip, block, OP(0), OP(1), OP(2)))
//GENERIC_TRANSLATION(AND64ri32, doAndRI<64>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION_REF(AND64ri32, 
        doAndRI<64>(ip, block, OP(0), OP(1), OP(2)),
        doAndRV<64>(ip, block, IMM_AS_DATA_REF(block, natM, ip), OP(0), OP(1)))
//GENERIC_TRANSLATION(AND64i32, doAndRI<64>(ip, block, MCOperand::CreateReg(X86::RAX), MCOperand::CreateReg(X86::RAX), OP(0)))
GENERIC_TRANSLATION_REF(AND64i32, 
        doAndRI<64>(ip, block, MCOperand::CreateReg(X86::RAX), MCOperand::CreateReg(X86::RAX), OP(0)),
        doAndRV<64>(ip, block, IMM_AS_DATA_REF(block, natM, ip), MCOperand::CreateReg(X86::RAX), MCOperand::CreateReg(X86::RAX)))

GENERIC_TRANSLATION_REF(AND32rm,
    doAndRM<32>(ip, block, ADDR_NOREF(2), OP(0), OP(1)),
    doAndRM<32>(ip, block, MEM_REFERENCE(2), OP(0), OP(1)))
GENERIC_TRANSLATION_REF(AND64rm,
    doAndRM<64>(ip, block, ADDR_NOREF(2), OP(0), OP(1)),
    doAndRM<64>(ip, block, MEM_REFERENCE(2), OP(0), OP(1)))

GENERIC_TRANSLATION(AND64rr, doAndRR<64>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION(AND32rr, doAndRR<32>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION(AND32rr_REV, doAndRR<32>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION(AND8i8, doAndRI<8>(ip, block, MCOperand::CreateReg(X86::AL), MCOperand::CreateReg(X86::AL), OP(0)))
GENERIC_TRANSLATION_REF(AND8mi,
    doAndMI<8>(ip, block, ADDR_NOREF(0), OP(5)),
    doAndMI<8>(ip, block, MEM_REFERENCE(0), OP(5)))
GENERIC_TRANSLATION_REF(AND8mr,
    doAndMR<8>(ip, block, ADDR_NOREF(0), OP(5)),
    doAndMR<8>(ip, block, MEM_REFERENCE(0), OP(5)))
GENERIC_TRANSLATION(AND8ri, doAndRI<8>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION_REF(AND8rm,
    doAndRM<8>(ip, block, ADDR_NOREF(2), OP(0), OP(1)),
    doAndRM<8>(ip, block, MEM_REFERENCE(2), OP(0), OP(1)))
GENERIC_TRANSLATION(AND8rr, doAndRR<8>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION(AND8rr_REV, doAndRR<8>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION_REF(NOT16m,
    doNotM<16>(ip, block, ADDR_NOREF(0)),
    doNotM<16>(ip, block, MEM_REFERENCE(0)))
GENERIC_TRANSLATION(NOT16r, doNotR<16>(ip, block, OP(0)))
GENERIC_TRANSLATION_REF(NOT32m,
    doNotM<32>(ip, block, ADDR_NOREF(0)),
    doNotM<32>(ip, block, MEM_REFERENCE(0)))
GENERIC_TRANSLATION_REF(NOT64m,
    doNotM<64>(ip, block, ADDR_NOREF(0)),
    doNotM<64>(ip, block, MEM_REFERENCE(0)))

GENERIC_TRANSLATION(NOT32r, doNotR<32>(ip, block, OP(0)))
GENERIC_TRANSLATION(NOT64r, doNotR<64>(ip, block, OP(0)))
GENERIC_TRANSLATION_REF(NOT8m,
    doNotM<8>(ip, block, ADDR_NOREF(0)),
    doNotM<8>(ip, block, MEM_REFERENCE(0)))
GENERIC_TRANSLATION(NOT8r, doNotR<8>(ip, block, OP(0)))
GENERIC_TRANSLATION(OR16i16, doOrRI<16>(ip, block, MCOperand::CreateReg(X86::AX), MCOperand::CreateReg(X86::AX), OP(0)))
GENERIC_TRANSLATION_REF(OR16mi,
    doOrMI<16>(ip, block, ADDR_NOREF(0), OP(5)),
    doOrMI<16>(ip, block, MEM_REFERENCE(0), OP(5)))
GENERIC_TRANSLATION_REF(OR16mi8,
    doOrMI<16>(ip, block, ADDR_NOREF(0), OP(5)),
    doOrMI<16>(ip, block, MEM_REFERENCE(0), OP(5)))
GENERIC_TRANSLATION_REF(OR16mr,
    doOrMR<16>(ip, block, ADDR_NOREF(0), OP(5)),
    doOrMR<16>(ip, block, MEM_REFERENCE(0), OP(5)))
GENERIC_TRANSLATION(OR16ri, doOrRI<16>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION(OR16ri8, doOrRI<16>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION_REF(OR16rm,
    doOrRM<16>(ip, block, ADDR_NOREF(2), OP(0), OP(1)),
    doOrRM<16>(ip, block, MEM_REFERENCE(2), OP(0), OP(1)))
GENERIC_TRANSLATION(OR16rr, doOrRR<16>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION(OR16rr_REV, doOrRR<16>(ip, block, OP(0), OP(1), OP(2)))
//GENERIC_TRANSLATION(OR32i32, doOrRI<32>(ip, block, MCOperand::CreateReg(X86::EAX), MCOperand::CreateReg(X86::EAX), OP(0)))
GENERIC_TRANSLATION_REF(OR32i32, 
        doOrRI<32>(ip, block, MCOperand::CreateReg(X86::EAX), MCOperand::CreateReg(X86::EAX), OP(0)),
        doOrRV<32>(ip, block, IMM_AS_DATA_REF<32>(block, natM, ip), MCOperand::CreateReg(X86::EAX), MCOperand::CreateReg(X86::EAX)))
GENERIC_TRANSLATION_REF(OR64i32, 
        doOrRI<64>(ip, block, MCOperand::CreateReg(X86::RAX), MCOperand::CreateReg(X86::RAX), OP(0)),
        doOrRV<64>(ip, block, IMM_AS_DATA_REF(block, natM, ip), MCOperand::CreateReg(X86::RAX), MCOperand::CreateReg(X86::RAX)))
GENERIC_TRANSLATION_REF(OR64ri32, 
        doOrRI<64>(ip, block, OP(0), OP(1), OP(2)),
        doOrRV<64>(ip, block, IMM_AS_DATA_REF(block, natM, ip), OP(0), OP(1)))

GENERIC_TRANSLATION_MI(OR32mi,
    doOrMI<32>(ip, block, ADDR_NOREF(0), OP(5)),
    doOrMI<32>(ip, block, MEM_REFERENCE(0), OP(5)),
    doOrMV<32>(ip,  block, ADDR_NOREF(0), IMM_AS_DATA_REF(block, natM, ip)),
    doOrMV<32>(ip,  block, MEM_REFERENCE(0), IMM_AS_DATA_REF(block, natM, ip)))

GENERIC_TRANSLATION_REF(OR32mi8,
    doOrMI<32>(ip, block, ADDR_NOREF(0), OP(5)),
    doOrMI<32>(ip, block, MEM_REFERENCE(0), OP(5)))
GENERIC_TRANSLATION_REF(OR32mr,
    doOrMR<32>(ip, block, ADDR_NOREF(0), OP(5)),
    doOrMR<32>(ip, block, MEM_REFERENCE(0), OP(5)))
GENERIC_TRANSLATION_REF(OR64mr,
    doOrMR<64>(ip, block, ADDR_NOREF(0), OP(5)),
    doOrMR<64>(ip, block, MEM_REFERENCE(0), OP(5)))
GENERIC_TRANSLATION(OR32ri, doOrRI<32>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION(OR32ri8, doOrRI<32>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION_REF(OR32rm,
    doOrRM<32>(ip, block, ADDR_NOREF(2), OP(0), OP(1)),
    doOrRM<32>(ip, block, MEM_REFERENCE(2), OP(0), OP(1)))
GENERIC_TRANSLATION(OR32rr, doOrRR<32>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION(OR32rr_REV, doOrRR<32>(ip, block, OP(0), OP(1), OP(2)))

GENERIC_TRANSLATION(OR64ri8, doOrRI<64>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION_REF(OR64rm,
  doOrRM<64>(ip, block, ADDR_NOREF(2), OP(0), OP(1)),
  doOrRM<64>(ip, block, MEM_REFERENCE(2), OP(0), OP(1)))
GENERIC_TRANSLATION(OR64rr, doOrRR<64>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION_REF(OR64mi8,
     doOrMI<64>(ip, block, ADDR_NOREF(0), OP(5)),
     doOrMI<64>(ip, block, MEM_REFERENCE(0), OP(5)))
GENERIC_TRANSLATION_MI(OR64mi32,
     doOrMI<64>(ip, block, ADDR_NOREF(0), OP(5)),
     doOrMI<64>(ip, block, MEM_REFERENCE(0), OP(5)),
     doOrMV<64>(ip, block, ADDR_NOREF(0), IMM_AS_DATA_REF(block, natM, ip)),
     doOrMV<64>(ip, block, MEM_REFERENCE(0), IMM_AS_DATA_REF(block, natM, ip)))

GENERIC_TRANSLATION(OR8i8, doOrRI<8>(ip, block, MCOperand::CreateReg(X86::AL), MCOperand::CreateReg(X86::AL), OP(0)))
GENERIC_TRANSLATION_REF(OR8mi,
    doOrMI<8>(ip, block, ADDR_NOREF(0), OP(5)),
    doOrMI<8>(ip, block, MEM_REFERENCE(0), OP(5)))
GENERIC_TRANSLATION_REF(OR8mr,
    doOrMR<8>(ip, block, ADDR_NOREF(0), OP(5)),
    doOrMR<8>(ip, block, MEM_REFERENCE(0), OP(5)))
GENERIC_TRANSLATION(OR8ri, doOrRI<8>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION_REF(OR8rm,
    doOrRM<8>(ip, block, ADDR_NOREF(2), OP(0), OP(1)),
    doOrRM<8>(ip, block, MEM_REFERENCE(2), OP(0), OP(1)))
GENERIC_TRANSLATION(OR8rr, doOrRR<8>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION(OR8rr_REV, doOrRR<8>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION(XOR16i16, doXorRI<16>(ip, block, MCOperand::CreateReg(X86::AX), MCOperand::CreateReg(X86::AX), OP(0)))
GENERIC_TRANSLATION_REF(XOR16mi,
    doXorMI<16>(ip, block, ADDR_NOREF(0), OP(5)),
    doXorMI<16>(ip, block, MEM_REFERENCE(0), OP(5)))
GENERIC_TRANSLATION_REF(XOR16mi8,
    doXorMI<16>(ip, block, ADDR_NOREF(0), OP(5)),
    doXorMI<16>(ip, block, MEM_REFERENCE(0), OP(5)))
GENERIC_TRANSLATION_REF(XOR16mr,
    doXorMR<16>(ip, block, ADDR_NOREF(0), OP(5)),
    doXorMR<16>(ip, block, MEM_REFERENCE(0), OP(5)))
GENERIC_TRANSLATION(XOR16ri, doXorRI<16>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION(XOR16ri8, doXorRI<16>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION_REF(XOR16rm,
    doXorRM<16>(ip, block, OP(0), OP(1), ADDR_NOREF(2)),
    doXorRM<16>(ip, block, OP(0), OP(1), MEM_REFERENCE(2)))
GENERIC_TRANSLATION(XOR16rr, doXorRR<16>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION(XOR16rr_REV, doXorRR<16>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION_MI(XOR32mi,
    doXorMI<32>(ip, block, ADDR_NOREF(0), OP(5)),
    doXorMI<32>(ip, block, MEM_REFERENCE(0), OP(5)),
    doXorMV<32>(ip,  block, ADDR_NOREF(0), IMM_AS_DATA_REF(block, natM, ip)),
    doXorMV<32>(ip,  block, MEM_REFERENCE(0), IMM_AS_DATA_REF(block, natM, ip)))

GENERIC_TRANSLATION_REF(XOR32mi8,
    doXorMI<32>(ip, block, ADDR_NOREF(0), OP(5)),
    doXorMI<32>(ip, block, MEM_REFERENCE(0), OP(5)))
GENERIC_TRANSLATION_REF(XOR32mr,
    doXorMR<32>(ip, block, ADDR_NOREF(0), OP(5)),
    doXorMR<32>(ip, block, MEM_REFERENCE(0), OP(5)))
GENERIC_TRANSLATION_REF(XOR64mr,
    doXorMR<64>(ip, block, ADDR_NOREF(0), OP(5)),
    doXorMR<64>(ip, block, MEM_REFERENCE(0), OP(5)))
GENERIC_TRANSLATION(XOR32ri, doXorRI<32>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION(XOR32ri8, doXorRI<32>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION(XOR64ri8, doXorRI<64>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION_REF(XOR32i32, 
        doXorRI<32>(ip, block, MCOperand::CreateReg(X86::EAX), MCOperand::CreateReg(X86::EAX), OP(0)),
        doXorRV<32>(ip, block, IMM_AS_DATA_REF<32>(block, natM, ip), MCOperand::CreateReg(X86::EAX), MCOperand::CreateReg(X86::EAX)))
GENERIC_TRANSLATION_REF(XOR64i32, 
        doXorRI<64>(ip, block, MCOperand::CreateReg(X86::RAX), MCOperand::CreateReg(X86::RAX), OP(0)),
        doXorRV<64>(ip, block, IMM_AS_DATA_REF(block, natM, ip), MCOperand::CreateReg(X86::RAX), MCOperand::CreateReg(X86::RAX)))
GENERIC_TRANSLATION_REF(XOR64ri32, 
        doXorRI<64>(ip, block, OP(0), OP(1), OP(2)),
        doXorRV<64>(ip, block, IMM_AS_DATA_REF(block, natM, ip), OP(0), OP(1)))

GENERIC_TRANSLATION_REF(XOR32rm,
    doXorRM<32>(ip, block, OP(0), OP(1), ADDR_NOREF(2)),
    doXorRM<32>(ip, block, OP(0), OP(1), MEM_REFERENCE(2)))
GENERIC_TRANSLATION(XOR32rr, doXorRR<32>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION(XOR32rr_REV, doXorRR<32>(ip, block, OP(0), OP(1), OP(2)))

GENERIC_TRANSLATION_REF(XOR64rm,
  doXorRM<64>(ip, block, OP(0), OP(1), ADDR_NOREF(2)),
  doXorRM<64>(ip, block, OP(0), OP(1), MEM_REFERENCE(2)))
GENERIC_TRANSLATION(XOR64rr, doXorRR<64>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION_REF(XOR64mi8,
     doXorMI<64>(ip, block, ADDR_NOREF(0), OP(5)),
     doXorMI<64>(ip, block, MEM_REFERENCE(0), OP(5)))
GENERIC_TRANSLATION_MI(XOR64mi32,
     doXorMI<64>(ip, block, ADDR_NOREF(0), OP(5)),
     doXorMI<64>(ip, block, MEM_REFERENCE(0), OP(5)),
     doXorMV<64>(ip, block, ADDR_NOREF(0), IMM_AS_DATA_REF(block, natM, ip)),
     doXorMV<64>(ip, block, MEM_REFERENCE(0), IMM_AS_DATA_REF(block, natM, ip)))

GENERIC_TRANSLATION(XOR8i8, doXorRI<8>(ip, block, MCOperand::CreateReg(X86::AL), MCOperand::CreateReg(X86::AL), OP(0)))
GENERIC_TRANSLATION_REF(XOR8mi,
    doXorMI<8>(ip, block, ADDR_NOREF(0), OP(5)),
    doXorMI<8>(ip, block, MEM_REFERENCE(0), OP(5)))
GENERIC_TRANSLATION_REF(XOR8mr,
    doXorMR<8>(ip, block, ADDR_NOREF(0), OP(5)),
    doXorMR<8>(ip, block, MEM_REFERENCE(0), OP(5)))
GENERIC_TRANSLATION(XOR8ri, doXorRI<8>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION_REF(XOR8rm,
    doXorRM<8>(ip, block, OP(0), OP(1), ADDR_NOREF(2)),
    doXorRM<8>(ip, block, OP(0), OP(1), MEM_REFERENCE(2)))
GENERIC_TRANSLATION(XOR8rr, doXorRR<8>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION(XOR8rr_REV, doXorRR<8>(ip, block, OP(0), OP(1), OP(2)))

void Bitops_populateDispatchMap(DispatchMap &m)
{
    m[X86::AND16i16] = translate_AND16i16;
    m[X86::AND16mi] = translate_AND16mi;
    m[X86::AND16mi8] = translate_AND16mi8;
    m[X86::AND16mr] = translate_AND16mr;
    m[X86::AND16ri] = translate_AND16ri;
    m[X86::AND16ri8] = translate_AND16ri8;
    m[X86::AND16rm] = translate_AND16rm;
    m[X86::AND16rr] = translate_AND16rr;
    m[X86::AND16rr_REV] = translate_AND16rr_REV;
    m[X86::AND32i32] = translate_AND32i32;
    m[X86::AND32mi] = translate_AND32mi;
    m[X86::AND32mi8] = translate_AND32mi8;
    m[X86::AND32mr] = translate_AND32mr;
    m[X86::AND32ri] = translate_AND32ri;
    m[X86::AND32ri8] = translate_AND32ri8;
    m[X86::AND32rm] = translate_AND32rm;
    m[X86::AND32rr] = translate_AND32rr;
    m[X86::AND32rr_REV] = translate_AND32rr_REV;
    m[X86::AND8i8] = translate_AND8i8;
    m[X86::AND8mi] = translate_AND8mi;
    m[X86::AND8mr] = translate_AND8mr;
    m[X86::AND8ri] = translate_AND8ri;
    m[X86::AND8rm] = translate_AND8rm;
    m[X86::AND8rr] = translate_AND8rr;
    m[X86::AND8rr_REV] = translate_AND8rr_REV;
    m[X86::AND64ri32] = translate_AND64ri32;
    m[X86::AND64rr] = translate_AND64rr;
    m[X86::AND64rm] = translate_AND64rm;
    m[X86::AND64ri8] = translate_AND64ri8;
    m[X86::AND64i32] = translate_AND64i32;
    m[X86::AND64mr] = translate_AND64mr;
    m[X86::AND64mi8] = translate_AND64mi8;
    m[X86::AND64mi32] = translate_AND64mi32;

    m[X86::NOT16m] = translate_NOT16m;
    m[X86::NOT16r] = translate_NOT16r;
    m[X86::NOT32m] = translate_NOT32m;
    m[X86::NOT32r] = translate_NOT32r;
    m[X86::NOT8m] = translate_NOT8m;
    m[X86::NOT8r] = translate_NOT8r;
    m[X86::NOT64r] = translate_NOT64r;
    m[X86::NOT64m] = translate_NOT64m;

    m[X86::OR16i16] = translate_OR16i16;
    m[X86::OR16mi] = translate_OR16mi;
    m[X86::OR16mi8] = translate_OR16mi8;
    m[X86::OR16mr] = translate_OR16mr;
    m[X86::OR16ri] = translate_OR16ri;
    m[X86::OR16ri8] = translate_OR16ri8;
    m[X86::OR16rm] = translate_OR16rm;
    m[X86::OR16rr] = translate_OR16rr;
    m[X86::OR16rr_REV] = translate_OR16rr_REV;
    m[X86::OR32i32] = translate_OR32i32;
    m[X86::OR64i32] = translate_OR64i32;
    m[X86::OR64ri32] = translate_OR64ri32;
    m[X86::OR32mi] = translate_OR32mi;
    m[X86::OR32mi8] = translate_OR32mi8;
    m[X86::OR32mr] = translate_OR32mr;
    m[X86::OR64mr] = translate_OR64mr;
    m[X86::OR32ri] = translate_OR32ri;
    m[X86::OR32ri8] = translate_OR32ri8;
    m[X86::OR32rm] = translate_OR32rm;
    m[X86::OR32rr] = translate_OR32rr;
    m[X86::OR32rr_REV] = translate_OR32rr_REV;
    m[X86::OR64mi32] = translate_OR64mi32;

    m[X86::OR64ri8] = translate_OR64ri8;
    m[X86::OR64rm] = translate_OR64rm;
    m[X86::OR64mr] = translate_OR64mr;
    m[X86::OR64rr] = translate_OR64rr;
    m[X86::OR64mi8] = translate_OR64mi8;

    m[X86::OR8i8] = translate_OR8i8;
    m[X86::OR8mi] = translate_OR8mi;
    m[X86::OR8mr] = translate_OR8mr;
    m[X86::OR8ri] = translate_OR8ri;
    m[X86::OR8rm] = translate_OR8rm;
    m[X86::OR8rr] = translate_OR8rr;
    m[X86::OR8rr_REV] = translate_OR8rr_REV;
    m[X86::XOR16i16] = translate_XOR16i16;
    m[X86::XOR16mi] = translate_XOR16mi;
    m[X86::XOR16mi8] = translate_XOR16mi8;
    m[X86::XOR16mr] = translate_XOR16mr;
    m[X86::XOR16ri] = translate_XOR16ri;
    m[X86::XOR16ri8] = translate_XOR16ri8;
    m[X86::XOR16rm] = translate_XOR16rm;
    m[X86::XOR16rr] = translate_XOR16rr;
    m[X86::XOR16rr_REV] = translate_XOR16rr_REV;
    m[X86::XOR32i32] = translate_XOR32i32;
    m[X86::XOR32mi] = translate_XOR32mi;
    m[X86::XOR32mi8] = translate_XOR32mi8;
    m[X86::XOR32mr] = translate_XOR32mr;
    m[X86::XOR64mr] = translate_XOR64mr;
    m[X86::XOR32ri] = translate_XOR32ri;
    m[X86::XOR32ri8] = translate_XOR32ri8;
    m[X86::XOR64ri8] = translate_XOR64ri8;
    m[X86::XOR64ri32] = translate_XOR64ri32;
    m[X86::XOR32rm] = translate_XOR32rm;
    m[X86::XOR32rr] = translate_XOR32rr;
    m[X86::XOR32rr_REV] = translate_XOR32rr_REV;
    m[X86::XOR64rm] = translate_XOR64rm;
    m[X86::XOR64rr] = translate_XOR64rr;
    m[X86::XOR8i8] = translate_XOR8i8;
    m[X86::XOR8mi] = translate_XOR8mi;
    m[X86::XOR8mr] = translate_XOR8mr;
    m[X86::XOR8ri] = translate_XOR8ri;
    m[X86::XOR8rm] = translate_XOR8rm;
    m[X86::XOR8rr] = translate_XOR8rr;
    m[X86::XOR8rr_REV] = translate_XOR8rr_REV;
    m[X86::XOR64mi8] = translate_XOR64mi8;
    m[X86::XOR64i32] = translate_XOR64i32;
    m[X86::XOR64mi32] = translate_XOR64mi32;
}
