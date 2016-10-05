/*
Copyright (c) 2013, Trail of Bits
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

  Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

  Redistributions in binary form must reproduce the above copyright notice, this  list of conditions and the following disclaimer in the documentation and/or
  other materials provided with the distribution.

  Neither the name of the {organization} nor the names of its
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
#include "x86Instrs_ADD.h"
#include "llvm/Support/Debug.h"

using namespace llvm;

static InstTransResult doNoop(BasicBlock *b) {
  //isn't this exciting
  return ContinueBlock;
}

GENERIC_TRANSLATION(NOOP, doNoop(block))

template <int width>
static Value * doAddVV(InstPtr ip, BasicBlock *&b, Value *lhs, Value *rhs)
{
    // Add src1 to the constant formed by src2.
    Value *addRes = BinaryOperator::Create(Instruction::Add, rhs, lhs, "", b);

    // Write the flag updates.
    // Compute AF.
    WriteAFAddSub<width>(b, addRes, lhs, rhs);
    // Compute SF.
    WriteSF<width>(b, addRes);
    // Compute ZF.
    WriteZF<width>(b, addRes);
    // Ccompute OF.
    WriteOFAdd<width>(b, addRes, lhs, rhs);
    // Compute PF.
    WritePF<width>(b, addRes);
    // Compute CF.
    WriteCFAdd<width>(b, addRes, lhs);

    return addRes;
}

template <int width>
static InstTransResult doAddMI(InstPtr ip, BasicBlock *&b,
                               Value           *addr,
                               const MCOperand &imm)
{
    TASSERT(imm.isImm(), "");
    TASSERT(addr != NULL, "");

    Value *fromMem = M_READ<width>(ip, b, addr);
    Value *immVal = CONST_V<width>(b, imm.getImm());

    Value *res = doAddVV<width>(ip, b, fromMem, immVal);

    M_WRITE<width>(ip, b, addr, res);

    return ContinueBlock; 
}

template <int width>
static InstTransResult doAddMV(InstPtr ip, BasicBlock *&b,
                               Value           *addr,
                               Value *rhs)
{
    TASSERT(addr != NULL, "");
    TASSERT(rhs != NULL, "");

    Value *fromMem = M_READ<width>(ip, b, addr);

    Value *res = doAddVV<width>(ip, b, fromMem, rhs);

    M_WRITE<width>(ip, b, addr, res);

    return ContinueBlock; 
}

template <int width>
static InstTransResult doAddMR(InstPtr ip, BasicBlock *&b,
                               Value           *addr,
                               const MCOperand &reg)
{
    TASSERT(reg.isReg(), "");
    TASSERT(addr != NULL, "");

    Value *fromReg = R_READ<width>(b, reg.getReg());
    Value *fromMem = M_READ<width>(ip, b, addr);
    
    Value *res = doAddVV<width>(ip, b, fromMem, fromReg);

    M_WRITE<width>(ip, b, addr, res);

    return ContinueBlock;
}

template <int width>
static InstTransResult doAddRI(InstPtr ip, BasicBlock *&b,
                               const MCOperand &dst,
                               const MCOperand &src1,
                               const MCOperand &src2)
{
    TASSERT(src1.isReg(), "");
    TASSERT(src2.isImm(), "");
    TASSERT(dst.isReg(), "");

	llvm::Module *M = b->getParent()->getParent();

    Value *srcReg = NULL;

    // Read from src1.
	srcReg = R_READ<width>(b, src1.getReg());
    
    // Constant.
    Value *constPart = CONST_V<width>(b, src2.getImm());

	R_WRITE<width>(b, dst.getReg(), doAddVV<width>(ip, b, srcReg, constPart));

    return ContinueBlock;
}

template <int width>
static InstTransResult doAddRM(InstPtr ip, BasicBlock *&b,
                               Value           *addr,
                               const MCOperand &o1,
                               const MCOperand &o2)
{
    TASSERT(o1.isReg(), "");
    TASSERT(o2.isReg(), "");
    TASSERT(addr != NULL, "");

    // Load from address.
    Value *v1 = M_READ<width>(ip, b, addr);

    // Read from o1.
    Value *v2 = R_READ<width>(b, o1.getReg());

	// Do add.
	Value *res = doAddVV<width>(ip, b, v1, v2);

	// Write to o2.
	R_WRITE<width>(b, o2.getReg(), res);

    return ContinueBlock;
}

template <int width>
static InstTransResult doAddRV(InstPtr ip, BasicBlock *&b,
                               Value           *addr,
                               const MCOperand &o1,
                               const MCOperand &o2)
{
    TASSERT(o1.isReg(), "");
    TASSERT(o2.isReg(), "");
    TASSERT(addr != NULL, "");

    llvm::errs() << "Doing AddRV at: " << to_string<VA>(ip->get_loc(), hex) << "\n";

    // Read from o1.
	Value *v2 = R_READ<width>(b, o1.getReg());

	// Do add.
	Value *res = doAddVV<width>(ip, b, addr, v2);

	// Write to o2.
	R_WRITE<width>(b, o2.getReg(), res);

    return ContinueBlock;
}


template <int width>
static InstTransResult doAddRR(InstPtr ip, BasicBlock *&b,
                               const MCOperand &dst,
                               const MCOperand &o1,
                               const MCOperand &o2)
{
    TASSERT(dst.isReg(), "");
    TASSERT(o1.isReg(), "");
    TASSERT(o2.isReg(), "");
    
    // Read from srcReg.
    Value *srcReg_v = R_READ<width>(b, o1.getReg());

    // Read from dstReg.
    Value *dstReg_v = R_READ<width>(b, o2.getReg());

    Value *addRes = doAddVV<width>(ip, b, srcReg_v, dstReg_v);
    
    // Store the result in dst.
    R_WRITE<width>(b, dst.getReg(), addRes);

    return ContinueBlock;
}

template <int width>
static Value * doAdcVV(InstPtr ip, BasicBlock *&b, Value *dst, Value *src)
{
    Type *t;

    switch (width)
    {
        case 8:
            t = Type::getInt8Ty(b->getContext());
            break;
        case 16:
            t = Type::getInt16Ty(b->getContext());
            break;
        case 32:
            t = Type::getInt32Ty(b->getContext());
            break;
        case 64:
            t = Type::getInt64Ty(b->getContext());
            break;
        default:
            throw TErr(__LINE__, __FILE__, "Width not supported");
    }

    Value *cf = new ZExtInst(F_READ(b, CF), t, "", b);

    Value *srcRes = BinaryOperator::Create(Instruction::Add, cf, src, "", b);
    Value *addRes = BinaryOperator::Create(Instruction::Add, srcRes, dst, "", b);

    // Write flags.
    WriteOFAdd<width>(b, addRes, dst, srcRes);
    WriteSF<width>(b, addRes);
    WriteZF<width>(b, addRes);
    WriteAFAddSub<width>(b, addRes, dst, srcRes);
    WriteCFAdd<width>(b, addRes, dst);
    WritePF<width>(b, addRes);

    return addRes;
}

template <int width>
static InstTransResult doAdcRV(InstPtr ip, BasicBlock *&b,
                               Value           *addr,
                               const MCOperand &o1,
                               const MCOperand &o2)
{
    TASSERT(o1.isReg(), "");
    TASSERT(o2.isReg(), "");
    TASSERT(addr != NULL, "");

    // Read from o1.
	Value *v2 = R_READ<width>(b, o1.getReg());

	// Do add.
	Value *res = doAdcVV<width>(ip, b, addr, v2);

	// Write to o2.
	R_WRITE<width>(b, o2.getReg(), res);

    return ContinueBlock;
}

template <int width>
static InstTransResult doAdcI(InstPtr ip, BasicBlock *&b, const MCOperand &src)
{
    TASSERT(src.isImm(), "");

    Value *imm = CONST_V<width>(b, src.getImm());
    Value *dst;

    switch (width)
    {
        case 8:
            dst = R_READ<width>(b, X86::AL);
            break;
        case 16:
            dst = R_READ<width>(b, X86::AX);
            break;
        case 32:
            dst = R_READ<width>(b, X86::EAX);
            break;
        case 64:
            dst = R_READ<width>(b, X86::RAX);
            break;
        default:
            throw TErr(__LINE__, __FILE__, "Width not supported");
    }

    Value *res = doAdcVV<width>(ip, b, dst, imm);

    switch (width)
    {
        case 8:
            R_WRITE<width>(b, X86::AL, res);
            break;
        case 16:
            R_WRITE<width>(b, X86::AX, res);
            break;
        case 32:
            R_WRITE<width>(b, X86::EAX, res);
            break;
        case 64:
            R_WRITE<width>(b, X86::RAX, res);
            break;
        default:
            throw TErr(__LINE__, __FILE__, "Width not supported");
    }

    return ContinueBlock;
}

template <int width>
static InstTransResult doAdcMI(InstPtr ip, BasicBlock *&b,
                               Value           *addr,
                               const MCOperand &src) 
{
    TASSERT(addr != NULL, "");
    TASSERT(src.isImm(), "");

    Value *dst = M_READ<width>(ip, b, addr);
    Value *imm = CONST_V<width>(b, src.getImm());

    Value *res = doAdcVV<width>(ip, b, dst, imm);

    M_WRITE<width>(ip, b, addr, res);

    return ContinueBlock;
}

template <int width>
static InstTransResult doAdcMV(InstPtr ip, BasicBlock *&b,
                               Value           *addr,
                               Value           *rhs)
{
    TASSERT(addr != NULL, "");
    TASSERT(rhs != NULL, "");


    Value *dst = M_READ<width>(ip, b, addr);

    Value *res = doAdcVV<width>(ip, b, dst, rhs);

    M_WRITE<width>(ip, b, addr, res);

    return ContinueBlock;
}

template <int width>
static InstTransResult doAdcMI8(InstPtr ip, BasicBlock *&b,
                                Value           *addr,
                                const MCOperand &src) 
{
    TASSERT(addr != NULL, "");
    TASSERT(src.isImm(), "");

    Value *dst = M_READ<width>(ip, b, addr);
    Value *imm = CONST_V<8>(b, src.getImm());

    Type *sx;
    sx = Type::getIntNTy(b->getContext(), width);

    Value *imm_sx = new SExtInst( imm, sx, "", b);

    Value *res = doAdcVV<width>(ip, b, dst, imm_sx);

    M_WRITE<width>(ip, b, addr, res);

    return ContinueBlock;
}

template <int width>
static InstTransResult doAdcMR(InstPtr ip, BasicBlock *&b,
                               Value           *addr,
                               const MCOperand &reg) 
{
    TASSERT(addr != NULL, "");
    TASSERT(reg.isReg(), "");

    Value *dst = M_READ<width>(ip, b, addr);
    Value *src = R_READ<width>(b, reg.getReg());

    Value *res = doAdcVV<width>(ip, b, dst, src);

    M_WRITE<width>(ip, b, addr, res);

    return ContinueBlock;
}

template <int width>
static InstTransResult doAdcRI(InstPtr ip, BasicBlock *&b,
                               const MCOperand &dst,
                               const MCOperand &o1,
                               const MCOperand &o2)
{
    TASSERT(dst.isReg(), "");
    TASSERT(o1.isReg(), "");
    TASSERT(o2.isImm(), "");

    Value *o1_v = R_READ<width>(b, o1.getReg());
    Value *o2_v = CONST_V<width>(b, o2.getImm());

    Value *res = doAdcVV<width>(ip, b, o1_v, o2_v);

    R_WRITE<width>(b, dst.getReg(), res);

    return ContinueBlock;
}

template <int width>
static InstTransResult doAdcRI8(InstPtr ip, BasicBlock *&b,
                                const MCOperand &dst,
                                const MCOperand &o1,
                                const MCOperand &o2)
{
    TASSERT(dst.isReg(), "");
    TASSERT(o1.isReg(), "");
    TASSERT(o2.isImm(), "");

    Value *o1_v = R_READ<width>(b, o1.getReg());
    Value *o2_v = CONST_V<8>(b, o2.getImm());

    Type *sx;
    sx = Type::getIntNTy(b->getContext(), width);

    Value *imm_sx = new SExtInst(o2_v, sx, "", b);

    Value *res = doAdcVV<width>(ip, b, o1_v, imm_sx);

    R_WRITE<width>(b, dst.getReg(), res);

    return ContinueBlock;
}

template <int width>
static InstTransResult doAdcRM(InstPtr ip, BasicBlock *&b,
                               Value           *addr,
                               const MCOperand &o1,
                               const MCOperand &o2)
{
    TASSERT(o1.isReg(), "");
    TASSERT(o2.isReg(), "");
    TASSERT(addr != NULL, "");

    // Load from address.
    Value *v1 = M_READ<width>(ip, b, addr);

    // Read from o1.
    Value *v2 = R_READ<width>(b, o1.getReg());

    // Do add.
    Value *res = doAdcVV<width>(ip, b, v1, v2);

    // Write to o2.
    R_WRITE<width>(b, o2.getReg(), res);

    return ContinueBlock;
}

template <int width>
static InstTransResult doAdcRR(InstPtr ip, BasicBlock *&b,
                               const MCOperand &dst,
                               const MCOperand &o1,
                               const MCOperand &o2)
{
    TASSERT(dst.isReg(), "");
    TASSERT(o1.isReg(), "");
    TASSERT(o2.isReg(), "");

    Value *dst_reg = R_READ<width>(b, o1.getReg());
    Value *src_reg = R_READ<width>(b, o2.getReg());

    Value *res = doAdcVV<width>(ip, b, dst_reg, src_reg);

    R_WRITE<width>(b, dst.getReg(), res);

    return ContinueBlock;
}

GENERIC_TRANSLATION(ADD16i16, doAddRI<16>(ip, block, MCOperand::CreateReg(X86::EAX), MCOperand::CreateReg(X86::EAX), OP(0)))

GENERIC_TRANSLATION_REF(ADD16mi, 
        doAddMI<16>(ip, block, ADDR_NOREF(0), OP(5)),
        doAddMI<16>(ip, block, MEM_REFERENCE(0), OP(5)))

GENERIC_TRANSLATION_REF(ADD16mi8, 
        doAddMI<16>(ip, block, ADDR_NOREF(0), OP(5)),
        doAddMI<16>(ip, block, MEM_REFERENCE(0), OP(5)))

GENERIC_TRANSLATION_REF(ADD16mr, 
        doAddMR<16>(ip, block, ADDR_NOREF(0), OP(5)),
        doAddMR<16>(ip, block, MEM_REFERENCE(0), OP(5)))

GENERIC_TRANSLATION(ADD16ri, doAddRI<16>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION(ADD16ri8, doAddRI<16>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION(ADD16ri8_DB, doAddRI<16>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION(ADD16ri_DB, doAddRI<16>(ip, block, OP(0), OP(1), OP(2)))

GENERIC_TRANSLATION_REF(ADD16rm, 
        doAddRM<16>(ip, block, ADDR_NOREF(2), OP(0), OP(1)),
        doAddRM<16>(ip, block, MEM_REFERENCE(2), OP(0), OP(1)))

GENERIC_TRANSLATION(ADD16rr, doAddRR<16>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION(ADD16rr_DB, doAddRR<16>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION(ADD16rr_REV, doAddRR<16>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION_REF(ADD32i32, 
        doAddRI<32>(ip, block, MCOperand::CreateReg(X86::EAX), MCOperand::CreateReg(X86::EAX), OP(0)),
        doAddRV<32>(ip, block, IMM_AS_DATA_REF<32>(block, natM, ip), MCOperand::CreateReg(X86::EAX), MCOperand::CreateReg(X86::EAX)))

GENERIC_TRANSLATION_REF(ADD64i32,
        doAddRI<64>(ip, block, MCOperand::CreateReg(X86::RAX), MCOperand::CreateReg(X86::RAX), OP(0)),
        doAddRV<64>(ip, block, IMM_AS_DATA_REF(block, natM, ip), MCOperand::CreateReg(X86::RAX), MCOperand::CreateReg(X86::RAX)))

GENERIC_TRANSLATION_MI(ADD32mi,
        doAddMI<32>(ip, block, ADDR_NOREF(0), OP(5)),
        doAddMI<32>(ip, block, MEM_REFERENCE(0), OP(5)),
        doAddMV<32>(ip, block, ADDR_NOREF(0), IMM_AS_DATA_REF(block, natM, ip)),
        doAddMV<32>(ip, block, MEM_REFERENCE(0), IMM_AS_DATA_REF(block, natM, ip)))

GENERIC_TRANSLATION_REF(ADD32mi8, 
        doAddMI<32>(ip, block, ADDR_NOREF(0), OP(5)),
        doAddMI<32>(ip, block, MEM_REFERENCE(0), OP(5)))

GENERIC_TRANSLATION_REF(ADD64mi8, 
        doAddMI<64>(ip, block, ADDR_NOREF(0), OP(5)),
        doAddMI<64>(ip, block, MEM_REFERENCE(0), OP(5)))

GENERIC_TRANSLATION_REF(ADD64mi32,
      doAddMI<64>(ip, block, ADDR_NOREF(0), OP(5)),
      doAddMI<64>(ip, block, MEM_REFERENCE(0), OP(5)))

GENERIC_TRANSLATION_REF(ADD32mr, 
        doAddMR<32>(ip, block, ADDR_NOREF(0), OP(5)),
        doAddMR<32>(ip, block, MEM_REFERENCE(0), OP(5)))

GENERIC_TRANSLATION_REF(ADD64mr, 
        doAddMR<64>(ip, block, ADDR_NOREF(0), OP(5)),
        doAddMR<64>(ip, block, MEM_REFERENCE(0), OP(5)))

GENERIC_TRANSLATION_REF(ADD32ri,
        doAddRI<32>(ip, block, OP(0), OP(1), OP(2)),
        doAddRV<32>(ip, block, IMM_AS_DATA_REF(block, natM, ip), OP(0), OP(1)))
GENERIC_TRANSLATION_REF(ADD32ri_DB,
        doAddRI<32>(ip, block, OP(0), OP(1), OP(2)),
        doAddRV<32>(ip, block, IMM_AS_DATA_REF(block, natM, ip), OP(0), OP(1)))

GENERIC_TRANSLATION(ADD32ri8, doAddRI<32>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION(ADD32ri8_DB, doAddRI<32>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION(ADD64ri8, doAddRI<64>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION(ADD64ri16, doAddRI<64>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION_REF(ADD64ri32,
        doAddRI<64>(ip, block, OP(0), OP(1), OP(2)),
        doAddRV<64>(ip, block, IMM_AS_DATA_REF(block, natM, ip), OP(0), OP(1)))

GENERIC_TRANSLATION_REF(ADD32rm, 
        doAddRM<32>(ip, block, ADDR_NOREF(2), OP(0), OP(1)),
        doAddRM<32>(ip, block, MEM_REFERENCE(2), OP(0), OP(1)))
GENERIC_TRANSLATION_REF(ADD64rm, 
        doAddRM<64>(ip, block, ADDR_NOREF(2), OP(0), OP(1)),
        doAddRM<64>(ip, block, MEM_REFERENCE(2), OP(0), OP(1)))

GENERIC_TRANSLATION(ADD64rr, doAddRR<64>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION(ADD32rr, doAddRR<32>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION(ADD32rr_DB, doAddRR<32>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION(ADD32rr_REV, doAddRR<32>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION(ADD8i8, doAddRI<8>(ip, block, MCOperand::CreateReg(X86::EAX), MCOperand::CreateReg(X86::EAX), OP(0)))

GENERIC_TRANSLATION_REF(ADD8mi, 
        doAddMI<8>(ip, block, ADDR_NOREF(0), OP(5)),
        doAddMI<8>(ip, block, MEM_REFERENCE(0), OP(5)))

GENERIC_TRANSLATION_REF(ADD8mr, 
        doAddMR<8>(ip, block, ADDR_NOREF(0), OP(5)),
        doAddMR<8>(ip, block, MEM_REFERENCE(0), OP(5)))

GENERIC_TRANSLATION(ADD8ri, doAddRI<8>(ip, block, OP(0), OP(1), OP(2)))

GENERIC_TRANSLATION_REF(ADD8rm, 
        doAddRM<8>(ip, block, ADDR_NOREF(2), OP(0), OP(1)),
        doAddRM<8>(ip, block, MEM_REFERENCE(2), OP(0), OP(1)))

GENERIC_TRANSLATION(ADD8rr, doAddRR<8>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION(ADD8rr_REV, doAddRR<8>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION(ADC16i16, doAdcI<16>(ip, block, OP(0)))

GENERIC_TRANSLATION_REF(ADC16mi, 
        doAdcMI<16>(ip, block, ADDR_NOREF(0), OP(5)),
        doAdcMI<16>(ip, block, MEM_REFERENCE(0), OP(5)))

GENERIC_TRANSLATION_REF(ADC16mi8, 
        doAdcMI8<16>(ip, block, ADDR_NOREF(0), OP(5)),
        doAdcMI8<16>(ip, block, MEM_REFERENCE(0), OP(5)))

GENERIC_TRANSLATION_REF(ADC16mr, 
        doAdcMR<16>(ip, block, ADDR_NOREF(0), OP(5)),
        doAdcMR<16>(ip, block, MEM_REFERENCE(0), OP(5)))

GENERIC_TRANSLATION(ADC16ri, doAdcRI<16>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION(ADC16ri8, doAdcRI8<16>(ip, block, OP(0), OP(1), OP(2)))

GENERIC_TRANSLATION_REF(ADC16rm, 
        doAdcRM<16>(ip, block, ADDR_NOREF(2), OP(0), OP(1)),
        doAdcRM<16>(ip, block, MEM_REFERENCE(2), OP(0), OP(1)))

GENERIC_TRANSLATION(ADC16rr, doAdcRR<16>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION(ADC16rr_REV, doAdcRR<16>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION(ADC32i32, doAdcI<32>(ip, block, OP(0)))

GENERIC_TRANSLATION_REF(ADC64i32,
        doAdcRI<64>(ip, block, MCOperand::CreateReg(X86::RAX), MCOperand::CreateReg(X86::RAX), OP(0)),
        doAdcRV<64>(ip, block, IMM_AS_DATA_REF<32>(block, natM, ip), MCOperand::CreateReg(X86::RAX), MCOperand::CreateReg(X86::RAX)))

GENERIC_TRANSLATION_MI(ADC32mi, 
        doAdcMI<32>(ip, block, ADDR_NOREF(0), OP(5)),
        doAdcMI<32>(ip, block, MEM_REFERENCE(0), OP(5)),
        doAdcMV<32>(ip, block, ADDR_NOREF(0), IMM_AS_DATA_REF(block, natM, ip)),
        doAdcMV<32>(ip, block, MEM_REFERENCE(0), IMM_AS_DATA_REF(block, natM, ip)))

GENERIC_TRANSLATION_REF(ADC32mi8, 
        doAdcMI8<32>(ip, block, ADDR_NOREF(0), OP(5)),
        doAdcMI8<32>(ip, block, MEM_REFERENCE(0), OP(5)))

GENERIC_TRANSLATION_REF(ADC32mr, 
        doAdcMR<32>(ip, block, ADDR_NOREF(0), OP(5)),
        doAdcMR<32>(ip, block, MEM_REFERENCE(0), OP(5)))

GENERIC_TRANSLATION_REF(ADC64ri32,
        doAdcRI<64>(ip, block, OP(0), OP(1), OP(2)),
        doAdcRV<64>(ip, block, IMM_AS_DATA_REF(block, natM, ip), OP(0), OP(1)))

GENERIC_TRANSLATION(ADC32ri, doAdcRI<32>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION(ADC32ri8, doAdcRI8<32>(ip, block, OP(0), OP(1), OP(2)))

GENERIC_TRANSLATION_REF(ADC32rm, 
        doAdcRM<32>(ip, block, ADDR_NOREF(2), OP(0), OP(1)),
        doAdcRM<32>(ip, block, MEM_REFERENCE(2), OP(0), OP(1)))

GENERIC_TRANSLATION(ADC64rr, doAdcRR<64>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION(ADC32rr, doAdcRR<32>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION(ADC32rr_REV, doAdcRR<32>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION(ADC8i8, doAdcI<8>(ip, block, OP(0)))

GENERIC_TRANSLATION_REF(ADC8mi, 
        doAdcMI<8>(ip, block, ADDR_NOREF(0), OP(5)),
        doAdcMI<8>(ip, block, MEM_REFERENCE(0), OP(5)))

GENERIC_TRANSLATION_REF(ADC8mr, 
        doAdcMR<8>(ip, block, ADDR_NOREF(0), OP(5)),
        doAdcMR<8>(ip, block, MEM_REFERENCE(0), OP(5)))

GENERIC_TRANSLATION(ADC8ri, doAdcRI<8>(ip, block, OP(0), OP(1), OP(2)))

GENERIC_TRANSLATION_REF(ADC8rm, 
        doAdcRM<8>(ip, block, ADDR_NOREF(2), OP(0), OP(1)),
        doAdcRM<8>(ip, block, MEM_REFERENCE(2), OP(0), OP(1)))

GENERIC_TRANSLATION(ADC8rr, doAdcRR<8>(ip, block, OP(0), OP(1), OP(2)))
GENERIC_TRANSLATION(ADC8rr_REV, doAdcRR<8>(ip, block, OP(0), OP(1), OP(2)))

void ADD_populateDispatchMap(DispatchMap &m)
{
    m[X86::ADD16i16] = translate_ADD16i16;
    m[X86::ADD16mi] = translate_ADD16mi;
    m[X86::ADD16mi8] = translate_ADD16mi8;
    m[X86::ADD16mr] = translate_ADD16mr; 
    m[X86::ADD16ri] = translate_ADD16ri;
    m[X86::ADD16ri8] = translate_ADD16ri8;
    m[X86::ADD16ri8_DB] = translate_ADD16ri8_DB;
    m[X86::ADD16ri_DB] = translate_ADD16ri_DB;
    m[X86::ADD16rm] = translate_ADD16rm;
    m[X86::ADD16rr] = translate_ADD16rr;
    m[X86::ADD16rr_DB] = translate_ADD16rr_DB;
    m[X86::ADD16rr_REV] = translate_ADD16rr_REV;
    m[X86::ADD32i32] = translate_ADD32i32;
    m[X86::ADD32ri] = translate_ADD32ri;
    m[X86::ADD32ri8] = translate_ADD32ri8;
    m[X86::ADD32ri8_DB] = translate_ADD32ri8_DB;
    m[X86::ADD32ri_DB] = translate_ADD32ri_DB;
    m[X86::ADD32mi] = translate_ADD32mi;
    m[X86::ADD32mi8] = translate_ADD32mi8;
    m[X86::ADD32mr] = translate_ADD32mr;
    m[X86::ADD32rm] = translate_ADD32rm;
    m[X86::ADD32rr] = translate_ADD32rr;
    m[X86::ADD32rr_DB] = translate_ADD32rr_DB;
    m[X86::ADD32rr_REV] = translate_ADD32rr_REV;
    m[X86::ADD8i8] = translate_ADD8i8;
    m[X86::ADD8mi] = translate_ADD8mi;
    m[X86::ADD8mr] = translate_ADD8mr;
    m[X86::ADD8ri] = translate_ADD8ri;
    m[X86::ADD8rm] = translate_ADD8rm;
    m[X86::ADD8rr] = translate_ADD8rr;
    m[X86::ADD8rr_REV] = translate_ADD8rr_REV;

    m[X86::ADD64ri8] = translate_ADD64ri8;
    m[X86::ADD64ri8_DB] = translate_ADD64ri8;
    m[X86::ADD64ri32] = translate_ADD64ri32;
    m[X86::ADD64ri32_DB] = translate_ADD64ri32;
    m[X86::ADD64i32] = translate_ADD64i32;
    m[X86::ADD64mi8] = translate_ADD64mi8;;
	m[X86::ADD64mi32] = translate_ADD64mi32;

	m[X86::ADD64rr_DB] = translate_ADD64rr;
	m[X86::ADD64rr] = translate_ADD64rr;
	m[X86::ADD64rr_REV] = translate_ADD64rr;
	m[X86::ADD64rm] = translate_ADD64rm;
	m[X86::ADD64mr] = translate_ADD64mr;


    m[X86::ADC16i16] = translate_ADC16i16;
    m[X86::ADC16mi] = translate_ADC16mi;
    m[X86::ADC16mi8] = translate_ADC16mi8;
    m[X86::ADC16mr] = translate_ADC16mr;
    m[X86::ADC16ri] = translate_ADC16ri;
    m[X86::ADC16ri8] = translate_ADC16ri8;
    m[X86::ADC16rm] = translate_ADC16rm;
    m[X86::ADC16rr] = translate_ADC16rr;
    m[X86::ADC16rr_REV] = translate_ADC16rr_REV;
    m[X86::ADC32i32] = translate_ADC32i32;
    m[X86::ADC32mi] = translate_ADC32mi;
    m[X86::ADC32mi8] = translate_ADC32mi8;
    m[X86::ADC32mr] = translate_ADC32mr;
    m[X86::ADC32ri] = translate_ADC32ri;
    m[X86::ADC32ri8] = translate_ADC32ri8;
    m[X86::ADC32rm] = translate_ADC32rm;
    m[X86::ADC32rr] = translate_ADC32rr;
    m[X86::ADC32rr_REV] = translate_ADC32rr_REV;
    m[X86::ADC8i8] = translate_ADC8i8;
    m[X86::ADC8mi] = translate_ADC8mi;
    m[X86::ADC8mr] = translate_ADC8mr;
    m[X86::ADC8ri] = translate_ADC8ri;
    m[X86::ADC8rm] = translate_ADC8rm;
    m[X86::ADC8rr] = translate_ADC8rr;
    m[X86::ADC8rr_REV] = translate_ADC8rr_REV;

	m[X86::ADC64i32] = translate_ADC64i32;
	m[X86::ADC64ri32] = translate_ADC64ri32;
	m[X86::ADC64rr] = translate_ADC64rr;
}
