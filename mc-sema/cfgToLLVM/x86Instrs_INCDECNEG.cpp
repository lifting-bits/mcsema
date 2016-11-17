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
#include "x86Instrs_INCDECNEG.h"

#define NASSERT(cond) TASSERT(cond, "")

using namespace llvm;

template <int width>
static Value *doNegV(InstPtr ip, BasicBlock *&b, Value *v) {
    //compare dest to 0
    Value   *cmpRes = 
        new ICmpInst(*b, CmpInst::ICMP_NE, v, CONST_V<width>(b, 0));

    F_WRITE(b, CF, cmpRes);
    //perform a signed subtraction
    Value *res = BinaryOperator::CreateSub(CONST_V<width>(b, 0), v, "", b);
    //populate the b of the flags
    WriteSF<width>(b, res);
    WritePF<width>(b, res);
    WriteZF<width>(b, res);
    WriteOFSub<width>(b, res, CONST_V<width>(b, 0), v);

    return res;
}

template <int width>
static InstTransResult doNegM(InstPtr ip,  BasicBlock *&b, Value *v) {
    NASSERT(v != NULL);

    Value   *fromMem = M_READ<width>(ip, b, v);
    Value   *result = doNegV<width>(ip, b, fromMem);
    M_WRITE<width>(ip, b, v, result);

    return EndBlock;
}

template <int width>
static InstTransResult doNegR(InstPtr ip,  BasicBlock      *&b,
                        const MCOperand &dst)
{
    NASSERT(dst.isReg());
	llvm::Module *M = b->getParent()->getParent();
	uint32_t regWidth = ArchPointerSize(M);

    // Cache a full width read of the register.
    Value *reg_f_v = (regWidth == x86::REG_SIZE)?
						x86::R_READ<32>(b, dst.getReg()) :
						x86_64::R_READ<64>(b, dst.getReg());
    
    // Do a read of the register.
    Value *reg_v = R_READ<width>(b, dst.getReg());

    Value *result = doNegV<width>(ip, b, reg_v);

    // Write it back out.
    R_WRITE<width>(b, dst.getReg(), result);

    // Update AF with the result from the register.
    if(regWidth == x86::REG_SIZE)
		WriteAF2<32>(b, reg_f_v, x86::R_READ<32>(b, dst.getReg()), CONST_V<32>(b, 1));
	else
		WriteAF2<64>(b, reg_f_v, x86_64::R_READ<64>(b, dst.getReg()), CONST_V<64>(b, 1));
		
    return ContinueBlock;
}

template <int width>
static Value *doIncV(InstPtr ip, BasicBlock *&b, Value *val) {

    //add by 1
    Value *result = BinaryOperator::CreateAdd(val, CONST_V<width>(b, 1), "", b);

    //do not set CF
    //set OF, SF, ZF, AF and PF
    WriteZF<width>(b, result);
    WritePF<width>(b, result);
    WriteSF<width>(b, result);
    WriteOFAdd<width>(b, result, val, CONST_V<width>(b,1));

    return result;
}

template <int width>
static InstTransResult doIncM(InstPtr ip,  BasicBlock  *&b, 
                        Value       *addr)
{
    NASSERT(addr != NULL);

    Value   *fromMem = M_READ<width>(ip, b, addr);

    Value   *result = doIncV<width>(ip, b, fromMem);

    M_WRITE<width>(ip, b, addr, result);

    return ContinueBlock;
}

template <int width>
static Value *doDecV(InstPtr ip, BasicBlock *&b, Value *val) {

    Value *result = BinaryOperator::CreateSub(val, CONST_V<width>(b, 1), "", b);

    //do not set CF
    //set OF, SF, ZF and PF
    WriteZF<width>(b, result);
    WritePF<width>(b, result);
    WriteSF<width>(b, result);
    WriteOFSub<width>(b, result, val, CONST_V<width>(b, 1));

    return result;
}

template <int width, int regWidth>
static InstTransResult doDecR(InstPtr ip,  BasicBlock      *&b,
                        const MCOperand &dst)
{
    NASSERT(dst.isReg());

    // Cache a full width read of the register.
    Value *reg_f_v = R_READ<regWidth>(b, dst.getReg());

    // Do a read of the register.
    Value *reg_v = R_READ<width>(b, dst.getReg());

    Value *result = doDecV<width>(ip, b, reg_v);

    // Write it back out.
    R_WRITE<width>(b, dst.getReg(), result);

    // Update AF with the result from the register.

	WriteAF2<regWidth>(b, reg_f_v, R_READ<regWidth>(b, dst.getReg()), CONST_V<regWidth>(b, 1));

    return ContinueBlock;
}

template <int width, int regWidth>
static InstTransResult doDecM(InstPtr ip, BasicBlock *&b, Value *m) {
    NASSERT(m != NULL);

    Value   *from_mem = M_READ<width>(ip, b, m);
    Value   *from_mem_fv = from_mem;
    if(regWidth > width) {
        // extend memory read to regWidth
        from_mem_fv = new ZExtInst(from_mem, Type::getIntNTy(b->getContext(), regWidth), "", b);
    }

    Value   *result = doDecV<width>(ip, b, from_mem);

    M_WRITE<width>(ip, b, m, result);

    if(regWidth > width) {
        result = new ZExtInst(result, Type::getIntNTy(b->getContext(), regWidth), "", b);
    }

	WriteAF2<regWidth>(b, from_mem_fv, result, CONST_V<regWidth>(b, 1));

    return ContinueBlock;
}

GENERIC_TRANSLATION(DEC64_16r, (doDecR<16, 64>(ip, block, OP(0))))
GENERIC_TRANSLATION(DEC64_32r, (doDecR<32, 64>(ip, block, OP(0))))
GENERIC_TRANSLATION(DEC16r, (doDecR<16, 16>(ip, block, OP(0))))
GENERIC_TRANSLATION(DEC8r, (doDecR<8, 8>(ip, block, OP(0))))
GENERIC_TRANSLATION(DEC32r, (doDecR<32,32>(ip, block, OP(0))) )
GENERIC_TRANSLATION(DEC64r, (doDecR<64,64>(ip, block, OP(0))) )
GENERIC_TRANSLATION_REF(DEC16m, 
	(doDecM<16,16>(ip, block, ADDR_NOREF(0))),
	(doDecM<16,16>(ip, block, MEM_REFERENCE(0))) )
GENERIC_TRANSLATION_REF(DEC32m, 
	(doDecM<32,32>(ip, block, ADDR_NOREF(0))),
	(doDecM<32,32>(ip, block, MEM_REFERENCE(0))) )
GENERIC_TRANSLATION_REF(DEC64m, 
	(doDecM<64,64>(ip, block, ADDR_NOREF(0))),
	(doDecM<64,64>(ip, block, MEM_REFERENCE(0))) )
GENERIC_TRANSLATION_REF(DEC8m, 
	(doDecM<8,8>(ip, block, ADDR_NOREF(0))) ,
	(doDecM<8,8>(ip, block, MEM_REFERENCE(0))) )
GENERIC_TRANSLATION_REF(DEC64_32m, 
	(doDecM<32,64>(ip, block, ADDR_NOREF(0))) ,
	(doDecM<32,64>(ip, block, MEM_REFERENCE(0))) )
GENERIC_TRANSLATION_REF(DEC64_16m, 
	(doDecM<16,64>(ip, block, ADDR_NOREF(0))) ,
	(doDecM<16,64>(ip, block, MEM_REFERENCE(0))) )
GENERIC_TRANSLATION_REF(INC16m, 
	doIncM<16>(ip, block, ADDR_NOREF(0)),
	doIncM<16>(ip, block, MEM_REFERENCE(0)))
GENERIC_TRANSLATION_REF(INC32m, 
	doIncM<32>(ip, block, ADDR_NOREF(0)),
	doIncM<32>(ip, block, MEM_REFERENCE(0)))
GENERIC_TRANSLATION_REF(INC8m, 
	doIncM<8>(ip, block, ADDR_NOREF(0)),
	doIncM<8>(ip, block, MEM_REFERENCE(0)))
	
GENERIC_TRANSLATION_REF(INC64m,
	doIncM<64>(ip, block, ADDR_NOREF(0)),
	doIncM<64>(ip, block, MEM_REFERENCE(0)))
	
template <int width, int regWidth>
static InstTransResult doIncR(InstPtr ip,  BasicBlock      *&b,
                        const MCOperand &dst)
{
    NASSERT(dst.isReg());

    // Cache a full width read of the register.
    Value *reg_f_v = R_READ<regWidth>(b, dst.getReg());

    // Do a read of the register.
    Value *reg_v = R_READ<width>(b, dst.getReg());

    Value *result = doIncV<width>(ip, b, reg_v);

    // Write it back out.
    R_WRITE<width>(b, dst.getReg(), result);

    // Update AF with the result from the register.

	WriteAF2<regWidth>(b, reg_f_v, R_READ<regWidth>(b, dst.getReg()), CONST_V<regWidth>(b, 1));

    return ContinueBlock;
}

GENERIC_TRANSLATION(INC64_16r, (doIncR<16, 64>(ip, block, OP(0))))
GENERIC_TRANSLATION(INC64_32r, (doIncR<32, 64>(ip, block, OP(0))))
GENERIC_TRANSLATION(INC16r, (doIncR<16, 16>(ip, block, OP(0))))
GENERIC_TRANSLATION(INC8r, (doIncR<8, 8>(ip, block, OP(0))))
GENERIC_TRANSLATION(INC32r, (doIncR<32,32>(ip, block, OP(0))) )
GENERIC_TRANSLATION(INC64r, (doIncR<64,64>(ip, block, OP(0))) )

GENERIC_TRANSLATION_REF(NEG16m, 
	doNegM<16>(ip, block, ADDR_NOREF(0)),
	doNegM<16>(ip, block, MEM_REFERENCE(0)))
GENERIC_TRANSLATION(NEG16r, doNegR<16>(ip, block, OP(0)))
GENERIC_TRANSLATION_REF(NEG32m, 
	doNegM<32>(ip, block, ADDR_NOREF(0)),
	doNegM<32>(ip, block, MEM_REFERENCE(0)))
GENERIC_TRANSLATION(NEG32r, doNegR<32>(ip, block, OP(0)))
GENERIC_TRANSLATION_REF(NEG64m,
  doNegM<64>(ip, block, ADDR_NOREF(0)),
  doNegM<64>(ip, block, MEM_REFERENCE(0)))
GENERIC_TRANSLATION(NEG64r, doNegR<64>(ip, block, OP(0)))
GENERIC_TRANSLATION_REF(NEG8m, 
	doNegM<8>(ip, block, ADDR_NOREF(0)),
	doNegM<8>(ip, block, MEM_REFERENCE(0)))
GENERIC_TRANSLATION(NEG8r, doNegR<8>(ip, block, OP(0)))

void INCDECNEG_populateDispatchMap(DispatchMap &m) {
    m[X86::DEC16r] = translate_DEC16r;
    m[X86::DEC8r] = translate_DEC8r;
    m[X86::DEC16m] = translate_DEC16m;
    m[X86::DEC32m] = translate_DEC32m;
    m[X86::DEC64m] = translate_DEC64m;
    m[X86::DEC8m] = translate_DEC8m;
    m[X86::DEC32r] = translate_DEC32r;

    m[X86::DEC64_16r] = translate_DEC64_16r;
    m[X86::DEC64_32r] = translate_DEC64_32r;
    m[X86::DEC64_32m] = translate_DEC64_32m;
    m[X86::DEC64_16m] = translate_DEC64_16m;
    m[X86::DEC64r] = translate_DEC64r;

    m[X86::INC16m] = translate_INC16m;
    m[X86::INC32m] = translate_INC32m;

    // On 64bit r/m8 can't be encoded if REX prefix is used
    m[X86::INC8m] = translate_INC8m;
    m[X86::INC8r] = translate_INC8r;

    // On 64bit INC16r/INC32r can't be encoded
    m[X86::INC16r] = translate_INC16r;
    m[X86::INC32r] = translate_INC32r;

    // Is it required to have check for REX prefix to check register premissions?
    // uses check for REX.W for 64 bit access.
    m[X86::INC64r] = translate_INC64r;
    m[X86::INC64_32r] = translate_INC64_32r;
    m[X86::INC64_16r] = translate_INC64_16r;

    m[X86::INC64m] = translate_INC64m;
    m[X86::INC64_32m] = translate_INC32m;
    m[X86::INC64_16m] = translate_INC16m;

    m[X86::NEG16m] = translate_NEG16m;
    m[X86::NEG16r] = translate_NEG16r;
    m[X86::NEG32m] = translate_NEG32m;
    m[X86::NEG32r] = translate_NEG32r;
    m[X86::NEG64m] = translate_NEG64m;
    m[X86::NEG64r] = translate_NEG64r;
    m[X86::NEG8m] = translate_NEG8m;
    m[X86::NEG8r] = translate_NEG8r;
}
