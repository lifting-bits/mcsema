#if 0
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
#include "toLLVM.h"
#include "raiseX86.h"
#include "X86.h"
#include "x86Instrs.h"
#include "x86Helpers.h"
#include "llvm/IR/BasicBlock.h"
#include "x86Instrs_ShiftRoll.h"
#include "x86Instrs_bitops.h"

using namespace llvm;
//using namespace x86;

Value* emit_aullshr(BasicBlock *&b, BasicBlock *nextb) {

    //  shrdl %cl, %edx, %eax
    Value *r_CL = R_READ<32>(b, X86::CL);
    Value *eCL = new ZExtInst(r_CL, 
            Type::getIntNTy(b->getContext(), 64), 
            "", 
            b);

    ShrdVV32(b, X86::EAX, X86::EDX, eCL);

    Value *r_EDX = R_READ<32>(b, X86::EDX);
    r_CL = R_READ<32>(b, X86::CL);
    //  shrl  %cl, %edx
    doShrVV32(b, r_EDX, r_CL);
    Value *r_ECX = R_READ<32>(b, X86::ECX);
    //  andl  $32, %ecx
    doAndVV32(b, r_ECX, CONST_V<32>(b, 32));

    BasicBlock *contBlock = BasicBlock::Create(b->getContext(), "aullshr_contBlock", b->getParent());

    BasicBlock *ifFalse = BasicBlock::Create(b->getContext(), "aullshr_ifFalse", b->getParent());
    //  je    L1
    Value *ZF_val = F_READ(b, ZF);
    BranchInst::Create(contBlock, ifFalse, ZF_val, b);
    //  movl  %edx, %eax
    r_EDX = R_READ<32>(ifFalse, X86::EDX);
    R_WRITE<32>(ifFalse, X86::EAX, r_EDX);
    BranchInst::Create(contBlock, ifFalse);

    //L1:
    //  ret
    //
    Value *retv = R_READ<32>(contBlock, X86::EAX);
    BranchInst::Create(nextb, contBlock);

    return retv;
}

#endif