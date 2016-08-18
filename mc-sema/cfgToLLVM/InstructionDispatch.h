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
#ifndef _INS_DISPATCH_H
#define _INS_DISPATCH_H
#include "llvm/MC/MCInst.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/InstrTypes.h"
#include <map>
#include "peToCFG.h"
#include "raiseX86.h"

typedef InstTransResult(*TranslationFuncPtr)(NativeModulePtr natM, llvm::BasicBlock *&block, InstPtr ip, llvm::MCInst &inst);
typedef std::map<unsigned, TranslationFuncPtr> DispatchMap;

extern DispatchMap translationDispatchMap;

bool initInstructionDispatch();

#define OP(x) inst.getOperand(x)
//#define ADDR(x) getAddrFromExpr(block, natM, inst, ip, x)
//#define ADDR_NOREF(x) \
//	getPointerSize(block->getParent()->getParent()) == Pointer32 ?	\
//		x86::getAddrFromExpr(block, natM, OP(x+0), OP(x+1), OP(x+2), OP(x+3).getImm(), OP(x+4), false) :\
//		x86_64::getAddrFromExpr(block, natM, OP(x+0), OP(x+1), OP(x+2), OP(x+3).getImm(), OP(x+4), false)

#define ADDR_NOREF(x) getPointerSize(block->getParent()->getParent()) == Pointer32 ? \
    ADDR_NOREF_IMPL<32>(natM, block, x, ip, inst) :\
    ADDR_NOREF_IMPL<64>(natM, block, x, ip, inst)

#define CREATE_BLOCK(nm, b) BasicBlock *block_ ## nm = BasicBlock::Create((b)->getContext(), #nm, (b)->getParent())
#define MEM_REFERENCE(which) MEM_AS_DATA_REF(block, natM, inst, ip, which)

#define GENERIC_TRANSLATION_MI(NAME, NOREFS, MEMREF, IMMREF, TWOREFS) static InstTransResult translate_ ## NAME (NativeModulePtr natM, BasicBlock *&block, InstPtr ip, MCInst &inst) {\
    InstTransResult ret;\
    Function *F = block->getParent(); \
    if( ip->has_mem_reference && ip->has_imm_reference) {\
        TWOREFS; \
    } else if( ip->has_mem_reference ) { \
        MEMREF; \
    } else if( ip->has_imm_reference ) { \
        IMMREF; \
    } else { \
        NOREFS; \
    } \
    return ContinueBlock;\
}


#define GENERIC_TRANSLATION_REF(NAME, NOREFS, HASREF) static InstTransResult translate_ ## NAME (NativeModulePtr natM, BasicBlock *&block, InstPtr ip, MCInst &inst) {\
    InstTransResult ret;\
    Function *F = block->getParent(); \
    if( ip->has_mem_reference || ip->has_imm_reference) {\
        HASREF;\
    } else {\
        NOREFS;\
    }\
    return ContinueBlock;\
}

#define GENERIC_TRANSLATION(NAME, NOREFS) static InstTransResult translate_ ## NAME (NativeModulePtr natM, BasicBlock *&block, InstPtr ip, MCInst &inst) {\
    InstTransResult ret;\
    ret = NOREFS;\
    return ret;\
}
#endif
