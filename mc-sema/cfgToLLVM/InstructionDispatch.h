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
#include "llvm/Module.h"
#include "llvm/Type.h"
#include "llvm/Constants.h"
#include "llvm/DerivedTypes.h"
#include "llvm/Instructions.h"
#include "llvm/Intrinsics.h"
#include "llvm/InstrTypes.h"
#include <map>
#include "peToCFG.h"
#include "raiseX86.h"

typedef InstTransResult(*TranslationFuncPtr)(NativeModulePtr natM, llvm::BasicBlock *&block, InstPtr ip, llvm::MCInst &inst);
typedef std::map<unsigned, TranslationFuncPtr> DispatchMap;

extern DispatchMap translationDispatchMap;

bool initInstructionDispatch();

#define OP(x) inst.getOperand(x)
#define ADDR(x) getAddrFromExpr(block, natM, inst, ip, x)
#define ADDR_NOREF(x) getAddrFromExpr(block, natM, OP(x+0), OP(x+1), OP(x+2), OP(x+3).getImm(), OP(x+4), false)
#define CREATE_BLOCK(nm, b) BasicBlock *block_ ## nm = BasicBlock::Create((b)->getContext(), #nm, (b)->getParent())
#define STD_GLOBAL_OP(which) GLOBAL(block, natM, inst, ip, which)

#define GENERIC_TRANSLATION_32MI(NAME, THECALL, GLOBALCALL, GLOBALIMMCALL) static InstTransResult translate_ ## NAME (NativeModulePtr natM, BasicBlock *&block, InstPtr ip, MCInst &inst) {\
    InstTransResult ret;\
    Function *F = block->getParent(); \
    if( ip->is_data_offset() ) { \
        if( ip->get_reloc_offset() < OP(5).getOffset() ) { \
            GLOBALCALL; \
        } else { \
            GLOBALIMMCALL; \
        } \
        ret = ContinueBlock; \
    } else { \
        ret = THECALL; \
    }\
    return ret;\
}


#define GENERIC_TRANSLATION_MEM(NAME, THECALL, GLOBALCALL) static InstTransResult translate_ ## NAME (NativeModulePtr natM, BasicBlock *&block, InstPtr ip, MCInst &inst) {\
    InstTransResult ret;\
    Function *F = block->getParent(); \
    if( ip->is_data_offset() ) {\
        GLOBALCALL;\
        ret = ContinueBlock;\
    } else {\
        ret = THECALL;\
    }\
    return ret;\
}

#define GENERIC_TRANSLATION(NAME, THECALL) static InstTransResult translate_ ## NAME (NativeModulePtr natM, BasicBlock *&block, InstPtr ip, MCInst &inst) {\
    InstTransResult ret;\
    ret = THECALL;\
    return ret;\
}
#endif
