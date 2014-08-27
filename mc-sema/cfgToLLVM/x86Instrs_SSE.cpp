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
#include "x86Instrs_SSE.h"
#include "x86Instrs_MOV.h"

using namespace llvm;

static InstTransResult translate_MOVSDrm(NativeModulePtr natM, BasicBlock *& block, InstPtr ip, MCInst &inst) 
{
    InstTransResult ret;
    Function *F = block->getParent();
    if( ip->has_external_ref()) {
        Value *addrInt = getValueForExternal<64>(F->getParent(), ip, block);
        //ret = doRMMov<32>(ip, block, addrInt, OP(0) );
        TASSERT(addrInt != NULL, "Could not get address for external");
        R_WRITE<64>(block, OP(0).getReg(), addrInt);
        return ContinueBlock;
    }
    else if( ip->is_data_offset() ) {
        ret = doRMMov<64>(ip, block, 
                GLOBAL( block, natM, inst, ip, 1 ),
                OP(0) );
    } else {
        ret = doRMMov<64>(ip, block, ADDR(1), OP(0));
    }
    return ret ;
}

static InstTransResult translate_MOVSDmr(NativeModulePtr natM, BasicBlock *& block, InstPtr ip, MCInst &inst) 
{
    InstTransResult ret;
    Function *F = block->getParent();
    if( ip->has_external_ref()) {
        Value *addrInt = getValueForExternal<64>(F->getParent(), ip, block);
        TASSERT(addrInt != NULL, "Could not get address for external");
        return doMRMov<64>(ip, block, addrInt, OP(5) );
    }
    else if( ip->is_data_offset() ) {
        ret = doMRMov<64>(ip, block, GLOBAL( block, natM, inst, ip, 0), OP(5) );
    } else { 
        ret = doMRMov<64>(ip, block, ADDR(0), OP(5)) ; 
    }
    return ret ; 
}

void SSE_populateDispatchMap(DispatchMap &m) {
    m[X86::MOVSDrm] = translate_MOVSDrm;
    m[X86::MOVSDmr] = translate_MOVSDmr;
}
