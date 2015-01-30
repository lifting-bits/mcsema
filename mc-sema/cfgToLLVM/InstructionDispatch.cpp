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
#include "llvm/MC/MCInst.h"
#include "llvm/IR/Intrinsics.h"
#include "x86Instrs_fpu.h"
#include "x86Instrs_MOV.h"
#include "x86Instrs_CMOV.h"
#include "x86Instrs_Jcc.h"
#include "x86Instrs_MULDIV.h"
#include "x86Instrs_CMPTEST.h"
#include "x86Instrs_ADD.h"
#include "x86Instrs_SUB.h"
#include "x86Instrs_Misc.h"
#include "x86Instrs_bitops.h"
#include "x86Instrs_ShiftRoll.h"
#include "x86Instrs_Exchanges.h"
#include "x86Instrs_INCDECNEG.h"
#include "x86Instrs_Stack.h"
#include "x86Instrs_String.h"
#include "x86Instrs_Branches.h"
#include "x86Instrs_SETcc.h"
#include "x86Instrs_SSE.h"

DispatchMap translationDispatchMap;

bool initInstructionDispatch() {

    FPU_populateDispatchMap(translationDispatchMap);
    MOV_populateDispatchMap(translationDispatchMap);
    CMOV_populateDispatchMap(translationDispatchMap);
    Jcc_populateDispatchMap(translationDispatchMap);
    MULDIV_populateDispatchMap(translationDispatchMap);
    CMPTEST_populateDispatchMap(translationDispatchMap);
    ADD_populateDispatchMap(translationDispatchMap);
    Misc_populateDispatchMap(translationDispatchMap);
    SUB_populateDispatchMap(translationDispatchMap);
    Bitops_populateDispatchMap(translationDispatchMap);
    ShiftRoll_populateDispatchMap(translationDispatchMap);
    Exchanges_populateDispatchMap(translationDispatchMap);
    INCDECNEG_populateDispatchMap(translationDispatchMap);
    Stack_populateDispatchMap(translationDispatchMap);
    String_populateDispatchMap(translationDispatchMap);
    Branches_populateDispatchMap(translationDispatchMap);
    SETcc_populateDispatchMap(translationDispatchMap);
    SSE_populateDispatchMap(translationDispatchMap);

    return true;
}
