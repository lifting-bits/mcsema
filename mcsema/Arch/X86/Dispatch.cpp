/* Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include "mcsema/Arch/Dispatch.h"

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

void X86InitInstructionDispatch(DispatchMap &dispatcher) {
  FPU_populateDispatchMap(dispatcher);
  MOV_populateDispatchMap(dispatcher);
  CMOV_populateDispatchMap(dispatcher);
  Jcc_populateDispatchMap(dispatcher);
  MULDIV_populateDispatchMap(dispatcher);
  CMPTEST_populateDispatchMap(dispatcher);
  ADD_populateDispatchMap(dispatcher);
  Misc_populateDispatchMap(dispatcher);
  SUB_populateDispatchMap(dispatcher);
  Bitops_populateDispatchMap(dispatcher);
  ShiftRoll_populateDispatchMap(dispatcher);
  Exchanges_populateDispatchMap(dispatcher);
  INCDECNEG_populateDispatchMap(dispatcher);
  Stack_populateDispatchMap(dispatcher);
  String_populateDispatchMap(dispatcher);
  Branches_populateDispatchMap(dispatcher);
  SETcc_populateDispatchMap(dispatcher);
  SSE_populateDispatchMap(dispatcher);
}
