/* Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include "mcsema/Arch/Dispatch.h"

#include "mcsema/Arch/X86/Semantics/fpu.h"
#include "mcsema/Arch/X86/Semantics/MOV.h"
#include "mcsema/Arch/X86/Semantics/CMOV.h"
#include "mcsema/Arch/X86/Semantics/Jcc.h"
#include "mcsema/Arch/X86/Semantics/MULDIV.h"
#include "mcsema/Arch/X86/Semantics/CMPTEST.h"
#include "mcsema/Arch/X86/Semantics/ADD.h"
#include "mcsema/Arch/X86/Semantics/SUB.h"
#include "mcsema/Arch/X86/Semantics/Misc.h"
#include "mcsema/Arch/X86/Semantics/bitops.h"
#include "mcsema/Arch/X86/Semantics/ShiftRoll.h"
#include "mcsema/Arch/X86/Semantics/Exchanges.h"
#include "mcsema/Arch/X86/Semantics/INCDECNEG.h"
#include "mcsema/Arch/X86/Semantics/Stack.h"
#include "mcsema/Arch/X86/Semantics/String.h"
#include "mcsema/Arch/X86/Semantics/Branches.h"
#include "mcsema/Arch/X86/Semantics/SETcc.h"
#include "mcsema/Arch/X86/Semantics/SSE.h"

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
