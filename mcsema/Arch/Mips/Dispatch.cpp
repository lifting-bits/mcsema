/* Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include "mcsema/Arch/Dispatch.h"

#include "mcsema/Arch/Mips/Semantics/ADDiu.h"
#include "mcsema/Arch/Mips/Semantics/ADDu.h"
#include "mcsema/Arch/Mips/Semantics/B.h"
#include "mcsema/Arch/Mips/Semantics/BEQ.h"
#include "mcsema/Arch/Mips/Semantics/BNE.h"
#include "mcsema/Arch/Mips/Semantics/JAL.h"
#include "mcsema/Arch/Mips/Semantics/JALR.h"
#include "mcsema/Arch/Mips/Semantics/JR.h"
#include "mcsema/Arch/Mips/Semantics/LUi.h"
#include "mcsema/Arch/Mips/Semantics/LW.h"
#include "mcsema/Arch/Mips/Semantics/OR.h"
#include "mcsema/Arch/Mips/Semantics/SB.h"
#include "mcsema/Arch/Mips/Semantics/SW.h"

#include "mcsema/Arch/Mips/Semantics/SRA.h"
#include "mcsema/Arch/Mips/Semantics/SLL.h"
#include "mcsema/Arch/Mips/Semantics/SLT.h"
#include "mcsema/Arch/Mips/Semantics/SLTi.h"
#include "mcsema/Arch/Mips/Semantics/SLTu.h"
#include "mcsema/Arch/Mips/Semantics/SLTiu.h"
#include "mcsema/Arch/Mips/Semantics/ADD.h"
#include "mcsema/Arch/Mips/Semantics/ADDi.h"
#include "mcsema/Arch/Mips/Semantics/AND.h"
#include "mcsema/Arch/Mips/Semantics/ANDi.h"
#include "mcsema/Arch/Mips/Semantics/SUB.h"
#include "mcsema/Arch/Mips/Semantics/SUBu.h"
#include "mcsema/Arch/Mips/Semantics/DIV.h"

#include "mcsema/Arch/Mips/Semantics/MULT.h"
#include "mcsema/Arch/Mips/Semantics/NOR.h"
#include "mcsema/Arch/Mips/Semantics/J.h"
#include "mcsema/Arch/Mips/Semantics/XOR.h"
#include "mcsema/Arch/Mips/Semantics/MFC0.h"
#include "mcsema/Arch/Mips/Semantics/LHu.h"
#include "mcsema/Arch/Mips/Semantics/LBu.h"
#include "mcsema/Arch/Mips/Semantics/SH.h"
#include "mcsema/Arch/Mips/Semantics/MFLO.h"
#include "mcsema/Arch/Mips/Semantics/ORi.h"

void MipsInitInstructionDispatch(DispatchMap &dispatcher) {
  ADDiu_populateDispatchMap(dispatcher);
  ADDu_populateDispatchMap(dispatcher);
  B_populateDispatchMap(dispatcher);
  BEQ_populateDispatchMap(dispatcher);
  BNE_populateDispatchMap(dispatcher);
  JAL_populateDispatchMap(dispatcher);
  JALR_populateDispatchMap(dispatcher);
  JR_populateDispatchMap(dispatcher);
  LUi_populateDispatchMap(dispatcher);
  LW_populateDispatchMap(dispatcher);
  OR_populateDispatchMap(dispatcher);
  SB_populateDispatchMap(dispatcher);
  SW_populateDispatchMap(dispatcher);
  SRA_populateDispatchMap(dispatcher);
  SLL_populateDispatchMap(dispatcher);
  SLT_populateDispatchMap(dispatcher);
  J_populateDispatchMap(dispatcher);
  SLTi_populateDispatchMap(dispatcher);
  SLTiu_populateDispatchMap(dispatcher);
  SUBMips_populateDispatchMap(dispatcher);
  SUBu_populateDispatchMap(dispatcher);
  DIV_populateDispatchMap(dispatcher);
  AND_populateDispatchMap(dispatcher);
  ANDi_populateDispatchMap(dispatcher);
  ADDMips_populateDispatchMap(dispatcher);
  ADDi_populateDispatchMap(dispatcher);
  XOR_populateDispatchMap(dispatcher);
  NOR_populateDispatchMap(dispatcher);
  MFLO_populateDispatchMap(dispatcher);
  SLTu_populateDispatchMap(dispatcher);
  ORi_populateDispatchMap(dispatcher);
  LHu_populateDispatchMap(dispatcher);
  LBu_populateDispatchMap(dispatcher);
  MULT_populateDispatchMap(dispatcher);
  SH_populateDispatchMap(dispatcher);
}
