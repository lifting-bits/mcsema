/*
 * Copyright (c) 2020 Trail of Bits, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <cstdint>
#include <cstdio>
#include <iomanip>
#include <iostream>
#include <sstream>

#include "pin.H"

KNOB<uintptr_t>
    gEntrypoint(KNOB_MODE_WRITEONCE, "pintool", "entrypoint", "0",
                "Entrypoint of lifted program. Usually address of `main`.");

KNOB<uintptr_t> gStopAt(KNOB_MODE_WRITEONCE, "pintool", "stop_at", "0",
                        "Address of code for when tracing should stop.");

struct RegInfo final {
  const char *name;
  LEVEL_BASE::REG reg;
};

static uintptr_t gLowAddr = 0;
static uintptr_t gHighAddr = 0;

static uintptr_t gLowExcludeAddr = 0;
static uintptr_t gHighExcludeAddr = 0;
#ifdef __x86_64__

static const struct RegInfo gGprs[] = {
    {"RIP", LEVEL_BASE::REG_RIP}, {"RAX", LEVEL_BASE::REG_RAX},
    {"RBX", LEVEL_BASE::REG_RBX}, {"RCX", LEVEL_BASE::REG_RCX},
    {"RDX", LEVEL_BASE::REG_RDX}, {"RSI", LEVEL_BASE::REG_RSI},
    {"RDI", LEVEL_BASE::REG_RDI}, {"RBP", LEVEL_BASE::REG_RBP},
    {"RSP", LEVEL_BASE::REG_RSP}, {"R8", LEVEL_BASE::REG_R8},
    {"R9", LEVEL_BASE::REG_R9},   {"R10", LEVEL_BASE::REG_R10},
    {"R11", LEVEL_BASE::REG_R11}, {"R12", LEVEL_BASE::REG_R12},
    {"R13", LEVEL_BASE::REG_R13}, {"R14", LEVEL_BASE::REG_R14},
    {"R15", LEVEL_BASE::REG_R15},
};

#else

static const struct RegInfo gGprs[] = {
    {"EIP", LEVEL_BASE::REG_EIP}, {"EAX", LEVEL_BASE::REG_EAX},
    {"EBX", LEVEL_BASE::REG_EBX}, {"ECX", LEVEL_BASE::REG_ECX},
    {"EDX", LEVEL_BASE::REG_EDX}, {"ESI", LEVEL_BASE::REG_ESI},
    {"EDI", LEVEL_BASE::REG_EDI}, {"EBP", LEVEL_BASE::REG_EBP},
    {"ESP", LEVEL_BASE::REG_ESP},
};

#endif  // __x86_64__

static bool gPrinting = false;
static unsigned gRepCount = 0;

VOID ClearReps(void) {
  gRepCount = 0;
}

VOID CountReps(void) {
  gRepCount++;
}

VOID PrintRegState(CONTEXT *ctx) {
  if (gRepCount > 1) {
    return;
  }

  auto pc = PIN_GetContextReg(ctx, gGprs[0].reg);
  if (!gPrinting) {
    gPrinting = gEntrypoint.Value() == pc;
    if (!gPrinting) {
      return;
    }
  }

  if (gStopAt.Value() == pc) {
    PIN_ExitApplication(0);
  }

  std::stringstream ss;
  const char *sep = "";
  for (auto &gpr : gGprs) {
    ss << sep << gpr.name << "=" << std::hex << std::setw(0)
       << PIN_GetContextReg(ctx, gpr.reg);
    sep = ",";
  }

  // `-add-reg-tracer` uses `printf`, so even though it's a bit weird, we'll
  // do it here too and hopefully achieve some similar buffering.
  fprintf(stderr, "%s\n", ss.str().c_str());
}

VOID InstrumentInstruction(INS ins, VOID *) {
  auto addr = INS_Address(ins);

  if (addr >= gLowAddr && addr < gHighAddr) {

    // A thunk; only include the address of the first instruction.
    if (addr >= gLowExcludeAddr && addr < gHighExcludeAddr) {
      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) CountReps, IARG_END);

    // Normal code.
    } else {
      if (INS_HasRealRep(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) CountReps, IARG_END);
      } else {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) ClearReps, IARG_END);
      }
    }

    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) PrintRegState, IARG_CONTEXT,
                   IARG_END);
  }
}

VOID FindEntrypoint(IMG img, void *) {
  auto low = IMG_LowAddress(img);
  auto high = IMG_HighAddress(img);
  if (low <= gEntrypoint.Value() && gEntrypoint.Value() <= high) {
    gLowAddr = low;
    gHighAddr = high;

    // Find
    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
      if (SEC_Name(sec) == ".plt" || SEC_Name(sec) == ".PLT") {
        gLowExcludeAddr = SEC_Address(sec);
        gHighExcludeAddr = gLowExcludeAddr + SEC_Size(sec);
      }
    }
  }
}

int main(int argc, char *argv[]) {
  PIN_InitSymbols();
  PIN_Init(argc, argv);

  for (IMG img = APP_ImgHead(); IMG_Valid(img); img = IMG_Next(img)) {
    FindEntrypoint(img, nullptr);
  }

  IMG_AddInstrumentFunction(FindEntrypoint, nullptr);
  INS_AddInstrumentFunction(InstrumentInstruction, nullptr);
  PIN_StartProgram();
  return 0;
}
