/* Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include "pin.H"

#include <cstdint>
#include <cstdio>
#include <iostream>
#include <sstream>


KNOB<uintptr_t> gEntrypoint(
    KNOB_MODE_WRITEONCE, "pintool", "entrypoint", "0",
    "Entrypoint of lifted program. Usually address of `main`.");

struct RegInfo final {
  const char *name;
  LEVEL_BASE::REG reg;
};

static uintptr_t gLowAddr = 0;
static uintptr_t gHighAddr = 0;

#ifdef __x86_64__

static const struct RegInfo gGprs[] = {
  {"RIP", LEVEL_BASE::REG_RIP},
  {"RAX", LEVEL_BASE::REG_RAX},
  {"RBX", LEVEL_BASE::REG_RBX},
  {"RCX", LEVEL_BASE::REG_RCX},
  {"RDX", LEVEL_BASE::REG_RDX},
  {"RSI", LEVEL_BASE::REG_RSI},
  {"RDI", LEVEL_BASE::REG_RDI},
  {"RBP", LEVEL_BASE::REG_RBP},
  {"RSP", LEVEL_BASE::REG_RSP},
  {"R8", LEVEL_BASE::REG_R8},
  {"R9", LEVEL_BASE::REG_R9},
  {"R10", LEVEL_BASE::REG_R10},
  {"R11", LEVEL_BASE::REG_R11},
  {"R12", LEVEL_BASE::REG_R12},
  {"R13", LEVEL_BASE::REG_R13},
  {"R14", LEVEL_BASE::REG_R14},
  {"R15", LEVEL_BASE::REG_R15},
};

#else

static const struct RegInfo gGprs[] = {
  {"EIP", LEVEL_BASE::REG_EIP},
  {"EAX", LEVEL_BASE::REG_EAX},
  {"EBX", LEVEL_BASE::REG_EBX},
  {"ECX", LEVEL_BASE::REG_ECX},
  {"EDX", LEVEL_BASE::REG_EDX},
  {"ESI", LEVEL_BASE::REG_ESI},
  {"EDI", LEVEL_BASE::REG_EDI},
  {"EBP", LEVEL_BASE::REG_EBP},
  {"ESP", LEVEL_BASE::REG_ESP},
};

#endif  // __x86_64__

VOID PrintRegState(CONTEXT *ctx) {
  static bool gPrinting = false;
  if (!gPrinting) {
    gPrinting = gEntrypoint.Value() == PIN_GetContextReg(ctx, gGprs[0].reg);
    if (!gPrinting) {
      return;
    }
  }

  std::stringstream ss;

  const char *sep = "";
  for (auto &gpr : gGprs) {
    ss
        << sep << gpr.name << "=" << std::hex
        << PIN_GetContextReg(ctx, gpr.reg);
    sep = " ";
  }

  // `-add-reg-tracer` uses `printf`, so even though it's a bit weird, we'll
  // do it here too and hopefully achieve some similar buffering.
  printf("%s\n", ss.str().c_str());
}

VOID InstrumentInstruction(INS ins, VOID *) {
  if (INS_Address(ins) >= gLowAddr && INS_Address(ins) <= gHighAddr) {
  INS_InsertCall(
      ins, IPOINT_BEFORE, (AFUNPTR)PrintRegState, IARG_CONTEXT, IARG_END);
  }
}

VOID FindEntrypoint(IMG img, void *) {
  auto low = IMG_LowAddress(img);
  auto high = IMG_HighAddress(img);
  if (low <= gEntrypoint.Value() && gEntrypoint.Value() <= high) {
    gLowAddr = low;
    gHighAddr = high;
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
