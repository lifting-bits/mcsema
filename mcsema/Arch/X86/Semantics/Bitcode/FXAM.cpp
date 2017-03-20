#include "mcsema/Arch/X86/Semantics/Bitcode/Instruction.h"
#include <cmath>

// FXAM semantics are adaptd from Remill
DEFINE_SEMANTICS(FXAM)
{
  auto st0 = state->ST0;

  uint8_t sign = __builtin_signbit(st0) == 0 ? 0 : 1;
  auto c = __builtin_fpclassify(FP_NAN, FP_INFINITE, FP_NORMAL, FP_SUBNORMAL,
                                FP_ZERO, st0);
  uint8_t c0;
  uint8_t c1;
  uint8_t c2;
  uint8_t c3;

  switch (c) {
    case FP_NAN:
      c0 = 1;
      c1 = 0;  // Weird.
      c2 = 0;
      c3 = 0;
      break;

    case FP_INFINITE:
      c0 = 1;
      c1 = 0;  // Weird.
      c2 = 1;
      c3 = 0;
      break;

    case FP_ZERO:
      c0 = 0;
      c1 = 0;  // Weird.
      c2 = 0;
      c3 = 1;
      break;

    case FP_SUBNORMAL:
      c0 = 0;
      c1 = sign;
      c2 = 1;
      c3 = 1;
      break;

    case FP_NORMAL:
      c0 = 0;
      c1 = sign;
      c2 = 1;
      c3 = 0;
      break;

    // Using empty or unsupported is valid here, though we use unsupported
    // because we don't actually model empty FPU stack slots.
    default:
      c0 = 0;
      c1 = 0;  // Maybe??
      c2 = 0;
      c3 = 0;
      break;
  }

  state->FPU_FLAG_C0 = c0;
  state->FPU_FLAG_C1 = c1;
  state->FPU_FLAG_C2 = c2;
  state->FPU_FLAG_C3 = c3;
}
