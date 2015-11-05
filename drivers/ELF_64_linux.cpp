/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include "mc-sema/common/RegisterState.h"

__thread static mcsema::RegState tRegState;

extern "C" int mcsema_main(mcsema::RegState *);

int main(int argc, char **argv) {
  tRegState.RDI = argc;
  tRegState.RSI = reinterpret_cast<uintptr_t>(argv);
  mcsema_main(&tRegState);
  return static_cast<int>(tRegState.RAX);
}
