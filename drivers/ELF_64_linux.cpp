/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <string>
#include <sstream>

#include "mc-sema/common/RegisterState.h"

struct alignas(128) Stack {
  char data[1UL << 20U];
};

static __thread mcsema::RegState tRegState;
static __thread Stack tStack;

extern "C" int mcsema_main(mcsema::RegState *);

int main(int argc, char **argv) {
  tRegState.RDI = argc;
  tRegState.RSI = reinterpret_cast<uintptr_t>(argv);
  tRegState.RSP = reinterpret_cast<uintptr_t>(&tStack + 1);
  mcsema_main(&tRegState);
  return static_cast<int>(tRegState.RAX);
}
