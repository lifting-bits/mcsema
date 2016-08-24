/* Copyright 2015 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <string>
#include <sstream>

#include "mc-sema/common/RegisterState.h"

struct alignas(128) Stack {
  char data[1UL << 22U];
};

static __thread mcsema::RegState tRegState;
static __thread Stack tStack;

extern "C" int mcsema_main(mcsema::RegState *);
extern "C" void __mcsema_init(void);
extern "C" int main(int argc, char **argv, char **envp) {
  tRegState.RDI = argc;
  tRegState.RSI = reinterpret_cast<uintptr_t>(argv);
  tRegState.RDX = reinterpret_cast<uintptr_t>(envp);
  tRegState.RSP = reinterpret_cast<uintptr_t>(&tStack + 1);
  __mcsema_init();
  mcsema_main(&tRegState);
  return static_cast<int>(tRegState.RAX);
}
