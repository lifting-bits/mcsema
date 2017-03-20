#include "mcsema/Arch/X86/Runtime/State.h"

#define DEFINE_SEMANTICS( INST ) void __mcsema_ ## INST ## (RegState *state)
