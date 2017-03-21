#pragma once

#include "mcsema/Arch/X86/Runtime/State.h"

#define DEFINE_SEMANTICS( INST ) extern "C" void __mcsema_ ## INST ( RegState *state )
