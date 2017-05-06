/*
 * Copyright (c) 2017 Trail of Bits, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cstdio>
#include <inttypes.h>

#define HAS_FEATURE_AVX 1
#define HAS_FEATURE_AVX512 0
#define ADDRESS_SIZE_BITS 64

#include "remill/Arch/X86/Runtime/State.h"
#include "mcsema/Arch/X86/Runtime/Registers.h"

extern "C" {

Memory *__mcsema_reg_tracer(Memory *memory, State &state, uintptr_t) {
  const char *format = nullptr;
  if (sizeof(void *) == 8) {
    fprintf(
        stderr,
        "RIP=%16" PRIx64 " RAX=%16" PRIx64 " RBX=%16" PRIx64
        " RCX=%16" PRIx64 " RDX=%16" PRIx64 " RSI=%16" PRIx64
        " RDI=%16" PRIx64 " RBP=%16" PRIx64 " RSP=%16" PRIx64
        " R8=%16" PRIx64 " R9=%16" PRIx64 " R10=%16" PRIx64
        " R11=%16" PRIx64 " R12=%16" PRIx64 " R13=%16" PRIx64
        " R14=%16" PRIx64 " R15=%16" PRIx64 "\n",

        state.RIP, state.RAX, state.RBX, state.RCX, state.RDX, state.RSI,
        state.RDI, state.RBP, state.RSP, state.R8, state.R9, state.R10,
        state.R11, state.R12, state.R13, state.R14, state.R15);
  } else {
    fprintf(
        stderr,
        "EIP=%8" PRIx32 " EAX=%8" PRIx32 " EBX=%8" PRIx32
        " ECX=%8" PRIx32 " EDX=%8" PRIx32 " ESI=%8" PRIx32
        " EDI=%8" PRIx32 " ESP=%8" PRIx32 " EBP=%8" PRIx32 "\n",
        state.EIP, state.EAX, state.EBX, state.ECX, state.EDX, state.ESI,
        state.EDI, state.EBP, state.ESP);
  }
  return memory;
}

}  // extern C
