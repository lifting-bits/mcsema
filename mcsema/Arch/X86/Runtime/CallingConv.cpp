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

#include "remill/Arch/Runtime/Operators.h"

#include "remill/Arch/X86/Runtime/State.h"

extern "C" {

#define MAKE_REG_ARG(cc, n, reg) \
    addr_t __mcsema_ ## cc ## _arg_ ## n(Memory *, State &state) { \
      return state.gpr.reg.aword; \
    }

#define MAKE_VEC_ARG(cc, n, vec_base, i) \
    addr_t __mcsema_ ## cc ## _arg_ ## n(Memory *, State &state) { \
      return state.vec[i].vec_base.IF_64BIT_ELSE(qwords, dwords).elems[0]; \
    }

#define MAKE_MEM_ARG(cc, n, base_reg, index) \
    addr_t __mcsema_ ## cc ## _arg_ ## n(Memory *memory, State &state) { \
      auto base = ReadPtr<addr_t>(state.gpr.base_reg.aword); \
      return Read(GetElementPtr(base, addr_t(index))); \
    }

#define MAKE_REG_RET(cc, reg) \
    Memory *__mcsema_ ## cc ## _ret(Memory *memory, State &state, addr_t val) {\
      state.gpr.reg.aword = val; \
      return memory; \
    }

#if 32 == ADDRESS_SIZE_BITS

MAKE_REG_RET(cdecl, eax)

// Note: We use `1` as the index from `rsp` because the push of the return
//       address will have already been emulated.
MAKE_MEM_ARG(cdecl, 1, rsp, 1)
MAKE_MEM_ARG(cdecl, 2, rsp, 2)
MAKE_MEM_ARG(cdecl, 3, rsp, 3)
MAKE_MEM_ARG(cdecl, 4, rsp, 4)
MAKE_MEM_ARG(cdecl, 5, rsp, 5)
MAKE_MEM_ARG(cdecl, 6, rsp, 6)
MAKE_MEM_ARG(cdecl, 7, rsp, 7)
MAKE_MEM_ARG(cdecl, 8, rsp, 8)
MAKE_MEM_ARG(cdecl, 9, rsp, 9)
MAKE_MEM_ARG(cdecl, 10, rsp, 10)
MAKE_MEM_ARG(cdecl, 11, rsp, 11)
MAKE_MEM_ARG(cdecl, 12, rsp, 12)
MAKE_MEM_ARG(cdecl, 13, rsp, 13)
MAKE_MEM_ARG(cdecl, 14, rsp, 14)
MAKE_MEM_ARG(cdecl, 15, rsp, 15)
MAKE_MEM_ARG(cdecl, 16, rsp, 16)


MAKE_REG_RET(stdcall, eax)

// Note: We use `1` as the index from `rsp` because the push of the return
//       address will have already been emulated.
MAKE_MEM_ARG(stdcall, 1, rsp, 1)
MAKE_MEM_ARG(stdcall, 2, rsp, 2)
MAKE_MEM_ARG(stdcall, 3, rsp, 3)
MAKE_MEM_ARG(stdcall, 4, rsp, 4)
MAKE_MEM_ARG(stdcall, 5, rsp, 5)
MAKE_MEM_ARG(stdcall, 6, rsp, 6)
MAKE_MEM_ARG(stdcall, 7, rsp, 7)
MAKE_MEM_ARG(stdcall, 8, rsp, 8)
MAKE_MEM_ARG(stdcall, 9, rsp, 9)
MAKE_MEM_ARG(stdcall, 10, rsp, 10)
MAKE_MEM_ARG(stdcall, 11, rsp, 11)
MAKE_MEM_ARG(stdcall, 12, rsp, 12)
MAKE_MEM_ARG(stdcall, 13, rsp, 13)
MAKE_MEM_ARG(stdcall, 14, rsp, 14)
MAKE_MEM_ARG(stdcall, 15, rsp, 15)
MAKE_MEM_ARG(stdcall, 16, rsp, 16)

MAKE_REG_RET(fastcall, eax)

// Note: We use `1` as the index from `rsp` because the push of the return
//       address will have already been emulated.
MAKE_REG_ARG(fastcall, 1, rcx)
MAKE_REG_ARG(fastcall, 2, rdx)
MAKE_MEM_ARG(fastcall, 3, rsp, 1)
MAKE_MEM_ARG(fastcall, 4, rsp, 2)
MAKE_MEM_ARG(fastcall, 5, rsp, 3)
MAKE_MEM_ARG(fastcall, 6, rsp, 4)
MAKE_MEM_ARG(fastcall, 7, rsp, 5)
MAKE_MEM_ARG(fastcall, 8, rsp, 6)
MAKE_MEM_ARG(fastcall, 9, rsp, 7)
MAKE_MEM_ARG(fastcall, 10, rsp, 8)
MAKE_MEM_ARG(fastcall, 11, rsp, 9)
MAKE_MEM_ARG(fastcall, 12, rsp, 10)
MAKE_MEM_ARG(fastcall, 13, rsp, 11)
MAKE_MEM_ARG(fastcall, 14, rsp, 12)
MAKE_MEM_ARG(fastcall, 15, rsp, 13)
MAKE_MEM_ARG(fastcall, 16, rsp, 14)

#else  // 32 == ADDRESS_SIZE_BITS

MAKE_REG_RET(amd64_sysv, rax)
MAKE_REG_ARG(amd64_sysv, 1, rdi)
MAKE_REG_ARG(amd64_sysv, 2, rsi)
MAKE_REG_ARG(amd64_sysv, 3, rdx)
MAKE_REG_ARG(amd64_sysv, 4, rcx)
MAKE_REG_ARG(amd64_sysv, 5, r8)
MAKE_REG_ARG(amd64_sysv, 6, r9)
MAKE_VEC_ARG(amd64_sysv, 7, xmm, 0)
MAKE_VEC_ARG(amd64_sysv, 8, xmm, 1)
MAKE_VEC_ARG(amd64_sysv, 9, xmm, 2)
MAKE_VEC_ARG(amd64_sysv, 10, xmm, 3)
MAKE_VEC_ARG(amd64_sysv, 11, xmm, 4)
MAKE_VEC_ARG(amd64_sysv, 12, xmm, 5)
MAKE_VEC_ARG(amd64_sysv, 13, xmm, 6)
MAKE_VEC_ARG(amd64_sysv, 14, xmm, 7)
MAKE_MEM_ARG(amd64_sysv, 15, rsp, 1)  // Note: return address on stack.
MAKE_MEM_ARG(amd64_sysv, 16, rsp, 2)

MAKE_REG_RET(amd64_win64, rax)
MAKE_REG_ARG(amd64_win64, 1, rcx)
MAKE_REG_ARG(amd64_win64, 2, rdx)
MAKE_REG_ARG(amd64_win64, 3, r8)
MAKE_REG_ARG(amd64_win64, 4, r9)
MAKE_MEM_ARG(amd64_win64, 5, rsp, 1)  // Note: return address on stack.
MAKE_MEM_ARG(amd64_win64, 6, rsp, 2)
MAKE_MEM_ARG(amd64_win64, 7, rsp, 3)
MAKE_MEM_ARG(amd64_win64, 8, rsp, 4)
MAKE_MEM_ARG(amd64_win64, 9, rsp, 5)
MAKE_MEM_ARG(amd64_win64, 10, rsp, 6)
MAKE_MEM_ARG(amd64_win64, 11, rsp, 7)
MAKE_MEM_ARG(amd64_win64, 12, rsp, 8)
MAKE_MEM_ARG(amd64_win64, 13, rsp, 9)
MAKE_MEM_ARG(amd64_win64, 14, rsp, 10)
MAKE_MEM_ARG(amd64_win64, 15, rsp, 11)
MAKE_MEM_ARG(amd64_win64, 16, rsp, 12)

#endif  // 64 == ADDRESS_SIZE_BITS

}  // extern C
