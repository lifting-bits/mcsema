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

#include <inttypes.h>
#include <stdlib.h>

#include <cfenv>
#include <cfloat>
#include <cstdio>

#define HAS_FEATURE_AVX 1
#define HAS_FEATURE_AVX512 0

#ifndef ADDRESS_SIZE_BITS
#  define ADDRESS_SIZE_BITS 64
#endif

#include "mcsema/Arch/X86/Runtime/Registers.h"
#include "remill/Arch/X86/Runtime/State.h"

#ifndef PRIx64
#  define PRIx64 "llx"
#endif

#ifndef PRIx32
#  define PRIx32 "x"
#endif

#if ADDRESS_SIZE_BITS == 64
#  define PRIxADDR PRIx64
#else
#  define PRIxADDR PRIx32
#endif

extern "C" {

// Debug registers.
uint64_t DR0;
uint64_t DR1;
uint64_t DR2;
uint64_t DR3;
uint64_t DR4;
uint64_t DR5;
uint64_t DR6;
uint64_t DR7;

// Control regs.
CR0Reg gCR0;
CR1Reg gCR1;
CR2Reg gCR2;
CR3Reg gCR3;
CR4Reg gCR4;
CR8Reg gCR8;

// enum : size_t {
//   kStackSize = 1UL << 20UL
// };

// struct alignas(16) Stack {
//   uint8_t bytes[kStackSize];  // 1 MiB.
// };

// __thread State __mcsema_reg_state;
// __thread Stack __mcsema_stack;

// State *__mcsema_get_reg_state(void) {
//   return &__mcsema_reg_state;
// }

// uint8_t *__mcsema_get_stack(void) {
//   return &(__mcsema_stack.bytes[kStackSize - 16UL]);
// }

Memory *__remill_sync_hyper_call(State &state, Memory *mem,
                                 SyncHyperCall::Name call) {
  auto eax = state.gpr.rax.dword;
  auto ebx = state.gpr.rbx.dword;
  auto ecx = state.gpr.rcx.dword;
  auto edx = state.gpr.rdx.dword;

  switch (call) {
    case SyncHyperCall::kX86CPUID:
      state.gpr.rax.aword = 0;
      state.gpr.rbx.aword = 0;
      state.gpr.rcx.aword = 0;
      state.gpr.rdx.aword = 0;

      asm volatile("cpuid"
                   : "=a"(state.gpr.rax.dword), "=b"(state.gpr.rbx.dword),
                     "=c"(state.gpr.rcx.dword), "=d"(state.gpr.rdx.dword)
                   : "a"(eax), "b"(ebx), "c"(ecx), "d"(edx));
      break;

    case SyncHyperCall::kX86ReadTSC:
      state.gpr.rax.aword = 0;
      state.gpr.rdx.aword = 0;
      asm volatile("rdtsc"
                   : "=a"(state.gpr.rax.dword), "=d"(state.gpr.rdx.dword));
      break;

    case SyncHyperCall::kX86ReadTSCP:
      state.gpr.rax.aword = 0;
      state.gpr.rcx.aword = 0;
      state.gpr.rdx.aword = 0;
      asm volatile("rdtscp"
                   : "=a"(state.gpr.rax.dword), "=c"(state.gpr.rcx.dword),
                     "=d"(state.gpr.rdx.dword));
      break;

    default: __builtin_unreachable();
  }

  return mem;
}

Memory *__mcsema_reg_tracer(State &state, addr_t, Memory *memory) {
  if (sizeof(void *) == 8) {
    fprintf(stderr,
            "RIP=%" PRIxADDR ",RAX=%" PRIxADDR ",RBX=%" PRIxADDR
            ",RCX=%" PRIxADDR ",RDX=%" PRIxADDR ",RSI=%" PRIxADDR
            ",RDI=%" PRIxADDR ",RBP=%" PRIxADDR ",RSP=%" PRIxADDR
            ",R8=%" PRIxADDR ",R9=%" PRIxADDR ",R10=%" PRIxADDR
            ",R11=%" PRIxADDR ",R12=%" PRIxADDR ",R13=%" PRIxADDR
            ",R14=%" PRIxADDR ",R15=%" PRIxADDR "\n",

            state.RIP, state.RAX, state.RBX, state.RCX, state.RDX, state.RSI,
            state.RDI, state.RBP, state.RSP, state.R8, state.R9, state.R10,
            state.R11, state.R12, state.R13, state.R14, state.R15);
  } else {
    fprintf(stderr,
            "EIP=%" PRIx32 ",EAX=%" PRIx32 ",EBX=%" PRIx32 ",ECX=%" PRIx32
            ",EDX=%" PRIx32 ",ESI=%" PRIx32 ",EDI=%" PRIx32 ",ESP=%" PRIx32
            ",EBP=%" PRIx32 "\n",
            state.EIP, state.EAX, state.EBX, state.ECX, state.EDX, state.ESI,
            state.EDI, state.EBP, state.ESP);
  }
  return memory;
}

// Read/write to I/O ports.
uint8_t __remill_read_io_port_8(Memory *, addr_t) {
  abort();
}

uint16_t __remill_read_io_port_16(Memory *, addr_t) {
  abort();
}

uint32_t __remill_read_io_port_32(Memory *, addr_t) {
  abort();
}

Memory *__remill_write_io_port_8(Memory *, addr_t, uint8_t) {
  abort();
}

Memory *__remill_write_io_port_16(Memory *, addr_t, uint16_t) {
  abort();
}

Memory *__remill_write_io_port_32(Memory *, addr_t, uint32_t) {
  abort();
}

// Memory read intrinsics.
uint8_t __remill_read_memory_8(Memory *, addr_t addr) {
  return *reinterpret_cast<uint8_t *>(addr);
}

uint16_t __remill_read_memory_16(Memory *, addr_t addr) {
  return *reinterpret_cast<uint16_t *>(addr);
}

uint32_t __remill_read_memory_32(Memory *, addr_t addr) {
  return *reinterpret_cast<uint32_t *>(addr);
}

uint64_t __remill_read_memory_64(Memory *, addr_t addr) {
  return *reinterpret_cast<uint64_t *>(addr);
}

// Memory write intrinsics.
Memory *__remill_write_memory_8(Memory *memory, addr_t addr, uint8_t val) {
  *reinterpret_cast<uint8_t *>(addr) = val;
  return memory;
}

Memory *__remill_write_memory_16(Memory *memory, addr_t addr, uint16_t val) {
  *reinterpret_cast<uint16_t *>(addr) = val;
  return memory;
}

Memory *__remill_write_memory_32(Memory *memory, addr_t addr, uint32_t val) {
  *reinterpret_cast<uint32_t *>(addr) = val;
  return memory;
}

Memory *__remill_write_memory_64(Memory *memory, addr_t addr, uint64_t val) {
  *reinterpret_cast<uint64_t *>(addr) = val;
  return memory;
}

float32_t __remill_read_memory_f32(Memory *, addr_t addr, float32_t val) {
  return *reinterpret_cast<float32_t *>(addr);
}

float64_t __remill_read_memory_f64(Memory *, addr_t addr, float64_t val) {
  return *reinterpret_cast<float64_t *>(addr);
}

float64_t __remill_read_memory_f80(Memory *, addr_t addr) {
  return static_cast<float64_t>(*reinterpret_cast<long double *>(addr));
}

Memory *__remill_write_memory_f32(Memory *memory, addr_t addr, float32_t val) {
  *reinterpret_cast<float32_t *>(addr) = val;
  return memory;
}

Memory *__remill_write_memory_f64(Memory *memory, addr_t addr, float64_t val) {
  *reinterpret_cast<float64_t *>(addr) = val;
  return memory;
}

Memory *__remill_write_memory_f80(Memory *memory, addr_t addr, float64_t val) {
  *reinterpret_cast<long double *>(addr) = static_cast<long double>(val);
  return memory;
}

// Memory barriers types, see: http://g.oswego.edu/dl/jmm/cookbook.html
Memory *__remill_barrier_load_load(Memory *memory) {
  return memory;
}

Memory *__remill_barrier_load_store(Memory *memory) {
  return memory;
}

Memory *__remill_barrier_store_load(Memory *memory) {
  return memory;
}

Memory *__remill_barrier_store_store(Memory *memory) {
  return memory;
}

// Atomic operations. The address/size are hints, but the granularity of the
// access can be bigger. These have implicit StoreLoad semantics.
Memory *__remill_atomic_begin(Memory *memory) {
  return memory;
}

Memory *__remill_atomic_end(Memory *memory) {
  return memory;
}

Memory *__remill_compare_exchange_memory_8(Memory *memory, addr_t addr,
                                           uint8_t &expected, uint8_t desired) {
  expected = __sync_val_compare_and_swap(reinterpret_cast<uint8_t *>(addr),
                                         expected, desired);
  return memory;
}

Memory *__remill_compare_exchange_memory_16(Memory *memory, addr_t addr,
                                            uint16_t &expected,
                                            uint16_t desired) {
  expected = __sync_val_compare_and_swap(reinterpret_cast<uint16_t *>(addr),
                                         expected, desired);
  return memory;
}

Memory *__remill_compare_exchange_memory_32(Memory *memory, addr_t addr,
                                            uint32_t &expected,
                                            uint32_t desired) {
  expected = __sync_val_compare_and_swap(reinterpret_cast<uint32_t *>(addr),
                                         expected, desired);
  return memory;
}

Memory *__remill_compare_exchange_memory_64(Memory *memory, addr_t addr,
                                            uint64_t &expected,
                                            uint64_t desired) {
  expected = __sync_val_compare_and_swap(reinterpret_cast<uint64_t *>(addr),
                                         expected, desired);
  return memory;
}

#ifdef _GXX_EXPERIMENTAL_CXX0X__
Memory *__remill_compare_exchange_memory_128(Memory *memory, addr_t addr,
                                             uint128_t &expected,
                                             uint128_t &desired) {
  expected = __sync_val_compare_and_swap(reinterpret_cast<uint128_t *>(addr),
                                         expected, desired);
  return memory;
}
#endif

Memory *__remill_fetch_and_add_8(Memory *memory, addr_t addr, uint8_t &value) {
  value = __sync_fetch_and_add(reinterpret_cast<uint8_t *>(addr), value);
  return memory;
}

Memory *__remill_fetch_and_add_16(Memory *memory, addr_t addr,
                                  uint16_t &value) {
  value = __sync_fetch_and_add(reinterpret_cast<uint16_t *>(addr), value);
  return memory;
}

Memory *__remill_fetch_and_add_32(Memory *memory, addr_t addr,
                                  uint32_t &value) {
  value = __sync_fetch_and_add(reinterpret_cast<uint32_t *>(addr), value);
  return memory;
}

Memory *__remill_fetch_and_add_64(Memory *memory, addr_t addr,
                                  uint64_t &value) {
  value = __sync_fetch_and_add(reinterpret_cast<uint64_t *>(addr), value);
  return memory;
}

Memory *__remill_fetch_and_sub_8(Memory *memory, addr_t addr, uint8_t &value) {
  value = __sync_fetch_and_sub(reinterpret_cast<uint8_t *>(addr), value);
  return memory;
}

Memory *__remill_fetch_and_sub_16(Memory *memory, addr_t addr,
                                  uint16_t &value) {
  value = __sync_fetch_and_sub(reinterpret_cast<uint16_t *>(addr), value);
  return memory;
}

Memory *__remill_fetch_and_sub_32(Memory *memory, addr_t addr,
                                  uint32_t &value) {
  value = __sync_fetch_and_sub(reinterpret_cast<uint32_t *>(addr), value);
  return memory;
}

Memory *__remill_fetch_and_sub_64(Memory *memory, addr_t addr,
                                  uint64_t &value) {
  value = __sync_fetch_and_sub(reinterpret_cast<uint64_t *>(addr), value);
  return memory;
}

Memory *__remill_fetch_and_or_8(Memory *memory, addr_t addr, uint8_t &value) {
  value = __sync_fetch_and_or(reinterpret_cast<uint8_t *>(addr), value);
  return memory;
}

Memory *__remill_fetch_and_or_16(Memory *memory, addr_t addr, uint16_t &value) {
  value = __sync_fetch_and_or(reinterpret_cast<uint16_t *>(addr), value);
  return memory;
}

Memory *__remill_fetch_and_or_32(Memory *memory, addr_t addr, uint32_t &value) {
  value = __sync_fetch_and_or(reinterpret_cast<uint32_t *>(addr), value);
  return memory;
}

Memory *__remill_fetch_and_or_64(Memory *memory, addr_t addr, uint64_t &value) {
  value = __sync_fetch_and_or(reinterpret_cast<uint64_t *>(addr), value);
  return memory;
}

Memory *__remill_fetch_and_and_8(Memory *memory, addr_t addr, uint8_t &value) {
  value = __sync_fetch_and_and(reinterpret_cast<uint8_t *>(addr), value);
  return memory;
}

Memory *__remill_fetch_and_and_16(Memory *memory, addr_t addr,
                                  uint16_t &value) {
  value = __sync_fetch_and_and(reinterpret_cast<uint16_t *>(addr), value);
  return memory;
}

Memory *__remill_fetch_and_and_32(Memory *memory, addr_t addr,
                                  uint32_t &value) {
  value = __sync_fetch_and_and(reinterpret_cast<uint32_t *>(addr), value);
  return memory;
}

Memory *__remill_fetch_and_and_64(Memory *memory, addr_t addr,
                                  uint64_t &value) {
  value = __sync_fetch_and_and(reinterpret_cast<uint64_t *>(addr), value);
  return memory;
}

Memory *__remill_fetch_and_xor_8(Memory *memory, addr_t addr, uint8_t &value) {
  value = __sync_fetch_and_xor(reinterpret_cast<uint8_t *>(addr), value);
  return memory;
}

Memory *__remill_fetch_and_xor_16(Memory *memory, addr_t addr,
                                  uint16_t &value) {
  value = __sync_fetch_and_xor(reinterpret_cast<uint16_t *>(addr), value);
  return memory;
}

Memory *__remill_fetch_and_xor_32(Memory *memory, addr_t addr,
                                  uint32_t &value) {
  value = __sync_fetch_and_xor(reinterpret_cast<uint32_t *>(addr), value);
  return memory;
}

Memory *__remill_fetch_and_xor_64(Memory *memory, addr_t addr,
                                  uint64_t &value) {
  value = __sync_fetch_and_xor(reinterpret_cast<uint64_t *>(addr), value);
  return memory;
}

int __remill_fpu_exception_test_and_clear(int read_mask, int clear_mask) {
  auto except = std::fetestexcept(read_mask);
  std::feclearexcept(clear_mask);
  return except;
}


}  // extern C
