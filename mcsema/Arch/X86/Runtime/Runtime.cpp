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
Memory *__remill_write_memory_8(
    Memory * memory, addr_t addr, uint8_t val) {
  *reinterpret_cast<uint8_t *>(addr) = val;
  return memory;
}

Memory *__remill_write_memory_16(
    Memory * memory, addr_t addr, uint16_t val) {
  *reinterpret_cast<uint16_t *>(addr) = val;
  return memory;
}

Memory *__remill_write_memory_32(
    Memory * memory, addr_t addr, uint32_t val) {
  *reinterpret_cast<uint32_t *>(addr) = val;
  return memory;
}

Memory *__remill_write_memory_64(
    Memory * memory, addr_t addr, uint64_t val) {
  *reinterpret_cast<uint64_t *>(addr) = val;
  return memory;
}

float32_t __remill_read_memory_f32(
    Memory *, addr_t addr, float32_t val) {
  return *reinterpret_cast<float32_t *>(addr);
}

float64_t __remill_read_memory_f64(
    Memory *, addr_t addr, float64_t val) {
  return *reinterpret_cast<float64_t *>(addr);

}

float64_t __remill_read_memory_f80(Memory *, addr_t addr) {
  return static_cast<float64_t>(*reinterpret_cast<long double *>(addr));
}

Memory *__remill_write_memory_f32(
    Memory * memory, addr_t addr, float32_t val) {
  *reinterpret_cast<float32_t *>(addr) = val;
  return memory;
}

Memory *__remill_write_memory_f64(
    Memory * memory, addr_t addr, float64_t val) {
  *reinterpret_cast<float64_t *>(addr) = val;
  return memory;
}

Memory *__remill_write_memory_f80(
    Memory * memory, addr_t addr, float64_t val) {
  *reinterpret_cast<long double *>(addr) = static_cast<long double>(val);
  return memory;
}

// Memory barriers types, see: http://g.oswego.edu/dl/jmm/cookbook.html
Memory *__remill_barrier_load_load(Memory * memory) {
  return memory;
}

Memory *__remill_barrier_load_store(Memory * memory) {
  return memory;
}

Memory *__remill_barrier_store_load(Memory * memory) {
  return memory;
}

Memory *__remill_barrier_store_store(Memory * memory) {
  return memory;
}

// Atomic operations. The address/size are hints, but the granularity of the
// access can be bigger. These have implicit StoreLoad semantics.
Memory *__remill_atomic_begin(Memory * memory) {
  return memory;
}

Memory *__remill_atomic_end(Memory * memory) {
  return memory;
}

}  // extern C
