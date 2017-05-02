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

#define HAS_FEATURE_AVX 1
#define HAS_FEATURE_AVX512 0
#define ADDRESS_SIZE_BITS 64

#include <remill/Arch/X86/Runtime/State.h>
#include <mcsema/Arch/X86/Runtime/Registers.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat"

static const size_t kStackSize = 1UL << 20UL;

int main(void) {

  FILE *out = fopen("runtime_64.S", "w");

  fprintf(out, "/* Auto-generated file! Don't modify! */\n\n");
  fprintf(out, "  .intel_syntax noprefix\n");
  fprintf(out, "\n");


  // Thread-local state structure, named by `__mcsema_reg_state`.
  fprintf(out, "  .type __mcsema_reg_state,@object\n");
  fprintf(out, "  .section .tbss,\"awT\",@nobits\n");
  fprintf(out, "  .align 16\n");
  fprintf(out, "__mcsema_reg_state:\n");
  fprintf(out, "  .zero %lu\n", sizeof(State));
  fprintf(out, "  .size __mcsema_reg_state, %lu\n", sizeof(State));
  fprintf(out, "\n");

  // Thread-local stack structure, named by `__mcsema_stack`.
  fprintf(out, "  .type __mcsema_stack,@object\n");
  fprintf(out, "  .section .tbss,\"awT\",@nobits\n");
  fprintf(out, "  .align 16\n");
  fprintf(out, "__mcsema_stack:\n");
  fprintf(out, "  .zero %lu\n", kStackSize);  // 1 MiB.
  fprintf(out, "  .size __mcsema_stack, %lu\n", kStackSize);
  fprintf(out, "\n");

  fprintf(out, "  .text\n");
  fprintf(out, "\n");

  // Forward declarations.
  fprintf(out, "  .globl __mcsema_detach_ret\n");
  fprintf(out, "\n");

  // Implements `__mcsema_attach_call`. This goes from native state into lifted
  // code.
  fprintf(out, "  .globl __mcsema_attach_call\n");
  fprintf(out, "  .type __mcsema_attach_call,@function\n");
  fprintf(out, "__mcsema_attach_call:\n");
  fprintf(out, "  .cfi_startproc\n");

  // On the stack:
  //     0  EA of the lifted function (from the CFG).
  //     8  Address of the lifted function (from the bitcode).
  //    16  Return address into native caller.

  // Set up arg2 with the address of the State structure. Also set up the `FS`
  // segment register so that TLS works :-)
  fprintf(out, "  mov fs:[__mcsema_reg_state@TPOFF + %lu], rsi\n", __builtin_offsetof(State, RSI));
  fprintf(out, "  mov rsi, QWORD PTR fs:[0]\n");
  fprintf(out, "  mov [rsi - __mcsema_reg_state@TPOFF + %lu], rsi\n", __builtin_offsetof(State, FS_BASE));
  fprintf(out, "  lea rsi, QWORD PTR [rsi - __mcsema_reg_state@TPOFF]\n");

  // Set up arg3 with the address of the lifted function, as it appeared in
  // the original binary, also stash it into the `State` structure.
  fprintf(out, "  mov [rsi + %lu], rdx\n", __builtin_offsetof(State, RDX));
  fprintf(out, "  pop rdx\n");  // Holds the lifted function address.
  fprintf(out, "  mov [rsi + %lu], rdx\n", __builtin_offsetof(State, RIP));

  // General purpose registers.
  fprintf(out, "  mov [rsi + %lu], rax\n", __builtin_offsetof(State, RAX));
  fprintf(out, "  mov [rsi + %lu], rbx\n", __builtin_offsetof(State, RBX));
  fprintf(out, "  mov [rsi + %lu], rcx\n", __builtin_offsetof(State, RCX));
  fprintf(out, "  mov [rsi + %lu], rdi\n", __builtin_offsetof(State, RDI));
  fprintf(out, "  mov [rsi + %lu], rbp\n", __builtin_offsetof(State, RBP));
  fprintf(out, "  mov [rsi + %lu], r8\n", __builtin_offsetof(State, R8));
  fprintf(out, "  mov [rsi + %lu], r9\n", __builtin_offsetof(State, R9));
  fprintf(out, "  mov [rsi + %lu], r10\n", __builtin_offsetof(State, R10));
  fprintf(out, "  mov [rsi + %lu], r11\n", __builtin_offsetof(State, R11));
  fprintf(out, "  mov [rsi + %lu], r12\n", __builtin_offsetof(State, R12));
  fprintf(out, "  mov [rsi + %lu], r13\n", __builtin_offsetof(State, R13));
  fprintf(out, "  mov [rsi + %lu], r14\n", __builtin_offsetof(State, R14));
  fprintf(out, "  mov [rsi + %lu], r15\n", __builtin_offsetof(State, R15));

  // XMM registers.
  fprintf(out, "  movntdq [rsi + %lu], xmm0\n", __builtin_offsetof(State, XMM0));
  fprintf(out, "  movntdq [rsi + %lu], xmm1\n", __builtin_offsetof(State, XMM1));
  fprintf(out, "  movntdq [rsi + %lu], xmm2\n", __builtin_offsetof(State, XMM2));
  fprintf(out, "  movntdq [rsi + %lu], xmm3\n", __builtin_offsetof(State, XMM3));
  fprintf(out, "  movntdq [rsi + %lu], xmm4\n", __builtin_offsetof(State, XMM4));
  fprintf(out, "  movntdq [rsi + %lu], xmm5\n", __builtin_offsetof(State, XMM5));
  fprintf(out, "  movntdq [rsi + %lu], xmm6\n", __builtin_offsetof(State, XMM6));
  fprintf(out, "  movntdq [rsi + %lu], xmm7\n", __builtin_offsetof(State, XMM7));
  fprintf(out, "  movntdq [rsi + %lu], xmm8\n", __builtin_offsetof(State, XMM8));
  fprintf(out, "  movntdq [rsi + %lu], xmm9\n", __builtin_offsetof(State, XMM9));
  fprintf(out, "  movntdq [rsi + %lu], xmm10\n", __builtin_offsetof(State, XMM10));
  fprintf(out, "  movntdq [rsi + %lu], xmm11\n", __builtin_offsetof(State, XMM11));
  fprintf(out, "  movntdq [rsi + %lu], xmm12\n", __builtin_offsetof(State, XMM12));
  fprintf(out, "  movntdq [rsi + %lu], xmm13\n", __builtin_offsetof(State, XMM13));
  fprintf(out, "  movntdq [rsi + %lu], xmm14\n", __builtin_offsetof(State, XMM14));
  fprintf(out, "  movntdq [rsi + %lu], xmm15\n", __builtin_offsetof(State, XMM15));

  // Get the RFlags.
  fprintf(out, "  pushfq\n");
  fprintf(out, "  pop rdi\n");
  fprintf(out, "  mov [rsi + %lu], rdi\n", __builtin_offsetof(State, rflag));

  // Clear our the `ArithFlags` struct, which is 16 bytes.
  fprintf(out, "  mov QWORD PTR [rsi + %lu], 0\n", __builtin_offsetof(State, aflag));
  fprintf(out, "  mov QWORD PTR [rsi + %lu], 0\n", __builtin_offsetof(State, aflag) + 8);

  // Marshal the RFlags into the ArithFlags struct.
  fprintf(out, "  bt rdi, 0\n");
  fprintf(out, "  adc BYTE PTR [rsi + %lu], 0\n", __builtin_offsetof(State, CF));

  fprintf(out, "  bt QWORD PTR [rsp], 2\n");
  fprintf(out, "  adc BYTE PTR [rsi + %lu], 0\n", __builtin_offsetof(State, PF));

  fprintf(out, "  bt QWORD PTR [rsp], 4\n");
  fprintf(out, "  adc BYTE PTR [rsi + %lu], 0\n", __builtin_offsetof(State, AF));

  fprintf(out, "  bt QWORD PTR [rsp], 6\n");
  fprintf(out, "  adc BYTE PTR [rsi + %lu], 0\n", __builtin_offsetof(State, ZF));

  fprintf(out, "  bt QWORD PTR [rsp], 7\n");
  fprintf(out, "  adc BYTE PTR [rsi + %lu], 0\n", __builtin_offsetof(State, SF));

  fprintf(out, "  bt QWORD PTR [rsp], 10\n");
  fprintf(out, "  adc BYTE PTR [rsi + %lu], 0\n", __builtin_offsetof(State, DF));

  fprintf(out, "  bt QWORD PTR [rsp], 11\n");
  fprintf(out, "  adc BYTE PTR [rsi + %lu], 0\n", __builtin_offsetof(State, OF));

  // If `RSP` is null then we need to initialize it to our new stack.
  fprintf(out, "  mov rdi, [rsi + %lu]\n", __builtin_offsetof(State, RSP));
  fprintf(out, "  cmp rdi, 0\n");
  fprintf(out, "  jnz .Lhave_stack\n");
  fprintf(out, "  mov rdi, fs:[0]\n");
  fprintf(out, "  lea rdi, [rdi - __mcsema_stack@TPOFF + %lu]\n", kStackSize);
  fprintf(out, ".Lhave_stack:\n");

  // Set up a return address so that when the lifted function returns, it will
  // go to `__mcsema_detach_ret`, which will return to native code.
  fprintf(out, "  lea rax, [rip + __mcsema_detach_ret]\n");
  fprintf(out, "  mov [rdi - 8], rax\n");

  // Put the address of the lifted function onto the lifted stack, so that we
  // can `RET` into the lifted function.
  fprintf(out, "  pop QWORD PTR [rdi - 16]\n");

  // Swap onto the lifted stack. The native `RSP` is now where it should be.
  fprintf(out, "  mov [rsi + %lu], rsp\n", __builtin_offsetof(State, RSP));
  fprintf(out, "  lea rsp, [rdi - 16]\n");

  // Set up arg1 as the memory pointer, which is (for now?) a nullptr.
  fprintf(out, "  xor rdi, rdi\n");

  // The address of the lifted function is still on the stack, and `RDX` holds
  // the native PC of the original function.

  // RDX currently holds the address of the lifted function (where we want to
  // go). Inside of the lifted function, RDX (arg3 of AMD64 ABI) needs to hold
  // the same thing as State::RIP. So, push on the address of the lifted
  // function, get RDX right, then `RET` to the lifted function.
  fprintf(out, "  ret\n");

  fprintf(out, ".Lfunc_end1:\n");
  fprintf(out, "  .size __mcsema_attach_call,.Lfunc_end1-__mcsema_attach_call\n");
  fprintf(out, "  .cfi_endproc\n");
  fprintf(out, "\n");

  // Implements `__mcsema_detach_ret`. This goes from lifted code into native code.
  // The native code pointer is located at the native `[State::RSP - 8]`
  // address.
  fprintf(out, "  .globl __mcsema_detach_ret\n");
  fprintf(out, "  .type __mcsema_detach_ret,@function\n");
  fprintf(out, "__mcsema_detach_ret:\n");
  fprintf(out, "  .cfi_startproc\n");

  fprintf(out, "  mov rsi, QWORD PTR fs:[0]\n");
  fprintf(out, "  lea rsi, QWORD PTR [rsi - __mcsema_reg_state@TPOFF]\n");

  // The lifted code emulated a ret, which incremented `rsp` by 8.
  // We "undo" that, then swap back to the native stack. When we swap, we
  // save into `State::RSP` where we are in the lifted stack, so that the
  // next attach can continue on where we left off.
  fprintf(out, "  sub QWORD PTR [rsi + %lu], 8\n", __builtin_offsetof(State, RSP));
  fprintf(out, "  xchg [rsi + %lu], rsp\n", __builtin_offsetof(State, RSP));

  // General purpose registers.
  fprintf(out, "  mov rax, [rsi + %lu]\n", __builtin_offsetof(State, RAX));
  fprintf(out, "  mov rbx, [rsi + %lu]\n", __builtin_offsetof(State, RBX));
  fprintf(out, "  mov rcx, [rsi + %lu]\n", __builtin_offsetof(State, RCX));
  fprintf(out, "  mov rdx, [rsi + %lu]\n", __builtin_offsetof(State, RDX));
  fprintf(out, "  mov rdi, [rsi + %lu]\n", __builtin_offsetof(State, RDI));
  fprintf(out, "  mov rbp, [rsi + %lu]\n", __builtin_offsetof(State, RBP));
  fprintf(out, "  mov r8, [rsi + %lu]\n", __builtin_offsetof(State, R8));
  fprintf(out, "  mov r9, [rsi + %lu]\n", __builtin_offsetof(State, R9));
  fprintf(out, "  mov r10, [rsi + %lu]\n", __builtin_offsetof(State, R10));
  fprintf(out, "  mov r11, [rsi + %lu]\n", __builtin_offsetof(State, R11));
  fprintf(out, "  mov r12, [rsi + %lu]\n", __builtin_offsetof(State, R12));
  fprintf(out, "  mov r13, [rsi + %lu]\n", __builtin_offsetof(State, R13));
  fprintf(out, "  mov r14, [rsi + %lu]\n", __builtin_offsetof(State, R14));
  fprintf(out, "  mov r15, [rsi + %lu]\n", __builtin_offsetof(State, R15));

  // XMM registers.
  fprintf(out, "  movntdqa xmm0, [rsi + %lu]\n", __builtin_offsetof(State, XMM0));
  fprintf(out, "  movntdqa xmm1, [rsi + %lu]\n", __builtin_offsetof(State, XMM1));
  fprintf(out, "  movntdqa xmm2, [rsi + %lu]\n", __builtin_offsetof(State, XMM2));
  fprintf(out, "  movntdqa xmm3, [rsi + %lu]\n", __builtin_offsetof(State, XMM3));
  fprintf(out, "  movntdqa xmm4, [rsi + %lu]\n", __builtin_offsetof(State, XMM4));
  fprintf(out, "  movntdqa xmm5, [rsi + %lu]\n", __builtin_offsetof(State, XMM5));
  fprintf(out, "  movntdqa xmm6, [rsi + %lu]\n", __builtin_offsetof(State, XMM6));
  fprintf(out, "  movntdqa xmm7, [rsi + %lu]\n", __builtin_offsetof(State, XMM7));
  fprintf(out, "  movntdqa xmm8, [rsi + %lu]\n", __builtin_offsetof(State, XMM8));
  fprintf(out, "  movntdqa xmm9, [rsi + %lu]\n", __builtin_offsetof(State, XMM9));
  fprintf(out, "  movntdqa xmm10, [rsi + %lu]\n", __builtin_offsetof(State, XMM10));
  fprintf(out, "  movntdqa xmm11, [rsi + %lu]\n", __builtin_offsetof(State, XMM11));
  fprintf(out, "  movntdqa xmm12, [rsi + %lu]\n", __builtin_offsetof(State, XMM12));
  fprintf(out, "  movntdqa xmm13, [rsi + %lu]\n", __builtin_offsetof(State, XMM13));
  fprintf(out, "  movntdqa xmm14, [rsi + %lu]\n", __builtin_offsetof(State, XMM14));
  fprintf(out, "  movntdqa xmm15, [rsi + %lu]\n", __builtin_offsetof(State, XMM15));

  fprintf(out, "  mov rsi, [rsi + %lu]\n", __builtin_offsetof(State, RSI));
  fprintf(out, "  ret\n");

  fprintf(out, ".Lfunc_end3:\n");
  fprintf(out, "  .size __mcsema_detach_ret,.Lfunc_end3-__mcsema_detach_ret\n");
  fprintf(out, "  .cfi_endproc\n");
  fprintf(out, "\n");

  // Implements `__remill_function_call`. This is a fully generic form of function
  // call detaching that is unaware of the ABI / calling convention of the target.
  fprintf(out, "  .globl __remill_jump\n");
  fprintf(out, "  .type __remill_jump,@function\n");

  fprintf(out, "__remill_jump:\n");
  fprintf(out, "  .globl __remill_function_call\n");
  fprintf(out, "  .type __remill_function_call,@function\n");
  fprintf(out, "__remill_function_call:\n");
  fprintf(out, "  .cfi_startproc\n");

  // Stash the memory pointer. This is probably actually nothing. But for
  // generality, we will store and return it, as is expected by the prototype
  // of `__remill_function_call` (see remill/Arch/Runtime/Intrinsics.h).
  fprintf(out, "  push rdi\n");

  // Stash the callee-saved registers (amd64 ABI). These registers need to
  // be restored later so that things are as they should be when we return
  // back onto the lifted stack.
  fprintf(out, "  push rbx\n");
  fprintf(out, "  push rbp\n");
  fprintf(out, "  push r12\n");
  fprintf(out, "  push r13\n");
  fprintf(out, "  push r14\n");
  fprintf(out, "  push r15\n");

  // Stash the return address stored on the native stack, the replace it
  // with the re-attach function.
  fprintf(out, "  mov r15, [rsi + %lu]\n", __builtin_offsetof(State, RSP));
  fprintf(out, "  push QWORD PTR [r15]\n");
  fprintf(out, "  lea r14, [rip + __mcsema_attach_ret]\n");
  fprintf(out, "  mov QWORD PTR [r15], r14\n");

  // Emulate a push of the target address onto the native stack. We will
  // `ret` to the target later on.
  //
  // Note: The target address is passed as arg3 (pc) to `__remill_function_call`
  //       which is `RDX` in the AMD64 ABI.
  fprintf(out, "  sub r15, 8\n");
  fprintf(out, "  mov QWORD PTR [r15], rdx\n");

  // Swap off-stack, stash the lifted stack pointer.
  fprintf(out, "  mov [rsi + %lu], rsp\n", __builtin_offsetof(State, RSP));
  fprintf(out, "  mov rsp, r15\n");

  // (Most) General purpose registers.
  fprintf(out, "  mov rax, [rsi + %lu]\n", __builtin_offsetof(State, RAX));
  fprintf(out, "  mov rbx, [rsi + %lu]\n", __builtin_offsetof(State, RBX));
  fprintf(out, "  mov rcx, [rsi + %lu]\n", __builtin_offsetof(State, RCX));
  fprintf(out, "  mov rdx, [rsi + %lu]\n", __builtin_offsetof(State, RDX));
  fprintf(out, "  mov rdi, [rsi + %lu]\n", __builtin_offsetof(State, RDI));
  fprintf(out, "  mov rbp, [rsi + %lu]\n", __builtin_offsetof(State, RBP));
  fprintf(out, "  mov r8, [rsi + %lu]\n", __builtin_offsetof(State, R8));
  fprintf(out, "  mov r9, [rsi + %lu]\n", __builtin_offsetof(State, R9));
  fprintf(out, "  mov r10, [rsi + %lu]\n", __builtin_offsetof(State, R10));
  fprintf(out, "  mov r11, [rsi + %lu]\n", __builtin_offsetof(State, R11));
  fprintf(out, "  mov r12, [rsi + %lu]\n", __builtin_offsetof(State, R12));
  fprintf(out, "  mov r13, [rsi + %lu]\n", __builtin_offsetof(State, R13));
  fprintf(out, "  mov r14, [rsi + %lu]\n", __builtin_offsetof(State, R14));
  fprintf(out, "  mov r15, [rsi + %lu]\n", __builtin_offsetof(State, R15));

  // XMM registers.
  fprintf(out, "  movntdqa xmm0, [rsi + %lu]\n", __builtin_offsetof(State, XMM0));
  fprintf(out, "  movntdqa xmm1, [rsi + %lu]\n", __builtin_offsetof(State, XMM1));
  fprintf(out, "  movntdqa xmm2, [rsi + %lu]\n", __builtin_offsetof(State, XMM2));
  fprintf(out, "  movntdqa xmm3, [rsi + %lu]\n", __builtin_offsetof(State, XMM3));
  fprintf(out, "  movntdqa xmm4, [rsi + %lu]\n", __builtin_offsetof(State, XMM4));
  fprintf(out, "  movntdqa xmm5, [rsi + %lu]\n", __builtin_offsetof(State, XMM5));
  fprintf(out, "  movntdqa xmm6, [rsi + %lu]\n", __builtin_offsetof(State, XMM6));
  fprintf(out, "  movntdqa xmm7, [rsi + %lu]\n", __builtin_offsetof(State, XMM7));
  fprintf(out, "  movntdqa xmm8, [rsi + %lu]\n", __builtin_offsetof(State, XMM8));
  fprintf(out, "  movntdqa xmm9, [rsi + %lu]\n", __builtin_offsetof(State, XMM9));
  fprintf(out, "  movntdqa xmm10, [rsi + %lu]\n", __builtin_offsetof(State, XMM10));
  fprintf(out, "  movntdqa xmm11, [rsi + %lu]\n", __builtin_offsetof(State, XMM11));
  fprintf(out, "  movntdqa xmm12, [rsi + %lu]\n", __builtin_offsetof(State, XMM12));
  fprintf(out, "  movntdqa xmm13, [rsi + %lu]\n", __builtin_offsetof(State, XMM13));
  fprintf(out, "  movntdqa xmm14, [rsi + %lu]\n", __builtin_offsetof(State, XMM14));
  fprintf(out, "  movntdqa xmm15, [rsi + %lu]\n", __builtin_offsetof(State, XMM15));

  // Swap out RSI.
  fprintf(out, "  mov rsi, [rsi + %lu]\n", __builtin_offsetof(State, RSI));

  // Code above put the native target address (stored in RDX on entry to
  // `__remill_function_call`) on the stack, just below the return address,
  // which is now `__mcsema_attach_ret`), so we can `ret` and go to our
  // intended target.
  fprintf(out, "  ret\n");

  fprintf(out, ".Lfunc_end5:\n");
  fprintf(out, "  .size __remill_function_call,.Lfunc_end5-__remill_function_call\n");
  fprintf(out, "  .cfi_endproc\n");
  fprintf(out, "\n");

  // Implements `__mcsema_attach_ret`. This goes from native state into lifted
  // code.
  fprintf(out, "  .globl __mcsema_attach_ret\n");
  fprintf(out, "  .type __mcsema_attach_ret,@function\n");
  fprintf(out, "__mcsema_attach_ret:\n");
  fprintf(out, "  .cfi_startproc\n");

  // Copy RSI, then store the address of the reg state struct into RSI for
  // easier indexing later on. Also set up the `FS` segment register so that
  // TLS works :-)
  fprintf(out, "  mov fs:[__mcsema_reg_state@TPOFF + %lu], rsi\n", __builtin_offsetof(State, RSI));
  fprintf(out, "  mov rsi, QWORD PTR fs:[0]\n");
  fprintf(out, "  mov [rsi - __mcsema_reg_state@TPOFF + %lu], rsi\n", __builtin_offsetof(State, FS_BASE));
  fprintf(out, "  lea rsi, QWORD PTR [rsi - __mcsema_reg_state@TPOFF]\n");

  // General purpose registers.
  fprintf(out, "  mov [rsi + %lu], rax\n", __builtin_offsetof(State, RAX));
  fprintf(out, "  mov [rsi + %lu], rbx\n", __builtin_offsetof(State, RBX));
  fprintf(out, "  mov [rsi + %lu], rcx\n", __builtin_offsetof(State, RCX));
  fprintf(out, "  mov [rsi + %lu], rdx\n", __builtin_offsetof(State, RDX));
  fprintf(out, "  mov [rsi + %lu], rdi\n", __builtin_offsetof(State, RDI));
  fprintf(out, "  mov [rsi + %lu], rbp\n", __builtin_offsetof(State, RBP));
  fprintf(out, "  mov [rsi + %lu], r8\n", __builtin_offsetof(State, R8));
  fprintf(out, "  mov [rsi + %lu], r9\n", __builtin_offsetof(State, R9));
  fprintf(out, "  mov [rsi + %lu], r10\n", __builtin_offsetof(State, R10));
  fprintf(out, "  mov [rsi + %lu], r11\n", __builtin_offsetof(State, R11));
  fprintf(out, "  mov [rsi + %lu], r12\n", __builtin_offsetof(State, R12));
  fprintf(out, "  mov [rsi + %lu], r13\n", __builtin_offsetof(State, R13));
  fprintf(out, "  mov [rsi + %lu], r14\n", __builtin_offsetof(State, R14));
  fprintf(out, "  mov [rsi + %lu], r15\n", __builtin_offsetof(State, R15));

  // Swap into the mcsema stack.
  fprintf(out, "  xchg rsp, [rsi + %lu]\n", __builtin_offsetof(State, RSP));

  // XMM registers.
  fprintf(out, "  movntdq [rsi + %lu], xmm0\n", __builtin_offsetof(State, XMM0));
  fprintf(out, "  movntdq [rsi + %lu], xmm1\n", __builtin_offsetof(State, XMM1));
  fprintf(out, "  movntdq [rsi + %lu], xmm2\n", __builtin_offsetof(State, XMM2));
  fprintf(out, "  movntdq [rsi + %lu], xmm3\n", __builtin_offsetof(State, XMM3));
  fprintf(out, "  movntdq [rsi + %lu], xmm4\n", __builtin_offsetof(State, XMM4));
  fprintf(out, "  movntdq [rsi + %lu], xmm5\n", __builtin_offsetof(State, XMM5));
  fprintf(out, "  movntdq [rsi + %lu], xmm6\n", __builtin_offsetof(State, XMM6));
  fprintf(out, "  movntdq [rsi + %lu], xmm7\n", __builtin_offsetof(State, XMM7));
  fprintf(out, "  movntdq [rsi + %lu], xmm8\n", __builtin_offsetof(State, XMM8));
  fprintf(out, "  movntdq [rsi + %lu], xmm9\n", __builtin_offsetof(State, XMM9));
  fprintf(out, "  movntdq [rsi + %lu], xmm10\n", __builtin_offsetof(State, XMM10));
  fprintf(out, "  movntdq [rsi + %lu], xmm11\n", __builtin_offsetof(State, XMM11));
  fprintf(out, "  movntdq [rsi + %lu], xmm12\n", __builtin_offsetof(State, XMM12));
  fprintf(out, "  movntdq [rsi + %lu], xmm13\n", __builtin_offsetof(State, XMM13));
  fprintf(out, "  movntdq [rsi + %lu], xmm14\n", __builtin_offsetof(State, XMM14));
  fprintf(out, "  movntdq [rsi + %lu], xmm15\n", __builtin_offsetof(State, XMM15));

  // On the mcsema stack:
  //     8    stashed r15
  //    16    stashed r14
  //    24    stashed r13
  //    32    stashed r12
  //    40    stashed rbp
  //    48    stashed rbx

  // Restore emulated return address.
  fprintf(out, "  pop QWORD PTR [rsi + %lu]\n", __builtin_offsetof(State, RIP));

  // Callee-saved registers.
  fprintf(out, "  pop r15\n");
  fprintf(out, "  pop r14\n");
  fprintf(out, "  pop r13\n");
  fprintf(out, "  pop r12\n");
  fprintf(out, "  pop rbp\n");
  fprintf(out, "  pop rbx\n");

  // Stashed memory pointer (for returning).
  fprintf(out, "  pop rax\n");
  fprintf(out, "  ret\n");

  fprintf(out, ".Lfunc_end2:\n");
  fprintf(out, "  .size __mcsema_attach_ret,.Lfunc_end2-__mcsema_attach_ret\n");
  fprintf(out, "  .cfi_endproc\n");
  fprintf(out, "\n");


  // Implements `__mcsema_debug_get_reg_state`. This is useful when debugging in
  // gdb.
  fprintf(out, "  .globl __mcsema_debug_get_reg_state\n");
  fprintf(out, "  .type __mcsema_debug_get_reg_state,@function\n");
  fprintf(out, "__mcsema_debug_get_reg_state:\n");
  fprintf(out, "  .cfi_startproc\n");
  fprintf(out, "  mov rax, fs:[0]\n");
  fprintf(out, "  lea rax, [rax - __mcsema_reg_state@TPOFF]\n");
  fprintf(out, "  ret\n");
  fprintf(out, ".Lfunc_end6:\n");
  fprintf(out, "  .size __mcsema_debug_get_reg_state,.Lfunc_end6-__mcsema_debug_get_reg_state\n");
  fprintf(out, "  .cfi_endproc\n");
  fprintf(out, "\n");

  // Error functions.
  fprintf(out, "  .globl __remill_error\n");
  fprintf(out, "  .type __remill_error,@function\n");

  fprintf(out, "  .globl __remill_missing_block\n");
  fprintf(out, "  .type __remill_missing_block,@function\n");

  fprintf(out, "  .globl __remill_function_return\n");
  fprintf(out, "  .type __remill_function_return,@function\n");

  fprintf(out, "  .globl __remill_sync_hyper_call\n");
  fprintf(out, "  .type __remill_sync_hyper_call,@function\n");

  fprintf(out, "__remill_error:\n");
  fprintf(out, "__remill_missing_block:\n");
  fprintf(out, "__remill_function_return:\n");
  fprintf(out, "__remill_sync_hyper_call:\n");
  fprintf(out, "  ud2\n");

  return 0;
}

#pragma clang diagnostic pop

//  // Align the stack.
//  fprintf(out, "  push rsp\n");
//  fprintf(out, "  push QWORD PTR [rsp]\n");
//  fprintf(out, "  and rsp, -16\n");

//  // Restore stack alignment
//  fprintf(out, "  pop rsp\n");


