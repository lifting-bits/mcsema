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

#include <cinttypes>
#include <cstdio>

#define HAS_FEATURE_AVX 1
#define HAS_FEATURE_AVX512 0
#define ADDRESS_SIZE_BITS 64

#include <mcsema/Arch/X86/Runtime/Registers.h>
#include <remill/Arch/X86/Runtime/State.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat"

static const size_t kStackSize = 1UL << 20UL;

static void PrintStoreFlags(FILE *out) {

  // FPU control.
  fprintf(out, "  fnstcw WORD PTR [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, x87.fxsave.cwd));

  fprintf(out, "  pushfq\n");
  fprintf(out, "  mov edx, 0xcd5\n");
  fprintf(out, "  not rdx\n");
  fprintf(out, "  and QWORD PTR [rsp], rdx\n");

  fprintf(out, "  mov edx, 1\n");
  fprintf(out, "  and dl, BYTE PTR [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, CF));
  fprintf(out, "  shl edx, 0\n");
  fprintf(out, "  or QWORD PTR [rsp], rdx\n");

  fprintf(out, "  mov edx, 1\n");
  fprintf(out, "  and dl, BYTE PTR [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, PF));
  fprintf(out, "  shl edx, 2\n");
  fprintf(out, "  or QWORD PTR [rsp], rdx\n");

  fprintf(out, "  mov edx, 1\n");
  fprintf(out, "  and dl, BYTE PTR [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, AF));
  fprintf(out, "  shl edx, 4\n");
  fprintf(out, "  or QWORD PTR [rsp], rdx\n");

  fprintf(out, "  mov edx, 1\n");
  fprintf(out, "  and dl, BYTE PTR [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, ZF));
  fprintf(out, "  shl edx, 6\n");
  fprintf(out, "  or QWORD PTR [rsp], rdx\n");

  fprintf(out, "  mov edx, 1\n");
  fprintf(out, "  and dl, BYTE PTR [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, SF));
  fprintf(out, "  shl edx, 7\n");
  fprintf(out, "  or QWORD PTR [rsp], rdx\n");

  fprintf(out, "  mov edx, 1\n");
  fprintf(out, "  and dl, BYTE PTR [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, DF));
  fprintf(out, "  shl edx, 10\n");
  fprintf(out, "  or QWORD PTR [rsp], rdx\n");

  fprintf(out, "  mov edx, 1\n");
  fprintf(out, "  and dl, BYTE PTR [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, OF));
  fprintf(out, "  shl edx, 11\n");
  fprintf(out, "  or QWORD PTR [rsp], rdx\n");

  fprintf(out, "  popfq\n");
}

static void PrintLoadFlags(FILE *out) {

  // FPU control.
  fprintf(out, "  push dx\n");
  fprintf(out, "  fldcw WORD PTR [rsp]\n");
  fprintf(out, "  pop WORD PTR [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, x87.fxsave.cwd));

  // Get the RFlags.
  fprintf(out, "  pushfq\n");
  fprintf(out, "  pop rdx\n");
  fprintf(out, "  mov [rdi + %" PRIuMAX "], rdx\n",
          __builtin_offsetof(State, rflag));

  // Clear our the `ArithFlags` struct, which is 16 bytes.
  fprintf(out, "  mov QWORD PTR [rdi + %" PRIuMAX "], 0\n",
          __builtin_offsetof(State, aflag));
  fprintf(out, "  mov QWORD PTR [rdi + %" PRIuMAX "], 0\n",
          __builtin_offsetof(State, aflag) + 8);

  // Marshal the RFlags into the ArithFlags struct.
  fprintf(out, "  bt rdx, 0\n");
  fprintf(out, "  adc BYTE PTR [rdi + %" PRIuMAX "], 0\n",
          __builtin_offsetof(State, CF));

  fprintf(out, "  bt rdx, 2\n");
  fprintf(out, "  adc BYTE PTR [rdi + %" PRIuMAX "], 0\n",
          __builtin_offsetof(State, PF));

  fprintf(out, "  bt rdx, 4\n");
  fprintf(out, "  adc BYTE PTR [rdi + %" PRIuMAX "], 0\n",
          __builtin_offsetof(State, AF));

  fprintf(out, "  bt rdx, 6\n");
  fprintf(out, "  adc BYTE PTR [rdi + %" PRIuMAX "], 0\n",
          __builtin_offsetof(State, ZF));

  fprintf(out, "  bt rdx, 7\n");
  fprintf(out, "  adc BYTE PTR [rdi + %" PRIuMAX "], 0\n",
          __builtin_offsetof(State, SF));

  fprintf(out, "  bt rdx, 10\n");
  fprintf(out, "  adc BYTE PTR [rdi + %" PRIuMAX "], 0\n",
          __builtin_offsetof(State, DF));

  fprintf(out, "  bt rdx, 11\n");
  fprintf(out, "  adc BYTE PTR [rdi + %" PRIuMAX "], 0\n",
          __builtin_offsetof(State, OF));
}

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
  fprintf(out, "  .zero %" PRIuMAX "\n", sizeof(State));
  fprintf(out, "  .size __mcsema_reg_state, %" PRIuMAX "\n", sizeof(State));
  fprintf(out, "\n");

  // Thread-local stack structure, named by `__mcsema_stack`.
  fprintf(out, "  .type __mcsema_stack,@object\n");
  fprintf(out, "  .section .tbss,\"awT\",@nobits\n");
  fprintf(out, "  .align 16\n");
  fprintf(out, "__mcsema_stack:\n");
  fprintf(out, "  .zero %" PRIuMAX "\n", kStackSize);  // 1 MiB.
  fprintf(out, "  .size __mcsema_stack, %" PRIuMAX "\n", kStackSize);
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

  // Save off the first three args of the ABI.
  fprintf(out, "  mov fs:[__mcsema_reg_state@TPOFF + %" PRIuMAX "], rsi\n",
          __builtin_offsetof(State, RSI));
  fprintf(out, "  mov fs:[__mcsema_reg_state@TPOFF + %" PRIuMAX "], rdi\n",
          __builtin_offsetof(State, RDI));
  fprintf(out, "  mov fs:[__mcsema_reg_state@TPOFF + %" PRIuMAX "], rdx\n",
          __builtin_offsetof(State, RDX));

  // On the stack:
  //     0  EA of the lifted function (from the CFG).
  //     8  Address of the lifted function (from the bitcode).
  //    16  Return address into native caller.

  // Set up the `FS` segment register so that TLS works :-)
  fprintf(out, "  mov rsi, QWORD PTR fs:[0]\n");
  fprintf(out, "  mov fs:[__mcsema_reg_state@TPOFF + %" PRIuMAX "], rsi\n",
          __builtin_offsetof(State, FS_BASE));

  // Get arg (rdi) to contain the State pointer.
  fprintf(out, "  lea rdi, QWORD PTR [__mcsema_reg_state@TPOFF]\n");
  fprintf(out, "  lea rdi, QWORD PTR [rsi + rdi]\n");

  // Get the program counter off of the stack.
  fprintf(out, "  pop QWORD PTR [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, RIP));

  // Remaining general purpose registers.
  fprintf(out, "  mov [rdi + %" PRIuMAX "], rax\n",
          __builtin_offsetof(State, RAX));
  fprintf(out, "  mov [rdi + %" PRIuMAX "], rbx\n",
          __builtin_offsetof(State, RBX));
  fprintf(out, "  mov [rdi + %" PRIuMAX "], rcx\n",
          __builtin_offsetof(State, RCX));
  fprintf(out, "  mov [rdi + %" PRIuMAX "], rbp\n",
          __builtin_offsetof(State, RBP));
  fprintf(out, "  mov [rdi + %" PRIuMAX "], r8\n",
          __builtin_offsetof(State, R8));
  fprintf(out, "  mov [rdi + %" PRIuMAX "], r9\n",
          __builtin_offsetof(State, R9));
  fprintf(out, "  mov [rdi + %" PRIuMAX "], r10\n",
          __builtin_offsetof(State, R10));
  fprintf(out, "  mov [rdi + %" PRIuMAX "], r11\n",
          __builtin_offsetof(State, R11));
  fprintf(out, "  mov [rdi + %" PRIuMAX "], r12\n",
          __builtin_offsetof(State, R12));
  fprintf(out, "  mov [rdi + %" PRIuMAX "], r13\n",
          __builtin_offsetof(State, R13));
  fprintf(out, "  mov [rdi + %" PRIuMAX "], r14\n",
          __builtin_offsetof(State, R14));
  fprintf(out, "  mov [rdi + %" PRIuMAX "], r15\n",
          __builtin_offsetof(State, R15));

  PrintLoadFlags(out);  // Note: Clobbers RDX.

  // XMM registers.
  fprintf(out, "  movntdq [rdi + %" PRIuMAX "], xmm0\n",
          __builtin_offsetof(State, XMM0));
  fprintf(out, "  movntdq [rdi + %" PRIuMAX "], xmm1\n",
          __builtin_offsetof(State, XMM1));
  fprintf(out, "  movntdq [rdi + %" PRIuMAX "], xmm2\n",
          __builtin_offsetof(State, XMM2));
  fprintf(out, "  movntdq [rdi + %" PRIuMAX "], xmm3\n",
          __builtin_offsetof(State, XMM3));
  fprintf(out, "  movntdq [rdi + %" PRIuMAX "], xmm4\n",
          __builtin_offsetof(State, XMM4));
  fprintf(out, "  movntdq [rdi + %" PRIuMAX "], xmm5\n",
          __builtin_offsetof(State, XMM5));
  fprintf(out, "  movntdq [rdi + %" PRIuMAX "], xmm6\n",
          __builtin_offsetof(State, XMM6));
  fprintf(out, "  movntdq [rdi + %" PRIuMAX "], xmm7\n",
          __builtin_offsetof(State, XMM7));
  fprintf(out, "  movntdq [rdi + %" PRIuMAX "], xmm8\n",
          __builtin_offsetof(State, XMM8));
  fprintf(out, "  movntdq [rdi + %" PRIuMAX "], xmm9\n",
          __builtin_offsetof(State, XMM9));
  fprintf(out, "  movntdq [rdi + %" PRIuMAX "], xmm10\n",
          __builtin_offsetof(State, XMM10));
  fprintf(out, "  movntdq [rdi + %" PRIuMAX "], xmm11\n",
          __builtin_offsetof(State, XMM11));
  fprintf(out, "  movntdq [rdi + %" PRIuMAX "], xmm12\n",
          __builtin_offsetof(State, XMM12));
  fprintf(out, "  movntdq [rdi + %" PRIuMAX "], xmm13\n",
          __builtin_offsetof(State, XMM13));
  fprintf(out, "  movntdq [rdi + %" PRIuMAX "], xmm14\n",
          __builtin_offsetof(State, XMM14));
  fprintf(out, "  movntdq [rdi + %" PRIuMAX "], xmm15\n",
          __builtin_offsetof(State, XMM15));

  // If `RSP` is null then we need to initialize it to our new stack.
  fprintf(out, "  mov rdx, [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, RSP));
  fprintf(out, "  cmp rdx, 0\n");
  fprintf(out, "  jnz .Lhave_stack\n");
  fprintf(out, "  lea r8, QWORD PTR [__mcsema_stack@TPOFF]\n");
  fprintf(out, "  mov rsi, fs:[0];\n");
  fprintf(out, "  lea rdx, QWORD PTR [rsi + r8 + %" PRIuMAX "]\n",
          (kStackSize - 16));
  fprintf(out, ".Lhave_stack:\n");

  // Set up a return address so that when the lifted function returns, it will
  // go to `__mcsema_detach_ret`, which will return to native code.
  fprintf(out, "  lea rax, [rip + __mcsema_detach_ret]\n");
  fprintf(out, "  mov [rdx - 8], rax\n");

  // Put the address of the lifted function onto the lifted stack, so that we
  // can `RET` into the lifted function.
  fprintf(out, "  pop QWORD PTR [rdx - 16]\n");

  // Swap onto the lifted stack. The native `RSP` is now where it should be.
  fprintf(out, "  mov [rdi + %" PRIuMAX "], rsp\n",
          __builtin_offsetof(State, RSP));
  fprintf(out, "  lea rsp, [rdx - 16]\n");

  // Set up arg2 as the program counter.
  fprintf(out, "  mov rsi, [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, RIP));

  // Set up arg3 as the memory pointer, which is (for now?) a nullptr.
  fprintf(out, "  xor rdx, rdx\n");

  // The address of the lifted function is still on the stack, and `RDX` holds
  // the native PC of the original function.

  // RDX currently holds the address of the lifted function (where we want to
  // go). Inside of the lifted function, RDX (arg3 of AMD64 ABI) needs to hold
  // the same thing as State::RIP. So, push on the address of the lifted
  // function, get RDX right, then `RET` to the lifted function.
  fprintf(out, "  ret\n");

  fprintf(out, ".Lfunc_end1:\n");
  fprintf(out,
          "  .size __mcsema_attach_call,.Lfunc_end1-__mcsema_attach_call\n");
  fprintf(out, "  .cfi_endproc\n");
  fprintf(out, "\n");

  // Implements `__mcsema_detach_ret`. This goes from lifted code into native code.
  // The native code pointer is located at the native `[State::RSP - 8]`
  // address.
  fprintf(out, "  .globl __mcsema_detach_ret\n");
  fprintf(out, "  .type __mcsema_detach_ret,@function\n");
  fprintf(out, "__mcsema_detach_ret:\n");
  fprintf(out, "  .cfi_startproc\n");

  // RAX holds the memory pointer, which is null.
  fprintf(out, "  mov rdi, QWORD PTR fs:[0]\n");
  fprintf(out, "  lea rax, QWORD PTR [__mcsema_reg_state@TPOFF]\n");
  fprintf(out, "  lea rdi, QWORD PTR [rdi + rax]\n");

  // The lifted code emulated a ret, which incremented `rsp` by 8.
  // We "undo" that, then swap back to the native stack. When we swap, we
  // save into `State::RSP` where we are in the lifted stack, so that the
  // next attach can continue on where we left off.
  fprintf(out, "  sub QWORD PTR [rdi + %" PRIuMAX "], 8\n",
          __builtin_offsetof(State, RSP));
  fprintf(out, "  xchg [rdi + %" PRIuMAX "], rsp\n",
          __builtin_offsetof(State, RSP));

  PrintStoreFlags(out);  // Clobbers RDX.

  // General purpose registers.
  fprintf(out, "  mov rax, [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, RAX));
  fprintf(out, "  mov rbx, [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, RBX));
  fprintf(out, "  mov rcx, [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, RCX));
  fprintf(out, "  mov rdx, [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, RDX));
  fprintf(out, "  mov rsi, [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, RSI));
  fprintf(out, "  mov rbp, [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, RBP));
  fprintf(out, "  mov r8, [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, R8));
  fprintf(out, "  mov r9, [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, R9));
  fprintf(out, "  mov r10, [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, R10));
  fprintf(out, "  mov r11, [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, R11));
  fprintf(out, "  mov r12, [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, R12));
  fprintf(out, "  mov r13, [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, R13));
  fprintf(out, "  mov r14, [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, R14));
  fprintf(out, "  mov r15, [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, R15));

  // XMM registers.
  fprintf(out, "  movntdqa xmm0, [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, XMM0));
  fprintf(out, "  movntdqa xmm1, [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, XMM1));
  fprintf(out, "  movntdqa xmm2, [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, XMM2));
  fprintf(out, "  movntdqa xmm3, [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, XMM3));
  fprintf(out, "  movntdqa xmm4, [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, XMM4));
  fprintf(out, "  movntdqa xmm5, [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, XMM5));
  fprintf(out, "  movntdqa xmm6, [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, XMM6));
  fprintf(out, "  movntdqa xmm7, [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, XMM7));
  fprintf(out, "  movntdqa xmm8, [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, XMM8));
  fprintf(out, "  movntdqa xmm9, [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, XMM9));
  fprintf(out, "  movntdqa xmm10, [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, XMM10));
  fprintf(out, "  movntdqa xmm11, [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, XMM11));
  fprintf(out, "  movntdqa xmm12, [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, XMM12));
  fprintf(out, "  movntdqa xmm13, [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, XMM13));
  fprintf(out, "  movntdqa xmm14, [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, XMM14));
  fprintf(out, "  movntdqa xmm15, [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, XMM15));

  fprintf(out, "  mov rdi, [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, RDI));
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
  fprintf(out, ".Lfunc_begin5:\n");
  fprintf(out, "  .cfi_startproc\n");

  // Stash the memory pointer. This is probably actually nothing. But for
  // generality, we will store and return it, as is expected by the prototype
  // of `__remill_function_call` (see remill/Arch/Runtime/Intrinsics.h).
  fprintf(out, "  push rdx\n");  // Alignment.
  fprintf(out, "  push rdx\n");

  // Stash the callee-saved registers (amd64 ABI). These registers need to
  // be restored later so that things are as they should be when we return
  // back onto the lifted stack.
  fprintf(out, "  push rbx\n");
  fprintf(out, "  push rbp\n");
  fprintf(out, "  push r12\n");
  fprintf(out, "  push r13\n");
  fprintf(out, "  push r14\n");
  fprintf(out, "  push r15\n");

  //  fprintf(out, "  push rcx\n");
  //  fprintf(out, "  push rdx\n");
  //  fprintf(out, "  push r8\n");
  //  fprintf(out, "  push r9\n");
  //  fprintf(out, "  push r10\n");
  //  fprintf(out, "  push r11\n");


  // Stash the return address stored on the native stack, the replace it
  // with the re-attach function.
  fprintf(out, "  mov r15, [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, RSP));
  fprintf(out, "  push QWORD PTR [r15]\n");
  fprintf(out, "  lea r14, [rip + __mcsema_attach_ret]\n");
  fprintf(out, "  mov QWORD PTR [r15], r14\n");

  // Emulate a push of the target address onto the native stack. We will
  // `ret` to the target later on.
  //
  // Note: The target address is passed as arg2 (pc) to `__remill_function_call`
  //       which is `RSI` in the AMD64 ABI.
  fprintf(out, "  sub r15, 8\n");
  fprintf(out, "  mov QWORD PTR [r15], rsi\n");

  // Swap off-stack, stash the lifted stack pointer.
  fprintf(out, "  mov [rdi + %" PRIuMAX "], rsp\n",
          __builtin_offsetof(State, RSP));
  fprintf(out, "  mov rsp, r15\n");

  PrintStoreFlags(out);  // Clobbers RDX.

  // (Most) General purpose registers.
  fprintf(out, "  mov rax, [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, RAX));
  fprintf(out, "  mov rbx, [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, RBX));
  fprintf(out, "  mov rcx, [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, RCX));
  fprintf(out, "  mov rdx, [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, RDX));
  fprintf(out, "  mov rsi, [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, RSI));
  fprintf(out, "  mov rbp, [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, RBP));
  fprintf(out, "  mov r8, [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, R8));
  fprintf(out, "  mov r9, [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, R9));
  fprintf(out, "  mov r10, [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, R10));
  fprintf(out, "  mov r11, [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, R11));
  fprintf(out, "  mov r12, [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, R12));
  fprintf(out, "  mov r13, [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, R13));
  fprintf(out, "  mov r14, [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, R14));
  fprintf(out, "  mov r15, [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, R15));

  // XMM registers.
  fprintf(out, "  movntdqa xmm0, [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, XMM0));
  fprintf(out, "  movntdqa xmm1, [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, XMM1));
  fprintf(out, "  movntdqa xmm2, [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, XMM2));
  fprintf(out, "  movntdqa xmm3, [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, XMM3));
  fprintf(out, "  movntdqa xmm4, [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, XMM4));
  fprintf(out, "  movntdqa xmm5, [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, XMM5));
  fprintf(out, "  movntdqa xmm6, [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, XMM6));
  fprintf(out, "  movntdqa xmm7, [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, XMM7));
  fprintf(out, "  movntdqa xmm8, [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, XMM8));
  fprintf(out, "  movntdqa xmm9, [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, XMM9));
  fprintf(out, "  movntdqa xmm10, [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, XMM10));
  fprintf(out, "  movntdqa xmm11, [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, XMM11));
  fprintf(out, "  movntdqa xmm12, [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, XMM12));
  fprintf(out, "  movntdqa xmm13, [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, XMM13));
  fprintf(out, "  movntdqa xmm14, [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, XMM14));
  fprintf(out, "  movntdqa xmm15, [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, XMM15));

  // Swap out RDI.
  fprintf(out, "  mov rdi, [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, RDI));

  // Code above put the native target address (stored in RDI on entry to
  // `__remill_function_call`) on the stack, just below the return address,
  // which is now `__mcsema_attach_ret`), so we can `ret` and go to our
  // intended target.
  fprintf(out, ".Ltmp1000:\n");
  fprintf(out, "  ret\n");

  fprintf(out, ".Lfunc_end5:\n");
  fprintf(
      out,
      "  .size __remill_function_call,.Lfunc_end5-__remill_function_call\n");
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
  fprintf(out, "  mov fs:[__mcsema_reg_state@TPOFF + %" PRIuMAX "], rdi\n",
          __builtin_offsetof(State, RDI));
  fprintf(out, "  mov fs:[__mcsema_reg_state@TPOFF + %" PRIuMAX "], rsi\n",
          __builtin_offsetof(State, RSI));

  fprintf(out, "  mov rdi, QWORD PTR fs:[0]\n");
  fprintf(out, "  mov fs:[__mcsema_reg_state@TPOFF + %" PRIuMAX "], rdi\n",
          __builtin_offsetof(State, FS_BASE));
  fprintf(out, "  lea rsi, [__mcsema_reg_state@TPOFF]\n");
  fprintf(out, "  lea rdi, QWORD PTR [rsi + rdi]\n");

  // General purpose registers.
  fprintf(out, "  mov [rdi + %" PRIuMAX "], rax\n",
          __builtin_offsetof(State, RAX));
  fprintf(out, "  mov [rdi + %" PRIuMAX "], rbx\n",
          __builtin_offsetof(State, RBX));
  fprintf(out, "  mov [rdi + %" PRIuMAX "], rcx\n",
          __builtin_offsetof(State, RCX));
  fprintf(out, "  mov [rdi + %" PRIuMAX "], rdx\n",
          __builtin_offsetof(State, RDX));
  fprintf(out, "  mov [rdi + %" PRIuMAX "], rbp\n",
          __builtin_offsetof(State, RBP));
  fprintf(out, "  mov [rdi + %" PRIuMAX "], r8\n",
          __builtin_offsetof(State, R8));
  fprintf(out, "  mov [rdi + %" PRIuMAX "], r9\n",
          __builtin_offsetof(State, R9));
  fprintf(out, "  mov [rdi + %" PRIuMAX "], r10\n",
          __builtin_offsetof(State, R10));
  fprintf(out, "  mov [rdi + %" PRIuMAX "], r11\n",
          __builtin_offsetof(State, R11));
  fprintf(out, "  mov [rdi + %" PRIuMAX "], r12\n",
          __builtin_offsetof(State, R12));
  fprintf(out, "  mov [rdi + %" PRIuMAX "], r13\n",
          __builtin_offsetof(State, R13));
  fprintf(out, "  mov [rdi + %" PRIuMAX "], r14\n",
          __builtin_offsetof(State, R14));
  fprintf(out, "  mov [rdi + %" PRIuMAX "], r15\n",
          __builtin_offsetof(State, R15));

  // Swap into the mcsema stack.
  fprintf(out, "  xchg rsp, [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, RSP));

  // XMM registers.
  fprintf(out, "  movntdq [rdi + %" PRIuMAX "], xmm0\n",
          __builtin_offsetof(State, XMM0));
  fprintf(out, "  movntdq [rdi + %" PRIuMAX "], xmm1\n",
          __builtin_offsetof(State, XMM1));
  fprintf(out, "  movntdq [rdi + %" PRIuMAX "], xmm2\n",
          __builtin_offsetof(State, XMM2));
  fprintf(out, "  movntdq [rdi + %" PRIuMAX "], xmm3\n",
          __builtin_offsetof(State, XMM3));
  fprintf(out, "  movntdq [rdi + %" PRIuMAX "], xmm4\n",
          __builtin_offsetof(State, XMM4));
  fprintf(out, "  movntdq [rdi + %" PRIuMAX "], xmm5\n",
          __builtin_offsetof(State, XMM5));
  fprintf(out, "  movntdq [rdi + %" PRIuMAX "], xmm6\n",
          __builtin_offsetof(State, XMM6));
  fprintf(out, "  movntdq [rdi + %" PRIuMAX "], xmm7\n",
          __builtin_offsetof(State, XMM7));
  fprintf(out, "  movntdq [rdi + %" PRIuMAX "], xmm8\n",
          __builtin_offsetof(State, XMM8));
  fprintf(out, "  movntdq [rdi + %" PRIuMAX "], xmm9\n",
          __builtin_offsetof(State, XMM9));
  fprintf(out, "  movntdq [rdi + %" PRIuMAX "], xmm10\n",
          __builtin_offsetof(State, XMM10));
  fprintf(out, "  movntdq [rdi + %" PRIuMAX "], xmm11\n",
          __builtin_offsetof(State, XMM11));
  fprintf(out, "  movntdq [rdi + %" PRIuMAX "], xmm12\n",
          __builtin_offsetof(State, XMM12));
  fprintf(out, "  movntdq [rdi + %" PRIuMAX "], xmm13\n",
          __builtin_offsetof(State, XMM13));
  fprintf(out, "  movntdq [rdi + %" PRIuMAX "], xmm14\n",
          __builtin_offsetof(State, XMM14));
  fprintf(out, "  movntdq [rdi + %" PRIuMAX "], xmm15\n",
          __builtin_offsetof(State, XMM15));

  PrintLoadFlags(out);  // Note: Clobbers RDX.

  // On the mcsema stack:
  //     0    emulated return address.
  //     8    stashed r15
  //    16    stashed r14
  //    24    stashed r13
  //    32    stashed r12
  //    40    stashed rbp
  //    48    stashed rbx

  // Restore emulated return address.
  fprintf(out, "  pop QWORD PTR [rdi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, RIP));

  //
  //  fprintf(out, "  pop r11\n");
  //  fprintf(out, "  pop r10\n");
  //  fprintf(out, "  pop r9\n");
  //  fprintf(out, "  pop r8\n");
  //  fprintf(out, "  pop rdx\n");
  //  fprintf(out, "  pop rcx\n");


  // Callee-saved registers.
  fprintf(out, "  pop r15\n");
  fprintf(out, "  pop r14\n");
  fprintf(out, "  pop r13\n");
  fprintf(out, "  pop r12\n");
  fprintf(out, "  pop rbp\n");
  fprintf(out, "  pop rbx\n");

  // Stashed memory pointer (for returning).
  fprintf(out, "  pop rax\n");  // Alignment.
  fprintf(out, "  pop rax\n");
  fprintf(out, "  ret\n");

  fprintf(out, ".Lfunc_end2:\n");
  fprintf(out, "  .size __mcsema_attach_ret,.Lfunc_end2-__mcsema_attach_ret\n");
  fprintf(out, "  .cfi_endproc\n");
  fprintf(out, "\n");

  // Implements `__mcsema_exception_ret`. It gets called after the exception returns to the handler.
  // It sets the native stack and base pointers correctly after cleaning the stack. It also save the native
  // registers state.
  // Arguments: RDI -> stack pointer
  //            RSI -> base pointer

  fprintf(out, "  .globl __mcsema_exception_ret\n");
  fprintf(out, "  .type __mcsema_exception_ret,@function\n");
  fprintf(out, "__mcsema_exception_ret:\n");
  fprintf(out, ".Lfunc_begin10:\n");
  fprintf(out, ".cfi_startproc\n");

  fprintf(out, "  mov fs:[__mcsema_reg_state@TPOFF + %" PRIuMAX "], rdi\n",
          __builtin_offsetof(State, RDI));
  fprintf(out, "  mov fs:[__mcsema_reg_state@TPOFF + %" PRIuMAX "], rsi\n",
          __builtin_offsetof(State, RSI));

  fprintf(out, "  mov rdi, QWORD PTR fs:[0]\n");
  fprintf(out, "  mov fs:[__mcsema_reg_state@TPOFF + %" PRIuMAX "], rdi\n",
          __builtin_offsetof(State, FS_BASE));
  fprintf(out, "  lea rsi, [__mcsema_reg_state@TPOFF]\n");
  fprintf(out, "  lea rdi, QWORD PTR [rsi + rdi]\n");

  // General purpose registers.
  //fprintf(out, "  mov [rdi + %" PRIuMAX "], rax\n", __builtin_offsetof(State, RAX));
  fprintf(out, "  mov [rdi + %" PRIuMAX "], rbx\n",
          __builtin_offsetof(State, RBX));
  fprintf(out, "  mov [rdi + %" PRIuMAX "], rcx\n",
          __builtin_offsetof(State, RCX));
  fprintf(out, "  mov [rdi + %" PRIuMAX "], rdx\n",
          __builtin_offsetof(State, RDX));

  // Sets the native stack and base pointers
  fprintf(out, "  mov rax, fs:[__mcsema_reg_state@TPOFF + %" PRIuMAX "]\n",
          __builtin_offsetof(State, RDI));
  fprintf(out, "  mov [rdi + %" PRIuMAX "], rax\n",
          __builtin_offsetof(State, RSP));
  fprintf(out, "  add QWORD PTR [rdi + %" PRIuMAX "], 8\n",
          __builtin_offsetof(State, RSP));
  fprintf(out, "  mov rax, fs:[__mcsema_reg_state@TPOFF + %" PRIuMAX "]\n",
          __builtin_offsetof(State, RSI));
  fprintf(out, "  mov [rdi + %" PRIuMAX "], rax\n",
          __builtin_offsetof(State, RBP));


  fprintf(out, "  mov [rdi + %" PRIuMAX "], r8\n",
          __builtin_offsetof(State, R8));
  fprintf(out, "  mov [rdi + %" PRIuMAX "], r9\n",
          __builtin_offsetof(State, R9));
  fprintf(out, "  mov [rdi + %" PRIuMAX "], r10\n",
          __builtin_offsetof(State, R10));
  fprintf(out, "  mov [rdi + %" PRIuMAX "], r11\n",
          __builtin_offsetof(State, R11));
  fprintf(out, "  mov [rdi + %" PRIuMAX "], r12\n",
          __builtin_offsetof(State, R12));
  fprintf(out, "  mov [rdi + %" PRIuMAX "], r13\n",
          __builtin_offsetof(State, R13));
  fprintf(out, "  mov [rdi + %" PRIuMAX "], r14\n",
          __builtin_offsetof(State, R14));
  fprintf(out, "  mov [rdi + %" PRIuMAX "], r15\n",
          __builtin_offsetof(State, R15));

  // XMM registers.
  fprintf(out, "  movntdq [rdi + %" PRIuMAX "], xmm0\n",
          __builtin_offsetof(State, XMM0));
  fprintf(out, "  movntdq [rdi + %" PRIuMAX "], xmm1\n",
          __builtin_offsetof(State, XMM1));
  fprintf(out, "  movntdq [rdi + %" PRIuMAX "], xmm2\n",
          __builtin_offsetof(State, XMM2));
  fprintf(out, "  movntdq [rdi + %" PRIuMAX "], xmm3\n",
          __builtin_offsetof(State, XMM3));
  fprintf(out, "  movntdq [rdi + %" PRIuMAX "], xmm4\n",
          __builtin_offsetof(State, XMM4));
  fprintf(out, "  movntdq [rdi + %" PRIuMAX "], xmm5\n",
          __builtin_offsetof(State, XMM5));
  fprintf(out, "  movntdq [rdi + %" PRIuMAX "], xmm6\n",
          __builtin_offsetof(State, XMM6));
  fprintf(out, "  movntdq [rdi + %" PRIuMAX "], xmm7\n",
          __builtin_offsetof(State, XMM7));
  fprintf(out, "  movntdq [rdi + %" PRIuMAX "], xmm8\n",
          __builtin_offsetof(State, XMM8));
  fprintf(out, "  movntdq [rdi + %" PRIuMAX "], xmm9\n",
          __builtin_offsetof(State, XMM9));
  fprintf(out, "  movntdq [rdi + %" PRIuMAX "], xmm10\n",
          __builtin_offsetof(State, XMM10));
  fprintf(out, "  movntdq [rdi + %" PRIuMAX "], xmm11\n",
          __builtin_offsetof(State, XMM11));
  fprintf(out, "  movntdq [rdi + %" PRIuMAX "], xmm12\n",
          __builtin_offsetof(State, XMM12));
  fprintf(out, "  movntdq [rdi + %" PRIuMAX "], xmm13\n",
          __builtin_offsetof(State, XMM13));
  fprintf(out, "  movntdq [rdi + %" PRIuMAX "], xmm14\n",
          __builtin_offsetof(State, XMM14));
  fprintf(out, "  movntdq [rdi + %" PRIuMAX "], xmm15\n",
          __builtin_offsetof(State, XMM15));

  fprintf(out, "  ret\n");
  fprintf(out, "  ud2\n");
  fprintf(out, ".Lfunc_end10:\n");
  fprintf(
      out,
      "  .size __mcsema_exception_ret,.Lfunc_end10-__mcsema_exception_ret\n");
  fprintf(out, "  .cfi_endproc\n");
  fprintf(out, "\n");

  // Implements `__mcsema_get_stack_pointer`. Returns the stack pointer register.
  fprintf(out, "  .globl __mcsema_get_stack_pointer\n");
  fprintf(out, "  .type __mcsema_get_stack_pointer,@function\n");
  fprintf(out, "__mcsema_get_stack_pointer:\n");
  fprintf(out, "  .cfi_startproc\n");
  fprintf(out, "  mov rax, fs:[__mcsema_reg_state@TPOFF + %" PRIuMAX "]\n",
          __builtin_offsetof(State, RSP));
  fprintf(out, "  ret\n");
  fprintf(out, ".Lfunc_end20:\n");
  fprintf(
      out,
      "  .size __mcsema_get_stack_pointer,.Lfunc_end20-__mcsema_get_stack_pointer\n");
  fprintf(out, "  .cfi_endproc\n");
  fprintf(out, "\n");

  // Implements `__mcsema_get_frame_pointer`. Returns the base pointer register.
  fprintf(out, "  .globl __mcsema_get_frame_pointer\n");
  fprintf(out, "  .type __mcsema_get_frame_pointer,@function\n");
  fprintf(out, "__mcsema_get_frame_pointer:\n");
  fprintf(out, "  .cfi_startproc\n");
  fprintf(out, "  mov rax, fs:[__mcsema_reg_state@TPOFF + %" PRIuMAX "]\n",
          __builtin_offsetof(State, RBP));
  fprintf(out, "  ret\n");
  fprintf(out, ".Lfunc_end21:\n");
  fprintf(
      out,
      "  .size __mcsema_get_frame_pointer,.Lfunc_end21-__mcsema_get_frame_pointer\n");
  fprintf(out, "  .cfi_endproc\n");
  fprintf(out, "\n");

  // Implements `__mcsema_get_type_index`. Returns the base pointer register.
  fprintf(out, "  .globl __mcsema_get_type_index\n");
  fprintf(out, "  .type __mcsema_get_type_index,@function\n");
  fprintf(out, "__mcsema_get_type_index:\n");
  fprintf(out, "  .cfi_startproc\n");
  fprintf(out, "  mov fs:[__mcsema_reg_state@TPOFF + %" PRIuMAX "], rax\n",
          __builtin_offsetof(State, RAX));
  fprintf(out, "  mov rax, rdx\n");
  fprintf(out, "  ret\n");
  fprintf(out, ".Lfunc_end22:\n");
  fprintf(
      out,
      "  .size __mcsema_get_type_index,.Lfunc_end22-__mcsema_get_type_index\n");
  fprintf(out, "  .cfi_endproc\n");
  fprintf(out, "\n");

  // Implements `__mcsema_debug_get_reg_state`. This is useful when debugging in
  // gdb.
  fprintf(out, "  .globl __mcsema_debug_get_reg_state\n");
  fprintf(out, "  .type __mcsema_debug_get_reg_state,@function\n");
  fprintf(out, "__mcsema_debug_get_reg_state:\n");
  fprintf(out, "  .cfi_startproc\n");
  fprintf(out, "  mov rax, fs:[0]\n");
  fprintf(out, "  lea rdx, [__mcsema_reg_state@TPOFF]\n");
  fprintf(out, "  lea rax, [rax + rdx]\n");
  fprintf(out, "  ret\n");
  fprintf(out, ".Lfunc_end6:\n");
  fprintf(
      out,
      "  .size __mcsema_debug_get_reg_state,.Lfunc_end6-__mcsema_debug_get_reg_state\n");
  fprintf(out, "  .cfi_endproc\n");
  fprintf(out, "\n");

  // Error functions.
  fprintf(out, "  .globl __remill_error\n");
  fprintf(out, "  .type __remill_error,@function\n");

  fprintf(out, "  .globl __remill_missing_block\n");
  fprintf(out, "  .type __remill_missing_block,@function\n");

  fprintf(out, "  .globl __remill_function_return\n");
  fprintf(out, "  .type __remill_function_return,@function\n");

  fprintf(out, "__remill_error:\n");
  fprintf(out, "__remill_missing_block:\n");
  fprintf(out, "__remill_function_return:\n");
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
