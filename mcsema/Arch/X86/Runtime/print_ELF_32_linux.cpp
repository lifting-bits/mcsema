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
#define ADDRESS_SIZE_BITS 32

#include <mcsema/Arch/X86/Runtime/Registers.h>
#include <remill/Arch/X86/Runtime/State.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat"

static const size_t kStackSize = 1UL << 20UL;

static void PrintStoreFlags(FILE *out) {

  // FPU control.
  fprintf(out, "  fnstcw WORD PTR [edi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, x87.fxsave.cwd));

  fprintf(out, "  pushfd\n");
  fprintf(out, "  mov edx, 0xcd5\n");
  fprintf(out, "  not edx\n");
  fprintf(out, "  and DWORD PTR [esp], edx\n");

  fprintf(out, "  mov edx, 1\n");
  fprintf(out, "  and dl, BYTE PTR [edi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, CF));
  fprintf(out, "  shl edx, 0\n");
  fprintf(out, "  or DWORD PTR [esp], edx\n");

  fprintf(out, "  mov edx, 1\n");
  fprintf(out, "  and dl, BYTE PTR [edi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, PF));
  fprintf(out, "  shl edx, 2\n");
  fprintf(out, "  or DWORD PTR [esp], edx\n");

  fprintf(out, "  mov edx, 1\n");
  fprintf(out, "  and dl, BYTE PTR [edi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, AF));
  fprintf(out, "  shl edx, 4\n");
  fprintf(out, "  or DWORD PTR [esp], edx\n");

  fprintf(out, "  mov edx, 1\n");
  fprintf(out, "  and dl, BYTE PTR [edi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, ZF));
  fprintf(out, "  shl edx, 6\n");
  fprintf(out, "  or DWORD PTR [esp], edx\n");

  fprintf(out, "  mov edx, 1\n");
  fprintf(out, "  and dl, BYTE PTR [edi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, SF));
  fprintf(out, "  shl edx, 7\n");
  fprintf(out, "  or DWORD PTR [esp], edx\n");

  fprintf(out, "  mov edx, 1\n");
  fprintf(out, "  and dl, BYTE PTR [edi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, DF));
  fprintf(out, "  shl edx, 10\n");
  fprintf(out, "  or DWORD PTR [esp], edx\n");

  fprintf(out, "  mov edx, 1\n");
  fprintf(out, "  and dl, BYTE PTR [edi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, OF));
  fprintf(out, "  shl edx, 11\n");
  fprintf(out, "  or DWORD PTR [esp], edx\n");

  fprintf(out, "  popfd\n");
}

static void PrintLoadFlags(FILE *out) {

  // FPU control.
  fprintf(out, "  push dx\n");
  fprintf(out, "  fldcw WORD PTR [esp]\n");
  fprintf(out, "  pop WORD PTR [edi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, x87.fxsave.cwd));

  // Clear our the `ArithFlags` struct, which is 16 bytes.
  fprintf(out, "  mov DWORD PTR [edi + %" PRIuMAX "], 0\n",
          __builtin_offsetof(State, aflag));
  fprintf(out, "  mov DWORD PTR [edi + %" PRIuMAX "], 0\n",
          __builtin_offsetof(State, aflag) + 4);
  fprintf(out, "  mov DWORD PTR [edi + %" PRIuMAX "], 0\n",
          __builtin_offsetof(State, aflag) + 8);
  fprintf(out, "  mov DWORD PTR [edi + %" PRIuMAX "], 0\n",
          __builtin_offsetof(State, aflag) + 12);

  // Get the EFlags.
  fprintf(out, "  pushfd\n");
  fprintf(out, "  pop edx\n");
  fprintf(out, "  mov DWORD PTR [edi + %" PRIuMAX "], edx\n",
          __builtin_offsetof(State, rflag));

  // Marshal the EFlags into the ArithFlags struct.
  fprintf(out, "  bt edx, 0\n");
  fprintf(out, "  adc BYTE PTR [edi + %" PRIuMAX "], 0\n",
          __builtin_offsetof(State, CF));

  fprintf(out, "  bt edx, 2\n");
  fprintf(out, "  adc BYTE PTR [edi + %" PRIuMAX "], 0\n",
          __builtin_offsetof(State, PF));

  fprintf(out, "  bt edx, 4\n");
  fprintf(out, "  adc BYTE PTR [edi + %" PRIuMAX "], 0\n",
          __builtin_offsetof(State, AF));

  fprintf(out, "  bt edx, 6\n");
  fprintf(out, "  adc BYTE PTR [edi + %" PRIuMAX "], 0\n",
          __builtin_offsetof(State, ZF));

  fprintf(out, "  bt edx, 7\n");
  fprintf(out, "  adc BYTE PTR [edi + %" PRIuMAX "], 0\n",
          __builtin_offsetof(State, SF));

  fprintf(out, "  bt edx, 10\n");
  fprintf(out, "  adc BYTE PTR [edi + %" PRIuMAX "], 0\n",
          __builtin_offsetof(State, DF));

  fprintf(out, "  bt edx, 11\n");
  fprintf(out, "  adc BYTE PTR [edi + %" PRIuMAX "], 0\n",
          __builtin_offsetof(State, OF));
}

int main(void) {

  FILE *out = fopen("runtime_32.S", "w");

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

  // General-purpose registers.
  fprintf(out, "  mov gs:[__mcsema_reg_state@TPOFF + %" PRIuMAX "], esi\n",
          __builtin_offsetof(State, ESI));
  fprintf(out, "  mov gs:[__mcsema_reg_state@TPOFF + %" PRIuMAX "], edi\n",
          __builtin_offsetof(State, EDI));

  // Set up the `GS` segment register so that TLS works :-)
  fprintf(out, "  mov esi, DWORD PTR gs:[0]\n");
  fprintf(out, "  mov gs:[__mcsema_reg_state@TPOFF + %" PRIuMAX "], esi\n",
          __builtin_offsetof(State, GS_BASE));
  fprintf(out, "  lea edi, DWORD PTR [__mcsema_reg_state@TPOFF]\n");
  fprintf(out, "  lea edi, DWORD PTR [esi + edi]\n");

  // `ESI` is the TLS base
  // `EDI` points to the State structure

  // Rest of the GPRs.
  fprintf(out, "  mov [edi + %" PRIuMAX "], edx\n",
          __builtin_offsetof(State, EDX));
  fprintf(out, "  mov [edi + %" PRIuMAX "], eax\n",
          __builtin_offsetof(State, EAX));
  fprintf(out, "  mov [edi + %" PRIuMAX "], ebx\n",
          __builtin_offsetof(State, EBX));
  fprintf(out, "  mov [edi + %" PRIuMAX "], ecx\n",
          __builtin_offsetof(State, ECX));
  fprintf(out, "  mov [edi + %" PRIuMAX "], ebp\n",
          __builtin_offsetof(State, EBP));

  // XMM registers.
  fprintf(out, "  movntdq [edi + %" PRIuMAX "], xmm0\n",
          __builtin_offsetof(State, XMM0));
  fprintf(out, "  movntdq [edi + %" PRIuMAX "], xmm1\n",
          __builtin_offsetof(State, XMM1));
  fprintf(out, "  movntdq [edi + %" PRIuMAX "], xmm2\n",
          __builtin_offsetof(State, XMM2));
  fprintf(out, "  movntdq [edi + %" PRIuMAX "], xmm3\n",
          __builtin_offsetof(State, XMM3));
  fprintf(out, "  movntdq [edi + %" PRIuMAX "], xmm4\n",
          __builtin_offsetof(State, XMM4));
  fprintf(out, "  movntdq [edi + %" PRIuMAX "], xmm5\n",
          __builtin_offsetof(State, XMM5));
  fprintf(out, "  movntdq [edi + %" PRIuMAX "], xmm6\n",
          __builtin_offsetof(State, XMM6));
  fprintf(out, "  movntdq [edi + %" PRIuMAX "], xmm7\n",
          __builtin_offsetof(State, XMM7));

  PrintLoadFlags(out);  // Note: Clobbers EDX.

  // If `ESP` is null then we need to initialize it to our new stack.
  //
  // Note: `ESI` is the TLS base.
  fprintf(out, "  mov edx, [edi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, ESP));
  fprintf(out, "  cmp edx, 0\n");
  fprintf(out, "  jnz .Lhave_stack\n");
  fprintf(out, "  lea eax, DWORD PTR [__mcsema_stack@TPOFF]\n");
  fprintf(out, "  lea edx, DWORD PTR [esi + eax + %" PRIuMAX "]\n",
          (kStackSize - 16));
  fprintf(out, ".Lhave_stack:\n");

  // `ESI` is the TLS base
  // `EDI` points to the State structure
  // `EDX` points to the McSema stack

  // On the stack:
  //     0  EA of the lifted function (from the CFG).
  //     4  Address of the lifted function (from the bitcode).
  //    12  Return address into native caller.

  // Get the program counter off of the stack.
  fprintf(out, "  pop esi\n");
  fprintf(out, "  mov DWORD PTR [edi + %" PRIuMAX "], esi\n",
          __builtin_offsetof(State, EIP));

  // Set up the arguments on the McSema stack: state, pc, memory.
  fprintf(out, "  lea edx, [edx - 20]\n");
  fprintf(out, "  mov DWORD PTR [edx + 16], edi\n");
  fprintf(out, "  mov DWORD PTR [edx + 12], esi\n");
  fprintf(out, "  mov DWORD PTR [edx + 8], 0\n");

  // Set up a return address so that when the lifted function returns, it will
  // go to `__mcsema_detach_ret`, which will return to native code.
  fprintf(out, "  push __mcsema_detach_ret\n");
  fprintf(out, "  pop DWORD PTR [edx + 4]\n");

  // Put the target address onto the McSema stack, we will `RET` to it below.
  fprintf(out, "  pop DWORD PTR [edx]\n", __builtin_offsetof(State, EIP));

  // Swap onto the lifted stack. The native `ESP` is now where it should be.
  fprintf(out, "  mov [edi + %" PRIuMAX "], esp\n",
          __builtin_offsetof(State, ESP));
  fprintf(out, "  mov esp, edx\n");

  // Ret to the target.
  fprintf(out, "  ret\n");

  fprintf(out, ".Lfunc_end1:\n");
  fprintf(out,
          "  .size __mcsema_attach_call,.Lfunc_end1-__mcsema_attach_call\n");
  fprintf(out, "  .cfi_endproc\n");
  fprintf(out, "\n");

  // Implements `__mcsema_detach_ret`. This goes from lifted code into native code.
  // The native code pointer is located at the native `[State::RSP - 4]`
  // address.
  fprintf(out, "  .globl __mcsema_detach_ret\n");
  fprintf(out, "  .type __mcsema_detach_ret,@function\n");
  fprintf(out, "__mcsema_detach_ret:\n");
  fprintf(out, "  .cfi_startproc\n");

  // Pop the state pointer, pc, and memory pointer arguments off the stack.
  fprintf(out, "  lea esp, [esp + 12]\n");

  // EAX holds the memory pointer, which is null.
  fprintf(out, "  mov edi, DWORD PTR gs:[0]\n");
  fprintf(out, "  lea eax, DWORD PTR [__mcsema_reg_state@TPOFF]\n");
  fprintf(out, "  lea edi, DWORD PTR [edi + eax]\n");

  // The lifted code emulated a ret, which incremented `esp` by 4.
  // We "undo" that, then swap back to the native stack. When we swap, we
  // save into `State::RSP` where we are in the lifted stack, so that the
  // next attach can continue on where we left off.
  fprintf(out, "  sub DWORD PTR [edi + %" PRIuMAX "], 4\n",
          __builtin_offsetof(State, ESP));
  fprintf(out, "  xchg [edi + %" PRIuMAX "], esp\n",
          __builtin_offsetof(State, ESP));

  PrintStoreFlags(out);  // Clobbers RDX.

  // General purpose registers.
  fprintf(out, "  mov eax, [edi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, EAX));
  fprintf(out, "  mov ebx, [edi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, EBX));
  fprintf(out, "  mov ecx, [edi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, ECX));
  fprintf(out, "  mov edx, [edi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, EDX));
  fprintf(out, "  mov esi, [edi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, ESI));
  fprintf(out, "  mov ebp, [edi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, EBP));

  // XMM registers.
  fprintf(out, "  movntdqa xmm0, [edi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, XMM0));
  fprintf(out, "  movntdqa xmm1, [edi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, XMM1));
  fprintf(out, "  movntdqa xmm2, [edi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, XMM2));
  fprintf(out, "  movntdqa xmm3, [edi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, XMM3));
  fprintf(out, "  movntdqa xmm4, [edi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, XMM4));
  fprintf(out, "  movntdqa xmm5, [edi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, XMM5));
  fprintf(out, "  movntdqa xmm6, [edi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, XMM6));
  fprintf(out, "  movntdqa xmm7, [edi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, XMM7));

  fprintf(out, "  mov edi, [edi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, EDI));
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

  // On the stack:
  //    0   <return address into lifted code>
  //    4   state pointer
  //    8   pc
  //   12   memory pointer

  // Stash the memory pointer. This is probably actually nothing. But for
  // generality, we will store and return it, as is expected by the prototype
  // of `__remill_function_call` (see remill/Arch/Runtime/Intrinsics.h).
  //fprintf(out, "  push rdx\n");  // Alignment.
  fprintf(out, "  push DWORD PTR [esp + 12]\n");


  // Stash the callee-saved registers (cdecl ABI). These registers need to
  // be restored later so that things are as they should be when we return
  // back onto the lifted stack.
  fprintf(out, "  push ebx\n");
  fprintf(out, "  push esi\n");
  fprintf(out, "  push edi\n");
  fprintf(out, "  push ebp\n");

  // Make `EDI` point to the `State` pointer.
  fprintf(out, "  mov edi, DWORD PTR [esp + 24]\n");

  // Make `EBX` be the native code target that we want to go to.
  fprintf(out, "  mov ebx, DWORD PTR [esp + 28]\n");

  // Stash the return address stored on the native stack, the replace it
  // with the re-attach function.
  fprintf(out, "  mov esi, [edi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, ESP));
  fprintf(out, "  push DWORD PTR [esi]\n");
  fprintf(out, "  push __mcsema_attach_ret\n");
  fprintf(out, "  pop DWORD PTR [esi]\n");

  // `EDI` is the `State` pointer.
  // `EBX` is the target address.
  // `ESI` is the stack pointer.

  // Emulate a push of the target address onto the native stack. We will
  // `ret` to the target later on.
  fprintf(out, "  sub esi, 4\n");
  fprintf(out, "  mov DWORD PTR [esi], ebx\n");

  PrintStoreFlags(out);  // Clobbers EDX.

  // Swap off-stack, stash the lifted stack pointer.
  fprintf(out, "  mov [edi + %" PRIuMAX "], esp\n",
          __builtin_offsetof(State, ESP));
  fprintf(out, "  mov esp, esi\n");

  // (Most) General purpose registers.
  fprintf(out, "  mov eax, [edi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, EAX));
  fprintf(out, "  mov ebx, [edi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, EBX));
  fprintf(out, "  mov ecx, [edi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, ECX));
  fprintf(out, "  mov edx, [edi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, EDX));
  fprintf(out, "  mov esi, [edi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, ESI));
  fprintf(out, "  mov ebp, [edi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, EBP));

  // XMM registers.
  fprintf(out, "  movntdqa xmm0, [edi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, XMM0));
  fprintf(out, "  movntdqa xmm1, [edi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, XMM1));
  fprintf(out, "  movntdqa xmm2, [edi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, XMM2));
  fprintf(out, "  movntdqa xmm3, [edi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, XMM3));
  fprintf(out, "  movntdqa xmm4, [edi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, XMM4));
  fprintf(out, "  movntdqa xmm5, [edi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, XMM5));
  fprintf(out, "  movntdqa xmm6, [edi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, XMM6));
  fprintf(out, "  movntdqa xmm7, [edi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, XMM7));

  // Swap out EDI.
  fprintf(out, "  mov edi, [edi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, EDI));

  // Code above put the native target address (stored in RDI on entry to
  // `__remill_function_call`) on the stack, just below the return address,
  // which is now `__mcsema_attach_ret`), so we can `ret` and go to our
  // intended target.
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
  fprintf(out, "  mov gs:[__mcsema_reg_state@TPOFF + %" PRIuMAX "], edi\n",
          __builtin_offsetof(State, EDI));
  fprintf(out, "  mov gs:[__mcsema_reg_state@TPOFF + %" PRIuMAX "], esi\n",
          __builtin_offsetof(State, ESI));

  fprintf(out, "  mov edi, DWORD PTR gs:[0]\n");
  fprintf(out, "  mov gs:[__mcsema_reg_state@TPOFF + %" PRIuMAX "], edi\n",
          __builtin_offsetof(State, FS_BASE));
  fprintf(out, "  lea esi, [__mcsema_reg_state@TPOFF]\n");
  fprintf(out, "  lea edi, DWORD PTR [esi + edi]\n");

  // General purpose registers.
  fprintf(out, "  mov [edi + %" PRIuMAX "], eax\n",
          __builtin_offsetof(State, EAX));
  fprintf(out, "  mov [edi + %" PRIuMAX "], ebx\n",
          __builtin_offsetof(State, EBX));
  fprintf(out, "  mov [edi + %" PRIuMAX "], ecx\n",
          __builtin_offsetof(State, ECX));
  fprintf(out, "  mov [edi + %" PRIuMAX "], edx\n",
          __builtin_offsetof(State, EDX));
  fprintf(out, "  mov [edi + %" PRIuMAX "], ebp\n",
          __builtin_offsetof(State, EBP));

  // Swap into the mcsema stack.
  fprintf(out, "  xchg esp, [edi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, ESP));

  // XMM registers.
  fprintf(out, "  movntdq [edi + %" PRIuMAX "], xmm0\n",
          __builtin_offsetof(State, XMM0));
  fprintf(out, "  movntdq [edi + %" PRIuMAX "], xmm1\n",
          __builtin_offsetof(State, XMM1));
  fprintf(out, "  movntdq [edi + %" PRIuMAX "], xmm2\n",
          __builtin_offsetof(State, XMM2));
  fprintf(out, "  movntdq [edi + %" PRIuMAX "], xmm3\n",
          __builtin_offsetof(State, XMM3));
  fprintf(out, "  movntdq [edi + %" PRIuMAX "], xmm4\n",
          __builtin_offsetof(State, XMM4));
  fprintf(out, "  movntdq [edi + %" PRIuMAX "], xmm5\n",
          __builtin_offsetof(State, XMM5));
  fprintf(out, "  movntdq [edi + %" PRIuMAX "], xmm6\n",
          __builtin_offsetof(State, XMM6));
  fprintf(out, "  movntdq [edi + %" PRIuMAX "], xmm7\n",
          __builtin_offsetof(State, XMM7));

  PrintLoadFlags(out);  // Note: Clobbers EDX.

  // On the mcsema stack:
  //     0    emulated return address.
  //     4    stashed ebp
  //     8    stashed edi
  //    12    stashed esi
  //    16    stashed ebx

  // Restore emulated return address.
  fprintf(out, "  pop DWORD PTR [edi + %" PRIuMAX "]\n",
          __builtin_offsetof(State, EIP));


  // Callee-saved registers.
  fprintf(out, "  pop ebp\n");
  fprintf(out, "  pop edi\n");
  fprintf(out, "  pop esi\n");
  fprintf(out, "  pop ebx\n");

  // Stashed memory pointer (for returning).
  fprintf(out, "  pop eax\n");
  fprintf(out, "  ret\n");

  fprintf(out, ".Lfunc_end2:\n");
  fprintf(out, "  .size __mcsema_attach_ret,.Lfunc_end2-__mcsema_attach_ret\n");
  fprintf(out, "  .cfi_endproc\n");
  fprintf(out, "\n");

  // Implements `__mcsema_exception_ret`. It gets called after the exception returns to the handler.
  // It sets the native stack and base pointers correctly after cleaning the stack. It also save the native
  // registers state.

  fprintf(out, "  .globl __mcsema_exception_ret\n");
  fprintf(out, "  .type __mcsema_exception_ret,@function\n");
  fprintf(out, "__mcsema_exception_ret:\n");
  fprintf(out, ".Lfunc_begin10:\n");
  fprintf(out, ".cfi_startproc\n");

  fprintf(out, "  mov gs:[__mcsema_reg_state@TPOFF + %" PRIuMAX "], edi\n",
          __builtin_offsetof(State, EDI));
  fprintf(out, "  mov gs:[__mcsema_reg_state@TPOFF + %" PRIuMAX "], esi\n",
          __builtin_offsetof(State, ESI));

  // Follow the cdecl ABI calling convention
  // Make `EDI` point to the stack pointer.
  fprintf(out, "  mov edi, DWORD PTR [esp + 24]\n");

  // Make `ESI` point to the frame pointer.
  fprintf(out, "  mov esi, DWORD PTR [esp + 28]\n");

  // Sets the native stack and base pointers
  fprintf(out, "  mov gs:[__mcsema_reg_state@TPOFF + %" PRIuMAX "], edi\n",
          __builtin_offsetof(State, ESP));
  fprintf(out, "  mov gs:[__mcsema_reg_state@TPOFF + %" PRIuMAX "], esi\n",
          __builtin_offsetof(State, EBP));


  fprintf(out, "  mov edi, DWORD PTR gs:[0]\n");
  fprintf(out, "  mov gs:[__mcsema_reg_state@TPOFF + %" PRIuMAX "], edi\n",
          __builtin_offsetof(State, FS_BASE));
  fprintf(out, "  lea esi, [__mcsema_reg_state@TPOFF]\n");
  fprintf(out, "  lea edi, DWORD PTR [esi + edi]\n");

  // General purpose registers.
  //fprintf(out, "  mov [edi + %" PRIuMAX "], eax\n", __builtin_offsetof(State, EAX));
  fprintf(out, "  mov [edi + %" PRIuMAX "], ebx\n",
          __builtin_offsetof(State, EBX));
  fprintf(out, "  mov [edi + %" PRIuMAX "], ecx\n",
          __builtin_offsetof(State, ECX));
  fprintf(out, "  mov [edi + %" PRIuMAX "], edx\n",
          __builtin_offsetof(State, EDX));

  // XMM registers.
  fprintf(out, "  movntdq [edi + %" PRIuMAX "], xmm0\n",
          __builtin_offsetof(State, XMM0));
  fprintf(out, "  movntdq [edi + %" PRIuMAX "], xmm1\n",
          __builtin_offsetof(State, XMM1));
  fprintf(out, "  movntdq [edi + %" PRIuMAX "], xmm2\n",
          __builtin_offsetof(State, XMM2));
  fprintf(out, "  movntdq [edi + %" PRIuMAX "], xmm3\n",
          __builtin_offsetof(State, XMM3));
  fprintf(out, "  movntdq [edi + %" PRIuMAX "], xmm4\n",
          __builtin_offsetof(State, XMM4));
  fprintf(out, "  movntdq [edi + %" PRIuMAX "], xmm5\n",
          __builtin_offsetof(State, XMM5));
  fprintf(out, "  movntdq [edi + %" PRIuMAX "], xmm6\n",
          __builtin_offsetof(State, XMM6));
  fprintf(out, "  movntdq [edi + %" PRIuMAX "], xmm7\n",
          __builtin_offsetof(State, XMM7));

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
  fprintf(out, "  mov eax, gs:[__mcsema_reg_state@TPOFF + %" PRIuMAX "]\n",
          __builtin_offsetof(State, ESP));
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
  fprintf(out, "  mov eax, gs:[__mcsema_reg_state@TPOFF + %" PRIuMAX "]\n",
          __builtin_offsetof(State, EBP));
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
  fprintf(out, "  mov gs:[__mcsema_reg_state@TPOFF + %" PRIuMAX "], eax\n",
          __builtin_offsetof(State, EAX));
  fprintf(out, "  mov eax, edx\n");
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
  fprintf(out, "  mov eax, gs:[0]\n");
  fprintf(out, "  lea edx, [__mcsema_reg_state@TPOFF]\n");
  fprintf(out, "  lea eax, [eax + edx]\n");
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
//  fprintf(out, "  push esp\n");
//  fprintf(out, "  push QWORD PTR [esp]\n");
//  fprintf(out, "  and esp, -16\n");

//  // Restore stack alignment
//  fprintf(out, "  pop esp\n");
