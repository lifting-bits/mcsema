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

#include <cstdio>

#define HAS_FEATURE_AVX 1
#define HAS_FEATURE_AVX512 0
#define ADDRESS_SIZE_BITS 64

#include "mcsema/Arch/X86/Runtime/Registers.h"
#include "remill/Arch/X86/Runtime/State.h"

static const unsigned long long kStackSize = 1ULL << 20ULL;
static const unsigned long long kStackArgSize = 264ULL;

void getTlsIndex(FILE *out, const char dest_reg[]) {

  // store TLS index into dest_reg

  fprintf(out, "push rdx\n");
  fprintf(out, "mov	edx, DWORD ptr [rip + _tls_index]\n");

  // do this awkward mov via rdx since we need to get a 32-bit
  // value, and this helps us avoid figuring out the 32-bit
  // component of the destination register
  fprintf(out, "mov %s, rdx\n", dest_reg);
  fprintf(out, "mov	rdx, QWORD ptr gs:[88]\n");
  fprintf(out, "mov	%s, QWORD ptr [rdx + 8*%s]\n", dest_reg, dest_reg);
  fprintf(out, "pop rdx\n");
}

void emitFunctionDef(FILE *out, const char func_name[]) {
  fprintf(out, ".def	 %s;\n", func_name);
  fprintf(out, ".scl	2;\n");
  fprintf(out, ".type	32;\n");
  fprintf(out, ".endef\n");
  fprintf(out, ".globl %s\n", func_name);
  fprintf(out, ".align 16, 0x90\n");
  fprintf(out, "%s:\n", func_name);
}

int main(void) {

  FILE *out = fopen("runtime_64.asm", "w");

  fprintf(out, "/* Auto-generated file! Don't modify! */\n\n");
  fprintf(out, "  .intel_syntax noprefix\n");
  fprintf(out, "\n");

  fprintf(out, "  .section        .tls$,\"wd\"\n");
  fprintf(out, "  .align 16\n");

  // Thread-local state structure, named by `__mcsema_reg_state`.
  fprintf(out, "  .globl  __mcsema_reg_state\n");
  fprintf(out, "  .align 16\n");
  fprintf(out, "__mcsema_reg_state:\n");
  fprintf(out, "  .zero   %llu\n", sizeof(RegState));
  fprintf(out, "\n");

  // Thread-local stack structure, named by `__mcsema_stack`.
  fprintf(out, "  .globl  __mcsema_stack\n");
  fprintf(out, "  .align 16\n");
  fprintf(out, "__mcsema_stack:\n");
  fprintf(out, "  .zero   %llu\n", kStackSize);  // MiB
  fprintf(out, "\n");

  // Thread-local stack structure, named by `__mcsema_stack_args`
  // used to store stack-passed function arguments
  fprintf(out, "  .globl  __mcsema_stack_args\n");
  fprintf(out, "  .align 16\n");
  fprintf(out, "__mcsema_stack_args:\n");
  fprintf(out, "  .zero   %llu\n", kStackArgSize);
  fprintf(out, "\n");

  // Thread-local variable structure, named by `__mcsema_stack_mark`
  // used to store the expected stack location on return,
  // so caller cleanup conventions can know how many bytes to pop off
  fprintf(out, "  .globl  __mcsema_stack_mark\n");
  fprintf(out, "  .align 8\n");
  fprintf(out, "__mcsema_stack_mark:\n");
  fprintf(out, "  .zero   %u\n", 8);
  fprintf(out, "\n");

  fprintf(out, "  .text\n");
  fprintf(out, "  .align	16, 0x90\n");
  fprintf(out, "\n");

  ///////////////////////////////////////////////////////////////////////////////////
  //
  //  __mcsema_attach_call
  //
  ///////////////////////////////////////////////////////////////////////////////////

  // Implements `__mcsema_attach_call`. This goes from native state into lifted code.
  // The lifted code function pointer is already on the stack.
  emitFunctionDef(out, "__mcsema_attach_call");

  // Pop the target function into the `RegState` structure. This resets `RSP`
  // to what it should be on entry to `__mcsema_attach_call`.
  //
  fprintf(
      out,
      "  push QWORD ptr [rsp]\n");  // dupliate last stack element (the jump-to RIP), so we can pop it
  fprintf(out,
          "  mov QWORD ptr [rsp+8], rbp\n");  // save rbp, we will clobber it
  getTlsIndex(out, "rbp");
  fprintf(out, "  pop QWORD PTR [rbp + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, RIP));
  fprintf(out, "  mov [rbp + __mcsema_reg_state@SECREL32 + %llu], rax\n",
          __builtin_offsetof(RegState, RAX));
  fprintf(out, "  pop rbp\n");  // restore rbp to previous value.
  getTlsIndex(out, "rax");  // we can now clobber rax

  // General purpose registers.
  fprintf(out, "  mov [rax + __mcsema_reg_state@SECREL32 + %llu], rbx\n",
          __builtin_offsetof(RegState, RBX));
  fprintf(out, "  mov [rax + __mcsema_reg_state@SECREL32 + %llu], rcx\n",
          __builtin_offsetof(RegState, RCX));
  fprintf(out, "  mov [rax + __mcsema_reg_state@SECREL32 + %llu], rdx\n",
          __builtin_offsetof(RegState, RDX));
  fprintf(out, "  mov [rax + __mcsema_reg_state@SECREL32 + %llu], rsi\n",
          __builtin_offsetof(RegState, RSI));
  fprintf(out, "  mov [rax + __mcsema_reg_state@SECREL32 + %llu], rdi\n",
          __builtin_offsetof(RegState, RDI));
  fprintf(out, "  mov [rax + __mcsema_reg_state@SECREL32 + %llu], rbp\n",
          __builtin_offsetof(RegState, RBP));

  fprintf(out, "  mov [rax + __mcsema_reg_state@SECREL32 + %llu], r8\n",
          __builtin_offsetof(RegState, R8));
  fprintf(out, "  mov [rax + __mcsema_reg_state@SECREL32 + %llu], r9\n",
          __builtin_offsetof(RegState, R9));
  fprintf(out, "  mov [rax + __mcsema_reg_state@SECREL32 + %llu], r10\n",
          __builtin_offsetof(RegState, R10));
  fprintf(out, "  mov [rax + __mcsema_reg_state@SECREL32 + %llu], r11\n",
          __builtin_offsetof(RegState, R11));
  fprintf(out, "  mov [rax + __mcsema_reg_state@SECREL32 + %llu], r12\n",
          __builtin_offsetof(RegState, R12));
  fprintf(out, "  mov [rax + __mcsema_reg_state@SECREL32 + %llu], r13\n",
          __builtin_offsetof(RegState, R13));
  fprintf(out, "  mov [rax + __mcsema_reg_state@SECREL32 + %llu], r14\n",
          __builtin_offsetof(RegState, R14));
  fprintf(out, "  mov [rax + __mcsema_reg_state@SECREL32 + %llu], r15\n",
          __builtin_offsetof(RegState, R15));

  // XMM registers.
  fprintf(out, "  movdqu [rax + __mcsema_reg_state@SECREL32 + %llu], xmm0\n",
          __builtin_offsetof(RegState, XMM0));
  fprintf(out, "  movdqu [rax + __mcsema_reg_state@SECREL32 + %llu], xmm1\n",
          __builtin_offsetof(RegState, XMM1));
  fprintf(out, "  movdqu [rax + __mcsema_reg_state@SECREL32 + %llu], xmm2\n",
          __builtin_offsetof(RegState, XMM2));
  fprintf(out, "  movdqu [rax + __mcsema_reg_state@SECREL32 + %llu], xmm3\n",
          __builtin_offsetof(RegState, XMM3));
  fprintf(out, "  movdqu [rax + __mcsema_reg_state@SECREL32 + %llu], xmm4\n",
          __builtin_offsetof(RegState, XMM4));
  fprintf(out, "  movdqu [rax + __mcsema_reg_state@SECREL32 + %llu], xmm5\n",
          __builtin_offsetof(RegState, XMM5));
  fprintf(out, "  movdqu [rax + __mcsema_reg_state@SECREL32 + %llu], xmm6\n",
          __builtin_offsetof(RegState, XMM6));
  fprintf(out, "  movdqu [rax + __mcsema_reg_state@SECREL32 + %llu], xmm7\n",
          __builtin_offsetof(RegState, XMM7));
  fprintf(out, "  movdqu [rax + __mcsema_reg_state@SECREL32 + %llu], xmm8\n",
          __builtin_offsetof(RegState, XMM8));
  fprintf(out, "  movdqu [rax + __mcsema_reg_state@SECREL32 + %llu], xmm9\n",
          __builtin_offsetof(RegState, XMM9));
  fprintf(out, "  movdqu [rax + __mcsema_reg_state@SECREL32 + %llu], xmm10\n",
          __builtin_offsetof(RegState, XMM10));
  fprintf(out, "  movdqu [rax + __mcsema_reg_state@SECREL32 + %llu], xmm11\n",
          __builtin_offsetof(RegState, XMM11));
  fprintf(out, "  movdqu [rax + __mcsema_reg_state@SECREL32 + %llu], xmm12\n",
          __builtin_offsetof(RegState, XMM12));
  fprintf(out, "  movdqu [rax + __mcsema_reg_state@SECREL32 + %llu], xmm13\n",
          __builtin_offsetof(RegState, XMM13));
  fprintf(out, "  movdqu [rax + __mcsema_reg_state@SECREL32 + %llu], xmm14\n",
          __builtin_offsetof(RegState, XMM14));
  fprintf(out, "  movdqu [rax + __mcsema_reg_state@SECREL32 + %llu], xmm15\n",
          __builtin_offsetof(RegState, XMM15));

  fprintf(out, "  xchg rsp, [rax + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, RSP));

  // If `RSP` is null then we need to initialize it to our new stack.
  fprintf(out, "  cmp rsp, 0\n");
  fprintf(out, "  jnz .Lhave_stack\n");

  // end inline getTlsIndex
  out, fprintf(out, "  lea rsp, [rax + __mcsema_stack@SECREL32 + %llu]\n",
               kStackSize);
  fprintf(out, ".Lhave_stack:\n");

  // the state struture is the first and only arg to lifted functions
  fprintf(out, "  lea rcx, [rax + __mcsema_reg_state@SECREL32]\n");

  // set up return address
  fprintf(out, "  lea rdx, [rip + __mcsema_detach_ret]\n");

  fprintf(out, "  push rdx\n");

  // get RIP we need to jump to, in the process, clobber TLS index
  fprintf(out,
          "  mov rax, QWORD PTR [rax + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, RIP));

  // and away we go!
  fprintf(out, "  jmp rax\n");
  fprintf(out, "\n");


  ///////////////////////////////////////////////////////////////////////////////////
  //
  //  __mcsema_attach_ret
  //
  ///////////////////////////////////////////////////////////////////////////////////

  // Implements `__mcsema_attach_ret`. This goes from native state into lifted code.
  // The lifted code function pointer is already on the stack.
  emitFunctionDef(out, "__mcsema_attach_ret");

  // this should be valid for cdecl:
  // return stack to where it was before we pasted
  // some arguments to it, so the caller can clean
  // up as expected
  //
  // add an extra 8 bytes to compensate for the fake return address
  fprintf(out, "  add rsp, %llu\n", kStackArgSize + 8);

  // Swap into the mcsema stack.
  fprintf(out, "push rax\n");
  getTlsIndex(out, "rax");
  fprintf(out, "  xchg rsp, [rax + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, RSP));

  // simulate a pop rax from old stack
  fprintf(out,
          "  add QWORD ptr [rax + __mcsema_reg_state@SECREL32 + %llu], 8\n",
          __builtin_offsetof(RegState, RSP));
  fprintf(out,
          "  mov rax, QWORD ptr [rax + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, RSP));
  fprintf(
      out,
      "  mov rax, QWORD ptr [rax-8]\n");  // use -8 here since we just added 8 to the old rsp to simulate a pop

  fprintf(out, "  push rcx\n");
  getTlsIndex(out, "rcx");

  // Return registers.
  fprintf(out, "  mov [rcx + __mcsema_reg_state@SECREL32 + %llu], rax\n",
          __builtin_offsetof(RegState, RAX));
  fprintf(out, "  movdqu [rcx + __mcsema_reg_state@SECREL32 + %llu], xmm0\n",
          __builtin_offsetof(RegState, XMM0));

  // Callee-saved registers.
  fprintf(out, "  mov [rcx + __mcsema_reg_state@SECREL32 + %llu], rbx\n",
          __builtin_offsetof(RegState, RBX));
  fprintf(out, "  mov [rcx + __mcsema_reg_state@SECREL32 + %llu], rsi\n",
          __builtin_offsetof(RegState, RSI));
  fprintf(out, "  mov [rcx + __mcsema_reg_state@SECREL32 + %llu], rdi\n",
          __builtin_offsetof(RegState, RDI));
  fprintf(out, "  mov [rcx + __mcsema_reg_state@SECREL32 + %llu], rbp\n",
          __builtin_offsetof(RegState, RBP));
  fprintf(out, "  mov [rcx + __mcsema_reg_state@SECREL32 + %llu], r12\n",
          __builtin_offsetof(RegState, R12));
  fprintf(out, "  mov [rcx + __mcsema_reg_state@SECREL32 + %llu], r13\n",
          __builtin_offsetof(RegState, R13));
  fprintf(out, "  mov [rcx + __mcsema_reg_state@SECREL32 + %llu], r14\n",
          __builtin_offsetof(RegState, R14));
  fprintf(out, "  mov [rcx + __mcsema_reg_state@SECREL32 + %llu], r15\n",
          __builtin_offsetof(RegState, R15));
  fprintf(out, "  movdqu [rcx + __mcsema_reg_state@SECREL32 + %llu], xmm6\n",
          __builtin_offsetof(RegState, XMM6));
  fprintf(out, "  movdqu [rcx + __mcsema_reg_state@SECREL32 + %llu], xmm7\n",
          __builtin_offsetof(RegState, XMM7));
  fprintf(out, "  movdqu [rcx + __mcsema_reg_state@SECREL32 + %llu], xmm8\n",
          __builtin_offsetof(RegState, XMM8));
  fprintf(out, "  movdqu [rcx + __mcsema_reg_state@SECREL32 + %llu], xmm9\n",
          __builtin_offsetof(RegState, XMM9));
  fprintf(out, "  movdqu [rcx + __mcsema_reg_state@SECREL32 + %llu], xmm10\n",
          __builtin_offsetof(RegState, XMM10));
  fprintf(out, "  movdqu [rcx + __mcsema_reg_state@SECREL32 + %llu], xmm11\n",
          __builtin_offsetof(RegState, XMM11));
  fprintf(out, "  movdqu [rcx + __mcsema_reg_state@SECREL32 + %llu], xmm12\n",
          __builtin_offsetof(RegState, XMM12));
  fprintf(out, "  movdqu [rcx + __mcsema_reg_state@SECREL32 + %llu], xmm13\n",
          __builtin_offsetof(RegState, XMM13));
  fprintf(out, "  movdqu [rcx + __mcsema_reg_state@SECREL32 + %llu], xmm14\n",
          __builtin_offsetof(RegState, XMM14));
  fprintf(out, "  movdqu [rcx + __mcsema_reg_state@SECREL32 + %llu], xmm15\n",
          __builtin_offsetof(RegState, XMM15));

  fprintf(out, "  pop rcx\n");

  // Unstash the callee-saved registers.
  fprintf(out, "  movdqu xmm6, [rsp+%llu]\n", 0 * sizeof(RegState::XMM6));
  fprintf(out, "  movdqu xmm7, [rsp+%llu]\n", 1 * sizeof(RegState::XMM7));
  fprintf(out, "  movdqu xmm8, [rsp+%llu]\n", 2 * sizeof(RegState::XMM8));
  fprintf(out, "  movdqu xmm9, [rsp+%llu]\n", 3 * sizeof(RegState::XMM9));
  fprintf(out, "  movdqu xmm10, [rsp+%llu]\n", 4 * sizeof(RegState::XMM10));
  fprintf(out, "  movdqu xmm11, [rsp+%llu]\n", 5 * sizeof(RegState::XMM11));
  fprintf(out, "  movdqu xmm12, [rsp+%llu]\n", 6 * sizeof(RegState::XMM12));
  fprintf(out, "  movdqu xmm13, [rsp+%llu]\n", 7 * sizeof(RegState::XMM13));
  fprintf(out, "  movdqu xmm14, [rsp+%llu]\n", 8 * sizeof(RegState::XMM14));
  fprintf(out, "  movdqu xmm15, [rsp+%llu]\n", 9 * sizeof(RegState::XMM15));
  fprintf(out, "  add rsp, %llu\n", sizeof(RegState::XMM0) * 10);
  fprintf(out, "  pop rbx\n");
  fprintf(out, "  pop rsi\n");
  fprintf(out, "  pop rdi\n");
  fprintf(out, "  pop rbp\n");
  fprintf(out, "  pop r12\n");
  fprintf(out, "  pop r13\n");
  fprintf(out, "  pop r14\n");
  fprintf(out, "  pop r15\n");
  fprintf(out, "  ret\n");
  fprintf(out, "\n");


  ///////////////////////////////////////////////////////////////////////////////////
  //
  //  __mcsema_attach_ret_value
  //
  ///////////////////////////////////////////////////////////////////////////////////

  // Implements `__mcsema_attach_ret_value`. This is the "opposite" of
  // `__mcsema_detach_call_value`.
  emitFunctionDef(out, "__mcsema_attach_ret_value");
  fprintf(out, "  push rbp\n");
  getTlsIndex(out, "rbp");

  // General purpose registers.
  fprintf(out, "  mov [rbp + __mcsema_reg_state@SECREL32 + %llu], rax\n",
          __builtin_offsetof(RegState, RAX));
  fprintf(out, "  mov [rbp + __mcsema_reg_state@SECREL32 + %llu], rbx\n",
          __builtin_offsetof(RegState, RBX));
  fprintf(out, "  mov [rbp + __mcsema_reg_state@SECREL32 + %llu], rcx\n",
          __builtin_offsetof(RegState, RCX));
  fprintf(out, "  mov [rbp + __mcsema_reg_state@SECREL32 + %llu], rdx\n",
          __builtin_offsetof(RegState, RDX));
  fprintf(out, "  mov [rbp + __mcsema_reg_state@SECREL32 + %llu], rsi\n",
          __builtin_offsetof(RegState, RSI));
  fprintf(out, "  mov [rbp + __mcsema_reg_state@SECREL32 + %llu], rdi\n",
          __builtin_offsetof(RegState, RDI));

  fprintf(out, "  mov [rbp + __mcsema_reg_state@SECREL32 + %llu], r8\n",
          __builtin_offsetof(RegState, R8));
  fprintf(out, "  mov [rbp + __mcsema_reg_state@SECREL32 + %llu], r9\n",
          __builtin_offsetof(RegState, R9));
  fprintf(out, "  mov [rbp + __mcsema_reg_state@SECREL32 + %llu], r10\n",
          __builtin_offsetof(RegState, R10));
  fprintf(out, "  mov [rbp + __mcsema_reg_state@SECREL32 + %llu], r11\n",
          __builtin_offsetof(RegState, R11));
  fprintf(out, "  mov [rbp + __mcsema_reg_state@SECREL32 + %llu], r12\n",
          __builtin_offsetof(RegState, R12));
  fprintf(out, "  mov [rbp + __mcsema_reg_state@SECREL32 + %llu], r13\n",
          __builtin_offsetof(RegState, R13));
  fprintf(out, "  mov [rbp + __mcsema_reg_state@SECREL32 + %llu], r14\n",
          __builtin_offsetof(RegState, R14));
  fprintf(out, "  mov [rbp + __mcsema_reg_state@SECREL32 + %llu], r15\n",
          __builtin_offsetof(RegState, R15));

  // restore rbp
  fprintf(out, "  pop rbp\n");

  // TODO(artem): check if we need to save rax
  getTlsIndex(out, "rax");
  fprintf(out, "  mov [rax + __mcsema_reg_state@SECREL32 + %llu], rbp\n",
          __builtin_offsetof(RegState, RBP));

  // XMM registers.
  fprintf(out, "  movdqu [rax + __mcsema_reg_state@SECREL32 + %llu], xmm0\n",
          __builtin_offsetof(RegState, XMM0));
  fprintf(out, "  movdqu [rax + __mcsema_reg_state@SECREL32 + %llu], xmm1\n",
          __builtin_offsetof(RegState, XMM1));
  fprintf(out, "  movdqu [rax + __mcsema_reg_state@SECREL32 + %llu], xmm2\n",
          __builtin_offsetof(RegState, XMM2));
  fprintf(out, "  movdqu [rax + __mcsema_reg_state@SECREL32 + %llu], xmm3\n",
          __builtin_offsetof(RegState, XMM3));
  fprintf(out, "  movdqu [rax + __mcsema_reg_state@SECREL32 + %llu], xmm4\n",
          __builtin_offsetof(RegState, XMM4));
  fprintf(out, "  movdqu [rax + __mcsema_reg_state@SECREL32 + %llu], xmm5\n",
          __builtin_offsetof(RegState, XMM5));
  fprintf(out, "  movdqu [rax + __mcsema_reg_state@SECREL32 + %llu], xmm6\n",
          __builtin_offsetof(RegState, XMM6));
  fprintf(out, "  movdqu [rax + __mcsema_reg_state@SECREL32 + %llu], xmm7\n",
          __builtin_offsetof(RegState, XMM7));
  fprintf(out, "  movdqu [rax + __mcsema_reg_state@SECREL32 + %llu], xmm8\n",
          __builtin_offsetof(RegState, XMM8));
  fprintf(out, "  movdqu [rax + __mcsema_reg_state@SECREL32 + %llu], xmm9\n",
          __builtin_offsetof(RegState, XMM9));
  fprintf(out, "  movdqu [rax + __mcsema_reg_state@SECREL32 + %llu], xmm10\n",
          __builtin_offsetof(RegState, XMM10));
  fprintf(out, "  movdqu [rax + __mcsema_reg_state@SECREL32 + %llu], xmm11\n",
          __builtin_offsetof(RegState, XMM11));
  fprintf(out, "  movdqu [rax + __mcsema_reg_state@SECREL32 + %llu], xmm12\n",
          __builtin_offsetof(RegState, XMM12));
  fprintf(out, "  movdqu [rax + __mcsema_reg_state@SECREL32 + %llu], xmm13\n",
          __builtin_offsetof(RegState, XMM13));
  fprintf(out, "  movdqu [rax + __mcsema_reg_state@SECREL32 + %llu], xmm14\n",
          __builtin_offsetof(RegState, XMM14));
  fprintf(out, "  movdqu [rax + __mcsema_reg_state@SECREL32 + %llu], xmm15\n",
          __builtin_offsetof(RegState, XMM15));

  // if this function had no args, this will be zero, otherwise
  // it will be -argcount*8 (rsp is now > old rsp, due to pops)
  fprintf(out, "  sub QWORD PTR [rax + __mcsema_stack_mark@SECREL32], rsp\n");

  // TODO(artem) check if we can clobber rcx
  fprintf(out, "  mov rcx, QWORD PTR [rax + __mcsema_stack_mark@SECREL32]\n");

  // adjust for our copied stack args + fake return (we copied kStackArgSize-8 before)
  fprintf(out, "  add rsp, %llu\n", kStackArgSize);
  fprintf(out, "  add rsp, rcx\n");

  fprintf(out,
          "  xchg rsp, QWORD PTR [rax + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, RSP));

  fprintf(out, "  pop QWORD PTR [rax + __mcsema_stack_mark@SECREL32]\n");

  // Unstash the callee-saved registers.
  fprintf(out, "  movdqu xmm6, [rsp+%llu]\n", 0 * sizeof(RegState::XMM6));
  fprintf(out, "  movdqu xmm7, [rsp+%llu]\n", 1 * sizeof(RegState::XMM7));
  fprintf(out, "  movdqu xmm8, [rsp+%llu]\n", 2 * sizeof(RegState::XMM8));
  fprintf(out, "  movdqu xmm9, [rsp+%llu]\n", 3 * sizeof(RegState::XMM9));
  fprintf(out, "  movdqu xmm10, [rsp+%llu]\n", 4 * sizeof(RegState::XMM10));
  fprintf(out, "  movdqu xmm11, [rsp+%llu]\n", 5 * sizeof(RegState::XMM11));
  fprintf(out, "  movdqu xmm12, [rsp+%llu]\n", 6 * sizeof(RegState::XMM12));
  fprintf(out, "  movdqu xmm13, [rsp+%llu]\n", 7 * sizeof(RegState::XMM13));
  fprintf(out, "  movdqu xmm14, [rsp+%llu]\n", 8 * sizeof(RegState::XMM14));
  fprintf(out, "  movdqu xmm15, [rsp+%llu]\n", 9 * sizeof(RegState::XMM15));
  fprintf(out, "  add rsp, %llu\n", sizeof(RegState::XMM0) * 10);
  fprintf(out, "  pop rbx\n");
  fprintf(out, "  pop rsi\n");
  fprintf(out, "  pop rdi\n");
  fprintf(out, "  pop rbp\n");
  fprintf(out, "  pop r12\n");
  fprintf(out, "  pop r13\n");
  fprintf(out, "  pop r14\n");
  fprintf(out, "  pop r15\n");

  fprintf(out, "  ret\n");
  fprintf(out, "\n");

  ///////////////////////////////////////////////////////////////////////////////////
  //
  //  __mcsema_detach_ret
  //
  ///////////////////////////////////////////////////////////////////////////////////

  // Implements `__mcsema_detach_ret`. This goes from lifted code into native code.
  // The native code pointer is located at the native `[RegState::RSP - 8]`
  // address.
  emitFunctionDef(out, "__mcsema_detach_ret");

  // General purpose registers.
  //
  fprintf(out, "  push rbp\n");
  getTlsIndex(out, "rbp");
  fprintf(out, "  mov rax, [rbp + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, RAX));
  fprintf(out, "  mov rbx, [rbp + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, RBX));
  fprintf(out, "  mov rcx, [rbp + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, RCX));
  fprintf(out, "  mov rdx, [rbp + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, RDX));
  fprintf(out, "  mov rsi, [rbp + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, RSI));
  fprintf(out, "  mov rdi, [rbp + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, RDI));

  fprintf(out, "  mov r8,  [rbp + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, R8));
  fprintf(out, "  mov r9,  [rbp + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, R9));
  fprintf(out, "  mov r10, [rbp + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, R10));
  fprintf(out, "  mov r11, [rbp + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, R11));
  fprintf(out, "  mov r12, [rbp + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, R12));
  fprintf(out, "  mov r13, [rbp + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, R13));
  fprintf(out, "  mov r14, [rbp + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, R14));
  fprintf(out, "  mov r15, [rbp + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, R15));

  // XMM registers.
  fprintf(out, "  movdqu xmm0, [rbp + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, XMM0));
  fprintf(out, "  movdqu xmm1, [rbp + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, XMM1));
  fprintf(out, "  movdqu xmm2, [rbp + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, XMM2));
  fprintf(out, "  movdqu xmm3, [rbp + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, XMM3));
  fprintf(out, "  movdqu xmm4, [rbp + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, XMM4));
  fprintf(out, "  movdqu xmm5, [rbp + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, XMM5));
  fprintf(out, "  movdqu xmm6, [rbp + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, XMM6));
  fprintf(out, "  movdqu xmm7, [rbp + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, XMM7));

  fprintf(out, "  movdqu xmm8,  [rbp + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, XMM8));
  fprintf(out, "  movdqu xmm9,  [rbp + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, XMM9));
  fprintf(out, "  movdqu xmm10, [rbp + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, XMM10));
  fprintf(out, "  movdqu xmm11, [rbp + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, XMM11));
  fprintf(out, "  movdqu xmm12, [rbp + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, XMM12));
  fprintf(out, "  movdqu xmm13, [rbp + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, XMM13));
  fprintf(out, "  movdqu xmm14, [rbp + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, XMM14));
  fprintf(out, "  movdqu xmm15, [rbp + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, XMM15));

  fprintf(out, "  pop rbp\n");

  fprintf(out, "  push rax\n");
  getTlsIndex(out, "rax");
  fprintf(out, "  mov rbp, [rax + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, RBP));

  // The lifted code emulated a ret, which did incremented `rsp` by 8.
  // We "undo" that, then swap back to the native stack. When we swap, we
  // save into `RegState::RSP` where we are in the lifted stack, so that the
  // next attach can continue on where we left off.
  fprintf(out,
          "  sub QWORD PTR [rax + __mcsema_reg_state@SECREL32 + %llu], 8\n",
          __builtin_offsetof(RegState, RSP));
  fprintf(out,
          "  xchg rsp, QWORD PTR [rax + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, RSP));

  // simulate a pop rax from old stack
  fprintf(out,
          "  add QWORD ptr [rax + __mcsema_reg_state@SECREL32 + %llu], 8\n",
          __builtin_offsetof(RegState, RSP));
  fprintf(out,
          "  mov rax, qword ptr [rax + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, RSP));
  fprintf(
      out,
      "  mov rax, qword ptr [rax-8]\n");  // use -8 here since we just added 8 to the old rsp to simulate a pop


  fprintf(out, "  ret\n");
  fprintf(out, "\n");

  ///////////////////////////////////////////////////////////////////////////////////
  //
  //  __mcsema_detach_call
  //
  ///////////////////////////////////////////////////////////////////////////////////
  // Implements `__mcsema_detach_call`. This partially goes from lifted code
  // into native code.
  emitFunctionDef(out, "__mcsema_detach_call");

  // *** This function assumes we can clobber rax

  // clobber rax to use as TLS index
  getTlsIndex(out, "rax");

  // Pop the target function into the `RegState` structure. This resets `RIP`
  // to what it should be on entry to `__mcsema_detach_call`.
  fprintf(out, "  pop QWORD PTR [rax + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, RIP));

  // Marshal the callee-saved registers (of the emulated code) into the native
  // state. We don't touch the argument registers.

  // Stash the callee-saved registers.
  fprintf(out, "  push r15\n");
  fprintf(out, "  push r14\n");
  fprintf(out, "  push r13\n");
  fprintf(out, "  push r12\n");
  fprintf(out, "  push rbp\n");
  fprintf(out, "  push rdi\n");
  fprintf(out, "  push rsi\n");
  fprintf(out, "  push rbx\n");
  fprintf(out, "  sub rsp, %llu\n", sizeof(RegState::XMM0) * 10);
  fprintf(out, "  movdqu  [rsp+%llu], xmm6 \n", 0 * sizeof(RegState::XMM6));
  fprintf(out, "  movdqu  [rsp+%llu], xmm7 \n", 1 * sizeof(RegState::XMM7));
  fprintf(out, "  movdqu  [rsp+%llu], xmm8 \n", 2 * sizeof(RegState::XMM8));
  fprintf(out, "  movdqu  [rsp+%llu], xmm9 \n", 3 * sizeof(RegState::XMM9));
  fprintf(out, "  movdqu  [rsp+%llu], xmm10\n", 4 * sizeof(RegState::XMM10));
  fprintf(out, "  movdqu  [rsp+%llu], xmm11\n", 5 * sizeof(RegState::XMM11));
  fprintf(out, "  movdqu  [rsp+%llu], xmm12\n", 6 * sizeof(RegState::XMM12));
  fprintf(out, "  movdqu  [rsp+%llu], xmm13\n", 7 * sizeof(RegState::XMM13));
  fprintf(out, "  movdqu  [rsp+%llu], xmm14\n", 8 * sizeof(RegState::XMM14));
  fprintf(out, "  movdqu  [rsp+%llu], xmm15\n", 9 * sizeof(RegState::XMM15));


  // copy posible stack args into temporary holding area
  fprintf(out, "  lea rdi, [rax + __mcsema_stack_args@SECREL32]\n");

  // stack args start after return address + callee saved GPRs + callee saved XMM
  fprintf(out, "  lea rsi, [rsp + %llu]\n",
          8 + 8 * 8 + sizeof(RegState::XMM0) * 10);

  // rcx is how much to copy
  fprintf(out, "  mov rcx, %llu\n", kStackArgSize);

  // do the copy
  fprintf(out, "  rep movsb\n");

  // restore arguments and callee-saved regs
  fprintf(out, "  mov rsi, [rax + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, RSI));
  fprintf(out, "  mov rdi, [rax + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, RDI));
  fprintf(out, "  mov rbx, [rax + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, RBX));
  fprintf(out, "  mov rbp, [rax + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, RBP));
  fprintf(out, "  mov rcx, [rax + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, RCX));
  fprintf(out, "  mov r12, [rax + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, R12));
  fprintf(out, "  mov r13, [rax + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, R13));
  fprintf(out, "  mov r14, [rax + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, R14));
  fprintf(out, "  mov r15, [rax + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, R15));

  // Swap onto the native stack.
  fprintf(out,
          "  xchg QWORD PTR [rax + __mcsema_reg_state@SECREL32 + %llu], rsp\n",
          __builtin_offsetof(RegState, RSP));

  // copy posible stack args from holding area to native stack
  // allocate space for our arguments on stack
  fprintf(out, "  sub rsp, %llu\n", kStackArgSize);

  // we need to save these
  fprintf(out, "  push rsi\n");
  fprintf(out, "  push rdi\n");
  fprintf(out, "  push rcx\n");

  // get the stack arg location, adjust for the just-pushed values
  fprintf(out, "  lea rdi, [rsp + %u]\n", 8 + 8 + 8);

  // source is temp area
  fprintf(out, "  lea rsi, [rax + __mcsema_stack_args@SECREL32]\n");
  fprintf(out, "  mov rcx, %llu\n", kStackArgSize);

  // copy stack args from temp area to new stack
  fprintf(out, "  rep movsb\n");

  // restore saved regs
  fprintf(out, "  pop rcx\n");
  fprintf(out, "  pop rdi\n");
  fprintf(out, "  pop rsi\n");

  // Set up a re-attach return address.
  // do not push __mcsema_attach_ret directly
  // to work around llvm assembler bug that emits it
  // as a 16-bit push
  fprintf(out, "  push rax\n");
  fprintf(out, "  lea rax, [rip + __mcsema_attach_ret]\n");

  // switched saved rax (TLS index) with current rax (pointer to function)
  // the pointer to function will be the first argument to the mcsema-xlated
  // code we are about to jump to
  fprintf(out, "  xchg rax, [rsp]\n");

  fprintf(out, "  jmp QWORD PTR [rax + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, RIP));


  fprintf(out, "\n");

  ///////////////////////////////////////////////////////////////////////////////////
  //
  //  __mcsema_detach_call_value
  //
  ///////////////////////////////////////////////////////////////////////////////////
  // Implements `__mcsema_detach_call_value`. This is a thin wrapper around
  // `__mcsema_detach_call`.
  emitFunctionDef(out, "__mcsema_detach_call_value");

  // Note: the bitcode has already put the target address into `RegState::RIP`.
  // *** assumes we can clobber rax

  // Stash the callee-saved registers.
  fprintf(out, "  push r15\n");
  fprintf(out, "  push r14\n");
  fprintf(out, "  push r13\n");
  fprintf(out, "  push r12\n");
  fprintf(out, "  push rbp\n");
  fprintf(out, "  push rdi\n");
  fprintf(out, "  push rsi\n");
  fprintf(out, "  push rbx\n");
  fprintf(out, "  sub rsp, %llu\n", sizeof(RegState::XMM0) * 10);
  fprintf(out, "  movdqu  [rsp+%llu], xmm6 \n", 0 * sizeof(RegState::XMM6));
  fprintf(out, "  movdqu  [rsp+%llu], xmm7 \n", 1 * sizeof(RegState::XMM7));
  fprintf(out, "  movdqu  [rsp+%llu], xmm8 \n", 2 * sizeof(RegState::XMM8));
  fprintf(out, "  movdqu  [rsp+%llu], xmm9 \n", 3 * sizeof(RegState::XMM9));
  fprintf(out, "  movdqu  [rsp+%llu], xmm10\n", 4 * sizeof(RegState::XMM10));
  fprintf(out, "  movdqu  [rsp+%llu], xmm11\n", 5 * sizeof(RegState::XMM11));
  fprintf(out, "  movdqu  [rsp+%llu], xmm12\n", 6 * sizeof(RegState::XMM12));
  fprintf(out, "  movdqu  [rsp+%llu], xmm13\n", 7 * sizeof(RegState::XMM13));
  fprintf(out, "  movdqu  [rsp+%llu], xmm14\n", 8 * sizeof(RegState::XMM14));
  fprintf(out, "  movdqu  [rsp+%llu], xmm15\n", 9 * sizeof(RegState::XMM15));

  getTlsIndex(out, "rax");

  // save current stack mark
  fprintf(out, "  push QWORD PTR [rax + __mcsema_stack_mark@SECREL32]\n");

  // copy posible stack args into temporary holding area
  fprintf(out, "  lea rdi, [rax + __mcsema_stack_args@SECREL32]\n");

  // this is not RSP since for do_call_value there is no spilling via an
  // intermediate function
  fprintf(out,
          "  mov rsi, QWORD PTR [rax + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, RSP));

  // use -8 since we have a ret addr on stack already and need alignment
  fprintf(out, "  mov rcx, %llu\n", kStackArgSize - 8);
  fprintf(out, "  rep movsb\n");

  // we wil use rbp to index once we clobber rax
  fprintf(out, "  mov rbp, rax\n");

  // we still read out rax on principle, in case we need to do debugging
  // but we clobber it later anyway, so... ignore it
  fprintf(out, "  mov rax, [rbp + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, RAX));
  fprintf(out, "  mov rax, rbp\n");
  fprintf(out, "  mov rbx, [rax + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, RBX));
  fprintf(out, "  mov rcx, [rax + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, RCX));
  fprintf(out, "  mov rdx, [rax + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, RDX));
  fprintf(out, "  mov rsi, [rax + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, RSI));
  fprintf(out, "  mov rdi, [rax + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, RDI));
  fprintf(out, "  mov rbp, [rax + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, RBP));

  fprintf(out, "  mov r8,  [rax + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, R8));
  fprintf(out, "  mov r9,  [rax + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, R9));
  fprintf(out, "  mov r10, [rax + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, R10));
  fprintf(out, "  mov r11, [rax + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, R11));
  fprintf(out, "  mov r12, [rax + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, R12));
  fprintf(out, "  mov r13, [rax + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, R13));
  fprintf(out, "  mov r14, [rax + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, R14));
  fprintf(out, "  mov r15, [rax + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, R15));

  // XMM registers.
  fprintf(out, "  movdqu xmm0, [rax + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, XMM0));
  fprintf(out, "  movdqu xmm1, [rax + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, XMM1));
  fprintf(out, "  movdqu xmm2, [rax + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, XMM2));
  fprintf(out, "  movdqu xmm3, [rax + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, XMM3));
  fprintf(out, "  movdqu xmm4, [rax + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, XMM4));
  fprintf(out, "  movdqu xmm5, [rax + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, XMM5));
  fprintf(out, "  movdqu xmm6, [rax + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, XMM6));
  fprintf(out, "  movdqu xmm7, [rax + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, XMM7));

  fprintf(out, "  movdqu xmm8,  [rax + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, XMM8));
  fprintf(out, "  movdqu xmm9,  [rax + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, XMM9));
  fprintf(out, "  movdqu xmm10, [rax + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, XMM10));
  fprintf(out, "  movdqu xmm11, [rax + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, XMM11));
  fprintf(out, "  movdqu xmm12, [rax + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, XMM12));
  fprintf(out, "  movdqu xmm13, [rax + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, XMM13));
  fprintf(out, "  movdqu xmm14, [rax + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, XMM14));
  fprintf(out, "  movdqu xmm15, [rax + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, XMM15));

  fprintf(out,
          "  xchg QWORD PTR [rax + __mcsema_reg_state@SECREL32 + %llu], rsp\n",
          __builtin_offsetof(RegState, RSP));

  // copy posible stack args from holding area to native stack
  // allocate space for our arguments on stack
  // use -8 since we have a ret addr on stack already and need alignment
  fprintf(out, "  sub rsp, %llu\n", kStackArgSize - 8);

  // we need to save these
  fprintf(out, "  push rsi\n");
  fprintf(out, "  push rdi\n");
  fprintf(out, "  push rcx\n");

  // get the stack arg location
  // compensate for rsi+rdi+rcx
  fprintf(out, "  lea rdi, [rsp + %u]\n", 8 + 8 + 8);

  // source is temp area
  fprintf(out, "  lea rsi, [rax + __mcsema_stack_args@SECREL32]\n");

  // use -8 since we have a ret addr on stack already and need alignment
  fprintf(out, "  mov rcx, %llu\n", kStackArgSize - 8);

  // copy
  fprintf(out, "  rep movsb\n");

  // restore saved regs
  fprintf(out, "  pop rcx\n");
  fprintf(out, "  pop rdi\n");
  fprintf(out, "  pop rsi\n");

  // save current RSP so we know how many bytes
  // the callee popped off the stack on return
  fprintf(out, "  mov QWORD PTR [rax + __mcsema_stack_mark@SECREL32], rsp\n");

  // Set up a re-attach return address.
  // clobber de7acccc on stack with attach by value RA
  // preserve rax
  fprintf(out, "  mov [rsp], rax\n");
  fprintf(out, "  lea rax, [rip + __mcsema_attach_ret_value]\n");
  fprintf(out, "  xchg rax, [rsp]\n");

  // Go native.
  fprintf(out, "  jmp QWORD PTR [rax + __mcsema_reg_state@SECREL32 + %llu]\n",
          __builtin_offsetof(RegState, RIP));
  fprintf(out, "\n");

  ///////////////////////////////////////////////////////////////////////////////////
  //
  //  __mcsema_debug_get_reg_state
  //
  ///////////////////////////////////////////////////////////////////////////////////
  // Implements `__mcsema_debug_get_reg_state`. This is useful when debugging in
  // gdb.
  emitFunctionDef(out, "__mcsema_debug_get_reg_state");
  getTlsIndex(out, "rax");
  fprintf(out, "  lea rax, [rax + __mcsema_reg_state@SECREL32]\n");
  fprintf(out, "  ret\n");
  fprintf(out, "\n");
  return 0;
}
