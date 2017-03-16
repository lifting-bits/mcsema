/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <cstdio>

#define ONLY_STRUCT
#include "State.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat"

static const unsigned long kStackSize = 1UL << 20UL;

int main(void) {

  FILE *out = fopen("runtime_64.S", "w");

  fprintf(out, "/* Auto-generated file! Don't modify! */\n\n");
  fprintf(out, "  .file __FILE__\n");
  fprintf(out, "  .intel_syntax noprefix\n");
  fprintf(out, "\n");

  // Thread-local state structure, named by `__mcsema_reg_state`.
  fprintf(out, "  .type __mcsema_reg_state,@object\n");
  fprintf(out, "  .section .tbss,\"awT\",@nobits\n");
  fprintf(out, "__mcsema_reg_state:\n");
  fprintf(out, "  .zero %lu\n", sizeof(RegState));
  fprintf(out, "  .size __mcsema_reg_state, 100\n");
  fprintf(out, "\n");

  // Thread-local stack structure, named by `__mcsema_stack`.
  fprintf(out, "  .type __mcsema_stack,@object\n");
  fprintf(out, "  .section .tbss,\"awT\",@nobits\n");
  fprintf(out, "__mcsema_stack:\n");
  fprintf(out, "  .zero %lu\n", kStackSize);  // 1 MiB.
  fprintf(out, "  .size __mcsema_stack, 100\n");
  fprintf(out, "\n");


  fprintf(out, "  .text\n");
  fprintf(out, "\n");

  // Forward declarations.
  fprintf(out, "  .globl __mcsema_detach_ret\n");
  fprintf(out, "\n");

  // Implements `__mcsema_attach_call`. This goes from native state into lifted code.
  // The lifted code function pointer is already on the stack.
  fprintf(out, "  .globl __mcsema_attach_call\n");
  fprintf(out, "  .type __mcsema_attach_call,@function\n");
  fprintf(out, "__mcsema_attach_call:\n");
  fprintf(out, "  .cfi_startproc\n");

  // Pop the target function into the `RegState` structure. This resets `RSP`
  // to what it should be on entry to `__mcsema_attach_call`.
  fprintf(out, "  pop QWORD PTR fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, RIP));

  // General purpose registers.
  fprintf(out, "  mov fs:[__mcsema_reg_state@TPOFF + %lu], rax\n", __builtin_offsetof(RegState, RAX));
  fprintf(out, "  mov fs:[__mcsema_reg_state@TPOFF + %lu], rbx\n", __builtin_offsetof(RegState, RBX));
  fprintf(out, "  mov fs:[__mcsema_reg_state@TPOFF + %lu], rcx\n", __builtin_offsetof(RegState, RCX));
  fprintf(out, "  mov fs:[__mcsema_reg_state@TPOFF + %lu], rdx\n", __builtin_offsetof(RegState, RDX));
  fprintf(out, "  mov fs:[__mcsema_reg_state@TPOFF + %lu], rsi\n", __builtin_offsetof(RegState, RSI));
  fprintf(out, "  mov fs:[__mcsema_reg_state@TPOFF + %lu], rdi\n", __builtin_offsetof(RegState, RDI));
  fprintf(out, "  mov fs:[__mcsema_reg_state@TPOFF + %lu], rbp\n", __builtin_offsetof(RegState, RBP));
  fprintf(out, "  xchg rsp, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, RSP));
  fprintf(out, "  mov fs:[__mcsema_reg_state@TPOFF + %lu], r8\n", __builtin_offsetof(RegState, R8));
  fprintf(out, "  mov fs:[__mcsema_reg_state@TPOFF + %lu], r9\n", __builtin_offsetof(RegState, R9));
  fprintf(out, "  mov fs:[__mcsema_reg_state@TPOFF + %lu], r10\n", __builtin_offsetof(RegState, R10));
  fprintf(out, "  mov fs:[__mcsema_reg_state@TPOFF + %lu], r11\n", __builtin_offsetof(RegState, R11));
  fprintf(out, "  mov fs:[__mcsema_reg_state@TPOFF + %lu], r12\n", __builtin_offsetof(RegState, R12));
  fprintf(out, "  mov fs:[__mcsema_reg_state@TPOFF + %lu], r13\n", __builtin_offsetof(RegState, R13));
  fprintf(out, "  mov fs:[__mcsema_reg_state@TPOFF + %lu], r14\n", __builtin_offsetof(RegState, R14));
  fprintf(out, "  mov fs:[__mcsema_reg_state@TPOFF + %lu], r15\n", __builtin_offsetof(RegState, R15));

  // XMM registers.
  fprintf(out, "  movdqu fs:[__mcsema_reg_state@TPOFF + %lu], xmm0\n", __builtin_offsetof(RegState, XMM0));
  fprintf(out, "  movdqu fs:[__mcsema_reg_state@TPOFF + %lu], xmm1\n", __builtin_offsetof(RegState, XMM1));
  fprintf(out, "  movdqu fs:[__mcsema_reg_state@TPOFF + %lu], xmm2\n", __builtin_offsetof(RegState, XMM2));
  fprintf(out, "  movdqu fs:[__mcsema_reg_state@TPOFF + %lu], xmm3\n", __builtin_offsetof(RegState, XMM3));
  fprintf(out, "  movdqu fs:[__mcsema_reg_state@TPOFF + %lu], xmm4\n", __builtin_offsetof(RegState, XMM4));
  fprintf(out, "  movdqu fs:[__mcsema_reg_state@TPOFF + %lu], xmm5\n", __builtin_offsetof(RegState, XMM5));
  fprintf(out, "  movdqu fs:[__mcsema_reg_state@TPOFF + %lu], xmm6\n", __builtin_offsetof(RegState, XMM6));
  fprintf(out, "  movdqu fs:[__mcsema_reg_state@TPOFF + %lu], xmm7\n", __builtin_offsetof(RegState, XMM7));
  fprintf(out, "  movdqu fs:[__mcsema_reg_state@TPOFF + %lu], xmm8\n", __builtin_offsetof(RegState, XMM8));
  fprintf(out, "  movdqu fs:[__mcsema_reg_state@TPOFF + %lu], xmm9\n", __builtin_offsetof(RegState, XMM9));
  fprintf(out, "  movdqu fs:[__mcsema_reg_state@TPOFF + %lu], xmm10\n", __builtin_offsetof(RegState, XMM10));
  fprintf(out, "  movdqu fs:[__mcsema_reg_state@TPOFF + %lu], xmm11\n", __builtin_offsetof(RegState, XMM11));
  fprintf(out, "  movdqu fs:[__mcsema_reg_state@TPOFF + %lu], xmm12\n", __builtin_offsetof(RegState, XMM12));
  fprintf(out, "  movdqu fs:[__mcsema_reg_state@TPOFF + %lu], xmm13\n", __builtin_offsetof(RegState, XMM13));
  fprintf(out, "  movdqu fs:[__mcsema_reg_state@TPOFF + %lu], xmm14\n", __builtin_offsetof(RegState, XMM14));
  fprintf(out, "  movdqu fs:[__mcsema_reg_state@TPOFF + %lu], xmm15\n", __builtin_offsetof(RegState, XMM15));

  // If `RSP` is null then we need to initialize it to our new stack.
  fprintf(out, "  cmp rsp, 0\n");
  fprintf(out, "  jnz .Lhave_stack\n");
  fprintf(out, "  mov rsp, fs:[0]\n");
  fprintf(out, "  lea rsp, [rsp + __mcsema_stack@TPOFF + %lu]\n", kStackSize);
  fprintf(out, ".Lhave_stack:\n");

  // `rsp` holds the address of the mcsema stack.
  //    1) Set up a return address on the mcsema stack.
  //    2) Tail-call to the lifted function.
  //
  // Note:  When the lifted function returns, it will go to `__mcsema_detach_ret`,
  //        which will return to native code.
  fprintf(out, "  lea rdi, [rip + __mcsema_detach_ret]\n");
  fprintf(out, "  push rdi\n");

  // Last but not least, set up `RDI` to be the address of the state structure.
  // A pointer to the state structure is passed as the first argument to lifted
  // code functions.
  fprintf(out, "  mov rdi, fs:[0]\n");
  fprintf(out, "  lea rdi, [rdi + __mcsema_reg_state@TPOFF]\n");
  fprintf(out, "  jmp fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, RIP));

  fprintf(out, ".Lfunc_end1:\n");
  fprintf(out, "  .size __mcsema_attach_call,.Lfunc_end1-__mcsema_attach_call\n");
  fprintf(out, "  .cfi_endproc\n");
  fprintf(out, "\n");

  // Implements `__mcsema_attach_ret`. This goes from native state into lifted code.
  // The lifted code function pointer is already on the stack.
  fprintf(out, "  .globl __mcsema_attach_ret\n");
  fprintf(out, "  .type __mcsema_attach_ret,@function\n");
  fprintf(out, "__mcsema_attach_ret:\n");
  fprintf(out, "  .cfi_startproc\n");

//  // Restore old stack alignment.
//  fprintf(out, "  pop rsp\n");

  // Swap into the mcsema stack.
  fprintf(out, "  xchg rsp, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, RSP));

  // Return registers.
  fprintf(out, "  mov fs:[__mcsema_reg_state@TPOFF + %lu], rax\n", __builtin_offsetof(RegState, RAX));
  fprintf(out, "  mov fs:[__mcsema_reg_state@TPOFF + %lu], rdx\n", __builtin_offsetof(RegState, RDX));
  fprintf(out, "  movdqu fs:[__mcsema_reg_state@TPOFF + %lu], xmm0\n", __builtin_offsetof(RegState, XMM0));

  // Callee-saved registers.
  fprintf(out, "  pop QWORD PTR fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, R15));
  fprintf(out, "  pop QWORD PTR fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, R14));
  fprintf(out, "  pop QWORD PTR fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, R13));
  fprintf(out, "  pop QWORD PTR fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, R12));
  fprintf(out, "  pop QWORD PTR fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, RBP));
  fprintf(out, "  pop QWORD PTR fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, RBX));

  // Unstash the callee-saved registers.
  fprintf(out, "  pop r15\n");
  fprintf(out, "  pop r14\n");
  fprintf(out, "  pop r13\n");
  fprintf(out, "  pop r12\n");
  fprintf(out, "  pop rbp\n");
  fprintf(out, "  pop rbx\n");

  fprintf(out, "  ret\n");

  fprintf(out, ".Lfunc_end2:\n");
  fprintf(out, "  .size __mcsema_attach_ret,.Lfunc_end2-__mcsema_attach_ret\n");
  fprintf(out, "  .cfi_endproc\n");
  fprintf(out, "\n");


  // Implements `__mcsema_attach_ret_value`. This is the "opposite" of
  // `__mcsema_detach_call_value`.
  fprintf(out, "  .globl __mcsema_attach_ret_value\n");
  fprintf(out, "  .type __mcsema_attach_ret_value,@function\n");
  fprintf(out, "__mcsema_attach_ret_value:\n");
  fprintf(out, "  .cfi_startproc\n");

  // General purpose registers.
  fprintf(out, "  mov fs:[__mcsema_reg_state@TPOFF + %lu], rax\n", __builtin_offsetof(RegState, RAX));
  fprintf(out, "  mov fs:[__mcsema_reg_state@TPOFF + %lu], rbx\n", __builtin_offsetof(RegState, RBX));
  fprintf(out, "  mov fs:[__mcsema_reg_state@TPOFF + %lu], rcx\n", __builtin_offsetof(RegState, RCX));
  fprintf(out, "  mov fs:[__mcsema_reg_state@TPOFF + %lu], rdx\n", __builtin_offsetof(RegState, RDX));
  fprintf(out, "  mov fs:[__mcsema_reg_state@TPOFF + %lu], rsi\n", __builtin_offsetof(RegState, RSI));
  fprintf(out, "  mov fs:[__mcsema_reg_state@TPOFF + %lu], rdi\n", __builtin_offsetof(RegState, RDI));
  fprintf(out, "  mov fs:[__mcsema_reg_state@TPOFF + %lu], rbp\n", __builtin_offsetof(RegState, RBP));
  fprintf(out, "  xchg rsp, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, RSP));
  fprintf(out, "  mov fs:[__mcsema_reg_state@TPOFF + %lu], r8\n", __builtin_offsetof(RegState, R8));
  fprintf(out, "  mov fs:[__mcsema_reg_state@TPOFF + %lu], r9\n", __builtin_offsetof(RegState, R9));
  fprintf(out, "  mov fs:[__mcsema_reg_state@TPOFF + %lu], r10\n", __builtin_offsetof(RegState, R10));
  fprintf(out, "  mov fs:[__mcsema_reg_state@TPOFF + %lu], r11\n", __builtin_offsetof(RegState, R11));
  fprintf(out, "  mov fs:[__mcsema_reg_state@TPOFF + %lu], r12\n", __builtin_offsetof(RegState, R12));
  fprintf(out, "  mov fs:[__mcsema_reg_state@TPOFF + %lu], r13\n", __builtin_offsetof(RegState, R13));
  fprintf(out, "  mov fs:[__mcsema_reg_state@TPOFF + %lu], r14\n", __builtin_offsetof(RegState, R14));
  fprintf(out, "  mov fs:[__mcsema_reg_state@TPOFF + %lu], r15\n", __builtin_offsetof(RegState, R15));

  // XMM registers.
  fprintf(out, "  movdqu fs:[__mcsema_reg_state@TPOFF + %lu], xmm0\n", __builtin_offsetof(RegState, XMM0));
  fprintf(out, "  movdqu fs:[__mcsema_reg_state@TPOFF + %lu], xmm1\n", __builtin_offsetof(RegState, XMM1));
  fprintf(out, "  movdqu fs:[__mcsema_reg_state@TPOFF + %lu], xmm2\n", __builtin_offsetof(RegState, XMM2));
  fprintf(out, "  movdqu fs:[__mcsema_reg_state@TPOFF + %lu], xmm3\n", __builtin_offsetof(RegState, XMM3));
  fprintf(out, "  movdqu fs:[__mcsema_reg_state@TPOFF + %lu], xmm4\n", __builtin_offsetof(RegState, XMM4));
  fprintf(out, "  movdqu fs:[__mcsema_reg_state@TPOFF + %lu], xmm5\n", __builtin_offsetof(RegState, XMM5));
  fprintf(out, "  movdqu fs:[__mcsema_reg_state@TPOFF + %lu], xmm6\n", __builtin_offsetof(RegState, XMM6));
  fprintf(out, "  movdqu fs:[__mcsema_reg_state@TPOFF + %lu], xmm7\n", __builtin_offsetof(RegState, XMM7));
  fprintf(out, "  movdqu fs:[__mcsema_reg_state@TPOFF + %lu], xmm8\n", __builtin_offsetof(RegState, XMM8));
  fprintf(out, "  movdqu fs:[__mcsema_reg_state@TPOFF + %lu], xmm9\n", __builtin_offsetof(RegState, XMM9));
  fprintf(out, "  movdqu fs:[__mcsema_reg_state@TPOFF + %lu], xmm10\n", __builtin_offsetof(RegState, XMM10));
  fprintf(out, "  movdqu fs:[__mcsema_reg_state@TPOFF + %lu], xmm11\n", __builtin_offsetof(RegState, XMM11));
  fprintf(out, "  movdqu fs:[__mcsema_reg_state@TPOFF + %lu], xmm12\n", __builtin_offsetof(RegState, XMM12));
  fprintf(out, "  movdqu fs:[__mcsema_reg_state@TPOFF + %lu], xmm13\n", __builtin_offsetof(RegState, XMM13));
  fprintf(out, "  movdqu fs:[__mcsema_reg_state@TPOFF + %lu], xmm14\n", __builtin_offsetof(RegState, XMM14));
  fprintf(out, "  movdqu fs:[__mcsema_reg_state@TPOFF + %lu], xmm15\n", __builtin_offsetof(RegState, XMM15));

  // Callee-saved registers.
  fprintf(out, "  pop QWORD PTR fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, R15));
  fprintf(out, "  pop QWORD PTR fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, R14));
  fprintf(out, "  pop QWORD PTR fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, R13));
  fprintf(out, "  pop QWORD PTR fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, R12));
  fprintf(out, "  pop QWORD PTR fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, RBP));
  fprintf(out, "  pop QWORD PTR fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, RBX));

  // Unstash the callee-saved registers.
  fprintf(out, "  pop r15\n");
  fprintf(out, "  pop r14\n");
  fprintf(out, "  pop r13\n");
  fprintf(out, "  pop r12\n");
  fprintf(out, "  pop rbp\n");
  fprintf(out, "  pop rbx\n");

  // If `RSP` is null then we need to initialize it to our new stack.
  fprintf(out, "  ret\n");

  fprintf(out, ".Lfunc_end0:\n");
  fprintf(out, "  .size __mcsema_attach_ret_value,.Lfunc_end0-__mcsema_attach_ret_value\n");
  fprintf(out, "  .cfi_endproc\n");
  fprintf(out, "\n");


  // Implements `__mcsema_detach_ret`. This goes from lifted code into native code.
  // The native code pointer is located at the native `[RegState::RSP - 8]`
  // address.
  fprintf(out, "  .globl __mcsema_detach_ret\n");
  fprintf(out, "  .type __mcsema_detach_ret,@function\n");
  fprintf(out, "__mcsema_detach_ret:\n");
  fprintf(out, "  .cfi_startproc\n");

  // The lifted code emulated a ret, which did incremented `rsp` by 8.
  // We "undo" that, then swap back to the native stack. When we swap, we
  // save into `RegState::RSP` where we are in the lifted stack, so that the
  // next attach can continue on where we left off.
  fprintf(out, "  sub QWORD PTR fs:[__mcsema_reg_state@TPOFF + %lu], 8\n", __builtin_offsetof(RegState, RSP));

  // General purpose registers.
  fprintf(out, "  mov rax, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, RAX));
  fprintf(out, "  mov rbx, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, RBX));
  fprintf(out, "  mov rcx, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, RCX));
  fprintf(out, "  mov rdx, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, RDX));
  fprintf(out, "  mov rsi, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, RSI));
  fprintf(out, "  mov rdi, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, RDI));
  fprintf(out, "  mov rbp, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, RBP));
  fprintf(out, "  xchg fs:[__mcsema_reg_state@TPOFF + %lu], rsp\n", __builtin_offsetof(RegState, RSP));
  fprintf(out, "  mov r8, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, R8));
  fprintf(out, "  mov r9, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, R9));
  fprintf(out, "  mov r10, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, R10));
  fprintf(out, "  mov r11, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, R11));
  fprintf(out, "  mov r12, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, R12));
  fprintf(out, "  mov r13, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, R13));
  fprintf(out, "  mov r14, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, R14));
  fprintf(out, "  mov r15, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, R15));

  // XMM registers.
  fprintf(out, "  movdqu xmm0, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, XMM0));
  fprintf(out, "  movdqu xmm1, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, XMM1));
  fprintf(out, "  movdqu xmm2, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, XMM2));
  fprintf(out, "  movdqu xmm3, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, XMM3));
  fprintf(out, "  movdqu xmm4, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, XMM4));
  fprintf(out, "  movdqu xmm5, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, XMM5));
  fprintf(out, "  movdqu xmm6, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, XMM6));
  fprintf(out, "  movdqu xmm7, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, XMM7));
  fprintf(out, "  movdqu xmm8, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, XMM8));
  fprintf(out, "  movdqu xmm9, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, XMM9));
  fprintf(out, "  movdqu xmm10, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, XMM10));
  fprintf(out, "  movdqu xmm11, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, XMM11));
  fprintf(out, "  movdqu xmm12, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, XMM12));
  fprintf(out, "  movdqu xmm13, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, XMM13));
  fprintf(out, "  movdqu xmm14, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, XMM14));
  fprintf(out, "  movdqu xmm15, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, XMM15));

  fprintf(out, "  ret\n");

  fprintf(out, ".Lfunc_end3:\n");
  fprintf(out, "  .size __mcsema_detach_ret,.Lfunc_end3-__mcsema_detach_ret\n");
  fprintf(out, "  .cfi_endproc\n");
  fprintf(out, "\n");

  // Implements `__mcsema_detach_call`. This partially goes from lifted code
  // into native code.
  fprintf(out, "  .globl __mcsema_detach_call\n");
  fprintf(out, "  .type __mcsema_detach_call,@function\n");
  fprintf(out, "__mcsema_detach_call:\n");
  fprintf(out, "  .cfi_startproc\n");

  // Pop the target function into the `RegState` structure. This resets `RSP`
  // to what it should be on entry to `__mcsema_detach_call`.
  fprintf(out, "  pop QWORD PTR fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, RIP));

  // Stash the callee-saved registers.
  fprintf(out, "  push rbx\n");
  fprintf(out, "  push rbp\n");
  fprintf(out, "  push r12\n");
  fprintf(out, "  push r13\n");
  fprintf(out, "  push r14\n");
  fprintf(out, "  push r15\n");

  // Marshal the callee-saved registers (of the emulated code) into the native
  // state. We don't touch the argument registers.
  fprintf(out, "  mov rbx, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, RBX));
  fprintf(out, "  push QWORD PTR fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, RBX));
  fprintf(out, "  mov rbp, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, RBP));
  fprintf(out, "  push QWORD PTR fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, RBP));
  fprintf(out, "  mov r12, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, R12));
  fprintf(out, "  push QWORD PTR fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, R12));
  fprintf(out, "  mov r13, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, R13));
  fprintf(out, "  push QWORD PTR fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, R13));
  fprintf(out, "  mov r14, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, R14));
  fprintf(out, "  push QWORD PTR fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, R14));
  fprintf(out, "  mov r15, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, R15));
  fprintf(out, "  push QWORD PTR fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, R15));

  // Swap onto the native stack.
  fprintf(out, "  xchg fs:[__mcsema_reg_state@TPOFF + %lu], rsp\n", __builtin_offsetof(RegState, RSP));

  // Set up a re-attach return address.
  fprintf(out, "  lea rax, [rip + __mcsema_attach_ret]\n");
  fprintf(out, "  mov [rsp], rax\n");

  fprintf(out, "  jmp fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, RIP));

  fprintf(out, ".Lfunc_end4:\n");
  fprintf(out, "  .size __mcsema_detach_call,.Lfunc_end4-__mcsema_detach_call\n");
  fprintf(out, "  .cfi_endproc\n");
  fprintf(out, "\n");

  // Implements `__mcsema_detach_call_value`. This is a thin wrapper around
  // `__mcsema_detach_call`.
  fprintf(out, "  .globl __mcsema_detach_call_value\n");
  fprintf(out, "  .type __mcsema_detach_call_value,@function\n");
  fprintf(out, "__mcsema_detach_call_value:\n");
  fprintf(out, "  .cfi_startproc\n");

  // Note: the bitcode has already put the target address into `RegState::RIP`.

  // Stash the callee-saved registers.
  fprintf(out, "  push rbx\n");
  fprintf(out, "  push rbp\n");
  fprintf(out, "  push r12\n");
  fprintf(out, "  push r13\n");
  fprintf(out, "  push r14\n");
  fprintf(out, "  push r15\n");

  fprintf(out, "  push QWORD PTR fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, RBX));
  fprintf(out, "  push QWORD PTR fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, RBP));
  fprintf(out, "  push QWORD PTR fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, R12));
  fprintf(out, "  push QWORD PTR fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, R13));
  fprintf(out, "  push QWORD PTR fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, R14));
  fprintf(out, "  push QWORD PTR fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, R15));

  // General purpose registers.
  fprintf(out, "  mov rax, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, RAX));
  fprintf(out, "  mov rbx, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, RBX));
  fprintf(out, "  mov rcx, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, RCX));
  fprintf(out, "  mov rdx, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, RDX));
  fprintf(out, "  mov rsi, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, RSI));
  fprintf(out, "  mov rdi, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, RDI));
  fprintf(out, "  mov rbp, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, RBP));
  fprintf(out, "  xchg fs:[__mcsema_reg_state@TPOFF + %lu], rsp\n", __builtin_offsetof(RegState, RSP));
  fprintf(out, "  mov r8, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, R8));
  fprintf(out, "  mov r9, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, R9));
  fprintf(out, "  mov r10, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, R10));
  fprintf(out, "  mov r11, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, R11));
  fprintf(out, "  mov r12, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, R12));
  fprintf(out, "  mov r13, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, R13));
  fprintf(out, "  mov r14, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, R14));
  fprintf(out, "  mov r15, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, R15));

  // XMM registers.
  fprintf(out, "  movdqu xmm0, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, XMM0));
  fprintf(out, "  movdqu xmm1, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, XMM1));
  fprintf(out, "  movdqu xmm2, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, XMM2));
  fprintf(out, "  movdqu xmm3, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, XMM3));
  fprintf(out, "  movdqu xmm4, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, XMM4));
  fprintf(out, "  movdqu xmm5, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, XMM5));
  fprintf(out, "  movdqu xmm6, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, XMM6));
  fprintf(out, "  movdqu xmm7, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, XMM7));
  fprintf(out, "  movdqu xmm8, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, XMM8));
  fprintf(out, "  movdqu xmm9, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, XMM9));
  fprintf(out, "  movdqu xmm10, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, XMM10));
  fprintf(out, "  movdqu xmm11, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, XMM11));
  fprintf(out, "  movdqu xmm12, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, XMM12));
  fprintf(out, "  movdqu xmm13, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, XMM13));
  fprintf(out, "  movdqu xmm14, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, XMM14));
  fprintf(out, "  movdqu xmm15, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, XMM15));

  // Set up a re-attach return address.
  fprintf(out, "  lea rax, [rip + __mcsema_attach_ret_value]\n");
  fprintf(out, "  mov [rsp], rax\n");

  // Go native.
  fprintf(out, "  jmp fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(RegState, RIP));

  fprintf(out, ".Lfunc_end5:\n");
  fprintf(out, "  .size __mcsema_detach_call_value,.Lfunc_end5-__mcsema_detach_call_value\n");
  fprintf(out, "  .cfi_endproc\n");
  fprintf(out, "\n");

  // Implements `__mcsema_debug_get_reg_state`. This is useful when debugging in
  // gdb.
  fprintf(out, "  .globl __mcsema_debug_get_reg_state\n");
  fprintf(out, "  .type __mcsema_debug_get_reg_state,@function\n");
  fprintf(out, "__mcsema_debug_get_reg_state:\n");
  fprintf(out, "  .cfi_startproc\n");
  fprintf(out, "  mov rax, fs:[0]\n");
  fprintf(out, "  lea rax, [rax + __mcsema_reg_state@TPOFF]\n");
  fprintf(out, "  ret\n");
  fprintf(out, ".Lfunc_end6:\n");
  fprintf(out, "  .size __mcsema_debug_get_reg_state,.Lfunc_end6-__mcsema_debug_get_reg_state\n");
  fprintf(out, "  .cfi_endproc\n");
  fprintf(out, "\n");
  return 0;
}

#pragma clang diagnostic pop

//  // Align the stack.
//  fprintf(out, "  push rsp\n");
//  fprintf(out, "  push QWORD PTR [rsp]\n");
//  fprintf(out, "  and rsp, -16\n");

//  // Restore stack alignment
//  fprintf(out, "  pop rsp\n");


