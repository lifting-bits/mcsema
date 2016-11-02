/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <cstdio>

#define ONLY_STRUCT
#include "../common/RegisterState.h"

static const unsigned long kStackSize = 1UL << 20UL;

int main(void) {

  printf("/* Auto-generated file! Don't modify! */\n\n");
  printf("  .file __FILE__\n");
  printf("  .intel_syntax noprefix\n");
  printf("\n");

  // Thread-local state structure, named by `__mcsema_reg_state`.
  printf("  .type __mcsema_reg_state,@object\n");
  printf("  .section .tbss,\"awT\",@nobits\n");
  printf("__mcsema_reg_state:\n");
  printf("  .zero %lu\n", sizeof(mcsema::RegState));
  printf("  .size __mcsema_reg_state, 100\n");
  printf("\n");

  // Thread-local stack structure, named by `__mcsema_stack`.
  printf("  .type __mcsema_stack,@object\n");
  printf("  .section .tbss,\"awT\",@nobits\n");
  printf("__mcsema_stack:\n");
  printf("  .zero %lu\n", kStackSize);  // 1 MiB.
  printf("  .size __mcsema_stack, 100\n");
  printf("\n");


  printf("  .text\n");
  printf("\n");

  // Forward declarations.
  printf("  .globl mcsema_main\n");
  printf("  .globl __mcsema_detach_ret\n");
  printf("\n");

  // Implements `__mcsema_attach_call`. This goes from native state into lifted code.
  // The lifted code function pointer is already on the stack.
  printf("  .globl __mcsema_attach_call\n");
  printf("  .type __mcsema_attach_call,@function\n");
  printf("__mcsema_attach_call:\n");
  printf("  .cfi_startproc\n");

  // Pop the target function into the `RegState` structure. This resets `RSP`
  // to what it should be on entry to `__mcsema_attach_call`.
  printf("  pop QWORD PTR fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, RIP));

  // General purpose registers.
  printf("  mov fs:[__mcsema_reg_state@TPOFF + %lu], rax\n", __builtin_offsetof(mcsema::RegState, RAX));
  printf("  mov fs:[__mcsema_reg_state@TPOFF + %lu], rbx\n", __builtin_offsetof(mcsema::RegState, RBX));
  printf("  mov fs:[__mcsema_reg_state@TPOFF + %lu], rcx\n", __builtin_offsetof(mcsema::RegState, RCX));
  printf("  mov fs:[__mcsema_reg_state@TPOFF + %lu], rdx\n", __builtin_offsetof(mcsema::RegState, RDX));
  printf("  mov fs:[__mcsema_reg_state@TPOFF + %lu], rsi\n", __builtin_offsetof(mcsema::RegState, RSI));
  printf("  mov fs:[__mcsema_reg_state@TPOFF + %lu], rdi\n", __builtin_offsetof(mcsema::RegState, RDI));
  printf("  mov fs:[__mcsema_reg_state@TPOFF + %lu], rbp\n", __builtin_offsetof(mcsema::RegState, RBP));
  printf("  xchg rsp, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, RSP));
  printf("  mov fs:[__mcsema_reg_state@TPOFF + %lu], r8\n", __builtin_offsetof(mcsema::RegState, R8));
  printf("  mov fs:[__mcsema_reg_state@TPOFF + %lu], r9\n", __builtin_offsetof(mcsema::RegState, R9));
  printf("  mov fs:[__mcsema_reg_state@TPOFF + %lu], r10\n", __builtin_offsetof(mcsema::RegState, R10));
  printf("  mov fs:[__mcsema_reg_state@TPOFF + %lu], r11\n", __builtin_offsetof(mcsema::RegState, R11));
  printf("  mov fs:[__mcsema_reg_state@TPOFF + %lu], r12\n", __builtin_offsetof(mcsema::RegState, R12));
  printf("  mov fs:[__mcsema_reg_state@TPOFF + %lu], r13\n", __builtin_offsetof(mcsema::RegState, R13));
  printf("  mov fs:[__mcsema_reg_state@TPOFF + %lu], r14\n", __builtin_offsetof(mcsema::RegState, R14));
  printf("  mov fs:[__mcsema_reg_state@TPOFF + %lu], r15\n", __builtin_offsetof(mcsema::RegState, R15));

  // XMM registers.
  printf("  movdqu fs:[__mcsema_reg_state@TPOFF + %lu], xmm0\n", __builtin_offsetof(mcsema::RegState, XMM0));
  printf("  movdqu fs:[__mcsema_reg_state@TPOFF + %lu], xmm1\n", __builtin_offsetof(mcsema::RegState, XMM1));
  printf("  movdqu fs:[__mcsema_reg_state@TPOFF + %lu], xmm2\n", __builtin_offsetof(mcsema::RegState, XMM2));
  printf("  movdqu fs:[__mcsema_reg_state@TPOFF + %lu], xmm3\n", __builtin_offsetof(mcsema::RegState, XMM3));
  printf("  movdqu fs:[__mcsema_reg_state@TPOFF + %lu], xmm4\n", __builtin_offsetof(mcsema::RegState, XMM4));
  printf("  movdqu fs:[__mcsema_reg_state@TPOFF + %lu], xmm5\n", __builtin_offsetof(mcsema::RegState, XMM5));
  printf("  movdqu fs:[__mcsema_reg_state@TPOFF + %lu], xmm6\n", __builtin_offsetof(mcsema::RegState, XMM6));
  printf("  movdqu fs:[__mcsema_reg_state@TPOFF + %lu], xmm7\n", __builtin_offsetof(mcsema::RegState, XMM7));
  printf("  movdqu fs:[__mcsema_reg_state@TPOFF + %lu], xmm8\n", __builtin_offsetof(mcsema::RegState, XMM8));
  printf("  movdqu fs:[__mcsema_reg_state@TPOFF + %lu], xmm9\n", __builtin_offsetof(mcsema::RegState, XMM9));
  printf("  movdqu fs:[__mcsema_reg_state@TPOFF + %lu], xmm10\n", __builtin_offsetof(mcsema::RegState, XMM10));
  printf("  movdqu fs:[__mcsema_reg_state@TPOFF + %lu], xmm11\n", __builtin_offsetof(mcsema::RegState, XMM11));
  printf("  movdqu fs:[__mcsema_reg_state@TPOFF + %lu], xmm12\n", __builtin_offsetof(mcsema::RegState, XMM12));
  printf("  movdqu fs:[__mcsema_reg_state@TPOFF + %lu], xmm13\n", __builtin_offsetof(mcsema::RegState, XMM13));
  printf("  movdqu fs:[__mcsema_reg_state@TPOFF + %lu], xmm14\n", __builtin_offsetof(mcsema::RegState, XMM14));
  printf("  movdqu fs:[__mcsema_reg_state@TPOFF + %lu], xmm15\n", __builtin_offsetof(mcsema::RegState, XMM15));

  // If `RSP` is null then we need to initialize it to our new stack.
  printf("  cmp rsp, 0\n");
  printf("  jnz .Lhave_stack\n");
  printf("  mov rsp, fs:[0]\n");
  printf("  lea rsp, [rsp + __mcsema_stack@TPOFF + %lu]\n", kStackSize);
  printf(".Lhave_stack:\n");

  // `rsp` holds the address of the mcsema stack.
  //    1) Set up a return address on the mcsema stack.
  //    2) Tail-call to the lifted function.
  //
  // Note:  When the lifted function returns, it will go to `__mcsema_detach_ret`,
  //        which will return to native code.
  printf("  lea rdi, [rip + __mcsema_detach_ret]\n");
  printf("  push rdi\n");

  // Last but not least, set up `RDI` to be the address of the state structure.
  // A pointer to the state structure is passed as the first argument to lifted
  // code functions.
  printf("  mov rdi, fs:[0]\n");
  printf("  lea rdi, [rdi + __mcsema_reg_state@TPOFF]\n");
  printf("  jmp fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, RIP));

  printf(".Lfunc_end1:\n");
  printf("  .size __mcsema_attach_call,.Lfunc_end1-__mcsema_attach_call\n");
  printf("  .cfi_endproc\n");
  printf("\n");

  // Implements `__mcsema_attach_ret`. This goes from native state into lifted code.
  // The lifted code function pointer is already on the stack.
  printf("  .globl __mcsema_attach_ret\n");
  printf("  .type __mcsema_attach_ret,@function\n");
  printf("__mcsema_attach_ret:\n");
  printf("  .cfi_startproc\n");

//  // Restore old stack alignment.
//  printf("  pop rsp\n");

  // Swap into the mcsema stack.
  printf("  xchg rsp, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, RSP));

  // Return registers.
  printf("  mov fs:[__mcsema_reg_state@TPOFF + %lu], rax\n", __builtin_offsetof(mcsema::RegState, RAX));
  printf("  mov fs:[__mcsema_reg_state@TPOFF + %lu], rdx\n", __builtin_offsetof(mcsema::RegState, RDX));
  printf("  movdqu fs:[__mcsema_reg_state@TPOFF + %lu], xmm0\n", __builtin_offsetof(mcsema::RegState, XMM0));

  // Callee-saved registers.
  printf("  mov fs:[__mcsema_reg_state@TPOFF + %lu], rbx\n", __builtin_offsetof(mcsema::RegState, RBX));
  printf("  mov fs:[__mcsema_reg_state@TPOFF + %lu], rbp\n", __builtin_offsetof(mcsema::RegState, RBP));
  printf("  mov fs:[__mcsema_reg_state@TPOFF + %lu], r12\n", __builtin_offsetof(mcsema::RegState, R12));
  printf("  mov fs:[__mcsema_reg_state@TPOFF + %lu], r13\n", __builtin_offsetof(mcsema::RegState, R13));
  printf("  mov fs:[__mcsema_reg_state@TPOFF + %lu], r14\n", __builtin_offsetof(mcsema::RegState, R14));
  printf("  mov fs:[__mcsema_reg_state@TPOFF + %lu], r15\n", __builtin_offsetof(mcsema::RegState, R15));

  // Unstash the callee-saved registers.
  printf("  pop r15\n");
  printf("  pop r14\n");
  printf("  pop r13\n");
  printf("  pop r12\n");
  printf("  pop rbp\n");
  printf("  pop rbx\n");

  printf("  ret\n");

  printf(".Lfunc_end2:\n");
  printf("  .size __mcsema_attach_ret,.Lfunc_end2-__mcsema_attach_ret\n");
  printf("  .cfi_endproc\n");
  printf("\n");


  // Implements `__mcsema_attach_ret_value`. This is the "opposite" of
  // `__mcsema_detach_call_value`.
  printf("  .globl __mcsema_attach_ret_value\n");
  printf("  .type __mcsema_attach_ret_value,@function\n");
  printf("__mcsema_attach_ret_value:\n");
  printf("  .cfi_startproc\n");

  // General purpose registers.
  printf("  mov fs:[__mcsema_reg_state@TPOFF + %lu], rax\n", __builtin_offsetof(mcsema::RegState, RAX));
  printf("  mov fs:[__mcsema_reg_state@TPOFF + %lu], rbx\n", __builtin_offsetof(mcsema::RegState, RBX));
  printf("  mov fs:[__mcsema_reg_state@TPOFF + %lu], rcx\n", __builtin_offsetof(mcsema::RegState, RCX));
  printf("  mov fs:[__mcsema_reg_state@TPOFF + %lu], rdx\n", __builtin_offsetof(mcsema::RegState, RDX));
  printf("  mov fs:[__mcsema_reg_state@TPOFF + %lu], rsi\n", __builtin_offsetof(mcsema::RegState, RSI));
  printf("  mov fs:[__mcsema_reg_state@TPOFF + %lu], rdi\n", __builtin_offsetof(mcsema::RegState, RDI));
  printf("  mov fs:[__mcsema_reg_state@TPOFF + %lu], rbp\n", __builtin_offsetof(mcsema::RegState, RBP));
  printf("  xchg rsp, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, RSP));
  printf("  mov fs:[__mcsema_reg_state@TPOFF + %lu], r8\n", __builtin_offsetof(mcsema::RegState, R8));
  printf("  mov fs:[__mcsema_reg_state@TPOFF + %lu], r9\n", __builtin_offsetof(mcsema::RegState, R9));
  printf("  mov fs:[__mcsema_reg_state@TPOFF + %lu], r10\n", __builtin_offsetof(mcsema::RegState, R10));
  printf("  mov fs:[__mcsema_reg_state@TPOFF + %lu], r11\n", __builtin_offsetof(mcsema::RegState, R11));
  printf("  mov fs:[__mcsema_reg_state@TPOFF + %lu], r12\n", __builtin_offsetof(mcsema::RegState, R12));
  printf("  mov fs:[__mcsema_reg_state@TPOFF + %lu], r13\n", __builtin_offsetof(mcsema::RegState, R13));
  printf("  mov fs:[__mcsema_reg_state@TPOFF + %lu], r14\n", __builtin_offsetof(mcsema::RegState, R14));
  printf("  mov fs:[__mcsema_reg_state@TPOFF + %lu], r15\n", __builtin_offsetof(mcsema::RegState, R15));

  // XMM registers.
  printf("  movdqu fs:[__mcsema_reg_state@TPOFF + %lu], xmm0\n", __builtin_offsetof(mcsema::RegState, XMM0));
  printf("  movdqu fs:[__mcsema_reg_state@TPOFF + %lu], xmm1\n", __builtin_offsetof(mcsema::RegState, XMM1));
  printf("  movdqu fs:[__mcsema_reg_state@TPOFF + %lu], xmm2\n", __builtin_offsetof(mcsema::RegState, XMM2));
  printf("  movdqu fs:[__mcsema_reg_state@TPOFF + %lu], xmm3\n", __builtin_offsetof(mcsema::RegState, XMM3));
  printf("  movdqu fs:[__mcsema_reg_state@TPOFF + %lu], xmm4\n", __builtin_offsetof(mcsema::RegState, XMM4));
  printf("  movdqu fs:[__mcsema_reg_state@TPOFF + %lu], xmm5\n", __builtin_offsetof(mcsema::RegState, XMM5));
  printf("  movdqu fs:[__mcsema_reg_state@TPOFF + %lu], xmm6\n", __builtin_offsetof(mcsema::RegState, XMM6));
  printf("  movdqu fs:[__mcsema_reg_state@TPOFF + %lu], xmm7\n", __builtin_offsetof(mcsema::RegState, XMM7));
  printf("  movdqu fs:[__mcsema_reg_state@TPOFF + %lu], xmm8\n", __builtin_offsetof(mcsema::RegState, XMM8));
  printf("  movdqu fs:[__mcsema_reg_state@TPOFF + %lu], xmm9\n", __builtin_offsetof(mcsema::RegState, XMM9));
  printf("  movdqu fs:[__mcsema_reg_state@TPOFF + %lu], xmm10\n", __builtin_offsetof(mcsema::RegState, XMM10));
  printf("  movdqu fs:[__mcsema_reg_state@TPOFF + %lu], xmm11\n", __builtin_offsetof(mcsema::RegState, XMM11));
  printf("  movdqu fs:[__mcsema_reg_state@TPOFF + %lu], xmm12\n", __builtin_offsetof(mcsema::RegState, XMM12));
  printf("  movdqu fs:[__mcsema_reg_state@TPOFF + %lu], xmm13\n", __builtin_offsetof(mcsema::RegState, XMM13));
  printf("  movdqu fs:[__mcsema_reg_state@TPOFF + %lu], xmm14\n", __builtin_offsetof(mcsema::RegState, XMM14));
  printf("  movdqu fs:[__mcsema_reg_state@TPOFF + %lu], xmm15\n", __builtin_offsetof(mcsema::RegState, XMM15));

  // Unstash the callee-saved registers.
  printf("  pop r15\n");
  printf("  pop r14\n");
  printf("  pop r13\n");
  printf("  pop r12\n");
  printf("  pop rbp\n");
  printf("  pop rbx\n");

  // If `RSP` is null then we need to initialize it to our new stack.
  printf("  ret\n");

  printf(".Lfunc_end0:\n");
  printf("  .size __mcsema_attach_ret_value,.Lfunc_end0-__mcsema_attach_ret_value\n");
  printf("  .cfi_endproc\n");
  printf("\n");


  // Implements `__mcsema_detach_ret`. This goes from lifted code into native code.
  // The native code pointer is located at the native `[RegState::RSP - 8]`
  // address.
  printf("  .globl __mcsema_detach_ret\n");
  printf("  .type __mcsema_detach_ret,@function\n");
  printf("__mcsema_detach_ret:\n");
  printf("  .cfi_startproc\n");

  // The lifted code emulated a ret, which did incremented `rsp` by 8.
  // We "undo" that, then swap back to the native stack. When we swap, we
  // save into `RegState::RSP` where we are in the lifted stack, so that the
  // next attach can continue on where we left off.
  printf("  sub QWORD PTR fs:[__mcsema_reg_state@TPOFF + %lu], 8\n", __builtin_offsetof(mcsema::RegState, RSP));

  // General purpose registers.
  printf("  mov rax, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, RAX));
  printf("  mov rbx, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, RBX));
  printf("  mov rcx, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, RCX));
  printf("  mov rdx, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, RDX));
  printf("  mov rsi, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, RSI));
  printf("  mov rdi, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, RDI));
  printf("  mov rbp, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, RBP));
  printf("  xchg fs:[__mcsema_reg_state@TPOFF + %lu], rsp\n", __builtin_offsetof(mcsema::RegState, RSP));
  printf("  mov r8, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, R8));
  printf("  mov r9, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, R9));
  printf("  mov r10, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, R10));
  printf("  mov r11, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, R11));
  printf("  mov r12, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, R12));
  printf("  mov r13, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, R13));
  printf("  mov r14, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, R14));
  printf("  mov r15, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, R15));

  // XMM registers.
  printf("  movdqu xmm0, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, XMM0));
  printf("  movdqu xmm1, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, XMM1));
  printf("  movdqu xmm2, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, XMM2));
  printf("  movdqu xmm3, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, XMM3));
  printf("  movdqu xmm4, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, XMM4));
  printf("  movdqu xmm5, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, XMM5));
  printf("  movdqu xmm6, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, XMM6));
  printf("  movdqu xmm7, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, XMM7));
  printf("  movdqu xmm8, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, XMM8));
  printf("  movdqu xmm9, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, XMM9));
  printf("  movdqu xmm10, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, XMM10));
  printf("  movdqu xmm11, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, XMM11));
  printf("  movdqu xmm12, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, XMM12));
  printf("  movdqu xmm13, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, XMM13));
  printf("  movdqu xmm14, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, XMM14));
  printf("  movdqu xmm15, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, XMM15));

  printf("  ret\n");

  printf(".Lfunc_end3:\n");
  printf("  .size __mcsema_detach_ret,.Lfunc_end3-__mcsema_detach_ret\n");
  printf("  .cfi_endproc\n");
  printf("\n");

  // Implements `__mcsema_detach_call`. This partially goes from lifted code
  // into native code.
  printf("  .globl __mcsema_detach_call\n");
  printf("  .type __mcsema_detach_call,@function\n");
  printf("__mcsema_detach_call:\n");
  printf("  .cfi_startproc\n");

  // Pop the target function into the `RegState` structure. This resets `RSP`
  // to what it should be on entry to `__mcsema_detach_call`.
  printf("  pop QWORD PTR fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, RIP));

  // Stash the callee-saved registers.
  printf("  push rbx\n");
  printf("  push rbp\n");
  printf("  push r12\n");
  printf("  push r13\n");
  printf("  push r14\n");
  printf("  push r15\n");

  // Marshal the callee-saved registers (of the emulated code) into the native
  // state. We don't touch the argument registers.
  printf("  mov rbx, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, RBX));
  printf("  mov rbp, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, RBP));
  printf("  mov r12, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, R12));
  printf("  mov r13, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, R13));
  printf("  mov r14, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, R14));
  printf("  mov r15, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, R15));

  // Swap onto the native stack.
  printf("  xchg fs:[__mcsema_reg_state@TPOFF + %lu], rsp\n", __builtin_offsetof(mcsema::RegState, RSP));

  // Set up a re-attach return address.
  printf("  lea rax, [rip + __mcsema_attach_ret]\n");
  printf("  mov [rsp], rax\n");

  printf("  jmp fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, RIP));

  printf(".Lfunc_end4:\n");
  printf("  .size __mcsema_detach_call,.Lfunc_end4-__mcsema_detach_call\n");
  printf("  .cfi_endproc\n");
  printf("\n");

  // Implements `__mcsema_detach_call_value`. This is a thin wrapper around
  // `__mcsema_detach_call`.
  printf("  .globl __mcsema_detach_call_value\n");
  printf("  .type __mcsema_detach_call_value,@function\n");
  printf("__mcsema_detach_call_value:\n");
  printf("  .cfi_startproc\n");

  // Note: the bitcode has already put the target address into `RegState::RIP`.

  // Stash the callee-saved registers.
  printf("  push rbx\n");
  printf("  push rbp\n");
  printf("  push r12\n");
  printf("  push r13\n");
  printf("  push r14\n");
  printf("  push r15\n");

  // General purpose registers.
  printf("  mov rax, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, RAX));
  printf("  mov rbx, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, RBX));
  printf("  mov rcx, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, RCX));
  printf("  mov rdx, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, RDX));
  printf("  mov rsi, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, RSI));
  printf("  mov rdi, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, RDI));
  printf("  mov rbp, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, RBP));
  printf("  xchg fs:[__mcsema_reg_state@TPOFF + %lu], rsp\n", __builtin_offsetof(mcsema::RegState, RSP));
  printf("  mov r8, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, R8));
  printf("  mov r9, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, R9));
  printf("  mov r10, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, R10));
  printf("  mov r11, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, R11));
  printf("  mov r12, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, R12));
  printf("  mov r13, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, R13));
  printf("  mov r14, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, R14));
  printf("  mov r15, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, R15));

  // XMM registers.
  printf("  movdqu xmm0, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, XMM0));
  printf("  movdqu xmm1, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, XMM1));
  printf("  movdqu xmm2, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, XMM2));
  printf("  movdqu xmm3, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, XMM3));
  printf("  movdqu xmm4, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, XMM4));
  printf("  movdqu xmm5, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, XMM5));
  printf("  movdqu xmm6, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, XMM6));
  printf("  movdqu xmm7, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, XMM7));
  printf("  movdqu xmm8, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, XMM8));
  printf("  movdqu xmm9, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, XMM9));
  printf("  movdqu xmm10, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, XMM10));
  printf("  movdqu xmm11, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, XMM11));
  printf("  movdqu xmm12, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, XMM12));
  printf("  movdqu xmm13, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, XMM13));
  printf("  movdqu xmm14, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, XMM14));
  printf("  movdqu xmm15, fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, XMM15));

  // Set up a re-attach return address.
  printf("  lea rax, [rip + __mcsema_attach_ret_value]\n");
  printf("  mov [rsp], rax\n");

  // Go native.
  printf("  jmp fs:[__mcsema_reg_state@TPOFF + %lu]\n", __builtin_offsetof(mcsema::RegState, RIP));

  printf(".Lfunc_end5:\n");
  printf("  .size __mcsema_detach_call_value,.Lfunc_end5-__mcsema_detach_call_value\n");
  printf("  .cfi_endproc\n");
  printf("\n");

  // Implements `__mcsema_debug_get_reg_state`. This is useful when debugging in
  // gdb.
  printf("  .globl __mcsema_debug_get_reg_state\n");
  printf("  .type __mcsema_debug_get_reg_state,@function\n");
  printf("__mcsema_debug_get_reg_state:\n");
  printf("  .cfi_startproc\n");
  printf("  mov rax, fs:[0]\n");
  printf("  lea rax, [rax + __mcsema_reg_state@TPOFF]\n");
  printf("  ret\n");
  printf(".Lfunc_end6:\n");
  printf("  .size __mcsema_debug_get_reg_state,.Lfunc_end6-__mcsema_debug_get_reg_state\n");
  printf("  .cfi_endproc\n");
  printf("\n");
  return 0;
}


//  // Align the stack.
//  printf("  push rsp\n");
//  printf("  push QWORD PTR [rsp]\n");
//  printf("  and rsp, -16\n");

//  // Restore stack alignment
//  printf("  pop rsp\n");


