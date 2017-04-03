/* Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <cstdio>

#define ONLY_STRUCT
#include "State.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat"

static const unsigned kStackSize = 1UL << 20U;
static const unsigned kStackArgSize = 256U;

int main(void) {

  FILE *out = fopen("runtime_32.S", "w");

  fprintf(out, "/* Auto-generated file! Don't modify! */\n\n");
  fprintf(out, "  .file __FILE__\n");
  fprintf(out, "  .intel_syntax noprefix\n");
  fprintf(out, "\n");

  // Thread-local state structure, named by `__mcsema_reg_state`.
  fprintf(out, "  .type __mcsema_reg_state,@object\n");
  fprintf(out, "  .section .tbss,\"awT\",@nobits\n");
  fprintf(out, "__mcsema_reg_state:\n");
  fprintf(out, "  .zero %u\n", sizeof(RegState));
  fprintf(out, "  .size __mcsema_reg_state, 100\n");
  fprintf(out, "\n");

  // Thread-local stack structure, named by `__mcsema_stack`.
  fprintf(out, "  .type __mcsema_stack,@object\n");
  fprintf(out, "  .section .tbss,\"awT\",@nobits\n");
  fprintf(out, "__mcsema_stack:\n");
  fprintf(out, "  .zero %u\n", kStackSize);  // 1 MiB.
  fprintf(out, "  .size __mcsema_stack, 100\n");
  fprintf(out, "\n");

  // Thread-local stack structure, named by `__mcsema_stack_args`
  // used to store stack-passed function arguments
  fprintf(out, "  .type __mcsema_stack_args,@object\n");
  fprintf(out, "  .section .tbss,\"awT\",@nobits\n");
  fprintf(out, "__mcsema_stack_args:\n");
  fprintf(out, "  .zero %u\n", kStackArgSize);
  fprintf(out, "  .size __mcsema_stack_args, 100\n");
  fprintf(out, "\n");

  // Thread-local variable structure, named by `__mcsema_stack_mark`
  // used to store the expected stack location on return,
  // so caller cleanup conventions can know how many bytes to pop off
  fprintf(out, "  .type __mcsema_stack_mark,@object\n");
  fprintf(out, "  .section .tbss,\"awT\",@nobits\n");
  fprintf(out, "__mcsema_stack_mark:\n");
  fprintf(out, "  .zero %u\n", 4);
  fprintf(out, "  .size __mcsema_stack_mark, 100\n");
  fprintf(out, "\n");

  fprintf(out, "  .text\n");
  fprintf(out, "\n");

  // Forward declarations.
  fprintf(out, "  .globl __mcsema_detach_ret_cdecl\n");
  fprintf(out, "\n");

  ///////////////////////////////////////////////////////////////
  //
  //         __mcsema_attach_call_cdecl
  //
  ///////////////////////////////////////////////////////////////

  // Implements `__mcsema_attach_call_cdecl`. This goes from native state into lifted code.
  // The lifted code function pointer is already on the stack.
  fprintf(out, "  .globl __mcsema_attach_call_cdecl\n");
  fprintf(out, "  .type __mcsema_attach_call_cdecl,@function\n");
  fprintf(out, "__mcsema_attach_call_cdecl:\n");
  fprintf(out, "  .cfi_startproc\n");

  // Pop the target function into the `RegState` structure. This resets `ESP`
  // to what it should be on entry to `__mcsema_attach_call`.
  fprintf(out, "  pop DWORD PTR gs:[__mcsema_reg_state@NTPOFF + %u]\n", __builtin_offsetof(RegState, RIP));

  // General purpose registers.
  fprintf(out, "  mov gs:[__mcsema_reg_state@NTPOFF + %u], eax\n", __builtin_offsetof(RegState, RAX));
  fprintf(out, "  mov gs:[__mcsema_reg_state@NTPOFF + %u], ebx\n", __builtin_offsetof(RegState, RBX));
  fprintf(out, "  mov gs:[__mcsema_reg_state@NTPOFF + %u], ecx\n", __builtin_offsetof(RegState, RCX));
  fprintf(out, "  mov gs:[__mcsema_reg_state@NTPOFF + %u], edx\n", __builtin_offsetof(RegState, RDX));
  fprintf(out, "  mov gs:[__mcsema_reg_state@NTPOFF + %u], esi\n", __builtin_offsetof(RegState, RSI));
  fprintf(out, "  mov gs:[__mcsema_reg_state@NTPOFF + %u], edi\n", __builtin_offsetof(RegState, RDI));
  fprintf(out, "  mov gs:[__mcsema_reg_state@NTPOFF + %u], ebp\n", __builtin_offsetof(RegState, RBP));

  fprintf(out, "  xchg esp, DWORD PTR gs:[__mcsema_reg_state@NTPOFF + %u]\n", __builtin_offsetof(RegState, RSP));

  // XMM registers.
  fprintf(out, "  movdqu gs:[__mcsema_reg_state@NTPOFF + %u], xmm0\n", __builtin_offsetof(RegState, XMM0));
  fprintf(out, "  movdqu gs:[__mcsema_reg_state@NTPOFF + %u], xmm1\n", __builtin_offsetof(RegState, XMM1));
  fprintf(out, "  movdqu gs:[__mcsema_reg_state@NTPOFF + %u], xmm2\n", __builtin_offsetof(RegState, XMM2));
  fprintf(out, "  movdqu gs:[__mcsema_reg_state@NTPOFF + %u], xmm3\n", __builtin_offsetof(RegState, XMM3));
  fprintf(out, "  movdqu gs:[__mcsema_reg_state@NTPOFF + %u], xmm4\n", __builtin_offsetof(RegState, XMM4));
  fprintf(out, "  movdqu gs:[__mcsema_reg_state@NTPOFF + %u], xmm5\n", __builtin_offsetof(RegState, XMM5));
  fprintf(out, "  movdqu gs:[__mcsema_reg_state@NTPOFF + %u], xmm6\n", __builtin_offsetof(RegState, XMM6));
  fprintf(out, "  movdqu gs:[__mcsema_reg_state@NTPOFF + %u], xmm7\n", __builtin_offsetof(RegState, XMM7));

  // If `ESP` is null then we need to initialize it to our new stack.
  fprintf(out, "  cmp esp, 0\n");
  fprintf(out, "  jnz .Lhave_stack\n");
  fprintf(out, "  mov esp, DWORD PTR gs:[0]\n");
  fprintf(out, "  lea esp, [esp + __mcsema_stack@NTPOFF + %u]\n", kStackSize);
  fprintf(out, ".Lhave_stack:\n");

  // the state struture is the first and only arg to lifted functions
  fprintf(out, "  mov eax, DWORD PTR gs:[0]\n");
  fprintf(out, "  lea eax, [eax + __mcsema_reg_state@NTPOFF]\n");
  fprintf(out, "  push eax\n");

  // `esp` holds the address of the mcsema stack.
  //    1) Set up a return address on the mcsema stack.
  //    2) Tail-call to the lifted function.
  //
  // Note:  When the lifted function returns, it will go to `__mcsema_detach_ret_cdecl`,
  //        which will return to native code.
  //

  // do not push __mcsema_detach_ret_cdecl directly
  // to work around llvm assembler bug that emits it
  // as a 16-bit push
  fprintf(out, "  lea eax, __mcsema_detach_ret_cdecl\n");
  fprintf(out, "  push eax\n");
  fprintf(out, "  jmp DWORD PTR gs:[__mcsema_reg_state@NTPOFF + %u]\n", __builtin_offsetof(RegState, RIP));

  fprintf(out, ".Lfunc_end1:\n");
  fprintf(out, "  .size __mcsema_attach_call_cdecl,.Lfunc_end1-__mcsema_attach_call_cdecl\n");
  fprintf(out, "  .cfi_endproc\n");
  fprintf(out, "\n");


  ///////////////////////////////////////////////////////////////
  //
  //         __mcsema_attach_ret_cdecl
  //
  ///////////////////////////////////////////////////////////////


  // Implements `__mcsema_attach_ret_cdecl`. This goes from native state into lifted code.
  fprintf(out, "  .globl __mcsema_attach_ret_cdecl\n");
  fprintf(out, "  .type __mcsema_attach_ret_cdecl,@function\n");
  fprintf(out, "__mcsema_attach_ret_cdecl:\n");
  fprintf(out, "  .cfi_startproc\n");

  // this should be valid for cdecl:
  // return stack to where it was before we pasted
  // some arguments to it, so the caller can clean
  // up as expected
  //
  // add an extra 4 bytes to compensate for the fake return address
  fprintf(out, "  add esp, %u\n", kStackArgSize+4);
  // Swap into the mcsema stack.
  fprintf(out, "  xchg esp, DWORD PTR gs:[__mcsema_reg_state@NTPOFF + %u]\n", __builtin_offsetof(RegState, RSP));

  // Return registers.
  fprintf(out, "  mov gs:[__mcsema_reg_state@NTPOFF + %u], eax\n", __builtin_offsetof(RegState, RAX));
  fprintf(out, "  mov gs:[__mcsema_reg_state@NTPOFF + %u], edx\n", __builtin_offsetof(RegState, RDX));
  fprintf(out, "  movdqu gs:[__mcsema_reg_state@NTPOFF + %u], xmm0\n", __builtin_offsetof(RegState, XMM0));

  // Callee-saved registers.
  fprintf(out, "  mov gs:[__mcsema_reg_state@NTPOFF + %u], ebp\n", __builtin_offsetof(RegState, RBP));
  fprintf(out, "  mov gs:[__mcsema_reg_state@NTPOFF + %u], ebx\n", __builtin_offsetof(RegState, RBX));
  fprintf(out, "  mov gs:[__mcsema_reg_state@NTPOFF + %u], esi\n", __builtin_offsetof(RegState, RSI));
  fprintf(out, "  mov gs:[__mcsema_reg_state@NTPOFF + %u], edi\n", __builtin_offsetof(RegState, RDI));

  // Unstash the callee-saved registers.
  fprintf(out, "  pop ebp\n");
  fprintf(out, "  pop ebx\n");
  fprintf(out, "  pop esi\n");
  fprintf(out, "  pop edi\n");

  fprintf(out, "  ret\n");

  fprintf(out, ".Lfunc_end2:\n");
  fprintf(out, "  .size __mcsema_attach_ret_cdecl,.Lfunc_end2-__mcsema_attach_ret_cdecl\n");
  fprintf(out, "  .cfi_endproc\n");
  fprintf(out, "\n");

  ///////////////////////////////////////////////////////////////
  //
  //         __mcsema_attach_ret_value
  //
  ///////////////////////////////////////////////////////////////

  // Implements `__mcsema_attach_ret_value`. This is the "opposite" of
  // `__mcsema_detach_call_value`.
  fprintf(out, "  .globl __mcsema_attach_ret_value\n");
  fprintf(out, "  .type __mcsema_attach_ret_value,@function\n");
  fprintf(out, "__mcsema_attach_ret_value:\n");
  fprintf(out, "  .cfi_startproc\n");

  // General purpose registers.
  fprintf(out, "  mov gs:[__mcsema_reg_state@NTPOFF + %u], eax\n", __builtin_offsetof(RegState, RAX));
  fprintf(out, "  mov gs:[__mcsema_reg_state@NTPOFF + %u], ebx\n", __builtin_offsetof(RegState, RBX));
  fprintf(out, "  mov gs:[__mcsema_reg_state@NTPOFF + %u], ecx\n", __builtin_offsetof(RegState, RCX));
  fprintf(out, "  mov gs:[__mcsema_reg_state@NTPOFF + %u], edx\n", __builtin_offsetof(RegState, RDX));
  fprintf(out, "  mov gs:[__mcsema_reg_state@NTPOFF + %u], esi\n", __builtin_offsetof(RegState, RSI));
  fprintf(out, "  mov gs:[__mcsema_reg_state@NTPOFF + %u], edi\n", __builtin_offsetof(RegState, RDI));
  fprintf(out, "  mov gs:[__mcsema_reg_state@NTPOFF + %u], ebp\n", __builtin_offsetof(RegState, RBP));

  // if this function had no args, this will be zero, otherwise
  // it will be -argcount*4 (esp is now > old esp, due to pops)
  fprintf(out, "  sub DWORD PTR gs:[__mcsema_stack_mark@NTPOFF], esp\n");
  fprintf(out, "  mov ecx, DWORD PTR gs:[__mcsema_stack_mark@NTPOFF]\n");
  // adjust for our copied stack args + fake return
  fprintf(out, "  add esp, %u\n", kStackArgSize+4);

  fprintf(out, "  xchg esp, DWORD PTR gs:[__mcsema_reg_state@NTPOFF + %u]\n", __builtin_offsetof(RegState, RSP));

  // XMM registers.
  fprintf(out, "  movdqu gs:[__mcsema_reg_state@NTPOFF + %u], xmm0\n", __builtin_offsetof(RegState, XMM0));
  fprintf(out, "  movdqu gs:[__mcsema_reg_state@NTPOFF + %u], xmm1\n", __builtin_offsetof(RegState, XMM1));
  fprintf(out, "  movdqu gs:[__mcsema_reg_state@NTPOFF + %u], xmm2\n", __builtin_offsetof(RegState, XMM2));
  fprintf(out, "  movdqu gs:[__mcsema_reg_state@NTPOFF + %u], xmm3\n", __builtin_offsetof(RegState, XMM3));
  fprintf(out, "  movdqu gs:[__mcsema_reg_state@NTPOFF + %u], xmm4\n", __builtin_offsetof(RegState, XMM4));
  fprintf(out, "  movdqu gs:[__mcsema_reg_state@NTPOFF + %u], xmm5\n", __builtin_offsetof(RegState, XMM5));
  fprintf(out, "  movdqu gs:[__mcsema_reg_state@NTPOFF + %u], xmm6\n", __builtin_offsetof(RegState, XMM6));
  fprintf(out, "  movdqu gs:[__mcsema_reg_state@NTPOFF + %u], xmm7\n", __builtin_offsetof(RegState, XMM7));

  // Unstash the callee-saved registers.
  fprintf(out, "  pop ebp\n");
  fprintf(out, "  pop ebx\n");
  fprintf(out, "  pop esi\n");
  fprintf(out, "  pop edi\n");

  // adjust again for the popped off arguments
  // this emulates a "retn XX", but that
  // only takes an immediate value
  fprintf(out, "  sub esp, ecx\n"); // this sub is an add since ecx is negative
  fprintf(out, "  add esp, 4\n"); // adjust for return address on stack

  // we still need to transfer control to the return addr on stack
  fprintf(out, "  lea ecx, [esp+ecx]\n");
  fprintf(out, "  jmp dword ptr [ecx-4]\n");

  fprintf(out, ".Lfunc_end0:\n");
  fprintf(out, "  .size __mcsema_attach_ret_value,.Lfunc_end0-__mcsema_attach_ret_value\n");
  fprintf(out, "  .cfi_endproc\n");
  fprintf(out, "\n");

  ///////////////////////////////////////////////////////////////
  //
  //         __mcsema_dettach_ret_cdecl
  //
  ///////////////////////////////////////////////////////////////

  // Implements `__mcsema_detach_ret_cdecl`. This goes from lifted code into native code.
  // The native code pointer is located at the native `[RegState::ESP - 4]`
  // address.
  fprintf(out, "  .globl __mcsema_detach_ret_cdecl\n");
  fprintf(out, "  .type __mcsema_detach_ret_cdecl,@function\n");
  fprintf(out, "__mcsema_detach_ret_cdecl:\n");
  fprintf(out, "  .cfi_startproc\n");

  // General purpose registers.
  fprintf(out, "  mov eax, gs:[__mcsema_reg_state@NTPOFF + %u]\n", __builtin_offsetof(RegState, RAX));
  fprintf(out, "  mov ebx, gs:[__mcsema_reg_state@NTPOFF + %u]\n", __builtin_offsetof(RegState, RBX));
  fprintf(out, "  mov ecx, gs:[__mcsema_reg_state@NTPOFF + %u]\n", __builtin_offsetof(RegState, RCX));
  fprintf(out, "  mov edx, gs:[__mcsema_reg_state@NTPOFF + %u]\n", __builtin_offsetof(RegState, RDX));
  fprintf(out, "  mov esi, gs:[__mcsema_reg_state@NTPOFF + %u]\n", __builtin_offsetof(RegState, RSI));
  fprintf(out, "  mov edi, gs:[__mcsema_reg_state@NTPOFF + %u]\n", __builtin_offsetof(RegState, RDI));
  fprintf(out, "  mov ebp, gs:[__mcsema_reg_state@NTPOFF + %u]\n", __builtin_offsetof(RegState, RBP));
  fprintf(out, "  xchg esp, DWORD PTR gs:[__mcsema_reg_state@NTPOFF + %u]\n", __builtin_offsetof(RegState, RSP));

  // XMM registers.
  fprintf(out, "  movdqu xmm0, gs:[__mcsema_reg_state@NTPOFF + %u]\n", __builtin_offsetof(RegState, XMM0));
  fprintf(out, "  movdqu xmm1, gs:[__mcsema_reg_state@NTPOFF + %u]\n", __builtin_offsetof(RegState, XMM1));
  fprintf(out, "  movdqu xmm2, gs:[__mcsema_reg_state@NTPOFF + %u]\n", __builtin_offsetof(RegState, XMM2));
  fprintf(out, "  movdqu xmm3, gs:[__mcsema_reg_state@NTPOFF + %u]\n", __builtin_offsetof(RegState, XMM3));
  fprintf(out, "  movdqu xmm4, gs:[__mcsema_reg_state@NTPOFF + %u]\n", __builtin_offsetof(RegState, XMM4));
  fprintf(out, "  movdqu xmm5, gs:[__mcsema_reg_state@NTPOFF + %u]\n", __builtin_offsetof(RegState, XMM5));
  fprintf(out, "  movdqu xmm6, gs:[__mcsema_reg_state@NTPOFF + %u]\n", __builtin_offsetof(RegState, XMM6));
  fprintf(out, "  movdqu xmm7, gs:[__mcsema_reg_state@NTPOFF + %u]\n", __builtin_offsetof(RegState, XMM7));

  // We assume the lifted code was generated by a sane complier and ended in a RET
  // which will write a return address into RegState::XIP and then pop off the stack,
  // if its callee cleanup.
  // We will jump to RegState::XIP since it shoudl be the 'real' return address we have to get to
  fprintf(out, "  jmp DWORD PTR gs:[__mcsema_reg_state@NTPOFF + %u]\n", __builtin_offsetof(RegState, RIP));

  fprintf(out, ".Lfunc_end3:\n");
  fprintf(out, "  .size __mcsema_detach_ret_cdecl,.Lfunc_end3-__mcsema_detach_ret_cdecl\n");
  fprintf(out, "  .cfi_endproc\n");
  fprintf(out, "\n");

  ///////////////////////////////////////////////////////////////
  //
  //         __mcsema_detach_call_cdecl
  //
  ///////////////////////////////////////////////////////////////

  // Implements `__mcsema_detach_call_cdecl`. This partially goes from lifted code
  // into native code.
  fprintf(out, "  .globl __mcsema_detach_call_cdecl\n");
  fprintf(out, "  .type __mcsema_detach_call_cdecl,@function\n");
  fprintf(out, "__mcsema_detach_call_cdecl:\n");
  fprintf(out, "  .cfi_startproc\n");

  // Pop the target function into the `RegState` structure. This resets `EIP`
  // to what it should be on entry to `__mcsema_detach_call_cdecl`.
  fprintf(out, "  pop DWORD PTR gs:[__mcsema_reg_state@NTPOFF + %u]\n", __builtin_offsetof(RegState, RIP));
  // Marshal the callee-saved registers (of the emulated code) into the native
  // state. We don't touch the argument registers.

  // Stash the callee-saved registers.
  fprintf(out, "  push edi\n");
  fprintf(out, "  push esi\n");
  fprintf(out, "  push ebx\n");
  fprintf(out, "  push ebp\n");
  // assume we can clobber eax and ecx

  // copy possible stack args into temporary holding area
  fprintf(out, "  mov eax, gs:[0]\n");
  fprintf(out, "  lea edi, [eax + __mcsema_stack_args@NTPOFF]\n");
  fprintf(out, "  lea esi, [esp + %u]\n", 4 + 4+4+4+4);
  fprintf(out, "  mov ecx, %u\n", kStackArgSize);
  fprintf(out, "  rep movsb\n");

  fprintf(out, "  mov esi, gs:[__mcsema_reg_state@NTPOFF + %u]\n", __builtin_offsetof(RegState, RSI));
  fprintf(out, "  mov edi, gs:[__mcsema_reg_state@NTPOFF + %u]\n", __builtin_offsetof(RegState, RDI));
  fprintf(out, "  mov ebx, gs:[__mcsema_reg_state@NTPOFF + %u]\n", __builtin_offsetof(RegState, RBX));
  fprintf(out, "  mov ebp, gs:[__mcsema_reg_state@NTPOFF + %u]\n", __builtin_offsetof(RegState, RBP));

  // Swap onto the native stack.
  fprintf(out, "  xchg DWORD PTR gs:[__mcsema_reg_state@NTPOFF + %u], esp\n", __builtin_offsetof(RegState, RSP));

  // copy possible stack args from holding area to native stack
  // allocate space for our arguments on stack
  fprintf(out, "  sub esp, %u\n", kStackArgSize);
  // we need to save these 
  fprintf(out, "  push esi\n");
  fprintf(out, "  push edi\n");
  fprintf(out, "  push ecx\n");
  // get the stack arg location
  fprintf(out, "  lea edi, [esp + %u]\n", 4+4+4);
  // source is temp area
  fprintf(out, "  mov eax, DWORD PTR gs:[0]\n");
  fprintf(out, "  lea esi, [eax + __mcsema_stack_args@NTPOFF]\n");
  fprintf(out, "  mov ecx, %u\n", kStackArgSize);
  // copy
  fprintf(out, "  rep movsb\n");

  // restore saved regs
  fprintf(out, "  pop ecx\n");
  fprintf(out, "  pop edi\n");
  fprintf(out, "  pop esi\n");

  // Set up a re-attach return address.
  // do not push __mcsema_attach_ret_cdecl directly
  // to work around llvm assembler bug that emits it
  // as a 16-bit push
  fprintf(out, "  lea eax, __mcsema_attach_ret_cdecl\n");
  fprintf(out, "  push eax\n");

  fprintf(out, "  jmp DWORD PTR gs:[__mcsema_reg_state@NTPOFF + %u]\n", __builtin_offsetof(RegState, RIP));

  fprintf(out, ".Lfunc_end4:\n");
  fprintf(out, "  .size __mcsema_detach_call_cdecl,.Lfunc_end4-__mcsema_detach_call_cdecl\n");
  fprintf(out, "  .cfi_endproc\n");
  fprintf(out, "\n");

  ///////////////////////////////////////////////////////////////
  //
  //         __mcsema_detach_call_value
  //
  ///////////////////////////////////////////////////////////////

  // Implements `__mcsema_detach_call_value`. This is a thin wrapper around
  // `__mcsema_detach_call`.
  fprintf(out, "  .globl __mcsema_detach_call_value\n");
  fprintf(out, "  .type __mcsema_detach_call_value,@function\n");
  fprintf(out, "__mcsema_detach_call_value:\n");
  fprintf(out, "  .cfi_startproc\n");

  // Note: the bitcode has already put the target address into `RegState::EIP`.

  // Stash the callee-saved registers.
  fprintf(out, "  push edi\n");
  fprintf(out, "  push esi\n");
  fprintf(out, "  push ebx\n");
  fprintf(out, "  push ebp\n");

  // save current stack mark
  fprintf(out, "  push DWORD PTR gs:[__mcsema_stack_mark@NTPOFF]\n");

  // copy possible stack args into temporary holding area
  fprintf(out, "  mov eax, DWORD PTR gs:[0]\n");
  fprintf(out, "  lea edi, [eax + __mcsema_stack_args@NTPOFF]\n");
  // this is not ESP since for do_call_value there is no spilling via an 
  // intermediate function
  fprintf(out, "  mov esi, DWORD PTR gs:[__mcsema_reg_state@NTPOFF + %u]\n", __builtin_offsetof(RegState, RSP));
  fprintf(out, "  mov ecx, %u\n", kStackArgSize);
  fprintf(out, "  rep movsb\n");

  // General purpose registers.
  fprintf(out, "  mov eax, gs:[__mcsema_reg_state@NTPOFF + %u]\n", __builtin_offsetof(RegState, RAX));
  fprintf(out, "  mov ebx, gs:[__mcsema_reg_state@NTPOFF + %u]\n", __builtin_offsetof(RegState, RBX));
  fprintf(out, "  mov ecx, gs:[__mcsema_reg_state@NTPOFF + %u]\n", __builtin_offsetof(RegState, RCX));
  fprintf(out, "  mov edx, gs:[__mcsema_reg_state@NTPOFF + %u]\n", __builtin_offsetof(RegState, RDX));
  fprintf(out, "  mov esi, gs:[__mcsema_reg_state@NTPOFF + %u]\n", __builtin_offsetof(RegState, RSI));
  fprintf(out, "  mov edi, gs:[__mcsema_reg_state@NTPOFF + %u]\n", __builtin_offsetof(RegState, RDI));
  fprintf(out, "  mov ebp, gs:[__mcsema_reg_state@NTPOFF + %u]\n", __builtin_offsetof(RegState, RBP));
  fprintf(out, "  xchg DWORD PTR gs:[__mcsema_reg_state@NTPOFF + %u], esp\n", __builtin_offsetof(RegState, RSP));

  // XMM registers.
  fprintf(out, "  movdqu xmm0, gs:[__mcsema_reg_state@NTPOFF + %u]\n", __builtin_offsetof(RegState, XMM0));
  fprintf(out, "  movdqu xmm1, gs:[__mcsema_reg_state@NTPOFF + %u]\n", __builtin_offsetof(RegState, XMM1));
  fprintf(out, "  movdqu xmm2, gs:[__mcsema_reg_state@NTPOFF + %u]\n", __builtin_offsetof(RegState, XMM2));
  fprintf(out, "  movdqu xmm3, gs:[__mcsema_reg_state@NTPOFF + %u]\n", __builtin_offsetof(RegState, XMM3));
  fprintf(out, "  movdqu xmm4, gs:[__mcsema_reg_state@NTPOFF + %u]\n", __builtin_offsetof(RegState, XMM4));
  fprintf(out, "  movdqu xmm5, gs:[__mcsema_reg_state@NTPOFF + %u]\n", __builtin_offsetof(RegState, XMM5));
  fprintf(out, "  movdqu xmm6, gs:[__mcsema_reg_state@NTPOFF + %u]\n", __builtin_offsetof(RegState, XMM6));
  fprintf(out, "  movdqu xmm7, gs:[__mcsema_reg_state@NTPOFF + %u]\n", __builtin_offsetof(RegState, XMM7));

  // copy possible stack args from holding area to native stack
  // allocate space for our arguments on stack
  fprintf(out, "  sub esp, %u\n", kStackArgSize);
  // we need to save these 
  fprintf(out, "  push esi\n");
  fprintf(out, "  push edi\n");
  fprintf(out, "  push ecx\n");
  // get the stack arg location
  fprintf(out, "  lea edi, [esp + %u]\n", 4+4+4);
  // source is temp area
  fprintf(out, "  mov eax, DWORD PTR gs:[0]\n");
  fprintf(out, "  lea esi, [eax + __mcsema_stack_args@NTPOFF]\n");
  fprintf(out, "  mov ecx, %u\n", kStackArgSize);
  // copy
  fprintf(out, "  rep movsb\n");

  // restore saved regs
  fprintf(out, "  pop ecx\n");
  fprintf(out, "  pop edi\n");
  fprintf(out, "  pop esi\n");

  // save current ESP so we know how many bytes
  // the callee popped off the stack on return
  fprintf(out, "  mov DWORD PTR gs:[__mcsema_stack_mark@NTPOFF], esp\n");

  // Set up a re-attach return address.
  // Set up a re-attach return address.
  // do not push __mcsema_attach_ret_value directly
  // to work around llvm assembler bug that emits it
  // as a 16-bit push
  fprintf(out, "  lea eax, __mcsema_attach_ret_value\n");
  fprintf(out, "  push eax\n");

  // Go native.
  fprintf(out, "  jmp DWORD PTR gs:[__mcsema_reg_state@NTPOFF + %u]\n", __builtin_offsetof(RegState, RIP));

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
  fprintf(out, "  mov eax, DWORD PTR gs:[0]\n");
  fprintf(out, "  lea eax, [eax + __mcsema_reg_state@NTPOFF]\n");
  fprintf(out, "  ret\n");
  fprintf(out, ".Lfunc_end6:\n");
  fprintf(out, "  .size __mcsema_debug_get_reg_state,.Lfunc_end6-__mcsema_debug_get_reg_state\n");
  fprintf(out, "  .cfi_endproc\n");
  fprintf(out, "\n");

  ///////////////////////////////////////////////////////////////
  //
  //         __mcsema_detach_call_stdcall
  //
  ///////////////////////////////////////////////////////////////

  // Implements `__mcsema_detach_call_stdcall`. This partially goes from lifted code
  // into native code.
  fprintf(out, "  .globl __mcsema_detach_call_stdcall\n");
  fprintf(out, "  .type __mcsema_detach_call_stdcall,@function\n");
  fprintf(out, "__mcsema_detach_call_stdcall:\n");
  fprintf(out, "  .cfi_startproc\n");

  // Pop the target function into the `RegState` structure. This resets `EIP`
  // to what it should be on entry to `__mcsema_detach_call_stdcall`.
  fprintf(out, "  pop DWORD PTR gs:[__mcsema_reg_state@NTPOFF + %u]\n", __builtin_offsetof(RegState, RIP));
  // Marshal the callee-saved registers (of the emulated code) into the native
  // state. We don't touch the argument registers.

  // Stash the callee-saved registers.
  fprintf(out, "  push edi\n");
  fprintf(out, "  push esi\n");
  fprintf(out, "  push ebx\n");
  fprintf(out, "  push ebp\n");

  // save current stack mark
  fprintf(out, "  push DWORD PTR gs:[__mcsema_stack_mark@NTPOFF]\n");

  // do not clobber fastcall args
  fprintf(out, "  push ecx\n");
  fprintf(out, "  push edx\n");


  // copy possible stack args into temporary holding area
  fprintf(out, "  mov eax, gs:[0]\n");
  fprintf(out, "  lea edi, [eax + __mcsema_stack_args@NTPOFF]\n");
  //  ra + stack_mark + (ecx + edx) +  (edi+esi+ebx+ebp)
  fprintf(out, "  lea esi, [esp + %u]\n", 4 + 4 + 4+4 + 4+4+4+4);
  fprintf(out, "  mov ecx, %u\n", kStackArgSize);
  fprintf(out, "  rep movsb\n");

  // do not clobber fastcall args
  fprintf(out, "  pop edx\n");
  fprintf(out, "  pop ecx\n");

  fprintf(out, "  mov edi, gs:[__mcsema_reg_state@NTPOFF + %u]\n", __builtin_offsetof(RegState, RDI));
  fprintf(out, "  mov esi, gs:[__mcsema_reg_state@NTPOFF + %u]\n", __builtin_offsetof(RegState, RSI));
  fprintf(out, "  mov ebx, gs:[__mcsema_reg_state@NTPOFF + %u]\n", __builtin_offsetof(RegState, RBX));
  fprintf(out, "  mov ebp, gs:[__mcsema_reg_state@NTPOFF + %u]\n", __builtin_offsetof(RegState, RBP));

  // Swap onto the native stack.
  fprintf(out, "  xchg DWORD PTR gs:[__mcsema_reg_state@NTPOFF + %u], esp\n", __builtin_offsetof(RegState, RSP));

  // copy possible stack args from holding area to native stack
  // allocate space for our arguments on stack
  fprintf(out, "  sub esp, %u\n", kStackArgSize);
  // we need to save these 
  fprintf(out, "  push esi\n");
  fprintf(out, "  push edi\n");
  fprintf(out, "  push ecx\n");
  // get the stack arg location
  fprintf(out, "  lea edi, [esp + %u]\n", 4+4+4);
  // source is temp area
  fprintf(out, "  mov eax, DWORD PTR gs:[0]\n");
  fprintf(out, "  lea esi, [eax + __mcsema_stack_args@NTPOFF]\n");
  fprintf(out, "  mov ecx, %u\n", kStackArgSize);
  // copy
  fprintf(out, "  rep movsb\n");

  // restore saved regs
  fprintf(out, "  pop ecx\n");
  fprintf(out, "  pop edi\n");
  fprintf(out, "  pop esi\n");

  // save current ESP so we know how many bytes
  // the callee popped off the stack on return
  fprintf(out, "  mov DWORD PTR gs:[__mcsema_stack_mark@NTPOFF], esp\n");

  // Set up a re-attach return address.
  // do not push __mcsema_attach_ret_stdcall directly
  // to work around llvm assembler bug that emits it
  // as a 16-bit push
  fprintf(out, "  lea eax, __mcsema_attach_ret_stdcall\n");
  fprintf(out, "  push eax\n");

  fprintf(out, "  jmp DWORD PTR gs:[__mcsema_reg_state@NTPOFF + %u]\n", __builtin_offsetof(RegState, RIP));

  fprintf(out, ".Lfunc_endA:\n");
  fprintf(out, "  .size __mcsema_detach_call_stdcall,.Lfunc_endA-__mcsema_detach_call_stdcall\n");
  fprintf(out, "  .cfi_endproc\n");
  fprintf(out, "\n");

  ///////////////////////////////////////////////////////////////
  //
  //         __mcsema_attach_ret_stdcall
  //
  ///////////////////////////////////////////////////////////////


  // Implements `__mcsema_attach_ret_stdcall`. This goes from native state into lifted code.
  fprintf(out, "  .globl __mcsema_attach_ret_stdcall\n");
  fprintf(out, "  .type __mcsema_attach_ret_stdcall,@function\n");
  fprintf(out, "__mcsema_attach_ret_stdcall:\n");
  fprintf(out, "  .cfi_startproc\n");

  // this should be valid for stdcall:
  // return stack to where it was before we pasted
  // some arguments to it, so the caller can clean
  // up as expected
  //
  // add an extra 4 bytes to compensate for the fake return address
  //
  // save current ESP so we know how many bytes
  // the callee popped off the stack on return
  //
  
  // if this function had no args, this will be zero, otherwise
  // it will be -argcount*4 (esp is now > old esp, due to pops)
  fprintf(out, "  sub DWORD PTR gs:[__mcsema_stack_mark@NTPOFF], esp\n");
  fprintf(out, "  mov ecx, DWORD PTR gs:[__mcsema_stack_mark@NTPOFF]\n");
  // adjust for our copied stack args + fake return
  fprintf(out, "  add esp, %u\n", kStackArgSize+4);
  // Swap into the mcsema stack.
  fprintf(out, "  xchg esp, DWORD PTR gs:[__mcsema_reg_state@NTPOFF + %u]\n", __builtin_offsetof(RegState, RSP));

  // Return registers.
  fprintf(out, "  mov gs:[__mcsema_reg_state@NTPOFF + %u], eax\n", __builtin_offsetof(RegState, RAX));
  fprintf(out, "  mov gs:[__mcsema_reg_state@NTPOFF + %u], edx\n", __builtin_offsetof(RegState, RDX));
  fprintf(out, "  movdqu gs:[__mcsema_reg_state@NTPOFF + %u], xmm0\n", __builtin_offsetof(RegState, XMM0));

  // Callee-saved registers.
  fprintf(out, "  mov gs:[__mcsema_reg_state@NTPOFF + %u], ebp\n", __builtin_offsetof(RegState, RBP));
  fprintf(out, "  mov gs:[__mcsema_reg_state@NTPOFF + %u], ebx\n", __builtin_offsetof(RegState, RBX));
  fprintf(out, "  mov gs:[__mcsema_reg_state@NTPOFF + %u], esi\n", __builtin_offsetof(RegState, RSI));
  fprintf(out, "  mov gs:[__mcsema_reg_state@NTPOFF + %u], edi\n", __builtin_offsetof(RegState, RDI));

  // Unstash the callee-saved registers.
  // restore old stack mark
  fprintf(out, "  pop DWORD PTR gs:[__mcsema_stack_mark@NTPOFF]\n");

  fprintf(out, "  pop ebp\n");
  fprintf(out, "  pop ebx\n");
  fprintf(out, "  pop esi\n");
  fprintf(out, "  pop edi\n");

  // adjust again for the popped off arguments
  // this emulates a "retn XX", but that
  // only takes an immediate value
  fprintf(out, "  sub esp, ecx\n"); // this sub is an add since ecx is negative
  fprintf(out, "  add esp, 4\n"); // adjust for return address on stack

  // we still need to transfer control to the return addr on stack
  fprintf(out, "  lea ecx, [esp+ecx]\n");
  fprintf(out, "  jmp dword ptr [ecx-4]\n");

  fprintf(out, ".Lfunc_end7:\n");
  fprintf(out, "  .size __mcsema_attach_ret_stdcall,.Lfunc_end7-__mcsema_attach_ret_stdcall\n");
  fprintf(out, "  .cfi_endproc\n");
  fprintf(out, "\n");

  ///////////////////////////////////////////////////////////////
  //
  //         __mcsema_detach_call_fastcall
  //
  ///////////////////////////////////////////////////////////////

  // Implements `__mcsema_detach_call_fastcall`. This partially goes from lifted code
  // into native code.
  fprintf(out, "  .globl __mcsema_detach_call_fastcall\n");
  fprintf(out, "  .type __mcsema_detach_call_fastcall,@function\n");
  fprintf(out, "__mcsema_detach_call_fastcall:\n");
  fprintf(out, "  .cfi_startproc\n");

  // stdcall takes care to save the fastcall regs, so these effectively become identical
  fprintf(out, "  lea eax, __mcsema_detach_call_stdcall\n");
  fprintf(out, "  jmp eax\n");

  fprintf(out, ".Lfunc_end8:\n");
  fprintf(out, "  .size __mcsema_detach_call_fastcall,.Lfunc_end8-__mcsema_detach_call_fastcall\n");
  fprintf(out, "  .cfi_endproc\n");
  fprintf(out, "\n");

  ///////////////////////////////////////////////////////////////
  //
  //         __mcsema_attach_ret_fastcall
  //
  ///////////////////////////////////////////////////////////////


  // Implements `__mcsema_attach_ret_fastcall`. This goes from native state into lifted code.
  //
  // ******************
  // this may never get used if we keep using __mcsema_detach_call_stdcall for fastcall
  // ******************
  fprintf(out, "  .globl __mcsema_attach_ret_fastcall\n");
  fprintf(out, "  .type __mcsema_attach_ret_fastcall,@function\n");
  fprintf(out, "__mcsema_attach_ret_fastcall:\n");
  fprintf(out, "  .cfi_startproc\n");

  // awkwardly push/ret to __mcsema_attach_ret_stdcall
  // since it should be compatible with fastcall
  fprintf(out, "  push eax\n");
  fprintf(out, "  lea eax, __mcsema_attach_ret_stdcall\n");
  fprintf(out, "  xchg eax, DWORD PTR [esp]\n");
  fprintf(out, "  ret\n");

  fprintf(out, ".Lfunc_end9:\n");
  fprintf(out, "  .size __mcsema_attach_ret_fastcall,.Lfunc_end9-__mcsema_attach_ret_fastcall\n");
  fprintf(out, "  .cfi_endproc\n");
  fprintf(out, "\n");

  return 0;
}

#pragma clang diagnostic pop
