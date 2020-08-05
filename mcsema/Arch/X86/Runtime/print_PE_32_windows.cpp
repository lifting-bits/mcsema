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
#define ADDRESS_SIZE_BITS 32

#include "mcsema/Arch/X86/Runtime/Registers.h"
#include "remill/Arch/X86/Runtime/State.h"

static const unsigned kStackSize = 1UL << 20U;
static const unsigned kStackArgSize = 256U;

void getTlsIndex(FILE *out, const char dest_reg[]) {
  fprintf(out, "push edx\n");
  fprintf(out, "mov %s, dword ptr [__tls_index]\n", dest_reg);
  fprintf(out, "mov edx, dword ptr fs:[44]\n");
  fprintf(out, "mov %s, dword ptr [edx + 4*%s]\n", dest_reg, dest_reg);
  fprintf(out, "pop edx\n");
}

int main(void) {

  FILE *out = fopen("runtime_32.asm", "w");

  fprintf(out, "/* Auto-generated file! Don't modify! */\n\n");
  fprintf(out, "  .intel_syntax noprefix\n");
  fprintf(out, "\n");

  fprintf(out, "  .section        .tls$,\"wd\"\n");

  // Thread-local state structure, named by `__mcsema_reg_state`.
  fprintf(out, "     .globl  __mcsema_reg_state\n");
  fprintf(out, "__mcsema_reg_state:\n");
  fprintf(out, "     .align  4\n");
  fprintf(out, "     .zero   %u\n", sizeof(State));
  fprintf(out, "\n");

  // Thread-local stack structure, named by `__mcsema_stack`.
  fprintf(out, "     .globl  __mcsema_stack\n");
  fprintf(out, "__mcsema_stack:\n");
  fprintf(out, "     .align  16\n");
  fprintf(out, "     .zero   %u\n", kStackSize);  // MiB
  fprintf(out, "\n");

  // Thread-local stack structure, named by `__mcsema_stack_args`
  // used to store stack-passed function arguments
  fprintf(out, "     .globl  __mcsema_stack_args\n");
  fprintf(out, "__mcsema_stack_args:\n");
  fprintf(out, "     .align  16\n");
  fprintf(out, "     .zero   %u\n", kStackArgSize);
  fprintf(out, "\n");

  // Thread-local variable structure, named by `__mcsema_stack_mark`
  // used to store the expected stack location on return,
  // so caller cleanup conventions can know how many bytes to pop off
  fprintf(out, "     .globl  __mcsema_stack_mark\n");
  fprintf(out, "__mcsema_stack_mark:\n");
  fprintf(out, "     .align  4\n");
  fprintf(out, "     .zero   %u\n", 4);
  fprintf(out, "\n");

  fprintf(out, "  .text\n");
  fprintf(out, "\n");

  // Forward declarations.
  fprintf(out, "  .globl __mcsema_detach_ret_cdecl\n");
  fprintf(out, "\n");

  ///////////////////////////////////////////////////////////////
  //
  //         __mcsema_attach_call
  //
  ///////////////////////////////////////////////////////////////

  // Implements `__mcsema_attach_call`. This goes from native state into lifted code.
  // The lifted code function pointer is already on the stack.
  fprintf(out, "  .globl __mcsema_attach_call\n");
  fprintf(out, "__mcsema_attach_call:\n");
  fprintf(out, "  .cfi_startproc\n");

  //*** assume we can clobber eax

  // save reg for use with TLS offsets
  fprintf(
      out,
      "  push dword ptr [esp]\n");  // dupliate last stack element (the jump-to EIP), so we can pop it
  fprintf(out,
          "  mov dword ptr [esp+4], ebp\n");  // save ebp, we will clobber it
  getTlsIndex(out, "ebp");

  // Pop the target function into the `State` structure. This resets `ESP`
  // to what it should be on entry to `__mcsema_attach_call`.
  fprintf(out, "  pop DWORD PTR [ebp + __mcsema_reg_state@SECREL32 + %u]\n",
          __builtin_offsetof(State, EIP));

  // General purpose registers.
  fprintf(out, "  mov [ebp + __mcsema_reg_state@SECREL32 + %u], eax\n",
          __builtin_offsetof(State, EAX));
  fprintf(out, "  mov [ebp + __mcsema_reg_state@SECREL32 + %u], ebx\n",
          __builtin_offsetof(State, EBX));
  fprintf(out, "  mov [ebp + __mcsema_reg_state@SECREL32 + %u], ecx\n",
          __builtin_offsetof(State, ECX));
  fprintf(out, "  mov [ebp + __mcsema_reg_state@SECREL32 + %u], edx\n",
          __builtin_offsetof(State, EDX));
  fprintf(out, "  mov [ebp + __mcsema_reg_state@SECREL32 + %u], esi\n",
          __builtin_offsetof(State, ESI));
  fprintf(out, "  mov [ebp + __mcsema_reg_state@SECREL32 + %u], edi\n",
          __builtin_offsetof(State, EDI));

  fprintf(out, "  pop ebp\n");

  getTlsIndex(out, "eax");
  fprintf(out, "  mov [eax + __mcsema_reg_state@SECREL32 + %u], ebp\n",
          __builtin_offsetof(State, EBP));

  // XMM registers.
  fprintf(out, "  movdqu [eax + __mcsema_reg_state@SECREL32 + %u], xmm0\n",
          __builtin_offsetof(State, XMM0));
  fprintf(out, "  movdqu [eax + __mcsema_reg_state@SECREL32 + %u], xmm1\n",
          __builtin_offsetof(State, XMM1));
  fprintf(out, "  movdqu [eax + __mcsema_reg_state@SECREL32 + %u], xmm2\n",
          __builtin_offsetof(State, XMM2));
  fprintf(out, "  movdqu [eax + __mcsema_reg_state@SECREL32 + %u], xmm3\n",
          __builtin_offsetof(State, XMM3));
  fprintf(out, "  movdqu [eax + __mcsema_reg_state@SECREL32 + %u], xmm4\n",
          __builtin_offsetof(State, XMM4));
  fprintf(out, "  movdqu [eax + __mcsema_reg_state@SECREL32 + %u], xmm5\n",
          __builtin_offsetof(State, XMM5));
  fprintf(out, "  movdqu [eax + __mcsema_reg_state@SECREL32 + %u], xmm6\n",
          __builtin_offsetof(State, XMM6));
  fprintf(out, "  movdqu [eax + __mcsema_reg_state@SECREL32 + %u], xmm7\n",
          __builtin_offsetof(State, XMM7));

  fprintf(out, "  xchg esp, [eax + __mcsema_reg_state@SECREL32 + %u]\n",
          __builtin_offsetof(State, ESP));

  // If `ESP` is null then we need to initialize it to our new stack.
  fprintf(out, "  cmp esp, 0\n");
  fprintf(out, "  jnz .Lhave_stack\n");

  // end inline getTlsIndex
  fprintf(out, "  lea esp, [eax + __mcsema_stack@SECREL32 + %u]\n", kStackSize);
  fprintf(out, ".Lhave_stack:\n");

  // the state struture is the first and only arg to lifted functions
  fprintf(out, "  push eax\n");
  fprintf(out, "  lea eax, [eax + __mcsema_reg_state@SECREL32]\n");
  fprintf(out, "  xchg eax, [esp]\n");

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
  fprintf(out, "  push eax\n");
  fprintf(out, "  lea eax, __mcsema_detach_ret_cdecl\n");
  fprintf(out, "  xchg eax, [esp]\n");

  // get EIP we need to jump to, in the process, clobber TLS index
  fprintf(out,
          "  mov eax, DWORD PTR [eax + __mcsema_reg_state@SECREL32 + %u]\n",
          __builtin_offsetof(State, EIP));

  // and away we go!
  fprintf(out, "  jmp eax\n");

  fprintf(out, ".Lfunc_end1:\n");
  fprintf(out, "  .cfi_endproc\n");
  fprintf(out, "\n");


  ///////////////////////////////////////////////////////////////
  //
  //         __mcsema_attach_ret_cdecl
  //
  ///////////////////////////////////////////////////////////////


  // Implements `__mcsema_attach_ret_cdecl`. This goes from native state into lifted code.
  fprintf(out, "  .globl __mcsema_attach_ret_cdecl\n");
  fprintf(out, "__mcsema_attach_ret_cdecl:\n");
  fprintf(out, "  .cfi_startproc\n");

  // this should be valid for cdecl:
  // return stack to where it was before we pasted
  // some arguments to it, so the caller can clean
  // up as expected
  //
  // add an extra 4 bytes to compensate for the fake return address
  fprintf(out, "  add esp, %u\n", kStackArgSize + 4);

  // Swap into the mcsema stack.
  fprintf(out, "push eax\n");
  getTlsIndex(out, "eax");
  fprintf(out, "  xchg esp, [eax + __mcsema_reg_state@SECREL32 + %u]\n",
          __builtin_offsetof(State, ESP));

  // simulate a pop eax from old stack
  fprintf(out, "  add dword ptr [eax + __mcsema_reg_state@SECREL32 + %u], 4\n",
          __builtin_offsetof(State, ESP));
  fprintf(out,
          "  mov eax, dword ptr [eax + __mcsema_reg_state@SECREL32 + %u]\n",
          __builtin_offsetof(State, ESP));
  fprintf(
      out,
      "  mov eax, dword ptr [eax-4]\n");  // use -4 here since we just added 4 to the old esp to simulate a pop

  fprintf(out, "  push ecx\n");
  getTlsIndex(out, "ecx");

  // Return registers.
  fprintf(out, "  mov [ecx + __mcsema_reg_state@SECREL32 + %u], eax\n",
          __builtin_offsetof(State, EAX));
  fprintf(out, "  mov [ecx + __mcsema_reg_state@SECREL32 + %u], edx\n",
          __builtin_offsetof(State, EDX));
  fprintf(out, "  movdqu [ecx + __mcsema_reg_state@SECREL32 + %u], xmm0\n",
          __builtin_offsetof(State, XMM0));

  // Callee-saved registers.
  fprintf(out, "  mov [ecx + __mcsema_reg_state@SECREL32 + %u], ebp\n",
          __builtin_offsetof(State, EBP));
  fprintf(out, "  mov [ecx + __mcsema_reg_state@SECREL32 + %u], ebx\n",
          __builtin_offsetof(State, EBX));
  fprintf(out, "  mov [ecx + __mcsema_reg_state@SECREL32 + %u], esi\n",
          __builtin_offsetof(State, ESI));
  fprintf(out, "  mov [ecx + __mcsema_reg_state@SECREL32 + %u], edi\n",
          __builtin_offsetof(State, EDI));

  fprintf(out, "  pop ecx\n");

  // Unstash the callee-saved registers.
  fprintf(out, "  pop ebp\n");
  fprintf(out, "  pop ebx\n");
  fprintf(out, "  pop esi\n");
  fprintf(out, "  pop edi\n");

  fprintf(out, "  ret\n");

  fprintf(out, ".Lfunc_end2:\n");
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
  fprintf(out, "__mcsema_attach_ret_value:\n");
  fprintf(out, "  .cfi_startproc\n");

  fprintf(out, "  push ebp\n");
  getTlsIndex(out, "ebp");

  // General purpose registers.
  fprintf(out, "  mov [ebp + __mcsema_reg_state@SECREL32 + %u], eax\n",
          __builtin_offsetof(State, EAX));
  fprintf(out, "  mov [ebp + __mcsema_reg_state@SECREL32 + %u], ebx\n",
          __builtin_offsetof(State, EBX));
  fprintf(out, "  mov [ebp + __mcsema_reg_state@SECREL32 + %u], ecx\n",
          __builtin_offsetof(State, ECX));
  fprintf(out, "  mov [ebp + __mcsema_reg_state@SECREL32 + %u], edx\n",
          __builtin_offsetof(State, EDX));
  fprintf(out, "  mov [ebp + __mcsema_reg_state@SECREL32 + %u], esi\n",
          __builtin_offsetof(State, ESI));
  fprintf(out, "  mov [ebp + __mcsema_reg_state@SECREL32 + %u], edi\n",
          __builtin_offsetof(State, EDI));

  fprintf(out, "  pop ebp\n");

  // TODO(artem): check if we need to save eax
  getTlsIndex(out, "eax");
  fprintf(out, "  mov [eax + __mcsema_reg_state@SECREL32 + %u], ebp\n",
          __builtin_offsetof(State, EBP));

  // XMM registers.
  fprintf(out, "  movdqu [eax + __mcsema_reg_state@SECREL32 + %u], xmm0\n",
          __builtin_offsetof(State, XMM0));
  fprintf(out, "  movdqu [eax + __mcsema_reg_state@SECREL32 + %u], xmm1\n",
          __builtin_offsetof(State, XMM1));
  fprintf(out, "  movdqu [eax + __mcsema_reg_state@SECREL32 + %u], xmm2\n",
          __builtin_offsetof(State, XMM2));
  fprintf(out, "  movdqu [eax + __mcsema_reg_state@SECREL32 + %u], xmm3\n",
          __builtin_offsetof(State, XMM3));
  fprintf(out, "  movdqu [eax + __mcsema_reg_state@SECREL32 + %u], xmm4\n",
          __builtin_offsetof(State, XMM4));
  fprintf(out, "  movdqu [eax + __mcsema_reg_state@SECREL32 + %u], xmm5\n",
          __builtin_offsetof(State, XMM5));
  fprintf(out, "  movdqu [eax + __mcsema_reg_state@SECREL32 + %u], xmm6\n",
          __builtin_offsetof(State, XMM6));
  fprintf(out, "  movdqu [eax + __mcsema_reg_state@SECREL32 + %u], xmm7\n",
          __builtin_offsetof(State, XMM7));


  // if this function had no args, this will be zero, otherwise
  // it will be -argcount*4 (esp is now > old esp, due to pops)
  fprintf(out, "  sub DWORD PTR [eax + __mcsema_stack_mark@SECREL32], esp\n");
  fprintf(out, "  mov ecx, DWORD PTR [eax + __mcsema_stack_mark@SECREL32]\n");

  // adjust for our copied stack args + fake return
  fprintf(out, "  add esp, %u\n", kStackArgSize + 4);
  fprintf(out, "  add esp, ecx\n");

  fprintf(out,
          "  xchg esp, DWORD PTR [eax + __mcsema_reg_state@SECREL32 + %u]\n",
          __builtin_offsetof(State, ESP));

  fprintf(out, "  pop DWORD PTR [eax + __mcsema_stack_mark@SECREL32]\n");

  // Unstash the callee-saved registers.
  fprintf(out, "  pop ebp\n");
  fprintf(out, "  pop ebx\n");
  fprintf(out, "  pop esi\n");
  fprintf(out, "  pop edi\n");

  fprintf(out, "  ret\n");

  fprintf(out, ".Lfunc_end0:\n");
  fprintf(out, "  .cfi_endproc\n");
  fprintf(out, "\n");

  ///////////////////////////////////////////////////////////////
  //
  //         __mcsema_dettach_ret_cdecl
  //
  ///////////////////////////////////////////////////////////////

  // Implements `__mcsema_detach_ret_cdecl`. This goes from lifted code into native code.
  // The native code pointer is located at the native `[State::ESP - 4]`
  // address.
  fprintf(out, "  .globl __mcsema_detach_ret_cdecl\n");
  fprintf(out, "__mcsema_detach_ret_cdecl:\n");
  fprintf(out, "  .cfi_startproc\n");

  // the stack has the State structure argument on it.
  // we need to pop it off anyway due to caller cleanup, so
  // just re-use it as a place to stash `ebp`, which we pop later
  fprintf(out, "  mov [esp], ebp\n");
  getTlsIndex(out, "ebp");

  // General purpose registers.
  fprintf(out, "  mov eax, [ebp + __mcsema_reg_state@SECREL32 + %u]\n",
          __builtin_offsetof(State, EAX));
  fprintf(out, "  mov ebx, [ebp + __mcsema_reg_state@SECREL32 + %u]\n",
          __builtin_offsetof(State, EBX));
  fprintf(out, "  mov ecx, [ebp + __mcsema_reg_state@SECREL32 + %u]\n",
          __builtin_offsetof(State, ECX));
  fprintf(out, "  mov edx, [ebp + __mcsema_reg_state@SECREL32 + %u]\n",
          __builtin_offsetof(State, EDX));
  fprintf(out, "  mov esi, [ebp + __mcsema_reg_state@SECREL32 + %u]\n",
          __builtin_offsetof(State, ESI));
  fprintf(out, "  mov edi, [ebp + __mcsema_reg_state@SECREL32 + %u]\n",
          __builtin_offsetof(State, EDI));

  // XMM registers.
  fprintf(out, "  movdqu xmm0, [ebp + __mcsema_reg_state@SECREL32 + %u]\n",
          __builtin_offsetof(State, XMM0));
  fprintf(out, "  movdqu xmm1, [ebp + __mcsema_reg_state@SECREL32 + %u]\n",
          __builtin_offsetof(State, XMM1));
  fprintf(out, "  movdqu xmm2, [ebp + __mcsema_reg_state@SECREL32 + %u]\n",
          __builtin_offsetof(State, XMM2));
  fprintf(out, "  movdqu xmm3, [ebp + __mcsema_reg_state@SECREL32 + %u]\n",
          __builtin_offsetof(State, XMM3));
  fprintf(out, "  movdqu xmm4, [ebp + __mcsema_reg_state@SECREL32 + %u]\n",
          __builtin_offsetof(State, XMM4));
  fprintf(out, "  movdqu xmm5, [ebp + __mcsema_reg_state@SECREL32 + %u]\n",
          __builtin_offsetof(State, XMM5));
  fprintf(out, "  movdqu xmm6, [ebp + __mcsema_reg_state@SECREL32 + %u]\n",
          __builtin_offsetof(State, XMM6));
  fprintf(out, "  movdqu xmm7, [ebp + __mcsema_reg_state@SECREL32 + %u]\n",
          __builtin_offsetof(State, XMM7));

  fprintf(out, "  pop ebp\n");

  fprintf(out, "  push eax\n");
  getTlsIndex(out, "eax");
  fprintf(out, "  mov ebp, [eax + __mcsema_reg_state@SECREL32 + %u]\n",
          __builtin_offsetof(State, EBP));
  fprintf(out,
          "  xchg esp, DWORD PTR [eax + __mcsema_reg_state@SECREL32 + %u]\n",
          __builtin_offsetof(State, ESP));

  // simulate a pop eax from old stack
  fprintf(out, "  add dword ptr [eax + __mcsema_reg_state@SECREL32 + %u], 4\n",
          __builtin_offsetof(State, ESP));
  fprintf(out,
          "  mov eax, dword ptr [eax + __mcsema_reg_state@SECREL32 + %u]\n",
          __builtin_offsetof(State, ESP));
  fprintf(
      out,
      "  mov eax, dword ptr [eax-4]\n");  // use -4 here since we just added 4 to the old esp to simulate a pop

  // We assume the lifted code was generated by a sane complier and ended in a RET
  // which will write a return address into State::XIP and then pop off the stack,
  // if its callee cleanup.
  // We will jump to State::XIP since it should be the 'real' return address we have to get to
  fprintf(out, "  push eax\n");
  getTlsIndex(out, "eax");
  fprintf(out, "  mov eax, [eax + __mcsema_reg_state@SECREL32 + %u]\n",
          __builtin_offsetof(State, EIP));

  // conveniently restores EAX to its saved value, and
  // uses the stack slot to set up an address we can return to

  fprintf(out, "  xchg eax, [esp]\n");

  // use the ret instruction to call [esp] and pop
  fprintf(out, "  ret\n");

  fprintf(out, ".Lfunc_end3:\n");
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
  fprintf(out, "__mcsema_detach_call_cdecl:\n");
  fprintf(out, "  .cfi_startproc\n");

  // *** This function assumes we can clobber eax and ecx

  // clobber eax to use as TLS index
  getTlsIndex(out, "eax");

  // Pop the target function into the `State` structure. This resets `EIP`
  // to what it should be on entry to `__mcsema_detach_call_cdecl`.
  fprintf(out, "  pop DWORD PTR [eax + __mcsema_reg_state@SECREL32 + %u]\n",
          __builtin_offsetof(State, EIP));

  // Marshal the callee-saved registers (of the emulated code) into the native
  // state. We don't touch the argument registers.

  // Stash the callee-saved registers.
  fprintf(out, "  push edi\n");
  fprintf(out, "  push esi\n");
  fprintf(out, "  push ebx\n");
  fprintf(out, "  push ebp\n");

  // copy posible stack args into temporary holding area
  fprintf(out, "  lea edi, [eax + __mcsema_stack_args@SECREL32]\n");

  // stack args start after ebp+ebx+esi+edi + return address
  fprintf(out, "  lea esi, [esp + %u]\n", 4 + 4 + 4 + 4 + 4);

  // ecx is how much to copy
  fprintf(out, "  mov ecx, %u\n", kStackArgSize);

  // do the copy
  fprintf(out, "  rep movsb\n");

  fprintf(out, "  mov esi, [eax + __mcsema_reg_state@SECREL32 + %u]\n",
          __builtin_offsetof(State, ESI));
  fprintf(out, "  mov edi, [eax + __mcsema_reg_state@SECREL32 + %u]\n",
          __builtin_offsetof(State, EDI));
  fprintf(out, "  mov ebx, [eax + __mcsema_reg_state@SECREL32 + %u]\n",
          __builtin_offsetof(State, EBX));
  fprintf(out, "  mov ebp, [eax + __mcsema_reg_state@SECREL32 + %u]\n",
          __builtin_offsetof(State, EBP));

  // Swap onto the native stack.
  fprintf(out,
          "  xchg DWORD PTR [eax + __mcsema_reg_state@SECREL32 + %u], esp\n",
          __builtin_offsetof(State, ESP));

  // copy posible stack args from holding area to native stack
  // allocate space for our arguments on stack
  fprintf(out, "  sub esp, %u\n", kStackArgSize);

  // we need to save these
  fprintf(out, "  push esi\n");
  fprintf(out, "  push edi\n");
  fprintf(out, "  push ecx\n");

  // get the stack arg location, adjust for the just-pushed values
  fprintf(out, "  lea edi, [esp + %u]\n", 4 + 4 + 4);

  // source is temp area
  fprintf(out, "  lea esi, [eax + __mcsema_stack_args@SECREL32]\n");
  fprintf(out, "  mov ecx, %u\n", kStackArgSize);

  // copy stack args from temp area to new stack
  fprintf(out, "  rep movsb\n");

  // restore saved regs
  fprintf(out, "  pop ecx\n");
  fprintf(out, "  pop edi\n");
  fprintf(out, "  pop esi\n");

  // Set up a re-attach return address.
  // do not push __mcsema_attach_ret_cdecl directly
  // to work around llvm assembler bug that emits it
  // as a 16-bit push
  fprintf(out, "  push eax\n");
  fprintf(out, "  lea eax, __mcsema_attach_ret_cdecl\n");

  // switched saved eax (TLS index) with current eax (pointer to function)
  // the pointer to function will be the first argument to the mcsema-xlated
  // code we are about to jump to
  fprintf(out, "  xchg eax, [esp]\n");

  fprintf(out, "  jmp DWORD PTR [eax + __mcsema_reg_state@SECREL32 + %u]\n",
          __builtin_offsetof(State, EIP));

  fprintf(out, ".Lfunc_end4:\n");
  fprintf(out, "  .cfi_endproc\n");
  fprintf(out, "\n");

  ///////////////////////////////////////////////////////////////
  //
  //         __mcsema_detach_call_value
  //
  ///////////////////////////////////////////////////////////////

  // Implements `__mcsema_detach_call_value`. This is a thin wrapper around
  // `__mcsema_detach_call`.

  // this function has three underscores (___):
  // first _ : cdecl name mangling for Windodws
  // following __: prefix indicating this is internal to mcsema
  // the extra _ for the cdecl prefix is needed since this function is called from bitcode
  // and not from other assembly code. The code generator will automatically mangle
  // based on calling convention
  fprintf(out, "  .globl ___mcsema_detach_call_value\n");
  fprintf(out, "___mcsema_detach_call_value:\n");
  fprintf(out, "  .cfi_startproc\n");

  // Note: the bitcode has already put the target address into `State::EIP`.
  // *** assumes we can clobber eax

  // Stash the callee-saved registers.
  fprintf(out, "  push edi\n");
  fprintf(out, "  push esi\n");
  fprintf(out, "  push ebx\n");
  fprintf(out, "  push ebp\n");

  getTlsIndex(out, "eax");

  // save current stack mark
  fprintf(out, "  push DWORD PTR [eax + __mcsema_stack_mark@SECREL32]\n");

  // copy posible stack args into temporary holding area
  fprintf(out, "  lea edi, [eax + __mcsema_stack_args@SECREL32]\n");

  // this is not ESP since for do_call_value there is no spilling via an
  // intermediate function
  fprintf(out,
          "  mov esi, DWORD PTR [eax + __mcsema_reg_state@SECREL32 + %u]\n",
          __builtin_offsetof(State, ESP));
  fprintf(out, "  mov ecx, %u\n", kStackArgSize);
  fprintf(out, "  rep movsb\n");

  // we wil use ebp to index once we clobber eax
  fprintf(out, "  mov ebp, eax\n");

  // General purpose registers.
  // we still read out eax on principle, in case we need to do debugging
  // but we clobber it later anyway, so... ignore it
  fprintf(out, "  mov eax, [ebp + __mcsema_reg_state@SECREL32 + %u]\n",
          __builtin_offsetof(State, EAX));
  fprintf(out, "  mov eax, ebp\n");
  fprintf(out, "  mov ebx, [eax + __mcsema_reg_state@SECREL32 + %u]\n",
          __builtin_offsetof(State, EBX));
  fprintf(out, "  mov ecx, [eax + __mcsema_reg_state@SECREL32 + %u]\n",
          __builtin_offsetof(State, ECX));
  fprintf(out, "  mov edx, [eax + __mcsema_reg_state@SECREL32 + %u]\n",
          __builtin_offsetof(State, EDX));
  fprintf(out, "  mov esi, [eax + __mcsema_reg_state@SECREL32 + %u]\n",
          __builtin_offsetof(State, ESI));
  fprintf(out, "  mov edi, [eax + __mcsema_reg_state@SECREL32 + %u]\n",
          __builtin_offsetof(State, EDI));
  fprintf(out, "  mov ebp, [eax + __mcsema_reg_state@SECREL32 + %u]\n",
          __builtin_offsetof(State, EBP));

  // XMM registers.
  fprintf(out, "  movdqu xmm0, [eax + __mcsema_reg_state@SECREL32 + %u]\n",
          __builtin_offsetof(State, XMM0));
  fprintf(out, "  movdqu xmm1, [eax + __mcsema_reg_state@SECREL32 + %u]\n",
          __builtin_offsetof(State, XMM1));
  fprintf(out, "  movdqu xmm2, [eax + __mcsema_reg_state@SECREL32 + %u]\n",
          __builtin_offsetof(State, XMM2));
  fprintf(out, "  movdqu xmm3, [eax + __mcsema_reg_state@SECREL32 + %u]\n",
          __builtin_offsetof(State, XMM3));
  fprintf(out, "  movdqu xmm4, [eax + __mcsema_reg_state@SECREL32 + %u]\n",
          __builtin_offsetof(State, XMM4));
  fprintf(out, "  movdqu xmm5, [eax + __mcsema_reg_state@SECREL32 + %u]\n",
          __builtin_offsetof(State, XMM5));
  fprintf(out, "  movdqu xmm6, [eax + __mcsema_reg_state@SECREL32 + %u]\n",
          __builtin_offsetof(State, XMM6));
  fprintf(out, "  movdqu xmm7, [eax + __mcsema_reg_state@SECREL32 + %u]\n",
          __builtin_offsetof(State, XMM7));

  fprintf(out,
          "  xchg DWORD PTR [eax + __mcsema_reg_state@SECREL32 + %u], esp\n",
          __builtin_offsetof(State, ESP));


  // copy posible stack args from holding area to native stack
  // allocate space for our arguments on stack
  fprintf(out, "  sub esp, %u\n", kStackArgSize);

  // we need to save these
  fprintf(out, "  push esi\n");
  fprintf(out, "  push edi\n");
  fprintf(out, "  push ecx\n");

  // get the stack arg location
  // compensate for esi+edi+ecx
  fprintf(out, "  lea edi, [esp + %u]\n", 4 + 4 + 4);

  // source is temp area
  fprintf(out, "  lea esi, [eax + __mcsema_stack_args@SECREL32]\n");
  fprintf(out, "  mov ecx, %u\n", kStackArgSize);

  // copy
  fprintf(out, "  rep movsb\n");

  // restore saved regs
  fprintf(out, "  pop ecx\n");
  fprintf(out, "  pop edi\n");
  fprintf(out, "  pop esi\n");

  // save current ESP so we know how many bytes
  // the callee popped off the stack on return
  fprintf(out, "  mov DWORD PTR [eax + __mcsema_stack_mark@SECREL32], esp\n");

  // Set up a re-attach return address.
  // clobber de7acccc on stack with attach by value RA
  // preserve eax
  fprintf(out, "  mov [esp], eax\n");
  fprintf(out, "  lea eax, __mcsema_attach_ret_value\n");
  fprintf(out, "  xchg eax, [esp]\n");

  // Go native.
  fprintf(out, "  jmp DWORD PTR [eax + __mcsema_reg_state@SECREL32 + %u]\n",
          __builtin_offsetof(State, EIP));

  fprintf(out, ".Lfunc_end5:\n");
  fprintf(out, "  .cfi_endproc\n");
  fprintf(out, "\n");

  // Implements `__mcsema_debug_get_reg_state`. This is useful when debugging in
  // gdb.
  fprintf(out, "  .globl __mcsema_debug_get_reg_state\n");
  fprintf(out, "__mcsema_debug_get_reg_state:\n");
  fprintf(out, "  .cfi_startproc\n");
  getTlsIndex(out, "eax");
  fprintf(out, "  lea eax, [eax + __mcsema_reg_state@SECREL32]\n");
  fprintf(out, "  ret\n");
  fprintf(out, ".Lfunc_end6:\n");
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
  fprintf(out, "__mcsema_detach_call_stdcall:\n");
  fprintf(out, "  .cfi_startproc\n");

  // *** assume we can clobber eax

  // Pop the target function into the `State` structure. This resets `EIP`
  // to what it should be on entry to `__mcsema_detach_call_stdcall`.
  getTlsIndex(out, "eax");
  fprintf(out, "  pop DWORD PTR [eax + __mcsema_reg_state@SECREL32 + %u]\n",
          __builtin_offsetof(State, EIP));

  // Marshal the callee-saved registers (of the emulated code) into the native
  // state. We don't touch the argument registers.

  // Stash the callee-saved registers.
  fprintf(out, "  push edi\n");
  fprintf(out, "  push esi\n");
  fprintf(out, "  push ebx\n");
  fprintf(out, "  push ebp\n");

  // save current stack mark
  fprintf(out, "  push DWORD PTR [eax + __mcsema_stack_mark@SECREL32]\n");

  // do not clobber fastcall args
  fprintf(out, "  push ecx\n");
  fprintf(out, "  push edx\n");


  // copy posible stack args into temporary holding area
  fprintf(out, "  lea edi, [eax + __mcsema_stack_args@SECREL32]\n");

  //  ra + stack_mark + (ecx + edx) +  (edi+esi+ebx+ebp)
  fprintf(out, "  lea esi, [esp + %u]\n", 4 + 4 + 4 + 4 + 4 + 4 + 4 + 4);
  fprintf(out, "  mov ecx, %u\n", kStackArgSize);
  fprintf(out, "  rep movsb\n");

  // do not clobber fastcall args
  fprintf(out, "  pop edx\n");
  fprintf(out, "  pop ecx\n");

  fprintf(out, "  mov edi, [eax + __mcsema_reg_state@SECREL32 + %u]\n",
          __builtin_offsetof(State, EDI));
  fprintf(out, "  mov esi, [eax + __mcsema_reg_state@SECREL32 + %u]\n",
          __builtin_offsetof(State, ESI));
  fprintf(out, "  mov ebx, [eax + __mcsema_reg_state@SECREL32 + %u]\n",
          __builtin_offsetof(State, EBX));
  fprintf(out, "  mov ebp, [eax + __mcsema_reg_state@SECREL32 + %u]\n",
          __builtin_offsetof(State, EBP));

  // Swap onto the native stack.
  fprintf(out,
          "  xchg DWORD PTR [eax + __mcsema_reg_state@SECREL32 + %u], esp\n",
          __builtin_offsetof(State, ESP));

  // copy posible stack args from holding area to native stack
  // allocate space for our arguments on stack
  fprintf(out, "  sub esp, %u\n", kStackArgSize);

  // we need to save these
  fprintf(out, "  push esi\n");
  fprintf(out, "  push edi\n");
  fprintf(out, "  push ecx\n");

  // get the stack arg location
  fprintf(out, "  lea edi, [esp + %u]\n", 4 + 4 + 4);

  // source is temp area
  fprintf(out, "  lea esi, [eax + __mcsema_stack_args@SECREL32]\n");
  fprintf(out, "  mov ecx, %u\n", kStackArgSize);

  // copy
  fprintf(out, "  rep movsb\n");

  // restore saved regs
  fprintf(out, "  pop ecx\n");
  fprintf(out, "  pop edi\n");
  fprintf(out, "  pop esi\n");

  // save current ESP so we know how many bytes
  // the callee popped off the stack on return
  fprintf(out, "  mov DWORD PTR [eax + __mcsema_stack_mark@SECREL32], esp\n");

  // Set up a re-attach return address.
  // do not push __mcsema_attach_ret_stdcall directly
  // to work around llvm assembler bug that emits it
  // as a 16-bit push
  fprintf(out, "  push eax\n");
  fprintf(out, "  lea eax, __mcsema_attach_ret_stdcall\n");
  fprintf(out, "  xchg eax, [esp]\n");

  fprintf(out, "  jmp DWORD PTR [eax + __mcsema_reg_state@SECREL32 + %u]\n",
          __builtin_offsetof(State, EIP));

  fprintf(out, ".Lfunc_endA:\n");
  fprintf(out, "  .cfi_endproc\n");
  fprintf(out, "\n");

  ///////////////////////////////////////////////////////////////
  //
  //         __mcsema_attach_ret_stdcall
  //
  ///////////////////////////////////////////////////////////////


  // Implements `__mcsema_attach_ret_stdcall`. This goes from native state into lifted code.
  fprintf(out, "  .globl __mcsema_attach_ret_stdcall\n");
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

  // assume we can clobber ecx
  getTlsIndex(out, "ecx");

  // if this function had no args, this will be zero, otherwise
  // it will be -argcount*4 (esp is now > old esp, due to pops)
  fprintf(out, "  sub DWORD PTR [ecx + __mcsema_stack_mark@SECREL32], esp\n");

  // adjust for our copied stack args + fake return
  fprintf(out, "  add esp, %u\n", kStackArgSize + 4);

  //fprintf(out, "  add esp, DWORD PTR [ecx + __mcsema_stack_mark@SECREL32]\n");
  // Swap into the mcsema stack.
  fprintf(out,
          "  xchg esp, DWORD PTR [ecx + __mcsema_reg_state@SECREL32 + %u]\n",
          __builtin_offsetof(State, ESP));

  // Return registers.
  fprintf(out, "  mov [ecx + __mcsema_reg_state@SECREL32 + %u], eax\n",
          __builtin_offsetof(State, EAX));
  fprintf(out, "  mov [ecx + __mcsema_reg_state@SECREL32 + %u], edx\n",
          __builtin_offsetof(State, EDX));
  fprintf(out, "  movdqu [ecx + __mcsema_reg_state@SECREL32 + %u], xmm0\n",
          __builtin_offsetof(State, XMM0));

  // Callee-saved registers.
  fprintf(out, "  mov [ecx + __mcsema_reg_state@SECREL32 + %u], ebp\n",
          __builtin_offsetof(State, EBP));
  fprintf(out, "  mov [ecx + __mcsema_reg_state@SECREL32 + %u], ebx\n",
          __builtin_offsetof(State, EBX));
  fprintf(out, "  mov [ecx + __mcsema_reg_state@SECREL32 + %u], esi\n",
          __builtin_offsetof(State, ESI));
  fprintf(out, "  mov [ecx + __mcsema_reg_state@SECREL32 + %u], edi\n",
          __builtin_offsetof(State, EDI));

  fprintf(out, "  mov ebp, ecx\n");

  // ecx is old stack mark we need for this function, to adjust stack after retn
  fprintf(out, "  mov ecx, DWORD PTR [ecx + __mcsema_stack_mark@SECREL32]\n");

  // restore old stack mark
  fprintf(out, "  pop DWORD PTR [ebp + __mcsema_stack_mark@SECREL32]\n");

  // Unstash the callee-saved registers.
  fprintf(out, "  pop ebp\n");
  fprintf(out, "  pop ebx\n");
  fprintf(out, "  pop esi\n");
  fprintf(out, "  pop edi\n");

  // adjust again for the poppped off arguments
  // this emulates a "retn XX", but that
  // only takes an immediate value
  fprintf(out, "  sub esp, ecx\n");  // this sub is an add since ecx is negative
  fprintf(out, "  add esp, 4\n");  // adjust for return address on stack

  // we still need to transfer control to the return addr on stack
  fprintf(out, "  lea ecx, [esp+ecx]\n");
  fprintf(out, "  jmp dword ptr [ecx-4]\n");

  fprintf(out, ".Lfunc_end7:\n");
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
  fprintf(out, "__mcsema_detach_call_fastcall:\n");
  fprintf(out, "  .cfi_startproc\n");

  // stdcall takes care to save the fastcall regs, so these effectively become identical
  fprintf(out, "  lea eax, __mcsema_detach_call_stdcall\n");
  fprintf(out, "  jmp eax\n");

  fprintf(out, ".Lfunc_end8:\n");
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
  fprintf(out, "__mcsema_attach_ret_fastcall:\n");
  fprintf(out, "  .cfi_startproc\n");

  // awkwardly push/ret to __mcsema_attach_ret_stdcall
  // since it should be compatible with fastcall
  fprintf(out, "  push eax\n");
  fprintf(out, "  lea eax, __mcsema_attach_ret_stdcall\n");
  fprintf(out, "  xchg eax, DWORD PTR [esp]\n");
  fprintf(out, "  ret\n");

  fprintf(out, ".Lfunc_end9:\n");
  fprintf(out, "  .cfi_endproc\n");
  fprintf(out, "\n");

  return 0;
}
