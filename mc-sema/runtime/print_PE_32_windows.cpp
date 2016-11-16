/* Copyright 2016 Trail of Bits */

#include <cstdio>

#define ONLY_STRUCT
#include "../common/RegisterState.h"

static const unsigned kStackSize = 1UL << 20U;
static const unsigned kStackArgSize = 256U;

void getTlsIndex(const char dest_reg[]) {
    printf("push edx\n");
    printf("mov %s, dword ptr [__tls_index]\n", dest_reg);
    printf("mov edx, dword ptr fs:[44]\n");
    printf("mov %s, dword ptr [edx + 4*%s]\n", dest_reg, dest_reg);
    printf("pop edx\n");
}

int main(void) {

  printf("/* Auto-generated file! Don't modify! */\n\n");
  printf("  .intel_syntax noprefix\n");
  printf("\n");

  printf("  .section        .tls$,\"wd\"\n");

  // Thread-local state structure, named by `__mcsema_reg_state`.
  printf("     .globl  __mcsema_reg_state\n");
  printf("__mcsema_reg_state:\n");
  printf("     .align  4\n");
  printf("     .zero   %u\n", sizeof(mcsema::RegState));
  printf("\n");

  // Thread-local stack structure, named by `__mcsema_stack`.
  printf("     .globl  __mcsema_stack\n");
  printf("__mcsema_stack:\n");
  printf("     .align  16\n");
  printf("     .zero   %u\n", kStackSize); // MiB
  printf("\n");

  // Thread-local stack structure, named by `__mcsema_stack_args`
  // used to store stack-passed function arguments
  printf("     .globl  __mcsema_stack_args\n");
  printf("__mcsema_stack_args:\n");
  printf("     .align  16\n");
  printf("     .zero   %u\n", kStackArgSize);
  printf("\n");

  // Thread-local variable structure, named by `__mcsema_stack_mark`
  // used to store the expected stack location on return,
  // so caller cleanup conventions can know how many bytes to pop off
  printf("     .globl  __mcsema_stack_mark\n");
  printf("__mcsema_stack_mark:\n");
  printf("     .align  4\n");
  printf("     .zero   %u\n", 4);
  printf("\n");

  printf("  .text\n");
  printf("\n");

  // Forward declarations.
  printf("  .globl __mcsema_detach_ret_cdecl\n");
  printf("\n");

  ///////////////////////////////////////////////////////////////
  //
  //         __mcsema_attach_call_cdecl
  //
  ///////////////////////////////////////////////////////////////

  // Implements `__mcsema_attach_call_cdecl`. This goes from native state into lifted code.
  // The lifted code function pointer is already on the stack.
  printf("  .globl __mcsema_attach_call_cdecl\n");
  printf("__mcsema_attach_call_cdecl:\n");
  printf("  .cfi_startproc\n");

  //*** assume we can clobber eax

  // save reg for use with TLS offsets
  printf("  push dword ptr [esp]\n"); // dupliate last stack element (the jump-to EIP), so we can pop it
  printf("  mov dword ptr [esp+4], ebp\n"); // save ebp, we will clobber it
  getTlsIndex("ebp");

  // Pop the target function into the `RegState` structure. This resets `ESP`
  // to what it should be on entry to `__mcsema_attach_call`.
  printf("  pop DWORD PTR [ebp + __mcsema_reg_state@SECREL32 + %u]\n", __builtin_offsetof(mcsema::RegState, EIP));

  // General purpose registers.
  printf("  mov [ebp + __mcsema_reg_state@SECREL32 + %u], eax\n", __builtin_offsetof(mcsema::RegState, EAX));
  printf("  mov [ebp + __mcsema_reg_state@SECREL32 + %u], ebx\n", __builtin_offsetof(mcsema::RegState, EBX));
  printf("  mov [ebp + __mcsema_reg_state@SECREL32 + %u], ecx\n", __builtin_offsetof(mcsema::RegState, ECX));
  printf("  mov [ebp + __mcsema_reg_state@SECREL32 + %u], edx\n", __builtin_offsetof(mcsema::RegState, EDX));
  printf("  mov [ebp + __mcsema_reg_state@SECREL32 + %u], esi\n", __builtin_offsetof(mcsema::RegState, ESI));
  printf("  mov [ebp + __mcsema_reg_state@SECREL32 + %u], edi\n", __builtin_offsetof(mcsema::RegState, EDI));

  printf("  pop ebp\n");

  getTlsIndex("eax");
  printf("  mov [eax + __mcsema_reg_state@SECREL32 + %u], ebp\n", __builtin_offsetof(mcsema::RegState, EBP));

  // XMM registers.
  printf("  movdqu [eax + __mcsema_reg_state@SECREL32 + %u], xmm0\n", __builtin_offsetof(mcsema::RegState, XMM0));
  printf("  movdqu [eax + __mcsema_reg_state@SECREL32 + %u], xmm1\n", __builtin_offsetof(mcsema::RegState, XMM1));
  printf("  movdqu [eax + __mcsema_reg_state@SECREL32 + %u], xmm2\n", __builtin_offsetof(mcsema::RegState, XMM2));
  printf("  movdqu [eax + __mcsema_reg_state@SECREL32 + %u], xmm3\n", __builtin_offsetof(mcsema::RegState, XMM3));
  printf("  movdqu [eax + __mcsema_reg_state@SECREL32 + %u], xmm4\n", __builtin_offsetof(mcsema::RegState, XMM4));
  printf("  movdqu [eax + __mcsema_reg_state@SECREL32 + %u], xmm5\n", __builtin_offsetof(mcsema::RegState, XMM5));
  printf("  movdqu [eax + __mcsema_reg_state@SECREL32 + %u], xmm6\n", __builtin_offsetof(mcsema::RegState, XMM6));
  printf("  movdqu [eax + __mcsema_reg_state@SECREL32 + %u], xmm7\n", __builtin_offsetof(mcsema::RegState, XMM7));

  printf("  xchg esp, [eax + __mcsema_reg_state@SECREL32 + %u]\n", __builtin_offsetof(mcsema::RegState, ESP));

  // If `ESP` is null then we need to initialize it to our new stack.
  printf("  cmp esp, 0\n");
  printf("  jnz .Lhave_stack\n");
    // end inline getTlsIndex
  printf("  lea esp, [eax + __mcsema_stack@SECREL32 + %u]\n", kStackSize);
  printf(".Lhave_stack:\n");

  // the state struture is the first and only arg to lifted functions
  printf("  push eax\n");
  printf("  lea eax, [eax + __mcsema_reg_state@SECREL32]\n");
  printf("  xchg eax, [esp]\n");

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
  printf("  push eax\n");
  printf("  lea eax, __mcsema_detach_ret_cdecl\n");
  printf("  xchg eax, [esp]\n");

  // get EIP we need to jump to, in the process, clobber TLS index
  printf("  mov eax, DWORD PTR [eax + __mcsema_reg_state@SECREL32 + %u]\n", __builtin_offsetof(mcsema::RegState, EIP));
  // and away we go!
  printf("  jmp eax\n");

  printf(".Lfunc_end1:\n");
  printf("  .cfi_endproc\n");
  printf("\n");


  ///////////////////////////////////////////////////////////////
  //
  //         __mcsema_attach_ret_cdecl
  //
  ///////////////////////////////////////////////////////////////


  // Implements `__mcsema_attach_ret_cdecl`. This goes from native state into lifted code.
  printf("  .globl __mcsema_attach_ret_cdecl\n");
  printf("__mcsema_attach_ret_cdecl:\n");
  printf("  .cfi_startproc\n");

  // this should be valid for cdecl:
  // return stack to where it was before we pasted
  // some arguments to it, so the caller can clean
  // up as expected
  //
  // add an extra 4 bytes to compensate for the fake return address
  printf("  add esp, %u\n", kStackArgSize+4);
  // Swap into the mcsema stack.
  printf("push eax\n");
  getTlsIndex("eax");
  printf("  xchg esp, [eax + __mcsema_reg_state@SECREL32 + %u]\n", __builtin_offsetof(mcsema::RegState, ESP));
  // simulate a pop eax from old stack
  printf("  add dword ptr [eax + __mcsema_reg_state@SECREL32 + %u], 4\n", __builtin_offsetof(mcsema::RegState, ESP));
  printf("  mov eax, dword ptr [eax + __mcsema_reg_state@SECREL32 + %u]\n", __builtin_offsetof(mcsema::RegState, ESP));
  printf("  mov eax, dword ptr [eax-4]\n"); // use -4 here since we just added 4 to the old esp to simulate a pop

  printf("  push ecx\n");
  getTlsIndex("ecx");
  // Return registers.
  printf("  mov [ecx + __mcsema_reg_state@SECREL32 + %u], eax\n", __builtin_offsetof(mcsema::RegState, EAX));
  printf("  mov [ecx + __mcsema_reg_state@SECREL32 + %u], edx\n", __builtin_offsetof(mcsema::RegState, EDX));
  printf("  movdqu [ecx + __mcsema_reg_state@SECREL32 + %u], xmm0\n", __builtin_offsetof(mcsema::RegState, XMM0));

  // Callee-saved registers.
  printf("  mov [ecx + __mcsema_reg_state@SECREL32 + %u], ebp\n", __builtin_offsetof(mcsema::RegState, EBP));
  printf("  mov [ecx + __mcsema_reg_state@SECREL32 + %u], ebx\n", __builtin_offsetof(mcsema::RegState, EBX));
  printf("  mov [ecx + __mcsema_reg_state@SECREL32 + %u], esi\n", __builtin_offsetof(mcsema::RegState, ESI));
  printf("  mov [ecx + __mcsema_reg_state@SECREL32 + %u], edi\n", __builtin_offsetof(mcsema::RegState, EDI));

  printf("  pop ecx\n");
  // Unstash the callee-saved registers.
  printf("  pop ebp\n");
  printf("  pop ebx\n");
  printf("  pop esi\n");
  printf("  pop edi\n");

  printf("  ret\n");

  printf(".Lfunc_end2:\n");
  printf("  .cfi_endproc\n");
  printf("\n");

  ///////////////////////////////////////////////////////////////
  //
  //         __mcsema_attach_ret_value
  //
  ///////////////////////////////////////////////////////////////

  // Implements `__mcsema_attach_ret_value`. This is the "opposite" of
  // `__mcsema_detach_call_value`.
  printf("  .globl __mcsema_attach_ret_value\n");
  printf("__mcsema_attach_ret_value:\n");
  printf("  .cfi_startproc\n");

  printf("  push ebp\n");
  getTlsIndex("ebp");

  // General purpose registers.
  printf("  mov [ebp + __mcsema_reg_state@SECREL32 + %u], eax\n", __builtin_offsetof(mcsema::RegState, EAX));
  printf("  mov [ebp + __mcsema_reg_state@SECREL32 + %u], ebx\n", __builtin_offsetof(mcsema::RegState, EBX));
  printf("  mov [ebp + __mcsema_reg_state@SECREL32 + %u], ecx\n", __builtin_offsetof(mcsema::RegState, ECX));
  printf("  mov [ebp + __mcsema_reg_state@SECREL32 + %u], edx\n", __builtin_offsetof(mcsema::RegState, EDX));
  printf("  mov [ebp + __mcsema_reg_state@SECREL32 + %u], esi\n", __builtin_offsetof(mcsema::RegState, ESI));
  printf("  mov [ebp + __mcsema_reg_state@SECREL32 + %u], edi\n", __builtin_offsetof(mcsema::RegState, EDI));

  printf("  pop ebp\n");

  // TODO(artem): check if we need to save eax
  getTlsIndex("eax");
  printf("  mov [eax + __mcsema_reg_state@SECREL32 + %u], ebp\n", __builtin_offsetof(mcsema::RegState, EBP));

  // XMM registers.
  printf("  movdqu [eax + __mcsema_reg_state@SECREL32 + %u], xmm0\n", __builtin_offsetof(mcsema::RegState, XMM0));
  printf("  movdqu [eax + __mcsema_reg_state@SECREL32 + %u], xmm1\n", __builtin_offsetof(mcsema::RegState, XMM1));
  printf("  movdqu [eax + __mcsema_reg_state@SECREL32 + %u], xmm2\n", __builtin_offsetof(mcsema::RegState, XMM2));
  printf("  movdqu [eax + __mcsema_reg_state@SECREL32 + %u], xmm3\n", __builtin_offsetof(mcsema::RegState, XMM3));
  printf("  movdqu [eax + __mcsema_reg_state@SECREL32 + %u], xmm4\n", __builtin_offsetof(mcsema::RegState, XMM4));
  printf("  movdqu [eax + __mcsema_reg_state@SECREL32 + %u], xmm5\n", __builtin_offsetof(mcsema::RegState, XMM5));
  printf("  movdqu [eax + __mcsema_reg_state@SECREL32 + %u], xmm6\n", __builtin_offsetof(mcsema::RegState, XMM6));
  printf("  movdqu [eax + __mcsema_reg_state@SECREL32 + %u], xmm7\n", __builtin_offsetof(mcsema::RegState, XMM7));


  // if this function had no args, this will be zero, otherwise
  // it will be -argcount*4 (esp is now > old esp, due to pops)
  printf("  sub DWORD PTR [eax + __mcsema_stack_mark@SECREL32], esp\n");
  printf("  mov ecx, DWORD PTR [eax + __mcsema_stack_mark@SECREL32]\n");

  // adjust for our copied stack args + fake return
  printf("  add esp, %u\n", kStackArgSize+4);
  printf("  add esp, ecx\n");

  printf("  xchg esp, DWORD PTR [eax + __mcsema_reg_state@SECREL32 + %u]\n", __builtin_offsetof(mcsema::RegState, ESP));

  printf("  pop DWORD PTR [eax + __mcsema_stack_mark@SECREL32]\n");
  // Unstash the callee-saved registers.
  printf("  pop ebp\n");
  printf("  pop ebx\n");
  printf("  pop esi\n");
  printf("  pop edi\n");

  printf("  ret\n");

  printf(".Lfunc_end0:\n");
  printf("  .cfi_endproc\n");
  printf("\n");

  ///////////////////////////////////////////////////////////////
  //
  //         __mcsema_dettach_ret_cdecl
  //
  ///////////////////////////////////////////////////////////////

  // Implements `__mcsema_detach_ret_cdecl`. This goes from lifted code into native code.
  // The native code pointer is located at the native `[RegState::ESP - 4]`
  // address.
  printf("  .globl __mcsema_detach_ret_cdecl\n");
  printf("__mcsema_detach_ret_cdecl:\n");
  printf("  .cfi_startproc\n");

  // the stack has the RegState structure argument on it. 
  // we need to pop it off anyway due to caller cleanup, so 
  // just re-use it as a place to stash `ebp`, which we pop later
  printf("  mov [esp], ebp\n");
  getTlsIndex("ebp");

  // General purpose registers.
  printf("  mov eax, [ebp + __mcsema_reg_state@SECREL32 + %u]\n", __builtin_offsetof(mcsema::RegState, EAX));
  printf("  mov ebx, [ebp + __mcsema_reg_state@SECREL32 + %u]\n", __builtin_offsetof(mcsema::RegState, EBX));
  printf("  mov ecx, [ebp + __mcsema_reg_state@SECREL32 + %u]\n", __builtin_offsetof(mcsema::RegState, ECX));
  printf("  mov edx, [ebp + __mcsema_reg_state@SECREL32 + %u]\n", __builtin_offsetof(mcsema::RegState, EDX));
  printf("  mov esi, [ebp + __mcsema_reg_state@SECREL32 + %u]\n", __builtin_offsetof(mcsema::RegState, ESI));
  printf("  mov edi, [ebp + __mcsema_reg_state@SECREL32 + %u]\n", __builtin_offsetof(mcsema::RegState, EDI));

  // XMM registers.
  printf("  movdqu xmm0, [ebp + __mcsema_reg_state@SECREL32 + %u]\n", __builtin_offsetof(mcsema::RegState, XMM0));
  printf("  movdqu xmm1, [ebp + __mcsema_reg_state@SECREL32 + %u]\n", __builtin_offsetof(mcsema::RegState, XMM1));
  printf("  movdqu xmm2, [ebp + __mcsema_reg_state@SECREL32 + %u]\n", __builtin_offsetof(mcsema::RegState, XMM2));
  printf("  movdqu xmm3, [ebp + __mcsema_reg_state@SECREL32 + %u]\n", __builtin_offsetof(mcsema::RegState, XMM3));
  printf("  movdqu xmm4, [ebp + __mcsema_reg_state@SECREL32 + %u]\n", __builtin_offsetof(mcsema::RegState, XMM4));
  printf("  movdqu xmm5, [ebp + __mcsema_reg_state@SECREL32 + %u]\n", __builtin_offsetof(mcsema::RegState, XMM5));
  printf("  movdqu xmm6, [ebp + __mcsema_reg_state@SECREL32 + %u]\n", __builtin_offsetof(mcsema::RegState, XMM6));
  printf("  movdqu xmm7, [ebp + __mcsema_reg_state@SECREL32 + %u]\n", __builtin_offsetof(mcsema::RegState, XMM7));

  printf("  pop ebp\n");

  printf("  push eax\n");
  getTlsIndex("eax");
  printf("  mov ebp, [eax + __mcsema_reg_state@SECREL32 + %u]\n", __builtin_offsetof(mcsema::RegState, EBP));
  printf("  xchg esp, DWORD PTR [eax + __mcsema_reg_state@SECREL32 + %u]\n", __builtin_offsetof(mcsema::RegState, ESP));
  // simulate a pop eax from old stack
  printf("  add dword ptr [eax + __mcsema_reg_state@SECREL32 + %u], 4\n", __builtin_offsetof(mcsema::RegState, ESP));
  printf("  mov eax, dword ptr [eax + __mcsema_reg_state@SECREL32 + %u]\n", __builtin_offsetof(mcsema::RegState, ESP));
  printf("  mov eax, dword ptr [eax-4]\n"); // use -4 here since we just added 4 to the old esp to simulate a pop

  // We assume the lifted code was generated by a sane complier and ended in a RET
  // which will write a return address into RegState::XIP and then pop off the stack,
  // if its callee cleanup.
  // We will jump to RegState::XIP since it should be the 'real' return address we have to get to
  printf("  push eax\n");
  getTlsIndex("eax");
  printf("  mov eax, [eax + __mcsema_reg_state@SECREL32 + %u]\n", __builtin_offsetof(mcsema::RegState, EIP));
  // conveniently restores EAX to its saved value, and
  // uses the stack slot to set up an address we can return to
  
  printf("  xchg eax, [esp]\n");

  // use the ret instruction to call [esp] and pop
  printf("  ret\n");

  printf(".Lfunc_end3:\n");
  printf("  .cfi_endproc\n");
  printf("\n");

  ///////////////////////////////////////////////////////////////
  //
  //         __mcsema_detach_call_cdecl
  //
  ///////////////////////////////////////////////////////////////

  // Implements `__mcsema_detach_call_cdecl`. This partially goes from lifted code
  // into native code.
  printf("  .globl __mcsema_detach_call_cdecl\n");
  printf("__mcsema_detach_call_cdecl:\n");
  printf("  .cfi_startproc\n");

  // *** This function assumes we can clobber eax and ecx
  
  // clobber eax to use as TLS index
  getTlsIndex("eax");
  // Pop the target function into the `RegState` structure. This resets `EIP`
  // to what it should be on entry to `__mcsema_detach_call_cdecl`.
  printf("  pop DWORD PTR [eax + __mcsema_reg_state@SECREL32 + %u]\n", __builtin_offsetof(mcsema::RegState, EIP));
  // Marshal the callee-saved registers (of the emulated code) into the native
  // state. We don't touch the argument registers.

  // Stash the callee-saved registers.
  printf("  push edi\n");
  printf("  push esi\n");
  printf("  push ebx\n");
  printf("  push ebp\n");

  // copy posible stack args into temporary holding area
  printf("  lea edi, [eax + __mcsema_stack_args@SECREL32]\n");
  // stack args start after ebp+ebx+esi+edi + return address
  printf("  lea esi, [esp + %u]\n", 4 + 4+4+4+4);
  // ecx is how much to copy
  printf("  mov ecx, %u\n", kStackArgSize);
  // do the copy
  printf("  rep movsb\n");

  printf("  mov esi, [eax + __mcsema_reg_state@SECREL32 + %u]\n", __builtin_offsetof(mcsema::RegState, ESI));
  printf("  mov edi, [eax + __mcsema_reg_state@SECREL32 + %u]\n", __builtin_offsetof(mcsema::RegState, EDI));
  printf("  mov ebx, [eax + __mcsema_reg_state@SECREL32 + %u]\n", __builtin_offsetof(mcsema::RegState, EBX));
  printf("  mov ebp, [eax + __mcsema_reg_state@SECREL32 + %u]\n", __builtin_offsetof(mcsema::RegState, EBP));

  // Swap onto the native stack.
  printf("  xchg DWORD PTR [eax + __mcsema_reg_state@SECREL32 + %u], esp\n", __builtin_offsetof(mcsema::RegState, ESP));

  // copy posible stack args from holding area to native stack
  // allocate space for our arguments on stack
  printf("  sub esp, %u\n", kStackArgSize);
  // we need to save these 
  printf("  push esi\n");
  printf("  push edi\n");
  printf("  push ecx\n");
  // get the stack arg location, adjust for the just-pushed values
  printf("  lea edi, [esp + %u]\n", 4+4+4);
  // source is temp area
  printf("  lea esi, [eax + __mcsema_stack_args@SECREL32]\n");
  printf("  mov ecx, %u\n", kStackArgSize);
  // copy stack args from temp area to new stack
  printf("  rep movsb\n");

  // restore saved regs
  printf("  pop ecx\n");
  printf("  pop edi\n");
  printf("  pop esi\n");

  // Set up a re-attach return address.
  // do not push __mcsema_attach_ret_cdecl directly
  // to work around llvm assembler bug that emits it
  // as a 16-bit push
  printf("  push eax\n");
  printf("  lea eax, __mcsema_attach_ret_cdecl\n");
  // switched saved eax (TLS index) with current eax (pointer to function)
  // the pointer to function will be the first argument to the mcsema-xlated
  // code we are about to jump to
  printf("  xchg eax, [esp]\n");

  printf("  jmp DWORD PTR [eax + __mcsema_reg_state@SECREL32 + %u]\n", __builtin_offsetof(mcsema::RegState, EIP));

  printf(".Lfunc_end4:\n");
  printf("  .cfi_endproc\n");
  printf("\n");

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
  printf("  .globl ___mcsema_detach_call_value\n");
  printf("___mcsema_detach_call_value:\n");
  printf("  .cfi_startproc\n");

  // Note: the bitcode has already put the target address into `RegState::EIP`.
  // *** assumes we can clobber eax

  // Stash the callee-saved registers.
  printf("  push edi\n");
  printf("  push esi\n");
  printf("  push ebx\n");
  printf("  push ebp\n");

  getTlsIndex("eax");
  // save current stack mark
  printf("  push DWORD PTR [eax + __mcsema_stack_mark@SECREL32]\n");

  // copy posible stack args into temporary holding area
  printf("  lea edi, [eax + __mcsema_stack_args@SECREL32]\n");
  // this is not ESP since for do_call_value there is no spilling via an 
  // intermediate function
  printf("  mov esi, DWORD PTR [eax + __mcsema_reg_state@SECREL32 + %u]\n", __builtin_offsetof(mcsema::RegState, ESP));
  printf("  mov ecx, %u\n", kStackArgSize);
  printf("  rep movsb\n");

  // we wil use ebp to index once we clobber eax
  printf("  mov ebp, eax\n");
  // General purpose registers.
  // we still read out eax on principle, in case we need to do debugging
  // but we clobber it later anyway, so... ignore it
  printf("  mov eax, [ebp + __mcsema_reg_state@SECREL32 + %u]\n", __builtin_offsetof(mcsema::RegState, EAX));
  printf("  mov eax, ebp\n");
  printf("  mov ebx, [eax + __mcsema_reg_state@SECREL32 + %u]\n", __builtin_offsetof(mcsema::RegState, EBX));
  printf("  mov ecx, [eax + __mcsema_reg_state@SECREL32 + %u]\n", __builtin_offsetof(mcsema::RegState, ECX));
  printf("  mov edx, [eax + __mcsema_reg_state@SECREL32 + %u]\n", __builtin_offsetof(mcsema::RegState, EDX));
  printf("  mov esi, [eax + __mcsema_reg_state@SECREL32 + %u]\n", __builtin_offsetof(mcsema::RegState, ESI));
  printf("  mov edi, [eax + __mcsema_reg_state@SECREL32 + %u]\n", __builtin_offsetof(mcsema::RegState, EDI));
  printf("  mov ebp, [eax + __mcsema_reg_state@SECREL32 + %u]\n", __builtin_offsetof(mcsema::RegState, EBP));

  // XMM registers.
  printf("  movdqu xmm0, [eax + __mcsema_reg_state@SECREL32 + %u]\n", __builtin_offsetof(mcsema::RegState, XMM0));
  printf("  movdqu xmm1, [eax + __mcsema_reg_state@SECREL32 + %u]\n", __builtin_offsetof(mcsema::RegState, XMM1));
  printf("  movdqu xmm2, [eax + __mcsema_reg_state@SECREL32 + %u]\n", __builtin_offsetof(mcsema::RegState, XMM2));
  printf("  movdqu xmm3, [eax + __mcsema_reg_state@SECREL32 + %u]\n", __builtin_offsetof(mcsema::RegState, XMM3));
  printf("  movdqu xmm4, [eax + __mcsema_reg_state@SECREL32 + %u]\n", __builtin_offsetof(mcsema::RegState, XMM4));
  printf("  movdqu xmm5, [eax + __mcsema_reg_state@SECREL32 + %u]\n", __builtin_offsetof(mcsema::RegState, XMM5));
  printf("  movdqu xmm6, [eax + __mcsema_reg_state@SECREL32 + %u]\n", __builtin_offsetof(mcsema::RegState, XMM6));
  printf("  movdqu xmm7, [eax + __mcsema_reg_state@SECREL32 + %u]\n", __builtin_offsetof(mcsema::RegState, XMM7));

  printf("  xchg DWORD PTR [eax + __mcsema_reg_state@SECREL32 + %u], esp\n", __builtin_offsetof(mcsema::RegState, ESP));


  // copy posible stack args from holding area to native stack
  // allocate space for our arguments on stack
  printf("  sub esp, %u\n", kStackArgSize);
  // we need to save these 
  printf("  push esi\n");
  printf("  push edi\n");
  printf("  push ecx\n");
  // get the stack arg location
  // compensate for esi+edi+ecx
  printf("  lea edi, [esp + %u]\n", 4+4+4);
  // source is temp area
  printf("  lea esi, [eax + __mcsema_stack_args@SECREL32]\n");
  printf("  mov ecx, %u\n", kStackArgSize);
  // copy
  printf("  rep movsb\n");

  // restore saved regs
  printf("  pop ecx\n");
  printf("  pop edi\n");
  printf("  pop esi\n");

  // save current ESP so we know how many bytes
  // the callee popped off the stack on return
  printf("  mov DWORD PTR [eax + __mcsema_stack_mark@SECREL32], esp\n");

  // Set up a re-attach return address.
  // clobber de7acccc on stack with attach by value RA
  // preserve eax
  printf("  mov [esp], eax\n");
  printf("  lea eax, __mcsema_attach_ret_value\n");
  printf("  xchg eax, [esp]\n");

  // Go native.
  printf("  jmp DWORD PTR [eax + __mcsema_reg_state@SECREL32 + %u]\n", __builtin_offsetof(mcsema::RegState, EIP));

  printf(".Lfunc_end5:\n");
  printf("  .cfi_endproc\n");
  printf("\n");

  // Implements `__mcsema_debug_get_reg_state`. This is useful when debugging in
  // gdb.
  printf("  .globl __mcsema_debug_get_reg_state\n");
  printf("__mcsema_debug_get_reg_state:\n");
  printf("  .cfi_startproc\n");
  getTlsIndex("eax");
  printf("  lea eax, [eax + __mcsema_reg_state@SECREL32]\n");
  printf("  ret\n");
  printf(".Lfunc_end6:\n");
  printf("  .cfi_endproc\n");
  printf("\n");

  ///////////////////////////////////////////////////////////////
  //
  //         __mcsema_detach_call_stdcall
  //
  ///////////////////////////////////////////////////////////////

  // Implements `__mcsema_detach_call_stdcall`. This partially goes from lifted code
  // into native code.
  printf("  .globl __mcsema_detach_call_stdcall\n");
  printf("__mcsema_detach_call_stdcall:\n");
  printf("  .cfi_startproc\n");

  // *** assume we can clobber eax

  // Pop the target function into the `RegState` structure. This resets `EIP`
  // to what it should be on entry to `__mcsema_detach_call_stdcall`.
  getTlsIndex("eax");
  printf("  pop DWORD PTR [eax + __mcsema_reg_state@SECREL32 + %u]\n", __builtin_offsetof(mcsema::RegState, EIP));
  // Marshal the callee-saved registers (of the emulated code) into the native
  // state. We don't touch the argument registers.

  // Stash the callee-saved registers.
  printf("  push edi\n");
  printf("  push esi\n");
  printf("  push ebx\n");
  printf("  push ebp\n");

  // save current stack mark
  printf("  push DWORD PTR [eax + __mcsema_stack_mark@SECREL32]\n");

  // do not clobber fastcall args
  printf("  push ecx\n");
  printf("  push edx\n");


  // copy posible stack args into temporary holding area
  printf("  lea edi, [eax + __mcsema_stack_args@SECREL32]\n");
  //  ra + stack_mark + (ecx + edx) +  (edi+esi+ebx+ebp)
  printf("  lea esi, [esp + %u]\n", 4 + 4 + 4+4 + 4+4+4+4);
  printf("  mov ecx, %u\n", kStackArgSize);
  printf("  rep movsb\n");

  // do not clobber fastcall args
  printf("  pop edx\n");
  printf("  pop ecx\n");

  printf("  mov edi, [eax + __mcsema_reg_state@SECREL32 + %u]\n", __builtin_offsetof(mcsema::RegState, EDI));
  printf("  mov esi, [eax + __mcsema_reg_state@SECREL32 + %u]\n", __builtin_offsetof(mcsema::RegState, ESI));
  printf("  mov ebx, [eax + __mcsema_reg_state@SECREL32 + %u]\n", __builtin_offsetof(mcsema::RegState, EBX));
  printf("  mov ebp, [eax + __mcsema_reg_state@SECREL32 + %u]\n", __builtin_offsetof(mcsema::RegState, EBP));

  // Swap onto the native stack.
  printf("  xchg DWORD PTR [eax + __mcsema_reg_state@SECREL32 + %u], esp\n", __builtin_offsetof(mcsema::RegState, ESP));

  // copy posible stack args from holding area to native stack
  // allocate space for our arguments on stack
  printf("  sub esp, %u\n", kStackArgSize);
  // we need to save these 
  printf("  push esi\n");
  printf("  push edi\n");
  printf("  push ecx\n");
  // get the stack arg location
  printf("  lea edi, [esp + %u]\n", 4+4+4);
  // source is temp area
  printf("  lea esi, [eax + __mcsema_stack_args@SECREL32]\n");
  printf("  mov ecx, %u\n", kStackArgSize);
  // copy
  printf("  rep movsb\n");

  // restore saved regs
  printf("  pop ecx\n");
  printf("  pop edi\n");
  printf("  pop esi\n");

  // save current ESP so we know how many bytes
  // the callee popped off the stack on return
  printf("  mov DWORD PTR [eax + __mcsema_stack_mark@SECREL32], esp\n");

  // Set up a re-attach return address.
  // do not push __mcsema_attach_ret_stdcall directly
  // to work around llvm assembler bug that emits it
  // as a 16-bit push
  printf("  push eax\n");
  printf("  lea eax, __mcsema_attach_ret_stdcall\n");
  printf("  xchg eax, [esp]\n");

  printf("  jmp DWORD PTR [eax + __mcsema_reg_state@SECREL32 + %u]\n", __builtin_offsetof(mcsema::RegState, EIP));

  printf(".Lfunc_endA:\n");
  printf("  .cfi_endproc\n");
  printf("\n");

  ///////////////////////////////////////////////////////////////
  //
  //         __mcsema_attach_ret_stdcall
  //
  ///////////////////////////////////////////////////////////////


  // Implements `__mcsema_attach_ret_stdcall`. This goes from native state into lifted code.
  printf("  .globl __mcsema_attach_ret_stdcall\n");
  printf("__mcsema_attach_ret_stdcall:\n");
  printf("  .cfi_startproc\n");

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
  getTlsIndex("ecx");
  
  // if this function had no args, this will be zero, otherwise
  // it will be -argcount*4 (esp is now > old esp, due to pops)
  printf("  sub DWORD PTR [ecx + __mcsema_stack_mark@SECREL32], esp\n");
  // adjust for our copied stack args + fake return
  printf("  add esp, %u\n", kStackArgSize+4);
  //printf("  add esp, DWORD PTR [ecx + __mcsema_stack_mark@SECREL32]\n");
  // Swap into the mcsema stack.
  printf("  xchg esp, DWORD PTR [ecx + __mcsema_reg_state@SECREL32 + %u]\n", __builtin_offsetof(mcsema::RegState, ESP));

  // Return registers.
  printf("  mov [ecx + __mcsema_reg_state@SECREL32 + %u], eax\n", __builtin_offsetof(mcsema::RegState, EAX));
  printf("  mov [ecx + __mcsema_reg_state@SECREL32 + %u], edx\n", __builtin_offsetof(mcsema::RegState, EDX));
  printf("  movdqu [ecx + __mcsema_reg_state@SECREL32 + %u], xmm0\n", __builtin_offsetof(mcsema::RegState, XMM0));

  // Callee-saved registers.
  printf("  mov [ecx + __mcsema_reg_state@SECREL32 + %u], ebp\n", __builtin_offsetof(mcsema::RegState, EBP));
  printf("  mov [ecx + __mcsema_reg_state@SECREL32 + %u], ebx\n", __builtin_offsetof(mcsema::RegState, EBX));
  printf("  mov [ecx + __mcsema_reg_state@SECREL32 + %u], esi\n", __builtin_offsetof(mcsema::RegState, ESI));
  printf("  mov [ecx + __mcsema_reg_state@SECREL32 + %u], edi\n", __builtin_offsetof(mcsema::RegState, EDI));

  printf("  mov ebp, ecx\n");
  // ecx is old stack mark we need for this function, to adjust stack after retn
  printf("  mov ecx, DWORD PTR [ecx + __mcsema_stack_mark@SECREL32]\n");
  // restore old stack mark
  printf("  pop DWORD PTR [ebp + __mcsema_stack_mark@SECREL32]\n");

  // Unstash the callee-saved registers.
  printf("  pop ebp\n");
  printf("  pop ebx\n");
  printf("  pop esi\n");
  printf("  pop edi\n");

  // adjust again for the poppped off arguments
  // this emulates a "retn XX", but that
  // only takes an immediate value
  printf("  sub esp, ecx\n"); // this sub is an add since ecx is negative
  printf("  add esp, 4\n"); // adjust for return address on stack

  // we still need to transfer control to the return addr on stack
  printf("  lea ecx, [esp+ecx]\n");
  printf("  jmp dword ptr [ecx-4]\n");

  printf(".Lfunc_end7:\n");
  printf("  .cfi_endproc\n");
  printf("\n");

  ///////////////////////////////////////////////////////////////
  //
  //         __mcsema_detach_call_fastcall
  //
  ///////////////////////////////////////////////////////////////

  // Implements `__mcsema_detach_call_fastcall`. This partially goes from lifted code
  // into native code.
  printf("  .globl __mcsema_detach_call_fastcall\n");
  printf("__mcsema_detach_call_fastcall:\n");
  printf("  .cfi_startproc\n");

  // stdcall takes care to save the fastcall regs, so these effectively become identical
  printf("  lea eax, __mcsema_detach_call_stdcall\n");
  printf("  jmp eax\n");

  printf(".Lfunc_end8:\n");
  printf("  .cfi_endproc\n");
  printf("\n");

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
  printf("  .globl __mcsema_attach_ret_fastcall\n");
  printf("__mcsema_attach_ret_fastcall:\n");
  printf("  .cfi_startproc\n");

  // awkwardly push/ret to __mcsema_attach_ret_stdcall
  // since it should be compatible with fastcall
  printf("  push eax\n");
  printf("  lea eax, __mcsema_attach_ret_stdcall\n");
  printf("  xchg eax, DWORD PTR [esp]\n");
  printf("  ret\n");

  printf(".Lfunc_end9:\n");
  printf("  .cfi_endproc\n");
  printf("\n");

  return 0;
}

