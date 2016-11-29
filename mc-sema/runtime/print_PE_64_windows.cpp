/* Copyright 2016 Trail of Bits */

#include <cstdio>

#define ONLY_STRUCT
#include "../common/RegisterState.h"

static const unsigned long long kStackSize = 1ULL << 20ULL;
static const unsigned long long kStackArgSize = 264ULL;

void getTlsIndex(const char dest_reg[]) {
  // store TLS index into dest_reg
  
  printf("push rdx\n");
	printf("mov	edx, DWORD ptr [rip + _tls_index]\n");
  // do this awkward mov via rdx since we need to get a 32-bit
  // value, and this helps us avoid figuring out the 32-bit 
  // component of the destination register
  printf("mov %s, rdx\n", dest_reg);
	printf("mov	rdx, QWORD ptr gs:[88]\n");
	printf("mov	%s, QWORD ptr [rdx + 8*%s]\n", dest_reg, dest_reg);
  printf("pop rdx\n");
}

void emitFunctionDef(const char func_name[]) {
	printf(".def	 %s;\n", func_name);
	printf(".scl	2;\n");
	printf(".type	32;\n");
	printf(".endef\n");
	printf(".globl %s\n", func_name);
  printf(".align 16, 0x90\n");
  printf("%s:\n", func_name);
}

int main(void) {

  printf("/* Auto-generated file! Don't modify! */\n\n");
  printf("  .intel_syntax noprefix\n");
  printf("\n");

  printf("  .section        .tls$,\"wd\"\n");
  printf("  .align 16\n");

  // Thread-local state structure, named by `__mcsema_reg_state`.
  printf("  .globl  __mcsema_reg_state\n");
  printf("  .align 16\n");
  printf("__mcsema_reg_state:\n");
  printf("  .zero   %llu\n", sizeof(mcsema::RegState));
  printf("\n");

  // Thread-local stack structure, named by `__mcsema_stack`.
  printf("  .globl  __mcsema_stack\n");
  printf("  .align 16\n");
  printf("__mcsema_stack:\n");
  printf("  .zero   %llu\n", kStackSize); // MiB
  printf("\n");

  // Thread-local stack structure, named by `__mcsema_stack_args`
  // used to store stack-passed function arguments
  printf("  .globl  __mcsema_stack_args\n");
  printf("  .align 16\n");
  printf("__mcsema_stack_args:\n");
  printf("  .zero   %llu\n", kStackArgSize);
  printf("\n");

  // Thread-local variable structure, named by `__mcsema_stack_mark`
  // used to store the expected stack location on return,
  // so caller cleanup conventions can know how many bytes to pop off
  printf("  .globl  __mcsema_stack_mark\n");
  printf("  .align 8\n");
  printf("__mcsema_stack_mark:\n");
  printf("  .zero   %u\n", 8);
  printf("\n");

  printf("  .text\n");
	printf("  .align	16, 0x90\n");
  printf("\n");

  ///////////////////////////////////////////////////////////////////////////////////
  //
  //  __mcsema_attach_call
  //
  ///////////////////////////////////////////////////////////////////////////////////

  // Implements `__mcsema_attach_call`. This goes from native state into lifted code.
  // The lifted code function pointer is already on the stack.
  emitFunctionDef("__mcsema_attach_call");

  // Pop the target function into the `RegState` structure. This resets `RSP`
  // to what it should be on entry to `__mcsema_attach_call`.
  //
  printf("  push QWORD ptr [rsp]\n"); // dupliate last stack element (the jump-to RIP), so we can pop it
  printf("  mov QWORD ptr [rsp+8], rbp\n"); // save rbp, we will clobber it
  getTlsIndex("rbp");
  printf("  pop QWORD PTR [rbp + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, RIP));
  printf("  mov [rbp + __mcsema_reg_state@SECREL32 + %llu], rax\n", __builtin_offsetof(mcsema::RegState, RAX));
  printf("  pop rbp\n"); // restore rbp to previous value. 
  getTlsIndex("rax"); // we can now clobber rax

  // General purpose registers.
  printf("  mov [rax + __mcsema_reg_state@SECREL32 + %llu], rbx\n", __builtin_offsetof(mcsema::RegState, RBX));
  printf("  mov [rax + __mcsema_reg_state@SECREL32 + %llu], rcx\n", __builtin_offsetof(mcsema::RegState, RCX));
  printf("  mov [rax + __mcsema_reg_state@SECREL32 + %llu], rdx\n", __builtin_offsetof(mcsema::RegState, RDX));
  printf("  mov [rax + __mcsema_reg_state@SECREL32 + %llu], rsi\n", __builtin_offsetof(mcsema::RegState, RSI));
  printf("  mov [rax + __mcsema_reg_state@SECREL32 + %llu], rdi\n", __builtin_offsetof(mcsema::RegState, RDI));
  printf("  mov [rax + __mcsema_reg_state@SECREL32 + %llu], rbp\n", __builtin_offsetof(mcsema::RegState, RBP));

  printf("  mov [rax + __mcsema_reg_state@SECREL32 + %llu], r8\n", __builtin_offsetof(mcsema::RegState, R8));
  printf("  mov [rax + __mcsema_reg_state@SECREL32 + %llu], r9\n", __builtin_offsetof(mcsema::RegState, R9));
  printf("  mov [rax + __mcsema_reg_state@SECREL32 + %llu], r10\n", __builtin_offsetof(mcsema::RegState, R10));
  printf("  mov [rax + __mcsema_reg_state@SECREL32 + %llu], r11\n", __builtin_offsetof(mcsema::RegState, R11));
  printf("  mov [rax + __mcsema_reg_state@SECREL32 + %llu], r12\n", __builtin_offsetof(mcsema::RegState, R12));
  printf("  mov [rax + __mcsema_reg_state@SECREL32 + %llu], r13\n", __builtin_offsetof(mcsema::RegState, R13));
  printf("  mov [rax + __mcsema_reg_state@SECREL32 + %llu], r14\n", __builtin_offsetof(mcsema::RegState, R14));
  printf("  mov [rax + __mcsema_reg_state@SECREL32 + %llu], r15\n", __builtin_offsetof(mcsema::RegState, R15));

  // XMM registers.
  printf("  movdqu [rax + __mcsema_reg_state@SECREL32 + %llu], xmm0\n", __builtin_offsetof(mcsema::RegState, XMM0));
  printf("  movdqu [rax + __mcsema_reg_state@SECREL32 + %llu], xmm1\n", __builtin_offsetof(mcsema::RegState, XMM1));
  printf("  movdqu [rax + __mcsema_reg_state@SECREL32 + %llu], xmm2\n", __builtin_offsetof(mcsema::RegState, XMM2));
  printf("  movdqu [rax + __mcsema_reg_state@SECREL32 + %llu], xmm3\n", __builtin_offsetof(mcsema::RegState, XMM3));
  printf("  movdqu [rax + __mcsema_reg_state@SECREL32 + %llu], xmm4\n", __builtin_offsetof(mcsema::RegState, XMM4));
  printf("  movdqu [rax + __mcsema_reg_state@SECREL32 + %llu], xmm5\n", __builtin_offsetof(mcsema::RegState, XMM5));
  printf("  movdqu [rax + __mcsema_reg_state@SECREL32 + %llu], xmm6\n", __builtin_offsetof(mcsema::RegState, XMM6));
  printf("  movdqu [rax + __mcsema_reg_state@SECREL32 + %llu], xmm7\n", __builtin_offsetof(mcsema::RegState, XMM7));
  printf("  movdqu [rax + __mcsema_reg_state@SECREL32 + %llu], xmm8\n", __builtin_offsetof(mcsema::RegState, XMM8));
  printf("  movdqu [rax + __mcsema_reg_state@SECREL32 + %llu], xmm9\n", __builtin_offsetof(mcsema::RegState, XMM9));
  printf("  movdqu [rax + __mcsema_reg_state@SECREL32 + %llu], xmm10\n", __builtin_offsetof(mcsema::RegState, XMM10));
  printf("  movdqu [rax + __mcsema_reg_state@SECREL32 + %llu], xmm11\n", __builtin_offsetof(mcsema::RegState, XMM11));
  printf("  movdqu [rax + __mcsema_reg_state@SECREL32 + %llu], xmm12\n", __builtin_offsetof(mcsema::RegState, XMM12));
  printf("  movdqu [rax + __mcsema_reg_state@SECREL32 + %llu], xmm13\n", __builtin_offsetof(mcsema::RegState, XMM13));
  printf("  movdqu [rax + __mcsema_reg_state@SECREL32 + %llu], xmm14\n", __builtin_offsetof(mcsema::RegState, XMM14));
  printf("  movdqu [rax + __mcsema_reg_state@SECREL32 + %llu], xmm15\n", __builtin_offsetof(mcsema::RegState, XMM15));

  printf("  xchg rsp, [rax + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, RSP));

  // If `RSP` is null then we need to initialize it to our new stack.
  printf("  cmp rsp, 0\n");
  printf("  jnz .Lhave_stack\n");
  // end inline getTlsIndex
  printf("  lea rsp, [rax + __mcsema_stack@SECREL32 + %llu]\n", kStackSize);
  printf(".Lhave_stack:\n");

  // the state struture is the first and only arg to lifted functions
  printf("  lea rcx, [rax + __mcsema_reg_state@SECREL32]\n");

  // set up return address
  printf("  lea rdx, [rip + __mcsema_detach_ret]\n");

  printf("  push rdx\n");

  // get RIP we need to jump to, in the process, clobber TLS index
  printf("  mov rax, QWORD PTR [rax + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, RIP));
  // and away we go!
  printf("  jmp rax\n");
  printf("\n");


  ///////////////////////////////////////////////////////////////////////////////////
  //
  //  __mcsema_attach_ret
  //
  ///////////////////////////////////////////////////////////////////////////////////

  // Implements `__mcsema_attach_ret`. This goes from native state into lifted code.
  // The lifted code function pointer is already on the stack.
  emitFunctionDef("__mcsema_attach_ret");

  // this should be valid for cdecl:
  // return stack to where it was before we pasted
  // some arguments to it, so the caller can clean
  // up as expected
  //
  // add an extra 8 bytes to compensate for the fake return address
  printf("  add rsp, %llu\n", kStackArgSize+8);
  // Swap into the mcsema stack.
  printf("push rax\n");
  getTlsIndex("rax");
  printf("  xchg rsp, [rax + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, RSP));
  // simulate a pop rax from old stack
  printf("  add QWORD ptr [rax + __mcsema_reg_state@SECREL32 + %llu], 8\n", __builtin_offsetof(mcsema::RegState, RSP));
  printf("  mov rax, QWORD ptr [rax + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, RSP));
  printf("  mov rax, QWORD ptr [rax-8]\n"); // use -8 here since we just added 8 to the old rsp to simulate a pop

  printf("  push rcx\n");
  getTlsIndex("rcx");
  // Return registers.
  printf("  mov [rcx + __mcsema_reg_state@SECREL32 + %llu], rax\n", __builtin_offsetof(mcsema::RegState, RAX));
  printf("  movdqu [rcx + __mcsema_reg_state@SECREL32 + %llu], xmm0\n", __builtin_offsetof(mcsema::RegState, XMM0));

  // Callee-saved registers.
  printf("  mov [rcx + __mcsema_reg_state@SECREL32 + %llu], rbx\n", __builtin_offsetof(mcsema::RegState, RBX));
  printf("  mov [rcx + __mcsema_reg_state@SECREL32 + %llu], rsi\n", __builtin_offsetof(mcsema::RegState, RSI));
  printf("  mov [rcx + __mcsema_reg_state@SECREL32 + %llu], rdi\n", __builtin_offsetof(mcsema::RegState, RDI));
  printf("  mov [rcx + __mcsema_reg_state@SECREL32 + %llu], rbp\n", __builtin_offsetof(mcsema::RegState, RBP));
  printf("  mov [rcx + __mcsema_reg_state@SECREL32 + %llu], r12\n", __builtin_offsetof(mcsema::RegState, R12));
  printf("  mov [rcx + __mcsema_reg_state@SECREL32 + %llu], r13\n", __builtin_offsetof(mcsema::RegState, R13));
  printf("  mov [rcx + __mcsema_reg_state@SECREL32 + %llu], r14\n", __builtin_offsetof(mcsema::RegState, R14));
  printf("  mov [rcx + __mcsema_reg_state@SECREL32 + %llu], r15\n", __builtin_offsetof(mcsema::RegState, R15));
  printf("  movdqu [rcx + __mcsema_reg_state@SECREL32 + %llu], xmm6\n", __builtin_offsetof(mcsema::RegState, XMM6));
  printf("  movdqu [rcx + __mcsema_reg_state@SECREL32 + %llu], xmm7\n", __builtin_offsetof(mcsema::RegState, XMM7));
  printf("  movdqu [rcx + __mcsema_reg_state@SECREL32 + %llu], xmm8\n", __builtin_offsetof(mcsema::RegState, XMM8));
  printf("  movdqu [rcx + __mcsema_reg_state@SECREL32 + %llu], xmm9\n", __builtin_offsetof(mcsema::RegState, XMM9));
  printf("  movdqu [rcx + __mcsema_reg_state@SECREL32 + %llu], xmm10\n", __builtin_offsetof(mcsema::RegState, XMM10));
  printf("  movdqu [rcx + __mcsema_reg_state@SECREL32 + %llu], xmm11\n", __builtin_offsetof(mcsema::RegState, XMM11));
  printf("  movdqu [rcx + __mcsema_reg_state@SECREL32 + %llu], xmm12\n", __builtin_offsetof(mcsema::RegState, XMM12));
  printf("  movdqu [rcx + __mcsema_reg_state@SECREL32 + %llu], xmm13\n", __builtin_offsetof(mcsema::RegState, XMM13));
  printf("  movdqu [rcx + __mcsema_reg_state@SECREL32 + %llu], xmm14\n", __builtin_offsetof(mcsema::RegState, XMM14));
  printf("  movdqu [rcx + __mcsema_reg_state@SECREL32 + %llu], xmm15\n", __builtin_offsetof(mcsema::RegState, XMM15));

  printf("  pop rcx\n");

  // Unstash the callee-saved registers.
  printf("  movdqu xmm6, [rsp+%llu]\n", 0*sizeof(mcsema::RegState::XMM6));
  printf("  movdqu xmm7, [rsp+%llu]\n", 1*sizeof(mcsema::RegState::XMM7));
  printf("  movdqu xmm8, [rsp+%llu]\n", 2*sizeof(mcsema::RegState::XMM8));
  printf("  movdqu xmm9, [rsp+%llu]\n", 3*sizeof(mcsema::RegState::XMM9));
  printf("  movdqu xmm10, [rsp+%llu]\n",4*sizeof(mcsema::RegState::XMM10));
  printf("  movdqu xmm11, [rsp+%llu]\n",5*sizeof(mcsema::RegState::XMM11));
  printf("  movdqu xmm12, [rsp+%llu]\n",6*sizeof(mcsema::RegState::XMM12));
  printf("  movdqu xmm13, [rsp+%llu]\n",7*sizeof(mcsema::RegState::XMM13));
  printf("  movdqu xmm14, [rsp+%llu]\n",8*sizeof(mcsema::RegState::XMM14));
  printf("  movdqu xmm15, [rsp+%llu]\n",9*sizeof(mcsema::RegState::XMM15));
  printf("  add rsp, %llu\n", sizeof(mcsema::RegState::XMM0)*10);
  printf("  pop rbx\n");
  printf("  pop rsi\n");
  printf("  pop rdi\n");
  printf("  pop rbp\n");
  printf("  pop r12\n");
  printf("  pop r13\n");
  printf("  pop r14\n");
  printf("  pop r15\n");
  printf("  ret\n");
  printf("\n");



  ///////////////////////////////////////////////////////////////////////////////////
  //
  //  __mcsema_attach_ret_value
  //
  ///////////////////////////////////////////////////////////////////////////////////

  // Implements `__mcsema_attach_ret_value`. This is the "opposite" of
  // `__mcsema_detach_call_value`.
  emitFunctionDef("__mcsema_attach_ret_value");
  printf("  push rbp\n");
  getTlsIndex("rbp");

  // General purpose registers.
  printf("  mov [rbp + __mcsema_reg_state@SECREL32 + %llu], rax\n", __builtin_offsetof(mcsema::RegState, RAX));
  printf("  mov [rbp + __mcsema_reg_state@SECREL32 + %llu], rbx\n", __builtin_offsetof(mcsema::RegState, RBX));
  printf("  mov [rbp + __mcsema_reg_state@SECREL32 + %llu], rcx\n", __builtin_offsetof(mcsema::RegState, RCX));
  printf("  mov [rbp + __mcsema_reg_state@SECREL32 + %llu], rdx\n", __builtin_offsetof(mcsema::RegState, RDX));
  printf("  mov [rbp + __mcsema_reg_state@SECREL32 + %llu], rsi\n", __builtin_offsetof(mcsema::RegState, RSI));
  printf("  mov [rbp + __mcsema_reg_state@SECREL32 + %llu], rdi\n", __builtin_offsetof(mcsema::RegState, RDI));

  printf("  mov [rbp + __mcsema_reg_state@SECREL32 + %llu], r8\n", __builtin_offsetof(mcsema::RegState, R8));
  printf("  mov [rbp + __mcsema_reg_state@SECREL32 + %llu], r9\n", __builtin_offsetof(mcsema::RegState, R9));
  printf("  mov [rbp + __mcsema_reg_state@SECREL32 + %llu], r10\n", __builtin_offsetof(mcsema::RegState, R10));
  printf("  mov [rbp + __mcsema_reg_state@SECREL32 + %llu], r11\n", __builtin_offsetof(mcsema::RegState, R11));
  printf("  mov [rbp + __mcsema_reg_state@SECREL32 + %llu], r12\n", __builtin_offsetof(mcsema::RegState, R12));
  printf("  mov [rbp + __mcsema_reg_state@SECREL32 + %llu], r13\n", __builtin_offsetof(mcsema::RegState, R13));
  printf("  mov [rbp + __mcsema_reg_state@SECREL32 + %llu], r14\n", __builtin_offsetof(mcsema::RegState, R14));
  printf("  mov [rbp + __mcsema_reg_state@SECREL32 + %llu], r15\n", __builtin_offsetof(mcsema::RegState, R15));

  // restore rbp
  printf("  pop rbp\n");

  // TODO(artem): check if we need to save rax
  getTlsIndex("rax");
  printf("  mov [rax + __mcsema_reg_state@SECREL32 + %llu], rbp\n", __builtin_offsetof(mcsema::RegState, RBP));
  // XMM registers.
  printf("  movdqu [rax + __mcsema_reg_state@SECREL32 + %llu], xmm0\n", __builtin_offsetof(mcsema::RegState, XMM0));
  printf("  movdqu [rax + __mcsema_reg_state@SECREL32 + %llu], xmm1\n", __builtin_offsetof(mcsema::RegState, XMM1));
  printf("  movdqu [rax + __mcsema_reg_state@SECREL32 + %llu], xmm2\n", __builtin_offsetof(mcsema::RegState, XMM2));
  printf("  movdqu [rax + __mcsema_reg_state@SECREL32 + %llu], xmm3\n", __builtin_offsetof(mcsema::RegState, XMM3));
  printf("  movdqu [rax + __mcsema_reg_state@SECREL32 + %llu], xmm4\n", __builtin_offsetof(mcsema::RegState, XMM4));
  printf("  movdqu [rax + __mcsema_reg_state@SECREL32 + %llu], xmm5\n", __builtin_offsetof(mcsema::RegState, XMM5));
  printf("  movdqu [rax + __mcsema_reg_state@SECREL32 + %llu], xmm6\n", __builtin_offsetof(mcsema::RegState, XMM6));
  printf("  movdqu [rax + __mcsema_reg_state@SECREL32 + %llu], xmm7\n", __builtin_offsetof(mcsema::RegState, XMM7));
  printf("  movdqu [rax + __mcsema_reg_state@SECREL32 + %llu], xmm8\n", __builtin_offsetof(mcsema::RegState, XMM8));
  printf("  movdqu [rax + __mcsema_reg_state@SECREL32 + %llu], xmm9\n", __builtin_offsetof(mcsema::RegState, XMM9));
  printf("  movdqu [rax + __mcsema_reg_state@SECREL32 + %llu], xmm10\n", __builtin_offsetof(mcsema::RegState, XMM10));
  printf("  movdqu [rax + __mcsema_reg_state@SECREL32 + %llu], xmm11\n", __builtin_offsetof(mcsema::RegState, XMM11));
  printf("  movdqu [rax + __mcsema_reg_state@SECREL32 + %llu], xmm12\n", __builtin_offsetof(mcsema::RegState, XMM12));
  printf("  movdqu [rax + __mcsema_reg_state@SECREL32 + %llu], xmm13\n", __builtin_offsetof(mcsema::RegState, XMM13));
  printf("  movdqu [rax + __mcsema_reg_state@SECREL32 + %llu], xmm14\n", __builtin_offsetof(mcsema::RegState, XMM14));
  printf("  movdqu [rax + __mcsema_reg_state@SECREL32 + %llu], xmm15\n", __builtin_offsetof(mcsema::RegState, XMM15));

  // if this function had no args, this will be zero, otherwise
  // it will be -argcount*8 (rsp is now > old rsp, due to pops)
  printf("  sub QWORD PTR [rax + __mcsema_stack_mark@SECREL32], rsp\n");
  // TODO(artem) check if we can clobber rcx
  printf("  mov rcx, QWORD PTR [rax + __mcsema_stack_mark@SECREL32]\n");

  // adjust for our copied stack args + fake return (we copied kStackArgSize-8 before)
  printf("  add rsp, %llu\n", kStackArgSize);
  printf("  add rsp, rcx\n");

  printf("  xchg rsp, QWORD PTR [rax + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, RSP));

  printf("  pop QWORD PTR [rax + __mcsema_stack_mark@SECREL32]\n");
  // Unstash the callee-saved registers.
  printf("  movdqu xmm6, [rsp+%llu]\n", 0*sizeof(mcsema::RegState::XMM6));
  printf("  movdqu xmm7, [rsp+%llu]\n", 1*sizeof(mcsema::RegState::XMM7));
  printf("  movdqu xmm8, [rsp+%llu]\n", 2*sizeof(mcsema::RegState::XMM8));
  printf("  movdqu xmm9, [rsp+%llu]\n", 3*sizeof(mcsema::RegState::XMM9));
  printf("  movdqu xmm10, [rsp+%llu]\n",4*sizeof(mcsema::RegState::XMM10));
  printf("  movdqu xmm11, [rsp+%llu]\n",5*sizeof(mcsema::RegState::XMM11));
  printf("  movdqu xmm12, [rsp+%llu]\n",6*sizeof(mcsema::RegState::XMM12));
  printf("  movdqu xmm13, [rsp+%llu]\n",7*sizeof(mcsema::RegState::XMM13));
  printf("  movdqu xmm14, [rsp+%llu]\n",8*sizeof(mcsema::RegState::XMM14));
  printf("  movdqu xmm15, [rsp+%llu]\n",9*sizeof(mcsema::RegState::XMM15));
  printf("  add rsp, %llu\n", sizeof(mcsema::RegState::XMM0)*10);
  printf("  pop rbx\n");
  printf("  pop rsi\n");
  printf("  pop rdi\n");
  printf("  pop rbp\n");
  printf("  pop r12\n");
  printf("  pop r13\n");
  printf("  pop r14\n");
  printf("  pop r15\n");

  printf("  ret\n");
  printf("\n");

  ///////////////////////////////////////////////////////////////////////////////////
  //
  //  __mcsema_detach_ret
  //
  ///////////////////////////////////////////////////////////////////////////////////

  // Implements `__mcsema_detach_ret`. This goes from lifted code into native code.
  // The native code pointer is located at the native `[RegState::RSP - 8]`
  // address.
  emitFunctionDef("__mcsema_detach_ret");

  // General purpose registers.
  //
  printf("  push rbp\n");
  getTlsIndex("rbp");
  printf("  mov rax, [rbp + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, RAX));
  printf("  mov rbx, [rbp + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, RBX));
  printf("  mov rcx, [rbp + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, RCX));
  printf("  mov rdx, [rbp + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, RDX));
  printf("  mov rsi, [rbp + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, RSI));
  printf("  mov rdi, [rbp + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, RDI));

  printf("  mov r8,  [rbp + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, R8));
  printf("  mov r9,  [rbp + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, R9));
  printf("  mov r10, [rbp + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, R10));
  printf("  mov r11, [rbp + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, R11));
  printf("  mov r12, [rbp + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, R12));
  printf("  mov r13, [rbp + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, R13));
  printf("  mov r14, [rbp + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, R14));
  printf("  mov r15, [rbp + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, R15));
  // XMM registers.
  printf("  movdqu xmm0, [rbp + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, XMM0));
  printf("  movdqu xmm1, [rbp + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, XMM1));
  printf("  movdqu xmm2, [rbp + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, XMM2));
  printf("  movdqu xmm3, [rbp + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, XMM3));
  printf("  movdqu xmm4, [rbp + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, XMM4));
  printf("  movdqu xmm5, [rbp + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, XMM5));
  printf("  movdqu xmm6, [rbp + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, XMM6));
  printf("  movdqu xmm7, [rbp + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, XMM7));
  
  printf("  movdqu xmm8,  [rbp + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, XMM8));
  printf("  movdqu xmm9,  [rbp + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, XMM9));
  printf("  movdqu xmm10, [rbp + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, XMM10));
  printf("  movdqu xmm11, [rbp + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, XMM11));
  printf("  movdqu xmm12, [rbp + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, XMM12));
  printf("  movdqu xmm13, [rbp + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, XMM13));
  printf("  movdqu xmm14, [rbp + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, XMM14));
  printf("  movdqu xmm15, [rbp + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, XMM15));

  printf("  pop rbp\n");

  printf("  push rax\n");
  getTlsIndex("rax");
  printf("  mov rbp, [rax + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, RBP));

  // The lifted code emulated a ret, which did incremented `rsp` by 8.
  // We "undo" that, then swap back to the native stack. When we swap, we
  // save into `RegState::RSP` where we are in the lifted stack, so that the
  // next attach can continue on where we left off.
  printf("  sub QWORD PTR [rax + __mcsema_reg_state@SECREL32 + %llu], 8\n", __builtin_offsetof(mcsema::RegState, RSP));
  printf("  xchg rsp, QWORD PTR [rax + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, RSP));
  // simulate a pop rax from old stack
  printf("  add QWORD ptr [rax + __mcsema_reg_state@SECREL32 + %llu], 8\n", __builtin_offsetof(mcsema::RegState, RSP));
  printf("  mov rax, qword ptr [rax + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, RSP));
  printf("  mov rax, qword ptr [rax-8]\n"); // use -8 here since we just added 8 to the old rsp to simulate a pop


  printf("  ret\n");
  printf("\n");

  ///////////////////////////////////////////////////////////////////////////////////
  //
  //  __mcsema_detach_call
  //
  ///////////////////////////////////////////////////////////////////////////////////
  // Implements `__mcsema_detach_call`. This partially goes from lifted code
  // into native code.
  emitFunctionDef("__mcsema_detach_call");

  // *** This function assumes we can clobber rax
  
  // clobber rax to use as TLS index
  getTlsIndex("rax");
  // Pop the target function into the `RegState` structure. This resets `RIP`
  // to what it should be on entry to `__mcsema_detach_call`.
  printf("  pop QWORD PTR [rax + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, RIP));
  // Marshal the callee-saved registers (of the emulated code) into the native
  // state. We don't touch the argument registers.

  // Stash the callee-saved registers.
  printf("  push r15\n");
  printf("  push r14\n");
  printf("  push r13\n");
  printf("  push r12\n");
  printf("  push rbp\n");
  printf("  push rdi\n");
  printf("  push rsi\n");
  printf("  push rbx\n");
  printf("  sub rsp, %llu\n", sizeof(mcsema::RegState::XMM0)*10);
  printf("  movdqu  [rsp+%llu], xmm6 \n", 0*sizeof(mcsema::RegState::XMM6));
  printf("  movdqu  [rsp+%llu], xmm7 \n", 1*sizeof(mcsema::RegState::XMM7));
  printf("  movdqu  [rsp+%llu], xmm8 \n", 2*sizeof(mcsema::RegState::XMM8));
  printf("  movdqu  [rsp+%llu], xmm9 \n", 3*sizeof(mcsema::RegState::XMM9));
  printf("  movdqu  [rsp+%llu], xmm10\n", 4*sizeof(mcsema::RegState::XMM10));
  printf("  movdqu  [rsp+%llu], xmm11\n", 5*sizeof(mcsema::RegState::XMM11));
  printf("  movdqu  [rsp+%llu], xmm12\n", 6*sizeof(mcsema::RegState::XMM12));
  printf("  movdqu  [rsp+%llu], xmm13\n", 7*sizeof(mcsema::RegState::XMM13));
  printf("  movdqu  [rsp+%llu], xmm14\n", 8*sizeof(mcsema::RegState::XMM14));
  printf("  movdqu  [rsp+%llu], xmm15\n", 9*sizeof(mcsema::RegState::XMM15));


  // copy posible stack args into temporary holding area
  printf("  lea rdi, [rax + __mcsema_stack_args@SECREL32]\n");
  // stack args start after return address + callee saved GPRs + callee saved XMM
  printf("  lea rsi, [rsp + %llu]\n", 8 + 8*8 + sizeof(mcsema::RegState::XMM0)*10);
  // rcx is how much to copy
  printf("  mov rcx, %llu\n", kStackArgSize);
  // do the copy
  printf("  rep movsb\n");

  // restore arguments and callee-saved regs
  printf("  mov rsi, [rax + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, RSI));
  printf("  mov rdi, [rax + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, RDI));
  printf("  mov rbx, [rax + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, RBX));
  printf("  mov rbp, [rax + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, RBP));
  printf("  mov rcx, [rax + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, RCX));
  printf("  mov r12, [rax + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, R12));
  printf("  mov r13, [rax + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, R13));
  printf("  mov r14, [rax + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, R14));
  printf("  mov r15, [rax + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, R15));

  // Swap onto the native stack.
  printf("  xchg QWORD PTR [rax + __mcsema_reg_state@SECREL32 + %llu], rsp\n", __builtin_offsetof(mcsema::RegState, RSP));

  // copy posible stack args from holding area to native stack
  // allocate space for our arguments on stack
  printf("  sub rsp, %llu\n", kStackArgSize);
  // we need to save these 
  printf("  push rsi\n");
  printf("  push rdi\n");
  printf("  push rcx\n");
  // get the stack arg location, adjust for the just-pushed values
  printf("  lea rdi, [rsp + %u]\n", 8+8+8);
  // source is temp area
  printf("  lea rsi, [rax + __mcsema_stack_args@SECREL32]\n");
  printf("  mov rcx, %llu\n", kStackArgSize);
  // copy stack args from temp area to new stack
  printf("  rep movsb\n");

  // restore saved regs
  printf("  pop rcx\n");
  printf("  pop rdi\n");
  printf("  pop rsi\n");

  // Set up a re-attach return address.
  // do not push __mcsema_attach_ret directly
  // to work around llvm assembler bug that emits it
  // as a 16-bit push
  printf("  push rax\n");
  printf("  lea rax, [rip + __mcsema_attach_ret]\n");
  // switched saved rax (TLS index) with current rax (pointer to function)
  // the pointer to function will be the first argument to the mcsema-xlated
  // code we are about to jump to
  printf("  xchg rax, [rsp]\n");

  printf("  jmp QWORD PTR [rax + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, RIP));


  printf("\n");

  ///////////////////////////////////////////////////////////////////////////////////
  //
  //  __mcsema_detach_call_value
  //
  ///////////////////////////////////////////////////////////////////////////////////
  // Implements `__mcsema_detach_call_value`. This is a thin wrapper around
  // `__mcsema_detach_call`.
  emitFunctionDef("__mcsema_detach_call_value");

  // Note: the bitcode has already put the target address into `RegState::RIP`.
  // *** assumes we can clobber rax

  // Stash the callee-saved registers.
  printf("  push r15\n");
  printf("  push r14\n");
  printf("  push r13\n");
  printf("  push r12\n");
  printf("  push rbp\n");
  printf("  push rdi\n");
  printf("  push rsi\n");
  printf("  push rbx\n");
  printf("  sub rsp, %llu\n", sizeof(mcsema::RegState::XMM0)*10);
  printf("  movdqu  [rsp+%llu], xmm6 \n", 0*sizeof(mcsema::RegState::XMM6));
  printf("  movdqu  [rsp+%llu], xmm7 \n", 1*sizeof(mcsema::RegState::XMM7));
  printf("  movdqu  [rsp+%llu], xmm8 \n", 2*sizeof(mcsema::RegState::XMM8));
  printf("  movdqu  [rsp+%llu], xmm9 \n", 3*sizeof(mcsema::RegState::XMM9));
  printf("  movdqu  [rsp+%llu], xmm10\n", 4*sizeof(mcsema::RegState::XMM10));
  printf("  movdqu  [rsp+%llu], xmm11\n", 5*sizeof(mcsema::RegState::XMM11));
  printf("  movdqu  [rsp+%llu], xmm12\n", 6*sizeof(mcsema::RegState::XMM12));
  printf("  movdqu  [rsp+%llu], xmm13\n", 7*sizeof(mcsema::RegState::XMM13));
  printf("  movdqu  [rsp+%llu], xmm14\n", 8*sizeof(mcsema::RegState::XMM14));
  printf("  movdqu  [rsp+%llu], xmm15\n", 9*sizeof(mcsema::RegState::XMM15));

  getTlsIndex("rax");
  // save current stack mark
  printf("  push QWORD PTR [rax + __mcsema_stack_mark@SECREL32]\n");

  // copy posible stack args into temporary holding area
  printf("  lea rdi, [rax + __mcsema_stack_args@SECREL32]\n");
  // this is not RSP since for do_call_value there is no spilling via an 
  // intermediate function
  printf("  mov rsi, QWORD PTR [rax + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, RSP));
  // use -8 since we have a ret addr on stack already and need alignment
  printf("  mov rcx, %llu\n", kStackArgSize-8);
  printf("  rep movsb\n");

  // we wil use rbp to index once we clobber rax
  printf("  mov rbp, rax\n");
  // we still read out rax on principle, in case we need to do debugging
  // but we clobber it later anyway, so... ignore it
  printf("  mov rax, [rbp + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, RAX));
  printf("  mov rax, rbp\n");
  printf("  mov rbx, [rax + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, RBX));
  printf("  mov rcx, [rax + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, RCX));
  printf("  mov rdx, [rax + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, RDX));
  printf("  mov rsi, [rax + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, RSI));
  printf("  mov rdi, [rax + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, RDI));
  printf("  mov rbp, [rax + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, RBP));

  printf("  mov r8,  [rax + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, R8));
  printf("  mov r9,  [rax + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, R9));
  printf("  mov r10, [rax + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, R10));
  printf("  mov r11, [rax + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, R11));
  printf("  mov r12, [rax + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, R12));
  printf("  mov r13, [rax + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, R13));
  printf("  mov r14, [rax + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, R14));
  printf("  mov r15, [rax + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, R15));
  // XMM registers.
  printf("  movdqu xmm0, [rax + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, XMM0));
  printf("  movdqu xmm1, [rax + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, XMM1));
  printf("  movdqu xmm2, [rax + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, XMM2));
  printf("  movdqu xmm3, [rax + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, XMM3));
  printf("  movdqu xmm4, [rax + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, XMM4));
  printf("  movdqu xmm5, [rax + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, XMM5));
  printf("  movdqu xmm6, [rax + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, XMM6));
  printf("  movdqu xmm7, [rax + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, XMM7));
  
  printf("  movdqu xmm8,  [rax + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, XMM8));
  printf("  movdqu xmm9,  [rax + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, XMM9));
  printf("  movdqu xmm10, [rax + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, XMM10));
  printf("  movdqu xmm11, [rax + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, XMM11));
  printf("  movdqu xmm12, [rax + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, XMM12));
  printf("  movdqu xmm13, [rax + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, XMM13));
  printf("  movdqu xmm14, [rax + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, XMM14));
  printf("  movdqu xmm15, [rax + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, XMM15));

  printf("  xchg QWORD PTR [rax + __mcsema_reg_state@SECREL32 + %llu], rsp\n", __builtin_offsetof(mcsema::RegState, RSP));

  // copy posible stack args from holding area to native stack
  // allocate space for our arguments on stack
  // use -8 since we have a ret addr on stack already and need alignment
  printf("  sub rsp, %llu\n", kStackArgSize-8);
  // we need to save these 
  printf("  push rsi\n");
  printf("  push rdi\n");
  printf("  push rcx\n");
  // get the stack arg location
  // compensate for rsi+rdi+rcx
  printf("  lea rdi, [rsp + %u]\n", 8+8+8);
  // source is temp area
  printf("  lea rsi, [rax + __mcsema_stack_args@SECREL32]\n");
  // use -8 since we have a ret addr on stack already and need alignment
  printf("  mov rcx, %llu\n", kStackArgSize-8);
  // copy
  printf("  rep movsb\n");

  // restore saved regs
  printf("  pop rcx\n");
  printf("  pop rdi\n");
  printf("  pop rsi\n");

  // save current RSP so we know how many bytes
  // the callee popped off the stack on return
  printf("  mov QWORD PTR [rax + __mcsema_stack_mark@SECREL32], rsp\n");

  // Set up a re-attach return address.
  // clobber de7acccc on stack with attach by value RA
  // preserve rax
  printf("  mov [rsp], rax\n");
  printf("  lea rax, [rip + __mcsema_attach_ret_value]\n");
  printf("  xchg rax, [rsp]\n");

  // Go native.
  printf("  jmp QWORD PTR [rax + __mcsema_reg_state@SECREL32 + %llu]\n", __builtin_offsetof(mcsema::RegState, RIP));
  printf("\n");

  ///////////////////////////////////////////////////////////////////////////////////
  //
  //  __mcsema_debug_get_reg_state
  //
  ///////////////////////////////////////////////////////////////////////////////////
  // Implements `__mcsema_debug_get_reg_state`. This is useful when debugging in
  // gdb.
  emitFunctionDef("__mcsema_debug_get_reg_state");
  getTlsIndex("rax");
  printf("  lea rax, [rax + __mcsema_reg_state@SECREL32]\n");
  printf("  ret\n");
  printf("\n");
  return 0;
}
