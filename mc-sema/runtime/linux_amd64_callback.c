#include <stdlib.h>
#include <stdint.h>

// build with 
// clang -std=gnu99 -m64 -emit-llvm -c -o linux_amd64_callback.bc linux_amd64_callback.c

#define ONLY_STRUCT
#include "../common/RegisterState.h"

#define MIN_STACK_SIZE 4096

// this is a terrible hack to be compatible with some mcsema definitions. please don't judge
extern uint64_t mmap(uint64_t addr, uint64_t length, uint32_t prot, uint32_t flags, uint32_t fd, uint32_t offset);
extern uint64_t munmap(uint64_t addr, uint64_t length);

// callback state
__thread RegState __mcsema_callback_state;
// "pointer" to alternate stack
__thread uint64_t __mcsema_alt_stack = 0;

void* __mcsema_create_alt_stack(size_t stack_size)
{
    // half for old stack to copy, half for stack to use in function
    if(stack_size < MIN_STACK_SIZE*2) {
        stack_size = MIN_STACK_SIZE*2;
    }
    __mcsema_alt_stack = mmap(0, stack_size, 3, 0x20022, -1, 0) + stack_size;
    return (void*)(__mcsema_alt_stack);
}

void __mcsema_free_alt_stack(size_t stack_size) {
    if(__mcsema_alt_stack != 0) {
        munmap(__mcsema_alt_stack-stack_size, stack_size);
    }
}

// RDI, RSI, RDX, RCX, R8, R9, XMM0–7, RBX, RBP, RSP, R12, R13, R14, R15 
// are all preserved
__attribute__((naked)) int __mcsema_inception()
{
    // for debugging; rax is assumed to be clobbered so we can do this
    __asm__ volatile("movq $0xAABBCCDD, %r10\n");
    __asm__ volatile("movq %%r10, %0\n": "=m"(__mcsema_callback_state.RAX) );

    // save preserved registers in struct regs
    __asm__ volatile("movq %%rdi, %0\n": "=m"(__mcsema_callback_state.RDI) );
    __asm__ volatile("movq %%rsi, %0\n": "=m"(__mcsema_callback_state.RSI) );
    __asm__ volatile("movq %%rdx, %0\n": "=m"(__mcsema_callback_state.RDX) );
    __asm__ volatile("movq %%rcx, %0\n": "=m"(__mcsema_callback_state.RCX) );
    __asm__ volatile("movq %%r8,  %0\n": "=m"(__mcsema_callback_state.R8) );
    __asm__ volatile("movq %%r9,  %0\n": "=m"(__mcsema_callback_state.R9) );
    __asm__ volatile("movq %%r12, %0\n": "=m"(__mcsema_callback_state.R12) );
    __asm__ volatile("movq %%r13, %0\n": "=m"(__mcsema_callback_state.R13) );
    __asm__ volatile("movq %%r14, %0\n": "=m"(__mcsema_callback_state.R14) );
    __asm__ volatile("movq %%r15, %0\n": "=m"(__mcsema_callback_state.R15) );

    // save XMM
    __asm__ volatile("movups %%xmm0, %0\n": "=m"(__mcsema_callback_state.XMM0) );
    __asm__ volatile("movups %%xmm1, %0\n": "=m"(__mcsema_callback_state.XMM1) );
    __asm__ volatile("movups %%xmm2, %0\n": "=m"(__mcsema_callback_state.XMM2) );
    __asm__ volatile("movups %%xmm3, %0\n": "=m"(__mcsema_callback_state.XMM3) );
    __asm__ volatile("movups %%xmm4, %0\n": "=m"(__mcsema_callback_state.XMM4) );
    __asm__ volatile("movups %%xmm5, %0\n": "=m"(__mcsema_callback_state.XMM5) );
    __asm__ volatile("movups %%xmm6, %0\n": "=m"(__mcsema_callback_state.XMM6) );
    __asm__ volatile("movups %%xmm7, %0\n": "=m"(__mcsema_callback_state.XMM7) );


    // copy over MIN_STACK_SIZE bytes of stack
    // at this point we saved all the registers, so we can clobber at will
    // since they are restored on function exit
    __asm__ volatile("movq %0, %%rcx\n": : "i"(MIN_STACK_SIZE) );
    __asm__ volatile("movq %rsp, %rsi\n");
    __asm__ volatile("movq %0, %%rdi\n": : "m"(__mcsema_alt_stack));
    __asm__ volatile("subq %0, %%rdi\n": : "i"(MIN_STACK_SIZE) );
    // set RSP to the alt stack rsp
    __asm__ volatile("movq %%rdi, %0\n": "=m"(__mcsema_callback_state.RSP) );
    __asm__ volatile("cld\n");
    __asm__ volatile("rep; movsb\n");

    // call translated_function(reg_state);
    __asm__ volatile("leaq %0, %%r10\n": : "m"(__mcsema_callback_state) );
    __asm__ volatile("leaq %fs:0, %r11\n");
    __asm__ volatile("subq %r11, %r10\n");
    __asm__ volatile("movq %fs:0, %rdi\n");
    __asm__ volatile("leaq (%rdi,%r10,1), %rdi\n");
    __asm__ volatile("callq *%rax\n");

    // restore registers
    __asm__ volatile("movq %0, %%rdi\n": : "m"(__mcsema_callback_state.RDI) );
    __asm__ volatile("movq %0, %%rsi\n": : "m"(__mcsema_callback_state.RSI) );
    __asm__ volatile("movq %0, %%rdx\n": : "m"(__mcsema_callback_state.RDX) );
    __asm__ volatile("movq %0, %%rcx\n": : "m"(__mcsema_callback_state.RCX) );
    __asm__ volatile("movq %0, %%r8\n": : "m"(__mcsema_callback_state.R8) );
    __asm__ volatile("movq %0, %%r9\n": : "m"(__mcsema_callback_state.R9) );
    __asm__ volatile("movq %0, %%r12\n": : "m"(__mcsema_callback_state.R12) );
    __asm__ volatile("movq %0, %%r13\n": : "m"(__mcsema_callback_state.R13) );
    __asm__ volatile("movq %0, %%r14\n": : "m"(__mcsema_callback_state.R14) );
    __asm__ volatile("movq %0, %%r15\n": : "m"(__mcsema_callback_state.R15) );
    // *do not* restore RSP, although this may be a bug

    // restore XMM
    __asm__ volatile("movups %0, %%xmm0\n": : "m"(__mcsema_callback_state.XMM0) );
    __asm__ volatile("movups %0, %%xmm1\n": : "m"(__mcsema_callback_state.XMM1) );
    __asm__ volatile("movups %0, %%xmm2\n": : "m"(__mcsema_callback_state.XMM2) );
    __asm__ volatile("movups %0, %%xmm3\n": : "m"(__mcsema_callback_state.XMM3) );
    __asm__ volatile("movups %0, %%xmm4\n": : "m"(__mcsema_callback_state.XMM4) );
    __asm__ volatile("movups %0, %%xmm5\n": : "m"(__mcsema_callback_state.XMM5) );
    __asm__ volatile("movups %0, %%xmm6\n": : "m"(__mcsema_callback_state.XMM6) );
    __asm__ volatile("movups %0, %%xmm7\n": : "m"(__mcsema_callback_state.XMM7) );

    // save return value into rax
    __asm__ volatile("movq %0, %%rax\n": : "m"(__mcsema_callback_state.RAX) );

    __asm__ volatile("retq\n");
}
