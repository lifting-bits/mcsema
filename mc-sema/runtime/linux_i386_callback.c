#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>

// build with 
// clang -std=gnu99 -m32 -emit-llvm -c -o linux_i386_callback.bc linux_i386_callback.c

#define ONLY_STRUCT
#include "../common/RegisterState.h"

#define MIN_STACK_SIZE 4096
#define NUM_DO_CALL_FRAMES 512 /* XXX what is reasonable here? */

// this is a terrible hack to be compatible with some mcsema definitions. please don't judge
extern uint32_t mmap(uint32_t addr, uint32_t length, uint32_t prot, uint32_t flags, uint32_t fd, uint32_t offset);
extern uint32_t munmap(uint32_t addr, uint32_t length);

// callback state
__thread RegState __mcsema_do_call_state;
// "pointer" to alternate stack
__thread uint32_t __mcsema_alt_stack = 0;

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

// RDI, RSI, RDX, RCX, R8, R9, XMM0–7, RBX, RBP, (maybe: RSP), R12, R13, R14, R15 
// are all preserved
__attribute__((naked)) int __mcsema_inception()
{
//    // for debugging; rax is assumed to be clobbered so we can do this
//    __asm__ volatile("movq $0xAABBCCDD, %r10\n");
//    __asm__ volatile("movq %%r10, %0\n": "=m"(__mcsema_do_call_state.RAX) );
//
//    // save preserved registers in struct regs
//    __asm__ volatile("movq %%rdi, %0\n": "=m"(__mcsema_do_call_state.RDI) );
//    __asm__ volatile("movq %%rsi, %0\n": "=m"(__mcsema_do_call_state.RSI) );
//    __asm__ volatile("movq %%rdx, %0\n": "=m"(__mcsema_do_call_state.RDX) );
//    __asm__ volatile("movq %%rcx, %0\n": "=m"(__mcsema_do_call_state.RCX) );
//    __asm__ volatile("movq %%rbx, %0\n": "=m"(__mcsema_do_call_state.RBX) );
//    __asm__ volatile("movq %%r8,  %0\n": "=m"(__mcsema_do_call_state.R8) );
//    __asm__ volatile("movq %%r9,  %0\n": "=m"(__mcsema_do_call_state.R9) );
//    __asm__ volatile("movq %%r12, %0\n": "=m"(__mcsema_do_call_state.R12) );
//    __asm__ volatile("movq %%r13, %0\n": "=m"(__mcsema_do_call_state.R13) );
//    __asm__ volatile("movq %%r14, %0\n": "=m"(__mcsema_do_call_state.R14) );
//    __asm__ volatile("movq %%r15, %0\n": "=m"(__mcsema_do_call_state.R15) );
//    __asm__ volatile("movq %%rbp, %0\n": "=m"(__mcsema_do_call_state.RBP) );
//
//    // save XMM
//    __asm__ volatile("movups %%xmm0, %0\n": "=m"(__mcsema_do_call_state.XMM0) );
//    __asm__ volatile("movups %%xmm1, %0\n": "=m"(__mcsema_do_call_state.XMM1) );
//    __asm__ volatile("movups %%xmm2, %0\n": "=m"(__mcsema_do_call_state.XMM2) );
//    __asm__ volatile("movups %%xmm3, %0\n": "=m"(__mcsema_do_call_state.XMM3) );
//    __asm__ volatile("movups %%xmm4, %0\n": "=m"(__mcsema_do_call_state.XMM4) );
//    __asm__ volatile("movups %%xmm5, %0\n": "=m"(__mcsema_do_call_state.XMM5) );
//    __asm__ volatile("movups %%xmm6, %0\n": "=m"(__mcsema_do_call_state.XMM6) );
//    __asm__ volatile("movups %%xmm7, %0\n": "=m"(__mcsema_do_call_state.XMM7) );
//
//
//    // copy over MIN_STACK_SIZE bytes of stack
//    // at this point we saved all the registers, so we can clobber at will
//    // since they are restored on function exit
//    __asm__ volatile("movq %0, %%rcx\n": : "i"(MIN_STACK_SIZE) );
//    __asm__ volatile("movq %rsp, %rsi\n");
//    __asm__ volatile("movq %0, %%rdi\n": : "m"(__mcsema_alt_stack));
//    
//    // force stack alignment to alignment of RSP
//    __asm__ volatile("movq %rsp, %r10\n");
//    __asm__ volatile("andq $0xF, %r10\n");
//    __asm__ volatile("subq $0x10, %rdi\n");
//    __asm__ volatile("addq %r10, %rdi\n");
//
//    // reserve space
//    __asm__ volatile("subq %0, %%rdi\n": : "i"(MIN_STACK_SIZE) );
//
//    // set RSP to the alt stack rsp
//    __asm__ volatile("movq %%rdi, %0\n": "=m"(__mcsema_do_call_state.RSP) );
//
//    // do memcpy
//    __asm__ volatile("cld\n");
//    __asm__ volatile("rep; movsb\n");
//
//    // call translated_function(reg_state);
//    __asm__ volatile("leaq %0, %%r10\n": : "m"(__mcsema_do_call_state) );
//    __asm__ volatile("leaq %fs:0, %r11\n");
//    __asm__ volatile("subq %r11, %r10\n");
//    __asm__ volatile("movq %fs:0, %rdi\n");
//    __asm__ volatile("leaq (%rdi,%r10,1), %rdi\n");
//    
//    // align stack for call
//    __asm__ volatile("subq $8, %rsp\n");
//
//    // call
//    __asm__ volatile("callq *%rax\n");
//
//    // undo align
//    __asm__ volatile("addq $8, %rsp\n");
//
//    // restore registers
//    __asm__ volatile("movq %0, %%rdi\n": : "m"(__mcsema_do_call_state.RDI) );
//    __asm__ volatile("movq %0, %%rsi\n": : "m"(__mcsema_do_call_state.RSI) );
//    __asm__ volatile("movq %0, %%rdx\n": : "m"(__mcsema_do_call_state.RDX) );
//    __asm__ volatile("movq %0, %%rcx\n": : "m"(__mcsema_do_call_state.RCX) );
//    __asm__ volatile("movq %0, %%rbx\n": : "m"(__mcsema_do_call_state.RBX) );
//    __asm__ volatile("movq %0, %%r8\n": : "m"(__mcsema_do_call_state.R8) );
//    __asm__ volatile("movq %0, %%r9\n": : "m"(__mcsema_do_call_state.R9) );
//    __asm__ volatile("movq %0, %%r12\n": : "m"(__mcsema_do_call_state.R12) );
//    __asm__ volatile("movq %0, %%r13\n": : "m"(__mcsema_do_call_state.R13) );
//    __asm__ volatile("movq %0, %%r14\n": : "m"(__mcsema_do_call_state.R14) );
//    __asm__ volatile("movq %0, %%r15\n": : "m"(__mcsema_do_call_state.R15) );
//    __asm__ volatile("movq %0, %%rbp\n": : "m"(__mcsema_do_call_state.RBP) );
//    // *do not* restore RSP, although this may be a bug
//
//    // restore XMM
//    __asm__ volatile("movups %0, %%xmm0\n": : "m"(__mcsema_do_call_state.XMM0) );
//    __asm__ volatile("movups %0, %%xmm1\n": : "m"(__mcsema_do_call_state.XMM1) );
//    __asm__ volatile("movups %0, %%xmm2\n": : "m"(__mcsema_do_call_state.XMM2) );
//    __asm__ volatile("movups %0, %%xmm3\n": : "m"(__mcsema_do_call_state.XMM3) );
//    __asm__ volatile("movups %0, %%xmm4\n": : "m"(__mcsema_do_call_state.XMM4) );
//    __asm__ volatile("movups %0, %%xmm5\n": : "m"(__mcsema_do_call_state.XMM5) );
//    __asm__ volatile("movups %0, %%xmm6\n": : "m"(__mcsema_do_call_state.XMM6) );
//    __asm__ volatile("movups %0, %%xmm7\n": : "m"(__mcsema_do_call_state.XMM7) );
//
//    // save return value into rax
//    __asm__ volatile("movq %0, %%rax\n": : "m"(__mcsema_do_call_state.RAX) );
//
//    __asm__ volatile("retq\n");
}

typedef struct _do_call_state_t {
    uint32_t __mcsema_real_esp;
    uint32_t __mcsema_jmp_count;
    char sse_state[512] __attribute__((aligned (16)));
    uint32_t reg_state[15];
} do_call_state_t;

__thread do_call_state_t do_call_state[NUM_DO_CALL_FRAMES];
__thread int32_t cur_do_call_frame = -1; /* XXX */
__thread uint32_t call_frame_counter = 0; /* XXX */

void do_call_value(void *state, uint32_t value)
{
    // get a clean frame to store state
    ++cur_do_call_frame;
    do_call_state_t *cs = &(do_call_state[cur_do_call_frame]);
    call_frame_counter = 0;
    cs->__mcsema_jmp_count = NUM_DO_CALL_FRAMES - cur_do_call_frame - 1;
    //uint32_t reg_state[] = cs->reg_state;

    __asm__ volatile(
            "pusha\n" // save all regs just so we don't have bother keeping track of what we saved
            "fxsave %0\n" // save sse state
            "movl %3, %%eax\n"  // capture "state" arg (mcsema regstate)
            "movl %4, %%ecx\n"  // capture "value" arg (call destination)
            "movl %2, %%esi\n" // pointer to TLS area where we save state
            "movl %c[state_edi](%%eax), %%edi\n" // dump struct regs to state
            "movl %c[state_edx](%%eax), %%edx\n"
            "movl %c[state_ebx](%%eax), %%ebx\n"
            "movl %c[state_ebp](%%eax), %%ebp\n"
            "movups %c[state_xmm0](%%eax), %%xmm0\n" // dump struct regs xmm state
            "movups %c[state_xmm1](%%eax), %%xmm1\n"
            "movups %c[state_xmm2](%%eax), %%xmm2\n"
            "movups %c[state_xmm3](%%eax), %%xmm3\n"
            "movups %c[state_xmm4](%%eax), %%xmm4\n"
            "movups %c[state_xmm5](%%eax), %%xmm5\n"
            "movups %c[state_xmm6](%%eax), %%xmm6\n"
            "movups %c[state_xmm7](%%eax), %%xmm7\n"
            "leal %c[real_esp_off](%%esi), %%esi\n" // where will we save the "real" esp?
            "movl %%esp, (%%esi)\n" // save our esp since we will switch to mcsema esp later
            "movl %c[state_esp](%%eax), %%esp\n" // switch to mcsema stack
            "addl $4, %%esp\n" // we pushed a fake return addr before, undo it
            "movl %%ecx, -4(%%esp)\n" // use that slot to store jump destination
            "movl %c[jmp_count](%%esi), %%ecx\n" // save recursion count into ecx
            "imull $7, %%ecx, %%ecx\n" //use that to calc how many INC instructions to skip
            "movl 0f, %%esi\n" // base return addr
            "addl %%ecx, %%esi\n" // calculate return addr
            "pushl %%esi\n" // push return addr
            "movl %c[state_ecx](%%eax), %%ecx\n" // complete struct regs spill
            "movl %c[state_esi](%%eax), %%esi\n"
            "movl %c[state_eax](%%eax), %%eax\n"
            "jmpl *-4(%%esp)\n"
            "0:\n"
            "incl %1\n" // set of jump locations that increment the call frame counter
            "incl %1\n" // the amount of these hit depends on the recursion depth
            "incl %1\n" // at depth 0, none are hit, at depth 1, there is 1, etc.
            "incl %1\n" // there are 512 incl entries
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "incl %1\n"
            "pushl %%eax\n" // save return value
            "pushl %%esi\n" // save temp reg
            "movl %1, %%eax\n" // get our recursion depth
            "imull %c[struct_size], %%eax\n" // see where we need to index into the save state array
            "addl %5, %%eax\n" // eax now points to our old saved state
            "leal %c[reg_state](%%eax), %%esi\n" // get reg state offset
            "movl %%ebx, %c[state_ebx](%%esi)\n" // convert native state to struct regs
            "movl %%ecx, %c[state_ecx](%%esi)\n" // convert native state to struct regs
            "movl %%edx, %c[state_edx](%%esi)\n" // convert native state to struct regs
            "movl %%edi, %c[state_edi](%%esi)\n" // convert native state to struct regs
            "movl %%ebp, %c[state_ebp](%%esi)\n" // convert native state to struct regs
            "movl %%eax, %%ebx\n" // already saved ebx, so lets use it as temp reg
            "movl %%esi, %%ecx\n" // already saved ecx, so lets use it as temp reg
            "popl %%esi\n" // get esi from function return
            "popl %%eax\n" // get eax from function return
            "movl %%eax, %c[state_eax](%%ecx)\n" // convert native state to struct regs
            "movl %%esi, %c[state_esi](%%ecx)\n" // convert native state to struct regs
            "movl %%esp, %c[state_esp](%%ecx)\n" // convert native state to struct regs
            "leal %c[real_esp_off](%%ebx), %%esi\n" // location of old native esp
            "movl (%%esi), %%esp\n" // return original stack
            "fxrstor %0\n"
            "popa\n"
            : "=m"(cs->sse_state), "=m"(call_frame_counter)
            : "m"(cs), "m"(state), "m"(value), "m"(do_call_state[0]),
                    [state_eax]"e"(offsetof(RegState, EAX)),
                    [state_ebx]"e"(offsetof(RegState, EBX)),
                    [state_ecx]"e"(offsetof(RegState, ECX)),
                    [state_edx]"e"(offsetof(RegState, EDX)),
                    [state_edi]"e"(offsetof(RegState, EDI)),
                    [state_esi]"e"(offsetof(RegState, ESI)),
                    [state_ebp]"e"(offsetof(RegState, EBP)),
                    [state_esp]"e"(offsetof(RegState, ESP)),
                    [state_xmm0]"e"(offsetof(RegState, XMM0)),
                    [state_xmm1]"e"(offsetof(RegState, XMM1)),
                    [state_xmm2]"e"(offsetof(RegState, XMM2)),
                    [state_xmm3]"e"(offsetof(RegState, XMM3)),
                    [state_xmm4]"e"(offsetof(RegState, XMM4)),
                    [state_xmm5]"e"(offsetof(RegState, XMM5)),
                    [state_xmm6]"e"(offsetof(RegState, XMM6)),
                    [state_xmm7]"e"(offsetof(RegState, XMM7)),
                    [real_esp_off]"e"(offsetof(do_call_state_t, __mcsema_real_esp)),
                    [jmp_count]"e"(offsetof(do_call_state_t, __mcsema_jmp_count)),
                    [reg_state]"e"(offsetof(do_call_state_t, reg_state)),
                    [sse_state]"e"(offsetof(do_call_state_t, sse_state)),
                    [struct_size]"e"(sizeof(do_call_state_t))
            : "memory", "eax", "ecx", "esi" );
    
    cur_do_call_frame--;
    call_frame_counter = 0;
}
