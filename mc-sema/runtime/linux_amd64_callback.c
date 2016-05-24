#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>

// build with 
// clang -std=gnu99 -m64 -emit-llvm -c -o linux_amd64_callback.bc linux_amd64_callback.c

#define ONLY_STRUCT
#include "../common/RegisterState.h"

#define MIN_STACK_SIZE 4096
#define NUM_DO_CALL_FRAMES 512 /* XXX what is reasonable here? */

// this is a terrible hack to be compatible with some mcsema definitions. please don't judge
extern uint64_t mmap(uint64_t addr, uint64_t length, uint32_t prot, uint32_t flags, uint32_t fd, uint32_t offset);
extern uint64_t munmap(uint64_t addr, uint64_t length);

// callback state
__thread RegState __mcsema_do_call_state;
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

// RDI, RSI, RDX, RCX, R8, R9, XMM0–7, RBX, RBP, (maybe: RSP), R12, R13, R14, R15 
// are all preserved
__attribute__((naked)) int __mcsema_inception()
{
    // for debugging; rax is assumed to be clobbered so we can do this
    __asm__ volatile("movq $0xAABBCCDD, %r10\n");
    __asm__ volatile("movq %%r10, %0\n": "=m"(__mcsema_do_call_state.RAX) );

    // save preserved registers in struct regs
    __asm__ volatile("movq %%rdi, %0\n": "=m"(__mcsema_do_call_state.RDI) );
    __asm__ volatile("movq %%rsi, %0\n": "=m"(__mcsema_do_call_state.RSI) );
    __asm__ volatile("movq %%rdx, %0\n": "=m"(__mcsema_do_call_state.RDX) );
    __asm__ volatile("movq %%rcx, %0\n": "=m"(__mcsema_do_call_state.RCX) );
    __asm__ volatile("movq %%rbx, %0\n": "=m"(__mcsema_do_call_state.RBX) );
    __asm__ volatile("movq %%r8,  %0\n": "=m"(__mcsema_do_call_state.R8) );
    __asm__ volatile("movq %%r9,  %0\n": "=m"(__mcsema_do_call_state.R9) );
    __asm__ volatile("movq %%r12, %0\n": "=m"(__mcsema_do_call_state.R12) );
    __asm__ volatile("movq %%r13, %0\n": "=m"(__mcsema_do_call_state.R13) );
    __asm__ volatile("movq %%r14, %0\n": "=m"(__mcsema_do_call_state.R14) );
    __asm__ volatile("movq %%r15, %0\n": "=m"(__mcsema_do_call_state.R15) );
    __asm__ volatile("movq %%rbp, %0\n": "=m"(__mcsema_do_call_state.RBP) );

    // save XMM
    __asm__ volatile("movups %%xmm0, %0\n": "=m"(__mcsema_do_call_state.XMM0) );
    __asm__ volatile("movups %%xmm1, %0\n": "=m"(__mcsema_do_call_state.XMM1) );
    __asm__ volatile("movups %%xmm2, %0\n": "=m"(__mcsema_do_call_state.XMM2) );
    __asm__ volatile("movups %%xmm3, %0\n": "=m"(__mcsema_do_call_state.XMM3) );
    __asm__ volatile("movups %%xmm4, %0\n": "=m"(__mcsema_do_call_state.XMM4) );
    __asm__ volatile("movups %%xmm5, %0\n": "=m"(__mcsema_do_call_state.XMM5) );
    __asm__ volatile("movups %%xmm6, %0\n": "=m"(__mcsema_do_call_state.XMM6) );
    __asm__ volatile("movups %%xmm7, %0\n": "=m"(__mcsema_do_call_state.XMM7) );


    // copy over MIN_STACK_SIZE bytes of stack
    // at this point we saved all the registers, so we can clobber at will
    // since they are restored on function exit
    __asm__ volatile("movq %0, %%rcx\n": : "i"(MIN_STACK_SIZE) );
    __asm__ volatile("movq %rsp, %rsi\n");
    __asm__ volatile("movq %0, %%rdi\n": : "m"(__mcsema_alt_stack));
    
    // force stack alignment to alignment of RSP
    __asm__ volatile("movq %rsp, %r10\n");
    __asm__ volatile("andq $0xF, %r10\n");
    __asm__ volatile("subq $0x10, %rdi\n");
    __asm__ volatile("addq %r10, %rdi\n");

    // reserve space
    __asm__ volatile("subq %0, %%rdi\n": : "i"(MIN_STACK_SIZE) );

    // set RSP to the alt stack rsp
    __asm__ volatile("movq %%rdi, %0\n": "=m"(__mcsema_do_call_state.RSP) );

    // do memcpy
    __asm__ volatile("cld\n");
    __asm__ volatile("rep; movsb\n");

    // call translated_function(reg_state);
    __asm__ volatile("leaq %0, %%r10\n": : "m"(__mcsema_do_call_state) );
    __asm__ volatile("leaq %fs:0, %r11\n");
    __asm__ volatile("subq %r11, %r10\n");
    __asm__ volatile("movq %fs:0, %rdi\n");
    __asm__ volatile("leaq (%rdi,%r10,1), %rdi\n");
    
    // align stack for call
    __asm__ volatile("subq $8, %rsp\n");

    // call
    __asm__ volatile("callq *%rax\n");

    // undo align
    __asm__ volatile("addq $8, %rsp\n");

    // restore registers
    __asm__ volatile("movq %0, %%rdi\n": : "m"(__mcsema_do_call_state.RDI) );
    __asm__ volatile("movq %0, %%rsi\n": : "m"(__mcsema_do_call_state.RSI) );
    __asm__ volatile("movq %0, %%rdx\n": : "m"(__mcsema_do_call_state.RDX) );
    __asm__ volatile("movq %0, %%rcx\n": : "m"(__mcsema_do_call_state.RCX) );
    __asm__ volatile("movq %0, %%rbx\n": : "m"(__mcsema_do_call_state.RBX) );
    __asm__ volatile("movq %0, %%r8\n": : "m"(__mcsema_do_call_state.R8) );
    __asm__ volatile("movq %0, %%r9\n": : "m"(__mcsema_do_call_state.R9) );
    __asm__ volatile("movq %0, %%r12\n": : "m"(__mcsema_do_call_state.R12) );
    __asm__ volatile("movq %0, %%r13\n": : "m"(__mcsema_do_call_state.R13) );
    __asm__ volatile("movq %0, %%r14\n": : "m"(__mcsema_do_call_state.R14) );
    __asm__ volatile("movq %0, %%r15\n": : "m"(__mcsema_do_call_state.R15) );
    __asm__ volatile("movq %0, %%rbp\n": : "m"(__mcsema_do_call_state.RBP) );
    // *do not* restore RSP, although this may be a bug

    // restore XMM
    __asm__ volatile("movups %0, %%xmm0\n": : "m"(__mcsema_do_call_state.XMM0) );
    __asm__ volatile("movups %0, %%xmm1\n": : "m"(__mcsema_do_call_state.XMM1) );
    __asm__ volatile("movups %0, %%xmm2\n": : "m"(__mcsema_do_call_state.XMM2) );
    __asm__ volatile("movups %0, %%xmm3\n": : "m"(__mcsema_do_call_state.XMM3) );
    __asm__ volatile("movups %0, %%xmm4\n": : "m"(__mcsema_do_call_state.XMM4) );
    __asm__ volatile("movups %0, %%xmm5\n": : "m"(__mcsema_do_call_state.XMM5) );
    __asm__ volatile("movups %0, %%xmm6\n": : "m"(__mcsema_do_call_state.XMM6) );
    __asm__ volatile("movups %0, %%xmm7\n": : "m"(__mcsema_do_call_state.XMM7) );

    // save return value into rax
    __asm__ volatile("movq %0, %%rax\n": : "m"(__mcsema_do_call_state.RAX) );

    __asm__ volatile("retq\n");
}

typedef struct _do_call_state_t {
    uint64_t __mcsema_real_rsp;
    uint64_t __mcsema_saved_rax;
    char sse_state[512] __attribute__((aligned (16)));
    uint64_t reg_state[15];
} do_call_state_t;

__thread do_call_state_t do_call_state[NUM_DO_CALL_FRAMES];
__thread int32_t cur_do_call_frame = -1; /* XXX */

void do_call_value(void *state, uint64_t value)
{
    // get a clean frame to store state
    cur_do_call_frame++;
    uint64_t reg_state[] = do_call_state[cur_do_call_frame].reg_state;
    
    // preserve current reg state
    __asm__ volatile("movq %%rax, %0\n": "=m"(reg_state[ 0]));
    __asm__ volatile("movq %%rbx, %0\n": "=m"(reg_state[ 1]));
    __asm__ volatile("movq %%rcx, %0\n": "=m"(reg_state[ 2]));
    __asm__ volatile("movq %%rdx, %0\n": "=m"(reg_state[ 3]));
    __asm__ volatile("movq %%rsi, %0\n": "=m"(reg_state[ 4]));
    __asm__ volatile("movq %%rdi, %0\n": "=m"(reg_state[ 5]));
    __asm__ volatile("movq %%rbp, %0\n": "=m"(reg_state[ 6]));

    __asm__ volatile("movq %%r8, %0\n":  "=m"(reg_state[ 7]));
    __asm__ volatile("movq %%r9, %0\n":  "=m"(reg_state[ 8]));
    __asm__ volatile("movq %%r10, %0\n": "=m"(reg_state[ 9]));
    __asm__ volatile("movq %%r11, %0\n": "=m"(reg_state[10]));
    __asm__ volatile("movq %%r12, %0\n": "=m"(reg_state[11]));
    __asm__ volatile("movq %%r13, %0\n": "=m"(reg_state[12]));
    __asm__ volatile("movq %%r14, %0\n": "=m"(reg_state[13]));
    __asm__ volatile("movq %%r15, %0\n": "=m"(reg_state[14]));

    // save xmm state
    __asm__ volatile("fxsave %0\n" : "=m"(do_call_state[cur_do_call_frame].sse_state));

    // we'll need these values later
    __asm__ volatile(
            "movq %0, %%rax\n" 
            "movq %1, %%r10\n" 
            : : "r"(state), "r"(value) : "rax","r10");
    __asm__ volatile("pushq %rax\n");

    // spill reg state to native regs
    __asm__ volatile("movq %c[offt](%%rax), %%rdi\n": : [offt]"e"(offsetof(RegState, RDI)) );
    __asm__ volatile("movq %c[offt](%%rax), %%rsi\n": : [offt]"e"(offsetof(RegState, RSI)) );
    __asm__ volatile("movq %c[offt](%%rax), %%rdx\n": : [offt]"e"(offsetof(RegState, RDX)) );
    __asm__ volatile("movq %c[offt](%%rax), %%rcx\n": : [offt]"e"(offsetof(RegState, RCX)) );
    __asm__ volatile("movq %c[offt](%%rax), %%r8\n": :  [offt]"e"(offsetof(RegState, R8)) );
    __asm__ volatile("movq %c[offt](%%rax), %%r9\n": :  [offt]"e"(offsetof(RegState, R9)) );
    __asm__ volatile("movq %c[offt](%%rax), %%r12\n": : [offt]"e"(offsetof(RegState, R12)) );
    __asm__ volatile("movq %c[offt](%%rax), %%r13\n": : [offt]"e"(offsetof(RegState, R13)) );
    __asm__ volatile("movq %c[offt](%%rax), %%r14\n": : [offt]"e"(offsetof(RegState, R14)) );
    __asm__ volatile("movq %c[offt](%%rax), %%r15\n": : [offt]"e"(offsetof(RegState, R15)) );
    __asm__ volatile("movq %c[offt](%%rax), %%rbp\n": : [offt]"e"(offsetof(RegState, RBP)) );

    __asm__ volatile("movups %c[offt](%%rax), %%xmm0\n": : [offt]"e"(offsetof(RegState, XMM0)) );
    __asm__ volatile("movups %c[offt](%%rax), %%xmm1\n": : [offt]"e"(offsetof(RegState, XMM1)) );
    __asm__ volatile("movups %c[offt](%%rax), %%xmm2\n": : [offt]"e"(offsetof(RegState, XMM2)) );
    __asm__ volatile("movups %c[offt](%%rax), %%xmm3\n": : [offt]"e"(offsetof(RegState, XMM3)) );
    __asm__ volatile("movups %c[offt](%%rax), %%xmm4\n": : [offt]"e"(offsetof(RegState, XMM4)) );
    __asm__ volatile("movups %c[offt](%%rax), %%xmm5\n": : [offt]"e"(offsetof(RegState, XMM5)) );
    __asm__ volatile("movups %c[offt](%%rax), %%xmm6\n": : [offt]"e"(offsetof(RegState, XMM6)) );
    __asm__ volatile("movups %c[offt](%%rax), %%xmm7\n": : [offt]"e"(offsetof(RegState, XMM7)) );


    // save "real" rsp
    //__asm__ volatile("movq %%rsp, %0\n": "=m"(__mcsema_real_rsp) );
    __asm__ volatile("movq %%rsp, %0\n": "=m"(do_call_state[cur_do_call_frame].__mcsema_real_rsp) );
    
    // switch rsp to translator rsp
    __asm__ volatile("movq %c[offt](%%rax), %%rsp\n": : [offt]"e"(offsetof(RegState, RSP)));

    // undo push of the 'fake' return address
    __asm__ volatile("addq $8, %rsp\n");

    // call value
    __asm__ volatile("callq *%r10\n");

    // save rax for later
    //__asm__ volatile("movq %%rax, %0\n": "=m"(__mcsema_saved_rax) );
    __asm__ volatile("movq %%rax, %0\n": "=m"(do_call_state[cur_do_call_frame].__mcsema_saved_rax) );

    // save old RSP since we'll need to shove it into struct regs
    __asm__ volatile("movq %rsp, %rax\n");

    // revert RSP
    //__asm__ volatile("movq %0, %%rsp\n": : "m"(__mcsema_real_rsp) );
    __asm__ volatile("movq %0, %%rsp\n": : "m"(do_call_state[cur_do_call_frame].__mcsema_real_rsp) );

    // restore previously saved rax pointer
    __asm__ volatile("popq %r10\n");
    
    // populate state->RSP
    __asm__ volatile("movq %%rax, %c[offt](%%r10)\n": : [offt]"e"(offsetof(RegState, RSP)) );
    __asm__ volatile("movq %r10, %rax\n");

    // populate state->RBP
    __asm__ volatile("movq %%rbp, %c[offt](%%rax)\n": : [offt]"e"(offsetof(RegState, RBP)) );

    // native regs -> regs
    __asm__ volatile("movq  %%rdi, %c[offt](%%rax)\n": :[offt]"e"(offsetof(RegState, RDI)) );
    __asm__ volatile("movq  %%rsi, %c[offt](%%rax)\n": :[offt]"e"(offsetof(RegState, RSI)) );
    __asm__ volatile("movq  %%rdx, %c[offt](%%rax)\n": :[offt]"e"(offsetof(RegState, RDX)) );
    __asm__ volatile("movq  %%rcx, %c[offt](%%rax)\n": :[offt]"e"(offsetof(RegState, RCX)) );
    __asm__ volatile("movq  %%r8 , %c[offt](%%rax)\n": :[offt]"e"(offsetof(RegState, R8 )) );
    __asm__ volatile("movq  %%r9 , %c[offt](%%rax)\n": :[offt]"e"(offsetof(RegState, R9 )) );
    __asm__ volatile("movq  %%r12, %c[offt](%%rax)\n": :[offt]"e"(offsetof(RegState, R12)) );
    __asm__ volatile("movq  %%r13, %c[offt](%%rax)\n": :[offt]"e"(offsetof(RegState, R13)) );
    __asm__ volatile("movq  %%r14, %c[offt](%%rax)\n": :[offt]"e"(offsetof(RegState, R14)) );
    __asm__ volatile("movq  %%r15, %c[offt](%%rax)\n": :[offt]"e"(offsetof(RegState, R15)) );

    __asm__ volatile("movups %%xmm0, %c[offt](%%rax)\n": : [offt]"e"(offsetof(RegState, XMM0)) );
    __asm__ volatile("movups %%xmm1, %c[offt](%%rax)\n": : [offt]"e"(offsetof(RegState, XMM1)) );
    __asm__ volatile("movups %%xmm2, %c[offt](%%rax)\n": : [offt]"e"(offsetof(RegState, XMM2)) );
    __asm__ volatile("movups %%xmm3, %c[offt](%%rax)\n": : [offt]"e"(offsetof(RegState, XMM3)) );
    __asm__ volatile("movups %%xmm4, %c[offt](%%rax)\n": : [offt]"e"(offsetof(RegState, XMM4)) );
    __asm__ volatile("movups %%xmm5, %c[offt](%%rax)\n": : [offt]"e"(offsetof(RegState, XMM5)) );
    __asm__ volatile("movups %%xmm6, %c[offt](%%rax)\n": : [offt]"e"(offsetof(RegState, XMM6)) );
    __asm__ volatile("movups %%xmm7, %c[offt](%%rax)\n": : [offt]"e"(offsetof(RegState, XMM7)) );

    __asm__ volatile("movq %0, %%r10\n": : "m"(do_call_state[cur_do_call_frame].__mcsema_saved_rax));
    __asm__ volatile("movq %%r10, %c[offt](%%rax)\n": :[offt]"e"(offsetof(RegState, RAX)) );

    __asm__ volatile("movq %0, %%rax\n": : "m"(reg_state[ 0]));
    __asm__ volatile("movq %0, %%rbx\n": : "m"(reg_state[ 1]));
    __asm__ volatile("movq %0, %%rcx\n": : "m"(reg_state[ 2]));
    __asm__ volatile("movq %0, %%rdx\n": : "m"(reg_state[ 3]));
    __asm__ volatile("movq %0, %%rsi\n": : "m"(reg_state[ 4]));
    __asm__ volatile("movq %0, %%rdi\n": : "m"(reg_state[ 5]));
    __asm__ volatile("movq %0, %%rbp\n": : "m"(reg_state[ 6]));
                                    
    __asm__ volatile("movq %0, %%r8 \n":  : "m"(reg_state[ 7]));
    __asm__ volatile("movq %0, %%r9 \n":  : "m"(reg_state[ 8]));
    __asm__ volatile("movq %0, %%r10\n":  : "m"(reg_state[ 9]));
    __asm__ volatile("movq %0, %%r11\n":  : "m"(reg_state[10]));
    __asm__ volatile("movq %0, %%r12\n":  : "m"(reg_state[11]));
    __asm__ volatile("movq %0, %%r13\n":  : "m"(reg_state[12]));
    __asm__ volatile("movq %0, %%r14\n":  : "m"(reg_state[13]));
    __asm__ volatile("movq %0, %%r15\n":  : "m"(reg_state[14]));
    __asm__ volatile("fxrstor %0\n" : "=m"(do_call_state[cur_do_call_frame].sse_state));
    
    cur_do_call_frame--;
}
