#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>

// build with 
// clang-3.5 -std=gnu99 -m64 -emit-llvm -c -o linux_amd64_callback.bc linux_amd64_callback.c

#define ONLY_STRUCT
#include "../common/RegisterState.h"

#define MIN_STACK_SIZE 4096
#define STACK_ALLOC_SIZE (MIN_STACK_SIZE * 10)
#define NUM_DO_CALL_FRAMES 512 /* XXX what is reasonable here? */
#define STACK_MAX 0x7ffffffff000

// this is a terrible hack to be compatible with some mcsema definitions. please don't judge
extern uint64_t mmap(uint64_t addr, uint64_t length, uint32_t prot, uint32_t flags, uint32_t fd, uint32_t offset);
//extern uint64_t munmap(uint64_t addr, uint64_t length);

// callback state
__thread RegState __mcsema_callback_state[NUM_DO_CALL_FRAMES];
// "pointer" to alternate stack
__thread uint64_t __mcsema_alt_stack[NUM_DO_CALL_FRAMES] = {0};
__thread uint64_t __mcsema_inception_depth = -1;
__thread RegState* __rsptr = NULL;
__thread uint64_t* __altstackptr = NULL;

void* __mcsema_create_alt_stack(size_t stack_size)
{
    // we need some place to set this, and this function
    // will get called before these are used
    __rsptr = &__mcsema_callback_state[0];
    __altstackptr = &__mcsema_alt_stack[0];
    
    // half for old stack to copy, half for stack to use in function
    if(stack_size < MIN_STACK_SIZE*2) {
        stack_size = MIN_STACK_SIZE*2;
    }
    void* r = (void*)mmap(0, stack_size, 3, 0x20022, -1, 0) + stack_size;
    return r;
}

// assumes call destination is pushed on the stack by a stub
// takes native state and shoves it into struct RegState
// TODO: FPU
__attribute__((naked)) int __mcsema_inception()
{
    // save all registers; we will need to shove
    // them into context state later
    __asm__ volatile(
            "pushq %r15\n"
            "pushq %r14\n"
            "pushq %r13\n"
            "pushq %r12\n"
            "pushq %r11\n"
            "pushq %r10\n"
            "pushq %r9\n"
            "pushq %r8\n"
            "pushq %rbp\n"
            "pushq %rdi\n"
            "pushq %rsi\n"
            "pushq %rdx\n"
            "pushq %rcx\n"
            "pushq %rbx\n"
            "pushq %rax\n");

    //++__mcsema_inception_depth;
    __asm__ volatile ("incq %0\n" :: "m"(__mcsema_inception_depth));

    // check if we have an alt stack allocated for this depth level
    // if not, allocate it
    __asm__ volatile (
            // offset of altstack from fs:0
            "leaq %[altstack], %%rax\n"
            // offset of fs:0
            "movq %%fs:0, %%rbx\n"
            // base + offset = location of test
            "addq %%rbx, %%rax\n"
            // check if we have an alt stack
            "cmpq $0, (%%rax)\n"
            "jne 0f\n"
            // no alt stack, call create alt stack
            "pushq %%rax\n" // align
            "pushq %%rax\n"
            "mov $%c[stack_alloc_size], %%rdi\n"
            "callq %P[createalt]\n"
            "movq %%rax, %%rbx\n"
            "popq %%rax\n" // align
            "popq %%rax\n"
            // store result into __mcsema_alt_stack array
            "movq %%rbx, (%%rax)\n"
            "0:\n"
            : [altstack]"=m"(__mcsema_alt_stack[__mcsema_inception_depth])
            : [createalt]"i"(__mcsema_create_alt_stack), 
              [stack_alloc_size]"i"(STACK_ALLOC_SIZE));
    
    __asm__ volatile(
            // get base of reg state array
            "movq %0, %%rsi\n"
            // get call depth
            "movq %1, %%rax\n"
            // see where we need to index into the save state array
            "imulq $%c[struct_size], %%rax\n"
            // new write point == array base + index
            "addq %%rax, %%rsi\n"

            "popq %%rax\n" // restore rax from saved stack
            "movq %%rax, %c[state_rax](%%rsi)\n" // convert native state to struct regs
            "movq %%rsi, %%rax\n" // we wrote rax to reg state, now use it as scratch
            // save all other registers to register context
            "popq %%rbx\n"
            "movq %%rbx, %c[state_rbx](%%rax)\n" // convert native state to struct regs
            "popq %%rcx\n"
            "movq %%rcx, %c[state_rcx](%%rax)\n" // convert native state to struct regs
            "popq %%rdx\n"
            "movq %%rdx, %c[state_rdx](%%rax)\n" // convert native state to struct regs
            "popq %%rsi\n"
            "movq %%rsi, %c[state_rsi](%%rax)\n" // convert native state to struct regs
            "popq %%rdi\n"
            "movq %%rdi, %c[state_rdi](%%rax)\n" // convert native state to struct regs
            "popq %%rbp\n"
            "movq %%rbp, %c[state_rbp](%%rax)\n" // convert native state to struct regs
            "popq %%r8\n"
            "movq %%r8,  %c[state_r8](%%rax)\n" // convert native state to struct regs
            "popq %%r9\n"
            "movq %%r9,  %c[state_r9](%%rax)\n" // convert native state to struct regs
            "popq %%r10\n"
            "movq %%r10, %c[state_r10](%%rax)\n" // convert native state to struct regs
            "popq %%r11\n"
            "movq %%r11, %c[state_r11](%%rax)\n" // convert native state to struct regs
            "popq %%r12\n"
            "movq %%r12, %c[state_r12](%%rax)\n" // convert native state to struct regs
            "popq %%r13\n"
            "movq %%r13, %c[state_r13](%%rax)\n" // convert native state to struct regs
            "popq %%r14\n"
            "movq %%r14, %c[state_r14](%%rax)\n" // convert native state to struct regs
            "popq %%r15\n"
            "movq %%r15, %c[state_r15](%%rax)\n" // convert native state to struct regs
            "movups %%xmm0, %c[state_xmm0](%%rax)\n"
            "movups %%xmm1, %c[state_xmm1](%%rax)\n"
            "movups %%xmm2, %c[state_xmm2](%%rax)\n"
            "movups %%xmm3, %c[state_xmm3](%%rax)\n"
            "movups %%xmm4, %c[state_xmm4](%%rax)\n"
            "movups %%xmm5, %c[state_xmm5](%%rax)\n"
            "movups %%xmm6, %c[state_xmm6](%%rax)\n"
            "movups %%xmm7, %c[state_xmm7](%%rax)\n"

            // copy over STACK_SIZE/2 bytes of stack (we may need to fetch stuff from it)
            // at this point we saved all the registers, so we can clobber at will
            // since they are restored on function exit
            // be careful not to try to copy past stack_max, or we will hit unmapped memory
            // rcx will contain amount of bytes to copy
            "movq $%c[half_stack_size], %%rcx\n" // attempted copy size
            "movq %%rsp, %%rsi\n" // base of copy
            "leaq (%%rsi, %%rcx, 1), %%rdi\n" // extent
            "movabs $%c[stack_max], %%r14\n" // max allowed
            "movq %%r14, %%r13\n"
            "subq %%rsi, %%r13\n" // copy size if extent is > max
            "cmpq %%r14, %%rdi\n" // compare extent and max
            "cmovaq %%r13, %%rcx\n" // if extent > max, copy only to max
            
            // get altstack base
            "movq %[alt_stack_base], %%rdi\n"
            // get altstack offset
            "movq %1, %%rbx\n"
            "imulq $8, %%rbx\n"
            // add base + offset
            "addq %%rbx, %%rdi\n"
            // read value in alt stack array
            "movq (%%rdi), %%rdi\n"
    
            // fetch call destination from stack
            "popq %%r8\n" // put translated destination into r8
                          // it was pushed in the stub that calls __mcsema_inception
                          // see linuxArchOps.cpp
                          //
            // align stack
            "movq %%rsp, %%r10\n"
            "andq $0xF, %%r10\n"
            "subq $0x10, %%rdi\n"
            "addq %%r10, %%rdi\n"
            "subq $%c[half_stack_size], %%rdi\n"

            // set RSP to the alt stack rsp
            "movq %%rdi, %c[state_rsp](%%rax)\n" // convert native state to struct regs
            // do memcpy
            "cld\n"
            "rep; movsb\n"

            // call translated_function(reg_state);
            // arg0 = rax
            "movq %%rax, %%rdi\n"
            // align stack for call
            "subq $8, %%rsp\n"
            // do the call
            "callq *%%r8\n"

            // assume things got clobbered
            // undo align
            "addq $8, %%rsp\n"
            // get base of reg states array
            "movq %0, %%rsi\n"
            // get depth count
            "movq %1, %%rax\n"
            // see where we need to index into the save state array
            "imulq $%c[struct_size], %%rax\n" 
            // new read point == base + size
            "addq %%rax, %%rsi\n"

            // restore state to native state
            "movq %c[state_rax](%%rsi), %%rax\n"
            "movq %c[state_rbx](%%rsi), %%rbx\n"
            "movq %c[state_rcx](%%rsi), %%rcx\n"
            "movq %c[state_rdx](%%rsi), %%rdx\n"
            "movq %c[state_rdi](%%rsi), %%rdi\n"
            "movq %c[state_rbp](%%rsi), %%rbp\n"
            "movq %c[state_r8](%%rsi), %%r8\n"
            "movq %c[state_r9](%%rsi), %%r9\n"
            "movq %c[state_r10](%%rsi), %%r10\n"
            "movq %c[state_r11](%%rsi), %%r11\n"
            "movq %c[state_r12](%%rsi), %%r12\n"
            "movq %c[state_r13](%%rsi), %%r13\n"
            "movq %c[state_r14](%%rsi), %%r14\n"
            "movq %c[state_r15](%%rsi), %%r15\n"

            "movups %c[state_xmm0](%%rsi), %%xmm0\n"
            "movups %c[state_xmm1](%%rsi), %%xmm1\n"
            "movups %c[state_xmm2](%%rsi), %%xmm2\n"
            "movups %c[state_xmm3](%%rsi), %%xmm3\n"
            "movups %c[state_xmm4](%%rsi), %%xmm4\n"
            "movups %c[state_xmm5](%%rsi), %%xmm5\n"
            "movups %c[state_xmm6](%%rsi), %%xmm6\n"
            "movups %c[state_xmm7](%%rsi), %%xmm7\n"

            // TODO adjust for RSP offset?

            "movq %c[state_rsi](%%rsi), %%rsi\n"
            : : "m"(__rsptr), "m"(__mcsema_inception_depth), 
              [state_rax]"e"(offsetof(RegState, RAX)),
              [state_rbx]"e"(offsetof(RegState, RBX)),
              [state_rcx]"e"(offsetof(RegState, RCX)),
              [state_rdx]"e"(offsetof(RegState, RDX)),
              [state_rdi]"e"(offsetof(RegState, RDI)),
              [state_rsi]"e"(offsetof(RegState, RSI)),
              [state_rbp]"e"(offsetof(RegState, RBP)),
              [state_rsp]"e"(offsetof(RegState, RSP)),
              [state_r8]"e"(offsetof(RegState, R8)),
              [state_r9]"e"(offsetof(RegState, R9)),
              [state_r10]"e"(offsetof(RegState, R10)),
              [state_r11]"e"(offsetof(RegState, R11)),
              [state_r12]"e"(offsetof(RegState, R12)),
              [state_r13]"e"(offsetof(RegState, R13)),
              [state_r14]"e"(offsetof(RegState, R14)),
              [state_r15]"e"(offsetof(RegState, R15)),
              [state_xmm0]"e"(offsetof(RegState, XMM0)),
              [state_xmm1]"e"(offsetof(RegState, XMM1)),
              [state_xmm2]"e"(offsetof(RegState, XMM2)),
              [state_xmm3]"e"(offsetof(RegState, XMM3)),
              [state_xmm4]"e"(offsetof(RegState, XMM4)),
              [state_xmm5]"e"(offsetof(RegState, XMM5)),
              [state_xmm6]"e"(offsetof(RegState, XMM6)),
              [state_xmm7]"e"(offsetof(RegState, XMM7)),
              [struct_size]"e"(sizeof(RegState)),
              [stack_alloc_size]"i"(STACK_ALLOC_SIZE),
              [half_stack_size]"i"(STACK_ALLOC_SIZE/2),
              [stack_max]"i"(STACK_MAX),
              [alt_stack_base]"m"(__altstackptr)
              );

    // --__mcsema_inception_depth;
    __asm__ volatile ("decq %0\n" :: "m"(__mcsema_inception_depth));
    __asm__ volatile ("retq\n");
}

typedef struct _do_call_state_t {
    uint64_t __mcsema_real_rsp;
    // used to hold how many COUNT_LEVEL blocks we will jump over
    // when calculating return addresses in do_call_value
    uint64_t __mcsema_jmp_count;
    char sse_state[512] __attribute__((aligned (16)));
    void *saved_state;
} do_call_state_t;

// hold recursive call states
__thread do_call_state_t do_call_state[NUM_DO_CALL_FRAMES];
// this is used to hold a pointer to the base of the do_call_state
// array, so we can avoid doing complex TLS math via inline assembly
__thread do_call_state_t* __csptr = NULL;

// count of current call frames
__thread int64_t cur_do_call_frame = -1; /* XXX */

// used to count how many call frames deep this recursion goes
// only one is needed since it is initialized to the same value on entry
// and only used after exit from a call, so it can be re-initialized repeatedly
__thread uint64_t call_frame_counter = -1;


#define COUNT_LEVEL(N) \
  ".align 16, 0x90\n" \
  #N ":" \
  "incq %1\n"

void do_call_value(void *state, uint64_t value)
{
    // get a pointer to base of call state array
    __csptr = &(do_call_state[0]);
    // get a clean frame to store state
    int64_t prev_call_frame = cur_do_call_frame++;
    // get a pointer to current call state
    do_call_state_t *cs = &(do_call_state[cur_do_call_frame]);
    // reset frame counter to -1 (it will always increment at least once)
    call_frame_counter = -1;

    // how many COUNT_LEVEL blocks will we jump over?
    cs->__mcsema_jmp_count = NUM_DO_CALL_FRAMES - cur_do_call_frame - 1;

    __asm__ volatile(
            "subq $128, %%rsp\n" // -128
            "fxsave %0\n" // save sse state
            "pushq %%rax\n"
            "pushq %%rbx\n"
            "pushq %%rcx\n"
            "pushq %%rdx\n"
            "pushq %%rsi\n"
            "pushq %%rdi\n"
            "pushq %%rbp\n"
            "pushq %%r8\n"
            "pushq %%r9\n"
            "pushq %%r10\n"
            "pushq %%r11\n"
            "pushq %%r12\n"
            "pushq %%r13\n"
            "pushq %%r14\n"
            "pushq %%r15\n" // -128 - 15*8

            "movq %3, %%rax\n"  // capture "state" arg (mcsema regstate)
            "movq %4, %%rcx\n"  // capture "value" arg (call destination)
            "movq %2, %%rsi\n" // pointer to TLS area where we save state
            "movq %c[state_rdx](%%rax), %%rdx\n"
            "movq %c[state_rbx](%%rax), %%rbx\n"
            "movq %c[state_rbp](%%rax), %%rbp\n"
            "movq %c[state_r8](%%rax), %%r8\n"
            "movq %c[state_r9](%%rax), %%r9\n"
            "movq %c[state_r10](%%rax), %%r10\n"
            "movq %c[state_r11](%%rax), %%r11\n"
            "movq %c[state_r12](%%rax), %%r12\n"
            "movq %c[state_r13](%%rax), %%r13\n"
            "movq %c[state_r14](%%rax), %%r14\n"
            "movq %c[state_r15](%%rax), %%r15\n"
            "movups %c[state_xmm0](%%rax), %%xmm0\n" // dump struct regs xmm state
            "movups %c[state_xmm1](%%rax), %%xmm1\n"
            "movups %c[state_xmm2](%%rax), %%xmm2\n"
            "movups %c[state_xmm3](%%rax), %%xmm3\n"
            "movups %c[state_xmm4](%%rax), %%xmm4\n"
            "movups %c[state_xmm5](%%rax), %%xmm5\n"
            "movups %c[state_xmm6](%%rax), %%xmm6\n"
            "movups %c[state_xmm7](%%rax), %%xmm7\n"
            "leaq %c[saved_state](%%rsi), %%rdi\n" // where will we save the reg state arg
            "movq %%rax, (%%rdi)\n" // save reg state arg
            "leaq %c[real_rsp_off](%%rsi), %%rdi\n" // where will we save the "real" esp?
            "movq %%rsp, (%%rdi)\n" // save our esp since we will switch to mcsema esp later
            "movq %c[state_rsp](%%rax), %%rsp\n" // switch to mcsema stack
            //"subq $8, %%rsp\n"
            "movq %%rcx, %%rdi\n" // use that slot to store jump destination
            "leaq %c[jmp_count](%%rsi), %%rsi\n" // save recursion count into rsi
            "movq (%%rsi), %%rcx\n" // save recursion count into ecx
            "shlq $4, %%rcx\n" // multiply recursion count by 16 to get offset (mul 16 = shl 4)
            "leaq 0f, %%rsi\n" // base return addr
            "addq %%rcx, %%rsi\n" // calculate return addr
            "pushq %%rsi\n" // push return addr
            "pushq %%rdi\n" // push jump destination (we call via push/ret)
            "movq %c[state_rdi](%%rax), %%rdi\n" // dump struct regs to state
            "movq %c[state_rcx](%%rax), %%rcx\n" // complete struct regs spill
            "movq %c[state_rsi](%%rax), %%rsi\n" // complete struct regs spill
            "movq %c[state_rax](%%rax), %%rax\n" // complete struct regs spill
            "retq\n"
            COUNT_LEVEL(0) // set of jump locations that increment the call frame counter
            COUNT_LEVEL(1) // the amount of these hit depends on the recursion depth
            COUNT_LEVEL(2) // at depth 0, none are hit, at depth 1, there is 1, etc.
            COUNT_LEVEL(3) // there are 512 incl entries
            COUNT_LEVEL(4) COUNT_LEVEL(5) COUNT_LEVEL(6) COUNT_LEVEL(7) COUNT_LEVEL(8) COUNT_LEVEL(9) COUNT_LEVEL(10) COUNT_LEVEL(11) COUNT_LEVEL(12)
            COUNT_LEVEL(13) COUNT_LEVEL(14) COUNT_LEVEL(15) COUNT_LEVEL(16) COUNT_LEVEL(17) COUNT_LEVEL(18) COUNT_LEVEL(19) COUNT_LEVEL(20) COUNT_LEVEL(21)
            COUNT_LEVEL(22) COUNT_LEVEL(23) COUNT_LEVEL(24) COUNT_LEVEL(25) COUNT_LEVEL(26) COUNT_LEVEL(27) COUNT_LEVEL(28) COUNT_LEVEL(29) COUNT_LEVEL(30)
            COUNT_LEVEL(31) COUNT_LEVEL(32) COUNT_LEVEL(33) COUNT_LEVEL(34) COUNT_LEVEL(35) COUNT_LEVEL(36) COUNT_LEVEL(37) COUNT_LEVEL(38) COUNT_LEVEL(39)
            COUNT_LEVEL(40) COUNT_LEVEL(41) COUNT_LEVEL(42) COUNT_LEVEL(43) COUNT_LEVEL(44) COUNT_LEVEL(45) COUNT_LEVEL(46) COUNT_LEVEL(47) COUNT_LEVEL(48)
            COUNT_LEVEL(49) COUNT_LEVEL(50) COUNT_LEVEL(51) COUNT_LEVEL(52) COUNT_LEVEL(53) COUNT_LEVEL(54) COUNT_LEVEL(55) COUNT_LEVEL(56) COUNT_LEVEL(57)
            COUNT_LEVEL(58) COUNT_LEVEL(59) COUNT_LEVEL(60) COUNT_LEVEL(61) COUNT_LEVEL(62) COUNT_LEVEL(63) COUNT_LEVEL(64) COUNT_LEVEL(65) COUNT_LEVEL(66)
            COUNT_LEVEL(67) COUNT_LEVEL(68) COUNT_LEVEL(69) COUNT_LEVEL(70) COUNT_LEVEL(71) COUNT_LEVEL(72) COUNT_LEVEL(73) COUNT_LEVEL(74) COUNT_LEVEL(75)
            COUNT_LEVEL(76) COUNT_LEVEL(77) COUNT_LEVEL(78) COUNT_LEVEL(79) COUNT_LEVEL(80) COUNT_LEVEL(81) COUNT_LEVEL(82) COUNT_LEVEL(83) COUNT_LEVEL(84)
            COUNT_LEVEL(85) COUNT_LEVEL(86) COUNT_LEVEL(87) COUNT_LEVEL(88) COUNT_LEVEL(89) COUNT_LEVEL(90) COUNT_LEVEL(91) COUNT_LEVEL(92) COUNT_LEVEL(93)
            COUNT_LEVEL(94) COUNT_LEVEL(95) COUNT_LEVEL(96) COUNT_LEVEL(97) COUNT_LEVEL(98) COUNT_LEVEL(99) COUNT_LEVEL(100) COUNT_LEVEL(101) COUNT_LEVEL(102)
            COUNT_LEVEL(103) COUNT_LEVEL(104) COUNT_LEVEL(105) COUNT_LEVEL(106) COUNT_LEVEL(107) COUNT_LEVEL(108) COUNT_LEVEL(109) COUNT_LEVEL(110) COUNT_LEVEL(111)
            COUNT_LEVEL(112) COUNT_LEVEL(113) COUNT_LEVEL(114) COUNT_LEVEL(115) COUNT_LEVEL(116) COUNT_LEVEL(117) COUNT_LEVEL(118) COUNT_LEVEL(119) COUNT_LEVEL(120)
            COUNT_LEVEL(121) COUNT_LEVEL(122) COUNT_LEVEL(123) COUNT_LEVEL(124) COUNT_LEVEL(125) COUNT_LEVEL(126) COUNT_LEVEL(127) COUNT_LEVEL(128) COUNT_LEVEL(129)
            COUNT_LEVEL(130) COUNT_LEVEL(131) COUNT_LEVEL(132) COUNT_LEVEL(133) COUNT_LEVEL(134) COUNT_LEVEL(135) COUNT_LEVEL(136) COUNT_LEVEL(137) COUNT_LEVEL(138)
            COUNT_LEVEL(139) COUNT_LEVEL(140) COUNT_LEVEL(141) COUNT_LEVEL(142) COUNT_LEVEL(143) COUNT_LEVEL(144) COUNT_LEVEL(145) COUNT_LEVEL(146) COUNT_LEVEL(147)
            COUNT_LEVEL(148) COUNT_LEVEL(149) COUNT_LEVEL(150) COUNT_LEVEL(151) COUNT_LEVEL(152) COUNT_LEVEL(153) COUNT_LEVEL(154) COUNT_LEVEL(155) COUNT_LEVEL(156)
            COUNT_LEVEL(157) COUNT_LEVEL(158) COUNT_LEVEL(159) COUNT_LEVEL(160) COUNT_LEVEL(161) COUNT_LEVEL(162) COUNT_LEVEL(163) COUNT_LEVEL(164) COUNT_LEVEL(165)
            COUNT_LEVEL(166) COUNT_LEVEL(167) COUNT_LEVEL(168) COUNT_LEVEL(169) COUNT_LEVEL(170) COUNT_LEVEL(171) COUNT_LEVEL(172) COUNT_LEVEL(173) COUNT_LEVEL(174)
            COUNT_LEVEL(175) COUNT_LEVEL(176) COUNT_LEVEL(177) COUNT_LEVEL(178) COUNT_LEVEL(179) COUNT_LEVEL(180) COUNT_LEVEL(181) COUNT_LEVEL(182) COUNT_LEVEL(183)
            COUNT_LEVEL(184) COUNT_LEVEL(185) COUNT_LEVEL(186) COUNT_LEVEL(187) COUNT_LEVEL(188) COUNT_LEVEL(189) COUNT_LEVEL(190) COUNT_LEVEL(191) COUNT_LEVEL(192)
            COUNT_LEVEL(193) COUNT_LEVEL(194) COUNT_LEVEL(195) COUNT_LEVEL(196) COUNT_LEVEL(197) COUNT_LEVEL(198) COUNT_LEVEL(199) COUNT_LEVEL(200) COUNT_LEVEL(201)
            COUNT_LEVEL(202) COUNT_LEVEL(203) COUNT_LEVEL(204) COUNT_LEVEL(205) COUNT_LEVEL(206) COUNT_LEVEL(207) COUNT_LEVEL(208) COUNT_LEVEL(209) COUNT_LEVEL(210)
            COUNT_LEVEL(211) COUNT_LEVEL(212) COUNT_LEVEL(213) COUNT_LEVEL(214) COUNT_LEVEL(215) COUNT_LEVEL(216) COUNT_LEVEL(217) COUNT_LEVEL(218) COUNT_LEVEL(219)
            COUNT_LEVEL(220) COUNT_LEVEL(221) COUNT_LEVEL(222) COUNT_LEVEL(223) COUNT_LEVEL(224) COUNT_LEVEL(225) COUNT_LEVEL(226) COUNT_LEVEL(227) COUNT_LEVEL(228)
            COUNT_LEVEL(229) COUNT_LEVEL(230) COUNT_LEVEL(231) COUNT_LEVEL(232) COUNT_LEVEL(233) COUNT_LEVEL(234) COUNT_LEVEL(235) COUNT_LEVEL(236) COUNT_LEVEL(237)
            COUNT_LEVEL(238) COUNT_LEVEL(239) COUNT_LEVEL(240) COUNT_LEVEL(241) COUNT_LEVEL(242) COUNT_LEVEL(243) COUNT_LEVEL(244) COUNT_LEVEL(245) COUNT_LEVEL(246)
            COUNT_LEVEL(247) COUNT_LEVEL(248) COUNT_LEVEL(249) COUNT_LEVEL(250) COUNT_LEVEL(251) COUNT_LEVEL(252) COUNT_LEVEL(253) COUNT_LEVEL(254) COUNT_LEVEL(255)
            COUNT_LEVEL(256) COUNT_LEVEL(257) COUNT_LEVEL(258) COUNT_LEVEL(259) COUNT_LEVEL(260) COUNT_LEVEL(261) COUNT_LEVEL(262) COUNT_LEVEL(263) COUNT_LEVEL(264)
            COUNT_LEVEL(265) COUNT_LEVEL(266) COUNT_LEVEL(267) COUNT_LEVEL(268) COUNT_LEVEL(269) COUNT_LEVEL(270) COUNT_LEVEL(271) COUNT_LEVEL(272) COUNT_LEVEL(273)
            COUNT_LEVEL(274) COUNT_LEVEL(275) COUNT_LEVEL(276) COUNT_LEVEL(277) COUNT_LEVEL(278) COUNT_LEVEL(279) COUNT_LEVEL(280) COUNT_LEVEL(281) COUNT_LEVEL(282)
            COUNT_LEVEL(283) COUNT_LEVEL(284) COUNT_LEVEL(285) COUNT_LEVEL(286) COUNT_LEVEL(287) COUNT_LEVEL(288) COUNT_LEVEL(289) COUNT_LEVEL(290) COUNT_LEVEL(291)
            COUNT_LEVEL(292) COUNT_LEVEL(293) COUNT_LEVEL(294) COUNT_LEVEL(295) COUNT_LEVEL(296) COUNT_LEVEL(297) COUNT_LEVEL(298) COUNT_LEVEL(299) COUNT_LEVEL(300)
            COUNT_LEVEL(301) COUNT_LEVEL(302) COUNT_LEVEL(303) COUNT_LEVEL(304) COUNT_LEVEL(305) COUNT_LEVEL(306) COUNT_LEVEL(307) COUNT_LEVEL(308) COUNT_LEVEL(309)
            COUNT_LEVEL(310) COUNT_LEVEL(311) COUNT_LEVEL(312) COUNT_LEVEL(313) COUNT_LEVEL(314) COUNT_LEVEL(315) COUNT_LEVEL(316) COUNT_LEVEL(317) COUNT_LEVEL(318)
            COUNT_LEVEL(319) COUNT_LEVEL(320) COUNT_LEVEL(321) COUNT_LEVEL(322) COUNT_LEVEL(323) COUNT_LEVEL(324) COUNT_LEVEL(325) COUNT_LEVEL(326) COUNT_LEVEL(327)
            COUNT_LEVEL(328) COUNT_LEVEL(329) COUNT_LEVEL(330) COUNT_LEVEL(331) COUNT_LEVEL(332) COUNT_LEVEL(333) COUNT_LEVEL(334) COUNT_LEVEL(335) COUNT_LEVEL(336)
            COUNT_LEVEL(337) COUNT_LEVEL(338) COUNT_LEVEL(339) COUNT_LEVEL(340) COUNT_LEVEL(341) COUNT_LEVEL(342) COUNT_LEVEL(343) COUNT_LEVEL(344) COUNT_LEVEL(345)
            COUNT_LEVEL(346) COUNT_LEVEL(347) COUNT_LEVEL(348) COUNT_LEVEL(349) COUNT_LEVEL(350) COUNT_LEVEL(351) COUNT_LEVEL(352) COUNT_LEVEL(353) COUNT_LEVEL(354)
            COUNT_LEVEL(355) COUNT_LEVEL(356) COUNT_LEVEL(357) COUNT_LEVEL(358) COUNT_LEVEL(359) COUNT_LEVEL(360) COUNT_LEVEL(361) COUNT_LEVEL(362) COUNT_LEVEL(363)
            COUNT_LEVEL(364) COUNT_LEVEL(365) COUNT_LEVEL(366) COUNT_LEVEL(367) COUNT_LEVEL(368) COUNT_LEVEL(369) COUNT_LEVEL(370) COUNT_LEVEL(371) COUNT_LEVEL(372)
            COUNT_LEVEL(373) COUNT_LEVEL(374) COUNT_LEVEL(375) COUNT_LEVEL(376) COUNT_LEVEL(377) COUNT_LEVEL(378) COUNT_LEVEL(379) COUNT_LEVEL(380) COUNT_LEVEL(381)
            COUNT_LEVEL(382) COUNT_LEVEL(383) COUNT_LEVEL(384) COUNT_LEVEL(385) COUNT_LEVEL(386) COUNT_LEVEL(387) COUNT_LEVEL(388) COUNT_LEVEL(389) COUNT_LEVEL(390)
            COUNT_LEVEL(391) COUNT_LEVEL(392) COUNT_LEVEL(393) COUNT_LEVEL(394) COUNT_LEVEL(395) COUNT_LEVEL(396) COUNT_LEVEL(397) COUNT_LEVEL(398) COUNT_LEVEL(399)
            COUNT_LEVEL(400) COUNT_LEVEL(401) COUNT_LEVEL(402) COUNT_LEVEL(403) COUNT_LEVEL(404) COUNT_LEVEL(405) COUNT_LEVEL(406) COUNT_LEVEL(407) COUNT_LEVEL(408)
            COUNT_LEVEL(409) COUNT_LEVEL(410) COUNT_LEVEL(411) COUNT_LEVEL(412) COUNT_LEVEL(413) COUNT_LEVEL(414) COUNT_LEVEL(415) COUNT_LEVEL(416) COUNT_LEVEL(417)
            COUNT_LEVEL(418) COUNT_LEVEL(419) COUNT_LEVEL(420) COUNT_LEVEL(421) COUNT_LEVEL(422) COUNT_LEVEL(423) COUNT_LEVEL(424) COUNT_LEVEL(425) COUNT_LEVEL(426)
            COUNT_LEVEL(427) COUNT_LEVEL(428) COUNT_LEVEL(429) COUNT_LEVEL(430) COUNT_LEVEL(431) COUNT_LEVEL(432) COUNT_LEVEL(433) COUNT_LEVEL(434) COUNT_LEVEL(435)
            COUNT_LEVEL(436) COUNT_LEVEL(437) COUNT_LEVEL(438) COUNT_LEVEL(439) COUNT_LEVEL(440) COUNT_LEVEL(441) COUNT_LEVEL(442) COUNT_LEVEL(443) COUNT_LEVEL(444)
            COUNT_LEVEL(445) COUNT_LEVEL(446) COUNT_LEVEL(447) COUNT_LEVEL(448) COUNT_LEVEL(449) COUNT_LEVEL(450) COUNT_LEVEL(451) COUNT_LEVEL(452) COUNT_LEVEL(453)
            COUNT_LEVEL(454) COUNT_LEVEL(455) COUNT_LEVEL(456) COUNT_LEVEL(457) COUNT_LEVEL(458) COUNT_LEVEL(459) COUNT_LEVEL(460) COUNT_LEVEL(461) COUNT_LEVEL(462)
            COUNT_LEVEL(463) COUNT_LEVEL(464) COUNT_LEVEL(465) COUNT_LEVEL(466) COUNT_LEVEL(467) COUNT_LEVEL(468) COUNT_LEVEL(469) COUNT_LEVEL(470) COUNT_LEVEL(471)
            COUNT_LEVEL(472) COUNT_LEVEL(473) COUNT_LEVEL(474) COUNT_LEVEL(475) COUNT_LEVEL(476) COUNT_LEVEL(477) COUNT_LEVEL(478) COUNT_LEVEL(479) COUNT_LEVEL(480)
            COUNT_LEVEL(481) COUNT_LEVEL(482) COUNT_LEVEL(483) COUNT_LEVEL(484) COUNT_LEVEL(485) COUNT_LEVEL(486) COUNT_LEVEL(487) COUNT_LEVEL(488) COUNT_LEVEL(489)
            COUNT_LEVEL(490) COUNT_LEVEL(491) COUNT_LEVEL(492) COUNT_LEVEL(493) COUNT_LEVEL(494) COUNT_LEVEL(495) COUNT_LEVEL(496) COUNT_LEVEL(497) COUNT_LEVEL(498)
            COUNT_LEVEL(499) COUNT_LEVEL(500) COUNT_LEVEL(501) COUNT_LEVEL(502) COUNT_LEVEL(503) COUNT_LEVEL(504) COUNT_LEVEL(505) COUNT_LEVEL(506) COUNT_LEVEL(507)
            COUNT_LEVEL(508) COUNT_LEVEL(509) COUNT_LEVEL(510) COUNT_LEVEL(511)
            //"addq $8, %%rsp\n"
            "pushq %%rax\n" // save return value
            "pushq %%rsi\n" // save temp reg
            "movq %1, %%rax\n" // get our recursion depth
            "imulq $%c[struct_size], %%rax\n" // see where we need to index into the save state array
            "movq %5, %%rsi\n" // get address of array base
            "addq %%rsi, %%rax\n" // rax now points to our old saved state (array base + index * element size)
            "movq %c[saved_state](%%rax), %%rsi\n" // get original mcsema state arg so we can write to it
            "movq %%rbx, %c[state_rbx](%%rsi)\n" // convert native state to struct regs
            "movq %%rcx, %c[state_rcx](%%rsi)\n" // convert native state to struct regs
            "movq %%rdx, %c[state_rdx](%%rsi)\n" // convert native state to struct regs
            "movq %%rdi, %c[state_rdi](%%rsi)\n" // convert native state to struct regs
            "movq %%rbp, %c[state_rbp](%%rsi)\n" // convert native state to struct regs
            "movq %%r8,  %c[state_r8](%%rsi)\n" // convert native state to struct regs
            "movq %%r9,  %c[state_r9](%%rsi)\n" // convert native state to struct regs
            "movq %%r10, %c[state_r10](%%rsi)\n" // convert native state to struct regs
            "movq %%r11, %c[state_r11](%%rsi)\n" // convert native state to struct regs
            "movq %%r12, %c[state_r12](%%rsi)\n" // convert native state to struct regs
            "movq %%r13, %c[state_r13](%%rsi)\n" // convert native state to struct regs
            "movq %%r14, %c[state_r14](%%rsi)\n" // convert native state to struct regs
            "movq %%r15, %c[state_r15](%%rsi)\n" // convert native state to struct regs
            "movups %%xmm0, %c[state_xmm0](%%rsi)\n"
            "movups %%xmm1, %c[state_xmm1](%%rsi)\n"
            "movups %%xmm2, %c[state_xmm2](%%rsi)\n"
            "movups %%xmm3, %c[state_xmm3](%%rsi)\n"
            "movups %%xmm4, %c[state_xmm4](%%rsi)\n"
            "movups %%xmm5, %c[state_xmm5](%%rsi)\n"
            "movups %%xmm6, %c[state_xmm6](%%rsi)\n"
            "movups %%xmm7, %c[state_xmm7](%%rsi)\n"
            "movq %%rax, %%rbx\n" // already saved rbx, so lets use it as temp reg
            "movq %%rsi, %%rcx\n" // already saved rcx, so lets use it as temp reg
            "popq %%rsi\n" // get rsi from function return
            "popq %%rax\n" // get rax from function return
            "movq %%rax, %c[state_rax](%%rcx)\n" // convert native state to struct regs
            "movq %%rsi, %c[state_rsi](%%rcx)\n" // convert native state to struct regs
            "movq %%rsp, %c[state_rsp](%%rcx)\n" // convert native state to struct regs
            "leaq %c[real_rsp_off](%%rbx), %%rsi\n" // location of old native rsp
            "movq (%%rsi), %%rsp\n" // return original stack
            "popq %%r15\n"
            "popq %%r14\n"
            "popq %%r13\n"
            "popq %%r12\n"
            "popq %%r11\n"
            "popq %%r10\n"
            "popq %%r9\n"
            "popq %%r8\n"
            "popq %%rbp\n"
            "popq %%rdi\n"
            "popq %%rsi\n"
            "popq %%rdx\n"
            "popq %%rcx\n"
            "popq %%rbx\n"
            "popq %%rax\n"
            "fxrstor %0\n"
            "addq $128, %%rsp\n"
            : "=m"(cs->sse_state), "=m"(call_frame_counter)
            : "m"(cs), "m"(state), "m"(value), "m"(__csptr),
                [state_rax]"e"(offsetof(RegState, RAX)),
                [state_rbx]"e"(offsetof(RegState, RBX)),
                [state_rcx]"e"(offsetof(RegState, RCX)),
                [state_rdx]"e"(offsetof(RegState, RDX)),
                [state_rdi]"e"(offsetof(RegState, RDI)),
                [state_rsi]"e"(offsetof(RegState, RSI)),
                [state_rbp]"e"(offsetof(RegState, RBP)),
                [state_rsp]"e"(offsetof(RegState, RSP)),
                [state_r8]"e"(offsetof(RegState, R8)),
                [state_r9]"e"(offsetof(RegState, R9)),
                [state_r10]"e"(offsetof(RegState, R10)),
                [state_r11]"e"(offsetof(RegState, R11)),
                [state_r12]"e"(offsetof(RegState, R12)),
                [state_r13]"e"(offsetof(RegState, R13)),
                [state_r14]"e"(offsetof(RegState, R14)),
                [state_r15]"e"(offsetof(RegState, R15)),
                [state_xmm0]"e"(offsetof(RegState, XMM0)),
                [state_xmm1]"e"(offsetof(RegState, XMM1)),
                [state_xmm2]"e"(offsetof(RegState, XMM2)),
                [state_xmm3]"e"(offsetof(RegState, XMM3)),
                [state_xmm4]"e"(offsetof(RegState, XMM4)),
                [state_xmm5]"e"(offsetof(RegState, XMM5)),
                [state_xmm6]"e"(offsetof(RegState, XMM6)),
                [state_xmm7]"e"(offsetof(RegState, XMM7)),
                [real_rsp_off]"e"(offsetof(do_call_state_t, __mcsema_real_rsp)),
                [jmp_count]"e"(offsetof(do_call_state_t, __mcsema_jmp_count)),
                [saved_state]"e"(offsetof(do_call_state_t, saved_state)),
                [sse_state]"e"(offsetof(do_call_state_t, sse_state)),
                [struct_size]"e"(sizeof(do_call_state_t))
            : "memory", "rax", "rcx", "rsi" );
    
    // reset call frame depth
    cur_do_call_frame = prev_call_frame;
    // reset call frame counter
    call_frame_counter = -1;

}
