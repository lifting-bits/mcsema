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

__attribute__((naked)) int __mcsema_inception()
{

    // save preserved registers in struct regs
    __asm__ volatile("movl %%eax, %0\n": "=m"(__mcsema_do_call_state.EAX) );
    __asm__ volatile("popl %eax\n"); // put translated destination into eax
                                      // it was pushed in the stub that calls __mcsema_inception
                                      // see linuxArchOps.cpp
    __asm__ volatile("movl %%ebx, %0\n": "=m"(__mcsema_do_call_state.EBX) );
    __asm__ volatile("movl %%ecx, %0\n": "=m"(__mcsema_do_call_state.ECX) );
    __asm__ volatile("movl %%edx, %0\n": "=m"(__mcsema_do_call_state.EDX) );
    __asm__ volatile("movl %%esi, %0\n": "=m"(__mcsema_do_call_state.ESI) );
    __asm__ volatile("movl %%edi, %0\n": "=m"(__mcsema_do_call_state.EDI) );
    __asm__ volatile("movl %%ebp, %0\n": "=m"(__mcsema_do_call_state.EBP) );

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
    __asm__ volatile("movl %0, %%ecx\n": : "i"(MIN_STACK_SIZE) );
    __asm__ volatile("movl %esp, %esi\n");
    __asm__ volatile("movl %0, %%edi\n": : "m"(__mcsema_alt_stack));

    // reserve space
    __asm__ volatile("subl %0, %%edi\n": : "i"(MIN_STACK_SIZE) );

    // set ESP to the alt stack
    __asm__ volatile("movl %%edi, %0\n": "=m"(__mcsema_do_call_state.ESP) );

    // do memcpy
    __asm__ volatile("cld\n");
    __asm__ volatile("rep; movsb\n");

    // call translated_function(reg_state);
    __asm__ volatile("leal %[call_state], %%esi\n"
                     "movl $%c[reg_size], %%ecx\n"
                     "subl %%ecx, %%esp\n"
                     "movl %%esp, %%edi\n"
                     "0:\n"                         // this is a loop verus rep movsd
                     "movb %%gs:(%%esi), %%dl\n"    // since we need to reference the 
                     "movb %%dl, (%%edi)\n"         // gs segment, so its hand coded.
                     "inc %%esi\n"                  // copy reg state from %gs to stack
                     "inc %%edi\n"
                     "loop 0b\n"
                     "pushl %%esp\n"
                     "call *%%eax\n" // stdcall on x86, caller cleans up
                     "movl $%c[reg_size], %%ecx\n"
                     "leal %[call_state], %%edi\n"
                     "1:\n"                         // same as above
                     "movb (%%esp), %%dl\n"
                     "movb %%dl, %%gs:(%%edi)\n"
                     "inc %%esp\n"
                     "inc %%edi\n"
                     "loop 1b\n"
                     :
                     : [reg_size]"e"(sizeof(RegState)), [call_state]"m"(__mcsema_do_call_state)
                     );


    // restore registers
    __asm__ volatile("movl %0, %%ebx\n": : "m"(__mcsema_do_call_state.EBX) );
    __asm__ volatile("movl %0, %%ecx\n": : "m"(__mcsema_do_call_state.ECX) );
    __asm__ volatile("movl %0, %%edx\n": : "m"(__mcsema_do_call_state.EDX) );
    __asm__ volatile("movl %0, %%esi\n": : "m"(__mcsema_do_call_state.ESI) );
    __asm__ volatile("movl %0, %%edi\n": : "m"(__mcsema_do_call_state.EDI) );
    __asm__ volatile("movl %0, %%ebp\n": : "m"(__mcsema_do_call_state.EBP) );
    // *do not* restore ESP, although this may be a bug

    // restore XMM
    __asm__ volatile("movups %0, %%xmm0\n": : "m"(__mcsema_do_call_state.XMM0) );
    __asm__ volatile("movups %0, %%xmm1\n": : "m"(__mcsema_do_call_state.XMM1) );
    __asm__ volatile("movups %0, %%xmm2\n": : "m"(__mcsema_do_call_state.XMM2) );
    __asm__ volatile("movups %0, %%xmm3\n": : "m"(__mcsema_do_call_state.XMM3) );
    __asm__ volatile("movups %0, %%xmm4\n": : "m"(__mcsema_do_call_state.XMM4) );
    __asm__ volatile("movups %0, %%xmm5\n": : "m"(__mcsema_do_call_state.XMM5) );
    __asm__ volatile("movups %0, %%xmm6\n": : "m"(__mcsema_do_call_state.XMM6) );
    __asm__ volatile("movups %0, %%xmm7\n": : "m"(__mcsema_do_call_state.XMM7) );

    // save return value into eax
    __asm__ volatile("movl %0, %%eax\n": : "m"(__mcsema_do_call_state.EAX) );

    __asm__ volatile("retl\n");
}

typedef struct _do_call_state_t {
    uint32_t __mcsema_real_esp;
    // used to hold how many COUNT_LEVEL blocks we will jump over
    // when calculating return addresses in do_call_value
    uint32_t __mcsema_jmp_count;
    char sse_state[512] __attribute__((aligned (16)));
    uint32_t reg_state[15];
} do_call_state_t;

// hold recursive call states
__thread do_call_state_t do_call_state[NUM_DO_CALL_FRAMES];
// this is used to hold a pointer to the base of the do_call_state
// array, so we can avoid doing complex TLS math via inline assembly
__thread do_call_state_t* __csptr = NULL;

// count of current call frames
__thread int32_t cur_do_call_frame = -1; /* XXX */

// used to count how many call frames deep this recursion goes
// only one is needed since it is initialized to the same value on entry
// and only used after exit from a call, so it can be re-initialized repeatedly
__thread uint32_t call_frame_counter = -1;


#define COUNT_LEVEL(N) \
  ".align 8, 0x90\n" \
  #N ":" \
  "incl %1\n"

void do_call_value(void *state, uint32_t value)
{
    // get a pointer to base of call state array
    __csptr = &(do_call_state[0]);
    // get a clean frame to store state
    int32_t prev_call_frame = cur_do_call_frame++;
    // get a pointer to current call state
    do_call_state_t *cs = &(do_call_state[cur_do_call_frame]);
    // reset frame counter to -1 (it will always increment at least once)
    call_frame_counter = -1;

    // how many COUNT_LEVEL blocks will we jump over?
    cs->__mcsema_jmp_count = NUM_DO_CALL_FRAMES - cur_do_call_frame - 1;

    __asm__ volatile(
            "fxsave %0\n" // save sse state
            "pusha\n" // save all regs just so we don't have bother keeping track of what we saved
            "movl %3, %%eax\n"  // capture "state" arg (mcsema regstate)
            "movl %4, %%ecx\n"  // capture "value" arg (call destination)
            "movl %2, %%esi\n" // pointer to TLS area where we save state
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
            "leal %c[real_esp_off](%%esi), %%edi\n" // where will we save the "real" esp?
            "movl %%esp, (%%edi)\n" // save our esp since we will switch to mcsema esp later
            "movl %c[state_esp](%%eax), %%esp\n" // switch to mcsema stack
            "movl %%ecx, 0(%%esp)\n" // use that slot to store jump destination
            "leal %c[jmp_count](%%esi), %%edi\n" // save recursion count into ecx
            "movl (%%edi), %%ecx\n" // save recursion count into ecx
            "shll $3, %%ecx\n" // multiply recursion count by 8 to get offset (mul 8 = shl 3)
            "leal 0f, %%esi\n" // base return addr
            "addl %%ecx, %%esi\n" // calculate return addr
            "pushl %%esi\n" // push return addr
            "movl %c[state_edi](%%eax), %%edi\n" // dump struct regs to state
            "movl %c[state_ecx](%%eax), %%ecx\n" // complete struct regs spill
            "movl %c[state_esi](%%eax), %%esi\n" // complete struct regs spill
            "movl %c[state_eax](%%eax), %%eax\n" // complete struct regs spill
            "jmpl *4(%%esp)\n"
            COUNT_LEVEL(0) // set of jump locations that increment the call frame counter
            COUNT_LEVEL(1) // the amount of these hit depends on the recursion depth
            COUNT_LEVEL(2) // at depth 0, none are hit, at depth 1, there is 1, etc.
            COUNT_LEVEL(3) // there are 512 incl entries
            COUNT_LEVEL(4)
            COUNT_LEVEL(5)
            COUNT_LEVEL(6)
            COUNT_LEVEL(7)
            COUNT_LEVEL(8)
            COUNT_LEVEL(9)
            COUNT_LEVEL(10)
            COUNT_LEVEL(11)
            COUNT_LEVEL(12)
            COUNT_LEVEL(13)
            COUNT_LEVEL(14)
            COUNT_LEVEL(15)
            COUNT_LEVEL(16)
            COUNT_LEVEL(17)
            COUNT_LEVEL(18)
            COUNT_LEVEL(19)
            COUNT_LEVEL(20)
            COUNT_LEVEL(21)
            COUNT_LEVEL(22)
            COUNT_LEVEL(23)
            COUNT_LEVEL(24)
            COUNT_LEVEL(25)
            COUNT_LEVEL(26)
            COUNT_LEVEL(27)
            COUNT_LEVEL(28)
            COUNT_LEVEL(29)
            COUNT_LEVEL(30)
            COUNT_LEVEL(31)
            COUNT_LEVEL(32)
            COUNT_LEVEL(33)
            COUNT_LEVEL(34)
            COUNT_LEVEL(35)
            COUNT_LEVEL(36)
            COUNT_LEVEL(37)
            COUNT_LEVEL(38)
            COUNT_LEVEL(39)
            COUNT_LEVEL(40)
            COUNT_LEVEL(41)
            COUNT_LEVEL(42)
            COUNT_LEVEL(43)
            COUNT_LEVEL(44)
            COUNT_LEVEL(45)
            COUNT_LEVEL(46)
            COUNT_LEVEL(47)
            COUNT_LEVEL(48)
            COUNT_LEVEL(49)
            COUNT_LEVEL(50)
            COUNT_LEVEL(51)
            COUNT_LEVEL(52)
            COUNT_LEVEL(53)
            COUNT_LEVEL(54)
            COUNT_LEVEL(55)
            COUNT_LEVEL(56)
            COUNT_LEVEL(57)
            COUNT_LEVEL(58)
            COUNT_LEVEL(59)
            COUNT_LEVEL(60)
            COUNT_LEVEL(61)
            COUNT_LEVEL(62)
            COUNT_LEVEL(63)
            COUNT_LEVEL(64)
            COUNT_LEVEL(65)
            COUNT_LEVEL(66)
            COUNT_LEVEL(67)
            COUNT_LEVEL(68)
            COUNT_LEVEL(69)
            COUNT_LEVEL(70)
            COUNT_LEVEL(71)
            COUNT_LEVEL(72)
            COUNT_LEVEL(73)
            COUNT_LEVEL(74)
            COUNT_LEVEL(75)
            COUNT_LEVEL(76)
            COUNT_LEVEL(77)
            COUNT_LEVEL(78)
            COUNT_LEVEL(79)
            COUNT_LEVEL(80)
            COUNT_LEVEL(81)
            COUNT_LEVEL(82)
            COUNT_LEVEL(83)
            COUNT_LEVEL(84)
            COUNT_LEVEL(85)
            COUNT_LEVEL(86)
            COUNT_LEVEL(87)
            COUNT_LEVEL(88)
            COUNT_LEVEL(89)
            COUNT_LEVEL(90)
            COUNT_LEVEL(91)
            COUNT_LEVEL(92)
            COUNT_LEVEL(93)
            COUNT_LEVEL(94)
            COUNT_LEVEL(95)
            COUNT_LEVEL(96)
            COUNT_LEVEL(97)
            COUNT_LEVEL(98)
            COUNT_LEVEL(99)
            COUNT_LEVEL(100)
            COUNT_LEVEL(101)
            COUNT_LEVEL(102)
            COUNT_LEVEL(103)
            COUNT_LEVEL(104)
            COUNT_LEVEL(105)
            COUNT_LEVEL(106)
            COUNT_LEVEL(107)
            COUNT_LEVEL(108)
            COUNT_LEVEL(109)
            COUNT_LEVEL(110)
            COUNT_LEVEL(111)
            COUNT_LEVEL(112)
            COUNT_LEVEL(113)
            COUNT_LEVEL(114)
            COUNT_LEVEL(115)
            COUNT_LEVEL(116)
            COUNT_LEVEL(117)
            COUNT_LEVEL(118)
            COUNT_LEVEL(119)
            COUNT_LEVEL(120)
            COUNT_LEVEL(121)
            COUNT_LEVEL(122)
            COUNT_LEVEL(123)
            COUNT_LEVEL(124)
            COUNT_LEVEL(125)
            COUNT_LEVEL(126)
            COUNT_LEVEL(127)
            COUNT_LEVEL(128)
            COUNT_LEVEL(129)
            COUNT_LEVEL(130)
            COUNT_LEVEL(131)
            COUNT_LEVEL(132)
            COUNT_LEVEL(133)
            COUNT_LEVEL(134)
            COUNT_LEVEL(135)
            COUNT_LEVEL(136)
            COUNT_LEVEL(137)
            COUNT_LEVEL(138)
            COUNT_LEVEL(139)
            COUNT_LEVEL(140)
            COUNT_LEVEL(141)
            COUNT_LEVEL(142)
            COUNT_LEVEL(143)
            COUNT_LEVEL(144)
            COUNT_LEVEL(145)
            COUNT_LEVEL(146)
            COUNT_LEVEL(147)
            COUNT_LEVEL(148)
            COUNT_LEVEL(149)
            COUNT_LEVEL(150)
            COUNT_LEVEL(151)
            COUNT_LEVEL(152)
            COUNT_LEVEL(153)
            COUNT_LEVEL(154)
            COUNT_LEVEL(155)
            COUNT_LEVEL(156)
            COUNT_LEVEL(157)
            COUNT_LEVEL(158)
            COUNT_LEVEL(159)
            COUNT_LEVEL(160)
            COUNT_LEVEL(161)
            COUNT_LEVEL(162)
            COUNT_LEVEL(163)
            COUNT_LEVEL(164)
            COUNT_LEVEL(165)
            COUNT_LEVEL(166)
            COUNT_LEVEL(167)
            COUNT_LEVEL(168)
            COUNT_LEVEL(169)
            COUNT_LEVEL(170)
            COUNT_LEVEL(171)
            COUNT_LEVEL(172)
            COUNT_LEVEL(173)
            COUNT_LEVEL(174)
            COUNT_LEVEL(175)
            COUNT_LEVEL(176)
            COUNT_LEVEL(177)
            COUNT_LEVEL(178)
            COUNT_LEVEL(179)
            COUNT_LEVEL(180)
            COUNT_LEVEL(181)
            COUNT_LEVEL(182)
            COUNT_LEVEL(183)
            COUNT_LEVEL(184)
            COUNT_LEVEL(185)
            COUNT_LEVEL(186)
            COUNT_LEVEL(187)
            COUNT_LEVEL(188)
            COUNT_LEVEL(189)
            COUNT_LEVEL(190)
            COUNT_LEVEL(191)
            COUNT_LEVEL(192)
            COUNT_LEVEL(193)
            COUNT_LEVEL(194)
            COUNT_LEVEL(195)
            COUNT_LEVEL(196)
            COUNT_LEVEL(197)
            COUNT_LEVEL(198)
            COUNT_LEVEL(199)
            COUNT_LEVEL(200)
            COUNT_LEVEL(201)
            COUNT_LEVEL(202)
            COUNT_LEVEL(203)
            COUNT_LEVEL(204)
            COUNT_LEVEL(205)
            COUNT_LEVEL(206)
            COUNT_LEVEL(207)
            COUNT_LEVEL(208)
            COUNT_LEVEL(209)
            COUNT_LEVEL(210)
            COUNT_LEVEL(211)
            COUNT_LEVEL(212)
            COUNT_LEVEL(213)
            COUNT_LEVEL(214)
            COUNT_LEVEL(215)
            COUNT_LEVEL(216)
            COUNT_LEVEL(217)
            COUNT_LEVEL(218)
            COUNT_LEVEL(219)
            COUNT_LEVEL(220)
            COUNT_LEVEL(221)
            COUNT_LEVEL(222)
            COUNT_LEVEL(223)
            COUNT_LEVEL(224)
            COUNT_LEVEL(225)
            COUNT_LEVEL(226)
            COUNT_LEVEL(227)
            COUNT_LEVEL(228)
            COUNT_LEVEL(229)
            COUNT_LEVEL(230)
            COUNT_LEVEL(231)
            COUNT_LEVEL(232)
            COUNT_LEVEL(233)
            COUNT_LEVEL(234)
            COUNT_LEVEL(235)
            COUNT_LEVEL(236)
            COUNT_LEVEL(237)
            COUNT_LEVEL(238)
            COUNT_LEVEL(239)
            COUNT_LEVEL(240)
            COUNT_LEVEL(241)
            COUNT_LEVEL(242)
            COUNT_LEVEL(243)
            COUNT_LEVEL(244)
            COUNT_LEVEL(245)
            COUNT_LEVEL(246)
            COUNT_LEVEL(247)
            COUNT_LEVEL(248)
            COUNT_LEVEL(249)
            COUNT_LEVEL(250)
            COUNT_LEVEL(251)
            COUNT_LEVEL(252)
            COUNT_LEVEL(253)
            COUNT_LEVEL(254)
            COUNT_LEVEL(255)
            COUNT_LEVEL(256)
            COUNT_LEVEL(257)
            COUNT_LEVEL(258)
            COUNT_LEVEL(259)
            COUNT_LEVEL(260)
            COUNT_LEVEL(261)
            COUNT_LEVEL(262)
            COUNT_LEVEL(263)
            COUNT_LEVEL(264)
            COUNT_LEVEL(265)
            COUNT_LEVEL(266)
            COUNT_LEVEL(267)
            COUNT_LEVEL(268)
            COUNT_LEVEL(269)
            COUNT_LEVEL(270)
            COUNT_LEVEL(271)
            COUNT_LEVEL(272)
            COUNT_LEVEL(273)
            COUNT_LEVEL(274)
            COUNT_LEVEL(275)
            COUNT_LEVEL(276)
            COUNT_LEVEL(277)
            COUNT_LEVEL(278)
            COUNT_LEVEL(279)
            COUNT_LEVEL(280)
            COUNT_LEVEL(281)
            COUNT_LEVEL(282)
            COUNT_LEVEL(283)
            COUNT_LEVEL(284)
            COUNT_LEVEL(285)
            COUNT_LEVEL(286)
            COUNT_LEVEL(287)
            COUNT_LEVEL(288)
            COUNT_LEVEL(289)
            COUNT_LEVEL(290)
            COUNT_LEVEL(291)
            COUNT_LEVEL(292)
            COUNT_LEVEL(293)
            COUNT_LEVEL(294)
            COUNT_LEVEL(295)
            COUNT_LEVEL(296)
            COUNT_LEVEL(297)
            COUNT_LEVEL(298)
            COUNT_LEVEL(299)
            COUNT_LEVEL(300)
            COUNT_LEVEL(301)
            COUNT_LEVEL(302)
            COUNT_LEVEL(303)
            COUNT_LEVEL(304)
            COUNT_LEVEL(305)
            COUNT_LEVEL(306)
            COUNT_LEVEL(307)
            COUNT_LEVEL(308)
            COUNT_LEVEL(309)
            COUNT_LEVEL(310)
            COUNT_LEVEL(311)
            COUNT_LEVEL(312)
            COUNT_LEVEL(313)
            COUNT_LEVEL(314)
            COUNT_LEVEL(315)
            COUNT_LEVEL(316)
            COUNT_LEVEL(317)
            COUNT_LEVEL(318)
            COUNT_LEVEL(319)
            COUNT_LEVEL(320)
            COUNT_LEVEL(321)
            COUNT_LEVEL(322)
            COUNT_LEVEL(323)
            COUNT_LEVEL(324)
            COUNT_LEVEL(325)
            COUNT_LEVEL(326)
            COUNT_LEVEL(327)
            COUNT_LEVEL(328)
            COUNT_LEVEL(329)
            COUNT_LEVEL(330)
            COUNT_LEVEL(331)
            COUNT_LEVEL(332)
            COUNT_LEVEL(333)
            COUNT_LEVEL(334)
            COUNT_LEVEL(335)
            COUNT_LEVEL(336)
            COUNT_LEVEL(337)
            COUNT_LEVEL(338)
            COUNT_LEVEL(339)
            COUNT_LEVEL(340)
            COUNT_LEVEL(341)
            COUNT_LEVEL(342)
            COUNT_LEVEL(343)
            COUNT_LEVEL(344)
            COUNT_LEVEL(345)
            COUNT_LEVEL(346)
            COUNT_LEVEL(347)
            COUNT_LEVEL(348)
            COUNT_LEVEL(349)
            COUNT_LEVEL(350)
            COUNT_LEVEL(351)
            COUNT_LEVEL(352)
            COUNT_LEVEL(353)
            COUNT_LEVEL(354)
            COUNT_LEVEL(355)
            COUNT_LEVEL(356)
            COUNT_LEVEL(357)
            COUNT_LEVEL(358)
            COUNT_LEVEL(359)
            COUNT_LEVEL(360)
            COUNT_LEVEL(361)
            COUNT_LEVEL(362)
            COUNT_LEVEL(363)
            COUNT_LEVEL(364)
            COUNT_LEVEL(365)
            COUNT_LEVEL(366)
            COUNT_LEVEL(367)
            COUNT_LEVEL(368)
            COUNT_LEVEL(369)
            COUNT_LEVEL(370)
            COUNT_LEVEL(371)
            COUNT_LEVEL(372)
            COUNT_LEVEL(373)
            COUNT_LEVEL(374)
            COUNT_LEVEL(375)
            COUNT_LEVEL(376)
            COUNT_LEVEL(377)
            COUNT_LEVEL(378)
            COUNT_LEVEL(379)
            COUNT_LEVEL(380)
            COUNT_LEVEL(381)
            COUNT_LEVEL(382)
            COUNT_LEVEL(383)
            COUNT_LEVEL(384)
            COUNT_LEVEL(385)
            COUNT_LEVEL(386)
            COUNT_LEVEL(387)
            COUNT_LEVEL(388)
            COUNT_LEVEL(389)
            COUNT_LEVEL(390)
            COUNT_LEVEL(391)
            COUNT_LEVEL(392)
            COUNT_LEVEL(393)
            COUNT_LEVEL(394)
            COUNT_LEVEL(395)
            COUNT_LEVEL(396)
            COUNT_LEVEL(397)
            COUNT_LEVEL(398)
            COUNT_LEVEL(399)
            COUNT_LEVEL(400)
            COUNT_LEVEL(401)
            COUNT_LEVEL(402)
            COUNT_LEVEL(403)
            COUNT_LEVEL(404)
            COUNT_LEVEL(405)
            COUNT_LEVEL(406)
            COUNT_LEVEL(407)
            COUNT_LEVEL(408)
            COUNT_LEVEL(409)
            COUNT_LEVEL(410)
            COUNT_LEVEL(411)
            COUNT_LEVEL(412)
            COUNT_LEVEL(413)
            COUNT_LEVEL(414)
            COUNT_LEVEL(415)
            COUNT_LEVEL(416)
            COUNT_LEVEL(417)
            COUNT_LEVEL(418)
            COUNT_LEVEL(419)
            COUNT_LEVEL(420)
            COUNT_LEVEL(421)
            COUNT_LEVEL(422)
            COUNT_LEVEL(423)
            COUNT_LEVEL(424)
            COUNT_LEVEL(425)
            COUNT_LEVEL(426)
            COUNT_LEVEL(427)
            COUNT_LEVEL(428)
            COUNT_LEVEL(429)
            COUNT_LEVEL(430)
            COUNT_LEVEL(431)
            COUNT_LEVEL(432)
            COUNT_LEVEL(433)
            COUNT_LEVEL(434)
            COUNT_LEVEL(435)
            COUNT_LEVEL(436)
            COUNT_LEVEL(437)
            COUNT_LEVEL(438)
            COUNT_LEVEL(439)
            COUNT_LEVEL(440)
            COUNT_LEVEL(441)
            COUNT_LEVEL(442)
            COUNT_LEVEL(443)
            COUNT_LEVEL(444)
            COUNT_LEVEL(445)
            COUNT_LEVEL(446)
            COUNT_LEVEL(447)
            COUNT_LEVEL(448)
            COUNT_LEVEL(449)
            COUNT_LEVEL(450)
            COUNT_LEVEL(451)
            COUNT_LEVEL(452)
            COUNT_LEVEL(453)
            COUNT_LEVEL(454)
            COUNT_LEVEL(455)
            COUNT_LEVEL(456)
            COUNT_LEVEL(457)
            COUNT_LEVEL(458)
            COUNT_LEVEL(459)
            COUNT_LEVEL(460)
            COUNT_LEVEL(461)
            COUNT_LEVEL(462)
            COUNT_LEVEL(463)
            COUNT_LEVEL(464)
            COUNT_LEVEL(465)
            COUNT_LEVEL(466)
            COUNT_LEVEL(467)
            COUNT_LEVEL(468)
            COUNT_LEVEL(469)
            COUNT_LEVEL(470)
            COUNT_LEVEL(471)
            COUNT_LEVEL(472)
            COUNT_LEVEL(473)
            COUNT_LEVEL(474)
            COUNT_LEVEL(475)
            COUNT_LEVEL(476)
            COUNT_LEVEL(477)
            COUNT_LEVEL(478)
            COUNT_LEVEL(479)
            COUNT_LEVEL(480)
            COUNT_LEVEL(481)
            COUNT_LEVEL(482)
            COUNT_LEVEL(483)
            COUNT_LEVEL(484)
            COUNT_LEVEL(485)
            COUNT_LEVEL(486)
            COUNT_LEVEL(487)
            COUNT_LEVEL(488)
            COUNT_LEVEL(489)
            COUNT_LEVEL(490)
            COUNT_LEVEL(491)
            COUNT_LEVEL(492)
            COUNT_LEVEL(493)
            COUNT_LEVEL(494)
            COUNT_LEVEL(495)
            COUNT_LEVEL(496)
            COUNT_LEVEL(497)
            COUNT_LEVEL(498)
            COUNT_LEVEL(499)
            COUNT_LEVEL(500)
            COUNT_LEVEL(501)
            COUNT_LEVEL(502)
            COUNT_LEVEL(503)
            COUNT_LEVEL(504)
            COUNT_LEVEL(505)
            COUNT_LEVEL(506)
            COUNT_LEVEL(507)
            COUNT_LEVEL(508)
            COUNT_LEVEL(509)
            COUNT_LEVEL(510)
            COUNT_LEVEL(511)
            "pushl %%eax\n" // save return value
            "pushl %%esi\n" // save temp reg
            "movl %1, %%eax\n" // get our recursion depth
            "imull $%c[struct_size], %%eax\n" // see where we need to index into the save state array
            "movl %5, %%esi\n" // get address of array base
            "addl %%esi, %%eax\n" // eax now points to our old saved state (array base + index * element size)
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
            "popa\n"
            "fxrstor %0\n"
            : "=m"(cs->sse_state), "=m"(call_frame_counter)
            : "m"(cs), "m"(state), "m"(value), "m"(__csptr),
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
    
    // reset call frame depth
    cur_do_call_frame = prev_call_frame;
    // reset call frame counter
    call_frame_counter = -1;
}
