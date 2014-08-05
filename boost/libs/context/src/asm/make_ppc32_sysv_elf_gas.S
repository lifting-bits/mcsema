/*
            Copyright Oliver Kowalke 2009.
   Distributed under the Boost Software License, Version 1.0.
      (See accompanying file LICENSE_1_0.txt or copy at
          http://www.boost.org/LICENSE_1_0.txt)
*/

/*******************************************************************
 *                                                                 *
 *  -------------------------------------------------------------  *
 *  |  0  |  1  |  2  |  3  |  4  |  5  |  6  |  7  |  8  |  9  |  *
 *  -------------------------------------------------------------  *
 *  |  0  |  4  |  8  |  12 |  16 |  20 |  24 |  28 |  32 |  36 |  *
 *  -------------------------------------------------------------  *
 *  | R13 | R14 | R15 | R16 | R17 | R18 | R19 | R20 | R21 | R22 |  *
 *  -------------------------------------------------------------  *
 *  -------------------------------------------------------------  *
 *  |  10 |  11 |  12 |  13 |  14 |  15 |  16 |  17 |  18 |  19 |  *
 *  -------------------------------------------------------------  *
 *  |  40 |  44 |  48 |  52 |  56 |  60 |  64 |  68 |  72 |  76 |  *
 *  -------------------------------------------------------------  *
 *  | R23 | R24 | R25 | R26 | R27 | R28 | R29 | R30 | R31 |  SP |  *
 *  -------------------------------------------------------------  *
 *  -------------------------------------------------------------  *
 *  |  20 |  21 |  22 |                                         |  *
 *  -------------------------------------------------------------  *
 *  |  80 |  84 |  88 |                                         |  *
 *  -------------------------------------------------------------  *
 *  |  CR |  LR |  PC |                                         |  *
 *  -------------------------------------------------------------  *
 *  -------------------------------------------------------------  *
 *  |  23 |  24 |                                               |  *
 *  -------------------------------------------------------------  *
 *  |  92 |  96 |                                               |  *
 *  -------------------------------------------------------------  *
 *  |  sp | size|                                               |  *
 *  -------------------------------------------------------------  *
 *  -------------------------------------------------------------  *
 *  |  25 |  26 |  27 |  28 |  29 |  30 |  31 |  32 |  33 |  34 |  *
 *  -------------------------------------------------------------  *
 *  | 100 | 104 | 108 | 112 | 116 | 120 | 124 | 128 | 132 | 136 |  *
 *  -------------------------------------------------------------  *
 *  |    F14    |    F15    |    F16    |    F17    |    F18    |  *
 *  -------------------------------------------------------------  *
 *  -------------------------------------------------------------  *
 *  |  35 |  36 |  37 |  38 |  39 |  40 |  41 |  42 |  43 |  44 |  *
 *  -------------------------------------------------------------  *
 *  | 140 | 144 | 148 | 152 | 156 | 160 | 164 | 168 | 172 | 176 |  *
 *  -------------------------------------------------------------  *
 *  |    F19    |    F20    |    F21    |    F22    |    F23    |  *
 *  -------------------------------------------------------------  *
 *  -------------------------------------------------------------  *
 *  |  45 |  46 |  47 |  48 |  49 |  50 |  51 |  52 |  53 |  54 |  *
 *  -------------------------------------------------------------  *
 *  | 180 | 184 | 188 | 192 | 196 | 200 | 204 | 208 | 212 | 216 |  *
 *  -------------------------------------------------------------  *
 *  |    F24    |    F25    |    F26    |    F27    |    F28    |  *
 *  -------------------------------------------------------------  *
 *  -------------------------------------------------------------  *
 *  |  55 |  56 |  57 |  58 |  59 |  60 |  61 |  62 |           |  *
 *  -------------------------------------------------------------  *
 *  | 220 | 224 | 228 | 232 | 236 | 240 | 244 | 248 |           |  *
 *  -------------------------------------------------------------  *
 *  |    F29    |    F30    |    F31    |   fpscr   |           |  *
 *  -------------------------------------------------------------  *
 *                                                                 *
 * *****************************************************************/

.text
.globl make_fcontext
.align 2
.type make_fcontext,@function
make_fcontext:
    mflr    %r0                 # save return address into R0
    stw     %r0, 4(%r1)         # save return address on stack, set up stack frame
    stwu    %r1, -48(%r1)       # allocate stack space, SP % 16 == 0

    stw     %r5, 32(%r1)        # save 3. arg of make_fcontext, pointer to context function 
    stw     %r4, 28(%r1)        # save 2. arg of make_fcontext, context stack size 
    stw     %r3, 24(%r1)        # save 1. arg of make_fcontext, pointer to context stack (base) 

    subi    %r3, %r3, 252       # reserve space for fcontext_t at top of context stack
    bl      align_stack@plt     # call align_stack, R3 contains address at 16 byte boundary after return
                                # == pointer to fcontext_t and address of context stack
    lwz     %r4, 24(%r1)        # restore pointer to context stack (base)
    lwz     %r5, 28(%r1)        # restore context stack size
    lwz     %r6, 32(%r1)        # restore pointer to context function

    stw     %r4, 92(%r3)        # save address of context stack (base) in fcontext_t
    stw     %r5, 96(%r3)        # save context stack size in fcontext_t
    stw     %r6, 88(%r3)        # save address of context function in fcontext_t

    subi    %r0, %r3, 64        # reserve 64 bytes (linkage + parameter area), R0 % 16 == 0
    stw     %r0, 76(%r3)        # save address in R0 as stack pointer for context function

    mflr    %r0                 # load LR
    bl      1f                  # jump to label 1
1:
    mflr    %r4                      # load LR into R4
    addi    %r4, %r4, finish - 1b    # compute abs address of label finish
    mtlr    %r0                      # restore LR
    stw     %r4, 84(%r3)             # save address of finish as return address for context function
                                     # entered after context function returns

    addi    %r1, %r1, 48        # deallocate stack space
    lwz     %r0, 4(%r1)         # load return address from stack, destroy stack frame
    mtlr    %r0                 # restore return address

    blr

finish:
    # SP points to same address as SP on entry of context function
    mflr    %r0                 # save return address into R0
    stw     %r0, 4(%r1)         # save return address on stack, set up stack frame
    stwu    %r1, -16(%r1)       # allocate stack space, SP % 16 == 0

    li      %r3,  0             # exit code is zero
    bl      _exit@plt           # exit application
.size make_fcontext, .-make_fcontext
