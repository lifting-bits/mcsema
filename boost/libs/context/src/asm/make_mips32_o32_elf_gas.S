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
 *  |  S0 |  S1 |  S2 |  S3 |  S4 |  S5 |  S6 |  S7 |  FP |  SP |  *
 *  -------------------------------------------------------------  *
 *  -------------------------------------------------------------  *
 *  |  10 |  11 |                                               |  *
 *  -------------------------------------------------------------  *
 *  |  40 |  44 |                                               |  *
 *  -------------------------------------------------------------  *
 *  |  RA |  PC |                                               |  *
 *  -------------------------------------------------------------  *
 *  -------------------------------------------------------------  *
 *  |  12 |  13 |                                               |  *
 *  -------------------------------------------------------------  *
 *  |  48 |  52 |                                               |  *
 *  -------------------------------------------------------------  *
 *  |  sp | size|                                               |  *
 *  -------------------------------------------------------------  *
 *  -------------------------------------------------------------  *
 *  |  14 |  15 |  16 |  17 |  18 |  19 |                       |  *
 *  -------------------------------------------------------------  *
 *  |  56 |  64 |  72 |  80 |  88 |  96 |                       |  *
 *  -------------------------------------------------------------  *
 *  | F20 | F22 | F24 | F26 | F28 | F30 |                       |  *
 *  -------------------------------------------------------------  *
 *                                                                 *
 * *****************************************************************/

.text
.globl make_fcontext
.align 2
.type make_fcontext,@function
.ent make_fcontext
make_fcontext:
#ifdef __PIC__
.set    noreorder
.cpload $t9
.set    reorder
#endif
    addiu   $sp, $sp, -48       # allocate stack space (contains shadow space for subroutines)
    sw      $ra, 44($sp)        # save return address
    sw      $fp, 40($sp)        # save frame pointer

    sw      $a2, 48($sp)        # save 3. arg of make_fcontnext, pointer to context function
    sw      $a1, 52($sp)        # save 2. arg of make_fcontext, context stack size
    sw      $a0, 56($sp)        # save 1. arg of make_fcontext, pointer to context stack (base)
    addiu   $a0, $a0, -104      # reserve space for fcontext_t at top of context stack
    lw      $t9, %call16(align_stack)($gp) # compute adddress of align_stack via global pointer
    jalr    $t9                 # call align_stack, V0 contains address at 16 byte boundary after return
                                # == pointer to fcontext_t and address of context stack
    lw      $a0, 56($sp)        # restore pointer to context stack (base)
    lw      $a1, 52($sp)        # restore context stack size
    lw      $a2, 48($sp)        # restore pointer to context function

    sw      $a0, 48($v0)        # save address of context stack (base) in fcontext_t 
    sw      $a1, 52($v0)        # save context stack size in fcontext_t 
    sw      $a2, 44($v0)        # save address of context function in fcontext_t 
    sw      $gp, ($v0)          # save global pointer in fcontext_t, S0 will contain address of global pointer

    addiu   $t0, $v0, -48       # reserve 48 bytes (includes 4 byte shadow space), T0 % 16 == 0
    sw      $t0, 36($v0)        # save address in T0 as stack pointer for context function, SP % 16 == 0

    la      $t9, finish         # compute abs address of label finish
    sw      $t9, 40($v0)        # save address of finish as return address for context function
                                # entered after context function returns

    lw      $fp, 40($sp)        # restore frame pointer
    lw      $ra, 44($sp)        # restore return address
    addiu   $sp, $sp, 48        # deallocate stack space

    jr      $ra

finish:
    # SP points to same adddress as SP on entry of context function
    addiu   $sp, $sp, -32       # allocate stack space (contains shadow space for subroutines)
    sw      $ra, 28($sp)        # save return address

    move    $gp, $s0                  # restore GP (global pointer)
    move    $a0, $zero                # exit code is zero
    lw      $t9, %call16(_exit)($gp)  # address of exit
    jalr    $t9                       # exit application
.end make_fcontext
.size make_fcontext, .-make_fcontext
