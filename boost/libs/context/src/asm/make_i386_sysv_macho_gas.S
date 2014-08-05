/*
            Copyright Oliver Kowalke 2009.
   Distributed under the Boost Software License, Version 1.0.
      (See accompanying file LICENSE_1_0.txt or copy at
          http://www.boost.org/LICENSE_1_0.txt)
*/

/********************************************************************
 *                                                                  *
 *  --------------------------------------------------------------  *
 *  |    0    |    1    |    2    |    3    |    4     |    5    |  *
 *  --------------------------------------------------------------  *
 *  |   0x0   |   0x4   |   0x8   |   0xc   |   0x10   |   0x14  |  *
 *  --------------------------------------------------------------  *
 *  |   EDI   |   ESI   |   EBX   |   EBP   |   ESP    |   EIP   |  *
 *  --------------------------------------------------------------  *
 *  --------------------------------------------------------------  *
 *  |    6    |    7    |                                        |  *
 *  --------------------------------------------------------------  *
 *  |   0x18  |   0x1c  |                                        |  *
 *  --------------------------------------------------------------  *
 *  |    sp   |   size  |                                        |  *
 *  --------------------------------------------------------------  *
 *  --------------------------------------------------------------  *
 *  |    8    |    9    |                                        |  *
 *  --------------------------------------------------------------  *
 *  |   0x20  |   0x24  |                                        |  *
 *  --------------------------------------------------------------  *
 *  | fc_mxcsr|fc_x87_cw|                                        |  *
 *  --------------------------------------------------------------  *
 *                                                                  *
 * *****************************************************************/

.text
.globl _make_fcontext
.align 2
_make_fcontext:
    pushl  %ebp                         /* save previous frame pointer; get the stack 16 byte aligned */
    movl   %esp,           %ebp         /* set EBP to ESP */
    subl   $0x10,          %esp         /* allocate stack space */

    movl   0x8(%ebp),      %eax         /* load 1. arg of make_fcontext, pointer to context stack (base) */
    leal   -0x28(%eax),    %eax         /* reserve space for fcontext_t at top of context stack */
    movl   %eax,           (%esp)       /* address in EAX becomes 1. arg of align_stack */
    call   _align_stack                 /* call align_stack, EAX contains address at 16 byte boundary after return */
                                        /* ==pointer to fcontext_t and address of context stack */

    movl   0x8(%ebp),      %edx         /* load 1. arg of make_fcontext, pointer to context stack (base) */
    movl   %edx,           0x18(%eax)   /* save address of stack pointer (base) in fcontext_t */
    movl   0xc(%ebp),      %edx         /* load 2. arg of make_fcontext, context stack size */
    movl   %edx,           0x1c(%eax)   /* save stack size in fcontext_t */
    movl   0x10(%ebp),     %edx         /* load 3. arg of make_fcontext, pointer to context function */
    movl   %edx,           0x14(%eax)   /* save address of context fcuntion in fcontext_t */

    stmxcsr  0x20(%eax)                 /* save MMX control and status word */
    fnstcw   0x24(%eax)                 /* save x87 control word */

    leal   -0xc(%eax),     %edx         /* reserve space for the last frame on context stack, (ESP - 0x4) % 16 == 0 */
    movl   %edx,           0x10(%eax)   /* save address in EDX as stack pointer for context function */

    call   1f
1:  popl   %ecx                         /* address of label 1 */
    addl   $finish-1b,     %ecx         /* compute abs address of label finish */
    movl    %ecx, (%edx)                /* save address of finish as return address for context function */
                                        /* entered after context function returns */

    addl   $0x10,          %esp         /* deallocate stack space */
    pop    %ebp

    ret

finish:
    /* ESP points to same address as ESP on entry of context function + 0x4 */
    xorl    %eax,  %eax
    movl    %eax,  (%esp)               /* exit code is zero */
    call   _exit                        /* exit application */
    hlt
