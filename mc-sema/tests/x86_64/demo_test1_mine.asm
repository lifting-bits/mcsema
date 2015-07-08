	.text
	.def	 demo1_entry;
	.scl	2;
	.type	32;
	.endef
	.globl	demo1_entry
	.align	16, 0x90
demo1_entry:                            # @demo1_entry
# BB#0:                                 # %driverBlockRaw
	pushq	%r15
	pushq	%r14
	pushq	%r13
	pushq	%r12
	pushq	%rsi
	pushq	%rdi
	pushq	%rbp
	pushq	%rbx
	subq	$168, %rsp
	movaps	%xmm6, 144(%rsp)        # 16-byte Spill
	movq	%rcx, %rax
	movl	(%rax), %r9d
	movups	8(%rax), %xmm0
	movups	24(%rax), %xmm1
	movq	40(%rax), %r14
	movq	48(%rax), %r10
	movups	56(%rax), %xmm2
	movups	72(%rax), %xmm3
	movups	88(%rax), %xmm4
	movups	104(%rax), %xmm5
	movups	120(%rax), %xmm6
	movb	142(%rax), %cl
	movb	%cl, 15(%rsp)           # 1-byte Spill
	leaq	143(%rax), %r11
	leaq	16(%rsp), %rdi
	movl	$32, %ecx
	movq	%rdi, %r15
	movq	%r11, %rsi
	rep;movsl
	movb	271(%rax), %cl
	movb	%cl, 14(%rsp)           # 1-byte Spill
	movb	272(%rax), %cl
	movb	%cl, 13(%rsp)           # 1-byte Spill
	movb	273(%rax), %bpl
	movb	274(%rax), %cl
	movb	%cl, 12(%rsp)           # 1-byte Spill
	movb	275(%rax), %cl
	movb	%cl, 11(%rsp)           # 1-byte Spill
	movb	276(%rax), %r12b
	movb	277(%rax), %r13b
	movb	278(%rax), %cl
	movb	%cl, 10(%rsp)           # 1-byte Spill
	movl	%r9d, %esi
	addl	$1, %esi
	setb	%dil
	movl	%esi, %r8d
	xorl	%r9d, %r8d
	movb	%r8b, %bl
	shrb	$4, %bl
	xorl	$-2147483648, %r9d      # imm = 0xFFFFFFFF80000000
	movb	%sil, %dl
	shrb	%dl
	andb	$85, %dl
	movb	%sil, %cl
	subb	%dl, %cl
	movb	%cl, %dl
	andb	$51, %dl
	shrb	$2, %cl
	andb	$51, %cl
	addb	%dl, %cl
	movb	%cl, %dl
	shrb	$4, %dl
	addb	%cl, %dl
	addq	$8, %r10
	testb	$1, %dl
	movq	%rsi, (%rax)
	movups	%xmm0, 8(%rax)
	movups	%xmm1, 24(%rax)
	movq	%r14, 40(%rax)
	movq	%r10, 48(%rax)
	movups	%xmm2, 56(%rax)
	movups	%xmm3, 72(%rax)
	movups	%xmm4, 88(%rax)
	movups	%xmm5, 104(%rax)
	movups	%xmm6, 120(%rax)
	movb	%dil, 136(%rax)
	sete	137(%rax)
	andb	$1, %bl
	testl	%esi, %esi
	movb	%bl, 138(%rax)
	sete	139(%rax)
	sets	140(%rax)
	testl	%r9d, %r8d
	sets	141(%rax)
	movb	15(%rsp), %cl           # 1-byte Reload
	movb	%cl, 142(%rax)
	movl	$16, %ecx
	movq	%r11, %rdi
	movq	%r15, %rsi
	rep;movsq
	movb	14(%rsp), %cl           # 1-byte Reload
	movb	%cl, 271(%rax)
	movb	13(%rsp), %cl           # 1-byte Reload
	movb	%cl, 272(%rax)
	movb	%bpl, 273(%rax)
	movb	12(%rsp), %cl           # 1-byte Reload
	movb	%cl, 274(%rax)
	movb	11(%rsp), %cl           # 1-byte Reload
	movb	%cl, 275(%rax)
	movb	%r12b, 276(%rax)
	movb	%r13b, 277(%rax)
	movb	10(%rsp), %cl           # 1-byte Reload
	movb	%cl, 278(%rax)
	movaps	144(%rsp), %xmm6        # 16-byte Reload
	addq	$168, %rsp
	popq	%rbx
	popq	%rbp
	popq	%rdi
	popq	%rsi
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%r15
	retq


