/* Auto-generated file! Don't modify! */

  .file __FILE__
  .intel_syntax noprefix

  .type __mcsema_reg_state,@object
  .section .tbss,"awT",@nobits
__mcsema_reg_state:
  .zero 596
  .size __mcsema_reg_state, 100

  .type __mcsema_stack,@object
  .section .tbss,"awT",@nobits
__mcsema_stack:
  .zero 1048576
  .size __mcsema_stack, 100

  .text

  .globl mcsema_main
  .globl __mcsema_detach_ret

  .globl __mcsema_attach_call
  .type __mcsema_attach_call,@function
__mcsema_attach_call:
  .cfi_startproc
  pop QWORD PTR fs:[__mcsema_reg_state@TPOFF + 0]
  mov fs:[__mcsema_reg_state@TPOFF + 8], rax
  mov fs:[__mcsema_reg_state@TPOFF + 16], rbx
  mov fs:[__mcsema_reg_state@TPOFF + 24], rcx
  mov fs:[__mcsema_reg_state@TPOFF + 32], rdx
  mov fs:[__mcsema_reg_state@TPOFF + 40], rsi
  mov fs:[__mcsema_reg_state@TPOFF + 48], rdi
  mov fs:[__mcsema_reg_state@TPOFF + 64], rbp
  xchg rsp, fs:[__mcsema_reg_state@TPOFF + 56]
  mov fs:[__mcsema_reg_state@TPOFF + 532], r8
  mov fs:[__mcsema_reg_state@TPOFF + 540], r9
  mov fs:[__mcsema_reg_state@TPOFF + 548], r10
  mov fs:[__mcsema_reg_state@TPOFF + 556], r11
  mov fs:[__mcsema_reg_state@TPOFF + 564], r12
  mov fs:[__mcsema_reg_state@TPOFF + 572], r13
  mov fs:[__mcsema_reg_state@TPOFF + 580], r14
  mov fs:[__mcsema_reg_state@TPOFF + 588], r15
  movdqu fs:[__mcsema_reg_state@TPOFF + 260], xmm0
  movdqu fs:[__mcsema_reg_state@TPOFF + 276], xmm1
  movdqu fs:[__mcsema_reg_state@TPOFF + 292], xmm2
  movdqu fs:[__mcsema_reg_state@TPOFF + 308], xmm3
  movdqu fs:[__mcsema_reg_state@TPOFF + 324], xmm4
  movdqu fs:[__mcsema_reg_state@TPOFF + 340], xmm5
  movdqu fs:[__mcsema_reg_state@TPOFF + 356], xmm6
  movdqu fs:[__mcsema_reg_state@TPOFF + 372], xmm7
  movdqu fs:[__mcsema_reg_state@TPOFF + 388], xmm8
  movdqu fs:[__mcsema_reg_state@TPOFF + 404], xmm9
  movdqu fs:[__mcsema_reg_state@TPOFF + 420], xmm10
  movdqu fs:[__mcsema_reg_state@TPOFF + 436], xmm11
  movdqu fs:[__mcsema_reg_state@TPOFF + 452], xmm12
  movdqu fs:[__mcsema_reg_state@TPOFF + 468], xmm13
  movdqu fs:[__mcsema_reg_state@TPOFF + 484], xmm14
  movdqu fs:[__mcsema_reg_state@TPOFF + 500], xmm15
  cmp rsp, 0
  jnz .Lhave_stack
  mov rsp, fs:[0]
  lea rsp, [rsp + __mcsema_stack@TPOFF + 1048576]
.Lhave_stack:
  lea rdi, [rip + __mcsema_detach_ret]
  push rdi
  mov rdi, fs:[0]
  lea rdi, [rdi + __mcsema_reg_state@TPOFF]
  jmp fs:[__mcsema_reg_state@TPOFF + 0]
.Lfunc_end1:
  .size __mcsema_attach_call,.Lfunc_end1-__mcsema_attach_call
  .cfi_endproc

  .globl __mcsema_attach_ret
  .type __mcsema_attach_ret,@function
__mcsema_attach_ret:
  .cfi_startproc
  xchg rsp, fs:[__mcsema_reg_state@TPOFF + 56]
  mov fs:[__mcsema_reg_state@TPOFF + 8], rax
  mov fs:[__mcsema_reg_state@TPOFF + 32], rdx
  movdqu fs:[__mcsema_reg_state@TPOFF + 260], xmm0
  mov fs:[__mcsema_reg_state@TPOFF + 16], rbx
  mov fs:[__mcsema_reg_state@TPOFF + 64], rbp
  mov fs:[__mcsema_reg_state@TPOFF + 564], r12
  mov fs:[__mcsema_reg_state@TPOFF + 572], r13
  mov fs:[__mcsema_reg_state@TPOFF + 580], r14
  mov fs:[__mcsema_reg_state@TPOFF + 588], r15
  pop r15
  pop r14
  pop r13
  pop r12
  pop rbp
  pop rbx
  ret
.Lfunc_end2:
  .size __mcsema_attach_ret,.Lfunc_end2-__mcsema_attach_ret
  .cfi_endproc

  .globl __mcsema_attach_ret_value
  .type __mcsema_attach_ret_value,@function
__mcsema_attach_ret_value:
  .cfi_startproc
  mov fs:[__mcsema_reg_state@TPOFF + 8], rax
  mov fs:[__mcsema_reg_state@TPOFF + 16], rbx
  mov fs:[__mcsema_reg_state@TPOFF + 24], rcx
  mov fs:[__mcsema_reg_state@TPOFF + 32], rdx
  mov fs:[__mcsema_reg_state@TPOFF + 40], rsi
  mov fs:[__mcsema_reg_state@TPOFF + 48], rdi
  mov fs:[__mcsema_reg_state@TPOFF + 64], rbp
  xchg rsp, fs:[__mcsema_reg_state@TPOFF + 56]
  mov fs:[__mcsema_reg_state@TPOFF + 532], r8
  mov fs:[__mcsema_reg_state@TPOFF + 540], r9
  mov fs:[__mcsema_reg_state@TPOFF + 548], r10
  mov fs:[__mcsema_reg_state@TPOFF + 556], r11
  mov fs:[__mcsema_reg_state@TPOFF + 564], r12
  mov fs:[__mcsema_reg_state@TPOFF + 572], r13
  mov fs:[__mcsema_reg_state@TPOFF + 580], r14
  mov fs:[__mcsema_reg_state@TPOFF + 588], r15
  movdqu fs:[__mcsema_reg_state@TPOFF + 260], xmm0
  movdqu fs:[__mcsema_reg_state@TPOFF + 276], xmm1
  movdqu fs:[__mcsema_reg_state@TPOFF + 292], xmm2
  movdqu fs:[__mcsema_reg_state@TPOFF + 308], xmm3
  movdqu fs:[__mcsema_reg_state@TPOFF + 324], xmm4
  movdqu fs:[__mcsema_reg_state@TPOFF + 340], xmm5
  movdqu fs:[__mcsema_reg_state@TPOFF + 356], xmm6
  movdqu fs:[__mcsema_reg_state@TPOFF + 372], xmm7
  movdqu fs:[__mcsema_reg_state@TPOFF + 388], xmm8
  movdqu fs:[__mcsema_reg_state@TPOFF + 404], xmm9
  movdqu fs:[__mcsema_reg_state@TPOFF + 420], xmm10
  movdqu fs:[__mcsema_reg_state@TPOFF + 436], xmm11
  movdqu fs:[__mcsema_reg_state@TPOFF + 452], xmm12
  movdqu fs:[__mcsema_reg_state@TPOFF + 468], xmm13
  movdqu fs:[__mcsema_reg_state@TPOFF + 484], xmm14
  movdqu fs:[__mcsema_reg_state@TPOFF + 500], xmm15
  pop r15
  pop r14
  pop r13
  pop r12
  pop rbp
  pop rbx
  ret
.Lfunc_end0:
  .size __mcsema_attach_ret_value,.Lfunc_end0-__mcsema_attach_ret_value
  .cfi_endproc

  .globl __mcsema_detach_ret
  .type __mcsema_detach_ret,@function
__mcsema_detach_ret:
  .cfi_startproc
  sub QWORD PTR fs:[__mcsema_reg_state@TPOFF + 56], 8
  mov rax, fs:[__mcsema_reg_state@TPOFF + 8]
  mov rbx, fs:[__mcsema_reg_state@TPOFF + 16]
  mov rcx, fs:[__mcsema_reg_state@TPOFF + 24]
  mov rdx, fs:[__mcsema_reg_state@TPOFF + 32]
  mov rsi, fs:[__mcsema_reg_state@TPOFF + 40]
  mov rdi, fs:[__mcsema_reg_state@TPOFF + 48]
  mov rbp, fs:[__mcsema_reg_state@TPOFF + 64]
  xchg fs:[__mcsema_reg_state@TPOFF + 56], rsp
  mov r8, fs:[__mcsema_reg_state@TPOFF + 532]
  mov r9, fs:[__mcsema_reg_state@TPOFF + 540]
  mov r10, fs:[__mcsema_reg_state@TPOFF + 548]
  mov r11, fs:[__mcsema_reg_state@TPOFF + 556]
  mov r12, fs:[__mcsema_reg_state@TPOFF + 564]
  mov r13, fs:[__mcsema_reg_state@TPOFF + 572]
  mov r14, fs:[__mcsema_reg_state@TPOFF + 580]
  mov r15, fs:[__mcsema_reg_state@TPOFF + 588]
  movdqu xmm0, fs:[__mcsema_reg_state@TPOFF + 260]
  movdqu xmm1, fs:[__mcsema_reg_state@TPOFF + 276]
  movdqu xmm2, fs:[__mcsema_reg_state@TPOFF + 292]
  movdqu xmm3, fs:[__mcsema_reg_state@TPOFF + 308]
  movdqu xmm4, fs:[__mcsema_reg_state@TPOFF + 324]
  movdqu xmm5, fs:[__mcsema_reg_state@TPOFF + 340]
  movdqu xmm6, fs:[__mcsema_reg_state@TPOFF + 356]
  movdqu xmm7, fs:[__mcsema_reg_state@TPOFF + 372]
  movdqu xmm8, fs:[__mcsema_reg_state@TPOFF + 388]
  movdqu xmm9, fs:[__mcsema_reg_state@TPOFF + 404]
  movdqu xmm10, fs:[__mcsema_reg_state@TPOFF + 420]
  movdqu xmm11, fs:[__mcsema_reg_state@TPOFF + 436]
  movdqu xmm12, fs:[__mcsema_reg_state@TPOFF + 452]
  movdqu xmm13, fs:[__mcsema_reg_state@TPOFF + 468]
  movdqu xmm14, fs:[__mcsema_reg_state@TPOFF + 484]
  movdqu xmm15, fs:[__mcsema_reg_state@TPOFF + 500]
  ret
.Lfunc_end3:
  .size __mcsema_detach_ret,.Lfunc_end3-__mcsema_detach_ret
  .cfi_endproc

  .globl __mcsema_detach_call
  .type __mcsema_detach_call,@function
__mcsema_detach_call:
  .cfi_startproc
  pop QWORD PTR fs:[__mcsema_reg_state@TPOFF + 0]
  push rbx
  push rbp
  push r12
  push r13
  push r14
  push r15
  mov rbx, fs:[__mcsema_reg_state@TPOFF + 16]
  mov rbp, fs:[__mcsema_reg_state@TPOFF + 64]
  mov r12, fs:[__mcsema_reg_state@TPOFF + 564]
  mov r13, fs:[__mcsema_reg_state@TPOFF + 572]
  mov r14, fs:[__mcsema_reg_state@TPOFF + 580]
  mov r15, fs:[__mcsema_reg_state@TPOFF + 588]
  xchg fs:[__mcsema_reg_state@TPOFF + 56], rsp
  lea rax, [rip + __mcsema_attach_ret]
  mov [rsp], rax
  jmp fs:[__mcsema_reg_state@TPOFF + 0]
.Lfunc_end4:
  .size __mcsema_detach_call,.Lfunc_end4-__mcsema_detach_call
  .cfi_endproc

  .globl __mcsema_detach_call_value
  .type __mcsema_detach_call_value,@function
__mcsema_detach_call_value:
  .cfi_startproc
  push rbx
  push rbp
  push r12
  push r13
  push r14
  push r15
  mov rax, fs:[__mcsema_reg_state@TPOFF + 8]
  mov rbx, fs:[__mcsema_reg_state@TPOFF + 16]
  mov rcx, fs:[__mcsema_reg_state@TPOFF + 24]
  mov rdx, fs:[__mcsema_reg_state@TPOFF + 32]
  mov rsi, fs:[__mcsema_reg_state@TPOFF + 40]
  mov rdi, fs:[__mcsema_reg_state@TPOFF + 48]
  mov rbp, fs:[__mcsema_reg_state@TPOFF + 64]
  xchg fs:[__mcsema_reg_state@TPOFF + 56], rsp
  mov r8, fs:[__mcsema_reg_state@TPOFF + 532]
  mov r9, fs:[__mcsema_reg_state@TPOFF + 540]
  mov r10, fs:[__mcsema_reg_state@TPOFF + 548]
  mov r11, fs:[__mcsema_reg_state@TPOFF + 556]
  mov r12, fs:[__mcsema_reg_state@TPOFF + 564]
  mov r13, fs:[__mcsema_reg_state@TPOFF + 572]
  mov r14, fs:[__mcsema_reg_state@TPOFF + 580]
  mov r15, fs:[__mcsema_reg_state@TPOFF + 588]
  movdqu xmm0, fs:[__mcsema_reg_state@TPOFF + 260]
  movdqu xmm1, fs:[__mcsema_reg_state@TPOFF + 276]
  movdqu xmm2, fs:[__mcsema_reg_state@TPOFF + 292]
  movdqu xmm3, fs:[__mcsema_reg_state@TPOFF + 308]
  movdqu xmm4, fs:[__mcsema_reg_state@TPOFF + 324]
  movdqu xmm5, fs:[__mcsema_reg_state@TPOFF + 340]
  movdqu xmm6, fs:[__mcsema_reg_state@TPOFF + 356]
  movdqu xmm7, fs:[__mcsema_reg_state@TPOFF + 372]
  movdqu xmm8, fs:[__mcsema_reg_state@TPOFF + 388]
  movdqu xmm9, fs:[__mcsema_reg_state@TPOFF + 404]
  movdqu xmm10, fs:[__mcsema_reg_state@TPOFF + 420]
  movdqu xmm11, fs:[__mcsema_reg_state@TPOFF + 436]
  movdqu xmm12, fs:[__mcsema_reg_state@TPOFF + 452]
  movdqu xmm13, fs:[__mcsema_reg_state@TPOFF + 468]
  movdqu xmm14, fs:[__mcsema_reg_state@TPOFF + 484]
  movdqu xmm15, fs:[__mcsema_reg_state@TPOFF + 500]
  lea rax, [rip + __mcsema_attach_ret_value]
  mov [rsp], rax
  jmp fs:[__mcsema_reg_state@TPOFF + 0]
.Lfunc_end5:
  .size __mcsema_detach_call_value,.Lfunc_end5-__mcsema_detach_call_value
  .cfi_endproc

  .globl __mcsema_debug_get_reg_state
  .type __mcsema_debug_get_reg_state,@function
__mcsema_debug_get_reg_state:
  .cfi_startproc
  mov rax, fs:[0]
  lea rax, [rax + __mcsema_reg_state@TPOFF]
  ret
.Lfunc_end6:
  .size __mcsema_debug_get_reg_state,.Lfunc_end6-__mcsema_debug_get_reg_state
  .cfi_endproc

