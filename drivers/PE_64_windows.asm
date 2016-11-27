/* Auto-generated file! Don't modify! */

  .intel_syntax noprefix

  .section        .tls$,"wd"
  .p2align 2
     .globl  __mcsema_reg_state
__mcsema_reg_state:
  .p2align 2
  .zero   532

     .globl  __mcsema_stack
__mcsema_stack:
  .p2align 4
  .zero   1048576

     .globl  __mcsema_stack_args
__mcsema_stack_args:
  .p2align 4
  .zero   256

     .globl  __mcsema_stack_mark
__mcsema_stack_mark:
  .p2align 2
  .zero   8

  .text
  .p2align	4, 0x90

.def	 __mcsema_attach_call;
.scl	2;
.type	32;
.endef
.globl __mcsema_attach_call
__mcsema_attach_call:
  push QWORD ptr [rsp]
  mov QWORD ptr [rsp+8], rbp
push rdx
mov	rbp, QWORD ptr [rip + _tls_index]
mov	rdx, QWORD ptr gs:[88]
mov	rbp, QWORD ptr [rdx + 8*rbp]
pop rdx
  pop QWORD PTR [rbp + __mcsema_reg_state@SECREL32 + 0]
  mov [rbp + __mcsema_reg_state@SECREL32 + 8], rax
  pop rbp
push rdx
mov	rax, QWORD ptr [rip + _tls_index]
mov	rdx, QWORD ptr gs:[88]
mov	rax, QWORD ptr [rdx + 8*rax]
pop rdx
  mov [rax + __mcsema_reg_state@SECREL32 + 16], rbx
  mov [rax + __mcsema_reg_state@SECREL32 + 24], rcx
  mov [rax + __mcsema_reg_state@SECREL32 + 32], rdx
  mov [rax + __mcsema_reg_state@SECREL32 + 40], rsi
  mov [rax + __mcsema_reg_state@SECREL32 + 48], rdi
  mov [rax + __mcsema_reg_state@SECREL32 + 64], rbp
  mov [rax + __mcsema_reg_state@SECREL32 + 468], r8
  mov [rax + __mcsema_reg_state@SECREL32 + 476], r9
  mov [rax + __mcsema_reg_state@SECREL32 + 484], r10
  mov [rax + __mcsema_reg_state@SECREL32 + 492], r11
  mov [rax + __mcsema_reg_state@SECREL32 + 500], r12
  mov [rax + __mcsema_reg_state@SECREL32 + 508], r13
  mov [rax + __mcsema_reg_state@SECREL32 + 516], r14
  mov [rax + __mcsema_reg_state@SECREL32 + 524], r15
  movdqu [rax + __mcsema_reg_state@SECREL32 + 196], xmm0
  movdqu [rax + __mcsema_reg_state@SECREL32 + 212], xmm1
  movdqu [rax + __mcsema_reg_state@SECREL32 + 228], xmm2
  movdqu [rax + __mcsema_reg_state@SECREL32 + 244], xmm3
  movdqu [rax + __mcsema_reg_state@SECREL32 + 260], xmm4
  movdqu [rax + __mcsema_reg_state@SECREL32 + 276], xmm5
  movdqu [rax + __mcsema_reg_state@SECREL32 + 292], xmm6
  movdqu [rax + __mcsema_reg_state@SECREL32 + 308], xmm7
  movdqu [rax + __mcsema_reg_state@SECREL32 + 324], xmm8
  movdqu [rax + __mcsema_reg_state@SECREL32 + 340], xmm9
  movdqu [rax + __mcsema_reg_state@SECREL32 + 356], xmm10
  movdqu [rax + __mcsema_reg_state@SECREL32 + 372], xmm11
  movdqu [rax + __mcsema_reg_state@SECREL32 + 388], xmm12
  movdqu [rax + __mcsema_reg_state@SECREL32 + 404], xmm13
  movdqu [rax + __mcsema_reg_state@SECREL32 + 420], xmm14
  movdqu [rax + __mcsema_reg_state@SECREL32 + 436], xmm15
  xchg rsp, [rax + __mcsema_reg_state@SECREL32 + 56]
  cmp rsp, 0
  jnz .Lhave_stack
  lea rsp, [rax + __mcsema_stack@SECREL32 + 1048576]
.Lhave_stack:
  lea rcx, [rax + __mcsema_reg_state@SECREL32]
  lea rdx, [rip + __mcsema_detach_ret]
  push rdx
  push rdx
  mov rax, QWORD PTR [rax + __mcsema_reg_state@SECREL32 + 0]
  jmp rax

.def	 __mcsema_attach_ret;
.scl	2;
.type	32;
.endef
.globl __mcsema_attach_ret
__mcsema_attach_ret:
  add rsp, 264
push rax
push rdx
mov	rax, QWORD ptr [rip + _tls_index]
mov	rdx, QWORD ptr gs:[88]
mov	rax, QWORD ptr [rdx + 8*rax]
pop rdx
  xchg rsp, [rax + __mcsema_reg_state@SECREL32 + 56]
  add QWORD ptr [rax + __mcsema_reg_state@SECREL32 + 56], 8
  mov rax, QWORD ptr [rax + __mcsema_reg_state@SECREL32 + 56]
  mov rax, QWORD ptr [rax-8]
  push rcx
push rdx
mov	rcx, QWORD ptr [rip + _tls_index]
mov	rdx, QWORD ptr gs:[88]
mov	rcx, QWORD ptr [rdx + 8*rcx]
pop rdx
  mov [rcx + __mcsema_reg_state@SECREL32 + 8], rax
  movdqu [rcx + __mcsema_reg_state@SECREL32 + 196], xmm0
  mov [rcx + __mcsema_reg_state@SECREL32 + 16], rbx
  mov [rcx + __mcsema_reg_state@SECREL32 + 40], rsi
  mov [rcx + __mcsema_reg_state@SECREL32 + 48], rdi
  mov [rcx + __mcsema_reg_state@SECREL32 + 64], rbp
  mov [rcx + __mcsema_reg_state@SECREL32 + 500], r12
  mov [rcx + __mcsema_reg_state@SECREL32 + 508], r13
  mov [rcx + __mcsema_reg_state@SECREL32 + 516], r14
  mov [rcx + __mcsema_reg_state@SECREL32 + 524], r15
  movdqu [rcx + __mcsema_reg_state@SECREL32 + 292], xmm6
  movdqu [rcx + __mcsema_reg_state@SECREL32 + 308], xmm7
  movdqu [rcx + __mcsema_reg_state@SECREL32 + 324], xmm8
  movdqu [rcx + __mcsema_reg_state@SECREL32 + 340], xmm9
  movdqu [rcx + __mcsema_reg_state@SECREL32 + 356], xmm10
  movdqu [rcx + __mcsema_reg_state@SECREL32 + 372], xmm11
  movdqu [rcx + __mcsema_reg_state@SECREL32 + 388], xmm12
  movdqu [rcx + __mcsema_reg_state@SECREL32 + 404], xmm13
  movdqu [rcx + __mcsema_reg_state@SECREL32 + 420], xmm14
  movdqu [rcx + __mcsema_reg_state@SECREL32 + 436], xmm15
  pop rcx
  pop rbx
  pop rsi
  pop rdi
  pop rbp
  pop r12
  pop r13
  pop r14
  pop r15
  movdqu xmm6, [rsp+0]
  movdqu xmm7, [rsp+16]
  movdqu xmm8, [rsp+32]
  movdqu xmm9, [rsp+48]
  movdqu xmm10, [rsp+64]
  movdqu xmm11, [rsp+80]
  movdqu xmm12, [rsp+96]
  movdqu xmm13, [rsp+112]
  movdqu xmm14, [rsp+128]
  movdqu xmm15, [rsp+144]
  add rsp, 160
  ret

.def	 __mcsema_attach_ret_value;
.scl	2;
.type	32;
.endef
.globl __mcsema_attach_ret_value
__mcsema_attach_ret_value:
  push rbp
push rdx
mov	rbp, QWORD ptr [rip + _tls_index]
mov	rdx, QWORD ptr gs:[88]
mov	rbp, QWORD ptr [rdx + 8*rbp]
pop rdx
  mov [rbp + __mcsema_reg_state@SECREL32 + 8], rax
  mov [rbp + __mcsema_reg_state@SECREL32 + 16], rbx
  mov [rbp + __mcsema_reg_state@SECREL32 + 24], rcx
  mov [rbp + __mcsema_reg_state@SECREL32 + 32], rdx
  mov [rbp + __mcsema_reg_state@SECREL32 + 40], rsi
  mov [rbp + __mcsema_reg_state@SECREL32 + 48], rdi
  mov [rbp + __mcsema_reg_state@SECREL32 + 468], r8
  mov [rbp + __mcsema_reg_state@SECREL32 + 476], r9
  mov [rbp + __mcsema_reg_state@SECREL32 + 484], r10
  mov [rbp + __mcsema_reg_state@SECREL32 + 492], r11
  mov [rbp + __mcsema_reg_state@SECREL32 + 500], r12
  mov [rbp + __mcsema_reg_state@SECREL32 + 508], r13
  mov [rbp + __mcsema_reg_state@SECREL32 + 516], r14
  mov [rbp + __mcsema_reg_state@SECREL32 + 524], r15
  pop rbp
push rdx
mov	rax, QWORD ptr [rip + _tls_index]
mov	rdx, QWORD ptr gs:[88]
mov	rax, QWORD ptr [rdx + 8*rax]
pop rdx
  mov [rax + __mcsema_reg_state@SECREL32 + 64], rbp
  movdqu [rax + __mcsema_reg_state@SECREL32 + 196], xmm0
  movdqu [rax + __mcsema_reg_state@SECREL32 + 212], xmm1
  movdqu [rax + __mcsema_reg_state@SECREL32 + 228], xmm2
  movdqu [rax + __mcsema_reg_state@SECREL32 + 244], xmm3
  movdqu [rax + __mcsema_reg_state@SECREL32 + 260], xmm4
  movdqu [rax + __mcsema_reg_state@SECREL32 + 276], xmm5
  movdqu [rax + __mcsema_reg_state@SECREL32 + 292], xmm6
  movdqu [rax + __mcsema_reg_state@SECREL32 + 308], xmm7
  movdqu [rax + __mcsema_reg_state@SECREL32 + 324], xmm8
  movdqu [rax + __mcsema_reg_state@SECREL32 + 340], xmm9
  movdqu [rax + __mcsema_reg_state@SECREL32 + 356], xmm10
  movdqu [rax + __mcsema_reg_state@SECREL32 + 372], xmm11
  movdqu [rax + __mcsema_reg_state@SECREL32 + 388], xmm12
  movdqu [rax + __mcsema_reg_state@SECREL32 + 404], xmm13
  movdqu [rax + __mcsema_reg_state@SECREL32 + 420], xmm14
  movdqu [rax + __mcsema_reg_state@SECREL32 + 436], xmm15
  sub QWORD PTR [rax + __mcsema_stack_mark@SECREL32], rsp
  mov rcx, QWORD PTR [rax + __mcsema_stack_mark@SECREL32]
  add rsp, 264
  add rsp, rcx
  xchg rsp, QWORD PTR [rax + __mcsema_reg_state@SECREL32 + 56]
  pop QWORD PTR [rax + __mcsema_stack_mark@SECREL32]
  pop rbx
  pop rsi
  pop rdi
  pop rbp
  pop r12
  pop r13
  pop r14
  pop r15
  movdqu xmm6, [rsp+0]
  movdqu xmm7, [rsp+16]
  movdqu xmm8, [rsp+32]
  movdqu xmm9, [rsp+48]
  movdqu xmm10, [rsp+64]
  movdqu xmm11, [rsp+80]
  movdqu xmm12, [rsp+96]
  movdqu xmm13, [rsp+112]
  movdqu xmm14, [rsp+128]
  movdqu xmm15, [rsp+144]
  add rsp, 160
  ret

.def	 __mcsema_detach_ret;
.scl	2;
.type	32;
.endef
.globl __mcsema_detach_ret
__mcsema_detach_ret:
  push rbp
push rdx
mov	rbp, QWORD ptr [rip + _tls_index]
mov	rdx, QWORD ptr gs:[88]
mov	rbp, QWORD ptr [rdx + 8*rbp]
pop rdx
  mov rax, [rbp + __mcsema_reg_state@SECREL32 + 8]
  mov rbx, [rbp + __mcsema_reg_state@SECREL32 + 16]
  mov rcx, [rbp + __mcsema_reg_state@SECREL32 + 24]
  mov rdx, [rbp + __mcsema_reg_state@SECREL32 + 32]
  mov rsi, [rbp + __mcsema_reg_state@SECREL32 + 40]
  mov rdi, [rbp + __mcsema_reg_state@SECREL32 + 48]
  mov r8,  [rbp + __mcsema_reg_state@SECREL32 + 468]
  mov r9,  [rbp + __mcsema_reg_state@SECREL32 + 476]
  mov r10, [rbp + __mcsema_reg_state@SECREL32 + 484]
  mov r11, [rbp + __mcsema_reg_state@SECREL32 + 492]
  mov r12, [rbp + __mcsema_reg_state@SECREL32 + 500]
  mov r13, [rbp + __mcsema_reg_state@SECREL32 + 508]
  mov r14, [rbp + __mcsema_reg_state@SECREL32 + 516]
  mov r15, [rbp + __mcsema_reg_state@SECREL32 + 524]
  movdqu xmm0, [rbp + __mcsema_reg_state@SECREL32 + 196]
  movdqu xmm1, [rbp + __mcsema_reg_state@SECREL32 + 212]
  movdqu xmm2, [rbp + __mcsema_reg_state@SECREL32 + 228]
  movdqu xmm3, [rbp + __mcsema_reg_state@SECREL32 + 244]
  movdqu xmm4, [rbp + __mcsema_reg_state@SECREL32 + 260]
  movdqu xmm5, [rbp + __mcsema_reg_state@SECREL32 + 276]
  movdqu xmm6, [rbp + __mcsema_reg_state@SECREL32 + 292]
  movdqu xmm7, [rbp + __mcsema_reg_state@SECREL32 + 308]
  movdqu xmm8,  [rbp + __mcsema_reg_state@SECREL32 + 324]
  movdqu xmm9,  [rbp + __mcsema_reg_state@SECREL32 + 340]
  movdqu xmm10, [rbp + __mcsema_reg_state@SECREL32 + 356]
  movdqu xmm11, [rbp + __mcsema_reg_state@SECREL32 + 372]
  movdqu xmm12, [rbp + __mcsema_reg_state@SECREL32 + 388]
  movdqu xmm13, [rbp + __mcsema_reg_state@SECREL32 + 404]
  movdqu xmm14, [rbp + __mcsema_reg_state@SECREL32 + 420]
  movdqu xmm15, [rbp + __mcsema_reg_state@SECREL32 + 436]
  pop rbp
  push rax
push rdx
mov	rax, QWORD ptr [rip + _tls_index]
mov	rdx, QWORD ptr gs:[88]
mov	rax, QWORD ptr [rdx + 8*rax]
pop rdx
  mov rbp, [rax + __mcsema_reg_state@SECREL32 + 64]
  sub QWORD PTR [rax + __mcsema_reg_state@SECREL32 + 56], 8
  xchg rsp, QWORD PTR [rax + __mcsema_reg_state@SECREL32 + 56]
  add QWORD ptr [rax + __mcsema_reg_state@SECREL32 + 56], 8
  mov rax, qword ptr [rax + __mcsema_reg_state@SECREL32 + 56]
  mov rax, qword ptr [rax-8]
  ret

.def	 __mcsema_detach_call;
.scl	2;
.type	32;
.endef
.globl __mcsema_detach_call
__mcsema_detach_call:
push rdx
mov	rax, QWORD ptr [rip + _tls_index]
mov	rdx, QWORD ptr gs:[88]
mov	rax, QWORD ptr [rdx + 8*rax]
pop rdx
  pop QWORD PTR [rax + __mcsema_reg_state@SECREL32 + 0]
  push r15
  push r14
  push r13
  push r12
  push rbp
  push rdi
  push rsi
  push rbx
  sub rsp, 160
  movdqu  [rsp+0], xmm6 
  movdqu  [rsp+16], xmm7 
  movdqu  [rsp+32], xmm8 
  movdqu  [rsp+48], xmm9 
  movdqu  [rsp+64], xmm10
  movdqu  [rsp+80], xmm11
  movdqu  [rsp+96], xmm12
  movdqu  [rsp+112], xmm13
  movdqu  [rsp+128], xmm14
  movdqu  [rsp+144], xmm15
  lea rdi, [rax + __mcsema_stack_args@SECREL32]
  lea rsi, [rsp + 232]
  mov rcx, 256
  rep movsb
  mov rsi, [rax + __mcsema_reg_state@SECREL32 + 40]
  mov rdi, [rax + __mcsema_reg_state@SECREL32 + 48]
  mov rbx, [rax + __mcsema_reg_state@SECREL32 + 16]
  mov rbp, [rax + __mcsema_reg_state@SECREL32 + 64]
  xchg QWORD PTR [rax + __mcsema_reg_state@SECREL32 + 56], rsp
  sub rsp, 256
  push rsi
  push rdi
  push rcx
  lea rdi, [rsp + 24]
  lea rsi, [rax + __mcsema_stack_args@SECREL32]
  mov rcx, 256
  rep movsb
  pop rcx
  pop rdi
  pop rsi
  push rax
  lea rax, [rip + __mcsema_attach_ret]
  xchg rax, [rsp]
  jmp QWORD PTR [rax + __mcsema_reg_state@SECREL32 + 0]

.def	 __mcsema_detach_call_value;
.scl	2;
.type	32;
.endef
.globl __mcsema_detach_call_value
__mcsema_detach_call_value:
  push r15
  push r14
  push r13
  push r12
  push rbp
  push rdi
  push rsi
  push rbx
  sub rsp, 160
  movdqu  [rsp+0], xmm6 
  movdqu  [rsp+16], xmm7 
  movdqu  [rsp+32], xmm8 
  movdqu  [rsp+48], xmm9 
  movdqu  [rsp+64], xmm10
  movdqu  [rsp+80], xmm11
  movdqu  [rsp+96], xmm12
  movdqu  [rsp+112], xmm13
  movdqu  [rsp+128], xmm14
  movdqu  [rsp+144], xmm15
push rdx
mov	rax, QWORD ptr [rip + _tls_index]
mov	rdx, QWORD ptr gs:[88]
mov	rax, QWORD ptr [rdx + 8*rax]
pop rdx
  push QWORD PTR [rax + __mcsema_stack_mark@SECREL32]
  lea rdi, [rax + __mcsema_stack_args@SECREL32]
  mov rsi, QWORD PTR [rax + __mcsema_reg_state@SECREL32 + 56]
  mov rcx, 256
  rep movsb
  mov rbp, rax
  mov rax, [rbp + __mcsema_reg_state@SECREL32 + 8]
  mov rax, rbp
  mov rbx, [rax + __mcsema_reg_state@SECREL32 + 16]
  mov rcx, [rax + __mcsema_reg_state@SECREL32 + 24]
  mov rdx, [rax + __mcsema_reg_state@SECREL32 + 32]
  mov rsi, [rax + __mcsema_reg_state@SECREL32 + 40]
  mov rdi, [rax + __mcsema_reg_state@SECREL32 + 48]
  mov rbp, [rax + __mcsema_reg_state@SECREL32 + 64]
  mov r8,  [rax + __mcsema_reg_state@SECREL32 + 468]
  mov r9,  [rax + __mcsema_reg_state@SECREL32 + 476]
  mov r10, [rax + __mcsema_reg_state@SECREL32 + 484]
  mov r11, [rax + __mcsema_reg_state@SECREL32 + 492]
  mov r12, [rax + __mcsema_reg_state@SECREL32 + 500]
  mov r13, [rax + __mcsema_reg_state@SECREL32 + 508]
  mov r14, [rax + __mcsema_reg_state@SECREL32 + 516]
  mov r15, [rax + __mcsema_reg_state@SECREL32 + 524]
  movdqu xmm0, [rax + __mcsema_reg_state@SECREL32 + 196]
  movdqu xmm1, [rax + __mcsema_reg_state@SECREL32 + 212]
  movdqu xmm2, [rax + __mcsema_reg_state@SECREL32 + 228]
  movdqu xmm3, [rax + __mcsema_reg_state@SECREL32 + 244]
  movdqu xmm4, [rax + __mcsema_reg_state@SECREL32 + 260]
  movdqu xmm5, [rax + __mcsema_reg_state@SECREL32 + 276]
  movdqu xmm6, [rax + __mcsema_reg_state@SECREL32 + 292]
  movdqu xmm7, [rax + __mcsema_reg_state@SECREL32 + 308]
  movdqu xmm8,  [rax + __mcsema_reg_state@SECREL32 + 324]
  movdqu xmm9,  [rax + __mcsema_reg_state@SECREL32 + 340]
  movdqu xmm10, [rax + __mcsema_reg_state@SECREL32 + 356]
  movdqu xmm11, [rax + __mcsema_reg_state@SECREL32 + 372]
  movdqu xmm12, [rax + __mcsema_reg_state@SECREL32 + 388]
  movdqu xmm13, [rax + __mcsema_reg_state@SECREL32 + 404]
  movdqu xmm14, [rax + __mcsema_reg_state@SECREL32 + 420]
  movdqu xmm15, [rax + __mcsema_reg_state@SECREL32 + 436]
  xchg QWORD PTR [rax + __mcsema_reg_state@SECREL32 + 56], rsp
  sub rsp, 256
  push rsi
  push rdi
  push rcx
  lea rdi, [rsp + 24]
  lea rsi, [rax + __mcsema_stack_args@SECREL32]
  mov rcx, 256
  rep movsb
  pop rcx
  pop rdi
  pop rsi
  mov QWORD PTR [rax + __mcsema_stack_mark@SECREL32], rsp
  mov [rsp], rax
  lea rax, [rip + __mcsema_attach_ret_value]
  xchg rax, [rsp]
  jmp QWORD PTR [rax + __mcsema_reg_state@SECREL32 + 0]

.def	 __mcsema_debug_get_reg_state;
.scl	2;
.type	32;
.endef
.globl __mcsema_debug_get_reg_state
__mcsema_debug_get_reg_state:
push rdx
mov	rax, QWORD ptr [rip + _tls_index]
mov	rdx, QWORD ptr gs:[88]
mov	rax, QWORD ptr [rdx + 8*rax]
pop rdx
  lea rax, [rax + __mcsema_reg_state@SECREL32]
  ret

