/* Auto-generated file! Don't modify! */

  .file __FILE__
  .intel_syntax noprefix

  .type __mcsema_reg_state,@object
  .section .tbss,"awT",@nobits
__mcsema_reg_state:
  .zero 448
  .size __mcsema_reg_state, 100

  .type __mcsema_stack,@object
  .section .tbss,"awT",@nobits
__mcsema_stack:
  .zero 1048576
  .size __mcsema_stack, 100

  .type __mcsema_stack_args,@object
  .section .tbss,"awT",@nobits
__mcsema_stack_args:
  .zero 256
  .size __mcsema_stack_args, 100

  .text

  .globl mcsema_main
  .globl __mcsema_detach_ret_cdecl

  .globl __mcsema_attach_call_cdecl
  .type __mcsema_attach_call_cdecl,@function
__mcsema_attach_call_cdecl:
  .cfi_startproc
  pop DWORD PTR gs:[__mcsema_reg_state@TPOFF + 0]
  mov gs:[__mcsema_reg_state@TPOFF + 4], eax
  mov gs:[__mcsema_reg_state@TPOFF + 8], ebx
  mov gs:[__mcsema_reg_state@TPOFF + 12], ecx
  mov gs:[__mcsema_reg_state@TPOFF + 16], edx
  mov gs:[__mcsema_reg_state@TPOFF + 24], edi
  mov gs:[__mcsema_reg_state@TPOFF + 20], esi
  mov gs:[__mcsema_reg_state@TPOFF + 32], ebp
  xchg esp, gs:[__mcsema_reg_state@TPOFF + 28]
  movdqu gs:[__mcsema_reg_state@TPOFF + 184], xmm0
  movdqu gs:[__mcsema_reg_state@TPOFF + 200], xmm1
  movdqu gs:[__mcsema_reg_state@TPOFF + 216], xmm2
  movdqu gs:[__mcsema_reg_state@TPOFF + 232], xmm3
  movdqu gs:[__mcsema_reg_state@TPOFF + 248], xmm4
  movdqu gs:[__mcsema_reg_state@TPOFF + 264], xmm5
  movdqu gs:[__mcsema_reg_state@TPOFF + 280], xmm6
  movdqu gs:[__mcsema_reg_state@TPOFF + 296], xmm7
  cmp esp, 0
  jnz .Lhave_stack
  mov esp, gs:[0]
  lea esp, [esp + __mcsema_stack@TPOFF + 1048576]
.Lhave_stack:
  push __mcsema_detach_ret_cdecl
  push gs:[0]
  jmp gs:[__mcsema_reg_state@TPOFF + 0]
.Lfunc_end1:
  .size __mcsema_attach_call_cdecl,.Lfunc_end1-__mcsema_attach_call_cdecl
  .cfi_endproc

  .globl __mcsema_attach_ret_cdecl
  .type __mcsema_attach_ret_cdecl,@function
__mcsema_attach_ret_cdecl:
  .cfi_startproc
  add esp, 256
  xchg esp, gs:[__mcsema_reg_state@TPOFF + 28]
  mov gs:[__mcsema_reg_state@TPOFF + 4], eax
  mov gs:[__mcsema_reg_state@TPOFF + 16], edx
  movdqu gs:[__mcsema_reg_state@TPOFF + 184], xmm0
  mov gs:[__mcsema_reg_state@TPOFF + 32], ebp
  mov gs:[__mcsema_reg_state@TPOFF + 8], ebx
  mov gs:[__mcsema_reg_state@TPOFF + 20], esi
  mov gs:[__mcsema_reg_state@TPOFF + 24], edi
  pop ebp
  pop ebx
  pop esi
  pop edi
  ret
.Lfunc_end2:
  .size __mcsema_attach_ret_cdecl,.Lfunc_end2-__mcsema_attach_ret_cdecl
  .cfi_endproc

  .globl __mcsema_attach_ret_value
  .type __mcsema_attach_ret_value,@function
__mcsema_attach_ret_value:
  .cfi_startproc
  mov gs:[__mcsema_reg_state@TPOFF + 4], eax
  mov gs:[__mcsema_reg_state@TPOFF + 8], ebx
  mov gs:[__mcsema_reg_state@TPOFF + 12], ecx
  mov gs:[__mcsema_reg_state@TPOFF + 16], edx
  mov gs:[__mcsema_reg_state@TPOFF + 24], edi
  mov gs:[__mcsema_reg_state@TPOFF + 20], esi
  mov gs:[__mcsema_reg_state@TPOFF + 32], ebp
  add esp, 256
  xchg esp, gs:[__mcsema_reg_state@TPOFF + 28]
  movdqu gs:[__mcsema_reg_state@TPOFF + 184], xmm0
  movdqu gs:[__mcsema_reg_state@TPOFF + 200], xmm1
  movdqu gs:[__mcsema_reg_state@TPOFF + 216], xmm2
  movdqu gs:[__mcsema_reg_state@TPOFF + 232], xmm3
  movdqu gs:[__mcsema_reg_state@TPOFF + 248], xmm4
  movdqu gs:[__mcsema_reg_state@TPOFF + 264], xmm5
  movdqu gs:[__mcsema_reg_state@TPOFF + 280], xmm6
  movdqu gs:[__mcsema_reg_state@TPOFF + 296], xmm7
  pop ebp
  pop ebx
  pop esi
  pop edi
  ret
.Lfunc_end0:
  .size __mcsema_attach_ret_value,.Lfunc_end0-__mcsema_attach_ret_value
  .cfi_endproc

  .globl __mcsema_detach_ret_cdecl
  .type __mcsema_detach_ret_cdecl,@function
__mcsema_detach_ret_cdecl:
  .cfi_startproc
  sub DWORD PTR gs:[__mcsema_reg_state@TPOFF + 28], 4
  mov eax, gs:[__mcsema_reg_state@TPOFF + 4]
  mov ebx, gs:[__mcsema_reg_state@TPOFF + 8]
  mov ecx, gs:[__mcsema_reg_state@TPOFF + 12]
  mov edx, gs:[__mcsema_reg_state@TPOFF + 16]
  mov edi, gs:[__mcsema_reg_state@TPOFF + 24]
  mov esi, gs:[__mcsema_reg_state@TPOFF + 20]
  mov ebp, gs:[__mcsema_reg_state@TPOFF + 32]
  movdqu xmm0, gs:[__mcsema_reg_state@TPOFF + 184]
  movdqu xmm1, gs:[__mcsema_reg_state@TPOFF + 200]
  movdqu xmm2, gs:[__mcsema_reg_state@TPOFF + 216]
  movdqu xmm3, gs:[__mcsema_reg_state@TPOFF + 232]
  movdqu xmm4, gs:[__mcsema_reg_state@TPOFF + 248]
  movdqu xmm5, gs:[__mcsema_reg_state@TPOFF + 264]
  movdqu xmm6, gs:[__mcsema_reg_state@TPOFF + 280]
  movdqu xmm7, gs:[__mcsema_reg_state@TPOFF + 296]
  ret
.Lfunc_end3:
  .size __mcsema_detach_ret_cdecl,.Lfunc_end3-__mcsema_detach_ret_cdecl
  .cfi_endproc

  .globl __mcsema_detach_call_cdecl
  .type __mcsema_detach_call_cdecl,@function
__mcsema_detach_call_cdecl:
  .cfi_startproc
  pop DWORD PTR gs:[__mcsema_reg_state@TPOFF + 0]
  mov eax, gs:[0]
  lea edi, [eax + __mcsema_stack_args@TPOFF]
  mov esi, esp
  mov ecx, 256
  rep movsb
  mov edi, gs:[__mcsema_reg_state@TPOFF + 24]
  mov esi, gs:[__mcsema_reg_state@TPOFF + 20]
  mov ebx, gs:[__mcsema_reg_state@TPOFF + 8]
  mov ebp, gs:[__mcsema_reg_state@TPOFF + 32]
  push edi
  push esi
  push ebx
  push ebp
  xchg gs:[__mcsema_reg_state@TPOFF + 28], esp
  sub esp, 256
  push esi
  push edi
  push ecx
  lea edi, [esp + 12]
  mov eax, gs:[0]
  lea esi, [eax + __mcsema_stack_args@TPOFF]
  mov ecx, 256
  rep movsb
  pop ecx
  pop edi
  pop esi
  push __mcsema_attach_ret_cdecl
  jmp gs:[__mcsema_reg_state@TPOFF + 0]
.Lfunc_end4:
  .size __mcsema_detach_call_cdecl,.Lfunc_end4-__mcsema_detach_call_cdecl
  .cfi_endproc

  .globl __mcsema_detach_call_value
  .type __mcsema_detach_call_value,@function
__mcsema_detach_call_value:
  .cfi_startproc
  push edi
  push esi
  push ebx
  push ebp
  mov eax, gs:[0]
  lea edi, [eax + __mcsema_stack_args@TPOFF]
  mov esi, gs:[__mcsema_reg_state@TPOFF + 28]
  mov ecx, 256
  rep movsb
  mov eax, gs:[__mcsema_reg_state@TPOFF + 4]
  mov ebx, gs:[__mcsema_reg_state@TPOFF + 8]
  mov ecx, gs:[__mcsema_reg_state@TPOFF + 12]
  mov edx, gs:[__mcsema_reg_state@TPOFF + 16]
  mov edi, gs:[__mcsema_reg_state@TPOFF + 24]
  mov esi, gs:[__mcsema_reg_state@TPOFF + 20]
  mov ebp, gs:[__mcsema_reg_state@TPOFF + 32]
  xchg gs:[__mcsema_reg_state@TPOFF + 28], esp
  movdqu xmm0, gs:[__mcsema_reg_state@TPOFF + 184]
  movdqu xmm1, gs:[__mcsema_reg_state@TPOFF + 200]
  movdqu xmm2, gs:[__mcsema_reg_state@TPOFF + 216]
  movdqu xmm3, gs:[__mcsema_reg_state@TPOFF + 232]
  movdqu xmm4, gs:[__mcsema_reg_state@TPOFF + 248]
  movdqu xmm5, gs:[__mcsema_reg_state@TPOFF + 264]
  movdqu xmm6, gs:[__mcsema_reg_state@TPOFF + 280]
  movdqu xmm7, gs:[__mcsema_reg_state@TPOFF + 296]
  sub esp, 256
  push esi
  push edi
  push ecx
  lea edi, [esp + 12]
  mov eax, gs:[0]
  lea esi, [eax + __mcsema_stack_args@TPOFF]
  mov ecx, 256
  rep movsb
  pop ecx
  pop edi
  pop esi
  push __mcsema_attach_ret_value
  jmp gs:[__mcsema_reg_state@TPOFF + 0]
.Lfunc_end5:
  .size __mcsema_detach_call_value,.Lfunc_end5-__mcsema_detach_call_value
  .cfi_endproc

  .globl __mcsema_debug_get_reg_state
  .type __mcsema_debug_get_reg_state,@function
__mcsema_debug_get_reg_state:
  .cfi_startproc
  mov eax, gs:[0]
  lea eax, [eax + __mcsema_reg_state@TPOFF]
  ret
.Lfunc_end6:
  .size __mcsema_debug_get_reg_state,.Lfunc_end6-__mcsema_debug_get_reg_state
  .cfi_endproc

