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

  .type __mcsema_stack_mark,@object
  .section .tbss,"awT",@nobits
__mcsema_stack_mark:
  .zero 4
  .size __mcsema_stack_mark, 100

  .text

  .globl mcsema_main
  .globl __mcsema_detach_ret_cdecl

  .globl __mcsema_attach_call_cdecl
  .type __mcsema_attach_call_cdecl,@function
__mcsema_attach_call_cdecl:
  .cfi_startproc
  pop DWORD PTR gs:[__mcsema_reg_state@NTPOFF + 0]
  mov gs:[__mcsema_reg_state@NTPOFF + 4], eax
  mov gs:[__mcsema_reg_state@NTPOFF + 8], ebx
  mov gs:[__mcsema_reg_state@NTPOFF + 12], ecx
  mov gs:[__mcsema_reg_state@NTPOFF + 16], edx
  mov gs:[__mcsema_reg_state@NTPOFF + 24], edi
  mov gs:[__mcsema_reg_state@NTPOFF + 20], esi
  mov gs:[__mcsema_reg_state@NTPOFF + 32], ebp
  xchg esp, DWORD PTR gs:[__mcsema_reg_state@NTPOFF + 28]
  movdqu gs:[__mcsema_reg_state@NTPOFF + 184], xmm0
  movdqu gs:[__mcsema_reg_state@NTPOFF + 200], xmm1
  movdqu gs:[__mcsema_reg_state@NTPOFF + 216], xmm2
  movdqu gs:[__mcsema_reg_state@NTPOFF + 232], xmm3
  movdqu gs:[__mcsema_reg_state@NTPOFF + 248], xmm4
  movdqu gs:[__mcsema_reg_state@NTPOFF + 264], xmm5
  movdqu gs:[__mcsema_reg_state@NTPOFF + 280], xmm6
  movdqu gs:[__mcsema_reg_state@NTPOFF + 296], xmm7
  cmp esp, 0
  jnz .Lhave_stack
  mov esp, DWORD PTR gs:[0]
  lea esp, [esp + __mcsema_stack@NTPOFF + 1048576]
.Lhave_stack:
  mov eax, DWORD PTR gs:[0]
  lea eax, [eax + __mcsema_reg_state@NTPOFF]
  push eax
  lea eax, __mcsema_detach_ret_cdecl
  push eax
  jmp DWORD PTR gs:[__mcsema_reg_state@NTPOFF + 0]
.Lfunc_end1:
  .size __mcsema_attach_call_cdecl,.Lfunc_end1-__mcsema_attach_call_cdecl
  .cfi_endproc

  .globl __mcsema_attach_ret_cdecl
  .type __mcsema_attach_ret_cdecl,@function
__mcsema_attach_ret_cdecl:
  .cfi_startproc
  add esp, 260
  xchg esp, DWORD PTR gs:[__mcsema_reg_state@NTPOFF + 28]
  mov gs:[__mcsema_reg_state@NTPOFF + 4], eax
  mov gs:[__mcsema_reg_state@NTPOFF + 16], edx
  movdqu gs:[__mcsema_reg_state@NTPOFF + 184], xmm0
  mov gs:[__mcsema_reg_state@NTPOFF + 32], ebp
  mov gs:[__mcsema_reg_state@NTPOFF + 8], ebx
  mov gs:[__mcsema_reg_state@NTPOFF + 20], esi
  mov gs:[__mcsema_reg_state@NTPOFF + 24], edi
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
  mov gs:[__mcsema_reg_state@NTPOFF + 4], eax
  mov gs:[__mcsema_reg_state@NTPOFF + 8], ebx
  mov gs:[__mcsema_reg_state@NTPOFF + 12], ecx
  mov gs:[__mcsema_reg_state@NTPOFF + 16], edx
  mov gs:[__mcsema_reg_state@NTPOFF + 24], edi
  mov gs:[__mcsema_reg_state@NTPOFF + 20], esi
  mov gs:[__mcsema_reg_state@NTPOFF + 32], ebp
  sub DWORD PTR gs:[__mcsema_stack_mark@NTPOFF], esp
  mov ecx, DWORD PTR gs:[__mcsema_stack_mark@NTPOFF]
  add esp, 260
  xchg esp, DWORD PTR gs:[__mcsema_reg_state@NTPOFF + 28]
  movdqu gs:[__mcsema_reg_state@NTPOFF + 184], xmm0
  movdqu gs:[__mcsema_reg_state@NTPOFF + 200], xmm1
  movdqu gs:[__mcsema_reg_state@NTPOFF + 216], xmm2
  movdqu gs:[__mcsema_reg_state@NTPOFF + 232], xmm3
  movdqu gs:[__mcsema_reg_state@NTPOFF + 248], xmm4
  movdqu gs:[__mcsema_reg_state@NTPOFF + 264], xmm5
  movdqu gs:[__mcsema_reg_state@NTPOFF + 280], xmm6
  movdqu gs:[__mcsema_reg_state@NTPOFF + 296], xmm7
  pop ebp
  pop ebx
  pop esi
  pop edi
  sub esp, ecx
  add esp, 4
  lea ecx, [esp+ecx]
  jmp dword ptr [ecx-4]
.Lfunc_end0:
  .size __mcsema_attach_ret_value,.Lfunc_end0-__mcsema_attach_ret_value
  .cfi_endproc

  .globl __mcsema_detach_ret_cdecl
  .type __mcsema_detach_ret_cdecl,@function
__mcsema_detach_ret_cdecl:
  .cfi_startproc
  mov eax, gs:[__mcsema_reg_state@NTPOFF + 4]
  mov ebx, gs:[__mcsema_reg_state@NTPOFF + 8]
  mov ecx, gs:[__mcsema_reg_state@NTPOFF + 12]
  mov edx, gs:[__mcsema_reg_state@NTPOFF + 16]
  mov edi, gs:[__mcsema_reg_state@NTPOFF + 24]
  mov esi, gs:[__mcsema_reg_state@NTPOFF + 20]
  mov ebp, gs:[__mcsema_reg_state@NTPOFF + 32]
  xchg esp, DWORD PTR gs:[__mcsema_reg_state@NTPOFF + 28]
  movdqu xmm0, gs:[__mcsema_reg_state@NTPOFF + 184]
  movdqu xmm1, gs:[__mcsema_reg_state@NTPOFF + 200]
  movdqu xmm2, gs:[__mcsema_reg_state@NTPOFF + 216]
  movdqu xmm3, gs:[__mcsema_reg_state@NTPOFF + 232]
  movdqu xmm4, gs:[__mcsema_reg_state@NTPOFF + 248]
  movdqu xmm5, gs:[__mcsema_reg_state@NTPOFF + 264]
  movdqu xmm6, gs:[__mcsema_reg_state@NTPOFF + 280]
  movdqu xmm7, gs:[__mcsema_reg_state@NTPOFF + 296]
  jmp DWORD PTR gs:[__mcsema_reg_state@NTPOFF + 0]
.Lfunc_end3:
  .size __mcsema_detach_ret_cdecl,.Lfunc_end3-__mcsema_detach_ret_cdecl
  .cfi_endproc

  .globl __mcsema_detach_call_cdecl
  .type __mcsema_detach_call_cdecl,@function
__mcsema_detach_call_cdecl:
  .cfi_startproc
  pop DWORD PTR gs:[__mcsema_reg_state@NTPOFF + 0]
  push edi
  push esi
  push ebx
  push ebp
  mov eax, gs:[0]
  lea edi, [eax + __mcsema_stack_args@NTPOFF]
  lea esi, [esp + 20]
  mov ecx, 256
  rep movsb
  mov edi, gs:[__mcsema_reg_state@NTPOFF + 24]
  mov esi, gs:[__mcsema_reg_state@NTPOFF + 20]
  mov ebx, gs:[__mcsema_reg_state@NTPOFF + 8]
  mov ebp, gs:[__mcsema_reg_state@NTPOFF + 32]
  xchg DWORD PTR gs:[__mcsema_reg_state@NTPOFF + 28], esp
  sub esp, 256
  push esi
  push edi
  push ecx
  lea edi, [esp + 12]
  mov eax, DWORD PTR gs:[0]
  lea esi, [eax + __mcsema_stack_args@NTPOFF]
  mov ecx, 256
  rep movsb
  pop ecx
  pop edi
  pop esi
  lea eax, __mcsema_attach_ret_cdecl
  push eax
  jmp DWORD PTR gs:[__mcsema_reg_state@NTPOFF + 0]
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
  push DWORD PTR gs:[__mcsema_stack_mark@NTPOFF]
  mov eax, DWORD PTR gs:[0]
  lea edi, [eax + __mcsema_stack_args@NTPOFF]
  mov esi, DWORD PTR gs:[__mcsema_reg_state@NTPOFF + 28]
  mov ecx, 256
  rep movsb
  mov eax, gs:[__mcsema_reg_state@NTPOFF + 4]
  mov ebx, gs:[__mcsema_reg_state@NTPOFF + 8]
  mov ecx, gs:[__mcsema_reg_state@NTPOFF + 12]
  mov edx, gs:[__mcsema_reg_state@NTPOFF + 16]
  mov edi, gs:[__mcsema_reg_state@NTPOFF + 24]
  mov esi, gs:[__mcsema_reg_state@NTPOFF + 20]
  mov ebp, gs:[__mcsema_reg_state@NTPOFF + 32]
  xchg DWORD PTR gs:[__mcsema_reg_state@NTPOFF + 28], esp
  movdqu xmm0, gs:[__mcsema_reg_state@NTPOFF + 184]
  movdqu xmm1, gs:[__mcsema_reg_state@NTPOFF + 200]
  movdqu xmm2, gs:[__mcsema_reg_state@NTPOFF + 216]
  movdqu xmm3, gs:[__mcsema_reg_state@NTPOFF + 232]
  movdqu xmm4, gs:[__mcsema_reg_state@NTPOFF + 248]
  movdqu xmm5, gs:[__mcsema_reg_state@NTPOFF + 264]
  movdqu xmm6, gs:[__mcsema_reg_state@NTPOFF + 280]
  movdqu xmm7, gs:[__mcsema_reg_state@NTPOFF + 296]
  sub esp, 256
  push esi
  push edi
  push ecx
  lea edi, [esp + 12]
  mov eax, DWORD PTR gs:[0]
  lea esi, [eax + __mcsema_stack_args@NTPOFF]
  mov ecx, 256
  rep movsb
  pop ecx
  pop edi
  pop esi
  mov DWORD PTR gs:[__mcsema_stack_mark@NTPOFF], esp
  lea eax, __mcsema_attach_ret_value
  push eax
  jmp DWORD PTR gs:[__mcsema_reg_state@NTPOFF + 0]
.Lfunc_end5:
  .size __mcsema_detach_call_value,.Lfunc_end5-__mcsema_detach_call_value
  .cfi_endproc

  .globl __mcsema_debug_get_reg_state
  .type __mcsema_debug_get_reg_state,@function
__mcsema_debug_get_reg_state:
  .cfi_startproc
  mov eax, DWORD PTR gs:[0]
  lea eax, [eax + __mcsema_reg_state@NTPOFF]
  ret
.Lfunc_end6:
  .size __mcsema_debug_get_reg_state,.Lfunc_end6-__mcsema_debug_get_reg_state
  .cfi_endproc

  .globl __mcsema_detach_call_stdcall
  .type __mcsema_detach_call_stdcall,@function
__mcsema_detach_call_stdcall:
  .cfi_startproc
  pop DWORD PTR gs:[__mcsema_reg_state@NTPOFF + 0]
  push edi
  push esi
  push ebx
  push ebp
  push DWORD PTR gs:[__mcsema_stack_mark@NTPOFF]
  push ecx
  push edx
  mov eax, gs:[0]
  lea edi, [eax + __mcsema_stack_args@NTPOFF]
  lea esi, [esp + 32]
  mov ecx, 256
  rep movsb
  pop edx
  pop ecx
  mov edi, gs:[__mcsema_reg_state@NTPOFF + 24]
  mov esi, gs:[__mcsema_reg_state@NTPOFF + 20]
  mov ebx, gs:[__mcsema_reg_state@NTPOFF + 8]
  mov ebp, gs:[__mcsema_reg_state@NTPOFF + 32]
  xchg DWORD PTR gs:[__mcsema_reg_state@NTPOFF + 28], esp
  sub esp, 256
  push esi
  push edi
  push ecx
  lea edi, [esp + 12]
  mov eax, DWORD PTR gs:[0]
  lea esi, [eax + __mcsema_stack_args@NTPOFF]
  mov ecx, 256
  rep movsb
  pop ecx
  pop edi
  pop esi
  mov DWORD PTR gs:[__mcsema_stack_mark@NTPOFF], esp
  lea eax, __mcsema_attach_ret_stdcall
  push eax
  jmp DWORD PTR gs:[__mcsema_reg_state@NTPOFF + 0]
.Lfunc_endA:
  .size __mcsema_detach_call_stdcall,.Lfunc_endA-__mcsema_detach_call_stdcall
  .cfi_endproc

  .globl __mcsema_attach_ret_stdcall
  .type __mcsema_attach_ret_stdcall,@function
__mcsema_attach_ret_stdcall:
  .cfi_startproc
  sub DWORD PTR gs:[__mcsema_stack_mark@NTPOFF], esp
  mov ecx, DWORD PTR gs:[__mcsema_stack_mark@NTPOFF]
  add esp, 260
  xchg esp, DWORD PTR gs:[__mcsema_reg_state@NTPOFF + 28]
  mov gs:[__mcsema_reg_state@NTPOFF + 4], eax
  mov gs:[__mcsema_reg_state@NTPOFF + 16], edx
  movdqu gs:[__mcsema_reg_state@NTPOFF + 184], xmm0
  mov gs:[__mcsema_reg_state@NTPOFF + 32], ebp
  mov gs:[__mcsema_reg_state@NTPOFF + 8], ebx
  mov gs:[__mcsema_reg_state@NTPOFF + 20], esi
  mov gs:[__mcsema_reg_state@NTPOFF + 24], edi
  pop DWORD PTR gs:[__mcsema_stack_mark@NTPOFF]
  pop ebp
  pop ebx
  pop esi
  pop edi
  sub esp, ecx
  add esp, 4
  lea ecx, [esp+ecx]
  jmp dword ptr [ecx-4]
.Lfunc_end7:
  .size __mcsema_attach_ret_stdcall,.Lfunc_end7-__mcsema_attach_ret_stdcall
  .cfi_endproc

  .globl __mcsema_detach_call_fastcall
  .type __mcsema_detach_call_fastcall,@function
__mcsema_detach_call_fastcall:
  .cfi_startproc
  lea eax, __mcsema_detach_call_stdcall
  jmp eax
.Lfunc_end8:
  .size __mcsema_detach_call_fastcall,.Lfunc_end8-__mcsema_detach_call_fastcall
  .cfi_endproc

  .globl __mcsema_attach_ret_fastcall
  .type __mcsema_attach_ret_fastcall,@function
__mcsema_attach_ret_fastcall:
  .cfi_startproc
  push eax
  lea eax, __mcsema_attach_ret_stdcall
  xchg eax, DWORD PTR [esp]
  ret
.Lfunc_end9:
  .size __mcsema_attach_ret_fastcall,.Lfunc_end9-__mcsema_attach_ret_fastcall
  .cfi_endproc

