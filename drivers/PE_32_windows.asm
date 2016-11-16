/* Auto-generated file! Don't modify! */

  .intel_syntax noprefix

  .section        .tls$,"wd"
     .globl  __mcsema_reg_state
__mcsema_reg_state:
     .align  4
     .zero   448

     .globl  __mcsema_stack
__mcsema_stack:
     .align  16
     .zero   1048576

     .globl  __mcsema_stack_args
__mcsema_stack_args:
     .align  16
     .zero   256

     .globl  __mcsema_stack_mark
__mcsema_stack_mark:
     .align  4
     .zero   4

  .text

  .globl __mcsema_detach_ret_cdecl

  .globl __mcsema_attach_call_cdecl
__mcsema_attach_call_cdecl:
  .cfi_startproc
  push dword ptr [esp]
  mov dword ptr [esp+4], ebp
push edx
mov ebp, dword ptr [__tls_index]
mov edx, dword ptr fs:[44]
mov ebp, dword ptr [edx + 4*ebp]
pop edx
  pop DWORD PTR [ebp + __mcsema_reg_state@SECREL32 + 0]
  mov [ebp + __mcsema_reg_state@SECREL32 + 4], eax
  mov [ebp + __mcsema_reg_state@SECREL32 + 8], ebx
  mov [ebp + __mcsema_reg_state@SECREL32 + 12], ecx
  mov [ebp + __mcsema_reg_state@SECREL32 + 16], edx
  mov [ebp + __mcsema_reg_state@SECREL32 + 20], esi
  mov [ebp + __mcsema_reg_state@SECREL32 + 24], edi
  pop ebp
push edx
mov eax, dword ptr [__tls_index]
mov edx, dword ptr fs:[44]
mov eax, dword ptr [edx + 4*eax]
pop edx
  mov [eax + __mcsema_reg_state@SECREL32 + 32], ebp
  movdqu [eax + __mcsema_reg_state@SECREL32 + 184], xmm0
  movdqu [eax + __mcsema_reg_state@SECREL32 + 200], xmm1
  movdqu [eax + __mcsema_reg_state@SECREL32 + 216], xmm2
  movdqu [eax + __mcsema_reg_state@SECREL32 + 232], xmm3
  movdqu [eax + __mcsema_reg_state@SECREL32 + 248], xmm4
  movdqu [eax + __mcsema_reg_state@SECREL32 + 264], xmm5
  movdqu [eax + __mcsema_reg_state@SECREL32 + 280], xmm6
  movdqu [eax + __mcsema_reg_state@SECREL32 + 296], xmm7
  xchg esp, [eax + __mcsema_reg_state@SECREL32 + 28]
  cmp esp, 0
  jnz .Lhave_stack
  lea esp, [eax + __mcsema_stack@SECREL32 + 1048576]
.Lhave_stack:
  push eax
  lea eax, [eax + __mcsema_reg_state@SECREL32]
  xchg eax, [esp]
  push eax
  lea eax, __mcsema_detach_ret_cdecl
  xchg eax, [esp]
  mov eax, DWORD PTR [eax + __mcsema_reg_state@SECREL32 + 0]
  jmp eax
.Lfunc_end1:
  .cfi_endproc

  .globl __mcsema_attach_ret_cdecl
__mcsema_attach_ret_cdecl:
  .cfi_startproc
  add esp, 260
push eax
push edx
mov eax, dword ptr [__tls_index]
mov edx, dword ptr fs:[44]
mov eax, dword ptr [edx + 4*eax]
pop edx
  xchg esp, [eax + __mcsema_reg_state@SECREL32 + 28]
  add dword ptr [eax + __mcsema_reg_state@SECREL32 + 28], 4
  mov eax, dword ptr [eax + __mcsema_reg_state@SECREL32 + 28]
  mov eax, dword ptr [eax-4]
  push ecx
push edx
mov ecx, dword ptr [__tls_index]
mov edx, dword ptr fs:[44]
mov ecx, dword ptr [edx + 4*ecx]
pop edx
  mov [ecx + __mcsema_reg_state@SECREL32 + 4], eax
  mov [ecx + __mcsema_reg_state@SECREL32 + 16], edx
  movdqu [ecx + __mcsema_reg_state@SECREL32 + 184], xmm0
  mov [ecx + __mcsema_reg_state@SECREL32 + 32], ebp
  mov [ecx + __mcsema_reg_state@SECREL32 + 8], ebx
  mov [ecx + __mcsema_reg_state@SECREL32 + 20], esi
  mov [ecx + __mcsema_reg_state@SECREL32 + 24], edi
  pop ecx
  pop ebp
  pop ebx
  pop esi
  pop edi
  ret
.Lfunc_end2:
  .cfi_endproc

  .globl __mcsema_attach_ret_value
__mcsema_attach_ret_value:
  .cfi_startproc
  push ebp
push edx
mov ebp, dword ptr [__tls_index]
mov edx, dword ptr fs:[44]
mov ebp, dword ptr [edx + 4*ebp]
pop edx
  mov [ebp + __mcsema_reg_state@SECREL32 + 4], eax
  mov [ebp + __mcsema_reg_state@SECREL32 + 8], ebx
  mov [ebp + __mcsema_reg_state@SECREL32 + 12], ecx
  mov [ebp + __mcsema_reg_state@SECREL32 + 16], edx
  mov [ebp + __mcsema_reg_state@SECREL32 + 20], esi
  mov [ebp + __mcsema_reg_state@SECREL32 + 24], edi
  pop ebp
push edx
mov eax, dword ptr [__tls_index]
mov edx, dword ptr fs:[44]
mov eax, dword ptr [edx + 4*eax]
pop edx
  mov [eax + __mcsema_reg_state@SECREL32 + 32], ebp
  movdqu [eax + __mcsema_reg_state@SECREL32 + 184], xmm0
  movdqu [eax + __mcsema_reg_state@SECREL32 + 200], xmm1
  movdqu [eax + __mcsema_reg_state@SECREL32 + 216], xmm2
  movdqu [eax + __mcsema_reg_state@SECREL32 + 232], xmm3
  movdqu [eax + __mcsema_reg_state@SECREL32 + 248], xmm4
  movdqu [eax + __mcsema_reg_state@SECREL32 + 264], xmm5
  movdqu [eax + __mcsema_reg_state@SECREL32 + 280], xmm6
  movdqu [eax + __mcsema_reg_state@SECREL32 + 296], xmm7
  sub DWORD PTR [eax + __mcsema_stack_mark@SECREL32], esp
  mov ecx, DWORD PTR [eax + __mcsema_stack_mark@SECREL32]
  add esp, 260
  add esp, ecx
  xchg esp, DWORD PTR [eax + __mcsema_reg_state@SECREL32 + 28]
  pop DWORD PTR [eax + __mcsema_stack_mark@SECREL32]
  pop ebp
  pop ebx
  pop esi
  pop edi
  ret
.Lfunc_end0:
  .cfi_endproc

  .globl __mcsema_detach_ret_cdecl
__mcsema_detach_ret_cdecl:
  .cfi_startproc
  mov [esp], ebp
push edx
mov ebp, dword ptr [__tls_index]
mov edx, dword ptr fs:[44]
mov ebp, dword ptr [edx + 4*ebp]
pop edx
  mov eax, [ebp + __mcsema_reg_state@SECREL32 + 4]
  mov ebx, [ebp + __mcsema_reg_state@SECREL32 + 8]
  mov ecx, [ebp + __mcsema_reg_state@SECREL32 + 12]
  mov edx, [ebp + __mcsema_reg_state@SECREL32 + 16]
  mov esi, [ebp + __mcsema_reg_state@SECREL32 + 20]
  mov edi, [ebp + __mcsema_reg_state@SECREL32 + 24]
  movdqu xmm0, [ebp + __mcsema_reg_state@SECREL32 + 184]
  movdqu xmm1, [ebp + __mcsema_reg_state@SECREL32 + 200]
  movdqu xmm2, [ebp + __mcsema_reg_state@SECREL32 + 216]
  movdqu xmm3, [ebp + __mcsema_reg_state@SECREL32 + 232]
  movdqu xmm4, [ebp + __mcsema_reg_state@SECREL32 + 248]
  movdqu xmm5, [ebp + __mcsema_reg_state@SECREL32 + 264]
  movdqu xmm6, [ebp + __mcsema_reg_state@SECREL32 + 280]
  movdqu xmm7, [ebp + __mcsema_reg_state@SECREL32 + 296]
  pop ebp
  push eax
push edx
mov eax, dword ptr [__tls_index]
mov edx, dword ptr fs:[44]
mov eax, dword ptr [edx + 4*eax]
pop edx
  mov ebp, [eax + __mcsema_reg_state@SECREL32 + 32]
  xchg esp, DWORD PTR [eax + __mcsema_reg_state@SECREL32 + 28]
  add dword ptr [eax + __mcsema_reg_state@SECREL32 + 28], 4
  mov eax, dword ptr [eax + __mcsema_reg_state@SECREL32 + 28]
  mov eax, dword ptr [eax-4]
  push eax
push edx
mov eax, dword ptr [__tls_index]
mov edx, dword ptr fs:[44]
mov eax, dword ptr [edx + 4*eax]
pop edx
  mov eax, [eax + __mcsema_reg_state@SECREL32 + 0]
  xchg eax, [esp]
  ret
.Lfunc_end3:
  .cfi_endproc

  .globl __mcsema_detach_call_cdecl
__mcsema_detach_call_cdecl:
  .cfi_startproc
push edx
mov eax, dword ptr [__tls_index]
mov edx, dword ptr fs:[44]
mov eax, dword ptr [edx + 4*eax]
pop edx
  pop DWORD PTR [eax + __mcsema_reg_state@SECREL32 + 0]
  push edi
  push esi
  push ebx
  push ebp
  lea edi, [eax + __mcsema_stack_args@SECREL32]
  lea esi, [esp + 20]
  mov ecx, 256
  rep movsb
  mov esi, [eax + __mcsema_reg_state@SECREL32 + 20]
  mov edi, [eax + __mcsema_reg_state@SECREL32 + 24]
  mov ebx, [eax + __mcsema_reg_state@SECREL32 + 8]
  mov ebp, [eax + __mcsema_reg_state@SECREL32 + 32]
  xchg DWORD PTR [eax + __mcsema_reg_state@SECREL32 + 28], esp
  sub esp, 256
  push esi
  push edi
  push ecx
  lea edi, [esp + 12]
  lea esi, [eax + __mcsema_stack_args@SECREL32]
  mov ecx, 256
  rep movsb
  pop ecx
  pop edi
  pop esi
  push eax
  lea eax, __mcsema_attach_ret_cdecl
  xchg eax, [esp]
  jmp DWORD PTR [eax + __mcsema_reg_state@SECREL32 + 0]
.Lfunc_end4:
  .cfi_endproc

  .globl ___mcsema_detach_call_value
___mcsema_detach_call_value:
  .cfi_startproc
  push edi
  push esi
  push ebx
  push ebp
push edx
mov eax, dword ptr [__tls_index]
mov edx, dword ptr fs:[44]
mov eax, dword ptr [edx + 4*eax]
pop edx
  push DWORD PTR [eax + __mcsema_stack_mark@SECREL32]
  lea edi, [eax + __mcsema_stack_args@SECREL32]
  mov esi, DWORD PTR [eax + __mcsema_reg_state@SECREL32 + 28]
  mov ecx, 256
  rep movsb
  mov ebp, eax
  mov eax, [ebp + __mcsema_reg_state@SECREL32 + 4]
  mov eax, ebp
  mov ebx, [eax + __mcsema_reg_state@SECREL32 + 8]
  mov ecx, [eax + __mcsema_reg_state@SECREL32 + 12]
  mov edx, [eax + __mcsema_reg_state@SECREL32 + 16]
  mov esi, [eax + __mcsema_reg_state@SECREL32 + 20]
  mov edi, [eax + __mcsema_reg_state@SECREL32 + 24]
  mov ebp, [eax + __mcsema_reg_state@SECREL32 + 32]
  movdqu xmm0, [eax + __mcsema_reg_state@SECREL32 + 184]
  movdqu xmm1, [eax + __mcsema_reg_state@SECREL32 + 200]
  movdqu xmm2, [eax + __mcsema_reg_state@SECREL32 + 216]
  movdqu xmm3, [eax + __mcsema_reg_state@SECREL32 + 232]
  movdqu xmm4, [eax + __mcsema_reg_state@SECREL32 + 248]
  movdqu xmm5, [eax + __mcsema_reg_state@SECREL32 + 264]
  movdqu xmm6, [eax + __mcsema_reg_state@SECREL32 + 280]
  movdqu xmm7, [eax + __mcsema_reg_state@SECREL32 + 296]
  xchg DWORD PTR [eax + __mcsema_reg_state@SECREL32 + 28], esp
  sub esp, 256
  push esi
  push edi
  push ecx
  lea edi, [esp + 12]
  lea esi, [eax + __mcsema_stack_args@SECREL32]
  mov ecx, 256
  rep movsb
  pop ecx
  pop edi
  pop esi
  mov DWORD PTR [eax + __mcsema_stack_mark@SECREL32], esp
  mov [esp], eax
  lea eax, __mcsema_attach_ret_value
  xchg eax, [esp]
  jmp DWORD PTR [eax + __mcsema_reg_state@SECREL32 + 0]
.Lfunc_end5:
  .cfi_endproc

  .globl __mcsema_debug_get_reg_state
__mcsema_debug_get_reg_state:
  .cfi_startproc
push edx
mov eax, dword ptr [__tls_index]
mov edx, dword ptr fs:[44]
mov eax, dword ptr [edx + 4*eax]
pop edx
  lea eax, [eax + __mcsema_reg_state@SECREL32]
  ret
.Lfunc_end6:
  .cfi_endproc

  .globl __mcsema_detach_call_stdcall
__mcsema_detach_call_stdcall:
  .cfi_startproc
push edx
mov eax, dword ptr [__tls_index]
mov edx, dword ptr fs:[44]
mov eax, dword ptr [edx + 4*eax]
pop edx
  pop DWORD PTR [eax + __mcsema_reg_state@SECREL32 + 0]
  push edi
  push esi
  push ebx
  push ebp
  push DWORD PTR [eax + __mcsema_stack_mark@SECREL32]
  push ecx
  push edx
  lea edi, [eax + __mcsema_stack_args@SECREL32]
  lea esi, [esp + 32]
  mov ecx, 256
  rep movsb
  pop edx
  pop ecx
  mov edi, [eax + __mcsema_reg_state@SECREL32 + 24]
  mov esi, [eax + __mcsema_reg_state@SECREL32 + 20]
  mov ebx, [eax + __mcsema_reg_state@SECREL32 + 8]
  mov ebp, [eax + __mcsema_reg_state@SECREL32 + 32]
  xchg DWORD PTR [eax + __mcsema_reg_state@SECREL32 + 28], esp
  sub esp, 256
  push esi
  push edi
  push ecx
  lea edi, [esp + 12]
  lea esi, [eax + __mcsema_stack_args@SECREL32]
  mov ecx, 256
  rep movsb
  pop ecx
  pop edi
  pop esi
  mov DWORD PTR [eax + __mcsema_stack_mark@SECREL32], esp
  push eax
  lea eax, __mcsema_attach_ret_stdcall
  xchg eax, [esp]
  jmp DWORD PTR [eax + __mcsema_reg_state@SECREL32 + 0]
.Lfunc_endA:
  .cfi_endproc

  .globl __mcsema_attach_ret_stdcall
__mcsema_attach_ret_stdcall:
  .cfi_startproc
push edx
mov ecx, dword ptr [__tls_index]
mov edx, dword ptr fs:[44]
mov ecx, dword ptr [edx + 4*ecx]
pop edx
  sub DWORD PTR [ecx + __mcsema_stack_mark@SECREL32], esp
  add esp, 260
  xchg esp, DWORD PTR [ecx + __mcsema_reg_state@SECREL32 + 28]
  mov [ecx + __mcsema_reg_state@SECREL32 + 4], eax
  mov [ecx + __mcsema_reg_state@SECREL32 + 16], edx
  movdqu [ecx + __mcsema_reg_state@SECREL32 + 184], xmm0
  mov [ecx + __mcsema_reg_state@SECREL32 + 32], ebp
  mov [ecx + __mcsema_reg_state@SECREL32 + 8], ebx
  mov [ecx + __mcsema_reg_state@SECREL32 + 20], esi
  mov [ecx + __mcsema_reg_state@SECREL32 + 24], edi
  mov ebp, ecx
  mov ecx, DWORD PTR [ecx + __mcsema_stack_mark@SECREL32]
  pop DWORD PTR [ebp + __mcsema_stack_mark@SECREL32]
  pop ebp
  pop ebx
  pop esi
  pop edi
  sub esp, ecx
  add esp, 4
  lea ecx, [esp+ecx]
  jmp dword ptr [ecx-4]
.Lfunc_end7:
  .cfi_endproc

  .globl __mcsema_detach_call_fastcall
__mcsema_detach_call_fastcall:
  .cfi_startproc
  lea eax, __mcsema_detach_call_stdcall
  jmp eax
.Lfunc_end8:
  .cfi_endproc

  .globl __mcsema_attach_ret_fastcall
__mcsema_attach_ret_fastcall:
  .cfi_startproc
  push eax
  lea eax, __mcsema_attach_ret_stdcall
  xchg eax, DWORD PTR [esp]
  ret
.Lfunc_end9:
  .cfi_endproc

