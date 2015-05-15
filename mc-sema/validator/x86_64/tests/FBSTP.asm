BITS 64
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=
;TEST_FILE_META_END

FLDPI
;TEST_BEGIN_RECORDING
lea rdi, [rsp-0x10]
mov dword [rdi+00], 0x0
mov dword [rdi+04], 0x0
mov dword [rdi+08], 0x0
FBSTP tword [rdi]
mov eax, [rdi+00]
mov ebx, [rdi+04]
mov ecx, [rdi+08]
mov edi, 0

;TEST_END_RECORDING

