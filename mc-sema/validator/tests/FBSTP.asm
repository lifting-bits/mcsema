BITS 32
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=
;TEST_FILE_META_END

FLDPI
;TEST_BEGIN_RECORDING
lea edi, [esp-0x10]
mov dword [edi+00], 0x0
mov dword [edi+04], 0x0
mov dword [edi+08], 0x0
FBSTP tword [edi]
mov eax, [edi+00]
mov ebx, [edi+04]
mov ecx, [edi+08]
mov edi, 0

;TEST_END_RECORDING

