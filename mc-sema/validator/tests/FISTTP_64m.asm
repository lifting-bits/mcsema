BITS 32
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=FLAG_FPU_IE
;TEST_FILE_META_END
    FLDPI
    ;TEST_BEGIN_RECORDING
    lea edi, [esp-0xC]
    fisttp qword [edi]
    mov eax, dword [edi+00]
    mov ebx, dword [edi+04]
    mov edi, 0x0
    ;TEST_END_RECORDING


