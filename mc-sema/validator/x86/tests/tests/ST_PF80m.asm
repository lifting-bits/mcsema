BITS 32
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=FLAG_FPU_IE
;TEST_FILE_META_END
    FLD1
    ;TEST_BEGIN_RECORDING
    lea edi, [esp-0x10]
    mov dword [edi+0x00], 0
    mov dword [edi+0x04], 0
    mov dword [edi+0x08], 0
    fstp tword [edi]
    mov eax, dword [edi+00]
    mov ebx, dword [edi+04]
    mov ecx, dword [edi+08]
    mov edi, 0x0
    ;TEST_END_RECORDING

