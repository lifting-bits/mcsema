BITS 32
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=FLAG_FPU_IE
;TEST_FILE_META_END
    FLD1
    ;TEST_BEGIN_RECORDING
    lea edi, [esp-0xC]
    fistp dword [edi]
    mov eax, dword [edi]
    mov edi, 0x0
    ;TEST_END_RECORDING


