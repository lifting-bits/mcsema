BITS 32
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=FLAG_AF
;TEST_FILE_META_END
    ; SETNEm
    mov ecx, 0x5
    mov ebx, 0xa
    cmp ecx, ebx
    ;TEST_BEGIN_RECORDING
    lea edi, [esp-0x4]
    mov DWORD [edi], 0xc
    setne [edi]
    mov eax, [edi]
    xor edi, edi
    ;TEST_END_RECORDING

