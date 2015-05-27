BITS 32
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=FLAG_AF
;TEST_FILE_META_END
    ; OR32mr
    ;TEST_BEGIN_RECORDING
    lea edi, [esp-0x4]
    mov DWORD [edi], 0x1234abcd
    mov eax, 0x5678fedc
    or [edi], eax
    mov edx, [edi]
    mov edi, 0x0
    ;TEST_END_RECORDING

