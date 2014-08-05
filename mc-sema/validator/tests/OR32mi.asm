BITS 32
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=FLAG_AF
;TEST_FILE_META_END
    ; OR32mi
    ;TEST_BEGIN_RECORDING
    lea edi, [esp-0x4]
    mov DWORD [edi], 0xabcd1234
    or DWORD [edi], 0x5678fedc
    mov edx, [edi]
    mov edi, 0x0
    ;TEST_END_RECORDING

