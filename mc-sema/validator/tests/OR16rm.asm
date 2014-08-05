BITS 32
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=FLAG_AF
;TEST_FILE_META_END
    ; OR16rm
    ;TEST_BEGIN_RECORDING
    lea edi, [esp-0x6]
    mov WORD [edi], 0x1234
    mov ax, 0x5678
    or ax, [edi]
    mov edi, 0x0
    ;TEST_END_RECORDING

