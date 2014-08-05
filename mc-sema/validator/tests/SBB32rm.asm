BITS 32
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=
;TEST_FILE_META_END
    ; SBB32rm
    ;TEST_BEGIN_RECORDING
    lea edi, [esp-0x4]
    mov DWORD [edi], 0x1234abcd
    mov eax, 0x56781234
    sbb eax, [edi]
    mov edi, 0x0
    ;TEST_END_RECORDING

