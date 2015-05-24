BITS 32
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=
;TEST_FILE_META_END
    ;TEST_BEGIN_RECORDING
    lea edi, [esp-08]
    mov dword [edi], 0
    FSTSW [edi]
    mov eax, dword [edi]
    mov edi, 0
    ;TEST_END_RECORDING

