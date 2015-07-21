BITS 32
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=
;TEST_FILE_META_END
    ; CMPXCHG32rm
    ;TEST_BEGIN_RECORDING
    lea edi, [esp-0x10]
    mov DWORD [edi], 0xbadf00d
    mov ecx, 0
    mov eax, 0xabcd4321
    cmpxchg [edi], ecx
    mov edx, [edi]
    mov edi, 0x0
    ;TEST_END_RECORDING

