BITS 64
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=
;TEST_FILE_META_END
    ; CMPXCHG32rm
    ;TEST_BEGIN_RECORDING
    lea rdi, [rsp-0x10]
    mov DWORD [rdi], 0xabcd4321
    mov eax, 0xabcd4321
    cmpxchg [rdi], ecx
    mov edx, [rdi]
    mov rdi, 0x0
    ;TEST_END_RECORDING

