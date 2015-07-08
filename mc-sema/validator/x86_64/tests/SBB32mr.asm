BITS 64
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=
;TEST_FILE_META_END
    ; SBB32mr
    ;TEST_BEGIN_RECORDING
    lea rdi, [rsp-0x4]
    mov DWORD [rdi], 0xabcd4321
    mov eax, 0x56781234
    sbb [rdi], eax
    mov edx, [rdi]
    mov rdi, 0x0
    ;TEST_END_RECORDING

