BITS 64
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=
;TEST_FILE_META_END
    ; XADD32rm
    ;TEST_BEGIN_RECORDING
    lea rdi, [rsp-0x4]
    mov DWORD [rdi], 0xabcd4321
    mov eax, 0x56781234
    xadd [rdi], eax
    mov edx, [rdi]
    mov edi, 0x0
    ;TEST_END_RECORDING

