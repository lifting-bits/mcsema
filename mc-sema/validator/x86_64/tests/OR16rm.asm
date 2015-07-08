BITS 64
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=FLAG_AF
;TEST_FILE_META_END
    ; OR16rm
    ;TEST_BEGIN_RECORDING
    lea rdi, [rsp-0x6]
    mov WORD [rdi], 0x1234
    mov ax, 0x5678
    or ax, [rdi]
    mov rdi, 0x0
    ;TEST_END_RECORDING

