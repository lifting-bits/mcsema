BITS 64
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=FLAG_OF
;TEST_FILE_META_END
    ; SUB16rm
    ;TEST_BEGIN_RECORDING
    lea rcx, [rsp-0x4]
    mov DWORD [rcx], 0xc8
    mov rdx, 0x3
    sub dx, WORD [rcx]
    mov edx, DWORD [rcx]
    mov rcx, 0
    ;TEST_END_RECORDING
