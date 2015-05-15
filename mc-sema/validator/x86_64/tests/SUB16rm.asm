BITS 64
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=FLAG_OF
;TEST_FILE_META_END
    ; SUB16rm
    ;TEST_BEGIN_RECORDING
    lea rcx, [rsp-0x4]
    mov DWORD [rcx], 0xc8
    mov edx, 0x3
    sub dx, WORD [rcx]
    mov rcx, [rcx]
    ;TEST_END_RECORDING

