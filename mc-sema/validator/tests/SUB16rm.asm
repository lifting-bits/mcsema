BITS 32
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=FLAG_OF
;TEST_FILE_META_END
    ; SUB16rm
    ;TEST_BEGIN_RECORDING
    lea ecx, [esp-0x4]
    mov DWORD [ecx], 0xc8
    mov edx, 0x3
    sub dx, WORD [ecx]
    mov ecx, [ecx]
    ;TEST_END_RECORDING

