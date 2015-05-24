BITS 32
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=
;TEST_FILE_META_END
    ; Add32RR
    xor eax, eax
    inc eax
    mov eax, 0x1
    mov ebx, 0x2
    ;TEST_BEGIN_RECORDING
    add eax, ebx
    ;TEST_END_RECORDING

