BITS 32
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=
;TEST_FILE_META_END
    ; SUB16mr
    ;TEST_BEGIN_RECORDING
    lea ebx, [esp-0x4]
    mov DWORD [ebx], 0xc8
    mov ecx, 0x3
    sub WORD [ebx], cx
    mov ebx, [ebx]
    ;TEST_END_RECORDING

