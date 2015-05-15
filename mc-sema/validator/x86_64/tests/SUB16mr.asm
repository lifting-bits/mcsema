BITS 64
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=
;TEST_FILE_META_END
    ; SUB16mr
    ;TEST_BEGIN_RECORDING
    lea rbx, [rsp-0x4]
    mov DWORD [rbx], 0xc8
    mov ecx, 0x3
    sub WORD [rbx], cx
    mov ebx, [rbx]
    ;TEST_END_RECORDING

