BITS 64
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=
;TEST_FILE_META_END
    ; SUB8rm
    ;TEST_BEGIN_RECORDING
    lea rax, [rsp-0x4]
    mov DWORD [rax], 0xc8
    mov ebx, 0x2
    sub bl, BYTE [rax]
    mov eax, [rax]
    ;TEST_END_RECORDING

