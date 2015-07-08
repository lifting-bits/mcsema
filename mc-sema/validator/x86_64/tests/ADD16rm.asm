BITS 64
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=
;TEST_FILE_META_END
    ; ADD16rm
    ;TEST_BEGIN_RECORDING
    lea rax, [rsp-0x10]
    mov DWORD [rax], 0x1000
    mov bx, 0x2
    add bx, [rax]
    mov eax, [rax]
    ;TEST_END_RECORDING

