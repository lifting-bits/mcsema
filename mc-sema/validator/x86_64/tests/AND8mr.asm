BITS 64
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=FLAG_AF
;TEST_FILE_META_END
    ; AND8mr
    ;TEST_BEGIN_RECORDING
    lea rax, [rsp-0x4]
    mov DWORD [rax], 0x55
    mov ebx, 0x77
    and BYTE [rax], bl
    mov eax, 0x0
    ;TEST_END_RECORDING

