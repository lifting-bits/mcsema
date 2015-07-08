BITS 64
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=FLAG_AF
;TEST_FILE_META_END
    ; AND16mr
    ;TEST_BEGIN_RECORDING
    lea rax, [rsp-0x4]
    mov DWORD [rax], 0x5555
    mov ebx, 0x7777
    and WORD [rax], bx
    mov eax, 0x0
    ;TEST_END_RECORDING

