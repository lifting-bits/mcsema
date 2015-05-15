BITS 64
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=FLAG_AF
;TEST_FILE_META_END
    ; OR32mr
    ;TEST_BEGIN_RECORDING
    lea rdi, [rsp-0x4]
    mov DWORD [rdi], 0x1234abcd
    mov eax, 0x5678fedc
    or [rdi], eax
    mov edx, [rdi]
    mov rdi, 0x0
    ;TEST_END_RECORDING

