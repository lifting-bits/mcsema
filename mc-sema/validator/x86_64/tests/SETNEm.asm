BITS 64
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=FLAG_AF
;TEST_FILE_META_END
    ; SETNEm
    mov ecx, 0x5
    mov ebx, 0xa
    cmp ecx, ebx
    ;TEST_BEGIN_RECORDING
    lea rdi, [rsp-0x4]
    mov DWORD [rdi], 0xc
    setne [rdi]
    mov eax, [rdi]
    xor edi, edi
    ;TEST_END_RECORDING

