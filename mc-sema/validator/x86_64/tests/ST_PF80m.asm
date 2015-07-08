BITS 64
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=FLAG_FPU_IE
;TEST_FILE_META_END
    FLD1
    ;TEST_BEGIN_RECORDING
    lea rdi, [rsp-0x10]
    mov dword [rdi+0x00], 0
    mov dword [rdi+0x04], 0
    mov dword [rdi+0x08], 0
    fstp tword [rdi]
    mov eax, dword [rdi+00]
    mov ebx, dword [rdi+04]
    mov ecx, dword [rdi+08]
    mov edi, 0x0
    ;TEST_END_RECORDING

