BITS 64
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=FLAG_FPU_IE
;TEST_FILE_META_END
    FLDPI
    ;TEST_BEGIN_RECORDING
    lea rdi, [rsp-0xC]
    fisttp qword [rdi]
    mov eax, dword [rdi+00]
    mov ebx, dword [rdi+04]
    mov edi, 0x0
    ;TEST_END_RECORDING


