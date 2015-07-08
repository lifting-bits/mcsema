BITS 64
;TEST_FILE_META_BEGIN
;TEST_TYPE=TEST_F
;TEST_IGNOREFLAGS=FLAG_FPU_IE
;TEST_FILE_META_END
    ; ST_F64m
    FLD1
    ;TEST_BEGIN_RECORDING
    lea rdi, [rsp-0x10]
    fst QWORD [rdi]
    mov eax, [rdi+0x00]
    mov ebx, [rdi+0x04]
    mov edi, 0x0
    ;TEST_END_RECORDING

